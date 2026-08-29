// Package usqueandroid provides Android-callable functions for the usque VPN library.
// This package is designed to be compiled with gomobile bind to produce an .aar file.
//
// Build with:
//
//	gomobile bind -v -target=android/arm64,android/arm -androidapi 24 -o usque.aar github.com/Diniboy1123/usque/android
package usqueandroid

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
    connectip "github.com/Diniboy1123/connect-ip-go"
)

// PacketFlow is the interface that Android must implement to exchange packets with the VPN
// This interface is used for bidirectional packet flow between Android TUN and Go tunnel
type PacketFlow interface {
	// WritePacket writes an IP packet to the Android TUN device
	// Called by Go when a packet is received from Cloudflare
	WritePacket(data []byte)
}

// VpnStateCallback is the interface for VPN state notifications
type VpnStateCallback interface {
	// OnConnected is called when the VPN successfully connects to Cloudflare
	OnConnected()
	// OnDisconnected is called when the VPN disconnects
	OnDisconnected(reason string)
	// OnError is called when an error occurs
	OnError(message string)
}

// tunnelState holds the state of the running tunnel
type tunnelState struct {
	mu        sync.Mutex
	running   bool
	cancel    context.CancelFunc
	inputChan chan []byte
	callback  VpnStateCallback
	tunDevice *AndroidTunDevice
	ipConn    *connectip.Conn
}
var state = &tunnelState{}

// Custom connection options
var (
	customSNI      = "speed.cloudflare.com" // Default SNI for censorship circumvention
	customEndpoint = ""          // Custom endpoint with port, e.g. "162.159.198.2:443" or "[2606:4700:103::2]:443"
	useHTTP2       = false       // Use TCP+HTTP/2 transport instead of QUIC/HTTP-3 (needs endpoint_h2_v4/v6 in config.json)
)

var currentSessionID int64 = 0

// Register creates a new Cloudflare WARP account and saves the configuration.
// This should be called once before starting the VPN.
//
// Parameters:
//   - configPath: Absolute path where the config.json will be saved
//   - deviceName: Optional device name (can be empty)
//
// Returns:
//   - error string if registration fails, empty string on success
func Register(configPath string, deviceName string) string {
	// Already registered?
	if err := config.LoadConfig(configPath); err == nil {
		return "" // Config already exists and is valid
	}

	accountData, err := api.Register(internal.DefaultModel, internal.DefaultLocale, "", true)
	if err != nil {
		return fmt.Sprintf("Registration failed: %v", err)
	}

	privKey, pubKey, err := internal.GenerateEcKeyPair()
	if err != nil {
		return fmt.Sprintf("Failed to generate key pair: %v", err)
	}

	updatedAccountData, err := api.EnrollKey(accountData.ID, accountData.Token, pubKey, deviceName)
    if err != nil {
		return fmt.Sprintf("Failed to enroll key: %v", err)
    }
	
	config.AppConfig = config.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privKey),
		EndpointV4:     updatedAccountData.Config.Peers[0].Endpoint.V4[:len(updatedAccountData.Config.Peers[0].Endpoint.V4)-2],
		EndpointV6:     updatedAccountData.Config.Peers[0].Endpoint.V6[1 : len(updatedAccountData.Config.Peers[0].Endpoint.V6)-3],
		EndpointPubKey: updatedAccountData.Config.Peers[0].PublicKey,

		ID:             updatedAccountData.ID,
		AccessToken:    accountData.Token,
		IPv4:           updatedAccountData.Config.Interface.Addresses.V4,
		IPv6:           updatedAccountData.Config.Interface.Addresses.V6,
	}

	if err := config.AppConfig.SaveConfig(configPath); err != nil {
		return fmt.Sprintf("Failed to save config: %v", err)
	}

	return ""
}

// IsRegistered checks if a valid configuration exists
func IsRegistered(configPath string) bool {
	return config.LoadConfig(configPath) == nil
}

// GetAssignedIPv4 returns the assigned IPv4 address from config
func GetAssignedIPv4(configPath string) string {
	if err := config.LoadConfig(configPath); err != nil {
		return ""
	}
	return config.AppConfig.IPv4
}

// GetAssignedIPv6 returns the assigned IPv6 address from config
func GetAssignedIPv6(configPath string) string {
	if err := config.LoadConfig(configPath); err != nil {
		return ""
	}
	return config.AppConfig.IPv6
}

// fd читается/пишется напрямую системными вызовами, БЕЗ обёртки в os.File.
// Это важно: у os.File есть автоматический финализатор, который рано или
// поздно сам попытается закрыть номер fd — а к этому моменту тот же номер
// может уже принадлежать другой, свежей VPN-сессии. Раз обёртки нет —
// финализатору нечего закрывать, Go никогда не полезет сюда сам.
type AndroidTunDevice struct {
    fd       int
    file     *os.File
    mtu      int
    inputCh  chan []byte
    outputFn PacketFlow
    stopCh   chan struct{}   // добавить
}

func newAndroidTunDevice(fd int, mtu int, packetFlow PacketFlow) (*AndroidTunDevice, error) {
    file := os.NewFile(uintptr(fd), "tun")
    if file == nil {
        return nil, fmt.Errorf("failed to create file from fd %d", fd)
    }
    return &AndroidTunDevice{
        fd: fd, file: file, mtu: mtu,
        inputCh: make(chan []byte, 256), outputFn: packetFlow,
        stopCh: make(chan struct{}),   // добавить
    }, nil
}

var (
	tunReadCount  int64
	tunReadBytes  int64
	tunWriteCount int64
	tunWriteBytes int64

	tunReadTCPCount  int64
	tunWriteTCPCount int64

	packetSamplesMu sync.Mutex
	packetSamples   []string

	traceMu  sync.Mutex
	traceLog []string
)

// trace записывает метку времени + событие в журнал остановки/запуска —
// чтобы видеть по секундам, где застревает остановка, а не гадать.
func trace(msg string) {
	traceMu.Lock()
	defer traceMu.Unlock()
	traceLog = append(traceLog, time.Now().Format("15:04:05.000")+" "+msg)
	if len(traceLog) > 50 {
		traceLog = traceLog[len(traceLog)-50:]
	}
}

// GetShutdownTrace возвращает журнал ключевых точек запуска/остановки туннеля.
func GetShutdownTrace() string {
	traceMu.Lock()
	defer traceMu.Unlock()
	return strings.Join(traceLog, "\n")
}

const packetSampleLimit = 150

func addPacketSample(dir string, b []byte) {
	packetSamplesMu.Lock()
	defer packetSamplesMu.Unlock()
	packetSamples = append(packetSamples, dir+" "+packetSummary(b))
	if len(packetSamples) > packetSampleLimit*2 {
		packetSamples = packetSamples[len(packetSamples)-packetSampleLimit*2:]
	}
}

func packetSummary(b []byte) string {
	if len(b) < 1 {
		return "empty"
	}
	ver := b[0] >> 4
	switch ver {
	case 4:
		if len(b) < 20 {
			return "v4 short"
		}
		proto := b[9]
		src := net.IP(b[12:16]).String()
		dst := net.IP(b[16:20]).String()
		sport, dport := 0, 0
		ihl := int(b[0]&0x0f) * 4
		flags := ""
		if (proto == 6 || proto == 17) && len(b) >= ihl+4 {
			sport = int(b[ihl])<<8 | int(b[ihl+1])
			dport = int(b[ihl+2])<<8 | int(b[ihl+3])
		}
		if proto == 6 && len(b) >= ihl+14 {
			flags = " flags=" + tcpFlagsString(b[ihl+13])
		}
		return fmt.Sprintf("v4 proto=%d %s:%d -> %s:%d len=%d%s", proto, src, sport, dst, dport, len(b), flags)
	case 6:
		if len(b) < 40 {
			return "v6 short"
		}
		proto := b[6]
		src := net.IP(b[8:24]).String()
		dst := net.IP(b[24:40]).String()
		sport, dport := 0, 0
		flags := ""
		if (proto == 6 || proto == 17) && len(b) >= 44 {
			sport = int(b[40])<<8 | int(b[41])
			dport = int(b[42])<<8 | int(b[43])
		}
		if proto == 6 && len(b) >= 54 {
			flags = " flags=" + tcpFlagsString(b[53])
		}
        return fmt.Sprintf("v6 proto=%d [%s]:%d -> [%s]:%d len=%d%s", proto, src, sport, dst, dport, len(b), flags)
	default:
		return fmt.Sprintf("unknown ver=%d len=%d", ver, len(b))
	}
}

func tcpFlagsString(b byte) string {
	var flags []string
	if b&0x02 != 0 { flags = append(flags, "SYN") }
	if b&0x10 != 0 { flags = append(flags, "ACK") }
	if b&0x04 != 0 { flags = append(flags, "RST") }
	if b&0x01 != 0 { flags = append(flags, "FIN") }
	if b&0x08 != 0 { flags = append(flags, "PSH") }
	if len(flags) == 0 { return "-" }
	return strings.Join(flags, "|")
}

// isTCPPort443 проверяет TCP-пакет именно на порт 443 (HTTPS) — чтобы
// сэмплы ловили конкретно попытку открыть сайт в браузере, а не фоновый
// трафик вроде push-уведомлений (порт 5228) или DNS-over-TLS (порт 853).
func isTCPPort443(b []byte) bool {
	if len(b) < 1 {
		return false
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 || b[9] != 6 {
			return false
		}
		ihl := int(b[0]&0x0f) * 4
		if len(b) < ihl+4 {
			return false
		}
		sport := int(b[ihl])<<8 | int(b[ihl+1])
		dport := int(b[ihl+2])<<8 | int(b[ihl+3])
		return sport == 443 || dport == 443
	case 6:
		if len(b) < 44 || b[6] != 6 {
			return false
		}
		sport := int(b[40])<<8 | int(b[41])
		dport := int(b[42])<<8 | int(b[43])
		return sport == 443 || dport == 443
	}
	return false
}

// GetPacketSamples возвращает разбор первых ~20 пакетов в каждую сторону —
// протокол, откуда, куда. Для диагностики маршрутизации.
func GetPacketSamples() string {
	packetSamplesMu.Lock()
	defer packetSamplesMu.Unlock()
	return strings.Join(packetSamples, "\n")
}

// ReadPacket не полагается на то, что кто-то извне вовремя закроет
// дескриптор. Читаем с таймаутом 150мс; если таймаут — проверяем stopCh и,
// если пора остановиться, возвращаем ошибку сами, без чужой помощи.
func (d *AndroidTunDevice) ReadPacket(buf []byte) (int, error) {
	for {
		d.file.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		n, err := d.file.Read(buf)
		if err == nil {
			atomic.AddInt64(&tunReadCount, 1)
			atomic.AddInt64(&tunReadBytes, int64(n))
			if isTCPPort443(buf[:n]) {
				atomic.AddInt64(&tunReadTCPCount, 1)
				addPacketSample("OUT", buf[:n])
			}
			return n, nil
		}
		if os.IsTimeout(err) {
			select {
			case <-d.stopCh:
				return 0, fmt.Errorf("tunnel stopping")
			default:
				continue
			}
		}
		return 0, err
	}
}

func (d *AndroidTunDevice) WritePacket(pkt []byte) error {
    if d.outputFn != nil { d.outputFn.WritePacket(pkt); return nil }
    _, err := d.file.Write(pkt)
    if err == nil {
        atomic.AddInt64(&tunWriteCount, 1)
        atomic.AddInt64(&tunWriteBytes, int64(len(pkt)))
        if isTCPPort443(pkt) {
            atomic.AddInt64(&tunWriteTCPCount, 1)
            addPacketSample("IN ", pkt)
        }
    }
    return err
}

// GetPacketStats возвращает счётчики трафика через TUN-устройство —
// для диагностики ситуации "подключено, но трафик не идёт".
func GetPacketStats() string {
	return fmt.Sprintf("out(TUN->tunnel): %d pkt / %d B | in(tunnel->TUN): %d pkt / %d B",
		atomic.LoadInt64(&tunReadCount), atomic.LoadInt64(&tunReadBytes),
		atomic.LoadInt64(&tunWriteCount), atomic.LoadInt64(&tunWriteBytes))
}

func (d *AndroidTunDevice) Close() error {
    if d.file != nil {
        return d.file.Close()
    }
    return nil
}

// StartTunnel starts the VPN tunnel using the provided TUN file descriptor.
// This function connects directly to Cloudflare WARP and forwards all traffic.
//
// Parameters:
//   - configPath: Path to the config.json file
//   - tunFd: The file descriptor of the Android TUN interface
//   - mtu: MTU size (usually 1280)
//   - packetFlow: Interface for writing packets back to Android TUN
//   - callback: State callback interface (can be nil)
//
// Returns:
//   - error string if startup fails, empty string on success
func StartTunnel(configPath string, tunFd int, mtu int, packetFlow PacketFlow, callback VpnStateCallback) string {
	state.mu.Lock()
	defer state.mu.Unlock()

	if state.running {
		return "Tunnel is already running"
	}

    mySessionID := atomic.AddInt64(&currentSessionID, 1)

	log.Printf("StartTunnel called: configPath=%s, tunFd=%d, mtu=%d", configPath, tunFd, mtu)

	// Load config
	if err := config.LoadConfig(configPath); err != nil {
		return fmt.Sprintf("Failed to load config: %v", err)
	}

	// Get keys
	privKey, err := config.AppConfig.GetEcPrivateKey()
	if err != nil {
		return fmt.Sprintf("Failed to get private key: %v", err)
	}
	peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		return fmt.Sprintf("Failed to get peer public key: %v", err)
	}

	// Generate certificate
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return fmt.Sprintf("Failed to generate cert: %v", err)
	}

	// Prepare TLS config with custom SNI
	sni := customSNI
	if sni == "" {
		sni = internal.ConnectSNI
	}
	log.Printf("Using SNI: %s", sni)
	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni, false)
	if err != nil {
		return fmt.Sprintf("Failed to prepare TLS: %v", err)
	}

	// Create Android TUN device wrapper
	tunDevice, err := newAndroidTunDevice(tunFd, mtu, packetFlow)
	if err != nil {
		state.tunDevice = tunDevice
		return fmt.Sprintf("Failed to create TUN device: %v", err)
	}

	// Endpoint — свой, если задан, иначе SelectEndpointFromConfig сам решит,
	// какое поле конфига брать (endpoint_v4/v6 для QUIC, endpoint_h2_v4/v6 для HTTP/2).
    var endpoint net.Addr
    if customEndpoint != "" {
        // Кастомный endpoint используется в обоих режимах — тип адреса ниже
        // подбирается под useHTTP2, так что TCP/UDP не перепутаются.
        host, port, err := parseEndpoint(customEndpoint)
        if err != nil {
            return fmt.Sprintf("Invalid custom endpoint '%s': %v", customEndpoint, err)
        }
        ip := net.ParseIP(host)
		
        if ip == nil {
            return fmt.Sprintf("Invalid custom endpoint IP '%s'", host)
        }
        if useHTTP2 {
            endpoint = &net.TCPAddr{IP: ip, Port: port}
        } else {
            endpoint = &net.UDPAddr{IP: ip, Port: port}
        }
        log.Printf("Using custom endpoint: %s:%d (http2=%v)", host, port, useHTTP2)
    } else {
        var err error
        endpoint, err = config.SelectEndpointFromConfig(useHTTP2, false, 443)
        if err != nil {
            return fmt.Sprintf("Failed to select endpoint: %v", err)
        }
        log.Printf("Using endpoint from config: %s (http2=%v)", endpoint, useHTTP2)
    }

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	state.cancel = cancel

    go func() {
        <-ctx.Done()
        trace("ctx.Done() -> closing stopCh")
        close(tunDevice.stopCh)
    }()
	
	state.running = true
	state.callback = callback

	// Start tunnel maintenance in background
    go func() {
        var lastReportedConnected int32 = -1 // -1 = ещё неизвестно, 0 = не подключено, 1 = подключено
		trace("MaintainTunnel: starting")
		log.Println("Starting MASQUE tunnel...")

        api.MaintainTunnel(ctx, api.MaintainTunnelConfig{
			TLSConfig:         tlsConfig,
            KeepalivePeriod:   30 * time.Second,
            InitialPacketSize: 0,
            Endpoint:          endpoint,
            Device:            tunDevice,
            MTU:               mtu,
            ReconnectDelay:    time.Second,
            UseHTTP2:          useHTTP2,
			AlwaysReconnect:   true,
			OnIPConnEstablished: func(c *connectip.Conn) {
				state.mu.Lock()
				state.ipConn = c
				state.mu.Unlock()
			},
			OnConnectFunc: func() {
    			if atomic.LoadInt64(&currentSessionID) != mySessionID {
        			return
    			}
    			if atomic.SwapInt32(&lastReportedConnected, 1) != 1 && callback != nil {
        			callback.OnConnected()
    			}
			},
			OnDisconnectFunc: func(err error) {
    			if atomic.LoadInt64(&currentSessionID) != mySessionID {
        			return
    			}
			    if atomic.SwapInt32(&lastReportedConnected, 0) != 0 && callback != nil {
        			reason := "tunnel disconnected"
			        if err != nil {
            			reason = err.Error()
			        }
			        callback.OnError(reason)
			    }
			},
        })
		
        // Tunnel exited
		trace("MaintainTunnel: returned")
		log.Println("MASQUE tunnel exited")
		tunDevice.Close()
		trace("tunDevice.Close(): done")

        state.mu.Lock()
        if atomic.LoadInt64(&currentSessionID) == mySessionID {
            state.running = false
        }
        state.mu.Unlock()

        if atomic.LoadInt64(&currentSessionID) == mySessionID && callback != nil {
            callback.OnDisconnected("Tunnel closed")
        }
	}()

	log.Println("Tunnel started successfully")
	return ""
}

// InputPacket sends an IP packet from Android TUN to the Go tunnel.
// This should be called by Android whenever a packet is read from the TUN device.
//
// Parameters:
//   - data: The raw IP packet bytes
func InputPacket(data []byte) {
	state.mu.Lock()
	ch := state.inputChan
	state.mu.Unlock()

	if ch != nil {
		// Non-blocking send
		select {
		case ch <- data:
		default:
			// Channel full, drop packet
		}
	}
}

// StopTunnel stops the running tunnel
func StopTunnel() {
	state.mu.Lock()
	defer state.mu.Unlock()

	if !state.running {
		return
	}

	trace("StopTunnel: called")
	log.Println("Stopping tunnel...")

	if state.cancel != nil {
		state.cancel()
	}
	if state.tunDevice != nil {
		state.tunDevice.Close()
		trace("StopTunnel: tunDevice.Close() direct")
		state.tunDevice = nil
	}
	if state.ipConn != nil {
		state.ipConn.Close()
		trace("StopTunnel: ipConn.Close() direct")
		state.ipConn = nil
	}
	
	state.running = false
}

// IsRunning returns true if the tunnel is currently running
func IsRunning() bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.running
}

// GetVersion returns the library version
func GetVersion() string {
	return "1.0.4-android"
}

// parseEndpoint parses an endpoint string in the format:
// - "host:port" for IPv4 (e.g., "162.159.198.2:443")
// - "[host]:port" for IPv6 (e.g., "[2606:4700:103::2]:443")
// - "host" without port (defaults to 443)
func parseEndpoint(endpoint string) (string, int, error) {
	// Check if it's an IPv6 address with brackets
	if len(endpoint) > 0 && endpoint[0] == '[' {
		// IPv6 format: [host]:port
		closeBracket := -1
		for i, c := range endpoint {
			if c == ']' {
				closeBracket = i
				break
			}
		}
		if closeBracket == -1 {
			return "", 0, fmt.Errorf("missing closing bracket for IPv6 address")
		}

		host := endpoint[1:closeBracket]

		// Check for port after bracket
		if closeBracket+1 < len(endpoint) && endpoint[closeBracket+1] == ':' {
			portStr := endpoint[closeBracket+2:]
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return "", 0, fmt.Errorf("invalid port: %s", portStr)
			}
			return host, port, nil
		}

		// No port, use default
		return host, 443, nil
	}

	// IPv4 or hostname format
	lastColon := -1
	for i := len(endpoint) - 1; i >= 0; i-- {
		if endpoint[i] == ':' {
			lastColon = i
			break
		}
	}

	if lastColon != -1 {
		// Has port
		host := endpoint[:lastColon]
		portStr := endpoint[lastColon+1:]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port: %s", portStr)
		}
		return host, port, nil
	}

	// No port, use default
	return endpoint, 443, nil
}

// ============================================
// Connection Configuration Functions
// ============================================

// SetSNI sets a custom SNI for the TLS connection.
// This can help with censorship circumvention.
// Default is "speed.cloudflare.com". Pass empty string to use Cloudflare's default.
func SetSNI(sni string) {
	customSNI = sni
	log.Printf("SNI set to: %s", sni)
}

// GetSNI returns the current SNI setting
func GetSNI() string {
	return customSNI
}

// SetEndpoint sets a custom endpoint for the MASQUE connection.
// Supports the following formats:
//   - "162.159.198.2" (IPv4, default port 443)
//   - "162.159.198.2:443" (IPv4 with custom port)
//   - "[2606:4700:103::2]" (IPv6, default port 443)
//   - "[2606:4700:103::2]:443" (IPv6 with custom port)
//
// Pass empty string to use the default endpoint from config.json.
func SetEndpoint(endpoint string) {
	customEndpoint = endpoint
	log.Printf("Custom endpoint set to: %s", endpoint)
}

// GetEndpoint returns the current custom endpoint setting
func GetEndpoint() string {
	return customEndpoint
}

// GetDefaultEndpoint returns the default endpoint from config (IPv4:443)
func GetDefaultEndpoint(configPath string, http2 bool) string {
    if err := config.LoadConfig(configPath); err != nil {
        return ""
    }
    if http2 {
        v4 := config.AppConfig.EndpointH2V4
        if v4 == "" {
            v4 = config.DefaultEndpointH2V4 // константа "162.159.198.2" из config/endpoints.go
        }
        return v4 + ":443"
    }
    return config.AppConfig.EndpointV4 + ":443"
}

// SetUseHttp2 включает TCP+HTTP/2-транспорт вместо QUIC/HTTP-3 — полезно,
// когда QUIC/UDP заблокирован на уровне сети. Использует endpoint_h2_v4/
// endpoint_h2_v6 из config.json (если не заданы — дефолт 162.159.198.2).
func SetUseHttp2(enabled bool) {
	useHTTP2 = enabled
	log.Printf("HTTP/2 transport set to: %v", enabled)
}

func GetUseHttp2() bool {
	return useHTTP2
}

func GetLicenseKey(configPath string) string {
    if err := config.LoadConfig(configPath); err != nil { return "" }
    account, err := api.GetAccount(config.AppConfig.ID, config.AppConfig.AccessToken)
    if err != nil { return "" }
    return account.License
}

func SetLicenseKey(configPath string, key string) string {
    if err := config.LoadConfig(configPath); err != nil { return err.Error() }
    if err := api.UpdateLicenceKey(config.AppConfig.ID, config.AppConfig.AccessToken, key); err != nil {
        return err.Error()
    }
    return ""
}

func RemoveLicenseKey(configPath string) string {
    if err := config.LoadConfig(configPath); err != nil { return err.Error() }
    if err := api.DeleteLicenceKey(config.AppConfig.ID, config.AppConfig.AccessToken); err != nil {
        return err.Error()
    }
    return ""
}

// ResetConnectionOptions resets all connection options to defaults
func ResetConnectionOptions() {
	customSNI = "speed.cloudflare.com"
	customEndpoint = ""
	useHTTP2 = false
	log.Println("Connection options reset to defaults")
}

// ============================================
// Alternative: File Descriptor based approach
// ============================================

// StartTunnelWithFd starts the tunnel by reading/writing directly to the TUN fd.
// This is simpler but requires the TUN fd to be readable/writable from Go.
func StartTunnelWithFd(configPath string, tunFd int, callback VpnStateCallback) string {
	return StartTunnel(configPath, tunFd, 1280, nil, callback)
}

// fdReadWriter wraps a file descriptor for io.ReadWriter
type fdReadWriter struct {
	file *os.File
}

func (f *fdReadWriter) Read(p []byte) (n int, err error) {
	return f.file.Read(p)
}

func (f *fdReadWriter) Write(p []byte) (n int, err error) {
	return f.file.Write(p)
}

// CreateTunReadWriter creates an io.ReadWriter from a TUN file descriptor
func CreateTunReadWriter(fd int) io.ReadWriter {
	file := os.NewFile(uintptr(fd), "tun")
	return &fdReadWriter{file: file}
}
