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
	"sync"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
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
}

var state = &tunnelState{}

// Custom connection options
var (
	customSNI      = "my.mail.ru" // Default SNI for censorship circumvention
	customEndpoint = ""          // Custom endpoint with port, e.g. "162.159.198.2:443" or "[2606:4700:103::]:2408"
	useHTTP2       = false       // Use TCP+HTTP/2 transport instead of QUIC/HTTP-3 (needs endpoint_h2_v4/v6 in config.json)
)

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

// AndroidTunDevice wraps the Android TUN file descriptor for packet IO
type AndroidTunDevice struct {
	fd       int
	file     *os.File
	mtu      int
	inputCh  chan []byte
	outputFn PacketFlow
}

// NewAndroidTunDevice creates a new Android TUN device wrapper
func newAndroidTunDevice(fd int, mtu int, packetFlow PacketFlow) (*AndroidTunDevice, error) {
	// Create a file from the file descriptor
	file := os.NewFile(uintptr(fd), "tun")
	if file == nil {
		return nil, fmt.Errorf("failed to create file from fd %d", fd)
	}

	return &AndroidTunDevice{
		fd:       fd,
		file:     file,
		mtu:      mtu,
		inputCh:  make(chan []byte, 256),
		outputFn: packetFlow,
	}, nil
}

func (d *AndroidTunDevice) ReadPacket(buf []byte) (int, error) {
	n, err := d.file.Read(buf)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (d *AndroidTunDevice) WritePacket(pkt []byte) error {
	if d.outputFn != nil {
		// Use the callback to write to Android TUN
		d.outputFn.WritePacket(pkt)
		return nil
	}
	// Fallback to direct write
	_, err := d.file.Write(pkt)
	return err
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
		return fmt.Sprintf("Failed to create TUN device: %v", err)
	}

	// Endpoint — свой, если задан, иначе SelectEndpointFromConfig сам решит,
	// какое поле конфига брать (endpoint_v4/v6 для QUIC, endpoint_h2_v4/v6 для HTTP/2).
	var endpoint net.Addr
	if customEndpoint != "" {
		// Parse custom endpoint (supports host:port format)
		host, port, err := parseEndpoint(customEndpoint)
		if err != nil {
			return fmt.Sprintf("Invalid custom endpoint '%s': %v", customEndpoint, err)
		}
		if useHTTP2 {
			endpoint = &net.TCPAddr{IP: net.ParseIP(host), Port: port}
		} else {
			endpoint = &net.UDPAddr{IP: net.ParseIP(host), Port: port}
		}
		log.Printf("Using custom endpoint: %s:%d (http2=%v)", host, port, useHTTP2)
	} else {
		var err error
		// Use default from config (IPv4)
		endpoint, err = config.SelectEndpointFromConfig(useHTTP2, false, 443)
		if err != nil {
			return fmt.Sprintf("Failed to select endpoint: %v", err)
		}
		log.Printf("Using endpoint from config: %s (http2=%v)", endpoint, useHTTP2)
	}

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	state.cancel = cancel
	state.running = true
	state.callback = callback

	// Start tunnel maintenance in background
	go func() {
		log.Println("Starting MASQUE tunnel...")

/*
		// Notify connected after a brief delay for connection establishment
		go func() {
			time.Sleep(3 * time.Second)
			state.mu.Lock()
			running := state.running
			state.mu.Unlock()
			if running && callback != nil {
				callback.OnConnected()
			}
		}()
*/

		api.MaintainTunnel(ctx, api.MaintainTunnelConfig{
            TLSConfig:         tlsConfig,
            KeepalivePeriod:   30 * time.Second,
            InitialPacketSize: 1242,
            Endpoint:          endpoint,
            Device:            tunDevice,
            MTU:               mtu,
            ReconnectDelay:    time.Second,
            UseHTTP2:          useHTTP2,
            OnConnectFunc: func() {
                if callback != nil {
                    callback.OnConnected()
                }
            },
            OnDisconnectFunc: func(err error) {
                if callback != nil {
                    reason := "tunnel disconnected"
                    if err != nil {
                        reason = err.Error()
                    }
                    callback.OnError(reason)
                }
            },
        })
		
		// Tunnel exited
		log.Println("MASQUE tunnel exited")
		tunDevice.Close()

		state.mu.Lock()
		state.running = false
		state.mu.Unlock()

		if callback != nil {
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

	log.Println("Stopping tunnel...")

	if state.cancel != nil {
		state.cancel()
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
// - "[host]:port" for IPv6 (e.g., "[2606:4700:103::]:2408")
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
// Default is "my.mail.ru". Pass empty string to use Cloudflare's default.
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
//   - "162.159.198.2:2408" (IPv4 with custom port)
//   - "[2606:4700:103::]" (IPv6, default port 443)
//   - "[2606:4700:103::]:2408" (IPv6 with custom port)
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
func GetDefaultEndpoint(configPath string) string {
	if err := config.LoadConfig(configPath); err == nil {
		return config.AppConfig.EndpointV4 + ":443"
	}
	return ""
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

// ResetConnectionOptions resets all connection options to defaults
func ResetConnectionOptions() {
	customSNI = "my.mail.ru"
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
