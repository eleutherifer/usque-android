# Usque VPN for Android

A native Android VPN application powered by Cloudflare WARP using the MASQUE protocol.

## Features

- 🔒 **Secure VPN** - Uses Cloudflare WARP infrastructure
- 🌐 **Dual Stack** - Full IPv4 and IPv6 support
- 🔧 **Customizable** - Configure SNI and endpoints for censorship circumvention
- 📱 **Native Android** - Built with Kotlin and Android VpnService
- ⚡ **Fast** - MASQUE/QUIC protocol for optimal performance

## Prerequisites

1. **Build the Go library first:**
   ```bash
   cd ../
   make android
   ```

2. **Copy the AAR to libs:**
   ```bash
   mkdir -p app/libs
   cp ../usque.aar app/libs/
   ```

3. **Android Studio** or Gradle 8.5+

## Building

### From Android Studio
1. Open this directory in Android Studio
2. Sync Gradle
3. Build → Build APK

### From Command Line
```bash
./gradlew assembleDebug
# or
./gradlew assembleRelease
```

Output: `app/build/outputs/apk/debug/app-debug.apk`

## Usage

1. **First Launch**: App will automatically register with Cloudflare WARP
2. **Connect**: Tap the "Connect" button
3. **Settings**: Configure SNI and endpoints before connecting

### Settings Options

| Option | Description | Default |
|--------|-------------|---------|
| SNI | Server Name Indication for TLS | `apteka.ru` |
| IPv4 Endpoint | WARP server IPv4 | From registration |
| IPv6 Endpoint | WARP server IPv6 | From registration |
| Use IPv6 | Connect via IPv6 endpoint | Off |

## Architecture

```
┌─────────────────────────────────────────┐
│           Android App (Kotlin)          │
├─────────────────────────────────────────┤
│  MainActivity     │  UsqueVpnService    │
│  - Settings UI    │  - TUN interface    │
│  - Connect/Stop   │  - VPN lifecycle    │
└─────────┬─────────┴──────────┬──────────┘
          │                    │
          │    usque.aar       │
          │   (Go Library)     │
          ▼                    ▼
┌─────────────────────────────────────────┐
│         usqueandroid Package            │
│  - StartTunnel()  - SetSNI()            │
│  - StopTunnel()   - SetEndpointV4/V6()  │
│  - Register()     - GetAssignedIP()     │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│         Cloudflare WARP Network         │
│            (MASQUE/QUIC)                │
└─────────────────────────────────────────┘
```

## Project Structure

```
usque-vpn/
├── app/
│   ├── libs/                    # usque.aar goes here
│   ├── src/main/
│   │   ├── kotlin/.../
│   │   │   ├── MainActivity.kt      # Main UI
│   │   │   └── UsqueVpnService.kt   # VPN service
│   │   ├── res/                 # Layouts, drawables
│   │   └── AndroidManifest.xml
│   └── build.gradle.kts
├── build.gradle.kts
├── settings.gradle.kts
└── README.md
```

## Troubleshooting

### VPN won't connect
- Check if another VPN is active
- Verify internet connection
- Try changing the endpoint

### No IPv6
- Ensure your network supports IPv6
- Check if IPv6 address was assigned in registration

### Settings reset after restart
- Settings are saved in SharedPreferences
- If issue persists, check app storage permissions

## License

MIT License - See [LICENSE](../LICENSE.md)
