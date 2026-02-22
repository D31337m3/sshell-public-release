# 🚀 SShell - The Next-Generation Terminal Multiplexer

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.6.3-blue.svg)](https://github.com/d31337m3/sshell-public-release/releases)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](https://github.com/d31337m3/sshell-public-release)

**Persistent sessions + Network roaming + Recording + Multi-user + Web viewer**

SShell is a feature-rich terminal multiplexer that combines the best of tmux, screen, mosh, and tmate - with unique competitive features.

## ✨ Key Features

### 🌐 Network Roaming
Mosh-like UDP heartbeat keeps connections alive through network changes
- Survives WiFi switching, VPN reconnections, mobile roaming
- 1-second heartbeat interval, 60-second timeout
- Zero configuration required

### 🎬 Session Recording
Built-in asciicast v2 recording
```bash
sshell rec-start my-session
sshell rec-stop my-session

# Playback (separate tiny tool)
sshell-player ~/.sshell/recordings/<file>.cast 1.5  # 1.5x speed
```

### 👥 Multi-User Sessions
True collaborative terminals
```bash
# User 1 (inviter): enable sharing (prints a share token)
sshell --share my-session@host-name.com

# User 2 (guest): join using token@host
sshell share-XXXXXXXX@host-name.com

# Inviter: stop sharing (disconnects guests)
sshell --stopshare my-session@host-name.com
```

### 🌐 Web Viewer
Access terminals from any browser
- No SSH client required
- MetaMask wallet authentication
- Live WebSocket streaming
- http://localhost:8080

> **Thread safety:** The web terminal uses `daemon_lookup_session_id()` (copies the session ID under a mutex) to safely pass session references to the HTTP/WebSocket handler thread, preventing use-after-free on concurrent session operations.

## 📦 Installation

### Quick Install (Linux/macOS)
```bash
# Interactive wizard (recommended — guides you through network, auth, and feature choices)
curl -sSL https://d31337m3.com/sshell/install.sh | bash

# Non-interactive / scripted installs — uses safe defaults, no prompts
curl -sSL https://d31337m3.com/sshell/install.sh | bash -s -- -y

# Server install — adds the daemon with safe defaults
curl -sSL https://d31337m3.com/sshell/install.sh | bash -s -- --daemon
```

The interactive wizard guides you through five steps: install type, network binding, authentication method, optional features (web terminal, roaming, systemd autostart), and a confirmation summary. It writes a fully configured `~/.sshell/daemon.json` from your answers.

### Manual Download
- [Linux (x86_64)](https://d31337m3.com/sshell-public-release/) - 33KB (also works inside WSL)
- Windows: native daemon is not currently shipped; use WSL for full functionality, or build the limited `sshell.exe` client (see WINDOWS.md)
- [Checksums](https://d31337m3.com/sshell/SHA256SUMS)

### Build from Source
```bash
# Install dependencies (Debian/Ubuntu)
sudo apt-get install -y gcc libjson-c-dev libwebsockets-dev \
  libmicrohttpd-dev libssl-dev libsecp256k1-dev

# Clone and build
git clone https://github.com/d31337m3/sshell.git
cd sshell
make && sudo make install
```

## 🎮 Quick Start

```bash
# Create new session
sshell

# Create named session
sshell new my-task

# List sessions
sshell list

# Attach to session
sshell attach my-task

# Detach from session (press keys)
Ctrl+B then 'd'

# Kill session
sshell kill my-task
```

## 🔥 Advanced Usage

### Session Recording
```bash
# Start recording
sshell rec-start my-session

# Stop recording
sshell rec-stop my-session

# Playback (default speed)

### Daemon presets
If present, the daemon reads `~/.sshell/daemon.json` on startup for defaults (CLI flags still override).
Example:
```json
{
  "mode": "tcp",
  "host": "0.0.0.0",
  "port": 7444,
  "auth_required": true,
  "wallet": "0x...",
  "wallet_allowlist": "~/.sshell/allowed_wallets.txt",
  "web_enabled": false,
  "web_port": 8080,
  "roaming": true,
  "log_level": "info"
}
```
sshell play my-session

# Playback at 2x speed
sshell play my-session 2.0
```

### Multi-User Collaboration
```bash
# User 1: Create and share session
sshell new collab-session
sshell --share collab-session@host-name.com
# Output: share-4Tl3TR7OFnmtkb6VEUBOhw

# User 2: Join session
sshell share-4Tl3TR7OFnmtkb6VEUBOhw@host-name.com
# Both users now see same terminal, both can type

# User 1: Revoke sharing (kicks guests)
sshell --stopshare collab-session@host-name.com
```

### Web Viewer
```bash
# Daemon automatically starts web server on port 8080
# Open browser to: http://localhost:8080

# Access specific session:
# http://localhost:8080?session=my-session

# Click "Connect MetaMask" to authenticate
```

## 🎯 Why SShell?

| Feature | tmux | screen | mosh | tmate | **SShell** |
|---------|------|--------|------|-------|------------|
| Session Persistence | ✅ | ✅ | ❌ | ❌ | ✅ |
| Network Roaming | ❌ | ❌ | ✅ | ❌ | ✅ |
| Session Recording | ❌ | ❌ | ❌ | ❌ | ✅ |
| Multi-User Sessions | ⚠️ | ⚠️ | ❌ | ✅ | ✅ |
| Web Viewer | ❌ | ❌ | ❌ | ❌ | ✅ |
| Blockchain Auth | ❌ | ❌ | ❌ | ❌ | ✅ |
| Binary Size | 800KB | 600KB | 1.2MB | N/A | **82KB** |

## 📊 Performance

- **Binary Size:** 82 KB total (43KB daemon + 39KB client)
- **Memory:** <1 MB per session
- **Attach Latency:** <5ms
- **I/O Throughput:** >50 MB/s

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│            SShell Daemon                │
├─────────────────────────────────────────┤
│  ┌──────────────┐  ┌─────────────────┐ │
│  │ Unix Socket  │  │ UDP Port 60001  │ │
│  │ (IPC)        │  │ (Roaming)       │ │
│  └──────┬───────┘  └────────┬────────┘ │
│         │                    │          │
│  ┌──────▼────────────────────▼────────┐ │
│  │   Session Manager                  │ │
│  │   - PTY Management                 │ │
│  │   - Recording (per session)        │ │
│  │   - Multi-user (per session)       │ │
│  └──────────────┬─────────────────────┘ │
│                 │                        │
│  ┌──────────────▼─────────────────────┐ │
│  │ HTTP/WebSocket Server (8080)       │ │
│  │ - xterm.js Frontend                │ │
│  │ - MetaMask Authentication          │ │
│  └────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

## 📖 Documentation

- [Complete Features](FEATURES.md) - Detailed feature overview
- [Security Notes](SECURITY.md) - Recommended safe defaults for TCP mode
- [Windows Support](WINDOWS.md) - Windows build instructions
- Man pages: `man sshell`, `man sshell-daemon`

## 🔧 Configuration

Config file: `~/.sshell/config.json`
```json
{
  "socket_path": "/run/user/1000/sshell.sock",
  "log_level": "info",
  "max_sessions": 100,
  "session_timeout": 86400,
  "roaming_port": 60001,
  "web_port": 8080
}
```

## 🤝 Contributing

Contributions welcome! Areas of interest:
- Performance optimizations
- Security enhancements
- Platform support (macOS, BSD)
- Documentation improvements
- Test coverage

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🙏 Acknowledgments

Inspired by:
- **tmux** - The terminal multiplexer standard
- **screen** - The original multiplexer
- **mosh** - Mobile shell with roaming
- **tmate** - Terminal sharing
- **asciinema** - Terminal recording

## 📞 Support

- GitHub Issues: https://github.com/d31337m3/sshell/issues
- Website: https://d31337m3.com/sshell
- Email: sshell@d31337m3.com

---

**SShell** - The terminal multiplexer for the modern age 🚀

Built with ❤️ in C | Version 1.6.3 | © 2026
