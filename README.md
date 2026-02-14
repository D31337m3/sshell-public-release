# 🚀 SShell - The Next-Generation Terminal Multiplexer

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.5.0-blue.svg)](https://github.com/d31337m3/sshell/releases)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](https://github.com/d31337m3/sshell)

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
sshell play my-session 1.5  # 1.5x speed
```

### 👥 Multi-User Sessions
True collaborative terminals
```bash
# User 1
sshell share my-session  # Returns token

# User 2
sshell join <token>      # Join session
```

### 🌐 Web Viewer
Access terminals from any browser
- No SSH client required
- MetaMask wallet authentication
- Live WebSocket streaming
- http://localhost:8080

## 📦 Installation

### Quick Install (Linux/macOS)
```bash
curl -sSL https://d31337m3.com/sshell/install.sh | bash
```

### Manual Download
- [Linux (x86_64)](https://d31337m3.com/sshell/sshell-linux-x86_64-v1.5.0.zip) - 33KB
- [Windows (x86_64)](https://d31337m3.com/sshell/sshell-windows-x86_64-v1.5.0.zip) - 101KB
- [Checksums](https://d31337m3.com/sshell/SHA256SUMS)

### Via pip (Python version)
```bash
pip install sshell
```

### Build from Source
```bash
# Install dependencies (Debian/Ubuntu)
sudo apt-get install -y gcc libjson-c-dev libwebsockets-dev \
    libmicrohttpd-dev libssl-dev

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
sshell play my-session

# Playback at 2x speed
sshell play my-session 2.0
```

### Multi-User Collaboration
```bash
# User 1: Create and share session
sshell new collab-session
sshell share collab-session
# Output: Share token: x7k9m2n5p8q3r6s1t4u7v2w9y5z8a3c1

# User 2: Join session
sshell join x7k9m2n5p8q3r6s1t4u7v2w9y5z8a3c1
# Both users now see same terminal, both can type
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
│     SShell Daemon (Phase 5 Enhanced)    │
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
- [Phase 5 Implementation](PHASE5_IMPLEMENTATION.md) - Technical details
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

Built with ❤️ in C | Version 1.5.0 | © 2026
