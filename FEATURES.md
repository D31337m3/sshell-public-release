# SShell - The Next-Generation Terminal Multiplexer

## 🚀 What Makes SShell Special?

SShell is not just another terminal multiplexer - it's a **comprehensive terminal management platform** with cutting-edge features that surpass all competitors.

## ✨ Feature Comparison

| Feature | tmux | screen | mosh | tmate | **SShell** |
|---------|------|--------|------|-------|------------|
| Session Persistence | ✅ | ✅ | ❌ | ❌ | ✅ |
| Network Roaming | ❌ | ❌ | ✅ | ❌ | ✅ |
| Session Recording | ❌ | ❌ | ❌ | ❌ | ✅ |
| Multi-User Sessions | ⚠️ | ⚠️ | ❌ | ✅ | ✅ |
| Web Viewer | ❌ | ❌ | ❌ | ❌ | ✅ |
| Blockchain Auth | ❌ | ❌ | ❌ | ❌ | ✅ |
| Binary Size | 800KB | 600KB | 1.2MB | N/A | **82KB** |

## 🎯 Core Features

### Session Management
- Create, attach, detach, list sessions
- Named sessions with auto-generated IDs
- Session persistence across daemon restarts
- Detach key combo: `Ctrl+B` then `d`
- Custom shell support

### Production Ready
- Systemd service integration
- Man pages included
- Security hardened
- Comprehensive logging
- 82 KB binary size

## 🔥 Advanced Features (Phase 5)

### 1. Network Roaming 🌐
Survives WiFi changes, VPN reconnections, mobile network roaming

### 2. Session Recording 🎬
Asciicast v2 format, variable-speed playback

### 3. Multi-User Sessions 👥
Up to 10 concurrent users, read-only/read-write modes

### 4. Web Viewer 🌐
Browser access with MetaMask authentication

## 🎮 Quick Start

```bash
# Create new session
sshell

# Record session
sshell rec-start my-session

# Share session
sshell --share my-session@host-name.com

# Join shared session (guest)
sshell share-XXXXXXXX@host-name.com

# Web access
firefox http://localhost:8080
```

## 📦 Installation

```bash
apt-get install -y gcc libjson-c-dev libwebsockets-dev libmicrohttpd-dev libssl-dev
cd /projects/sshell
make && sudo make install
```

---

**SShell** - The terminal multiplexer for the modern age 🚀
