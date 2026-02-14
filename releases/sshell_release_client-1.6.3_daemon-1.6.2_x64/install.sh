#!/bin/bash
# Quick installer for SShell

set -euo pipefail

VERSION="1.6.1"
RELEASE_URL="https://github.com/d31337m3/sshell/releases/download/v${VERSION}/sshell-linux-x86_64-v${VERSION}.zip"

WITH_DAEMON=0
ENABLE_DAEMON=0
WRITE_DAEMON_CONFIG=1

for arg in "$@"; do
    case "$arg" in
        --daemon)
            WITH_DAEMON=1
            ;;
        --enable-daemon)
            WITH_DAEMON=1
            ENABLE_DAEMON=1
            ;;
        --help|-h)
            echo "Usage: $0 [--daemon] [--enable-daemon] [--no-config]";
            exit 0
            ;;
        --no-config)
            WRITE_DAEMON_CONFIG=0
            ;;
    esac
done

echo "=========================================="
echo "SShell Installer v${VERSION}"
echo "=========================================="
echo ""

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

install_deps_apt() {
    echo "Installing build/runtime dependencies via apt..."
    apt-get update -y
    apt-get install -y \
        curl unzip ca-certificates \
        libjson-c-dev libwebsockets-dev libmicrohttpd-dev libssl-dev libsecp256k1-dev
}

ensure_deps() {
    if need_cmd unzip && (need_cmd curl || need_cmd wget); then
        return 0
    fi

    if [ "$EUID" -ne 0 ]; then
        echo "Error: missing prerequisites (need unzip and curl/wget). Run with sudo to auto-install deps on Debian/Ubuntu." >&2
        exit 1
    fi

    if need_cmd apt-get; then
        install_deps_apt
        return 0
    fi

    echo "Error: unsupported package manager for auto-install. Please install: unzip + curl/wget + required libs." >&2
    exit 1
}

ensure_deps

target_home() {
    if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        # Best-effort: pick sudo user home.
        getent passwd "$SUDO_USER" | cut -d: -f6
        return 0
    fi
    echo "$HOME"
}

write_default_daemon_json() {
    if [ "$WRITE_DAEMON_CONFIG" -ne 1 ]; then
        return 0
    fi

    local home
    home="$(target_home)"
    if [ -z "$home" ]; then
        return 0
    fi

    local cfg_dir="$home/.sshell"
    local cfg_file="$cfg_dir/daemon.json"

    mkdir -p "$cfg_dir"

    if [ -f "$cfg_file" ]; then
        echo "Found existing $cfg_file (leaving unchanged)"
        return 0
    fi

    cat > "$cfg_file" <<'JSON'
{
    "mode": "tcp",
    "host": "0.0.0.0",
    "port": 7444,
    "ufw_auto": true,
    "auth_required": true,
    "log_level": "info"
}
JSON

    chmod 600 "$cfg_file" || true
    echo "Wrote default daemon preset: $cfg_file"
}

# Check if running as root for system-wide install
if [ "$EUID" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
    echo "Installing system-wide to ${INSTALL_DIR}"
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    echo "Installing to ${INSTALL_DIR}"
fi

# Download and extract
echo "Downloading SShell v${VERSION}..."
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

if command -v curl &> /dev/null; then
    curl -L -o sshell.zip "$RELEASE_URL"
elif command -v wget &> /dev/null; then
    wget -O sshell.zip "$RELEASE_URL"
else
    echo "Error: Neither curl nor wget found. Please install one."
    exit 1
fi

echo "Extracting..."
unzip -q sshell.zip

echo "Installing binaries..."
chmod +x sshell
mv sshell "$INSTALL_DIR/"

if [ -f sshell-player ]; then
    chmod +x sshell-player
    mv sshell-player "$INSTALL_DIR/"
fi

if [ "$WITH_DAEMON" -eq 1 ]; then
    if [ ! -f sshell-daemon ]; then
        echo "Error: release archive did not contain sshell-daemon" >&2
        exit 1
    fi
    chmod +x sshell-daemon
    mv sshell-daemon "$INSTALL_DIR/"
fi

write_default_daemon_json

cd /
rm -rf "$TMP_DIR"

echo ""
echo "=========================================="
echo "✅ Installation complete!"
echo "=========================================="
echo ""
echo "Binaries installed to: $INSTALL_DIR"
echo ""
echo "Quick Start:"
echo "  sshell              # Create new session"
echo "  sshell list         # List sessions"
echo "  sshell-daemon       # Start daemon (if installed)"
echo "  sshell rec-start S  # Start recording"
echo "  sshell-player FILE  # Playback recording"
echo ""

if [ "$WITH_DAEMON" -eq 1 ] && [ "$ENABLE_DAEMON" -eq 1 ]; then
    echo "Configuring daemon autostart (systemd user service)..."

    if ! need_cmd systemctl; then
        echo "Warning: systemctl not found; skipping autostart enable." >&2
        exit 0
    fi

    if [ ! -d "$HOME/.config/systemd/user" ]; then
        mkdir -p "$HOME/.config/systemd/user"
    fi

    cat > "$HOME/.config/systemd/user/sshell.service" <<EOF
[Unit]
Description=SShell Persistent Session Daemon
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/sshell-daemon --no-fork
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=default.target
EOF

    systemctl --user daemon-reload || true
    systemctl --user enable --now sshell.service || true
    echo "Autostart requested. If this is WSL or systemd isn't running, you may need to start the daemon manually." >&2
fi

echo "For more info: https://github.com/d31337m3/sshell"
echo ""
