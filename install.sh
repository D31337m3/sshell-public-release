#!/bin/bash
# Quick installer for SShell

set -e

VERSION="1.5.0"
RELEASE_URL="https://github.com/d31337m3/sshell/releases/download/v${VERSION}/sshell-linux-x86_64-v${VERSION}.zip"

echo "=========================================="
echo "SShell Installer v${VERSION}"
echo "=========================================="
echo ""

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
chmod +x sshell sshell-daemon
mv sshell "$INSTALL_DIR/"
mv sshell-daemon "$INSTALL_DIR/"

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
echo "  sshell-daemon       # Start daemon"
echo ""
echo "For more info: https://github.com/d31337m3/sshell"
echo ""
