#!/bin/bash
# GitHub Release Instructions for SShell v1.5.0

echo "=========================================="
echo "SShell GitHub Setup Instructions"
echo "=========================================="
echo ""
echo "Step 1: Create GitHub Repository"
echo "---------------------------------"
echo "1. Go to https://github.com/new"
echo "2. Repository name: sshell"
echo "3. Description: Next-generation terminal multiplexer"
echo "4. Public repository"
echo "5. Do NOT initialize with README"
echo "6. Click 'Create repository'"
echo ""
echo "Step 2: Add Remote and Push"
echo "---------------------------"
echo "Run these commands:"
echo ""
echo "  cd /projects/sshell"
echo "  git remote add origin https://github.com/d31337m3/sshell.git"
echo "  git push -u origin master"
echo "  git push --tags"
echo ""
echo "Step 3: Create GitHub Release"
echo "-----------------------------"
echo "1. Go to: https://github.com/d31337m3/sshell/releases/new"
echo "2. Tag: v1.5.0"
echo "3. Release title: SShell v1.5.0 - Phase 5 Complete"
echo "4. Description:"
echo ""
cat << 'EOF'
## 🚀 SShell v1.5.0 - Phase 5 Complete

The next-generation terminal multiplexer with competitive features!

### ✨ New in v1.5.0

- 🌐 **Network Roaming** - Mosh-like UDP heartbeat
- 🎬 **Session Recording** - Built-in asciicast v2 support
- 👥 **Multi-User Sessions** - Collaborative terminals
- 🌐 **Web Viewer** - Browser access with MetaMask auth

### 📦 Downloads

- **Linux:** `sshell-linux-x86_64-v1.5.0.zip` (33 KB)
- **Windows:** `sshell-windows-x86_64-v1.5.0.zip` (101 KB)

### 🚀 Quick Install

```bash
curl -sSL https://d31337m3.com/sshell/install.sh | bash
```

Or download binaries from the assets below.

### 📝 Checksums

See `SHA256SUMS` file in assets.

### 🎯 What's Special?

- Smallest binary (82KB vs 800KB+ competitors)
- All-in-one solution (sessions + recording + collaboration)
- Blockchain authentication (MetaMask)
- Zero configuration required

Full documentation: https://github.com/d31337m3/sshell
EOF
echo ""
echo "5. Upload these files as release assets:"
echo "   - releases/sshell-linux-x86_64-v1.5.0.zip"
echo "   - releases/sshell-windows-x86_64-v1.5.0.zip"
echo "   - releases/SHA256SUMS"
echo ""
echo "6. Click 'Publish release'"
echo ""
echo "Step 4: Update Website URLs"
echo "---------------------------"
echo "After creating the GitHub release, update these files:"
echo ""
echo "1. /projects/sshell/install.sh"
echo "   - Line 6: RELEASE_URL=\"https://github.com/USERNAME/sshell/releases/download/v1.5.0/sshell-linux-x86_64-v1.5.0.zip\""
echo ""
echo "2. /var/www/d31337m3.com/sshell/index.html"
echo "   - Update GitHub links from 'yourusername' to your actual username"
echo ""
echo "3. /projects/sshell/README.md"
echo "   - Update all GitHub URLs"
echo ""
echo "Step 5: Test Installation"
echo "-------------------------"
echo "Test the installer script:"
echo ""
echo "  curl -sSL https://d31337m3.com/sshell/install.sh | bash"
echo ""
echo "Step 6: Announce!"
echo "-----------------"
echo "Share on:"
echo "- Twitter/X"
echo "- Reddit (r/commandline, r/linux)"
echo "- Hacker News"
echo "- Dev.to"
echo ""
echo "=========================================="
echo "Repository ready for GitHub!"
echo "=========================================="
