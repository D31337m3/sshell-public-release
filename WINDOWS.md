# Windows Build Instructions

## Building SShell for Windows

### Prerequisites
- MinGW-w64 (GCC for Windows)
- Make for Windows

### Build Commands

```bash
# Using MinGW on Linux (cross-compile)
x86_64-w64-mingw32-gcc -o sshell.exe c-src/client/client_windows.c -lws2_32

# On Windows with MinGW
gcc -o sshell.exe c-src/client/client_windows.c -lws2_32
```

### Notes
- Windows version uses Named Pipes instead of Unix sockets
- Currently supports basic commands (list, attach, kill)
- Full PTY support requires Windows 10+ ConPTY API (Linux Port is more viable, use under Windows WSL)
- For full functionality, use linux version under WSL (Windows Subsystem for Linux) on Windows 10 or newer.

### Recommended: Use WSL
For the best experience on Windows, we recommend running SShell in WSL:

```powershell
# Install WSL
wsl --install

# Inside WSL
curl -sSL https://d31337m3.com/sshell/install.sh | bash
```

## Creating Windows Release

```bash
# Cross-compile from Linux
apt-get install mingw-w64
x86_64-w64-mingw32-gcc -o sshell.exe c-src/client/client_windows.c -lws2_32 -static
zip sshell-windows-x86_64-v1.5.0.zip sshell.exe
```
