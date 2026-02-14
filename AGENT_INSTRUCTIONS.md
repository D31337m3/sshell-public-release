# SShell (Sticky Shell) - Agent Development Instructions

## Project Overview
**Name:** SShell (Sticky Shell)  
**Purpose:** A persistent shell session manager that survives SSH disconnections and allows users to reconnect to ongoing sessions at any time.  
**Initial Language:** Python (for rapid development)  
**Target Language:** C (for production binary compilation)  
**Execution Context:** CLI tool invoked during active SSH sessions

---

## Core Problem Statement
Standard SSH sessions are ephemeral - when a connection drops due to network issues, timeout, or logout, all running processes terminate and session state is lost. SShell solves this by creating persistent shell environments that:
- Survive network disconnections
- Persist across login/logout events
- Allow reconnection to in-progress tasks
- Enable asynchronous task delegation to remote servers

---

## Technical Requirements

### 1. Core Functionality

#### Session Persistence
- **Requirement:** Shell sessions must persist independently of SSH connection state
- **Implementation Strategy:** 
  - Leverage existing terminal multiplexer concepts (tmux/screen model)
  - Create detached shell processes that run under a session daemon
  - Maintain session metadata (ID, creation time, last access, process tree)
  - Store session state in filesystem or shared memory

#### Session Management
- **Create Sessions:** `sshell` or `sshell new [session-name]`
- **List Sessions:** `sshell list` or `sshell ls`
- **Attach to Session:** `sshell attach [session-name/id]`
- **Detach from Session:** Keyboard shortcut (e.g., Ctrl+B then D) or connection loss
- **Kill Session:** `sshell kill [session-name/id]`
- **Rename Session:** `sshell rename [old-name] [new-name]`

#### Process Isolation
- Each session runs in isolated PTY (pseudo-terminal)
- Sessions must not interfere with each other
- Parent process must survive SSH connection termination
- Child processes inherit session isolation

### 2. Architecture Design

#### Component Structure
```
sshell/
├── daemon/          # Background session manager
│   ├── manager.py   # Session lifecycle management
│   ├── pty_handler.py  # PTY creation and management
│   └── ipc.py       # Inter-process communication
├── client/          # CLI interface
│   ├── commands.py  # Command parsing and routing
│   ├── attach.py    # Session attachment logic
│   └── ui.py        # Terminal UI rendering
├── common/
│   ├── session.py   # Session data structures
│   ├── protocol.py  # Client-daemon protocol
│   └── config.py    # Configuration management
└── server/          # (Bonus) Custom SSH-like server
    ├── listener.py  # Network listener
    ├── auth.py      # Authentication
    └── transport.py # Encrypted transport
```

#### Daemon Architecture
- **Service Type:** Systemd service (Linux) or init daemon
- **Lifecycle:** Starts on system boot, runs continuously
- **Communication:** Unix domain sockets for client-daemon IPC
- **Session Storage:** `/var/lib/sshell/sessions/` or `~/.sshell/sessions/`
- **State Persistence:** JSON/SQLite for session metadata

#### Client-Daemon Protocol
```
Client → Daemon: REQUEST [command] [session-id] [parameters]
Daemon → Client: RESPONSE [status] [data]

Commands:
- CREATE: Create new session
- ATTACH: Attach to existing session
- DETACH: Detach from session (optional, can just close connection)
- LIST: Get all sessions
- KILL: Terminate session
- STATUS: Get session info
```

### 3. Python Implementation Guide

#### Phase 1: Core Session Management
**Files to Create:**
1. `sshell_daemon.py` - Main daemon process
2. `sshell_client.py` - CLI client entry point
3. `session_manager.py` - Session CRUD operations
4. `pty_manager.py` - PTY allocation and I/O handling

**Key Libraries:**
- `pty` - PTY creation and management
- `socket` - Unix domain sockets for IPC
- `select` or `asyncio` - Non-blocking I/O multiplexing
- `termios` - Terminal control
- `fcntl` - File descriptor operations
- `signal` - Signal handling (SIGCHLD, SIGHUP, SIGTERM)

**Critical Implementation Details:**

```python
# PTY Session Creation
import pty, os, select

def create_session(shell="/bin/bash"):
    """Create detached PTY session"""
    pid, master_fd = pty.fork()
    if pid == 0:  # Child
        # Start shell in new session
        os.setsid()
        os.execvp(shell, [shell])
    else:  # Parent
        # Return master FD for I/O and child PID
        return pid, master_fd

# Session Reattachment
def attach_session(master_fd, client_socket):
    """Proxy I/O between PTY and client"""
    while True:
        r, w, e = select.select([master_fd, client_socket], [], [])
        if master_fd in r:
            data = os.read(master_fd, 4096)
            client_socket.sendall(data)
        if client_socket in r:
            data = client_socket.recv(4096)
            os.write(master_fd, data)
```

**Session Persistence Strategy:**
- Fork daemon on first `sshell` invocation if not running
- Daemon forks new child for each session
- Daemon maintains mapping: session_id → (pid, master_fd, metadata)
- Store metadata in JSON: `{"id": "sess-1234", "name": "build-task", "created": 1234567890, "last_attached": 1234567899, "shell": "/bin/bash"}`

#### Phase 2: Client Interface
**Commands to Implement:**
```bash
sshell                    # Create new session or attach to most recent
sshell new [name]         # Create named session
sshell attach [name/id]   # Attach to specific session
sshell list               # List all sessions
sshell kill [name/id]     # Terminate session
sshell killall            # Terminate all sessions
```

**Terminal Handling:**
- Save terminal state on attach: `termios.tcgetattr()`
- Set raw mode for transparent passthrough
- Restore terminal state on detach: `termios.tcsetattr()`
- Handle window size changes: `SIGWINCH` signal

#### Phase 3: Daemon Lifecycle
**Daemon Requirements:**
- Auto-start on first client invocation
- Check if daemon running: PID file at `/var/run/sshell.pid` or `~/.sshell/daemon.pid`
- Graceful shutdown: Save session state, send SIGTERM to sessions
- Crash recovery: Reload session state on restart
- Orphan cleanup: Detect and reap dead child processes

**Systemd Integration:**
```ini
[Unit]
Description=SShell Session Daemon
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/bin/sshell-daemon
PIDFile=/var/run/sshell.pid
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### 4. Security Considerations

#### Access Control
- Sessions owned by creating user UID
- Socket permissions: 0700 (user-only)
- Validate client UID matches session owner
- Prevent privilege escalation attacks

#### Resource Limits
- Max sessions per user (default: 10)
- Session timeout for inactive sessions (optional)
- Memory/CPU limits per session (cgroups)

#### Input Sanitization
- Validate session names (alphanumeric + hyphen/underscore)
- Prevent path traversal in session IDs
- Escape shell metacharacters

### 5. Bonus Feature: Custom SSH Server

#### Architecture
```
Client                    Server
  |                         |
  |---- TCP Connect ------->|
  |<--- Protocol Version ---|
  |---- Auth Request ------>|
  |<--- Auth Response ------|
  |---- CREATE SESSION ---->|
  |<--- Session Ready ------|
  |<=== Encrypted I/O ====>|
```

#### Implementation Requirements
- **Network Layer:** TCP socket listener on port (default: 2222)
- **Encryption:** TLS/SSL wrapping or SSH-like key exchange
- **Authentication:** 
  - Username/password (PAM integration)
  - Public key authentication
  - Store authorized keys in `~/.sshell/authorized_keys`
- **Protocol:** Custom binary protocol or extend existing SSH
- **Integration:** Reuse session daemon backend

**Client Usage:**
```bash
sshell root@d31337m3.com          # Connect and create/attach session
sshell root@d31337m3.com:sess-1   # Connect to specific session
```

**Python Libraries:**
- `paramiko` - SSH protocol implementation (if extending SSH)
- `cryptography` - Encryption primitives
- `pam` - PAM authentication (Linux)

**C Port Considerations:**
- Use `libssh` or `libssh2` for SSH protocol
- OpenSSL for encryption
- PAM library for authentication

### 6. Conversion to C

#### Why C?
- Lower resource footprint
- Faster execution
- Native system call access
- Better control over process lifecycle
- Easier packaging as single binary

#### C Implementation Strategy

**Phase 1: Direct Translation**
- Map Python classes to C structs
- Replace Python standard library with libc equivalents
- Use `fork()`, `exec()`, `setsid()` directly
- PTY management: `openpty()`, `forkpty()` from `<pty.h>`

**Phase 2: Optimization**
- Replace Python's select/asyncio with `epoll()` (Linux) or `kqueue()` (BSD)
- Use mmap for session state persistence
- Implement lock-free data structures where possible

**Libraries Needed:**
- `libc` - Standard C library
- `libutil` - PTY functions (BSD) or equivalent
- `libsocket` - Unix domain sockets
- `libjson-c` or `jansson` - JSON parsing
- `libsystemd` - Systemd integration (optional)

**Code Structure:**
```c
// session.h
typedef struct {
    char id[64];
    char name[256];
    pid_t pid;
    int master_fd;
    time_t created;
    time_t last_attached;
} sshell_session_t;

// pty.c
int sshell_create_session(sshell_session_t *session, const char *shell);
int sshell_attach_session(sshell_session_t *session, int client_fd);
void sshell_detach_session(sshell_session_t *session);
int sshell_kill_session(sshell_session_t *session);
```

**Memory Management:**
- Avoid dynamic allocation in hot paths
- Use memory pools for session structures
- Implement reference counting for shared resources

### 7. Testing Strategy

#### Unit Tests
- Session creation and destruction
- PTY allocation and deallocation
- Client-daemon message protocol
- Session state serialization/deserialization

#### Integration Tests
- Full workflow: create → attach → detach → reattach → kill
- Multiple concurrent sessions
- Network disconnection simulation
- Daemon crash and recovery

#### Load Tests
- 100+ concurrent sessions
- Rapid create/destroy cycles
- High I/O throughput scenarios

#### Manual Testing
```bash
# Test 1: Basic persistence
ssh server "sshell new test1 && sleep 100"
# (Disconnect SSH)
ssh server "sshell attach test1"
# (Verify sleep still running)

# Test 2: Multiple sessions
sshell new build && make large-project
sshell new logs && tail -f /var/log/syslog
sshell list
# (Switch between them)

# Test 3: Crash recovery
pkill sshell-daemon
sshell list  # Should show previous sessions
```

### 8. Documentation Requirements

#### User Documentation
- `README.md` - Project overview and quick start
- `INSTALL.md` - Installation instructions
- `man sshell(1)` - Man page for CLI
- `USAGE.md` - Detailed usage examples

#### Developer Documentation
- `ARCHITECTURE.md` - System design and data flow
- `PROTOCOL.md` - Client-daemon protocol specification
- `PORTING.md` - Python to C conversion guide
- Inline code comments for complex logic

### 9. Development Roadmap

#### Milestone 1: MVP (Python)
- [ ] Daemon that can fork PTY sessions
- [ ] Client that can create and attach to sessions
- [ ] Basic session listing
- [ ] Session persistence across daemon restarts

#### Milestone 2: Feature Complete (Python)
- [ ] Named sessions
- [ ] Session kill/cleanup
- [ ] Terminal size handling
- [ ] Signal forwarding
- [ ] Error handling and logging

#### Milestone 3: Production Ready (Python)
- [ ] Systemd integration
- [ ] Multi-user support
- [ ] Security hardening
- [ ] Comprehensive testing
- [ ] Documentation

#### Milestone 4: C Port
- [ ] Core daemon in C
- [ ] Client in C
- [ ] Feature parity with Python version
- [ ] Performance optimization
- [ ] Binary packaging

#### Milestone 5: Bonus SSH Server
- [ ] Network listener
- [ ] Authentication system
- [ ] Encrypted transport
- [ ] Client tool integration

### 10. Edge Cases and Considerations

#### Zombie Sessions
- Detect sessions where shell has exited but session still exists
- Auto-cleanup after configurable timeout
- Clear indication in `sshell list`

#### Terminal Quirks
- Different terminal emulators (xterm, screen, tmux, etc.)
- Color support and ANSI escape codes
- Unicode and multi-byte characters
- Terminal size detection and resizing

#### Shell Compatibility
- Different shells: bash, zsh, fish, sh
- Shell-specific initialization files
- Environment variable propagation

#### Network Issues (SSH Server)
- Connection timeout handling
- Keepalive mechanisms
- Graceful degradation on packet loss
- Reconnection with same session ID

### 11. Performance Targets

#### Python Version
- Session creation: <100ms
- Attach latency: <50ms
- I/O throughput: >10MB/s per session
- Memory per session: <10MB
- Max concurrent sessions: 100+ per GB RAM

#### C Version
- Session creation: <10ms
- Attach latency: <5ms
- I/O throughput: >50MB/s per session
- Memory per session: <1MB
- Max concurrent sessions: 1000+ per GB RAM

### 12. Configuration

#### Config File Format (`~/.sshell/config` or `/etc/sshell/config`)
```ini
[daemon]
socket_path = /var/run/sshell.sock
session_dir = ~/.sshell/sessions
max_sessions = 10
log_level = info

[sessions]
default_shell = /bin/bash
session_timeout = 0  # 0 = never timeout
auto_cleanup_zombies = true

[server]  # Bonus feature
listen_address = 0.0.0.0
listen_port = 2222
enable_password_auth = true
enable_key_auth = true
authorized_keys = ~/.sshell/authorized_keys
```

### 13. Error Handling

#### Critical Errors (Exit)
- Daemon already running with different PID
- Permission denied on socket/session directory
- Unable to allocate PTY

#### Recoverable Errors (Log and Continue)
- Session not found (inform user)
- Session already attached (allow multiple attachments or deny)
- Client disconnection during attach

#### User Errors (Clear Message)
- Invalid session name
- Session limit reached
- Trying to kill non-existent session

---

## Quick Start for Agent

1. **Start with Python MVP:**
   - Implement daemon with session creation and PTY forking
   - Implement client with attach/detach capability
   - Test basic persistence

2. **Iterate on Features:**
   - Add session listing and management
   - Implement proper terminal handling
   - Add logging and error handling

3. **Harden for Production:**
   - Add security checks
   - Implement proper cleanup
   - Write tests

4. **Port to C:**
   - Start with data structures
   - Port daemon core logic
   - Port client logic
   - Optimize and test

5. **Add Bonus SSH Server:**
   - Implement after core is stable
   - Reuse session backend
   - Add network and authentication layers

---

## Success Criteria

The project is successful when:
- ✅ User can start a long-running task via SSH
- ✅ Network disconnection does not terminate the task
- ✅ User can reconnect and resume interaction with the task
- ✅ Multiple sessions can run concurrently
- ✅ Sessions persist across system reboots (if daemon configured to auto-start)
- ✅ C binary is compact (<1MB) and fast
- ✅ (Bonus) Custom SSH-like server allows connection with persistent sessions

---

## References and Prior Art

- **tmux**: Terminal multiplexer - study session management
- **GNU Screen**: Original terminal multiplexer
- **mosh**: Mobile shell - study connection persistence
- **dtach**: Simple program that emulates detach feature of screen
- **abduco**: Session management (simpler than tmux/screen)
- **reptyr**: Reparent running program to new terminal
- **systemd-run**: Running transient units

Study these projects for inspiration, but implement from scratch for learning and customization.
