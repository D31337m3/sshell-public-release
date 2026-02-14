"""Command-line interface for SShell client."""

import os
import sys
import socket
import termios
import tty
import signal
import struct
import fcntl
import subprocess
from typing import Optional

from ..common.config import config
from ..common.protocol import (
    Message, Response, Command, Status,
    send_message, recv_message
)
from ..common.session import Session


class SShellClient:
    """Client for interacting with SShell daemon."""
    
    def __init__(self):
        self.original_tty_attrs = None
    
    def ensure_daemon_running(self):
        """Ensure daemon is running, start it if not."""
        if not config.socket_path.exists():
            print("Starting SShell daemon...")
            self._start_daemon()
            import time
            time.sleep(0.5)  # Give daemon time to start
    
    def _start_daemon(self):
        """Start the daemon process."""
        daemon_script = sys.argv[0].replace('sshell', 'sshell-daemon')
        
        # Try to find the daemon executable
        daemon_cmd = None
        if os.path.exists(daemon_script):
            daemon_cmd = [sys.executable, daemon_script]
        else:
            # Try installed version
            daemon_cmd = ['sshell-daemon']
        
        try:
            # Start daemon in background
            subprocess.Popen(
                daemon_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True
            )
        except Exception as e:
            print(f"Error: Failed to start daemon: {e}", file=sys.stderr)
            sys.exit(1)
    
    def connect(self) -> socket.socket:
        """Connect to the daemon."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(str(config.socket_path))
            return sock
        except (ConnectionRefusedError, FileNotFoundError):
            print("Error: Cannot connect to daemon. Try starting it with 'sshell-daemon'", file=sys.stderr)
            sys.exit(1)
    
    def create_session(self, name: Optional[str] = None, shell: Optional[str] = None):
        """Create a new session."""
        self.ensure_daemon_running()
        
        sock = self.connect()
        
        data = {}
        if name:
            data['name'] = name
        if shell:
            data['shell'] = shell
        
        msg = Message(Command.CREATE, data)
        send_message(sock, msg)
        
        response = recv_message(sock, Response)
        sock.close()
        
        if response.status == Status.OK:
            session = Session.from_dict(response.data['session'])
            print(f"Created session: {session.name} (id: {session.id})")
            return session
        else:
            print(f"Error: {response.message}", file=sys.stderr)
            sys.exit(1)
    
    def attach_session(self, session_id: Optional[str] = None, session_name: Optional[str] = None):
        """Attach to an existing session."""
        self.ensure_daemon_running()
        
        sock = self.connect()
        
        # Get terminal size
        rows, cols = self._get_terminal_size()
        
        data = {
            'rows': rows,
            'cols': cols
        }
        if session_id:
            data['session_id'] = session_id
        if session_name:
            data['session_name'] = session_name
        
        msg = Message(Command.ATTACH, data)
        send_message(sock, msg)
        
        response = recv_message(sock, Response)
        
        if response.status != Status.OK:
            print(f"Error: {response.message}", file=sys.stderr)
            sock.close()
            sys.exit(1)
        
        session = Session.from_dict(response.data['session'])
        
        # Enter raw mode and proxy I/O
        self._raw_mode_attach(sock, session)
    
    def list_sessions(self):
        """List all sessions."""
        self.ensure_daemon_running()
        
        sock = self.connect()
        msg = Message(Command.LIST)
        send_message(sock, msg)
        
        response = recv_message(sock, Response)
        sock.close()
        
        if response.status == Status.OK:
            sessions = [Session.from_dict(s) for s in response.data['sessions']]
            
            if not sessions:
                print("No active sessions")
                return
            
            print(f"{'ID':<10} {'Name':<20} {'Status':<10} {'PID':<8} {'Created'}")
            print("-" * 70)
            
            for session in sessions:
                from datetime import datetime
                created = datetime.fromtimestamp(session.created).strftime('%Y-%m-%d %H:%M:%S')
                pid = str(session.pid) if session.pid else '-'
                
                # Update status based on alive check
                status = session.status
                if status == 'running' and not session.is_alive():
                    status = 'dead'
                
                print(f"{session.id:<10} {session.name:<20} {status:<10} {pid:<8} {created}")
        else:
            print(f"Error: {response.message}", file=sys.stderr)
            sys.exit(1)
    
    def kill_session(self, session_id: Optional[str] = None, session_name: Optional[str] = None):
        """Kill a session."""
        self.ensure_daemon_running()
        
        sock = self.connect()
        
        data = {}
        if session_id:
            data['session_id'] = session_id
        if session_name:
            data['session_name'] = session_name
        
        msg = Message(Command.KILL, data)
        send_message(sock, msg)
        
        response = recv_message(sock, Response)
        sock.close()
        
        if response.status == Status.OK:
            print(response.message)
        else:
            print(f"Error: {response.message}", file=sys.stderr)
            sys.exit(1)
    
    def _get_terminal_size(self):
        """Get current terminal size."""
        try:
            size = struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, b'\x00' * 8))
            return size[0], size[1]
        except:
            return 24, 80
    
    def _raw_mode_attach(self, sock: socket.socket, session: Session):
        """Attach to session in raw terminal mode."""
        stdin_fd = sys.stdin.fileno()
        stdout_fd = sys.stdout.fileno()
        
        # Save original terminal settings
        self.original_tty_attrs = termios.tcgetattr(stdin_fd)
        
        # Detach key state tracking
        detach_prefix_pressed = False
        DETACH_PREFIX = b'\x02'  # Ctrl+B
        DETACH_KEY = b'd'  # D
        
        # Set up signal handler for window resize
        def handle_resize(s, f):
            try:
                rows, cols = self._get_terminal_size()
                # Send resize command to daemon
                msg = Message(Command.RESIZE, {
                    'session_id': session.id,
                    'rows': rows,
                    'cols': cols
                })
                # Create temporary socket for resize command
                resize_sock = self.connect()
                send_message(resize_sock, msg)
                recv_message(resize_sock, Response)  # Acknowledge
                resize_sock.close()
            except Exception:
                pass
        
        signal.signal(signal.SIGWINCH, handle_resize)
        
        try:
            # Enter raw mode
            tty.setraw(stdin_fd)
            
            # Make stdin non-blocking
            flags = fcntl.fcntl(stdin_fd, fcntl.F_GETFL)
            fcntl.fcntl(stdin_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            # Make socket non-blocking
            sock.setblocking(False)
            
            # I/O loop
            import select
            while True:
                try:
                    readable, _, _ = select.select([stdin_fd, sock], [], [], 0.1)
                    
                    if stdin_fd in readable:
                        try:
                            data = os.read(stdin_fd, 4096)
                            if data:
                                # Check for detach key combination
                                if detach_prefix_pressed and data == DETACH_KEY:
                                    # Detach requested
                                    break
                                elif data == DETACH_PREFIX:
                                    detach_prefix_pressed = True
                                    continue  # Don't send prefix to shell
                                else:
                                    detach_prefix_pressed = False
                                    sock.sendall(data)
                            else:
                                break
                        except BlockingIOError:
                            pass
                    
                    if sock in readable:
                        try:
                            data = sock.recv(4096)
                            if data:
                                os.write(stdout_fd, data)
                            else:
                                break
                        except BlockingIOError:
                            pass
                
                except KeyboardInterrupt:
                    break
                except Exception:
                    break
        
        finally:
            self._restore_terminal(stdin_fd)
            sock.close()
            if detach_prefix_pressed or True:  # Always show message
                print("\n[detached]")
    
    def _handle_resize(self, sock: socket.socket):
        """Handle terminal window resize."""
        rows, cols = self._get_terminal_size()
        # Note: In a full implementation, we'd send a resize message to daemon
        # For now, the daemon handles SIGWINCH on the PTY side
    
    def rename_session(self, old_target: str, new_name: str):
        """Rename a session."""
        self.ensure_daemon_running()
        
        sock = self.connect()
        
        data = {
            'session_name': old_target,
            'new_name': new_name
        }
        
        msg = Message(Command.RENAME, data)
        send_message(sock, msg)
        
        response = recv_message(sock, Response)
        sock.close()
        
        if response.status == Status.OK:
            print(response.message)
        else:
            print(f"Error: {response.message}", file=sys.stderr)
            sys.exit(1)
    
    def _restore_terminal(self, fd: int):
        """Restore terminal to original state."""
        if self.original_tty_attrs:
            termios.tcsetattr(fd, termios.TCSADRAIN, self.original_tty_attrs)
            self.original_tty_attrs = None


def main():
    """Main entry point for CLI."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='SShell - Persistent shell sessions',
        epilog='Run without arguments to create and attach to a new session'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Create command
    create_parser = subparsers.add_parser('new', help='Create a new session')
    create_parser.add_argument('name', nargs='?', help='Session name')
    create_parser.add_argument('-s', '--shell', help='Shell to use')
    create_parser.add_argument('--no-attach', action='store_true', help='Do not attach after creating')
    
    # Attach command
    attach_parser = subparsers.add_parser('attach', help='Attach to a session')
    attach_parser.add_argument('target', help='Session ID or name')
    
    # List command
    subparsers.add_parser('list', help='List all sessions')
    subparsers.add_parser('ls', help='List all sessions (alias)')
    
    # Kill command
    kill_parser = subparsers.add_parser('kill', help='Kill a session')
    kill_parser.add_argument('target', help='Session ID or name')
    
    # Rename command
    rename_parser = subparsers.add_parser('rename', help='Rename a session')
    rename_parser.add_argument('target', help='Current session ID or name')
    rename_parser.add_argument('new_name', help='New session name')
    
    args = parser.parse_args()
    
    client = SShellClient()
    
    try:
        if args.command == 'new':
            session = client.create_session(name=args.name, shell=args.shell)
            if not args.no_attach:
                client.attach_session(session_id=session.id)
        
        elif args.command == 'attach':
            client.attach_session(session_name=args.target)
        
        elif args.command in ['list', 'ls']:
            client.list_sessions()
        
        elif args.command == 'kill':
            client.kill_session(session_name=args.target)
        
        elif args.command == 'rename':
            client.rename_session(args.target, args.new_name)
        
        else:
            # No command - default behavior: create new session and attach
            session = client.create_session()
            client.attach_session(session_id=session.id)
    
    except KeyboardInterrupt:
        print()
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
