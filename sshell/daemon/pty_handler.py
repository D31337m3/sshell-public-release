"""PTY (pseudo-terminal) management for session isolation."""

import os
import pty
import fcntl
import termios
import struct
import select
import signal
from typing import Optional, Tuple

from ..common.session import Session


class PTYManager:
    """Manages PTY creation and I/O for shell sessions."""
    
    @staticmethod
    def create_session(session: Session) -> Tuple[int, int]:
        """
        Create a new PTY session with a forked shell process.
        
        Returns:
            Tuple of (pid, master_fd)
        """
        pid, master_fd = pty.fork()
        
        if pid == 0:  # Child process
            # pty.fork() already creates a new session, so no need to call setsid()
            
            # Execute shell
            shell = session.shell
            env = os.environ.copy()
            env['TERM'] = env.get('TERM', 'xterm-256color')
            
            try:
                os.execvpe(shell, [shell], env)
            except Exception as e:
                print(f"Failed to execute shell: {e}")
                os._exit(1)
        
        else:  # Parent process
            # Set non-blocking mode on master FD
            flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
            fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            session.pid = pid
            session.master_fd = master_fd
            session.status = 'running'
            
            return pid, master_fd
    
    @staticmethod
    def set_window_size(fd: int, rows: int, cols: int):
        """Set the terminal window size."""
        try:
            winsize = struct.pack('HHHH', rows, cols, 0, 0)
            fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
        except Exception:
            pass
    
    @staticmethod
    def get_window_size(fd: int) -> Tuple[int, int]:
        """Get the terminal window size."""
        try:
            winsize = fcntl.ioctl(fd, termios.TIOCGWINSZ, b'\x00' * 8)
            rows, cols = struct.unpack('HHHH', winsize)[:2]
            return rows, cols
        except Exception:
            return 24, 80  # Default size
    
    @staticmethod
    def proxy_io(master_fd: int, client_fd: int, timeout: Optional[float] = None) -> bool:
        """
        Proxy I/O between PTY master and client socket.
        
        Returns:
            True if connection should continue, False if client disconnected
        """
        try:
            readable, _, exceptional = select.select(
                [master_fd, client_fd],
                [],
                [master_fd, client_fd],
                timeout
            )
            
            if exceptional:
                return False
            
            for fd in readable:
                try:
                    if fd == master_fd:
                        # Data from shell to client
                        data = os.read(master_fd, 4096)
                        if data:
                            os.write(client_fd, data)
                        else:
                            return False
                    
                    elif fd == client_fd:
                        # Data from client to shell
                        data = os.read(client_fd, 4096)
                        if data:
                            os.write(master_fd, data)
                        else:
                            return False
                
                except (OSError, IOError) as e:
                    if e.errno in (11, 35):  # EAGAIN, EWOULDBLOCK
                        continue
                    return False
            
            return True
        
        except (OSError, IOError, KeyboardInterrupt):
            return False
    
    @staticmethod
    def kill_session(session: Session):
        """Terminate a session's shell process."""
        if session.pid:
            try:
                os.kill(session.pid, signal.SIGTERM)
                # Give it time to terminate gracefully
                import time
                time.sleep(0.1)
                try:
                    os.kill(session.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            except ProcessLookupError:
                pass
        
        if session.master_fd:
            try:
                os.close(session.master_fd)
            except OSError:
                pass
        
        session.status = 'dead'
        session.pid = None
        session.master_fd = None
