"""Main daemon for managing persistent shell sessions."""

import os
import sys
import signal
import socket
import logging
import json
from pathlib import Path
from typing import Dict, Optional

from ..common.session import Session
from ..common.config import config
from ..common.protocol import (
    Message, Response, Command, Status,
    send_message, recv_message
)
from .pty_handler import PTYManager


class SessionDaemon:
    """Daemon that manages all persistent shell sessions."""
    
    def __init__(self):
        self.sessions: Dict[str, Session] = {}
        self.pty_manager = PTYManager()
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        
        # Ensure directories exist first
        config.ensure_directories()
        
        # Set up logging
        logging.basicConfig(
            filename=str(config.log_file),
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('sshell-daemon')
    
    def start(self):
        """Start the daemon."""
        self.logger.info("Starting SShell daemon")
        
        # Ensure directories exist
        config.ensure_directories()
        
        # Check if daemon is already running
        if self._is_daemon_running():
            self.logger.error("Daemon already running")
            print("Error: Daemon is already running", file=sys.stderr)
            sys.exit(1)
        
        # Load existing sessions
        self._load_sessions()
        
        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGCHLD, self._handle_sigchld)
        signal.signal(signal.SIGALRM, self._handle_cleanup)
        
        # Create Unix domain socket
        self._create_socket()
        
        # Write PID file
        self._write_pid_file()
        
        # Start cleanup timer
        signal.alarm(config.cleanup_interval)
        
        # Main loop
        self.running = True
        self._main_loop()
    
    def _is_daemon_running(self) -> bool:
        """Check if daemon is already running."""
        if not config.pid_file.exists():
            return False
        
        try:
            pid = int(config.pid_file.read_text().strip())
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, ValueError, OSError):
            # Stale PID file
            config.pid_file.unlink(missing_ok=True)
            return False
    
    def _write_pid_file(self):
        """Write current PID to file."""
        config.pid_file.write_text(str(os.getpid()))
    
    def _create_socket(self):
        """Create Unix domain socket for client communication."""
        # Remove old socket file if it exists
        if config.socket_path.exists():
            config.socket_path.unlink()
        
        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.bind(str(config.socket_path))
        self.server_socket.listen(5)
        
        # Set permissions
        os.chmod(str(config.socket_path), 0o600)
        
        self.logger.info(f"Listening on {config.socket_path}")
    
    def _main_loop(self):
        """Main event loop for handling client requests."""
        while self.running:
            try:
                client_socket, _ = self.server_socket.accept()
                self._handle_client(client_socket)
            except Exception as e:
                self.logger.error(f"Error in main loop: {e}")
    
    def _handle_client(self, client_socket: socket.socket):
        """Handle a client connection."""
        try:
            msg = recv_message(client_socket, Message)
            if not msg:
                client_socket.close()
                return
            
            self.logger.info(f"Received command: {msg.command}")
            
            # Route command to appropriate handler
            if msg.command == Command.CREATE:
                response = self._handle_create(msg.data)
            elif msg.command == Command.ATTACH:
                response = self._handle_attach(msg.data, client_socket)
                return  # Attach handles its own socket closure
            elif msg.command == Command.LIST:
                response = self._handle_list()
            elif msg.command == Command.KILL:
                response = self._handle_kill(msg.data)
            elif msg.command == Command.STATUS:
                response = self._handle_status(msg.data)
            elif msg.command == Command.RENAME:
                response = self._handle_rename(msg.data)
            elif msg.command == Command.RESIZE:
                response = self._handle_resize(msg.data)
            elif msg.command == Command.PING:
                response = Response(Status.OK, message="pong")
            elif msg.command == Command.SHUTDOWN:
                response = self._handle_shutdown()
            else:
                response = Response(Status.ERROR, message="Unknown command")
            
            send_message(client_socket, response)
            client_socket.close()
        
        except Exception as e:
            self.logger.error(f"Error handling client: {e}")
            try:
                response = Response(Status.ERROR, message=str(e))
                send_message(client_socket, response)
                client_socket.close()
            except:
                pass
    
    def _handle_create(self, data: dict) -> Response:
        """Create a new session."""
        name = data.get('name')
        shell = data.get('shell', config.default_shell)
        
        # Check session limit
        if len(self.sessions) >= config.max_sessions:
            return Response(Status.ERROR, message=f"Maximum session limit ({config.max_sessions}) reached")
        
        # Check if name already exists
        if name and any(s.name == name for s in self.sessions.values()):
            return Response(Status.ALREADY_EXISTS, message=f"Session '{name}' already exists")
        
        # Create session
        session = Session.create(name=name, shell=shell)
        
        try:
            # Fork PTY
            pid, master_fd = self.pty_manager.create_session(session)
            
            # Store session
            self.sessions[session.id] = session
            self._save_session(session)
            
            self.logger.info(f"Created session {session.id} (name: {session.name}, pid: {pid})")
            
            return Response(
                Status.OK,
                data={'session': session.to_dict()},
                message=f"Session '{session.name}' created"
            )
        
        except Exception as e:
            self.logger.error(f"Failed to create session: {e}", exc_info=True)
            return Response(Status.ERROR, message=f"Failed to create session: {e}")
    
    def _handle_attach(self, data: dict, client_socket: socket.socket):
        """Attach to an existing session."""
        session_id = data.get('session_id')
        session_name = data.get('session_name')
        rows = data.get('rows', 24)
        cols = data.get('cols', 80)
        
        # Find session
        session = self._find_session(session_id, session_name)
        
        if not session:
            response = Response(Status.NOT_FOUND, message="Session not found")
            send_message(client_socket, response)
            client_socket.close()
            return
        
        # Check if session is alive
        if not session.is_alive():
            response = Response(Status.ERROR, message="Session process is dead")
            send_message(client_socket, response)
            client_socket.close()
            return
        
        # Send OK response
        response = Response(
            Status.OK,
            data={'session': session.to_dict()},
            message=f"Attached to session '{session.name}'"
        )
        send_message(client_socket, response)
        
        # Update session
        session.update_last_attached()
        session.status = 'attached'
        self._save_session(session)
        
        # Set window size
        self.pty_manager.set_window_size(session.master_fd, rows, cols)
        
        # Proxy I/O between client and PTY
        self.logger.info(f"Attaching to session {session.id}")
        
        try:
            # Get client socket file descriptor
            client_fd = client_socket.fileno()
            
            # Proxy I/O until client disconnects
            while self.pty_manager.proxy_io(session.master_fd, client_fd, timeout=0.1):
                session.update_activity()  # Update activity on each I/O
                pass
        
        except Exception as e:
            self.logger.error(f"Error during attach: {e}", exc_info=True)
        
        finally:
            session.status = 'running'
            self._save_session(session)
            client_socket.close()
            self.logger.info(f"Detached from session {session.id}")
    
    def _handle_list(self) -> Response:
        """List all sessions."""
        # Update session status
        for session in self.sessions.values():
            if not session.is_alive() and session.status == 'running':
                session.status = 'dead'
        
        sessions_data = [s.to_dict() for s in self.sessions.values()]
        return Response(Status.OK, data={'sessions': sessions_data})
    
    def _handle_kill(self, data: dict) -> Response:
        """Kill a session."""
        session_id = data.get('session_id')
        session_name = data.get('session_name')
        
        session = self._find_session(session_id, session_name)
        
        if not session:
            return Response(Status.NOT_FOUND, message="Session not found")
        
        self.pty_manager.kill_session(session)
        self._save_session(session)
        
        self.logger.info(f"Killed session {session.id}")
        
        return Response(Status.OK, message=f"Session '{session.name}' killed")
    
    def _handle_status(self, data: dict) -> Response:
        """Get status of a session."""
        session_id = data.get('session_id')
        session_name = data.get('session_name')
        
        session = self._find_session(session_id, session_name)
        
        if not session:
            return Response(Status.NOT_FOUND, message="Session not found")
        
        return Response(Status.OK, data={'session': session.to_dict()})
    
    def _handle_shutdown(self) -> Response:
        """Shutdown the daemon."""
        self.logger.info("Shutdown requested")
        self.running = False
        return Response(Status.OK, message="Daemon shutting down")
    
    def _handle_rename(self, data: dict) -> Response:
        """Rename a session."""
        session_id = data.get('session_id')
        session_name = data.get('session_name')
        new_name = data.get('new_name')
        
        if not new_name:
            return Response(Status.ERROR, message="New name is required")
        
        # Check if new name already exists
        if any(s.name == new_name for s in self.sessions.values()):
            return Response(Status.ALREADY_EXISTS, message=f"Session '{new_name}' already exists")
        
        session = self._find_session(session_id, session_name)
        if not session:
            return Response(Status.NOT_FOUND, message="Session not found")
        
        old_name = session.name
        session.name = new_name
        self._save_session(session)
        
        self.logger.info(f"Renamed session {session.id} from '{old_name}' to '{new_name}'")
        
        return Response(Status.OK, message=f"Session renamed from '{old_name}' to '{new_name}'")
    
    def _handle_resize(self, data: dict) -> Response:
        """Resize a session's terminal."""
        session_id = data.get('session_id')
        rows = data.get('rows', 24)
        cols = data.get('cols', 80)
        
        session = self._find_session(session_id, None)
        if not session:
            return Response(Status.NOT_FOUND, message="Session not found")
        
        if session.master_fd:
            self.pty_manager.set_window_size(session.master_fd, rows, cols)
            self.logger.debug(f"Resized session {session.id} to {rows}x{cols}")
            return Response(Status.OK, message=f"Session resized to {rows}x{cols}")
        else:
            return Response(Status.ERROR, message="Session has no active PTY")
    
    def _find_session(self, session_id: Optional[str], session_name: Optional[str]) -> Optional[Session]:
        """Find a session by ID or name."""
        if session_id:
            return self.sessions.get(session_id)
        
        if session_name:
            for session in self.sessions.values():
                if session.name == session_name:
                    return session
        
        return None
    
    def _load_sessions(self):
        """Load existing sessions from disk."""
        if not config.session_dir.exists():
            return
        
        for session_file in config.session_dir.glob('*.json'):
            try:
                session_data = json.loads(session_file.read_text())
                session = Session.from_dict(session_data)
                
                # Check if session process is still alive
                if session.is_alive():
                    self.sessions[session.id] = session
                    self.logger.info(f"Loaded session {session.id} (pid: {session.pid})")
                else:
                    # Clean up dead session
                    session_file.unlink(missing_ok=True)
            
            except Exception as e:
                self.logger.error(f"Failed to load session from {session_file}: {e}")
    
    def _save_session(self, session: Session):
        """Save session metadata to disk."""
        session_file = config.get_session_file(session.id)
        session_file.write_text(session.to_json())
    
    def _handle_signal(self, signum, frame):
        """Handle termination signals."""
        self.logger.info(f"Received signal {signum}")
        self.running = False
    
    def _handle_sigchld(self, signum, frame):
        """Handle child process termination."""
        try:
            while True:
                pid, status = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
                
                # Find session with this PID
                for session in self.sessions.values():
                    if session.pid == pid:
                        session.status = 'dead'
                        session.pid = None
                        self._save_session(session)
                        self.logger.info(f"Session {session.id} process terminated")
                        break
        
        except ChildProcessError:
            pass
    
    def _handle_cleanup(self, signum, frame):
        """Periodic cleanup of dead and idle sessions."""
        self.logger.debug("Running periodic cleanup")
        
        sessions_to_remove = []
        
        for session_id, session in self.sessions.items():
            # Check if process is dead
            if not session.is_alive() and session.status != 'dead':
                session.status = 'dead'
                self._save_session(session)
                self.logger.info(f"Session {session_id} marked as dead")
            
            # Auto-cleanup dead sessions if enabled
            if config.auto_cleanup_dead and session.status == 'dead':
                sessions_to_remove.append(session_id)
                self.logger.info(f"Auto-cleaning dead session {session_id}")
            
            # Check for idle timeout
            if config.session_timeout > 0 and session.is_idle(config.session_timeout):
                sessions_to_remove.append(session_id)
                self.logger.info(f"Session {session_id} timed out after {config.session_timeout}s idle")
                self.pty_manager.kill_session(session)
        
        # Remove dead/timed-out sessions
        for session_id in sessions_to_remove:
            session_file = config.get_session_file(session_id)
            session_file.unlink(missing_ok=True)
            del self.sessions[session_id]
        
        # Schedule next cleanup
        signal.alarm(config.cleanup_interval)
    
    def cleanup(self):
        """Clean up resources."""
        self.logger.info("Cleaning up")
        
        if self.server_socket:
            self.server_socket.close()
        
        if config.socket_path.exists():
            config.socket_path.unlink()
        
        if config.pid_file.exists():
            config.pid_file.unlink()


def daemonize():
    """Daemonize the process."""
    # First fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        print(f"fork #1 failed: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Decouple from parent environment
    os.chdir('/')
    os.setsid()
    os.umask(0)
    
    # Second fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        print(f"fork #2 failed: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    si = open(os.devnull, 'r')
    so = open(os.devnull, 'a+')
    se = open(os.devnull, 'a+')
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())


def main():
    """Main entry point for daemon."""
    # Check if --no-fork flag is present (for debugging)
    if '--no-fork' not in sys.argv:
        daemonize()
    
    daemon = SessionDaemon()
    
    try:
        daemon.start()
    except KeyboardInterrupt:
        pass
    finally:
        daemon.cleanup()


if __name__ == '__main__':
    main()
