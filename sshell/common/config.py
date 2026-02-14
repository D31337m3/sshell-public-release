"""Configuration management for SShell."""

import os
from pathlib import Path
from typing import Optional


class Config:
    """Configuration manager for SShell."""
    
    def __init__(self):
        self.home_dir = Path.home()
        self.config_dir = self.home_dir / '.sshell'
        self.session_dir = self.config_dir / 'sessions'
        self.socket_path = self.config_dir / 'daemon.sock'
        self.pid_file = self.config_dir / 'daemon.pid'
        self.log_file = self.config_dir / 'daemon.log'
        
        self.default_shell = os.environ.get('SHELL', '/bin/bash')
        self.max_sessions = 10
        self.session_timeout = 0  # 0 = no timeout (seconds)
        self.auto_cleanup_dead = True
        self.cleanup_interval = 60  # Check for cleanup every 60 seconds
        
    def ensure_directories(self):
        """Create necessary directories if they don't exist."""
        self.config_dir.mkdir(mode=0o700, exist_ok=True)
        self.session_dir.mkdir(mode=0o700, exist_ok=True)
    
    def get_session_file(self, session_id: str) -> Path:
        """Get the path to a session's metadata file."""
        return self.session_dir / f"{session_id}.json"


# Global configuration instance
config = Config()
