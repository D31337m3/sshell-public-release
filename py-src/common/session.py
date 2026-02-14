"""Session data structures and management."""

import json
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Session:
    """Represents a persistent shell session."""
    
    id: str
    name: str
    pid: Optional[int]
    master_fd: Optional[int]
    created: float
    last_attached: float
    last_activity: float
    shell: str
    status: str  # 'running', 'dead', 'attached'
    
    @classmethod
    def create(cls, name: Optional[str] = None, shell: str = "/bin/bash"):
        """Create a new session with generated ID."""
        session_id = str(uuid.uuid4())[:8]
        session_name = name or f"session-{session_id}"
        now = time.time()
        
        return cls(
            id=session_id,
            name=session_name,
            pid=None,
            master_fd=None,
            created=now,
            last_attached=now,
            last_activity=now,
            shell=shell,
            status='created'
        )
    
    def to_dict(self):
        """Convert session to dictionary (for JSON serialization)."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict):
        """Create session from dictionary."""
        # Handle migration: add last_activity if missing
        if 'last_activity' not in data:
            data['last_activity'] = data.get('last_attached', time.time())
        return cls(**data)
    
    def to_json(self) -> str:
        """Serialize session to JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_json(cls, json_str: str):
        """Deserialize session from JSON string."""
        return cls.from_dict(json.loads(json_str))
    
    def update_last_attached(self):
        """Update the last attached timestamp."""
        self.last_attached = time.time()
        self.last_activity = time.time()
    
    def update_activity(self):
        """Update the last activity timestamp."""
        self.last_activity = time.time()
    
    def is_idle(self, timeout_seconds: int) -> bool:
        """Check if session has been idle for longer than timeout."""
        if timeout_seconds <= 0:
            return False
        return (time.time() - self.last_activity) > timeout_seconds
    
    def is_alive(self) -> bool:
        """Check if the session process is alive."""
        if self.pid is None:
            return False
        
        try:
            import os
            import signal
            os.kill(self.pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False
