"""Client-daemon communication protocol."""

import json
from enum import Enum
from typing import Any, Dict, Optional


class Command(Enum):
    """Commands that can be sent from client to daemon."""
    CREATE = "create"
    ATTACH = "attach"
    DETACH = "detach"
    LIST = "list"
    KILL = "kill"
    STATUS = "status"
    RENAME = "rename"
    RESIZE = "resize"
    PING = "ping"
    SHUTDOWN = "shutdown"


class Status(Enum):
    """Response status codes."""
    OK = "ok"
    ERROR = "error"
    NOT_FOUND = "not_found"
    ALREADY_EXISTS = "already_exists"


class Message:
    """Base class for protocol messages."""
    
    def __init__(self, command: Command, data: Optional[Dict[str, Any]] = None):
        self.command = command
        self.data = data or {}
    
    def to_json(self) -> str:
        """Serialize message to JSON."""
        return json.dumps({
            'command': self.command.value,
            'data': self.data
        })
    
    @classmethod
    def from_json(cls, json_str: str):
        """Deserialize message from JSON."""
        obj = json.loads(json_str)
        return cls(
            command=Command(obj['command']),
            data=obj.get('data', {})
        )
    
    def to_bytes(self) -> bytes:
        """Convert message to bytes with length prefix."""
        json_str = self.to_json()
        json_bytes = json_str.encode('utf-8')
        length = len(json_bytes)
        return length.to_bytes(4, byteorder='big') + json_bytes
    
    @classmethod
    def from_bytes(cls, data: bytes):
        """Parse message from bytes."""
        json_str = data.decode('utf-8')
        return cls.from_json(json_str)


class Response:
    """Response message from daemon to client."""
    
    def __init__(self, status: Status, data: Optional[Dict[str, Any]] = None, message: str = ""):
        self.status = status
        self.data = data or {}
        self.message = message
    
    def to_json(self) -> str:
        """Serialize response to JSON."""
        return json.dumps({
            'status': self.status.value,
            'data': self.data,
            'message': self.message
        })
    
    @classmethod
    def from_json(cls, json_str: str):
        """Deserialize response from JSON."""
        obj = json.loads(json_str)
        return cls(
            status=Status(obj['status']),
            data=obj.get('data', {}),
            message=obj.get('message', '')
        )
    
    def to_bytes(self) -> bytes:
        """Convert response to bytes with length prefix."""
        json_str = self.to_json()
        json_bytes = json_str.encode('utf-8')
        length = len(json_bytes)
        return length.to_bytes(4, byteorder='big') + json_bytes
    
    @classmethod
    def from_bytes(cls, data: bytes):
        """Parse response from bytes."""
        json_str = data.decode('utf-8')
        return cls.from_json(json_str)


def send_message(sock, msg):
    """Send a message through a socket."""
    sock.sendall(msg.to_bytes())


def recv_message(sock, message_class=Message):
    """Receive a message from a socket."""
    length_bytes = sock.recv(4)
    if not length_bytes:
        return None
    
    length = int.from_bytes(length_bytes, byteorder='big')
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    
    return message_class.from_bytes(data)
