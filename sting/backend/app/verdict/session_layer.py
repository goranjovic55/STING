"""
Session Layer - Per-session write buffer
Intercepts all writes, real service never touched until COMMIT
"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class SessionWrite:
    path: str
    content: Any
    write_type: str
    timestamp: datetime = field(default_factory=datetime.utcnow)

class SessionLayer:
    def __init__(self, session_id: str, protocol: str):
        self.session_id = session_id
        self.protocol = protocol
        self.writes: Dict[str, SessionWrite] = {}
        self.reads: List[str] = []
        self.captures: List[str] = []
        self.resource_disk_mb = 0.0
        self.resource_memory_mb = 0
        self.resource_files = 0
        self.max_disk_mb = 50
        self.max_memory_mb = 10
        self.max_files = 100
        self.max_db_rows = 10000
        self.db_rows = 0
        self.ttl_seconds = 1800
        self.created_at = datetime.utcnow()
        
    def write(self, path: str, content: Any, write_type: str = "file") -> bool:
        if self.resource_files >= self.max_files:
            return False
        if self.resource_disk_mb >= self.max_disk_mb:
            return False
        self.writes[path] = SessionWrite(path, content, write_type)
        self.resource_files += 1
        if isinstance(content, (str, bytes)):
            size_mb = len(content) / (1024 * 1024)
            self.resource_disk_mb += size_mb
        return True
    
    def read(self, path: str) -> Optional[Any]:
        self.reads.append(path)
        if path in self.writes:
            return self.writes[path].content
        return None
    
    def add_capture(self, file_hash: str):
        self.captures.append(file_hash)
    
    def diff(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "protocol": self.protocol,
            "writes": [{"path": w.path, "type": w.write_type} for w in self.writes.values()],
            "reads": self.reads,
            "captures": self.captures,
            "resources": {"disk_mb": round(self.resource_disk_mb, 2), "files": self.resource_files}
        }
    
    def nuke(self):
        self.writes.clear()
        self.reads.clear()
        self.captures.clear()
        self.resource_disk_mb = 0
        self.resource_files = 0
        self.db_rows = 0
    
    def commit(self) -> List[SessionWrite]:
        return list(self.writes.values())
    
    def snapshot(self) -> Dict[str, Any]:
        return {"session_id": self.session_id, "writes": {p: {"content": w.content} for p, w in self.writes.items()}}

_sessions: Dict[str, SessionLayer] = {}

def get_session(session_id: str) -> Optional[SessionLayer]:
    return _sessions.get(session_id)

def create_session(session_id: str, protocol: str) -> SessionLayer:
    layer = SessionLayer(session_id, protocol)
    _sessions[session_id] = layer
    return layer

def delete_session(session_id: str) -> bool:
    if session_id in _sessions:
        del _sessions[session_id]
        return True
    return False
