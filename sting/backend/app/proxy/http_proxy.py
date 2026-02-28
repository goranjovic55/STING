# HTTP Proxy - FastAPI middleware-based transparent proxy
from typing import Optional, Dict, Any
from datetime import datetime
import uuid

from ..verdict.engine import get_engine
from ..verdict.session_layer import create_session, get_session


class HTTPProxy:
    """HTTP proxy that intercepts requests for analysis"""

    def __init__(self):
        self.engine = get_engine()
        self.port = 8080

    async def intercept_request(self, method: str, path: str, headers: dict, body: bytes = None) -> Dict[str, Any]:
        """Intercept and analyze HTTP request"""
        session_id = str(uuid.uuid4())
        ip = headers.get("X-Forwarded-For", headers.get("Remote-Addr", "unknown"))

        # Create session
        self.engine.create_session(session_id, ip, "http")
        session = create_session(session_id, "http")

        # Score based on headers/path
        if "Authorization" in headers or "Cookie" in headers:
            self.engine.score_event(session_id, "AUTH_ATTEMPT")

        # Check for suspicious patterns
        if any(p in path.lower() for p in ["/admin", "/wp-admin", "/phpmyadmin", "/.git", ".env"]):
            self.engine.score_event(session_id, "RECON_SEQUENCE")
            session.add_capture(path)

        # Store request in session
        session.write(path, {"method": method, "headers": dict(headers)}, "http_request")

        return {
            "session_id": session_id,
            "verdict": self.engine.get_verdict(session_id).__dict__
        }

    async def get_response(self, session_id: str, path: str) -> Dict[str, Any]:
        """Get fake response for path"""
        session = get_session(session_id)
        if not session:
            return {"status": 404, "body": "Not Found"}

        verdict = self.engine.get_verdict(session_id)

        # If cleared, pass through (not implemented - would forward to real backend)
        if verdict.state == "CLEARED":
            return {"status": 200, "body": "Proxied response", "passthrough": True}

        # Trap mode - return deceptive content
        return self._fake_response(path, session)

    def _fake_response(self, path: str, session) -> Dict[str, Any]:
        """Generate fake response for deception"""
        path_lower = path.lower()

        if path_lower == "/" or path_lower == "/index.html":
            return {
                "status": 200,
                "body": "<html><body><h1>Apache2 Ubuntu Default Page</h1><p>It works!</p></body></html>",
                "headers": {"Content-Type": "text/html"}
            }

        if "wp-admin" in path_lower or "wordpress" in path_lower:
            session.add_capture(path)
            self.engine.score_event(session.session_id, "CANARY_HIT")
            return {"status": 404, "body": "Not Found"}

        if ".env" in path_lower or ".git" in path_lower:
            session.add_capture(path)
            self.engine.score_event(session.session_id, "CANARY_HIT")
            return {"status": 403, "body": "Forbidden"}

        if path_lower.endswith(".php"):
            return {"status": 200, "body": "<?php phpinfo(); ?>", "headers": {"Content-Type": "text/html"}}

        return {"status": 404, "body": "Not Found"}


_proxy = HTTPProxy()

def get_http_proxy() -> HTTPProxy:
    return _proxy
