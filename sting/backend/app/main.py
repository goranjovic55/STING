# STING 2.0 - Main FastAPI Application
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Set, Optional
import uuid

from app.core.config import settings
from app.core.db import engine
from app.models.session import Base

# Import API routers
from app.api.v1 import events, sessions, canary, samples, lab, export

# SSH Proxy state
_ssh_proxy_task: Optional[asyncio.Task] = None
_ssh_proxy_running = False

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, channel: str, session_id: str = None):
        await websocket.accept()
        key = f"{channel}:{session_id if session_id else 'global'}"
        if key not in self.active_connections:
            self.active_connections[key] = set()
        self.active_connections[key].add(websocket)

    def disconnect(self, websocket: WebSocket, channel: str, session_id: str = None):
        key = f"{channel}:{session_id if session_id else 'global'}"
        if key in self.active_connections:
            self.active_connections[key].discard(websocket)

    async def broadcast(self, channel: str, message: dict, session_id: str = None):
        key = f"{channel}:{session_id if session_id else 'global'}"
        if key in self.active_connections:
            for connection in self.active_connections[key]:
                await connection.send_json(message)

manager = ConnectionManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup - create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # Shutdown
    await engine.dispose()

app = FastAPI(
    title="STING 2.0 API",
    description="Deception Platform API",
    version="2.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Include routers
app.include_router(events.router, prefix="/api/v1/events", tags=["events"])
app.include_router(sessions.router, prefix="/api/v1/sessions", tags=["sessions"])
app.include_router(canary.router, prefix="/api/v1/canary", tags=["canary"])
app.include_router(samples.router, prefix="/api/v1/samples", tags=["samples"])
app.include_router(lab.router, prefix="/api/v1/lab", tags=["lab"])
app.include_router(export.router, prefix="/api/v1/export", tags=["export"])

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.websocket("/ws/{channel}/{session_id}")
async def websocket_endpoint(websocket: WebSocket, channel: str, session_id: str = None):
    await manager.connect(websocket, channel, session_id)
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            # Handle subscribe/unsubscribe
            if message.get("type") == "subscribe":
                # Already connected via connect()
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel, session_id)

# Auth endpoints (stub)
from jose import JWTError, jwt

@app.post("/api/v1/auth/token")
async def login(username: str, password: str):
    # Single user auth - check against settings
    if username == settings.STING_USERNAME and password == settings.STING_PASSWORD:
        token = jwt.encode(
            {"sub": username, "exp": datetime.utcnow() + timedelta(hours=24)},
            settings.SECRET_KEY,
            algorithm="HS256"
        )
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, settings.SECRET_KEY, algorithms=["HS256"])
        return payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Proxy control endpoints
from app.proxy.ssh_proxy import start_ssh_proxy

@app.post("/api/v1/proxy/ssh/start")
async def start_ssh():
    """Start the SSH proxy server"""
    global _ssh_proxy_task, _ssh_proxy_running
    if _ssh_proxy_running:
        return {"status": "already_running", "message": "SSH proxy already running"}

    try:
        _ssh_proxy_task = asyncio.create_task(start_ssh_proxy("0.0.0.0", 2222))
        _ssh_proxy_running = True
        return {"status": "started", "message": "SSH proxy started on port 2222"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start SSH proxy: {str(e)}")


@app.post("/api/v1/proxy/ssh/stop")
async def stop_ssh():
    """Stop the SSH proxy server"""
    global _ssh_proxy_task, _ssh_proxy_running
    if not _ssh_proxy_running:
        return {"status": "not_running", "message": "SSH proxy not running"}

    if _ssh_proxy_task:
        _ssh_proxy_task.cancel()
        try:
            await _ssh_proxy_task
        except asyncio.CancelledError:
            pass
    _ssh_proxy_running = False
    return {"status": "stopped", "message": "SSH proxy stopped"}


@app.get("/api/v1/proxy/status")
async def get_proxy_status():
    """Get proxy status"""
    return {
        "ssh": {"running": _ssh_proxy_running, "port": 2222}
    }


# Export manager for use in other modules
__all__ = ["app", "manager"]
