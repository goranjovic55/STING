---
name: backend-api
description: Load when editing Python files in backend/, api/, routes/, services/, models/, websocket files, or alembic/. Provides FastAPI, async SQLAlchemy, WebSocket, Authentication, and Database Migration patterns.
---

# Backend API

## Merged Skills
- **authentication**: JWT tokens, session management, OAuth flows
- **security**: Input sanitization, CORS, rate limiting, XSS/CSRF protection
- **monitoring**: Structured logging, metrics, tracing, health checks
- **websocket-realtime**: ConnectionManager, broadcast, room management

## ⚠️ Critical Gotchas

| Category | Pattern | Solution |
|----------|---------|----------|
| JSONB | Nested object won't save | Use `flag_modified(obj, 'field')` before commit |
| Auth | 401 errors on frontend | Call `logout()` from authStore for redirect |
| Migrations | Model changes not applied | Run `alembic upgrade head` after changes |
| WebSocket | Connection drops silently | Always handle `WebSocketDisconnect` exception |
| Security | Token bypass | Validate tokens server-side, never trust client |
| Input | Injection attacks | Sanitize inputs, use parameterized queries |
| Logging | Missing context | Use structured logging with request context |

## Rules

| Rule | Pattern |
|------|---------|
| Layer separation | Endpoint → Service → Model |
| Type safety | Always `response_model=Schema` |
| Async I/O | `await` all DB/network calls |
| Auth dependency | `Depends(get_current_user)` |
| WebSocket | Use ConnectionManager pattern |
| JSONB mutations | Always `flag_modified()` after update |

## Avoid

| ❌ Bad | ✅ Good |
|--------|---------|
| DB logic in routes | Service layer |
| Mutable defaults | `Field(default_factory=list)` |
| Missing types | `response_model=Schema` |
| Sync DB calls | `await db.execute()` |
| Direct JSONB mutation | `flag_modified()` after change |

## Patterns

```python
# Pattern 1: CRUD endpoint with proper typing
@router.get("/{id}", response_model=ItemResponse)
async def get_item(id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Item).where(Item.id == id))
    if not (item := result.scalar_one_or_none()):
        raise HTTPException(404, "Not found")
    return item

# Pattern 2: JSONB mutation (CRITICAL - must flag_modified)
from sqlalchemy.orm.attributes import flag_modified

agent.agent_metadata['key'] = value
flag_modified(agent, 'agent_metadata')  # REQUIRED
await db.commit()

# Pattern 3: WebSocket with proper disconnect handling
@router.websocket("/ws/{id}")
async def ws_endpoint(ws: WebSocket, id: str):
    await manager.connect(ws, id)
    try:
        while True:
            data = await ws.receive_json()
            await process_message(data)
    except WebSocketDisconnect:
        manager.disconnect(id)

# Pattern 4: JWT token creation
from datetime import datetime, timedelta
import jwt

def create_access_token(data: dict) -> str:
    expire = datetime.utcnow() + timedelta(minutes=15)
    return jwt.encode({**data, "exp": expire}, SECRET_KEY, algorithm="HS256")

# Pattern 5: Service layer pattern
class ItemService:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create(self, data: ItemCreate) -> Item:
        item = Item(**data.dict())
        self.db.add(item)
        await self.db.commit()
        return item
```

## Alembic Migrations

| Task | Command |
|------|---------|
| Create migration | `alembic revision --autogenerate -m "description"` |
| Apply migrations | `alembic upgrade head` |
| Rollback one | `alembic downgrade -1` |
| View history | `alembic history` |
| Current version | `alembic current` |

## Commands

| Task | Command |
|------|---------|
| Run server | `cd backend && uvicorn app.main:app --reload` |
| Run tests | `cd backend && pytest -v` |
| Create migration | `cd backend && alembic revision --autogenerate -m "msg"` |
| Apply migrations | `cd backend && alembic upgrade head` |
| Enter container | `docker exec -it nop-backend bash` |
