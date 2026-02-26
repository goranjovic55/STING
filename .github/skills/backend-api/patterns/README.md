# Backend API Patterns

Reusable code patterns for FastAPI, async SQLAlchemy, and WebSocket development.

## Pattern Files

| Pattern | Description | Usage |
|---------|-------------|-------|
| `crud_endpoint.py` | CRUD endpoint template | `GET`, `POST`, `PUT`, `DELETE` |
| `service_layer.py` | Service class template | Business logic separation |
| `websocket_handler.py` | WebSocket endpoint | Real-time communication |
| `jsonb_mutation.py` | JSONB field updates | PostgreSQL JSONB handling |

## Usage

Patterns are referenced in SKILL.md and auto-suggested when relevant triggers are detected.

### CRUD Endpoint Pattern
```python
@router.get("/{id}", response_model=ItemResponse)
async def get_item(id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Item).where(Item.id == id))
    if not (item := result.scalar_one_or_none()):
        raise HTTPException(404, "Not found")
    return item
```

### JSONB Mutation Pattern (Critical)
```python
from sqlalchemy.orm.attributes import flag_modified

# MUST use flag_modified for nested JSONB updates
agent.agent_metadata['key'] = value
flag_modified(agent, 'agent_metadata')  # REQUIRED
await db.commit()
```

### Service Layer Pattern
```python
class ItemService:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create(self, data: ItemCreate) -> Item:
        item = Item(**data.dict())
        self.db.add(item)
        await self.db.commit()
        return item
    
    async def get(self, id: int) -> Optional[Item]:
        result = await self.db.execute(select(Item).where(Item.id == id))
        return result.scalar_one_or_none()
```

### WebSocket Handler Pattern
```python
@router.websocket("/ws/{id}")
async def ws_endpoint(ws: WebSocket, id: str):
    await manager.connect(ws, id)
    try:
        while True:
            data = await ws.receive_json()
            await process_message(data)
    except WebSocketDisconnect:
        manager.disconnect(id)
```

## Pattern Selection

| Task | Pattern |
|------|---------|
| New endpoint | crud_endpoint.py |
| Business logic | service_layer.py |
| Real-time features | websocket_handler.py |
| JSONB fields | jsonb_mutation.py |
