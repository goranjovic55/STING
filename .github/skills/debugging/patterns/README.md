# Debugging Patterns

Reusable patterns for systematic debugging and error resolution.

## Pattern Files

| Pattern | Description | Usage |
|---------|-------------|-------|
| `jsonb_fix.py` | JSONB mutation fix | SQLAlchemy nested updates |
| `async_capture.tsx` | Async state capture | React stale closure fix |
| `error_boundary.tsx` | Error boundary wrapper | Prevent black screens |
| `container_debug.sh` | Container debugging | Docker log analysis |

## JSONB Mutation Fix (SQLAlchemy)
```python
from sqlalchemy.orm.attributes import flag_modified

agent.agent_metadata['key'] = value
flag_modified(agent, 'agent_metadata')  # CRITICAL
await db.commit()
```

## Async State Capture (React)
```tsx
const handleClick = async () => {
  const capturedState = { ...localState };  // Capture BEFORE async
  await updateNode(nodeId, capturedState);
  await saveCurrentWorkflow();
};
```

## Error Boundary Wrapper
```tsx
<ErrorBoundary fallback={<ErrorFallback />}>
  <RiskyComponent />
</ErrorBoundary>
```

## Container Debugging
```bash
docker compose logs -f backend --tail 100
docker exec -it nop-backend bash
docker compose down && docker compose up -d --build
```

## Pattern Selection

| Issue | Pattern |
|-------|---------|
| JSONB not saving | jsonb_fix.py |
| React stale state | async_capture.tsx |
| Black screen | error_boundary.tsx |
| Container issues | container_debug.sh |
