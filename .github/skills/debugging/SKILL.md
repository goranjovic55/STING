---
name: debugging
description: Load when encountering errors, tracebacks, or investigating bugs. Provides systematic debugging patterns and common gotchas from 141 workflow logs.
---

# Debugging

## Merged Skills
- **error-analysis**: Reading tracebacks, identifying root cause
- **gotcha-lookup**: Known issues from project history

## ⚠️ Critical Gotchas (from 131 logs)

| Category | Pattern | Solution |
|----------|---------|----------|
| API | 307 redirect on POST | Add trailing slash to URL |
| API | 401 on valid token | Check auth headers, token expiry |
| Auth | localStorage returns null | Check `nop-auth` key, not `auth_token` |
| State | Persisted state stale | Version storage key, clear cache |
| State | Nested object not updating | Use immutable update or flag_modified |
| State | React state stale in async | Use callback/ref patterns |
| State | ConfigPanel save lost | Persist to backend, not just Zustand |
| Build | Changes not visible | Rebuild with `--no-cache` |
| Build | Container old code | Use `--build --force-recreate` |
| Syntax | JSX comment error | Use `{/* */}` not `//` in JSX |
| CSS | Element hidden | Check z-index, overflow, position |
| Frontend | Dropdown flickering | Memoize options with useMemo |
| Frontend | Black screen | Add error boundary/try-catch |
| Mock | Block executor mock data | Check mock vs real implementation |
| JSONB | Nested object not updating | Use `flag_modified()` after update |
| Workflow | Progress stuck at 3/4 | Set 100% on `execution_completed` event |
| Workflow | Black screen on switch | Call `reset()` to clear execution state |
| Context | Connection menu hidden | Check DOM ordering, z-index, pointer-events |
| Cache | Same skill reloaded | Load skill ONCE per domain, cache list |
| Scripts | Parse fails | Create log BEFORE running scripts |
| Workflow | END scripts fail | Create workflow log FIRST |
| Terminal | Line wrapping corrupts | Limit line length, handle overflow |
| Undo/Redo | Deep state breaks | Use immutable update patterns |
| Credentials | Params missing | Validate block config completeness |
| JS | Empty object {} is truthy | Use `Object.keys(obj).length > 0` check |
| WebSocket | execution_completed missing state | Include nodeStatuses in WS completion event |
| Docker | Bridge uses gateway IP | Use different IP for containers (e.g., 172.x.0.254) |
| Ports | Wrong service on port | Verify port mappings (8000=Portainer, 12000=NOP) |
| API | Wrong endpoint path | Check actual API routes, not assumed ones |

## Rules

| Rule | Pattern |
|------|---------|
| Check gotchas first | 75% of issues are known - check table above |
| Read full traceback | Don't stop at first error line |
| Root cause focus | Fix cause, not symptoms |
| Plan before fix | Understand problem before coding |
| Verify fix works | Test that issue is actually resolved |
| Document findings | Add new gotchas to workflow log |

## Avoid

| ❌ Bad | ✅ Good |
|--------|---------|
| Fix symptoms | Find root cause |
| Ignore traceback | Read entire error |
| Skip gotcha check | Check known issues first |
| Assume fix works | Verify with test |
| Undocumented fix | Add to gotchas if new |

## Patterns

```python
# Pattern 1: JSONB mutation fix (SQLAlchemy)
from sqlalchemy.orm.attributes import flag_modified

agent.agent_metadata['key'] = value
flag_modified(agent, 'agent_metadata')  # CRITICAL
await db.commit()

# Pattern 2: Async state capture (React)
const handleClick = async () => {
  const capturedState = { ...localState };  // Capture BEFORE async
  await updateNode(nodeId, capturedState);
  await saveCurrentWorkflow();
};
```

```tsx
// Pattern 3: Error boundary wrapper
<ErrorBoundary fallback={<ErrorFallback />}>
  <RiskyComponent />
</ErrorBoundary>
```

```bash
# Pattern 4: Container debugging
docker compose logs -f backend --tail 100
docker exec -it nop-backend bash
docker compose down && docker compose up -d --build
```

## Debug Protocol

| Step | Action |
|------|--------|
| 1 | **CHECK gotchas table** (75% are known) |
| 2 | READ full error/traceback |
| 3 | ANALYZE root cause (not symptoms) |
| 4 | PLAN fix before implementing |
| 5 | VERIFY fix resolves issue |
| 6 | DOCUMENT in workflow log |

## Commands

| Issue | Command |
|-------|---------|
| Backend logs | `docker compose logs -f backend` |
| Frontend logs | `docker compose logs -f frontend` |
| Rebuild clean | `docker compose build --no-cache` |
| Full reset | `docker compose down && docker compose up -d --build` |
| Check processes | `docker compose ps` |
| Enter container | `docker exec -it nop-backend bash` |
