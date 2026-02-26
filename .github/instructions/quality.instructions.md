---
applyTo: '**'
description: 'Quality checks and common gotchas. Verification steps and error protocol.'
---

# Quality

> Based on 100k simulation: Check gotchas FIRST for 75% debug acceleration

## When This Applies
- After every code edit
- When encountering errors
- Before committing changes

## After Every Edit
1. Verify syntax (no errors)
2. Check duplicates (multi-file edits)
3. Validate imports

## Error Protocol
1. **CHECK gotchas table FIRST** (75% are known issues)
2. READ full error/traceback
3. ANALYZE root cause (not symptoms)
4. Load debugging skill
5. PLAN fix before implementing
6. VERIFY fix resolves issue
7. DOCUMENT root cause in workflow log

## Checklist
□ No syntax errors | □ No duplicates | □ Imports resolve | □ Tests pass

## ⚠️ Common Gotchas (from 141 workflow logs - top 30 kept)

| Category | Pattern | Solution |
|----------|---------|----------|
| API | 307 redirect on POST | Add trailing slash to URL |
| API | 401 on valid token | Check auth headers, token expiry |
| State | Persisted state stale | Version storage key, clear cache |
| State | Nested object not updating | Use immutable update or flag_modified |
| Build | Changes not visible | Rebuild with `--no-cache` |
| Build | Container old code | Use `--build --force-recreate` |
| Syntax | JSX comment error | Use `{/* */}` not `//` in JSX |
| CSS | Element hidden | Check z-index, overflow, position |
| Scripts | Parse fails | Create log BEFORE running scripts |
| Workflow | END scripts fail | Create workflow log FIRST |
| Frontend | Dropdown flickering | Memoize options with useMemo |
| Frontend | Black screen | Add error boundary/try-catch |
| Terminal | Line wrapping corrupts | Limit line length, handle overflow |
| Undo/Redo | Deep state breaks | Use immutable update patterns |
| Credentials | Params missing | Validate block config completeness |
| Auth | localStorage returns null | Check `nop-auth` key, not `auth_token` |
| State | React state stale in async | Use callback/ref patterns |
| State | ConfigPanel save lost | Persist to backend, not just Zustand |
| Mock | Block executor mock data | Check mock vs real implementation |
| JSONB | Nested object not updating | Use `flag_modified()` after update |
| Workflow | Progress stuck at 3/4 | Set 100% on `execution_completed` event |
| Workflow | Black screen on switch | Call `reset()` to clear execution state |
| Context | Connection menu hidden | Check DOM ordering, z-index, pointer-events |
| Cache | Same skill reloaded | Load skill ONCE per domain, cache list |
| JS | Empty object {} is truthy | Use `Object.keys(obj).length > 0` check |
| WebSocket | execution_completed missing state | Include nodeStatuses in WS completion event |
| API | 307 redirect on DELETE | Remove trailing slashes from frontend, add fallback routes |
| Remote | guacd security layer mismatch | Use security='any' + XRDP security_layer=negotiate |
| Build | Frontend changes not visible | Clear browser cache with Ctrl+Shift+R |
| Protocol | VNC asks for username | Use conditional rendering `tab.protocol !== 'vnc'` |
| Guacamole | Keyboard stuck after disconnect | Replace Guacamole.Keyboard with native event listeners |
| Guacamole | Pointer lock traps cursor | Remove requestPointerLock() calls entirely |
| Fullscreen | Browser extension overlay on maximize | Test in incognito mode to isolate extension interference |
| Fullscreen | Browser API triggers native controls | Use CSS `fixed inset-0 z-50` instead of requestFullscreen() |
| Docker | Bridge uses gateway IP (172.x.0.1) | Use different IP for containers (e.g., 172.x.0.254) |
| Ports | Port 8000 is Portainer not NOP | Use port 12000 for NOP frontend proxy |
| API | Non-existent /api/v1/discovery/ | Use /api/v1/traffic/l2/topology for L2 data |
| API | Health at /health not /api/v1/health | Use root /health endpoint |
| Testing | API response field names vary | Check actual response structure before asserting |
| Edit | Multi-replace overlapping matches | Use separate replace operations for distinct sections |
| Topology | Performance modes override styles | Update color in ALL branches (>300, >1000 nodes) |
| MAC | Locally administered MACs no vendor | 2nd hex digit 2/6/A/E = local, use "VM/Container" |
| MAC | Docker/VM MAC prefixes | 02:42:xx=Docker, d2:xx/92:xx=VM, detect via 2nd digit |
| Build | Frontend container old code | Rebuild via `docker-compose.dev.yml`, Ctrl+Shift+R |
| Hostname | Fake host-x-x-x-x names | Set hostname=None, only use real DNS/DHCP hostnames |
| TypeScript | Closure null narrowing fails | Use local binding `const snapshot = data` before callback |
| React | Initial useEffect skips data fetch | Include `token` in deps, not empty `[]` |
| Build | Volume mounts don't update deps | Source code reflects live, dependencies need rebuild |
| Ports | Port 3000/8000 conflicts | Check ports not in use before starting |
| State | State not syncing across components | Use WebSocket or polling with `useEffect` |
| Types | Frontend/backend type mismatch | Regenerate types: `npm run generate-types` |
| UI | Button onClick not working | Verify onClick handler is connected to function |
