---
applyTo: 'frontend/**,backend/**'
description: 'Coordination patterns for fullstack changes spanning frontend and backend.'
---

# Fullstack Sessions

> Based on 100k simulation: 65.6% of sessions are fullstack

## When This Applies
- Editing both frontend and backend in same session
- Adding new API endpoints with UI
- Debugging cross-layer issues

## Pre-Load Skills
When editing both frontend + backend:
```
frontend-react ⭐ + backend-api ⭐
```

## Coordination Checklist
1. **API Changes** → Update types → Update UI → Test
2. **Database Schema** → Run migration → Update models → Update API → Update frontend
3. **New Feature** → Plan → Backend service → API endpoint → Frontend component → Integration test

## Common Patterns

| Change Type | Order | Skills |
|-------------|-------|--------|
| New endpoint | Backend → Frontend | backend-api, frontend-react |
| UI update | Frontend → Backend (if API needed) | frontend-react, backend-api |
| Bug fix | Debug → Fix → Test | debugging, testing |
| Schema change | Migration → Model → API → UI | backend-api, frontend-react |

## Gotchas

See [quality.instructions.md](quality.instructions.md) for full gotchas list.

**Fullstack-specific:** 307 redirect → add trailing slash, CORS → check main.py origins

## Verification
After fullstack changes:
1. Check API response (backend logs): `docker compose logs -f backend`
2. Check network tab (frontend): DevTools → Network
3. Test end-to-end flow
4. Verify state persistence: Check localStorage/sessionStorage

## Token Optimization
- Use domain_index for O(1) file lookup
- Check hot_cache before reading files
- Batch related edits together
