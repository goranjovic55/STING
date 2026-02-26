---
applyTo: 'Dockerfile,docker-compose*.yml,**/*.sh,**/Dockerfile'
description: 'Docker build and deployment commands for NOP project.'
---

# Build

Setup and validation commands for NOP project.

## When This Applies
- Starting or stopping services
- Rebuilding after code changes
- Debugging container issues

## Setup

```bash
docker-compose up -d          # Start all services
docker-compose logs -f        # View logs
```

## Common Tasks

| Task | Command |
|------|---------|
| Start | `docker-compose up -d` |
| Stop | `docker-compose down` |
| Rebuild | `docker-compose build --no-cache` |
| Backend logs | `docker-compose logs -f backend` |
| Frontend logs | `docker-compose logs -f frontend` |

## ⚡ Command Batching (Reduce API Calls)

**Batch independent commands with `&&`:**
```bash
# ❌ Bad: 3 separate terminal calls
docker-compose down
docker-compose build
docker-compose up -d

# ✅ Good: 1 terminal call
docker-compose down && docker-compose build && docker-compose up -d
```

**Batch file operations:**
```bash
# ❌ Bad: Multiple greps
grep -r "pattern1" src/
grep -r "pattern2" src/

# ✅ Good: Single grep with alternation
grep -rE "pattern1|pattern2" src/
```

**Target:** Reduce terminal API calls by 30% through batching

## ⛔ MANDATORY Before Finishing

1. **Check logs** for errors: `docker-compose logs backend`
2. **Verify services** running: `docker-compose ps`
3. **Test changes** in browser if UI modified

## ⚠️ Critical Gotchas

See [quality.instructions.md](quality.instructions.md) for full gotchas list.

**Build-specific:** Restart ≠ Rebuild (code changes need `docker-compose build`)
