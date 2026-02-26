---
name: docker
description: Load when editing Dockerfile, docker-compose*.yml, or managing containers. Provides container management patterns for development and production environments.
---

# Docker

## Merged Skills
- **container-management**: Start, stop, rebuild, logs
- **compose-files**: Multi-container orchestration, environment separation

## ⚠️ Critical Gotchas

| Category | Pattern | Solution |
|----------|---------|----------|
| Stale code | `restart` keeps old code | Use `up -d --build` instead |
| Cache issues | Changes not appearing | Add `--force-recreate` flag |
| Wrong compose | Using prod for dev | Always use `docker-compose.dev.yml` for local |
| Network sockets | Broadcast not working | Add `SO_BROADCAST` socket option |
| Volume mounts | Source changes not reflecting | Check volume paths in compose file |
| Port conflicts | Container won't start | Check ports 3000, 8000, 5432 not in use |

## Rules

| Rule | Pattern |
|------|---------|
| Dev compose | Always use `docker-compose.dev.yml` for local development |
| Rebuild after code | `up -d --build` not `restart` |
| Force recreate | Add `--force-recreate` when cache issues |
| Check logs first | `docker compose logs -f {service}` before debugging |
| Clean rebuilds | `--no-cache` for dependency changes |

## Avoid

| ❌ Bad | ✅ Good |
|--------|---------|
| `docker compose restart` | `docker compose up -d --build` |
| Production compose for dev | `docker-compose.dev.yml` |
| Debugging without logs | `docker compose logs -f backend` |
| Ignoring exit codes | Check `docker compose ps` for health |

## Patterns

```bash
# Pattern 1: Development startup (DEFAULT)
docker compose -f docker/docker-compose.dev.yml up -d

# Pattern 2: Rebuild single service
docker compose -f docker/docker-compose.dev.yml up -d --build backend

# Pattern 3: Force full recreate (cache issues)
docker compose up -d --build --force-recreate backend

# Pattern 4: Clean rebuild (dependency changes)
docker compose build --no-cache backend
docker compose up -d

# Pattern 5: Debug container
docker compose logs -f backend --tail 100
docker exec -it nop-backend bash
```

## Environment Detection

| Situation | Compose File |
|-----------|--------------|
| Local development | `docker/docker-compose.dev.yml` |
| Production deploy | `docker-compose.yml` |
| Testing | `docker/docker-compose.test.yml` |
| Debugging | `docker/docker-compose.debug.yml` |

## Commands

| Task | Command |
|------|---------|
| Start dev | `docker compose -f docker/docker-compose.dev.yml up -d` |
| Rebuild service | `docker compose up -d --build backend` |
| View logs | `docker compose logs -f backend` |
| Enter container | `docker exec -it nop-backend bash` |
| Stop all | `docker compose down` |
| Full reset | `docker compose down && docker compose up -d --build` |
| Check status | `docker compose ps` |
