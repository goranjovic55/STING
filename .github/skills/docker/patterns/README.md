# Docker Patterns

Reusable patterns for container management and Docker Compose operations.

## Pattern Files

| Pattern | Description | Usage |
|---------|-------------|-------|
| `dev_startup.sh` | Development startup | Start all services |
| `rebuild_service.sh` | Rebuild single service | Code changes |
| `force_recreate.sh` | Force full recreate | Cache issues |
| `clean_rebuild.sh` | Clean rebuild | Dependency changes |

## Development Startup (DEFAULT)
```bash
docker compose -f docker/docker-compose.dev.yml up -d
```

## Rebuild Single Service
```bash
docker compose -f docker/docker-compose.dev.yml up -d --build backend
```

## Force Full Recreate (Cache Issues)
```bash
docker compose up -d --build --force-recreate backend
```

## Clean Rebuild (Dependency Changes)
```bash
docker compose build --no-cache backend
docker compose up -d
```

## Debug Container
```bash
docker compose logs -f backend --tail 100
docker exec -it nop-backend bash
```

## Pattern Selection

| Situation | Pattern |
|-----------|---------|
| Start development | dev_startup.sh |
| Code changes | rebuild_service.sh |
| Cache issues | force_recreate.sh |
| Dependency changes | clean_rebuild.sh |
