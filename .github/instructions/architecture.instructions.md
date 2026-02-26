---
applyTo: '**'
description: 'Project architecture reference for NOP - folder structure, component layers, and code organization patterns.'
---

# Architecture & Structure

Project organization for NOP (Network Operations Platform).

## When This Applies
- Adding new files or components
- Navigating unfamiliar parts of codebase
- Deciding where to place new code
- Moving or reorganizing code

## Root Structure

| Folder | Purpose |
|--------|---------|
| `backend/` | FastAPI Python services |
| `frontend/` | React TypeScript UI |
| `docker/` | Container configurations |
| `docs/` | Documentation by type |
| `.github/` | AKIS framework + workflows |
| `.project/` | Blueprints, design docs, feature specs |
| `log/workflow/` | Session logs |
| `scripts/` | Python automation |

## Root Files
- .py: agent.py only
- .sh: deploy.sh only  
- .md: README, CHANGELOG, CONTRIBUTING
- config: docker-compose.yml, .env, project_knowledge.json

## Layers

| Layer | Tech | Location |
|-------|------|----------|
| API | FastAPI, asyncio | `backend/app/` |
| UI | React, TypeScript, Zustand | `frontend/src/` |
| Infra | Docker, PostgreSQL, Redis | `docker/`, `docker-compose.yml` |
| Agent | AKIS framework | `.github/` |

## File Placement

| Type | Location |
|------|----------|
| Source | `{service}/src/` or `{service}/app/` |
| Tests | `{service}/tests/` |
| Docs | `docs/{type}/` |
| Blueprints | `.project/{feature}/` |
| Logs | `log/workflow/` |
| Infra | Root `docker-compose.yml` |

## Finding Related Code

| Component | Location |
|-----------|----------|
| Services | `backend/app/services/` |
| API routes | `backend/app/api/` |
| UI components | `frontend/src/components/` |
| State stores | `frontend/src/store/` |
| Hooks | `frontend/src/hooks/` |
| Pages | `frontend/src/pages/` |

## ⚠️ Critical Gotchas

See [quality.instructions.md](quality.instructions.md) for full gotchas list.

**Architecture-specific:**
- Services: Use `async/await`, avoid blocking calls
- State: Use Zustand `useStore` hooks (not Redux patterns)
- Runtime: Docker-first, services run in containers
