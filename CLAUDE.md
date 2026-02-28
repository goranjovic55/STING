# STING 2.0 — AKIS Framework v8.0
> Deception Platform — Transparent Proxy + Session Layer + Real-Time Malware Lab

## Project Overview
STING 2.0 is a deception platform that acts as a transparent proxy overlay over existing services.
Every connection is hostile until cleared. Session layer buffers all writes. Operator decides: NUKE / COMMIT / LAB.

## Architecture Summary
- **Proxy Layer**: asyncssh (:22), nginx middleware (:80), Go TCP proxy (generic)
- **Verdict Engine**: score 0-100, starts hostile, drops on clean behavior
- **Session Layer**: per-session write buffer (memory dict / tmpfs / savepoint)
- **Canary System**: file/credential/URL/DNS/token canaries
- **Malware Lab**: isolated Docker network, real-time strace/tshark/inotify streams via WebSocket
- **Backend API**: FastAPI :8700
- **Frontend UI**: React :8701

## Stack
- Backend: Python / FastAPI / asyncpg / asyncssh
- Frontend: React + Vite + TypeScript
- Database: PostgreSQL
- Real-time: WebSocket (4 streams: syscalls/network/filesystem/processes)
- Lab: Docker isolated network, strace, tshark, inotifywait, pspy64

## Project Structure
```
sting/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/v1/
│   │   │   ├── events.py
│   │   │   ├── sessions.py
│   │   │   ├── canary.py
│   │   │   ├── samples.py
│   │   │   ├── lab.py
│   │   │   └── export.py
│   │   ├── proxy/
│   │   │   ├── ssh_proxy.py      # asyncssh proxy + virtual FS
│   │   │   ├── http_proxy.py     # FastAPI middleware
│   │   │   └── tcp_proxy.py      # generic TCP proxy
│   │   ├── verdict/
│   │   │   ├── engine.py         # scoring state machine
│   │   │   ├── rules.py          # score events/weights
│   │   │   └── session_layer.py  # per-session write buffer
│   │   ├── lab/
│   │   │   ├── detonator.py      # spawn isolated container
│   │   │   ├── monitor.py        # strace/tshark/inotify sidecar
│   │   │   ├── streamer.py       # WebSocket event push
│   │   │   └── analyzer.py       # YARA + MITRE mapping
│   │   ├── models/
│   │   │   ├── session.py
│   │   │   ├── event.py
│   │   │   ├── sample.py
│   │   │   └── lab_job.py
│   │   └── core/
│   │       ├── config.py
│   │       ├── auth.py
│   │       └── db.py
│   ├── tests/
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Sessions.tsx
│   │   │   ├── Canaries.tsx
│   │   │   ├── Samples.tsx
│   │   │   └── Lab.tsx
│   │   ├── components/
│   │   │   ├── LiveFeed.tsx
│   │   │   ├── SessionDiff.tsx
│   │   │   ├── LabViewer.tsx     # real-time syscall/network/fs/proc streams
│   │   │   └── ThreatMap.tsx
│   │   └── api/
│   └── package.json
├── lab/
│   ├── Dockerfile.victim         # clean base image
│   ├── Dockerfile.sidecar        # strace+tshark+inotify+pspy
│   ├── docker-compose.lab.yml    # isolated network
│   └── fake-services/
│       ├── dns_sink.py
│       └── http_sink.py
├── docker-compose.yml
├── .project/blueprints/
└── CLAUDE.md (this file)
```

## AKIS Gates

### G0 — Framework Load
- Read this CLAUDE.md fully
- Understand the deception platform model
- Check existing code before writing new

### G1 — Context
- Hostile-until-cleared: every session starts at score 100
- Session layer intercepts ALL writes — real service untouched until COMMIT
- Three operator decisions: NUKE / COMMIT / LAB
- Resource envelopes per session (disk/memory/TTL limits)
- Universal model across SSH/HTTP/FTP/DB/TCP

### G2 — Design Before Code
- Plan module structure before implementing
- Identify dependencies (asyncssh, FastAPI, Docker SDK, yara-python)
- Design DB schema before writing models
- Design WebSocket message format before implementing streams

### G3 — Implementation Standards
- FastAPI: async everywhere, Pydantic models for all request/response
- asyncssh: subclass SSHServer + SFTPServer for virtual FS
- Session layer: dict-based for SSH (path→content), savepoint-based for DB
- Verdict engine: event-driven, thread-safe score updates
- Lab streams: 4 WebSocket channels per job (syscalls/network/fs/processes)

### G4 — Self-Review
- No sync code in async context
- Session layer never references real FS directly
- Score events are logged with timestamp + session_id
- Resource limits enforced at write time, not after

### G5 — Testing
- Unit test verdict engine (score transitions)
- Unit test session layer (write/read/nuke/commit)
- Integration test: SSH proxy → verdict → virtual FS
- Integration test: detonation → stream → WebSocket

### G6 — Documentation
- API endpoints: OpenAPI auto-docs via FastAPI
- WebSocket message schemas: document all 4 stream formats
- Lab setup: README for isolated Docker network

### G7 — Delivery
- `git add . && git commit -m "feat: ..." && git push origin master`
- Verify services start: `docker-compose up -d`
- Report: what was built, what tested, what's next

## Phase 1 Tasks (START HERE)

Build in this order:

1. **Project scaffold** — create directory structure above
2. **Database schema** — PostgreSQL, tables: sessions, events, canaries, samples, lab_jobs
3. **Backend skeleton** — FastAPI app, health endpoint, JWT auth stub
4. **Session model** — `session_layer.py`: write/read/nuke/commit/diff operations
5. **Verdict engine** — `engine.py`: score state machine, event handlers, score rules
6. **WebSocket event bus** — single bus, multiple channels, sessions subscribe
7. **SSH proxy stub** — asyncssh server, accepts connections, creates session layer, serves fake shell
8. **Virtual FS** — canary files, fake /etc/shadow, fake /root/secrets.txt
9. **Basic React shell** — pages scaffold, sidebar nav, WebSocket connection
10. **Live event feed component** — renders real-time events from WebSocket

Commit after each working piece. Push to GitHub.

## Key Rules
- NUKE = drop session layer, zero trace, real service untouched
- COMMIT = merge session layer to real service
- LAB = snapshot session layer → ship to lab → wipe proxy side
- Resource limit breach = auto-nuke + score spike +40
- Score < 30 = passthrough to real service (transparent proxy mode)
- Score ≥ 30 = trap mode (virtual FS, canaries, fake responses)
