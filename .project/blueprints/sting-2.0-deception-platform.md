# STING 2.0 — Deception Platform Blueprint
**Version:** 2.0-DRAFT-r2 | **Date:** 2026-02-28 | **Author:** Falke AI

---

## 1. EVOLUTION: 1.0 → 2.0

```
STING 1.0 (current)          STING 2.0 (proposed)
─────────────────────         ──────────────────────────────────────
Cowrie logs → parse           Transparent proxy overlay
→ analyze → alert             + Verdict engine (hostile-until-cleared)
                              + Userspace virtual FS
                              + Real-time malware lab
                              + Full web UI + REST API
Passive observer              Active deception operator
```

---

## 2. CORE DESIGN PRINCIPLE

**Hostile Until Cleared.**

Every connection is treated as hostile by default. STING owns the public ports. Real services run internally. The proxy decides in real-time what each session sees.

```
BEFORE (direct exposure):
Internet → :22   → sshd (real)
Internet → :80   → nginx (real)
Internet → :5432 → postgres (real)

AFTER (STING overlay):
Internet → :22   → STING PROXY ─→ verdict engine
Internet → :80   → STING PROXY ─→ verdict engine
Internet → :5432 → STING PROXY ─→ verdict engine
                        │
                   HOSTILE │ CLEARED
                        ↓       ↓
                   Trap layer  Passthrough
                   Fake shell  :22022 sshd
                   Canaries    :8081 nginx
                   Capture     :6432 postgres

Real services untouched. Just moved to internal ports.
```

**No kernel code. No OverlayFS. No eBPF. Pure userspace.**

Research confirms this approach is novel — no existing open-source tool combines:
1. Transparent proxy overlay over real services
2. Verdict-based hostile-until-cleared scoring
3. Dynamic passthrough to real backend
4. Real-time malware lab with syscall streaming

Closest existing: Honeytrap (proxy capability, no verdict). Cowrie (SSH deception, no proxy/passthrough).

---

## 3. ARCHITECTURE

```
┌───────────────────────────────────────────────────────────────────┐
│                         INTERNET                                  │
└──────────────────────────┬────────────────────────────────────────┘
                           │ all traffic
              ┌────────────▼────────────────┐
              │      STING PROXY LAYER       │
              │   (userspace, per-protocol)  │
              │                             │
              │  SSH proxy  (asyncssh :22)  │
              │  HTTP proxy (fastapi  :80)  │
              │  TCP proxy  (generic  :any) │
              └──────────┬──────────────────┘
                         │
              ┌──────────▼──────────────────┐
              │      VERDICT ENGINE          │
              │                             │
              │  session score (0-100)      │
              │  100 = hostile (default)    │
              │  drops on clean behavior    │
              │  spikes on hostile patterns │
              └───┬───────────────┬─────────┘
                  │               │
          HOSTILE │               │ CLEARED
                  ▼               ▼
        ┌─────────────┐   ┌──────────────────┐
        │ TRAP LAYER  │   │ REAL SERVICES    │
        │             │   │                  │
        │ Virtual FS  │   │ sshd  :22022     │
        │ Fake shell  │   │ nginx :8081      │
        │ Canary files│   │ any   :X+1000    │
        │ Fake creds  │   │                  │
        │ Capture hook│   │ (transparent,    │
        │             │   │  session still   │
        └──────┬──────┘   │  monitored)      │
               │          └──────────────────┘
               ▼
        ┌─────────────────────────────┐
        │      STING BACKEND API      │
        │      (FastAPI :8700)        │
        │                             │
        │  /events  /samples  /lab    │
        │  /canary  /verdict  /export │
        └──────────┬──────────────────┘
                   │
        ┌──────────▼──────────────────┐
        │      STING FRONTEND UI      │
        │      (React :8701)          │
        │                             │
        │  Dashboard  │  Lab View     │
        │  Trap Mgmt  │  Sample View  │
        └─────────────────────────────┘
                   │
        ┌──────────▼──────────────────┐
        │      MALWARE LAB            │
        │  (isolated Docker network)  │
        │                             │
        │  Victim container           │
        │  Monitoring sidecar         │
        │  Real-time syscall stream   │
        │  WebSocket → frontend       │
        └─────────────────────────────┘
```

---

## 4. VERDICT ENGINE

Real-time scoring. Every session starts at 100 (hostile).

```
SCORE EVENTS:

Drops (toward cleared):
  Successful auth (known-good cred)    -30
  Normal file access (non-canary)       -5 per action
  Normal commands (ls, cd, cat)         -2 per command
  No recon patterns after 30s          -20
  Clean for 60s continuous             -20

Spikes (stay/return hostile):
  Failed auth attempt                  +15
  Canary file accessed                 +50  (flags session permanently)
  wget/curl to executable              +80  (flags permanently)
  /etc/passwd read                     +25
  uname+id+whoami combo (recon seq)    +40
  Known bad IP (threat intel)          +100 (irrecoverable)
  Binary execution from /tmp           +60

Passthrough threshold:  score < 30
Re-hostile threshold:   score > 50 (yanks passthrough mid-session)
```

**Session state machine:**

```
HOSTILE (100) ──[clean behavior]──→ PENDING ──[threshold]──→ CLEARED
    ↑                                                            │
    └──────────────[hostile pattern detected]────────────────────┘
```

---

## 5. PROXY IMPLEMENTATIONS

### SSH Proxy (asyncssh)

```python
class StingSSHProxy(asyncssh.SSHServer):
    
    async def on_connect(self, conn):
        session = Session(conn.get_extra_info('peername'))
        session.score = 100  # hostile by default
        
    async def auth_attempt(self, user, password):
        self.session.score_event('AUTH_ATTEMPT', +15)
        if is_known_good(user, password):
            self.session.score_event('AUTH_SUCCESS', -30)
            return True
        # Always accept — attacker gets fake shell
        return True
    
    async def get_shell(self):
        if self.session.score < 30:
            # Cleared — proxy to real sshd
            return await proxy_to_real(self.real_host, self.real_port)
        else:
            # Hostile — serve virtual shell
            return StingVirtualShell(self.session)

class StingVirtualFS:
    CANARY_FILES = {
        '/root/secrets.txt':      ('db_pass=Sup3rS3cr3t!', 'CANARY'),
        '/etc/shadow':            (fake_shadow,             'CANARY'),
        '/home/admin/.ssh/id_rsa': (fake_privkey,           'CANARY'),
        '/var/backups/db.sql':    (fake_sql_dump,           'CANARY'),
    }
    # All other paths: serve realistic fake content
    # Writes: accepted silently, never persist
```

### HTTP Proxy (nginx + lua verdict check)

```nginx
location / {
    access_by_lua_block {
        local verdict = get_verdict(ngx.var.remote_addr)
        if verdict == "hostile" then
            -- serve trap response (fake login, canary page)
            ngx.exec("@sting_trap")
        end
        -- cleared: fall through to real backend
    }
    proxy_pass http://127.0.0.1:8081;
}
```

### Generic TCP Proxy (Go)

```go
// For any service STING doesn't have a specific proxy for
// Bind to :X, proxy to :X+1000 if cleared, else serve trap
func handleConn(c net.Conn) {
    session := verdict.GetSession(c.RemoteAddr())
    if session.Score < 30 {
        proxyTo(c, realPort)
    } else {
        serveTrap(c, session)
    }
}
```

---

## 6. CANARY SYSTEM

Canaries are tripwires embedded in the fake layer.

| Canary Type | Trigger | Score Impact |
|-------------|---------|-------------|
| File canary | read/open on fake file | +50, permanent flag |
| Credential canary | login with fake cred | +60, permanent flag |
| URL canary | HTTP GET to beacon URL | alert only (external) |
| Token canary | AWS key / API key used | alert only (external) |
| DNS canary | lookup of unique subdomain | alert only (external) |

URL/token/DNS canaries beacon back to STING API even if attacker uses the credential from *outside* the trap environment. Out-of-band detection.

---

## 7. MALWARE LAB — REAL-TIME ANALYSIS

The core innovation: not just capture and report — watch it run live.

### Architecture

```
DETONATION:
Malware sample
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  ISOLATED DOCKER NETWORK (172.31.0.0/24)            │
│  No route to internet. Fake services only.          │
│                                                     │
│  ┌──────────────────┐    ┌─────────────────────┐   │
│  │  VICTIM CONTAINER │    │  MONITORING SIDECAR │   │
│  │                  │    │                     │   │
│  │  Clean base img  │◄───│  strace -f -e all   │   │
│  │  Malware runs    │    │  tshark -i any      │   │
│  │  here            │    │  inotifywait -m -r  │   │
│  │                  │    │  pspy64             │   │
│  │                  │    │  ss -tlnp poll      │   │
│  └──────────────────┘    └──────────┬──────────┘   │
│                                     │               │
│           ┌─────────────────────────┘               │
│           │ event streams                           │
│           ▼                                         │
│  ┌─────────────────────┐                            │
│  │  FAKE SERVICES      │                            │
│  │  DNS (logs queries) │                            │
│  │  HTTP (logs reqs)   │                            │
│  │  SMTP sink          │                            │
│  └─────────────────────┘                            │
└──────────────────────┬──────────────────────────────┘
                       │ WebSocket stream
                       ▼
                 STING API → Frontend
```

### Real-Time Streams (WebSocket)

Four parallel streams pushed live to frontend:

```
STREAM 1: SYSCALLS
{ "t": 0.001, "pid": 1234, "call": "openat",   "args": ["/etc/passwd"], "ret": 3 }
{ "t": 0.002, "pid": 1234, "call": "read",      "args": [3, 4096],       "ret": 1024 }
{ "t": 0.003, "pid": 1234, "call": "execve",    "args": ["/tmp/.x"],     "ret": 0 }
{ "t": 0.004, "pid": 1235, "call": "connect",   "args": ["45.63.x.x:4444"], "ret": 0 }

STREAM 2: NETWORK
{ "t": 0.001, "type": "dns",  "query": "pool.minexmr.com" }
{ "t": 0.002, "type": "tcp",  "dst": "45.63.x.x:4444", "syn": true }
{ "t": 0.004, "type": "data", "dst": "45.63.x.x:4444", "bytes": 256 }

STREAM 3: FILESYSTEM
{ "t": 0.001, "event": "CREATE", "path": "/tmp/.xmrig" }
{ "t": 0.003, "event": "MODIFY", "path": "/var/spool/cron/root" }
{ "t": 0.004, "event": "DELETE", "path": "/tmp/miner.sh" }

STREAM 4: PROCESSES
{ "t": 0.000, "event": "SPAWN",  "pid": 1234, "cmd": "/bin/sh miner.sh" }
{ "t": 0.003, "event": "SPAWN",  "pid": 1235, "cmd": "/tmp/.xmrig --pool ..." }
{ "t": 0.003, "event": "SPAWN",  "pid": 1236, "cmd": "crontab -" }
```

### Live Lab UI

```
╔══════════════════════════════════════════════════════════════════════╗
║  ◈ STING / LAB / miner.sh  [▶ RUNNING 00:03]  [⏸ PAUSE] [⏹ STOP] ║
╠══════════════════════════════════════════════════════════════════════╣
║  SYSCALLS                    NETWORK                                 ║
║  ┌─────────────────────┐     ┌───────────────────────────────────┐  ║
║  │openat /etc/passwd   │     │→ DNS pool.minexmr.com             │  ║
║  │read fd=3 1024b      │     │→ TCP 45.63.x.x:4444 SYN           │  ║
║  │execve /tmp/.xmrig   │🔴   │← SYN-ACK                          │  ║
║  │connect 45.63.x.x   │🔴   │→ DATA 256b                        │  ║
║  │write crontab        │🔴   └───────────────────────────────────┘  ║
║  └─────────────────────┘                                            ║
║                                                                      ║
║  PROCESS TREE                FILESYSTEM DIFF                        ║
║  ┌─────────────────────┐     ┌───────────────────────────────────┐  ║
║  │ sh (1234)           │     │ + /tmp/.xmrig                     │  ║
║  │ └─ .xmrig (1235) 🔴│     │ ~ /var/spool/cron/root            │🔴║
║  │ └─ crontab (1236)🔴│     │ - /tmp/miner.sh                   │  ║
║  └─────────────────────┘     └───────────────────────────────────┘  ║
║                                                                      ║
║  TIMELINE ──────────────────────────────────────────────────────   ║
║  0s    1s    2s    3s    4s    5s    6s    7s    8s    9s    10s    ║
║  EXEC  ──── NET ─── PERSIST ─── CLEAN                              ║
╚══════════════════════════════════════════════════════════════════════╝
```

### On-Demand Deep Inspection

During live session, analyst can:

```bash
# Dump process memory
/proc/{pid}/mem → strings + entropy scan → detect packed payload

# Inspect open file descriptors
/proc/{pid}/fd/* → what files/sockets is it holding

# Read memory maps
/proc/{pid}/maps → which libraries loaded, code regions

# Freeze + inspect (SIGSTOP)
kill -STOP {pid} → snapshot state → manual inspection → SIGCONT

# Container checkpoint (CRIU)
criu dump -t {pid} → full state snapshot → resume later
```

All accessible from lab UI with one click.

---

## 8. POST-ANALYSIS INTELLIGENCE

After detonation completes:

```
Raw streams
     │
     ▼
PATTERN EXTRACTOR
     │
     ├── YARA rule (from strings + behavior)
     ├── MITRE ATT&CK mapping (syscall patterns → techniques)
     ├── IOC list (IPs, domains, hashes, paths)
     └── Behavioral signature (for future detection)
     │
     ▼
STING DB (PostgreSQL)
     │
     ├── Searchable sample vault
     ├── Pattern clustering (similar behaviors grouped)
     └── IOC feed (exportable JSON/STIX)
```

**Auto-generated YARA rule:**

```
rule STING_a1b2c3 {
  meta:
    description = "Auto-generated by STING lab"
    date = "2026-02-28"
    hash = "a1b2c3..."
  strings:
    $s1 = "pool.minexmr.com"
    $s2 = "/tmp/.xmrig"
    $s3 = "--pool"
    $net1 = { 45 63 xx xx }  // C2 IP pattern
  condition:
    2 of ($s*) or $net1
}
```

---

## 9. TECH STACK

| Layer | Tech | Reason |
|-------|------|--------|
| SSH proxy | asyncssh (Python) | Full SSHv2, shell + SFTP hooks |
| HTTP proxy | nginx + lua / FastAPI middleware | Flexible verdict injection |
| TCP proxy | Go net package | Performance, simplicity |
| Backend API | FastAPI (Python) | Matches existing codebase |
| Frontend | React + Vite | Component-based, WebSocket support |
| Database | PostgreSQL | Concurrent writes, JSONB for events |
| Real-time | WebSocket (native FastAPI) | Four parallel event streams |
| Lab containers | Docker + custom network | Isolation, snapshots |
| Syscall capture | strace -f | Reliable, no kernel module |
| Network capture | tshark | Deep protocol decode |
| FS monitoring | inotifywait | Userspace, no kernel |
| Process watch | pspy64 | No root required |
| Memory inspect | /proc/{pid}/mem | Native Linux |

**All userspace. Zero kernel modules.**

---

## 10. COWRIE — DEMOTED

Cowrie no longer in critical path. Reasons:
- Detectable (timing artifacts, incomplete command set, honeyfs signatures)
- No verdict engine support
- SSH/Telnet only
- Conflicts with our virtual FS layer

**New role:** Port 2222, passive logger only. Feeds STING event stream as one signal among many. Useful as secondary attractor — unsophisticated scanners hit it first.

---

## 11. IMPLEMENTATION ROADMAP

### Phase 1 — Foundation (Week 1-2)
```
[ ] FastAPI backend skeleton (CT102:8700)
[ ] PostgreSQL schema (sessions, events, samples, verdicts, lab_jobs)
[ ] React frontend shell (CT102:8701)
[ ] JWT auth (single-user)
[ ] WebSocket event bus
[ ] Wire existing Cowrie logs to new API (backward compat)
```

### Phase 2 — Proxy + Verdict Engine (Week 2-3)
```
[ ] asyncssh SSH proxy with session tracking
[ ] Verdict engine (score state machine)
[ ] Virtual FS (canary files + fake content)
[ ] Fake shell (basic command responses)
[ ] HTTP proxy middleware (nginx lua)
[ ] Passthrough to real services on verdict
```

### Phase 3 — Canary System (Week 3-4)
```
[ ] Canary file management API + UI
[ ] File canary hit detection
[ ] Credential canary (fake creds in virtual FS)
[ ] URL/DNS/token canary beacon server
[ ] Canary dashboard (hit stats per canary)
```

### Phase 4a — Lab Foundation (Week 4)
```
[ ] Isolated Docker network setup
[ ] Victim container base image
[ ] Monitoring sidecar (strace + tshark + inotifywait + pspy)
[ ] Fake DNS/HTTP services (sink)
[ ] Raw stream collector → STING API
[ ] Detonation API endpoint
```

### Phase 4b — Real-Time Lab UI (Week 5)
```
[ ] WebSocket stream → frontend
[ ] Live syscall feed
[ ] Live network feed
[ ] Live filesystem diff
[ ] Process tree view
[ ] Timeline visualization
[ ] Pause/freeze controls (/proc SIGSTOP)
[ ] Memory inspect viewer (/proc/{pid}/mem)
```

### Phase 5 — Intelligence (Week 5-6)
```
[ ] YARA rule generator (auto from strings + behavior)
[ ] MITRE ATT&CK mapper (syscall patterns → techniques)
[ ] IOC extractor (IPs, domains, hashes, paths)
[ ] Pattern clustering (similar behaviors)
[ ] PDF report generator
[ ] IOC feed export (JSON / STIX)
```

### Phase 6 — Production Test (Week 6-7)
```
[ ] Deploy on CT102 (dev)
[ ] Wire to CT100 Cowrie as test input
[ ] Generate test malware via Venice (8 samples)
[ ] Full pipeline: capture → detonate → lab → intelligence
[ ] Load test (simulated campaign)
[ ] Harden API
[ ] Production deploy
```

---

## 12. TEST MALWARE PLAN (Venice-generated)

Before prod, test with AI-generated samples:

| Sample | Behavior | Test objective |
|--------|----------|---------------|
| Shell dropper | wget + chmod + exec | Capture + detonation |
| SSH key injector | /root/.ssh/authorized_keys write | Persistence detection |
| Crypto miner | XMRig-style, pool connect | Network + process stream |
| Port scanner | Internal sweep | Network pattern |
| Data exfil | curl to fake C2 | Network stream + IOC |
| Rootkit-lite | /proc hide attempt | Syscall detection |
| Reverse shell | bash TCP | Network + process |
| Polymorphic wrapper | base64 decode + exec | Entropy detection |

Pass: STING catches, captures, streams live, maps to MITRE, generates YARA.

---

**Awaiting green light.**

---

## 13. UNIVERSAL SESSION LAYER

Every connection — regardless of protocol — gets a **session layer**: an isolated write buffer that intercepts all mutations to the real service. The real service never sees attacker writes until operator explicitly commits.

```
UNIVERSAL MODEL:

Real Service (untouched)
        ↑
        │ only on COMMIT
        │
  SESSION LAYER (per connection)
  ┌─────────────────────────────────────┐
  │ session_id: abc123                  │
  │ ip: 45.63.x.x  score: 87           │
  │                                     │
  │ All writes buffered here            │
  │ Reads: session layer first,         │
  │        fall through to real service │
  │ Attacker sees: success always       │
  └─────────────────────────────────────┘
        │
   Operator decision:
   [NUKE]   → drop layer, zero trace
   [COMMIT] → merge to real service
   [LAB]    → ship layer to lab, wipe proxy side
              attacker stays connected (silent transfer)
              OR connection dropped (operator choice)
```

### Per-Protocol Implementation

| Service | "Write" | Session Layer | Revert |
|---------|---------|--------------|--------|
| SSH | file write | in-memory FS dict / tmpfs | del dict |
| FTP | file upload | ring buffer (last 10MB) + metadata | delete buffer |
| HTTP | POST/PUT body | request log | discard |
| PostgreSQL | INSERT/UPDATE/DELETE | SAVEPOINT per session | ROLLBACK TO SAVEPOINT |
| MySQL | same | same | same |
| SMTP | email send | queued, undelivered | dequeue |
| Redis | SET/HSET/etc | command log | replay DEL |
| Generic TCP | stream data | ring buffer | drop buffer |

### DB Isolation — Savepoint Model

```sql
-- Session connects
BEGIN;
SAVEPOINT sting_abc123;

-- Attacker runs:
INSERT INTO users VALUES ('backdoor', 'admin');
-- Attacker sees: "1 row inserted" (real, inside savepoint)

-- Operator: NUKE
ROLLBACK TO SAVEPOINT sting_abc123;
-- DB: as if it never happened

-- Operator: COMMIT
RELEASE SAVEPOINT sting_abc123; COMMIT;
-- DB: now real
```

**DDL edge case:** `CREATE TABLE` / `DROP TABLE` can't always roll back cleanly inside savepoints. Solution: hostile sessions routed to an isolated DB schema (`sting_session_abc123`). NUKE = `DROP SCHEMA sting_session_abc123 CASCADE`.

### LAB Transfer — Pre-seeded Context

When operator chooses LAB, the victim container is pre-seeded with the attacker's full session state:

```
Lab victim container receives:
  writes/          ← everything attacker wrote
  reads/           ← canary hits, accessed paths  
  captures/        ← downloaded binaries
  manifest.json    ← IP, timing, commands, score

Result: lab runs the malware in the exact environment
        the attacker set up — full attack chain visible,
        not just isolated binary
```

---

## 14. SESSION RESOURCE ENVELOPES

Every hostile session gets a fixed resource budget. Proxy enforces hard limits — resource exhaustion attacks (50GB FTP upload, 10M DB inserts) are neutralized automatically.

### Per-Session Budget

```
SESSION ENVELOPE (defaults, operator-configurable):

  disk_mb:       50     # total writes to session layer
  memory_mb:     10     # in-memory FS cap
  max_files:     100    # file count cap
  max_db_rows:   10000  # savepoint row cap
  max_duration:  1800s  # 30min hard TTL
  
ON ANY BREACH:
  action:        auto_nuke   (or: alert_only | throttle)
  score_spike:   +40         (hitting limits = hostile signal)
  notify:        true
```

### Score-Based Resource Tiers

Higher hostility = tighter resource box:

| Score | Tier | Disk | TTL |
|-------|------|------|-----|
| 80–100 | High hostile | 10MB | 5min |
| 50–79 | Medium | 25MB | 15min |
| 20–49 | Pending | 50MB | 30min |
| 0–19 | Near-cleared | full | unlimited |

### FTP / Large Upload — Ring Buffer

Never buffer entire file. Rolling capture window:

```
Attacker uploads 50GB:

Ring buffer (last 10MB always kept):
[chunk_n-100]...[chunk_n-1][chunk_n]
                                  ↑ newest

Older chunks → streamed to LAB immediately if capture active
             → metadata only retained (offset, sha256)

Attacker sees: transfer progress + fake success
Real service:  never receives anything
```

Rationale: malware payloads fit in the first 10MB. 50GB uploads are noise or DoS attempts — ring buffer captures the payload, discards the padding.

### Concurrent Session Cap

```
MAX_HOSTILE_SESSIONS = 50  (configurable)

If cap reached:
  new connection → fast honeypot mode
                   fake-accept → log IP → auto-nuke after 30s
                   no resource allocation
```

### Session TTL — The Backstop

Every hostile session auto-nukes at TTL regardless of activity:

```
T+0:    Session created, envelope allocated
T+TTL:  AUTO-NUKE
        Attacker sees: connection timeout (normal)
        Operator gets: summary notification + full diff
```

Worst-case storage = MAX_HOSTILE_SESSIONS × max_disk_mb × concurrency window. Fully predictable and bounded.


---

## 13. UNIVERSAL SESSION LAYER

Every connection — regardless of protocol — gets a **session layer**: an isolated write buffer. Real service never touched until operator COMMIT.

```
SESSION LAYER MODEL:

Real Service (untouched)
        ↑
        │ only on COMMIT
  ──────┘
  SESSION LAYER (per connection, in-memory)
  ┌─────────────────────────────────────┐
  │ id: abc123  ip: 45.63.x.x          │
  │ score: 87 (hostile)                 │
  │ writes: {'/tmp/x': b'...', ...}     │
  │ reads: ['/root/secrets.txt', ...]   │
  │ captures: ['miner.sh (sha256)']     │
  │ resource: 12MB / 50MB  3min / 30min │
  └─────────────────────────────────────┘
```

### Operator Decision Tree

```
Session active — operator sees live diff
      │
      ├─ [NUKE]    Drop layer. Zero trace. Real FS untouched.
      │            Attacker sees: connection reset or timeout.
      │
      ├─ [COMMIT]  Merge writes to real service.
      │            Legit user confirmed.
      │
      └─ [LAB]     Package session layer → ship to detonation lab.
                   Wipe proxy session layer.
                   Attacker options:
                     SILENT: stays connected, fresh clean state
                             (attacker may re-drop tools = second capture)
                     DROP:   connection terminated
                   Lab victim container pre-seeded with attacker's
                   full environment (files written, dirs created, etc.)
```

### Per-Protocol Implementation

| Service | Write interception | Session layer | Revert |
|---------|-------------------|---------------|--------|
| SSH | asyncssh virtual FS | memory dict {path: content} | del dict |
| FTP | proxy intercept | ring buffer (last 10MB) + metadata | delete buffer |
| HTTP | middleware intercept | request log | discard |
| PostgreSQL | SQL proxy | SAVEPOINT sting_{id} | ROLLBACK TO SAVEPOINT |
| MySQL | same | same | same |
| SMTP | queue intercept | undelivered queue | dequeue |
| Redis | command intercept | command replay log | replay DEL |
| Generic TCP | stream buffer | ring buffer | drop buffer |

### DB Isolation (Savepoint Model)

```sql
BEGIN;
SAVEPOINT sting_abc123;
-- All attacker writes inside savepoint
-- Attacker sees: success (rows affected)
-- NUKE:   ROLLBACK TO SAVEPOINT sting_abc123
-- COMMIT: RELEASE SAVEPOINT sting_abc123; COMMIT
```
DDL edge case: hostile sessions routed to isolated schema `sting_{session_id}`. NUKE = `DROP SCHEMA CASCADE`.

---

## 14. SESSION RESOURCE ENVELOPES

Every hostile session has a fixed resource budget. Exhaustion = auto-nuke + score spike.

### Score-Based Tiers

| Score | Tier | Disk | TTL |
|-------|------|------|-----|
| 80–100 | High hostile | 10MB | 5min |
| 50–79 | Medium | 25MB | 15min |
| 20–49 | Pending | 50MB | 30min |
| 0–19 | Near-cleared | unlimited | unlimited |

### Defaults (configurable)

```yaml
session_limits:
  disk_mb: 50
  memory_mb: 10
  max_files: 100
  max_db_rows: 10000
  max_duration: 1800
on_breach:
  action: auto_nuke       # auto_nuke | alert_only | throttle
  score_spike: 40
  notify: true
```

### FTP / Large Upload — Ring Buffer

Never buffer entire file. Rolling 10MB window:
- Older chunks → streamed to LAB capture + metadata only retained
- Attacker sees: progress + fake success
- Real service: receives nothing

### Concurrent Session Cap

```
MAX_HOSTILE_SESSIONS = 50
If cap reached → new connection = fast honeypot mode
  (fake-accept → log IP → auto-nuke after 30s, zero resource allocation)
```

---

## 15. DETAILED IMPLEMENTATION ROADMAP

### Phase 1 — Foundation (Week 1)

| Task | Details | Deliverable |
|------|---------|-------------|
| P1-01 | Project scaffold: dirs, requirements.txt, docker-compose.yml | Repo structure |
| P1-02 | PostgreSQL schema: sessions, events, canaries, samples, lab_jobs tables | DB migrations |
| P1-03 | FastAPI app skeleton: main.py, health endpoint, CORS, middleware | GET /health → 200 |
| P1-04 | JWT auth: single-user, token endpoint, auth dependency | POST /auth/token |
| P1-05 | Session model: session_layer.py — write/read/nuke/commit/diff | Unit tests pass |
| P1-06 | Verdict engine: score state machine, event handlers, all score rules | Unit tests pass |
| P1-07 | WebSocket event bus: channels, subscribe/publish, session routing | WS connects |
| P1-08 | React scaffold: Vite + TS, router, sidebar, pages stub | npm run dev works |
| P1-09 | Live feed component: WebSocket → event list, color-coded by type | Renders events |
| P1-10 | Docker-compose: backend + frontend + postgres + redis | docker-compose up |

### Phase 2 — SSH Proxy + Verdict (Week 2)

| Task | Details | Deliverable |
|------|---------|-------------|
| P2-01 | asyncssh SSH proxy: binds :22, accepts connections, creates session layer | Accepts SSH |
| P2-02 | Verdict engine wired to SSH proxy: score events on auth/commands | Score updates |
| P2-03 | Virtual FS: canary files, fake /etc/shadow, realistic fake tree | cat /root/secrets.txt → canary |
| P2-04 | Fake shell: basic commands (ls/cd/cat/pwd/id/whoami/uname) | Shell responds |
| P2-05 | Passthrough: score < 30 → proxy to real sshd (:22022) | Transparent pass |
| P2-06 | Session diff API: GET /api/v1/sessions/{id}/diff | Returns write diff |
| P2-07 | Sessions UI page: active sessions, score, activity, diff view | Visible in UI |
| P2-08 | Operator actions: POST /api/v1/sessions/{id}/nuke|commit|lab | NUKE drops layer |

### Phase 3 — Canary System (Week 3)

| Task | Details | Deliverable |
|------|---------|-------------|
| P3-01 | Canary management API: CRUD /api/v1/canary | Create/list/delete canaries |
| P3-02 | File canary hit detection: access to canary path → event + score spike | Hit logged |
| P3-03 | Credential canary: fake creds in virtual /etc/shadow → login triggers alert | Cred canary fires |
| P3-04 | URL canary beacon server: GET /beacon/{id} → logs external attacker | Beacon hits |
| P3-05 | DNS canary: unique subdomain → STING DNS sink logs query | DNS hit logged |
| P3-06 | Token canary: fake AWS/API keys → external beacon on use | Token canary |
| P3-07 | Canary dashboard UI: list all canaries, hit count, timeline | Canary page live |

### Phase 4a — Lab Foundation (Week 4)

| Task | Details | Deliverable |
|------|---------|-------------|
| P4-01 | Isolated Docker network: 172.31.0.0/24, no external routing | Network created |
| P4-02 | Victim container base image: Dockerfile.victim (minimal Debian) | Image builds |
| P4-03 | Monitoring sidecar: strace + tshark + inotifywait + pspy + ss poll | Sidecar captures |
| P4-04 | Fake DNS sink: logs all queries, returns NXDOMAIN or fake IPs | DNS logged |
| P4-05 | Fake HTTP sink: logs all requests, returns 200 OK | HTTP logged |
| P4-06 | Detonation API: POST /api/v1/lab/detonate/{hash} → spawn containers | Job created |
| P4-07 | Lab job status: GET /api/v1/lab/jobs, GET /api/v1/lab/jobs/{id} | Status returns |
| P4-08 | Session→Lab transfer: LAB action packages session layer → pre-seeds victim | Pre-seed works |

### Phase 4b — Real-Time Lab UI (Week 5)

| Task | Details | Deliverable |
|------|---------|-------------|
| P4b-01 | 4-channel WebSocket: syscalls / network / filesystem / processes | 4 streams live |
| P4b-02 | Syscall stream parser: strace output → structured JSON events | Parsed syscalls |
| P4b-03 | Network stream parser: tshark output → structured JSON events | Parsed network |
| P4b-04 | Filesystem stream: inotifywait → structured JSON events | FS diffs live |
| P4b-05 | Process stream: pspy + ss → process spawn/kill events | Proc tree live |
| P4b-06 | Lab viewer UI: 4-panel live view (syscalls/net/fs/proc) | Live panels |
| P4b-07 | Process tree component: parent/child relationships, colored by risk | Tree renders |
| P4b-08 | Timeline component: horizontal timeline, phase markers | Timeline live |
| P4b-09 | Pause/freeze: SIGSTOP via API, UI pause button | Freeze works |
| P4b-10 | Memory inspect: GET /proc/{pid}/mem → strings + entropy in UI | Mem inspect |

### Phase 5 — Intelligence Layer (Week 6)

| Task | Details | Deliverable |
|------|---------|-------------|
| P5-01 | YARA rule generator: extract strings + patterns → yara-python rule | YARA generated |
| P5-02 | MITRE ATT&CK mapper: syscall patterns → technique IDs | ATT&CK tags |
| P5-03 | IOC extractor: IPs/domains/hashes/paths from all streams | IOC list |
| P5-04 | Pattern clustering: group similar behaviors across samples | Cluster view |
| P5-05 | IOC feed export: GET /api/v1/export/ioc → JSON / STIX | Export works |
| P5-06 | PDF report: full analysis → generate PDF with all findings | PDF downloads |
| P5-07 | Sample vault UI: browse samples, filter by type/date/score | Vault page |
| P5-08 | Lab results UI: YARA + MITRE + IOC + timeline in one view | Results page |

### Phase 6 — HTTP Proxy + Additional Protocols (Week 6-7)

| Task | Details | Deliverable |
|------|---------|-------------|
| P6-01 | nginx + lua verdict middleware: calls STING verdict API per request | HTTP proxied |
| P6-02 | HTTP session layer: intercept POST/PUT, fake 200, log body | HTTP writes buffered |
| P6-03 | FTP proxy: intercept uploads, ring buffer, fake success | FTP buffered |
| P6-04 | Resource envelope enforcement: disk/memory/TTL per session | Limits enforced |
| P6-05 | Auto-nuke on breach: TTL expiry + limit hit → automatic NUKE | Auto-nuke fires |
| P6-06 | Concurrent session cap: MAX=50, fast mode beyond cap | Cap enforced |

### Phase 7 — Production Test (Week 7)

| Task | Details | Deliverable |
|------|---------|-------------|
| P7-01 | Deploy on CT102 (dev mode, all services) | Live on CT102 |
| P7-02 | Generate 8 test malware samples via Venice | Samples ready |
| P7-03 | Full pipeline test: trap → capture → lab → stream → intelligence | End-to-end pass |
| P7-04 | Load test: 50 concurrent hostile sessions | No OOM, no crash |
| P7-05 | Detection test: all 8 samples detected + MITRE mapped | 8/8 pass |
| P7-06 | YARA test: generated rules catch samples on rescan | Rules valid |
| P7-07 | Production harden: rate limiting, input validation, auth | Hardened |
| P7-08 | CT100 integration: wire to live Cowrie feed + SSH port 22 | Prod live |

---

## 16. VENICE TEST MALWARE PLAN

8 samples generated via Venice API, tested against full STING pipeline:

| # | Sample | Behavior | Test Objective |
|---|--------|----------|---------------|
| 1 | dropper.sh | wget + chmod + exec | Capture + detonation chain |
| 2 | ssh_persist.sh | inject /root/.ssh/authorized_keys | Persistence detection (T1098) |
| 3 | miner.sh | XMRig-style, pool connect | Network stream + T1496 |
| 4 | scanner.sh | internal network sweep | Network pattern + T1046 |
| 5 | exfil.sh | curl POST to fake C2 | Network IOC extraction |
| 6 | rootkit_lite.sh | /proc name manipulation | Syscall detection T1014 |
| 7 | reverse_shell.sh | bash TCP reverse shell | Network + process T1059 |
| 8 | polymorphic.sh | base64 decode + exec | Entropy detection |

Pass criteria: STING catches → captures → streams live → MITRE maps → YARA generates.

