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
