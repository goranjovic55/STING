# Honeypot Intelligence Pipeline

Production-ready honeypot log analysis and alerting system for Cowrie SSH/Telnet honeypot.

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Parser    │───▶│  Analyzer   │───▶│   Storage   │───▶│   Alerter   │
│  (parser.py)│    │ (analyzer.py)│    │ (storage.py)│    │ (alerter.py)│
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                                                   │
       │              ┌─────────────┐                       │
       └─────────────▶│  SQLite DB  │◀──────────────────────┘
                      │  + JSONL    │
                      └─────────────┘
```

## Components

### 1. Parser (`parser.py`)
- Reads NDJSON logs from Cowrie honeypot
- Validates JSON structure
- Extracts key fields: eventid, timestamp, src_ip, session, commands, etc.
- Supports local files, SSH remote access, and tail -f mode

### 2. Analyzer (`analyzer.py`)
Detects attack patterns:
- **BRUTE_FORCE**: ≥5 failed logins from same IP in 60s
- **SUCCESS_LOGIN**: Any successful authentication (CRITICAL)
- **MALWARE_DOWNLOAD**: wget/curl downloading files
- **COMMAND_SEQUENCE**: Track attacker commands per session
- **PERSISTENCE**: SSH key injection, cron modifications
- **RECON**: System enumeration commands

Severity levels: LOW, MEDIUM, HIGH, CRITICAL

### 3. Storage (`storage.py`)
- SQLite database at `data/honeypot.db`
- Tables: events, sessions, attackers, alerts, daily_summaries
- JSONL archive for raw events
- Full-text search capabilities

### 4. Alerter (`alerter.py`)
- Telegram-compatible markdown output
- Immediate alerts for CRITICAL/HIGH events
- Batch/digest alerts for MEDIUM/LOW severity
- Daily summary reports

### 5. Main Pipeline (`main.py`)
- Orchestrates parse → analyze → store → alert
- Batch mode: Process historical logs
- Realtime mode: Tail logs continuously
- Configurable via environment variables and config file

## Installation

```bash
# Clone or copy files to /root/honeypot-intel/
cd /root/honeypot-intel

# Install dependencies
pip3 install requests

# Configure environment
cp config/.env.example .env
# Edit .env with your Telegram credentials

# Initialize database (auto-created on first run)
python3 src/main.py --mode batch --since 24
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TELEGRAM_BOT_TOKEN` | Telegram bot token | (required) |
| `TELEGRAM_CHAT_ID` | Telegram chat/channel ID | (required) |
| `HONEYPOT_DB_PATH` | SQLite database path | `/root/honeypot-intel/data/honeypot.db` |
| `HONEYPOT_LOG_PATH` | Pipeline log file | `/root/honeypot-intel/logs/pipeline.log` |
| `HONEYPOT_SSH_HOST` | SSH host for remote logs | `CT100` |
| `HONEYPOT_MODE` | Processing mode | `batch` |

### Config File (`config/pipeline.conf`)

JSON configuration for detection thresholds, paths, and feature flags.

## Usage

### Batch Processing (Last 24 Hours)
```bash
python3 src/main.py --mode batch --since 24
```

### Real-time Mode (Tail -f)
```bash
python3 src/main.py --mode realtime
```

### Daily Report Only
```bash
python3 src/main.py --daily-report
```

### Cron Job (Daily at 06:00 UTC)
```bash
# Add to crontab:
0 6 * * * /root/honeypot-intel/scripts/cron.sh
```

## Directory Structure

```
/root/honeypot-intel/
├── src/
│   ├── parser.py       # Log parsing
│   ├── analyzer.py     # Pattern detection
│   ├── storage.py      # Database management
│   ├── alerter.py      # Alert formatting
│   └── main.py         # Pipeline orchestration
├── config/
│   └── pipeline.conf   # Configuration file
├── scripts/
│   └── cron.sh         # Daily cron job
├── data/
│   └── honeypot.db     # SQLite database
├── logs/
│   └── pipeline.log    # Application logs
└── archive/
    └── events_*.jsonl  # Archived raw events
```

## Database Schema

### Events Table
Raw honeypot events with full JSON payload.

### Sessions Table
Aggregated session statistics per attack session.

### Attackers Table
IP-based tracking with reputation scoring.

### Alerts Table
Security alerts with severity and notification status.

### Daily Summaries Table
Aggregated daily statistics for reporting.

## Alert Types

| Alert Type | Severity | Description |
|------------|----------|-------------|
| BRUTE_FORCE | HIGH | Multiple failed login attempts |
| SUCCESS_LOGIN | CRITICAL | Successful authentication |
| MALWARE_DOWNLOAD | HIGH | Suspicious file downloads |
| COMMAND_SEQUENCE | MEDIUM | Extended command execution |
| PERSISTENCE_ATTEMPT | CRITICAL | Backdoor/persistence mechanisms |
| RECONNAISSANCE | MEDIUM | System enumeration |
| SUSPICIOUS_PATTERN | HIGH | Dangerous command patterns |

## Telegram Output Format

### Immediate Alert (CRITICAL/HIGH)
```
🚨 CRITICAL | 🔓 SUCCESS_LOGIN

📝 Successful login: admin (after 5 failed attempts)

🕐 2024-01-15 14:30:45 UTC
🌐 192.168.1.100
🔌 Session: abc123...

📊 Details:
• Username: `admin`
• Failed before: 5
```

### Digest Format
```
📊 Honeypot Alert Digest
🕐 Last 6h | 12 total alerts

🚨 CRITICAL: 2 | ⚠️ HIGH: 5 | ⚡ MEDIUM: 5

🔥 Important Alerts:
  🔓 192.168.1.100: Successful login: root...

🎯 Top Attackers:
  192.168.1.100: 8 alerts
```

## Testing

```bash
# Test parser
cd src
python3 parser.py

# Test analyzer
python3 analyzer.py

# Test alerter (no actual send)
python3 alerter.py
```

## Troubleshooting

### Database is locked
- Check if another instance is running
- Use `lsof data/honeypot.db` to find locking process

### Telegram not sending
- Verify `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`
- Check bot has permission to post in channel
- Review logs in `logs/pipeline.log`

### SSH connection fails
- Verify SSH key authentication to CT100
- Check `ssh CT100` works manually
- Ensure cowrie log path is correct

## License

MIT License - For internal use only.
