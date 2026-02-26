# NOP Integration Guide

## Overview
Integration between Honeypot Intelligence Pipeline and Network Observatory Platform (NOP).

## Architecture
```
Cowrie Honeypot (CT100:2222) → cowrie.json → Honeypot-Intel → [Telegram + NOP API]
```

## Integration Points

### 1. Asset Management
Register attackers in NOP as threat assets.

### 2. Alert System  
Create NOP alerts for critical attacks.

### 3. Workflow Automation
Trigger NOP workflows (block IP, scan network, capture traffic).

### 4. Traffic Correlation
Enrich honeypot data with NOP network context.

### 5. Agent Coordination
Deploy NOP agents to investigate attackers.

## Configuration
```json
{
  "nop": {
    "enabled": true,
    "api_url": "http://radxa-e54c:12001",
    "username": "admin",
    "password": "admin123"
  }
}
```

## Implementation
See `src/integrations/nop.py` for full code.

## Development
- VSCode: Open `/root/dev/honeypot-intel` as workspace
- Claude Code: Already configured in CT102 tmux session
- Tests: Run `pytest tests/`
