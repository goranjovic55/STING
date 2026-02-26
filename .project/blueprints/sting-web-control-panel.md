# STING Web Control Panel - Blueprint

**Status:** Proposed  
**Priority:** Medium  
**Complexity:** High  
**Dependencies:** STING core, Cowrie, Network overlay system

---

## Vision

Complete web-based honeypot orchestration and monitoring platform that transparently overlays onto existing infrastructure.

**Core Concept:**
- Design honeypots via web UI
- Deploy as transparent overlay (same ports as real services)
- Attacker sees "real" server but hits canary credentials
- Live monitoring of malware execution and commands
- Trend analysis and activity tracking

---

## Components

### 1. Web Control Panel

**Features:**
- Dashboard with real-time attack graphs
- Honeypot designer (visual trap configuration)
- Credential canary management
- Attack trend visualization
- Live command execution monitoring
- Malware tracking (campaigns, IOCs, behaviors)

**Tech Stack (Proposed):**
- Frontend: React/Vue (lightweight, responsive)
- Backend: FastAPI (Python, async)
- Real-time: WebSockets for live updates
- Visualization: D3.js or Chart.js

### 2. Honeypot Connector

**Supported Honeypots:**
- Cowrie (SSH/Telnet) - primary
- Additional: Dionaea, Conpot, etc. (future)

**Integration:**
- Connect to existing Cowrie instances
- Pull logs in real-time
- Control honeypot configuration remotely
- Deploy new honeypots dynamically

### 3. Transparent Overlay System

**Architecture:**
```
Real Service (port X)
    ↓
Overlay Router (iptables/nftables)
    ↓
Decision Logic:
    ├─ Valid credentials → Real service
    └─ Invalid/canary credentials → Honeypot
```

**Features:**
- Same port as real service (no detection)
- Transparent redirection based on credentials
- No visible difference to attacker
- Preserves real service functionality

**Implementation:**
- Network-level routing (iptables DNAT/REDIRECT)
- Credential detection layer
- Seamless failover to honeypot

### 4. Canary Credential System

**Types:**
- SSH keys (deployed but monitored)
- Username/password pairs (obvious but wrong)
- API tokens (look valid, trigger alerts)

**Management:**
- Generate canaries via UI
- Deploy across infrastructure
- Alert on usage
- Track which canary triggered which attack

### 5. Live Monitoring & Analytics

**Real-time:**
- Commands executed by attackers
- Malware downloads (hash, source, behavior)
- Network connections from compromised honeypot
- Attack progression (recon → exploit → persistence)

**Historical:**
- Attack trends over time
- Attacker infrastructure mapping
- Campaign tracking (same IOCs across targets)
- Success rate by attack type

**Visualization:**
- Geographic attack origin maps
- Timeline of attack phases
- Network graph of attacker infrastructure
- Malware family trees

---

## Use Cases

### 1. Infrastructure Protection
- Overlay onto production servers
- Detect attacks without blocking legitimate users
- Early warning system

### 2. Threat Intelligence
- Track real-world attack campaigns
- Collect malware samples
- Understand attacker TTPs
- Share IOCs with community

### 3. Security Research
- Study attack evolution
- Test defenses safely
- Analyze malware behavior in controlled environment

### 4. Incident Response
- Replay attacks for analysis
- Understand breach timeline
- Collect evidence

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                 Web Control Panel                    │
│  (Dashboard, Honeypot Designer, Analytics)          │
└─────────────────┬───────────────────────────────────┘
                  │
        ┌─────────┴─────────┐
        │   STING Backend   │
        │   (FastAPI/WS)    │
        └─────────┬─────────┘
                  │
     ┌────────────┼────────────┐
     │            │            │
┌────▼────┐  ┌───▼────┐  ┌───▼─────┐
│ Cowrie  │  │Overlay │  │ Canary  │
│Connector│  │ Router │  │ Manager │
└────┬────┘  └───┬────┘  └───┬─────┘
     │           │            │
     └───────────┼────────────┘
                 │
        ┌────────▼────────┐
        │  Infrastructure │
        │  (Real servers  │
        │  + Honeypots)   │
        └─────────────────┘
```

---

## Technical Challenges

### 1. Transparent Routing
- Maintain low latency
- Handle encrypted protocols (TLS/SSH)
- No detectable fingerprints

### 2. Credential Detection
- Pre-auth detection (before honeypot hit)
- Handle protocol-specific auth (SSH keys, LDAP, etc.)
- Fast decision (<100ms)

### 3. Malware Analysis
- Sandbox integration for safe execution
- Behavioral analysis without triggering anti-sandbox
- Network traffic capture

### 4. Scalability
- Handle 1000+ honeypots
- Real-time updates for 100+ concurrent attacks
- Historical data storage (TB scale)

---

## Implementation Phases

### Phase 1: Core Platform
- [ ] Web UI skeleton (dashboard, honeypot list)
- [ ] Cowrie connector (read logs, parse events)
- [ ] Basic visualization (attack timeline, top IPs)
- [ ] Database schema (attacks, honeypots, IOCs)

### Phase 2: Overlay System
- [ ] Network routing logic (iptables rules)
- [ ] Credential detection layer
- [ ] Transparent redirection
- [ ] Testing with SSH/Telnet

### Phase 3: Canary Management
- [ ] Canary generation (SSH keys, passwords)
- [ ] Deployment automation
- [ ] Alert system (canary triggered)
- [ ] Tracking/attribution

### Phase 4: Advanced Analytics
- [ ] Campaign tracking (IOC correlation)
- [ ] Malware family classification
- [ ] Attacker infrastructure mapping
- [ ] Trend prediction

### Phase 5: Multi-Honeypot Support
- [ ] Dionaea connector (malware capture)
- [ ] Conpot connector (ICS/SCADA)
- [ ] Custom honeypot API
- [ ] Unified event format

---

## Security Considerations

**Control Panel:**
- Strong authentication (2FA)
- Role-based access control
- Audit logging
- Rate limiting

**Honeypot Isolation:**
- Network segmentation
- No access to production data
- Sandboxed malware execution
- Kill switch for compromised honeypots

**Data Protection:**
- Encrypted storage (attack logs, IOCs)
- Anonymize sensitive data
- Retention policies
- GDPR compliance (if tracking EU attackers)

---

## Success Metrics

- **Detection Rate:** % of attacks caught by overlay
- **False Positives:** Valid users redirected to honeypot (<0.1%)
- **Latency:** Routing decision time (<100ms)
- **Coverage:** % of infrastructure protected
- **Intelligence Value:** Unique IOCs discovered per week

---

## Future Enhancements

- **AI-based attack prediction:** Learn attacker patterns, predict next move
- **Automated response:** Block attacker infrastructure automatically
- **Threat intel sharing:** Contribute to community feeds (AbuseIPDB, etc.)
- **Deception technology:** Fake files, services, vulnerabilities
- **Attacker profiling:** Skill level, goals, tools, origin

---

## References

- Cowrie: https://github.com/cowrie/cowrie
- Honeypot architectures: SANS whitepapers
- Transparent proxying: iptables TPROXY
- Deception tech: Thinkst Canary (commercial reference)

---

**Created:** 2026-02-26  
**Author:** Falke AI  
**Status:** Awaiting approval for Phase 1 implementation
