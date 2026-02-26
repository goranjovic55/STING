---
applyTo: '**'
description: 'Protocol details: skill loading enforcement, pre-commit gate, simulation stats.'
---

# Protocol Details

> Core protocols in copilot-instructions.md. This file: G2 enforcement + detailed triggers + stats.

## G2: Skill Loading Enforcement

**Violation Rate:** 30.8% (HIGH priority fix)  
**Cost per Violation:** +5,200 tokens  
**Total Cost:** 160M tokens across 100k sessions

**MANDATORY Pattern:**
```
1. Identify file type
2. Load skill FIRST (skill tool)
3. Announce skill loaded
4. Then make edits
```

**Visual Warning:**
```
⚠️ EDITING .tsx WITHOUT frontend-react SKILL
This will cost +5,200 tokens in wasted context.
Load skill now with: skill("frontend-react")
```

## Skill Triggers (Detailed)

| Trigger | Skill | Type |
|---------|-------|------|
| .tsx .jsx components/ | frontend-react | edit |
| .py backend/ api/ services/ | backend-api | edit |
| Dockerfile docker-compose*.yml | docker | edit |
| docker compose build up | docker | command |
| .github/workflows/*.yml | ci-cd | edit |
| .md docs/ README | documentation | edit |
| error traceback exception | debugging | analysis |
| test_* *.test.* pytest jest | testing | edit/command |
| .github/skills/* agents/* | akis-dev | edit |
| design blueprint architecture | planning | analysis |
| research compare standards | research | analysis |

## Pre-Commit Gate (G5 + G4)

Before `git commit`:
1. ✓ Syntax check (no errors) - G5
2. ✓ Build passes (if applicable)
3. ✓ Tests pass (if test files edited)
4. ✓ Workflow log created (sessions >15 min) - G4

**Block commit if any fails.**

**Compliance Rates (from 100k simulation):**
- G5 verification: 82.0% → Target: 95%+
- G4 workflow log: 78.2% → Target: 95%+

## Simulation Stats (100k Sessions - Jan 2026)

### Baseline Performance
| Metric | Value | Efficiency Score |
|--------|-------|------------------|
| Success Rate | 86.6% | 0.89 |
| Token Usage | 20,172/session | 0.40 |
| API Calls | 37.4/session | - |
| Resolution Time (P50) | 52.4 min | 0.26 |
| Cognitive Load | 79.1% | 0.33 |
| Discipline (Gates) | 80.8% | 0.87 |
| Traceability | 83.4% | 0.89 |
| **Overall Efficiency** | - | **0.61** |

### Optimization Targets
| Metric | Baseline | Target | Optimized |
|--------|----------|--------|-----------|
| Token Usage | 20,172 | -20% | 16,138 |
| API Calls | 37.4 | -15% | 31.8 |
| Speed (P50) | 52.4 min | -10% | 47.2 min |
| Parallel Rate | 19.1% | 60% | 60%+ |
| Overall Efficiency | 0.61 | +16% | 0.71 |

### Gate Compliance (Identify Focus Areas)
| Gate | Compliance | Violation Rate | Priority |
|------|-----------|----------------|----------|
| G2 - Skill Loading | 69.2% | 30.8% | 🔴 HIGH |
| G4 - Workflow Log | 78.2% | 21.8% | 🔴 HIGH |
| G5 - Verification | 82.0% | 18.0% | 🟡 MEDIUM |
| G7 - Parallel | 89.6% | 10.4% | 🟡 MEDIUM |
| G1 - TODO | 90.3% | 9.7% | ✅ LOW |
| G3 - START | 92.1% | 7.9% | ✅ LOW |
| G6 - Single | 100.0% | 0.0% | ✅ PERFECT |

### Knowledge Graph Impact (G0)
| Metric | Without G0 | With G0 | Change |
|--------|------------|---------|--------|
| File reads | 100% | 23.2% | -76.8% |
| Token consumption | 100% | 32.8% | -67.2% |
| Cache hit rate | 0% | 71.3% | +71.3% |

### Delegation Impact
| Strategy | Efficiency | Success | Quality |
|----------|-----------|---------|---------|
| medium_and_complex (3+ files) | 0.789 | 93.9% | 93.9% |
| no_delegation | 0.594 | 72.4% | 72.4% |
| **Improvement** | **+32.8%** | **+21.5%** | **+21.5%** |

## Documentation Index

| Need | Location |
|------|----------|
| How-to | `docs/guides/` |
| Feature | `docs/features/` |
| API ref | `docs/technical/` |
| Architecture | `docs/architecture/` |
| Analysis | `docs/analysis/` |
