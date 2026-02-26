---
session:
  id: "{YYYY-MM-DD}_{task_name}"
  date: "{YYYY-MM-DD}"
  complexity: medium  # simple | medium | complex
  domain: fullstack   # frontend_only | backend_only | fullstack | docker_heavy

skills:
  loaded: [{skill1}, {skill2}]
  suggested: []

files:
  modified:
    - {path: "path/to/file.tsx", type: tsx, domain: frontend}
    - {path: "path/to/file.py", type: py, domain: backend}
  types: {tsx: 1, py: 1}

agents:
  delegated: []  # or [{name: code, task: "desc", result: success}]

commands:
  - {cmd: "docker-compose up -d", domain: docker, success: true}

gates:
  passed: [G1, G2, G3, G4, G5, G6]
  violations: []

root_causes:
  - problem: "Description of problem"
    solution: "How it was fixed"
    skill: debugging

gotchas:
  - pattern: "Pattern that caused issue"
    warning: "What can go wrong"
    solution: "How to avoid/fix"
    applies_to: [skill-name]
---

# Session Log: {TASK_NAME}

**Date:** {YYYY-MM-DD}
**Duration:** ~{N} min
**Complexity:** {simple|medium|complex}

## Summary
{Brief description of what was accomplished - 2-3 sentences max}

## Tasks Completed
- ✓ {Task 1}
- ✓ {Task 2}
- ✓ {Task 3}

## Files Modified
| File | Changes |
|------|---------|
| `path/file.ext` | Brief description |

## Script Results
| Script | Output |
|--------|--------|
| knowledge.py | X entities merged |
| skills.py | X suggestions |
| docs.py | X suggestions |
| agents.py | X suggestions |
| instructions.py | X suggestions |

## Verification
- ✓ Syntax check passed
- ✓ Build successful
- ✓ Tests passed
