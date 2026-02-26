---
applyTo: '**'
description: 'Workflow details: END phase triggers, log format, verification helpers.'
---

# Workflow Details

> Core workflow in copilot-instructions.md. This file: END details + verification + log format.

## G5: Verification After Edits

**After EVERY edit, verify syntax:**

| File Type | Verification Command |
|-----------|---------------------|
| .py | `python -m py_compile {file}` |
| .ts .tsx | `npx tsc --noEmit {file}` |
| .json | `python -c "import json; json.load(open('{file}'))"` |
| .yml .yaml | `python -c "import yaml; yaml.safe_load(open('{file}'))"` |
| .md | Visual check only |

**Batch verification:**
```bash
# Multiple Python files
python -m py_compile file1.py && python -m py_compile file2.py
```

⚠️ **G5 violation costs +8.5 min rework** per error. Verify immediately after edit.

## END Phase (Detailed)

**Triggers (G4):**
- Session duration >15 minutes
- Keywords: "done", "complete", "finished", "ready to commit", "all tasks complete"

**Step 1:** Close ⊘ orphans, verify all edits (G5)

**Step 2:** Create `log/workflow/YYYY-MM-DD_HHMMSS_task.md` (G4 - MANDATORY for >15 min)

⚠️ **G4 compliance = 78.2%**. Improve to 95%+ by creating workflow log when:
- Session >15 minutes
- Bug fix with root cause identified
- Complex task (6+ files modified)

**Step 3:** Run scripts (all with `--update` - backups created automatically):
```bash
python .github/scripts/knowledge.py --update
python .github/scripts/skills.py --update
python .github/scripts/docs.py --update
python .github/scripts/agents.py --update
python .github/scripts/instructions.py --update
```

**Step 4:** Present results table with changes and rollback:
| Script | Output | Changes | Rollback |
|--------|--------|---------|----------|
| knowledge.py | X entities | project_knowledge.json | `.backups/` |
| skills.py | X skills | INDEX.md | `.backups/` |
| docs.py | X docs | docs/INDEX.md | `.backups/` |
| agents.py | X agents | agents/*.md | `.backups/` |
| instructions.py | X instructions | instructions/*.md | `.backups/` |

**Rollback if needed:** `cp .github/skills/.backups/INDEX_YYYYMMDD_*.md .github/skills/INDEX.md`

**Step 5:** ASK before applying suggestions

**Step 6:** ASK before `git push`

## Workflow Log Format

```yaml
---
session:
  id: "YYYY-MM-DD_task"
  complexity: medium  # simple|medium|complex

skills:
  loaded: [skill1, skill2]

files:
  modified:
    - {path: "file.tsx", domain: frontend}

agents:
  delegated:
    - {name: code, task: "Task", result: success}

root_causes:  # REQUIRED for debugging
  - problem: "Error description"
    solution: "Fix applied"
---

# Session: Task Name

## Summary
Brief description.

## Tasks
- ✓ Task 1
- ✓ Task 2
```

## Fullstack Coordination
1. Pre-load: frontend-react + backend-api
2. Order: API → Types → UI → Test
3. Check: trailing slashes, CORS, state sync
