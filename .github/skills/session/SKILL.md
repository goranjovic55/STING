---
name: session
description: Load for session lifecycle management, TODO tracking, phase transitions (START/WORK/END), and session cleanup. Maintains session structure and gate compliance.
---

# Session Management

## Merged Skills
- **workflow**: Phase transitions, gate compliance
- **todo-management**: TODO tracking, structured naming

## ⚠️ Critical Gotchas

| Category | Pattern | Solution |
|----------|---------|----------|
| Orphan TODO | ◆ left at END | Mark ✓ or ⊘ before END phase |
| Skip START | Editing before START | Complete START phase first |
| Multi-active | Multiple ◆ active | Only ONE ◆ at a time (G6) |
| No cleanup | Session ends dirty | Run session_cleanup.py in END |
| No log | END without workflow log | Create log before commit |

## Rules

| Rule | Pattern |
|------|---------|
| START first | Complete START before any edits |
| One TODO active | Only one ◆ at a time (G6) |
| Close all TODOs | All ◆ marked ✓ or ⊘ before END |
| Create log | Workflow log required for >15 min sessions |
| Run AKIS updates | Run knowledge/skills/agents/instructions scripts at END |
| Run cleanup | session_cleanup.py in END phase |

## Avoid

| ❌ Bad | ✅ Good |
|--------|---------|
| Skip START phase | Complete full START |
| Multiple ◆ active | One ◆ only |
| Leave ◆ at END | Mark all ✓ or ⊘ |
| No workflow log | Create log/workflow/ entry |
| Skip AKIS updates | Run all 4 update scripts |
| Manual cleanup | Run session_cleanup.py |

## Phase Flow

```
START → WORK → END → VERIFY
```

| Phase | Actions | Gates |
|-------|---------|-------|
| START | Load knowledge, announce skills, create TODOs | G0, G1, G3 |
| WORK | ◆ → Skill → Edit → Verify → ✓ | G2, G5, G6 |
| END | Close TODOs, create log, run AKIS updates, cleanup | G4 |
| VERIFY | All gates passed, all tasks ✓ | All |

## ⛔ END Phase: AKIS Framework Updates

At END phase, run these scripts to keep AKIS framework current:

```bash
# 1. Update knowledge graph
python .github/scripts/knowledge.py --update

# 2. Update skills index
python .github/scripts/skills.py --update

# 3. Update agents
python .github/scripts/agents.py --update

# 4. Update instructions
python .github/scripts/instructions.py --update
```

**Results Table (present to user):**
| Script | Output | Changes | Rollback |
|--------|--------|---------|----------|
| knowledge.py | X entities | project_knowledge.json | `.backups/` |
| skills.py | X skills | INDEX.md | `.backups/` |
| agents.py | X agents | agents/*.md | `.backups/` |
| instructions.py | X instr | instructions/*.md | `.backups/` |

## TODO Format

```
○ [agent:phase:skill] Task description [context]
```

| Symbol | Meaning |
|--------|---------|
| ○ | Pending |
| ◆ | Working (only ONE) |
| ✓ | Done |
| ⊘ | Paused/blocked |
| ⧖ | Delegated |

## Patterns

```python
# Pattern 1: Increment session counter
python .github/skills/session/scripts/session_tracker.py increment

# Pattern 2: Check if maintenance due
python .github/skills/session/scripts/session_tracker.py check-maintenance

# Pattern 3: Session cleanup at END
python .github/skills/session/scripts/session_cleanup.py

# Pattern 4: Get current session number
python .github/skills/session/scripts/session_tracker.py current
```

## Workflow Log Template

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

## Commands

| Task | Command |
|------|---------|
| Increment session | `python .github/skills/session/scripts/session_tracker.py increment` |
| Current session | `python .github/skills/session/scripts/session_tracker.py current` |
| Check maintenance | `python .github/skills/session/scripts/session_tracker.py check-maintenance` |
| Cleanup | `python .github/skills/session/scripts/session_cleanup.py` |
| Update knowledge | `python .github/scripts/knowledge.py --update` |
| Update skills | `python .github/scripts/skills.py --update` |
| Update agents | `python .github/scripts/agents.py --update` |
| Update instructions | `python .github/scripts/instructions.py --update` |

## Gate Compliance

| Gate | Session Responsibility |
|------|------------------------|
| G1 | manage_todo_list, mark ◆ before edit |
| G3 | Complete START phase with announcement |
| G4 | Complete END phase with workflow log |
| G6 | Only ONE ◆ active at a time |
