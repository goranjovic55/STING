# Session Management Patterns

Reusable patterns for session lifecycle management.

## Pattern Files

| Pattern | Description | Usage |
|---------|-------------|-------|
| `start_phase.md.template` | START phase checklist | Beginning of session |
| `end_phase.md.template` | END phase checklist | End of session |
| `todo_format.md.template` | Structured TODO naming | TODO creation |
| `workflow_log.md.template` | Workflow log template | Session documentation |

## Usage

Patterns are referenced in SKILL.md and auto-suggested when relevant triggers are detected.

### START Phase Pattern

```markdown
## START Phase Checklist
1. [ ] Load knowledge (head -100 project_knowledge.json)
2. [ ] Read skills/INDEX.md
3. [ ] Create TODOs with manage_todo_list
4. [ ] Announce: "AKIS v7.4 [complexity]. Skills: [list]. [N] tasks. Ready."
```

### END Phase Pattern

```markdown
## END Phase Checklist
1. [ ] All ◆ marked ✓ or ⊘
2. [ ] Syntax verified on all edits
3. [ ] Create workflow log (if >15 min)
4. [ ] Run update scripts
5. [ ] Run session cleanup
6. [ ] ASK before git push
```

### TODO Format Pattern

```markdown
## Structured TODO Format
○ [agent:phase:skill] Task description [context]

Examples:
○ [AKIS:START:planning] Analyze requirements
○ [code:WORK:backend-api] Implement auth endpoint [parent→abc123]
○ [debugger:WORK:debugging] Fix null pointer [deps→task1]
```

### Workflow Log Pattern

```yaml
---
session:
  id: "YYYY-MM-DD_HHMMSS_task"
  complexity: medium

skills:
  loaded: [backend-api, frontend-react]

files:
  modified:
    - {path: "backend/app/api.py", domain: backend}
---

# Session: Feature Implementation

## Summary
Implemented X feature.

## Tasks
- ✓ Task 1
- ✓ Task 2
```

## Pattern Selection

| Task | Pattern |
|------|---------|
| Starting session | start_phase.md.template |
| Ending session | end_phase.md.template |
| Creating TODO | todo_format.md.template |
| Documenting work | workflow_log.md.template |
