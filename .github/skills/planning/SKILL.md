---
name: planning
description: Load for new features, design tasks, and architecture decisions. Provides structured workflow for UNDERSTAND → RESEARCH → DESIGN → HANDOFF phases.
---

# Planning

## Merged Skills
- **requirements**: Clarifying scope, boundaries, acceptance criteria
- **architecture**: High-level design decisions, component structure

## ⚠️ Critical Gotchas

| Category | Pattern | Solution |
|----------|---------|----------|
| Premature code | Implementing without design | Create blueprint FIRST in `.project/` |
| External first | Searching web before local | Check docs/ + codebase BEFORE external |
| Scope creep | Expanding beyond boundaries | Define scope in blueprint, stick to it |
| Complexity | Underestimating 6+ file changes | Complex tasks MUST use planning phase |
| Handoff | No clear transition to BUILD | End planning with task list + skill annotations |

## Rules

| Rule | Pattern |
|------|---------|
| Blueprint first | Create `.project/{feature}.md` before any code |
| Local research | grep docs/ + codebase before external search |
| Scope boundaries | Define what's IN and OUT in blueprint |
| Task decomposition | Break into <3 file tasks where possible |
| Skill annotation | Tag tasks with `[skill-name]` for BUILD phase |

## Avoid

| ❌ Bad | ✅ Good |
|--------|---------|
| Start coding immediately | Create blueprint first |
| Research externally first | Check local docs/ first |
| Undefined scope | Explicit IN/OUT boundaries |
| Monolithic tasks | Decomposed to <3 files each |
| Untracked design changes | Update blueprint as design evolves |

## Patterns

```markdown
# Blueprint: {Feature Name}

## Scope
- **Goal:** One sentence describing outcome
- **IN:** What this feature includes
- **OUT:** What this feature excludes
- **Files:** Estimated file count and locations

## Design
- **Approach:** High-level solution strategy
- **Components:** Key parts and their responsibilities
- **Dependencies:** External services, libraries, other features

## Tasks
1. [ ] Task description [backend-api]
2. [ ] Task description [frontend-react]
3. [ ] Task description [testing]

## Research Notes
- {Finding 1}
- {Finding 2}
```

## Workflow

| Phase | Action | Output |
|-------|--------|--------|
| UNDERSTAND | Clarify requirements, ask questions | Clear scope statement |
| RESEARCH | Local first, then external | Research notes in blueprint |
| DESIGN | Create blueprint with approach | `.project/{feature}.md` |
| HANDOFF | Transition to BUILD phase | Task list with skills |

## Commands

| Task | Command |
|------|---------|
| Create blueprint | `touch .project/{feature}.md` |
| Find existing patterns | `grep -r "pattern" docs/ backend/ frontend/` |
| Check similar features | `ls .project/` |
