# AKIS v7.4 - Agent Knowledge & Instruction System

AI coding agent framework: **A**gent • **K**nowledge • **I**nstructions • **S**kills

**Portable:** Copy `.github/` to any codebase.

## Structure

| File | Purpose |
|------|--------|
| `copilot-instructions.md` | Terse rules (START→WORK→END) |
| `instructions/protocols.instructions.md` | Gates, skill triggers, delegation |
| `instructions/architecture.instructions.md` | Project structure & file placement |
| `instructions/workflow.instructions.md` | Phases, TODO, END steps |
| `instructions/quality.instructions.md` | Verification, gotchas |
| `skills/INDEX.md` | Domain→skill lookup |
| `skills/*/SKILL.md` | Agent Skills (per-domain) |
| `agents/*.agent.md` | Custom agents (8 total) |
| `scripts/*.py` | Codemap, skill suggestions |
| `templates/*.md` | Workflow log, skill, agent templates |

## Key Scripts

```bash
python .github/scripts/knowledge.py      # Update knowledge (--update, --generate, --suggest)
python .github/scripts/skills.py         # Skill management (--update, --generate, --suggest)
python .github/scripts/instructions.py   # Instruction optimization
python .github/scripts/docs.py           # Documentation updates
python .github/scripts/agents.py         # Agent management
python .github/scripts/session_cleanup.py # Session cleanup
```

## Usage

1. Agent reads `copilot-instructions.md` at session start
2. Follows START→WORK→END phases
3. Loads skills from `skills/` when touching relevant files
4. At END: runs scripts, creates workflow log

---

*Context over Process. Knowledge over Ceremony.*
