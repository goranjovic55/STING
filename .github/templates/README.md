# AKIS Templates

## Template Index

| Template | Use | Location |
|----------|-----|----------|
| **AKIS Framework** |||
| `agent.md` | Specialist agents | `.github/agents/` |
| `skill.md` | Reusable patterns | `.github/skills/` |
| `instruction.md` | Copilot code guidance | `.github/instructions/` |
| `workflow-log.md` | Session logs (>15min) | `log/workflow/` |
| `workflow-prompt.md` | Multi-phase workflows | `.github/prompts/` |
| **Documentation (Diátaxis)** |||
| `doc_tutorial.md` | Learning-oriented guides | `docs/guides/` |
| `doc_guide.md` | Task-oriented how-to | `docs/guides/` |
| `doc_reference.md` | API/config reference | `docs/technical/` |
| `doc_explanation.md` | Architecture/concepts | `docs/architecture/`, `docs/features/` |
| `doc_analysis.md` | Reports and audits | `docs/analysis/` |
| **Legacy** |||
| `feature-doc.md` | Feature documentation | `docs/features/` |
| `guide-doc.md` | How-to guides | `docs/guides/` |
| `doc-update-notes.md` | Doc update tracking | `log/workflow/` |

## Documentation Templates (Diátaxis Framework)

Based on [Diátaxis](https://diataxis.fr/) - industry standard for technical documentation:

| Template | Type | Purpose |
|----------|------|---------|
| `doc_tutorial.md` | Tutorial | Learning-oriented, step-by-step for new users |
| `doc_guide.md` | How-To | Task-oriented, solve specific problems |
| `doc_reference.md` | Reference | Information-oriented, lookup technical details |
| `doc_explanation.md` | Explanation | Understanding-oriented, architecture/concepts |
| `doc_analysis.md` | Analysis | Project reports, audits, metrics |

## Skills vs Instructions vs Agents

| Type | Purpose | Triggered By | Content Focus |
|------|---------|--------------|---------------|
| **Skill** | Deep domain knowledge | Agent loads manually | Gotchas, patterns, commands |
| **Instruction** | Code generation guidance | File pattern match (applyTo) | Rules, standards, examples |
| **Agent** | Task orchestration | User invokes mode | Workflow, delegation, tools |

## Style Rules
- Terse: Bullets > paragraphs
- Actionable: What to do, not theory
- Examples: Copy-paste ready
- Links: Cross-reference related docs
- Tables: Use for structured content

## YAML Frontmatter Requirements

### Agent (`*.agent.md`)
```yaml
---
name: agent-name                    # REQUIRED: lowercase with hyphens
description: 'What it does'         # REQUIRED: 10-500 chars, single-quoted
tools: ['read', 'edit', 'search']   # OPTIONAL: tool permissions
---
```

### Skill (`SKILL.md`)
```yaml
---
name: skill-name                    # REQUIRED: matches folder name
description: 'When to load...'      # REQUIRED: max 1024 chars
---
```

### Instruction (`*.instructions.md`)
```yaml
---
description: 'Code guidance for...' # REQUIRED: 1-500 chars
applyTo: '**/*.ts'                  # REQUIRED: glob pattern
---
```

## Tool Aliases for Agents

| Alias | Alternative Names | Description |
|-------|------------------|-------------|
| `execute` | shell, bash | Execute shell commands |
| `read` | view | Read file contents |
| `edit` | write, multiedit | Edit and modify files |
| `search` | grep, glob | Search files/text |
| `agent` | runsubagent | Invoke other agents |
| `web` | fetch | Fetch web content |
| `todo` | todowrite | Task management |
