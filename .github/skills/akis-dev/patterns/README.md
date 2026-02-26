# AKIS Development Patterns

Reusable patterns for AKIS framework development.

## Pattern Files

| Pattern | Description | Usage |
|---------|-------------|-------|
| `skill_template.md` | New skill structure | Create skills |
| `agent_template.md` | Agent definition | Create agents |
| `instruction_template.md` | Instructions file | Add instructions |
| `knowledge_entry.json` | Knowledge graph entry | Add entities |

## Skill Template
```markdown
---
name: skill-name
description: Load when... Provides...
---

# Skill Name

## Merged Skills
- **sub-skill**: Description

## ⚠️ Critical Gotchas

| Category | Pattern | Solution |
|----------|---------|----------|
| Issue | Trigger | Fix |

## Rules

| Rule | Pattern |
|------|---------|
| Rule 1 | Pattern 1 |

## Avoid

| ❌ Bad | ✅ Good |
|--------|---------|
| Bad practice | Good practice |

## Patterns

\`\`\`python
# Code pattern
\`\`\`

## Commands

| Task | Command |
|------|---------|
| Task 1 | `command` |
```

## Agent Template
```markdown
---
name: agent-name
description: 'Agent purpose description'
tools: ['tool1', 'tool2']
---

# Agent Name

## Triggers
| Pattern | Type |
|---------|------|
| keyword | Keywords |

## Methodology
1. Step 1
2. Step 2

## Rules
| Rule | Requirement |
|------|-------------|
| Rule 1 | Requirement 1 |
```

## Knowledge Entry
```json
{
  "entity": "entity_name",
  "type": "component|service|file",
  "domain": "frontend|backend|infrastructure",
  "relations": [
    {"type": "depends_on", "target": "other_entity"}
  ]
}
```

## Pattern Selection

| Task | Pattern |
|------|---------|
| New skill | skill_template.md |
| New agent | agent_template.md |
| Add instructions | instruction_template.md |
| Knowledge graph | knowledge_entry.json |
