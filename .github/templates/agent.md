---
name: {agent-name}
description: '{Brief description of what the agent does and when to use it. 10-500 chars.}'
tools: ['read', 'edit', 'search', 'execute']
---

# {Agent Name} Agent

> `@{agent-name}` | {Short tagline describing primary action}

## Triggers

| Pattern | Type |
|---------|------|
| {keyword1}, {keyword2} | Keywords |
| {.ext1}, {.ext2} | Extensions |
| {folder1/}, {folder2/} | Directories |

## Methodology (⛔ REQUIRED ORDER)
1. **{PHASE1}** - {What to do in this phase}
2. **{PHASE2}** - {What to do in this phase}
3. **{PHASE3}** - {What to do in this phase}
4. **{VERIFY}** - {Verification step}

## Rules

| Rule | Requirement |
|------|-------------|
| {Rule1} | {What must be done} |
| {Rule2} | {What must be done} |

## Output Format
```markdown
## {Task Type}: [Description]
### Files: path/file.ext (change summary)
### Verification: ✓ check1 | ✓ check2
[RETURN] ← {agent-name} | result: ✓ | files: N
```

## ⚠️ Gotchas
- {Common issue 1} | {How to handle}
- {Common issue 2} | {How to handle}

## ⚙️ Optimizations
- **{Optimization1}**: {Description of efficiency improvement}
- **{Optimization2}**: {Description of efficiency improvement}

## Orchestration

| From | To |
|------|----|
| AKIS, {caller-agents} | AKIS |

## Handoffs (Optional)
```yaml
handoffs:
  - label: {Next Step Button Text}
    agent: {target-agent}
    prompt: '{Pre-filled prompt for next agent}'
```
