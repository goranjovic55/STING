---
name: research
description: Load for investigating standards, comparing approaches, or gathering best practices. Provides GATHER → ANALYZE → SYNTHESIZE workflow with local-first strategy.
---

# Research

## Merged Skills
- **standards**: Industry best practices, conventions
- **comparison**: Evaluating alternatives, trade-offs

## ⚠️ Critical Gotchas

| Category | Pattern | Solution |
|----------|---------|----------|
| External first | Searching web before local | Check docs/ + codebase FIRST (saves 80% tokens) |
| Time sink | Research taking >5 min per topic | Time box strictly, move on with best available |
| Lost findings | Research not documented | Cache findings in blueprint or knowledge |
| No sources | Recommendations without citations | Always document where standards came from |
| Over-research | Researching solved problems | Check if pattern exists in codebase first |

## Rules

| Rule | Pattern |
|------|---------|
| Local first | grep docs/ + codebase before any external search |
| Time box | Keep research <5 min per topic |
| Cache findings | Document in blueprint or update knowledge file |
| Cite sources | Note where standards/patterns came from |
| Synthesize | Return actionable recommendation, not just data |

## Avoid

| ❌ Bad | ✅ Good |
|--------|---------|
| Search web first | grep local docs first |
| Open-ended research | Time-boxed to 5 min |
| Undocumented findings | Cached in blueprint |
| Raw data dump | Synthesized recommendation |
| Re-researching | Check knowledge cache first |

## Patterns

```markdown
# Research Output Format

## Research: {Topic}

### Local Findings
- Pattern found in: `backend/app/services/example.py`
- Existing implementation: {description}

### Standards (if external needed)
- Source: {URL or reference}
- Key points: {summary}

### Recommendation
- **Action:** {what to do}
- **Rationale:** {why this approach}
- **Trade-offs:** {what we're giving up}
```

```bash
# Local research commands
grep -r "pattern" docs/
grep -r "similar_feature" backend/ frontend/
cat docs/technical/relevant.md
```

## Sources (Priority Order)

| Priority | Source | When to Use |
|----------|--------|-------------|
| 1 | Project docs/ | Always check first |
| 2 | Codebase patterns | Existing implementations |
| 3 | project_knowledge.json | Cached gotchas, patterns |
| 4 | External standards | Only if local insufficient |

## Workflow

| Phase | Action | Output |
|-------|--------|--------|
| GATHER | grep local, then external if needed | Raw findings |
| ANALYZE | Compare patterns, check standards | Evaluated options |
| SYNTHESIZE | Return recommendation + rationale | Actionable advice |

## Commands

| Task | Command |
|------|---------|
| Search docs | `grep -r "topic" docs/` |
| Find patterns | `grep -r "pattern" backend/ frontend/` |
| Check knowledge | `head -100 project_knowledge.json` |
| Search gotchas | `grep "error_pattern" project_knowledge.json` |
