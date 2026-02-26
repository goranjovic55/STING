# Research Patterns

Reusable patterns for investigating standards and best practices.

## Pattern Files

| Pattern | Description | Usage |
|---------|-------------|-------|
| `research_output.md` | Research findings | Document results |
| `comparison_table.md` | Alternative comparison | Evaluate options |
| `recommendation.md` | Final recommendation | Actionable advice |
| `source_citation.md` | Source tracking | Reference standards |

## Research Output Format
```markdown
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

## Comparison Table
```markdown
## Comparison: {Options}

| Criteria | Option A | Option B | Option C |
|----------|----------|----------|----------|
| Performance | ⭐⭐⭐ | ⭐⭐ | ⭐ |
| Complexity | Low | Medium | High |
| Maintenance | Easy | Moderate | Difficult |
| Community | Large | Medium | Small |

### Recommendation
Option A because...
```

## Recommendation Template
```markdown
## Recommendation: {Topic}

### Decision
{Clear statement of what to do}

### Rationale
1. Reason 1
2. Reason 2

### Trade-offs
- Pro: {benefit}
- Con: {drawback}

### Implementation
- Step 1
- Step 2
```

## Pattern Selection

| Stage | Pattern |
|-------|---------|
| Gather findings | research_output.md |
| Compare options | comparison_table.md |
| Final advice | recommendation.md |
| Track sources | source_citation.md |
