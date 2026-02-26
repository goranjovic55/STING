---
name: documentation
description: Load when editing .md files, docs/ directory, README, or CHANGELOG. Provides documentation structure and best practices for technical writing.
---

# Documentation

## Merged Skills
- **technical-writing**: Clear, concise documentation
- **api-docs**: Endpoint documentation, schemas
- **guides**: How-to tutorials, step-by-step instructions

## ⚠️ Critical Gotchas

| Category | Pattern | Solution |
|----------|---------|----------|
| Stale docs | Docs updated separately from code | Update docs in SAME commit as code changes |
| Broken links | Links break after file moves | Check relative paths, use `grep -r "old_path"` |
| Stale examples | Code samples don't work | Verify examples actually run |
| Duplicate content | Same info in multiple places | Link to source, don't duplicate |
| Missing context | Doc assumes knowledge | Include prerequisites, link to background |
| No navigation | Users can't find docs | Update docs/INDEX.md with new entries |

## Rules

| Rule | Pattern |
|------|---------|
| Same commit | Doc changes in same commit as code |
| Include examples | Code samples for every concept |
| Link don't duplicate | Reference existing docs |
| Update INDEX | Add new docs to docs/INDEX.md |
| Verify examples | Test that code samples work |

## Avoid

| ❌ Bad | ✅ Good |
|--------|---------|
| Docs in separate PR | Same commit as code |
| Duplicate content | Link to existing docs |
| No code examples | Include runnable samples |
| Orphan docs | Update INDEX.md |
| Assumed knowledge | State prerequisites |

## Patterns

```markdown
# Pattern 1: Feature documentation
# Feature Name

## Overview
Brief description of what this feature does and why it exists.

## Prerequisites
- Requirement 1
- Requirement 2

## Usage

```python
# Example code that actually works
from module import feature
result = feature.do_something()
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `option1` | string | `"default"` | What it does |

## See Also
- [Related Feature](./related.md)
```

```markdown
# Pattern 2: API endpoint documentation
## POST /api/resource/

Creates a new resource.

### Request
```json
{
  "name": "string",
  "value": 123
}
```

### Response (201)
```json
{
  "id": 1,
  "name": "string",
  "created_at": "2026-01-13T00:00:00Z"
}
```

### Errors
| Code | Description |
|------|-------------|
| 400 | Invalid request body |
| 401 | Unauthorized |
```

## Templates (Diátaxis Framework)

| Template | Type | Use For | Location |
|----------|------|---------|----------|
| `.github/templates/doc_tutorial.md` | Tutorial | Learning-oriented guides | `docs/guides/` |
| `.github/templates/doc_guide.md` | How-To | Task-oriented instructions | `docs/guides/` |
| `.github/templates/doc_reference.md` | Reference | API specs, config lookup | `docs/technical/` |
| `.github/templates/doc_explanation.md` | Explanation | Architecture, concepts | `docs/architecture/` |
| `.github/templates/doc_analysis.md` | Analysis | Reports, audits, metrics | `docs/analysis/` |

## Structure

| Content Type | Location | Purpose |
|--------------|----------|---------|
| How-to guides | `docs/guides/` | Task-oriented tutorials |
| Feature docs | `docs/features/` | Feature explanations |
| API reference | `docs/technical/` | API specs, schemas |
| Architecture | `docs/architecture/` | Design decisions |
| Analysis/Reports | `docs/analysis/` | Audits, metrics, reports |
| Quick start | `README.md` | Getting started |
| Navigation | `docs/INDEX.md` | Doc discovery |
| Standards | `docs/contributing/` | Style guide, conventions |

## Commands

| Task | Command |
|------|---------|
| Find broken links | `grep -r "](.*\.md)" docs/ \| xargs -I{} test -f {}` |
| Check for stale refs | `grep -r "old_feature" docs/` |
| Update index | Edit `docs/INDEX.md` |
| Preview locally | Open .md file in VS Code preview |
