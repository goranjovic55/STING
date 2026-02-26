---
name: knowledge
description: Load for project knowledge querying, architecture lookup, gotcha checks, and knowledge maintenance. Query first (hot_cache, domain_index, gotchas), update at END.
---

# Knowledge

## Merged Skills
- **context-management**: Project knowledge graph, entity lookup
- **caching**: Hot cache, domain index, gotchas lookup
- **architecture-lookup**: File paths, structure, "where is X"

## ⚠️ Critical Gotchas

| Category | Pattern | Solution |
|----------|---------|----------|
| Multiple queries | Running --query 5 times | Read first 100 lines ONCE at START |
| Repeated reads | Reading knowledge file multiple times | Keep in memory for entire session |
| Wrong lookup | Searching when data is cached | Check hot_cache before file reads |
| Stale knowledge | Entity refs outdated | Run `knowledge.py --update` after sessions |
| Missing gotchas | New issues not documented | Add to workflow log, will be merged |
| Skip query | Searching codebase directly | Query knowledge FIRST (75% hit rate) |

## Rules

| Rule | Pattern |
|------|---------|
| Query first | Check knowledge before grep/find/list_dir |
| Load once | Read first 100 lines ONCE at session start |
| Memory-first | Keep loaded knowledge in context |
| Hot cache first | Check `hot_cache.entity_refs` before file reads |
| Gotchas first | Check `gotchas.issues` when debugging |
| Update at END | Run `knowledge.py --update` in END phase |

## When to Use Knowledge Skill

| Need | Query |
|------|-------|
| "Where is X file?" | domain_index.backend/frontend |
| "What does Y do?" | hot_cache.entity_refs |
| "Known issues with Z?" | gotchas.issues |
| "How are A and B connected?" | layer relations |
| Architecture questions | domain_index + interconnections |
| File path lookup | domain_index |
| Debug pattern | gotchas first |

## Avoid

| ❌ Bad | ✅ Good |
|--------|---------|
| Run --query 5 times | Read first 100 lines once |
| grep knowledge.json | Check loaded gotchas in memory |
| list_dir for paths | Check domain_index |
| Search for entity | Check hot_cache first |

## ⛔ MANDATORY: Load Once at START

```bash
head -100 project_knowledge.json  # Do this ONCE
```

**This gives you (in memory for entire session):**

| Line | Content | Use For |
|------|---------|---------|
| 1 | HOT_CACHE | Top 20 entities + file paths |
| 2 | DOMAIN_INDEX | 81 backend, 71 frontend paths |
| 3 | CHANGE_TRACKING | File modification hashes |
| 4 | GOTCHAS | 38 known issues + solutions |
| 5 | INTERCONNECTIONS | Entity chains |
| 6 | SESSION_PATTERNS | Preload hints |
| 7-12 | Layer entities | Graph structure |
| 13-93 | Layer relations | Lookup paths |

## Patterns

```bash
# Pattern 1: Session start - load knowledge
head -100 project_knowledge.json

# Pattern 2: Query specific entity (rare, only if cache miss)
python .github/scripts/knowledge.py --query "entity_name"

# Pattern 3: Update knowledge after session
python .github/scripts/knowledge.py --update
```

```python
# Pattern 4: Using knowledge programmatically
import json

with open('project_knowledge.json') as f:
    for i, line in enumerate(f):
        if i >= 100:
            break
        data = json.loads(line)
        if data.get('type') == 'hot_cache':
            entity_refs = data['entity_refs']
        elif data.get('type') == 'gotchas':
            issues = data['issues']
```

## Query Order (Using In-Memory Knowledge)

| Step | Check | If Miss |
|------|-------|---------|
| 1 | hot_cache.top_entities | → Step 2 |
| 2 | gotchas.issues | → Step 3 |
| 3 | domain_index.backend/frontend | → Step 4 |
| 4 | layer relations | → Step 5 |
| 5 | Use --query CLI | → Step 6 |
| 6 | Read file directly | Last resort |

## File Structure

| Lines | Content |
|-------|---------|
| 1-6 | Headers (ALL lookup data) |
| 7-12 | Layer entities (KNOWLEDGE_GRAPH, HOT_CACHE, ...) |
| 13-93 | Layer relations (caches → entity, indexes → file) |
| 94+ | Code entities (sorted by weight) |
| 300+ | Code relations (imports, calls) |

## Commands

| Task | Command |
|------|---------|
| Load knowledge | `head -100 project_knowledge.json` |
| Query entity | `python .github/scripts/knowledge.py --query "name"` |
| Update knowledge | `python .github/scripts/knowledge.py --update` |
| Suggest updates | `python .github/scripts/knowledge.py --suggest` |

## Stats (v4.2)
- First 100 lines: ~15KB (fits in context)
- Contains: 100% of lookup data
- File reads saved: 76.8%
- Queries saved: 90%+ (vs multiple --query calls)
