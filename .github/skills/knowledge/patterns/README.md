# Knowledge Patterns

Reusable patterns for project knowledge graph management using **JSONL format**.

## JSONL Structure

`project_knowledge.json` uses JSONL (JSON Lines) format - **one JSON object per line**:

| Line | Type | Content | Use For |
|------|------|---------|----------|
| 1 | `hot_cache` | Top 30 entities + entity_refs | Quick entity lookup |
| 2 | `domain_index` | Backend/Frontend file paths | File location |
| 3 | `change_tracking` | File hashes | Staleness detection |
| 4 | `gotchas` | 30+ issues + solutions | Debug patterns |
| 5 | `interconnections` | Entity chains | Context recovery |
| 6 | `session_patterns` | Preload hints | Predictive loading |
| 7+ | `entity` / `relation` | Individual graph nodes | Full graph |

## Pattern Files

| Pattern | Description | Usage |
|---------|-------------|-------|
| `entity_template.jsonl` | Entity definition | Add new entities |
| `relation_template.jsonl` | Relation definition | Link entities |
| `query_pattern.py` | JSONL query | Search knowledge |
| `cache_update.py` | Cache management | Update hot cache |

## JSONL Read Pattern (Recommended)

```python
import json

def load_knowledge_jsonl(filepath: str = 'project_knowledge.json'):
    """Load JSONL knowledge file - read line by line."""
    knowledge = {}
    
    with open(filepath, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            data = json.loads(line)
            obj_type = data.get('type')
            
            # First 6 lines are header objects
            if obj_type in ('hot_cache', 'domain_index', 'change_tracking', 
                           'gotchas', 'interconnections', 'session_patterns'):
                knowledge[obj_type] = data
            
            # Stop after first 100 lines for quick context
            if line_num >= 100:
                break
    
    return knowledge
```

## Entity Template (JSONL)
```json
{"type": "entity", "name": "entity_name", "entityType": "component", "weight": 100, "observations": ["Description"]}
```

## Relation Template (JSONL)
```json
{"type": "relation", "from": "entity_a", "to": "entity_b", "relationType": "depends_on"}
```

## Graph Query Pattern (JSONL)
```python
def query_knowledge_jsonl(entity_name: str, knowledge: dict) -> dict:
    """Query JSONL knowledge graph for entity info."""
    # Check hot cache first (already parsed from line 1)
    hot_cache = knowledge.get('hot_cache', {})
    entity_refs = hot_cache.get('entity_refs', {})
    
    if entity_name in entity_refs:
        return {
            'name': entity_name,
            'path': entity_refs[entity_name],
            'source': 'hot_cache'
        }
    
    # Check domain index (parsed from line 2)
    domain_index = knowledge.get('domain_index', {})
    
    # Check backend entities
    backend_entities = domain_index.get('backend_entities', {})
    if entity_name in backend_entities:
        return {
            'name': entity_name,
            'path': backend_entities[entity_name],
            'domain': 'backend',
            'source': 'domain_index'
        }
    
    # Check frontend entities
    frontend_entities = domain_index.get('frontend_entities', {})
    if entity_name in frontend_entities:
        return {
            'name': entity_name,
            'path': frontend_entities[entity_name],
            'domain': 'frontend',
            'source': 'domain_index'
        }
    
    return None
```

## Gotcha Lookup Pattern
```python
def check_gotchas_jsonl(search_term: str, knowledge: dict) -> list:
    """Search gotchas for matching issues."""
    gotchas = knowledge.get('gotchas', {})
    issues = gotchas.get('issues', {})
    
    matches = []
    for problem, details in issues.items():
        if search_term.lower() in problem.lower():
            matches.append({
                'problem': problem,
                'solution': details.get('solution'),
                'source': details.get('source'),
                'applies_to': details.get('applies_to', [])
            })
    
    return matches
```

## Pattern Selection

| Task | Pattern |
|------|---------|
| Load first 100 lines | `load_knowledge_jsonl()` |
| Find entity path | `query_knowledge_jsonl()` |
| Check known issues | `check_gotchas_jsonl()` |
| Add entity | Append JSONL line |
| Update cache | Modify line 1 |

## CLI Usage

```bash
# Load first 100 lines (headers + top entities)
head -100 project_knowledge.json

# Count lines
wc -l project_knowledge.json

# Extract hot_cache (line 1)
head -1 project_knowledge.json | python -c "import sys,json; print(json.dumps(json.load(sys.stdin), indent=2))"

# Extract gotchas (line 4)
sed -n '4p' project_knowledge.json | python -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('issues',{})), 'gotchas')"
```
