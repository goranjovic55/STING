#!/usr/bin/env python3
"""
Knowledge Skill Validation Script

Validates project_knowledge.json JSONL structure and content.
JSONL format: one JSON object per line.
"""

import json
import sys
from pathlib import Path


# Expected line types in order for first 6 lines
EXPECTED_HEADERS = [
    'hot_cache',
    'domain_index', 
    'change_tracking',
    'gotchas',
    'interconnections',
    'session_patterns'
]


def validate_knowledge_file(filepath: Path) -> list:
    """Validate JSONL knowledge graph file."""
    issues = []
    line_count = 0
    entity_count = 0
    relation_count = 0
    
    try:
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                    
                line_count += 1
                
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as e:
                    issues.append({
                        'file': str(filepath),
                        'line': line_num,
                        'message': f'Invalid JSON on line {line_num}: {e}',
                        'severity': 'error'
                    })
                    continue
                
                # Check type field exists
                if 'type' not in data:
                    issues.append({
                        'file': str(filepath),
                        'line': line_num,
                        'message': f'Line {line_num}: Missing "type" field',
                        'severity': 'warning'
                    })
                    continue
                
                obj_type = data['type']
                
                # Validate header lines (first 6)
                if line_count <= 6:
                    expected = EXPECTED_HEADERS[line_count - 1]
                    if obj_type != expected:
                        issues.append({
                            'file': str(filepath),
                            'line': line_num,
                            'message': f'Line {line_num}: Expected type "{expected}", got "{obj_type}"',
                            'severity': 'warning'
                        })
                
                # Count entities and relations
                if obj_type == 'entity':
                    entity_count += 1
                elif obj_type == 'relation':
                    relation_count += 1
                
                # Validate hot_cache structure
                if obj_type == 'hot_cache':
                    if 'top_entities' not in data:
                        issues.append({
                            'file': str(filepath),
                            'line': line_num,
                            'message': 'hot_cache missing "top_entities" field',
                            'severity': 'warning'
                        })
                    if 'entity_refs' not in data:
                        issues.append({
                            'file': str(filepath),
                            'line': line_num,
                            'message': 'hot_cache missing "entity_refs" field',
                            'severity': 'warning'
                        })
                
                # Validate entity structure
                if obj_type == 'entity':
                    if 'name' not in data:
                        issues.append({
                            'file': str(filepath),
                            'line': line_num,
                            'message': f'Entity on line {line_num} missing "name" field',
                            'severity': 'warning'
                        })
                
                # Validate relation structure
                if obj_type == 'relation':
                    for field in ['from', 'to', 'relationType']:
                        if field not in data:
                            issues.append({
                                'file': str(filepath),
                                'line': line_num,
                                'message': f'Relation on line {line_num} missing "{field}" field',
                                'severity': 'warning'
                            })
        
        print(f"\n📊 Stats: {line_count} lines, {entity_count} entities, {relation_count} relations")
                            
    except Exception as e:
        issues.append({
            'file': str(filepath),
            'message': f'Could not read file: {e}',
            'severity': 'error'
        })
    
    return issues


def main():
    """Run validation."""
    print("Knowledge Skill Validation (JSONL Format)")
    print("=" * 60)
    
    issues = []
    
    knowledge_file = Path('project_knowledge.json')
    if knowledge_file.exists():
        issues.extend(validate_knowledge_file(knowledge_file))
    else:
        print("⚠️ project_knowledge.json not found")
    
    if issues:
        errors = [i for i in issues if i['severity'] == 'error']
        warnings = [i for i in issues if i['severity'] == 'warning']
        
        for issue in issues:
            prefix = '❌' if issue['severity'] == 'error' else '⚠️'
            line_info = f" (line {issue.get('line', '?')})" if 'line' in issue else ''
            print(f"{prefix} {issue['file']}{line_info}: {issue['message']}")
        
        print(f"\n📋 Summary: {len(errors)} errors, {len(warnings)} warnings")
    else:
        print("✅ Knowledge graph validated (JSONL format)")
    
    return 0 if not any(i['severity'] == 'error' for i in issues) else 1


if __name__ == '__main__':
    sys.exit(main())
