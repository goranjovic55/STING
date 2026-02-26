#!/usr/bin/env python3
"""
Planning Skill Validation Script

Validates blueprint and planning documents.
"""

import sys
from pathlib import Path


def check_blueprint(filepath: Path) -> list:
    """Check blueprint for required sections."""
    issues = []
    
    try:
        content = filepath.read_text()
        
        required_sections = ['## Scope', '## Design', '## Tasks']
        for section in required_sections:
            if section not in content and section.lower() not in content.lower():
                issues.append({
                    'file': str(filepath),
                    'message': f'Blueprint missing {section} section',
                    'severity': 'warning'
                })
                
    except Exception as e:
        issues.append({
            'file': str(filepath),
            'message': f'Could not read file: {e}',
            'severity': 'error'
        })
    
    return issues


def main():
    """Run validation."""
    print("Planning Skill Validation")
    print("=" * 60)
    
    issues = []
    
    # Find blueprint files
    project_dir = Path('.project')
    if project_dir.exists():
        for f in project_dir.glob('**/*.md'):
            issues.extend(check_blueprint(f))
    
    if issues:
        for issue in issues:
            prefix = '❌' if issue['severity'] == 'error' else '⚠️'
            print(f"{prefix} {issue['file']}: {issue['message']}")
    else:
        print("✅ All planning documents validated")
    
    return 0 if not any(i['severity'] == 'error' for i in issues) else 1


if __name__ == '__main__':
    sys.exit(main())
