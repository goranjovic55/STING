#!/usr/bin/env python3
"""
AKIS Development Skill Validation Script

Validates AKIS framework files (skills, agents, instructions).
"""

import sys
from pathlib import Path


def check_skill_file(filepath: Path) -> list:
    """Check skill file for required structure."""
    issues = []
    
    try:
        content = filepath.read_text()
        
        # Check for YAML frontmatter
        if not content.startswith('---'):
            issues.append({
                'file': str(filepath),
                'message': 'SKILL.md missing YAML frontmatter',
                'severity': 'error'
            })
        
        # Check for required sections
        required = ['## Rules', '## Patterns', '## Commands']
        for section in required:
            if section not in content:
                issues.append({
                    'file': str(filepath),
                    'message': f'Missing {section} section',
                    'severity': 'warning'
                })
        
        # Check for Critical Gotchas
        if 'Critical Gotchas' not in content and 'Gotchas' not in content:
            issues.append({
                'file': str(filepath),
                'message': 'Missing Gotchas section',
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
    print("AKIS Development Skill Validation")
    print("=" * 60)
    
    issues = []
    
    # Find skill files
    skills_dir = Path('.github/skills')
    if skills_dir.exists():
        for skill_dir in skills_dir.iterdir():
            if skill_dir.is_dir():
                skill_file = skill_dir / 'SKILL.md'
                if skill_file.exists():
                    issues.extend(check_skill_file(skill_file))
    
    if issues:
        for issue in issues:
            prefix = '❌' if issue['severity'] == 'error' else '⚠️'
            print(f"{prefix} {issue['file']}: {issue['message']}")
    else:
        print("✅ All AKIS files validated")
    
    return 0 if not any(i['severity'] == 'error' for i in issues) else 1


if __name__ == '__main__':
    sys.exit(main())
