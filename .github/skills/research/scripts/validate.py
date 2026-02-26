#!/usr/bin/env python3
"""
Research Skill Validation Script

Validates research outputs have required sections.
"""

import sys
from pathlib import Path


def check_research_doc(filepath: Path) -> list:
    """Check research document for required sections."""
    issues = []
    
    try:
        content = filepath.read_text()
        
        # Check for recommendation section
        if 'research' in filepath.name.lower():
            if 'recommendation' not in content.lower():
                issues.append({
                    'file': str(filepath),
                    'message': 'Research document should include a Recommendation section',
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
    print("Research Skill Validation")
    print("=" * 60)
    
    issues = []
    
    # Find research documents
    for pattern in ['.project/**/*research*.md', 'docs/**/*research*.md']:
        for f in Path('.').glob(pattern):
            issues.extend(check_research_doc(f))
    
    if issues:
        for issue in issues:
            prefix = '❌' if issue['severity'] == 'error' else '⚠️'
            print(f"{prefix} {issue['file']}: {issue['message']}")
    else:
        print("✅ All research documents validated")
    
    return 0 if not any(i['severity'] == 'error' for i in issues) else 1


if __name__ == '__main__':
    sys.exit(main())
