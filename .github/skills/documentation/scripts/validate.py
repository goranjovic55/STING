#!/usr/bin/env python3
"""
Documentation Skill Validation Script

Validates documentation files for completeness and formatting.
"""

import sys
from pathlib import Path


def check_markdown_file(filepath: Path) -> list:
    """Check markdown file for common issues."""
    issues = []
    
    try:
        content = filepath.read_text()
        
        # Check for main heading
        if not content.strip().startswith('#'):
            issues.append({
                'file': str(filepath),
                'message': 'Missing main heading (should start with #)',
                'severity': 'warning'
            })
        
        # Check README has sections
        if 'README' in str(filepath).upper():
            required_sections = ['##']
            if not any(section in content for section in required_sections):
                issues.append({
                    'file': str(filepath),
                    'message': 'README should have subsections (##)',
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
    print("Documentation Skill Validation")
    print("=" * 60)
    
    issues = []
    
    # Find markdown files in docs/ and root
    doc_files = list(Path('docs').glob('**/*.md')) if Path('docs').exists() else []
    doc_files.extend(Path('.').glob('*.md'))
    
    for f in doc_files[:20]:  # Check first 20
        issues.extend(check_markdown_file(f))
    
    if issues:
        for issue in issues:
            prefix = '❌' if issue['severity'] == 'error' else '⚠️'
            print(f"{prefix} {issue['file']}: {issue['message']}")
    else:
        print("✅ All documentation validated")
    
    return 0 if not any(i['severity'] == 'error' for i in issues) else 1


if __name__ == '__main__':
    sys.exit(main())
