#!/usr/bin/env python3
"""
CI/CD Skill Validation Script

Validates GitHub Actions workflow files.
"""

import sys
from pathlib import Path


def check_workflow_file(filepath: Path) -> list:
    """Check workflow file for common issues."""
    issues = []
    
    try:
        content = filepath.read_text()
        
        # Check for name
        if 'name:' not in content:
            issues.append({
                'file': str(filepath),
                'message': 'Workflow missing name',
                'severity': 'warning'
            })
        
        # Check for on trigger
        if 'on:' not in content:
            issues.append({
                'file': str(filepath),
                'message': 'Workflow missing trigger (on:)',
                'severity': 'error'
            })
        
        # Check for jobs
        if 'jobs:' not in content:
            issues.append({
                'file': str(filepath),
                'message': 'Workflow missing jobs section',
                'severity': 'error'
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
    print("CI/CD Skill Validation")
    print("=" * 60)
    
    issues = []
    
    # Find workflow files
    workflows_dir = Path('.github/workflows')
    if workflows_dir.exists():
        for f in workflows_dir.glob('*.yml'):
            issues.extend(check_workflow_file(f))
    
    if issues:
        for issue in issues:
            prefix = '❌' if issue['severity'] == 'error' else '⚠️'
            print(f"{prefix} {issue['file']}: {issue['message']}")
    else:
        print("✅ All workflow files validated")
    
    return 0 if not any(i['severity'] == 'error' for i in issues) else 1


if __name__ == '__main__':
    sys.exit(main())
