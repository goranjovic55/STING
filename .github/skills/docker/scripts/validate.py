#!/usr/bin/env python3
"""
Docker Skill Validation Script

Validates Docker and docker-compose configurations.
"""

import sys
from pathlib import Path


def check_compose_file(filepath: Path) -> list:
    """Check docker-compose file for common issues."""
    issues = []
    
    try:
        content = filepath.read_text()
        
        # Check for restart policy
        if 'restart:' not in content:
            issues.append({
                'file': str(filepath),
                'message': 'Missing restart policy for services',
                'severity': 'warning'
            })
        
        # Check for health checks
        if 'healthcheck:' not in content and 'docker-compose.dev' not in str(filepath):
            issues.append({
                'file': str(filepath),
                'message': 'Consider adding healthcheck for production',
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
    print("Docker Skill Validation")
    print("=" * 60)
    
    issues = []
    
    # Find docker-compose files
    compose_files = list(Path('.').glob('**/docker-compose*.yml'))
    
    for f in compose_files:
        issues.extend(check_compose_file(f))
    
    if issues:
        for issue in issues:
            prefix = '❌' if issue['severity'] == 'error' else '⚠️'
            print(f"{prefix} {issue['file']}: {issue['message']}")
    else:
        print("✅ All Docker configurations validated")
    
    return 0 if not any(i['severity'] == 'error' for i in issues) else 1


if __name__ == '__main__':
    sys.exit(main())
