#!/usr/bin/env python3
"""
Security Skill Validation Script

Validates code for common security vulnerabilities.
"""

import re
import sys
from pathlib import Path


def check_python_file(filepath: Path) -> list:
    """Check Python file for security issues."""
    issues = []
    
    try:
        content = filepath.read_text()
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for SQL string formatting (injection risk)
            if re.search(r'f["\'].*SELECT.*{', line, re.IGNORECASE):
                issues.append({
                    'file': str(filepath),
                    'line': i,
                    'message': 'Possible SQL injection: use parameterized queries',
                    'severity': 'error'
                })
            
            # Check for eval/exec
            if 'eval(' in line or 'exec(' in line:
                issues.append({
                    'file': str(filepath),
                    'line': i,
                    'message': 'Avoid eval/exec - code injection risk',
                    'severity': 'error'
                })
            
            # Check for hardcoded secrets
            if re.search(r'(password|secret|api_key)\s*=\s*["\'][^"\']+["\']', line, re.IGNORECASE):
                if 'os.environ' not in line and 'getenv' not in line:
                    issues.append({
                        'file': str(filepath),
                        'line': i,
                        'message': 'Possible hardcoded secret - use environment variables',
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
    print("Security Skill Validation")
    print("=" * 60)
    
    issues = []
    
    # Check Python files in backend
    backend_dir = Path('backend')
    if backend_dir.exists():
        for f in backend_dir.rglob('*.py'):
            if 'test' not in str(f).lower():
                issues.extend(check_python_file(f))
    
    if issues:
        for issue in issues:
            prefix = '❌' if issue['severity'] == 'error' else '⚠️'
            line_info = f":{issue.get('line', 0)}" if issue.get('line') else ''
            print(f"{prefix} {issue['file']}{line_info}: {issue['message']}")
    else:
        print("✅ No security issues found")
    
    return 0 if not any(i['severity'] == 'error' for i in issues) else 1


if __name__ == '__main__':
    sys.exit(main())
