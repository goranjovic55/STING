#!/usr/bin/env python3
"""
Testing Skill Validation Script

Validates test files for common issues.
"""

import re
import sys
from pathlib import Path


def check_test_file(filepath: Path) -> list:
    """Check test file for common issues."""
    issues = []
    
    try:
        content = filepath.read_text()
        lines = content.split('\n')
        
        # Check for async test without proper fixtures
        if 'async def test_' in content:
            if '@pytest.fixture' not in content and 'async_client' not in content:
                issues.append({
                    'file': str(filepath),
                    'message': 'Async tests may need async fixtures',
                    'severity': 'warning'
                })
        
        # Check for time.sleep in tests
        for i, line in enumerate(lines, 1):
            if 'time.sleep' in line:
                issues.append({
                    'file': str(filepath),
                    'line': i,
                    'message': 'Use explicit waits instead of time.sleep()',
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
    print("Testing Skill Validation")
    print("=" * 60)
    
    issues = []
    
    # Find test files
    test_patterns = ['**/test_*.py', '**/*_test.py', '**/*.test.ts', '**/*.test.tsx']
    test_files = []
    for pattern in test_patterns:
        test_files.extend(Path('.').glob(pattern))
    
    # Skip node_modules
    test_files = [f for f in test_files if 'node_modules' not in str(f)]
    
    for f in test_files[:20]:  # Check first 20
        issues.extend(check_test_file(f))
    
    if issues:
        for issue in issues:
            prefix = '❌' if issue['severity'] == 'error' else '⚠️'
            line_info = f":{issue.get('line', 0)}" if issue.get('line') else ''
            print(f"{prefix} {issue['file']}{line_info}: {issue['message']}")
    else:
        print("✅ All test files validated")
    
    return 0 if not any(i['severity'] == 'error' for i in issues) else 1


if __name__ == '__main__':
    sys.exit(main())
