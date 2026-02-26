#!/usr/bin/env python3
"""
Frontend React Skill Validation Script

Validates TypeScript/React files for common issues identified in gotchas.
Run this before committing frontend changes.

Usage:
    python .github/skills/frontend-react/scripts/validate.py
    python .github/skills/frontend-react/scripts/validate.py --file frontend/src/components/MyComponent.tsx
"""

import re
import sys
from pathlib import Path
from typing import List, Dict, Any

# Gotchas to check
GOTCHAS = {
    'jsx_comment': {
        'pattern': r'^\s*//.*$',  # Line starting with //
        'context': r'<[A-Z]',  # In JSX context (component)
        'message': 'Possible incorrect comment syntax in JSX - use {/* */} not //',
        'severity': 'warning',
    },
    'missing_key': {
        'pattern': r'\.map\s*\(',
        'check': 'key=',
        'message': 'Array.map() should include key prop on returned elements',
        'severity': 'warning',
    },
    'async_useeffect': {
        'pattern': r'useEffect\s*\(\s*async',
        'message': 'useEffect cannot be async - use wrapper function inside',
        'severity': 'error',
    },
    'empty_deps': {
        'pattern': r'useEffect\s*\([^)]+,\s*\[\s*\]\s*\)',
        'message': 'Empty dependency array - verify no dependencies are needed',
        'severity': 'warning',
    },
    'wrong_auth_key': {
        'pattern': r'localStorage\.(get|set)Item\s*\(\s*[\'"](?!nop-auth)',
        'context': r'auth|token|user',
        'message': 'Auth storage should use "nop-auth" key, not "token" or "auth_token"',
        'severity': 'error',
    },
    'stale_closure': {
        'pattern': r'async\s*\(\)\s*=>\s*\{[^}]*set[A-Z]',
        'message': 'Potential stale closure in async handler - capture state before async call',
        'severity': 'warning',
    },
}


def check_file(filepath: Path) -> List[Dict[str, Any]]:
    """Check a single file for gotchas."""
    issues = []
    
    try:
        content = filepath.read_text(encoding='utf-8')
        lines = content.split('\n')
    except Exception as e:
        return [{'file': str(filepath), 'line': 0, 'message': f'Could not read file: {e}', 'severity': 'error'}]
    
    # Skip non-React files
    if not any(ext in str(filepath) for ext in ['.tsx', '.jsx']):
        return []
    
    # Check for issues
    for i, line in enumerate(lines, 1):
        # Check async useEffect (always error)
        if re.search(GOTCHAS['async_useeffect']['pattern'], line):
            issues.append({
                'file': str(filepath),
                'line': i,
                'gotcha': 'async_useeffect',
                'message': GOTCHAS['async_useeffect']['message'],
                'severity': 'error',
                'code': line.strip(),
            })
        
        # Check for map without key (look ahead)
        if re.search(GOTCHAS['missing_key']['pattern'], line):
            # Check next 10 lines for key prop
            context = '\n'.join(lines[i:min(len(lines), i+10)])
            if 'key=' not in context and 'key =' not in context:
                issues.append({
                    'file': str(filepath),
                    'line': i,
                    'gotcha': 'missing_key',
                    'message': GOTCHAS['missing_key']['message'],
                    'severity': 'warning',
                    'code': line.strip(),
                })
    
    return issues


def validate_syntax(filepath: Path) -> List[Dict[str, Any]]:
    """Basic TypeScript/React syntax validation."""
    issues = []
    
    try:
        content = filepath.read_text(encoding='utf-8')
        
        # Check for unbalanced braces (simple check)
        open_braces = content.count('{')
        close_braces = content.count('}')
        if open_braces != close_braces:
            issues.append({
                'file': str(filepath),
                'line': 0,
                'message': f'Unbalanced braces: {open_braces} open, {close_braces} close',
                'severity': 'error',
            })
        
        # Check for unbalanced JSX tags (simple check)
        jsx_open = len(re.findall(r'<[A-Z][a-zA-Z]*[^/>]*>', content))
        jsx_self_close = len(re.findall(r'<[A-Z][a-zA-Z]*[^>]*/>', content))
        jsx_close = len(re.findall(r'</[A-Z][a-zA-Z]*>', content))
        
        if jsx_open > jsx_close + jsx_self_close:
            issues.append({
                'file': str(filepath),
                'line': 0,
                'message': f'Possible unclosed JSX tags: {jsx_open} open, {jsx_close} close, {jsx_self_close} self-closing',
                'severity': 'warning',
            })
            
    except Exception as e:
        issues.append({
            'file': str(filepath),
            'line': 0,
            'message': f'Could not read file: {e}',
            'severity': 'error',
        })
    
    return issues


def main():
    """Run validation."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate frontend React files')
    parser.add_argument('--file', '-f', help='Specific file to validate')
    parser.add_argument('--dir', '-d', default='frontend/src', help='Directory to scan')
    args = parser.parse_args()
    
    # Collect files to check
    files = []
    if args.file:
        files = [Path(args.file)]
    else:
        frontend_dir = Path(args.dir)
        if frontend_dir.exists():
            files = list(frontend_dir.rglob('*.tsx')) + list(frontend_dir.rglob('*.jsx'))
    
    if not files:
        print("No React files found to validate")
        return 0
    
    print(f"Validating {len(files)} React files...")
    print("=" * 60)
    
    all_issues = []
    errors = 0
    warnings = 0
    
    for filepath in files:
        # Skip test files and node_modules
        if 'test' in str(filepath).lower() or 'node_modules' in str(filepath):
            continue
        
        # Syntax check
        syntax_issues = validate_syntax(filepath)
        all_issues.extend(syntax_issues)
        
        # Gotcha check
        gotcha_issues = check_file(filepath)
        all_issues.extend(gotcha_issues)
    
    # Report issues
    if all_issues:
        for issue in all_issues:
            prefix = '❌' if issue['severity'] == 'error' else '⚠️'
            print(f"{prefix} {issue['file']}:{issue['line']}")
            print(f"   {issue['message']}")
            if 'code' in issue:
                print(f"   Code: {issue['code'][:60]}...")
            print()
            
            if issue['severity'] == 'error':
                errors += 1
            else:
                warnings += 1
    
    print("=" * 60)
    print(f"Validation complete: {errors} errors, {warnings} warnings")
    
    if errors > 0:
        print("\n❌ Validation FAILED - fix errors before committing")
        return 1
    elif warnings > 0:
        print("\n⚠️ Validation passed with warnings")
        return 0
    else:
        print("\n✅ All files pass validation")
        return 0


if __name__ == '__main__':
    sys.exit(main())
