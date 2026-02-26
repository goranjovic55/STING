#!/usr/bin/env python3
"""
Backend API Skill Validation Script

Validates Python backend files for common issues identified in gotchas.
Run this before committing backend changes.

Usage:
    python .github/skills/backend-api/scripts/validate.py
    python .github/skills/backend-api/scripts/validate.py --file backend/app/api/endpoints/items.py
"""

import ast
import re
import sys
from pathlib import Path
from typing import List, Dict, Any

# Gotchas to check
GOTCHAS = {
    'jsonb_mutation': {
        'pattern': r'\.agent_metadata\[|\.config\[|\.data\[',
        'check': 'flag_modified',
        'message': 'JSONB mutation without flag_modified() - changes may not persist',
        'severity': 'error',
    },
    'sync_db_call': {
        'pattern': r'\.execute\(',
        'check': 'await',
        'message': 'DB execute() without await - use async pattern',
        'severity': 'error',
    },
    'missing_response_model': {
        'pattern': r'@router\.(get|post|put|delete|patch)\(',
        'check': 'response_model',
        'message': 'Endpoint missing response_model - add type safety',
        'severity': 'warning',
    },
    'websocket_disconnect': {
        'pattern': r'@router\.websocket\(',
        'check': 'WebSocketDisconnect',
        'message': 'WebSocket endpoint should handle WebSocketDisconnect exception',
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
    
    # Check for JSONB mutations without flag_modified
    for i, line in enumerate(lines, 1):
        for gotcha_name, gotcha in GOTCHAS.items():
            if re.search(gotcha['pattern'], line):
                # Look for the check pattern in nearby lines
                context = '\n'.join(lines[max(0, i-5):min(len(lines), i+5)])
                if gotcha['check'] not in context:
                    issues.append({
                        'file': str(filepath),
                        'line': i,
                        'gotcha': gotcha_name,
                        'message': gotcha['message'],
                        'severity': gotcha['severity'],
                        'code': line.strip(),
                    })
    
    return issues


def validate_syntax(filepath: Path) -> List[Dict[str, Any]]:
    """Validate Python syntax."""
    issues = []
    
    try:
        content = filepath.read_text(encoding='utf-8')
        ast.parse(content)
    except SyntaxError as e:
        issues.append({
            'file': str(filepath),
            'line': e.lineno or 0,
            'message': f'Syntax error: {e.msg}',
            'severity': 'error',
        })
    
    return issues


def main():
    """Run validation."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate backend API files')
    parser.add_argument('--file', '-f', help='Specific file to validate')
    parser.add_argument('--dir', '-d', default='backend', help='Directory to scan')
    args = parser.parse_args()
    
    # Collect files to check
    files = []
    if args.file:
        files = [Path(args.file)]
    else:
        backend_dir = Path(args.dir)
        if backend_dir.exists():
            files = list(backend_dir.rglob('*.py'))
    
    if not files:
        print("No Python files found to validate")
        return 0
    
    print(f"Validating {len(files)} backend files...")
    print("=" * 60)
    
    all_issues = []
    errors = 0
    warnings = 0
    
    for filepath in files:
        # Skip test files and migrations
        if 'test' in str(filepath).lower() or 'alembic' in str(filepath):
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
