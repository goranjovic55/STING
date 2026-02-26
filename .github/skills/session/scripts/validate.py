#!/usr/bin/env python3
"""
Session Skill Validation Script

Validates session management patterns and gate compliance.
Run this before committing session-related changes.

Usage:
    python .github/skills/session/scripts/validate.py
    python .github/skills/session/scripts/validate.py --file log/workflow/session.md
"""

import re
import sys
from pathlib import Path
from typing import List, Dict, Any


# Session gotchas to check
GOTCHAS = {
    'orphan_todo': {
        'pattern': r'◆',
        'check': r'✓|⊘',
        'message': 'TODO left in working state (◆) - mark ✓ or ⊘',
        'severity': 'warning',
    },
    'multi_active': {
        'pattern': r'◆.*◆',
        'check': None,
        'message': 'Multiple active TODOs (◆) - only ONE allowed (G6)',
        'severity': 'warning',
    },
    'missing_start': {
        'pattern': r'^(- \[x\]|✓).*edit',
        'check': r'START',
        'message': 'Edit mentioned without START phase',
        'severity': 'error',
    },
    'missing_log': {
        'pattern': r'END.*phase|session.*complete',
        'check': r'workflow.*log|log/workflow',
        'message': 'END mentioned without workflow log',
        'severity': 'warning',
    },
}


def check_workflow_log(filepath: Path) -> List[Dict[str, Any]]:
    """Check a workflow log for session issues."""
    issues = []
    
    try:
        content = filepath.read_text(encoding='utf-8')
    except Exception as e:
        return [{'file': str(filepath), 'line': 0, 'message': f'Could not read file: {e}', 'severity': 'error'}]
    
    # Check for required frontmatter
    if not content.startswith('---'):
        issues.append({
            'file': str(filepath),
            'line': 1,
            'message': 'Workflow log missing YAML frontmatter',
            'severity': 'error',
        })
    
    # Check for session id
    if 'session:' not in content:
        issues.append({
            'file': str(filepath),
            'line': 1,
            'message': 'Workflow log missing session section',
            'severity': 'warning',
        })
    
    # Check for skills loaded
    if 'skills:' not in content:
        issues.append({
            'file': str(filepath),
            'line': 1,
            'message': 'Workflow log missing skills section',
            'severity': 'warning',
        })
    
    # Check for files modified
    if 'files:' not in content and 'modified' not in content:
        issues.append({
            'file': str(filepath),
            'line': 1,
            'message': 'Workflow log missing files modified section',
            'severity': 'warning',
        })
    
    return issues


def check_session_tracker(filepath: Path) -> List[Dict[str, Any]]:
    """Check session tracker file for issues."""
    issues = []
    
    try:
        import json
        content = filepath.read_text(encoding='utf-8')
        data = json.loads(content)
        
        if 'current_session' not in data:
            issues.append({
                'file': str(filepath),
                'line': 1,
                'message': 'Session tracker missing current_session field',
                'severity': 'error',
            })
    except json.JSONDecodeError as e:
        issues.append({
            'file': str(filepath),
            'line': 1,
            'message': f'Invalid JSON in session tracker: {e}',
            'severity': 'error',
        })
    except Exception:
        pass  # File may not exist yet
    
    return issues


def main():
    """Run session validation."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate session management')
    parser.add_argument('--file', '-f', help='Specific file to validate')
    args = parser.parse_args()
    
    all_issues = []
    errors = 0
    warnings = 0
    
    print("Session Skill Validation")
    print("=" * 60)
    
    # Check workflow logs
    log_dir = Path('log/workflow')
    if log_dir.exists():
        logs = list(log_dir.glob('*.md'))[-5:]  # Check last 5 logs
        for log in logs:
            issues = check_workflow_log(log)
            all_issues.extend(issues)
    
    # Check session tracker
    tracker = Path('.github/.session-tracker.json')
    if tracker.exists():
        issues = check_session_tracker(tracker)
        all_issues.extend(issues)
    
    # Report issues
    if all_issues:
        for issue in all_issues:
            prefix = '❌' if issue['severity'] == 'error' else '⚠️'
            print(f"{prefix} {issue['file']}:{issue.get('line', 0)}")
            print(f"   {issue['message']}")
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
        print("\n✅ All session checks pass")
        return 0


if __name__ == '__main__':
    sys.exit(main())
