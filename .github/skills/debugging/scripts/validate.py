#!/usr/bin/env python3
"""
Debugging Skill Validation Script

Validates that debugging patterns are correctly applied.
"""

import sys
from pathlib import Path


def check_workflow_log(log_path: Path) -> list:
    """Check workflow log for required debugging elements."""
    issues = []
    
    if not log_path.exists():
        return [{'file': str(log_path), 'message': 'Workflow log not found', 'severity': 'warning'}]
    
    content = log_path.read_text()
    
    # Check for root_causes in debugging sessions
    if 'debug' in log_path.name.lower() or 'fix' in log_path.name.lower():
        if 'root_causes:' not in content and 'root_cause' not in content.lower():
            issues.append({
                'file': str(log_path),
                'message': 'Debugging session missing root_causes documentation',
                'severity': 'warning'
            })
    
    return issues


def main():
    """Run validation."""
    print("Debugging Skill Validation")
    print("=" * 60)
    
    workflow_dir = Path('log/workflow')
    issues = []
    
    if workflow_dir.exists():
        for log_file in sorted(workflow_dir.glob('*.md'))[-5:]:  # Check last 5
            issues.extend(check_workflow_log(log_file))
    
    if issues:
        for issue in issues:
            print(f"⚠️ {issue['file']}: {issue['message']}")
    else:
        print("✅ All debugging patterns validated")
    
    return 0 if not any(i['severity'] == 'error' for i in issues) else 1


if __name__ == '__main__':
    sys.exit(main())
