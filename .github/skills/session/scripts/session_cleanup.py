#!/usr/bin/env python3
"""
AKIS Session Cleanup

Cleans up temporary files and artifacts at end of session.
Runs during END phase to maintain workspace hygiene.

Usage:
    python .github/scripts/session_cleanup.py [--dry-run]
    
Output: JSON summary of cleanup actions
"""

import os
import json
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set


# Cleanup targets
CLEANUP_PATTERNS = {
    'backup_files': {
        'patterns': ['*_backup_*.json', '*.bak', '*.orig'],
        'location': '.',
        'max_age_days': 7,
        'keep_count': 3  # Keep N most recent
    },
    'python_cache': {
        'patterns': ['__pycache__'],
        'location': '.',
        'type': 'directory',
        'exclude': ['node_modules', '.git', 'venv', '.venv']
    },
    'editor_temp': {
        'patterns': ['*.swp', '*.swo', '*~', '.DS_Store'],
        'location': '.',
        'exclude': ['node_modules', '.git']
    },
    'test_artifacts': {
        'patterns': ['.pytest_cache', '.coverage', 'htmlcov', '*.pyc'],
        'location': '.',
        'exclude': ['node_modules', '.git']
    }
}

# Protected paths (never clean)
PROTECTED = {
    '.git',
    'node_modules',
    '.venv',
    'venv',
    'volumes',
    '.github/scripts',  # Don't delete ourselves
}


def is_protected(path: Path) -> bool:
    """Check if path is protected."""
    path_str = str(path)
    for protected in PROTECTED:
        if protected in path_str:
            return True
    return False


def find_files(pattern: str, location: str = '.', exclude: List[str] = None) -> List[Path]:
    """Find files matching pattern."""
    exclude = exclude or []
    root = Path(location)
    results = []
    
    for match in root.glob(f'**/{pattern}'):
        if is_protected(match):
            continue
        skip = False
        for exc in exclude:
            if exc in str(match):
                skip = True
                break
        if not skip:
            results.append(match)
    
    return results


def get_file_age_days(path: Path) -> float:
    """Get file age in days."""
    try:
        mtime = path.stat().st_mtime
        age = datetime.now().timestamp() - mtime
        return age / (24 * 3600)
    except OSError:
        return 0


def cleanup_backups(dry_run: bool = False) -> Dict[str, Any]:
    """Clean old backup files, keeping most recent."""
    config = CLEANUP_PATTERNS['backup_files']
    results = {
        'type': 'backup_files',
        'found': [],
        'deleted': [],
        'kept': []
    }
    
    for pattern in config['patterns']:
        files = find_files(pattern, config['location'])
        
        # Group by base name pattern
        groups: Dict[str, List[Path]] = {}
        for f in files:
            base = f.name.split('_backup_')[0] if '_backup_' in f.name else f.stem
            groups.setdefault(base, []).append(f)
        
        # For each group, keep N most recent
        for base, group_files in groups.items():
            sorted_files = sorted(group_files, key=lambda p: p.stat().st_mtime, reverse=True)
            
            for i, f in enumerate(sorted_files):
                age = get_file_age_days(f)
                results['found'].append(str(f))
                
                # Keep if: within keep_count AND not too old
                if i < config['keep_count'] and age < config['max_age_days']:
                    results['kept'].append(str(f))
                else:
                    if not dry_run:
                        try:
                            f.unlink()
                            results['deleted'].append(str(f))
                        except OSError:
                            pass
                    else:
                        results['deleted'].append(f'{f} (would delete)')
    
    return results


def cleanup_cache_dirs(dry_run: bool = False) -> Dict[str, Any]:
    """Clean Python cache directories."""
    config = CLEANUP_PATTERNS['python_cache']
    results = {
        'type': 'python_cache',
        'found': [],
        'deleted': []
    }
    
    for pattern in config['patterns']:
        dirs = find_files(pattern, config['location'], config.get('exclude', []))
        
        for d in dirs:
            if d.is_dir():
                results['found'].append(str(d))
                if not dry_run:
                    try:
                        import shutil
                        shutil.rmtree(d)
                        results['deleted'].append(str(d))
                    except OSError:
                        pass
                else:
                    results['deleted'].append(f'{d} (would delete)')
    
    return results


def cleanup_temp_files(dry_run: bool = False) -> Dict[str, Any]:
    """Clean editor temporary files."""
    config = CLEANUP_PATTERNS['editor_temp']
    results = {
        'type': 'editor_temp',
        'found': [],
        'deleted': []
    }
    
    for pattern in config['patterns']:
        files = find_files(pattern, config['location'], config.get('exclude', []))
        
        for f in files:
            if f.is_file():
                results['found'].append(str(f))
                if not dry_run:
                    try:
                        f.unlink()
                        results['deleted'].append(str(f))
                    except OSError:
                        pass
                else:
                    results['deleted'].append(f'{f} (would delete)')
    
    return results


def cleanup_test_artifacts(dry_run: bool = False) -> Dict[str, Any]:
    """Clean test cache and coverage artifacts."""
    config = CLEANUP_PATTERNS['test_artifacts']
    results = {
        'type': 'test_artifacts',
        'found': [],
        'deleted': []
    }
    
    for pattern in config['patterns']:
        items = find_files(pattern, config['location'], config.get('exclude', []))
        
        for item in items:
            results['found'].append(str(item))
            if not dry_run:
                try:
                    if item.is_dir():
                        import shutil
                        shutil.rmtree(item)
                    else:
                        item.unlink()
                    results['deleted'].append(str(item))
                except OSError:
                    pass
            else:
                results['deleted'].append(f'{item} (would delete)')
    
    return results


def run_git_cleanup(dry_run: bool = False) -> Dict[str, Any]:
    """Run git cleanup commands."""
    results = {
        'type': 'git_cleanup',
        'commands': []
    }
    
    if dry_run:
        results['commands'].append('git gc --auto (would run)')
        return results
    
    try:
        # Light garbage collection
        subprocess.run(
            ['git', 'gc', '--auto'],
            capture_output=True,
            timeout=30
        )
        results['commands'].append('git gc --auto')
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass
    
    return results


def main():
    """Run session cleanup."""
    import sys
    dry_run = '--dry-run' in sys.argv
    
    mode = "DRY RUN" if dry_run else "CLEANUP"
    print(f"🧹 AKIS Session Cleanup [{mode}]")
    print("=" * 40)
    
    results = {
        'timestamp': datetime.now().isoformat(),
        'dry_run': dry_run,
        'cleanups': []
    }
    
    # Run all cleanup tasks
    cleanups = [
        ('Backup files', cleanup_backups),
        ('Python cache', cleanup_cache_dirs),
        ('Editor temp files', cleanup_temp_files),
        ('Test artifacts', cleanup_test_artifacts),
        ('Git maintenance', run_git_cleanup),
    ]
    
    total_deleted = 0
    
    for name, func in cleanups:
        print(f"\n📂 {name}...")
        result = func(dry_run)
        results['cleanups'].append(result)
        
        deleted_count = len(result.get('deleted', result.get('commands', [])))
        total_deleted += deleted_count
        
        if deleted_count > 0:
            print(f"   ✓ {deleted_count} items cleaned")
        else:
            print(f"   ○ Nothing to clean")
    
    # Summary
    print(f"\n{'=' * 40}")
    print(f"🧹 Total: {total_deleted} items {'would be ' if dry_run else ''}cleaned")
    
    # Output JSON for agent consumption
    if '--json' in sys.argv:
        print("\n" + json.dumps(results, indent=2))
    
    return 0


if __name__ == '__main__':
    exit(main())
