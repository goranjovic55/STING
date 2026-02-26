#!/usr/bin/env python3
"""
AKIS Session Tracker

Tracks session numbers and determines when maintenance workflows should run.
Used in the LEARN/COMPLETE phase to increment session count and check if
maintenance is due.

Usage:
    # Increment session count and get current number
    python .github/scripts/session_tracker.py increment
    
    # Get current session number without incrementing
    python .github/scripts/session_tracker.py current
    
    # Check if maintenance is due (returns 0 if due, 1 if not)
    python .github/scripts/session_tracker.py check-maintenance
    
    # Reset counter (use with caution)
    python .github/scripts/session_tracker.py reset
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any


TRACKER_FILE = Path('.github/.session-tracker.json')
MAINTENANCE_INTERVAL = 10  # Run maintenance every N sessions


def load_tracker() -> Dict[str, Any]:
    """Load session tracker data."""
    if not TRACKER_FILE.exists():
        return {
            'current_session': 0,
            'last_maintenance_session': 0,
            'last_updated': None,
            'sessions': []
        }
    
    try:
        with open(TRACKER_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {
            'current_session': 0,
            'last_maintenance_session': 0,
            'last_updated': None,
            'sessions': []
        }


def save_tracker(data: Dict[str, Any]) -> None:
    """Save session tracker data."""
    TRACKER_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(TRACKER_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def increment_session() -> int:
    """Increment session counter and return new session number."""
    tracker = load_tracker()
    tracker['current_session'] += 1
    tracker['last_updated'] = datetime.now().isoformat()
    
    # Add session record
    session_record = {
        'session_number': tracker['current_session'],
        'timestamp': tracker['last_updated']
    }
    tracker['sessions'].append(session_record)
    
    # Keep only last 100 session records to prevent unbounded growth
    if len(tracker['sessions']) > 100:
        tracker['sessions'] = tracker['sessions'][-100:]
    
    save_tracker(tracker)
    
    print(f"Session {tracker['current_session']}")
    return tracker['current_session']


def get_current_session() -> int:
    """Get current session number without incrementing."""
    tracker = load_tracker()
    current = tracker.get('current_session', 0)
    print(f"Session {current}")
    return current


def check_maintenance() -> bool:
    """Check if maintenance workflow should be triggered."""
    tracker = load_tracker()
    current = tracker.get('current_session', 0)
    last_maintenance = tracker.get('last_maintenance_session', 0)
    
    sessions_since_maintenance = current - last_maintenance
    is_due = sessions_since_maintenance >= MAINTENANCE_INTERVAL
    
    if is_due:
        print(f"Maintenance due: {sessions_since_maintenance} sessions since last maintenance")
        print(f"Current session: {current}")
        print(f"Last maintenance: {last_maintenance}")
        return True
    else:
        print(f"Maintenance not due: {sessions_since_maintenance}/{MAINTENANCE_INTERVAL} sessions")
        return False


def mark_maintenance_done() -> None:
    """Mark that maintenance workflow was completed."""
    tracker = load_tracker()
    tracker['last_maintenance_session'] = tracker['current_session']
    tracker['last_updated'] = datetime.now().isoformat()
    save_tracker(tracker)
    print(f"Maintenance marked complete at session {tracker['current_session']}")


def reset_tracker() -> None:
    """Reset session counter (use with caution)."""
    tracker = {
        'current_session': 0,
        'last_maintenance_session': 0,
        'last_updated': datetime.now().isoformat(),
        'sessions': []
    }
    save_tracker(tracker)
    print("Session tracker reset to 0")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: session_tracker.py [increment|current|check-maintenance|mark-maintenance-done|reset]")
        return 1
    
    command = sys.argv[1]
    
    if command == 'increment':
        increment_session()
        return 0
    elif command == 'current':
        get_current_session()
        return 0
    elif command == 'check-maintenance':
        is_due = check_maintenance()
        return 0 if is_due else 1
    elif command == 'mark-maintenance-done':
        mark_maintenance_done()
        return 0
    elif command == 'reset':
        reset_tracker()
        return 0
    else:
        print(f"Unknown command: {command}")
        print("Usage: session_tracker.py [increment|current|check-maintenance|mark-maintenance-done|reset]")
        return 1


if __name__ == '__main__':
    exit(main())
