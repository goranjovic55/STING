"""
Storage Module for Honeypot Intelligence
Manages SQLite database and JSONL archiving.
"""

import json
import sqlite3
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Iterator
from contextlib import contextmanager
from dataclasses import asdict


class Storage:
    """Manages persistent storage for honeypot data."""
    
    SCHEMA = """
    -- Events table: raw honeypot events
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        eventid TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        src_ip TEXT,
        dst_ip TEXT,
        dst_port INTEGER,
        session TEXT,
        username TEXT,
        password TEXT,
        input TEXT,
        url TEXT,
        filename TEXT,
        shasum TEXT,
        sensor TEXT,
        message TEXT,
        raw_json TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Sessions table: session tracking
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE NOT NULL,
        src_ip TEXT,
        start_time TEXT,
        end_time TEXT,
        duration_seconds REAL,
        failed_logins INTEGER DEFAULT 0,
        successful_login INTEGER DEFAULT 0,
        username TEXT,
        commands_count INTEGER DEFAULT 0,
        files_downloaded INTEGER DEFAULT 0,
        files_uploaded INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Attackers table: IP-based tracking
    CREATE TABLE IF NOT EXISTS attackers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        session_count INTEGER DEFAULT 0,
        failed_logins INTEGER DEFAULT 0,
        successful_logins INTEGER DEFAULT 0,
        commands_executed INTEGER DEFAULT 0,
        files_downloaded INTEGER DEFAULT 0,
        country TEXT,
        asn TEXT,
        reputation_score REAL DEFAULT 0.0,
        tags TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Alerts table: security alerts
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        src_ip TEXT,
        session TEXT,
        description TEXT,
        details TEXT,  -- JSON
        indicators TEXT,  -- JSON array
        acknowledged INTEGER DEFAULT 0,
        notified INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Daily summaries table
    CREATE TABLE IF NOT EXISTS daily_summaries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT UNIQUE NOT NULL,
        total_events INTEGER DEFAULT 0,
        unique_attackers INTEGER DEFAULT 0,
        new_attackers INTEGER DEFAULT 0,
        sessions INTEGER DEFAULT 0,
        failed_logins INTEGER DEFAULT 0,
        successful_logins INTEGER DEFAULT 0,
        commands_executed INTEGER DEFAULT 0,
        files_downloaded INTEGER DEFAULT 0,
        alerts_critical INTEGER DEFAULT 0,
        alerts_high INTEGER DEFAULT 0,
        alerts_medium INTEGER DEFAULT 0,
        alerts_low INTEGER DEFAULT 0,
        top_attackers TEXT,  -- JSON
        top_commands TEXT,  -- JSON
        summary_text TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Indexes for performance
    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
    CREATE INDEX IF NOT EXISTS idx_events_session ON events(session);
    CREATE INDEX IF NOT EXISTS idx_events_eventid ON events(eventid);
    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
    CREATE INDEX IF NOT EXISTS idx_alerts_notified ON alerts(notified);
    CREATE INDEX IF NOT EXISTS idx_attackers_ip ON attackers(ip_address);
    CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id);
    """
    
    def __init__(self, db_path: str, archive_dir: str, logger: Optional[logging.Logger] = None):
        self.db_path = db_path
        self.archive_dir = Path(archive_dir)
        self.logger = logger or logging.getLogger(__name__)
        
        # Ensure directories exist
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_db()
        
        # Stats
        self.events_stored = 0
        self.alerts_stored = 0
    
    def _init_db(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.executescript(self.SCHEMA)
            conn.commit()
        self.logger.info(f"Database initialized: {self.db_path}")
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def store_event(self, event) -> int:
        """Store a parsed event. Returns the inserted row ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO events 
                (eventid, timestamp, src_ip, dst_ip, dst_port, session, 
                 username, password, input, url, filename, shasum, sensor, message, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.eventid,
                    event.timestamp.isoformat(),
                    event.src_ip,
                    event.dst_ip,
                    event.dst_port,
                    event.session,
                    event.username,
                    event.password,
                    event.input,
                    event.url,
                    event.filename,
                    event.shasum,
                    event.sensor,
                    event.message,
                    json.dumps(event.raw)
                )
            )
            conn.commit()
            self.events_stored += 1
            return cursor.lastrowid
    
    def store_events_batch(self, events: List[Any]) -> int:
        """Store multiple events efficiently. Returns count stored."""
        if not events:
            return 0
        
        with self._get_connection() as conn:
            data = [
                (
                    e.eventid, e.timestamp.isoformat(), e.src_ip, e.dst_ip,
                    e.dst_port, e.session, e.username, e.password, e.input,
                    e.url, e.filename, e.shasum, e.sensor, e.message,
                    json.dumps(e.raw)
                )
                for e in events
            ]
            
            conn.executemany(
                """
                INSERT INTO events 
                (eventid, timestamp, src_ip, dst_ip, dst_port, session, 
                 username, password, input, url, filename, shasum, sensor, message, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                data
            )
            conn.commit()
            self.events_stored += len(events)
            return len(events)
    
    def _serialize_json(self, obj):
        """Serialize object to JSON, handling datetime."""
        def datetime_handler(o):
            if isinstance(o, datetime):
                return o.isoformat()
            raise TypeError(f"Object of type {type(o)} is not JSON serializable")
        return json.dumps(obj, default=datetime_handler)
    
    def store_alert(self, alert) -> int:
        """Store an alert. Returns the inserted row ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO alerts 
                (alert_type, severity, timestamp, src_ip, session, description, details, indicators)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_type.value,
                    alert.severity.value,
                    alert.timestamp.isoformat(),
                    alert.src_ip,
                    alert.session,
                    alert.description,
                    self._serialize_json(alert.details),
                    self._serialize_json(alert.indicators)
                )
            )
            conn.commit()
            self.alerts_stored += 1
            return cursor.lastrowid
    
    def store_session_summary(self, session_id: str, summary: Dict[str, Any]):
        """Store or update session summary."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO sessions 
                (session_id, src_ip, start_time, end_time, duration_seconds,
                 failed_logins, successful_login, username, commands_count,
                 files_downloaded, files_uploaded)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    summary.get('src_ip'),
                    summary.get('start_time'),
                    summary.get('last_activity'),
                    summary.get('duration_seconds'),
                    summary.get('failed_logins', 0),
                    1 if summary.get('successful_login') else 0,
                    summary.get('username'),
                    summary.get('commands_executed', 0),
                    summary.get('files_downloaded', 0),
                    summary.get('files_uploaded', 0)
                )
            )
            conn.commit()
    
    def update_attacker_stats(self, src_ip: str, event_type: str, timestamp: datetime):
        """Update attacker statistics."""
        if not src_ip:
            return
        
        with self._get_connection() as conn:
            # Try to update existing
            if event_type == 'cowrie.login.failed':
                field = 'failed_logins'
            elif event_type == 'cowrie.login.success':
                field = 'successful_logins'
            elif event_type == 'cowrie.command.input':
                field = 'commands_executed'
            elif event_type == 'cowrie.session.file_download':
                field = 'files_downloaded'
            else:
                field = None
            
            if field:
                conn.execute(
                    f"""
                    UPDATE attackers 
                    SET {field} = {field} + 1, last_seen = ?, updated_at = ?
                    WHERE ip_address = ?
                    """,
                    (timestamp.isoformat(), datetime.utcnow().isoformat(), src_ip)
                )
            else:
                conn.execute(
                    """
                    UPDATE attackers 
                    SET last_seen = ?, updated_at = ?
                    WHERE ip_address = ?
                    """,
                    (timestamp.isoformat(), datetime.utcnow().isoformat(), src_ip)
                )
            
            # If no rows updated, insert new
            if conn.total_changes == 0:
                conn.execute(
                    """
                    INSERT INTO attackers 
                    (ip_address, first_seen, last_seen, updated_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (src_ip, timestamp.isoformat(), timestamp.isoformat(), datetime.utcnow().isoformat())
                )
            
            conn.commit()
    
    def get_unnotified_alerts(self, severity_levels: List[str] = None) -> List[Dict]:
        """Get alerts that haven't been notified yet."""
        with self._get_connection() as conn:
            if severity_levels:
                placeholders = ','.join('?' * len(severity_levels))
                query = f"""
                    SELECT * FROM alerts 
                    WHERE notified = 0 AND severity IN ({placeholders})
                    ORDER BY timestamp DESC
                """
                rows = conn.execute(query, severity_levels).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM alerts 
                    WHERE notified = 0
                    ORDER BY timestamp DESC
                    """
                ).fetchall()
            
            return [dict(row) for row in rows]
    
    def mark_alerts_notified(self, alert_ids: List[int]):
        """Mark alerts as notified."""
        if not alert_ids:
            return
        
        with self._get_connection() as conn:
            placeholders = ','.join('?' * len(alert_ids))
            conn.execute(
                f"UPDATE alerts SET notified = 1 WHERE id IN ({placeholders})",
                alert_ids
            )
            conn.commit()
    
    def archive_events(self, date: Optional[datetime] = None) -> str:
        """Archive events to JSONL file. Returns archive filepath."""
        date = date or datetime.utcnow()
        archive_file = self.archive_dir / f"events_{date.strftime('%Y%m%d')}.jsonl"
        
        with self._get_connection() as conn:
            # Get events for the date
            start = date.replace(hour=0, minute=0, second=0, microsecond=0)
            end = start + timedelta(days=1)
            
            rows = conn.execute(
                """
                SELECT raw_json FROM events 
                WHERE timestamp >= ? AND timestamp < ?
                ORDER BY timestamp
                """,
                (start.isoformat(), end.isoformat())
            ).fetchall()
        
        # Write to JSONL
        with open(archive_file, 'w') as f:
            for row in rows:
                f.write(row['raw_json'] + '\n')
        
        self.logger.info(f"Archived {len(rows)} events to {archive_file}")
        return str(archive_file)
    
    def get_daily_stats(self, date: Optional[datetime] = None) -> Dict[str, Any]:
        """Get statistics for a specific day."""
        date = date or datetime.utcnow()
        start = date.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
        
        with self._get_connection() as conn:
            # Event counts
            event_stats = conn.execute(
                """
                SELECT 
                    COUNT(*) as total,
                    COUNT(DISTINCT src_ip) as unique_ips,
                    COUNT(DISTINCT session) as sessions,
                    SUM(CASE WHEN eventid = 'cowrie.login.failed' THEN 1 ELSE 0 END) as failed_logins,
                    SUM(CASE WHEN eventid = 'cowrie.login.success' THEN 1 ELSE 0 END) as success_logins,
                    SUM(CASE WHEN eventid = 'cowrie.command.input' THEN 1 ELSE 0 END) as commands,
                    SUM(CASE WHEN eventid = 'cowrie.session.file_download' THEN 1 ELSE 0 END) as downloads
                FROM events
                WHERE timestamp >= ? AND timestamp < ?
                """,
                (start.isoformat(), end.isoformat())
            ).fetchone()
            
            # Alert counts
            alert_stats = conn.execute(
                """
                SELECT 
                    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low
                FROM alerts
                WHERE timestamp >= ? AND timestamp < ?
                """,
                (start.isoformat(), end.isoformat())
            ).fetchone()
            
            # Top attackers
            top_attackers = conn.execute(
                """
                SELECT src_ip, COUNT(*) as count
                FROM events
                WHERE timestamp >= ? AND timestamp < ? AND src_ip IS NOT NULL
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT 5
                """,
                (start.isoformat(), end.isoformat())
            ).fetchall()
            
            # Top commands
            top_commands = conn.execute(
                """
                SELECT input, COUNT(*) as count
                FROM events
                WHERE timestamp >= ? AND timestamp < ? 
                AND eventid = 'cowrie.command.input' AND input IS NOT NULL
                GROUP BY input
                ORDER BY count DESC
                LIMIT 5
                """,
                (start.isoformat(), end.isoformat())
            ).fetchall()
        
        return {
            'date': start.strftime('%Y-%m-%d'),
            'events': dict(event_stats) if event_stats else {},
            'alerts': dict(alert_stats) if alert_stats else {},
            'top_attackers': [dict(row) for row in top_attackers],
            'top_commands': [dict(row) for row in top_commands]
        }
    
    def store_daily_summary(self, stats: Dict[str, Any]):
        """Store daily summary."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO daily_summaries
                (date, total_events, unique_attackers, sessions, failed_logins,
                 successful_logins, commands_executed, files_downloaded,
                 alerts_critical, alerts_high, alerts_medium, alerts_low,
                 top_attackers, top_commands, summary_text)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    stats['date'],
                    stats['events'].get('total', 0),
                    stats['events'].get('unique_ips', 0),
                    stats['events'].get('sessions', 0),
                    stats['events'].get('failed_logins', 0),
                    stats['events'].get('success_logins', 0),
                    stats['events'].get('commands', 0),
                    stats['events'].get('downloads', 0),
                    stats['alerts'].get('critical', 0),
                    stats['alerts'].get('high', 0),
                    stats['alerts'].get('medium', 0),
                    stats['alerts'].get('low', 0),
                    json.dumps(stats.get('top_attackers', [])),
                    json.dumps(stats.get('top_commands', [])),
                    stats.get('summary_text', '')
                )
            )
            conn.commit()
    
    def query_events(self, 
                     start_time: Optional[datetime] = None,
                     end_time: Optional[datetime] = None,
                     src_ip: Optional[str] = None,
                     eventid: Optional[str] = None,
                     limit: int = 100) -> List[Dict]:
        """Query events with filters."""
        with self._get_connection() as conn:
            query = "SELECT * FROM events WHERE 1=1"
            params = []
            
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time.isoformat())
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time.isoformat())
            if src_ip:
                query += " AND src_ip = ?"
                params.append(src_ip)
            if eventid:
                query += " AND eventid = ?"
                params.append(eventid)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]
    
    def get_stats(self) -> Dict[str, int]:
        """Return storage statistics."""
        with self._get_connection() as conn:
            event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            session_count = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            attacker_count = conn.execute("SELECT COUNT(*) FROM attackers").fetchone()[0]
        
        return {
            'events_in_db': event_count,
            'alerts_in_db': alert_count,
            'sessions_in_db': session_count,
            'attackers_in_db': attacker_count,
            'events_stored_this_run': self.events_stored,
            'alerts_stored_this_run': self.alerts_stored
        }


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    storage = Storage(
        db_path='/tmp/test_honeypot.db',
        archive_dir='/tmp/test_archive'
    )
    print("Storage module loaded successfully")
