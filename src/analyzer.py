"""
Pattern Analyzer for Honeypot Events
Detects attack patterns and assigns severity levels.
"""

import re
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class Severity(Enum):
    """Alert severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertType(Enum):
    """Types of alerts we can generate."""
    BRUTE_FORCE = "BRUTE_FORCE"
    SUCCESS_LOGIN = "SUCCESS_LOGIN"
    MALWARE_DOWNLOAD = "MALWARE_DOWNLOAD"
    COMMAND_SEQUENCE = "COMMAND_SEQUENCE"
    PERSISTENCE_ATTEMPT = "PERSISTENCE_ATTEMPT"
    RECONNAISSANCE = "RECONNAISSANCE"
    SUSPICIOUS_PATTERN = "SUSPICIOUS_PATTERN"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"


@dataclass
class Alert:
    """Represents a security alert."""
    alert_type: AlertType
    severity: Severity
    timestamp: datetime
    src_ip: Optional[str]
    session: Optional[str]
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            'alert_type': self.alert_type.value,
            'severity': self.severity.value,
            'timestamp': self.timestamp.isoformat(),
            'src_ip': self.src_ip,
            'session': self.session,
            'description': self.description,
            'details': self.details,
            'indicators': self.indicators
        }


@dataclass
class SessionState:
    """Tracks state for a single attack session."""
    session_id: str
    src_ip: Optional[str]
    start_time: datetime
    commands: List[Tuple[datetime, str]] = field(default_factory=list)
    failed_logins: List[Tuple[datetime, str, str]] = field(default_factory=list)  # (time, user, pass)
    successful_login: Optional[Tuple[datetime, str, str]] = None
    files_downloaded: List[Dict[str, Any]] = field(default_factory=list)
    files_uploaded: List[Dict[str, Any]] = field(default_factory=list)
    last_activity: datetime = field(default_factory=datetime.utcnow)
    
    def add_command(self, timestamp: datetime, command: str):
        """Add a command to session history."""
        self.commands.append((timestamp, command))
        self.last_activity = timestamp
    
    def add_failed_login(self, timestamp: datetime, username: str, password: str):
        """Record a failed login attempt."""
        self.failed_logins.append((timestamp, username, password))
        self.last_activity = timestamp
    
    def add_successful_login(self, timestamp: datetime, username: str, password: str):
        """Record successful login."""
        self.successful_login = (timestamp, username, password)
        self.last_activity = timestamp


class PatternAnalyzer:
    """Analyzes honeypot events for attack patterns."""
    
    # Configuration for pattern detection
    BRUTE_FORCE_THRESHOLD = 5  # Failed logins
    BRUTE_FORCE_WINDOW = 60    # Seconds
    
    # Known suspicious commands and patterns
    MALWARE_DOWNLOAD_PATTERNS = [
        r'wget\s+.*\s+-O\s+',
        r'wget\s+.*\s+-o\s+',
        r'curl\s+.*\s+-o\s+',
        r'curl\s+.*\s+--output\s+',
        r'wget\s+http[s]?://',
        r'curl\s+.*http[s]?://',
        r'fetch\s+',
        r'ftp\s+-get\s+',
        r'(?:wget|curl|fetch)\s+.*\.(?:sh|py|pl|elf|bin|so|dll|exe)',
    ]
    
    PERSISTENCE_COMMANDS = [
        r'ssh-keygen',
        r'ssh-copy-id',
        r'authorized_keys',
        r'crontab\s+-e',
        r'cron\s+',
        r'crontab\s+',
        r'/etc/cron',
        r'/var/spool/cron',
        r'\.bashrc',
        r'\.bash_profile',
        r'\.profile',
        r'/etc/profile',
        r'/etc/rc\.local',
        r'systemctl\s+enable',
        r'update-rc\.d',
        r'chkconfig',
        r'echo\s+.*>>\s+/\.ssh/',
        r'echo\s+.*>>\s+.*authorized_keys',
    ]
    
    RECON_COMMANDS = [
        r'uname\s+-a',
        r'uname\s+-m',
        r'cat\s+/etc/passwd',
        r'cat\s+/etc/shadow',
        r'cat\s+/etc/group',
        r'cat\s+/proc/cpuinfo',
        r'cat\s+/proc/meminfo',
        r'cat\s+/proc/version',
        r'cat\s+/etc/os-release',
        r'cat\s+/etc/issue',
        r'ifconfig',
        r'ip\s+addr',
        r'ip\s+link',
        r'netstat',
        r'ss\s+-',
        r'route\s+-n',
        r'arp\s+-a',
        r'ps\s+aux',
        r'ps\s+ef',
        r'top\s+-',
        r'whoami',
        r'id',
        r'groups',
        r'last\s+',
        r'lastlog',
        r'w\s*$',
        r'who\s*$',
        r'finger',
        r'ls\s+-la\s+/',
        r'ls\s+-la\s+/etc',
        r'ls\s+-la\s+/home',
        r'find\s+/\s+',
        r'df\s+-h',
        r'du\s+-sh',
        r'free\s+-',
        r'uptime',
        r'hostname\s+-',
        r'dmidecode',
        r'lspci',
        r'lsusb',
        r'lscpu',
        r'lsmod',
    ]
    
    SUSPICIOUS_PATTERNS = [
        r'(?:rm\s+-rf\s+/|rm\s+-rf\s+\*|mkfs\.ext|dd\s+if=)',
        r'(?:curl\s+.*\|\s*sh|wget\s+.*\|\s*sh|curl\s+.*\|\s*bash)',
        r'(?:chmod\s+\+x\s+|chmod\s+777\s+|chmod\s+755\s+)',
        r'(?:base64\s+-d|base64\s+--decode)',
        r'(?:python\s+-c|perl\s+-e|ruby\s+-e|php\s+-r)',
        r'(?:nc\s+-l|ncat\s+-l|netcat\s+-l)',
        r'(?:nc\s+.*\s+-e|ncat\s+.*\s+-e)',
        r'/dev/tcp/',
        r'/dev/udp/',
        r'(?:mkfifo|fifo)',
    ]
    
    CRYPTOMINING_PATTERNS = [
        r'(?:xmrig|minerd|cpuminer|stratum|pool\.minexmr|pool\.supportxmr)',
        r'(?:monero|bitcoin|ethereum|mining|miner)',
        r'hashrate',
        r'cryptonight',
    ]
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        
        # Session tracking
        self.sessions: Dict[str, SessionState] = {}
        
        # IP tracking for brute force detection
        self.ip_login_attempts: Dict[str, List[datetime]] = defaultdict(list)
        
        # Compiled regex patterns
        self._compile_patterns()
        
        # Stats
        self.alerts_generated = 0
        self.sessions_tracked = 0
    
    def _compile_patterns(self):
        """Compile regex patterns for performance."""
        self.malware_regex = [re.compile(p, re.IGNORECASE) for p in self.MALWARE_DOWNLOAD_PATTERNS]
        self.persistence_regex = [re.compile(p, re.IGNORECASE) for p in self.PERSISTENCE_COMMANDS]
        self.recon_regex = [re.compile(p, re.IGNORECASE) for p in self.RECON_COMMANDS]
        self.suspicious_regex = [re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_PATTERNS]
        self.mining_regex = [re.compile(p, re.IGNORECASE) for p in self.CRYPTOMINING_PATTERNS]
    
    def analyze_event(self, event) -> List[Alert]:
        """
        Analyze a single event and generate alerts.
        
        Args:
            event: CowrieEvent object
        
        Returns:
            List of Alert objects
        """
        alerts = []
        
        # Get or create session state
        session = self._get_session(event)
        
        # Route to specific analyzers based on event type
        eventid = event.eventid
        
        if eventid == 'cowrie.login.failed':
            alerts.extend(self._analyze_failed_login(event, session))
        
        elif eventid == 'cowrie.login.success':
            alerts.extend(self._analyze_successful_login(event, session))
        
        elif eventid == 'cowrie.command.input':
            alerts.extend(self._analyze_command(event, session))
        
        elif eventid == 'cowrie.session.file_download':
            alerts.extend(self._analyze_file_download(event, session))
        
        elif eventid == 'cowrie.session.file_upload':
            alerts.extend(self._analyze_file_upload(event, session))
        
        # Check for session-level patterns
        alerts.extend(self._check_session_patterns(session))
        
        return alerts
    
    def _get_session(self, event) -> SessionState:
        """Get or create session state."""
        session_id = event.session or 'unknown'
        
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState(
                session_id=session_id,
                src_ip=event.src_ip,
                start_time=event.timestamp
            )
            self.sessions_tracked += 1
        
        return self.sessions[session_id]
    
    def _analyze_failed_login(self, event, session: SessionState) -> List[Alert]:
        """Analyze failed login attempts for brute force."""
        alerts = []
        src_ip = event.src_ip
        timestamp = event.timestamp
        username = event.username or 'unknown'
        password = event.password or 'unknown'
        
        # Track in session
        session.add_failed_login(timestamp, username, password)
        
        # Track by IP for brute force detection
        if src_ip:
            self.ip_login_attempts[src_ip].append(timestamp)
            
            # Clean old attempts outside window
            cutoff = timestamp - timedelta(seconds=self.BRUTE_FORCE_WINDOW)
            self.ip_login_attempts[src_ip] = [
                t for t in self.ip_login_attempts[src_ip] if t > cutoff
            ]
            
            # Check threshold
            if len(self.ip_login_attempts[src_ip]) >= self.BRUTE_FORCE_THRESHOLD:
                alerts.append(Alert(
                    alert_type=AlertType.BRUTE_FORCE,
                    severity=Severity.HIGH,
                    timestamp=timestamp,
                    src_ip=src_ip,
                    session=event.session,
                    description=f"Brute force attack detected: {len(self.ip_login_attempts[src_ip])} failed logins in {self.BRUTE_FORCE_WINDOW}s",
                    details={
                        'attempt_count': len(self.ip_login_attempts[src_ip]),
                        'time_window': self.BRUTE_FORCE_WINDOW,
                        'usernames_tried': list(set(attempt[0] for attempt in session.failed_logins)),
                        'sample_passwords': [attempt[1] for attempt in session.failed_logins[-3:]]
                    },
                    indicators=[src_ip, username, password]
                ))
                self.alerts_generated += 1
        
        return alerts
    
    def _analyze_successful_login(self, event, session: SessionState) -> List[Alert]:
        """Analyze successful logins."""
        alerts = []
        
        username = event.username or 'unknown'
        password = event.password or 'unknown'
        
        session.add_successful_login(event.timestamp, username, password)
        
        # Always alert on successful logins - this is critical
        severity = Severity.CRITICAL if session.failed_logins else Severity.HIGH
        
        alerts.append(Alert(
            alert_type=AlertType.SUCCESS_LOGIN,
            severity=severity,
            timestamp=event.timestamp,
            src_ip=event.src_ip,
            session=event.session,
            description=f"Successful login: {username} (after {len(session.failed_logins)} failed attempts)" if session.failed_logins else f"Successful login: {username}",
            details={
                'username': username,
                'password': password,
                'failed_attempts_before_success': len(session.failed_logins),
                'time_since_session_start': (event.timestamp - session.start_time).total_seconds()
            },
            indicators=[event.src_ip, username, password]
        ))
        self.alerts_generated += 1
        
        return alerts
    
    def _analyze_command(self, event, session: SessionState) -> List[Alert]:
        """Analyze command input for suspicious patterns."""
        alerts = []
        command = event.input or ''
        timestamp = event.timestamp
        
        if not command:
            return alerts
        
        # Add to session history
        session.add_command(timestamp, command)
        
        # Check for malware download patterns
        for pattern in self.malware_regex:
            if pattern.search(command):
                alerts.append(Alert(
                    alert_type=AlertType.MALWARE_DOWNLOAD,
                    severity=Severity.HIGH,
                    timestamp=timestamp,
                    src_ip=event.src_ip,
                    session=event.session,
                    description=f"Potential malware download attempt: {command[:80]}",
                    details={
                        'command': command,
                        'pattern_matched': pattern.pattern
                    },
                    indicators=[event.src_ip, command]
                ))
                self.alerts_generated += 1
                break
        
        # Check for persistence attempts
        for pattern in self.persistence_regex:
            if pattern.search(command):
                alerts.append(Alert(
                    alert_type=AlertType.PERSISTENCE_ATTEMPT,
                    severity=Severity.CRITICAL,
                    timestamp=timestamp,
                    src_ip=event.src_ip,
                    session=event.session,
                    description=f"Persistence mechanism detected: {command[:80]}",
                    details={
                        'command': command,
                        'pattern_matched': pattern.pattern
                    },
                    indicators=[event.src_ip, command]
                ))
                self.alerts_generated += 1
                break
        
        # Check for reconnaissance
        recon_matches = []
        for pattern in self.recon_regex:
            if pattern.search(command):
                recon_matches.append(pattern.pattern)
        
        if recon_matches:
            # Don't alert for every recon command, only if we've seen several
            recent_recon = [cmd for ts, cmd in session.commands 
                          if (timestamp - ts).total_seconds() < 300]  # Last 5 minutes
            
            if len(recent_recon) >= 3:
                alerts.append(Alert(
                    alert_type=AlertType.RECONNAISSANCE,
                    severity=Severity.MEDIUM,
                    timestamp=timestamp,
                    src_ip=event.src_ip,
                    session=event.session,
                    description=f"System reconnaissance detected: {len(recent_recon)} enumeration commands",
                    details={
                        'commands': recent_recon[-5:],  # Last 5 commands
                        'command_count': len(session.commands)
                    },
                    indicators=[event.src_ip] + recent_recon[-3:]
                ))
                self.alerts_generated += 1
        
        # Check for suspicious patterns
        for pattern in self.suspicious_regex:
            if pattern.search(command):
                alerts.append(Alert(
                    alert_type=AlertType.SUSPICIOUS_PATTERN,
                    severity=Severity.HIGH,
                    timestamp=timestamp,
                    src_ip=event.src_ip,
                    session=event.session,
                    description=f"Suspicious command pattern: {command[:80]}",
                    details={
                        'command': command,
                        'pattern_matched': pattern.pattern
                    },
                    indicators=[event.src_ip, command]
                ))
                self.alerts_generated += 1
                break
        
        return alerts
    
    def _analyze_file_download(self, event, session: SessionState) -> List[Alert]:
        """Analyze file download events."""
        alerts = []
        
        url = event.url or 'unknown'
        filename = event.filename or 'unknown'
        shasum = event.shasum or 'unknown'
        
        session.files_downloaded.append({
            'url': url,
            'filename': filename,
            'shasum': shasum,
            'timestamp': event.timestamp
        })
        
        # Check for crypto mining indicators
        for pattern in self.mining_regex:
            if pattern.search(url) or pattern.search(filename):
                alerts.append(Alert(
                    alert_type=AlertType.MALWARE_DOWNLOAD,
                    severity=Severity.CRITICAL,
                    timestamp=event.timestamp,
                    src_ip=event.src_ip,
                    session=event.session,
                    description=f"Potential cryptominer download: {filename}",
                    details={
                        'url': url,
                        'filename': filename,
                        'shasum': shasum
                    },
                    indicators=[event.src_ip, url, shasum]
                ))
                self.alerts_generated += 1
                return alerts
        
        # General malware download alert
        alerts.append(Alert(
            alert_type=AlertType.MALWARE_DOWNLOAD,
            severity=Severity.HIGH,
            timestamp=event.timestamp,
            src_ip=event.src_ip,
            session=event.session,
            description=f"File downloaded: {filename}",
            details={
                'url': url,
                'filename': filename,
                'shasum': shasum
            },
            indicators=[event.src_ip, url, shasum]
        ))
        self.alerts_generated += 1
        
        return alerts
    
    def _analyze_file_upload(self, event, session: SessionState) -> List[Alert]:
        """Analyze file upload events."""
        # Track but don't necessarily alert
        session.files_uploaded.append({
            'filename': event.filename or 'unknown',
            'shasum': event.shasum or 'unknown',
            'timestamp': event.timestamp
        })
        return []
    
    def _check_session_patterns(self, session: SessionState) -> List[Alert]:
        """Check for patterns that span multiple events in a session."""
        alerts = []
        
        # Check for command sequence patterns - track by session_id
        if not hasattr(self, '_sequence_checked'):
            self._sequence_checked = set()
        
        if len(session.commands) >= 5 and session.session_id not in self._sequence_checked:
            self._sequence_checked.add(session.session_id)
            
            commands = [cmd for _, cmd in session.commands]
            
            # Alert on significant command sequences
            if len(commands) >= 10:
                alerts.append(Alert(
                    alert_type=AlertType.COMMAND_SEQUENCE,
                    severity=Severity.MEDIUM,
                    timestamp=session.last_activity,
                    src_ip=session.src_ip,
                    session=session.session_id,
                    description=f"Extended command sequence: {len(commands)} commands executed",
                    details={
                        'command_count': len(commands),
                        'session_duration': (session.last_activity - session.start_time).total_seconds(),
                        'commands': commands[:20]  # First 20 commands
                    },
                    indicators=[session.src_ip] + commands[:5]
                ))
                self.alerts_generated += 1
        
        return alerts
    
    def get_session_summary(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get summary of a tracked session."""
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        return {
            'session_id': session.session_id,
            'src_ip': session.src_ip,
            'start_time': session.start_time.isoformat(),
            'last_activity': session.last_activity.isoformat(),
            'duration_seconds': (session.last_activity - session.start_time).total_seconds(),
            'failed_logins': len(session.failed_logins),
            'successful_login': session.successful_login is not None,
            'commands_executed': len(session.commands),
            'files_downloaded': len(session.files_downloaded),
            'files_uploaded': len(session.files_uploaded)
        }
    
    def cleanup_old_sessions(self, max_age_hours: int = 24):
        """Remove sessions older than specified hours."""
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        removed = 0
        
        for session_id in list(self.sessions.keys()):
            if self.sessions[session_id].last_activity < cutoff:
                del self.sessions[session_id]
                removed += 1
        
        # Also clean IP tracking
        for ip in list(self.ip_login_attempts.keys()):
            self.ip_login_attempts[ip] = [
                t for t in self.ip_login_attempts[ip] if t > cutoff
            ]
            if not self.ip_login_attempts[ip]:
                del self.ip_login_attempts[ip]
        
        self.logger.debug(f"Cleaned up {removed} old sessions")
        return removed
    
    def get_stats(self) -> Dict[str, int]:
        """Return analyzer statistics."""
        return {
            'alerts_generated': self.alerts_generated,
            'sessions_tracked': self.sessions_tracked,
            'active_sessions': len(self.sessions),
            'tracked_ips': len(self.ip_login_attempts)
        }


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    analyzer = PatternAnalyzer()
    print("Pattern Analyzer loaded successfully")
