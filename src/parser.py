"""
Cowrie Honeypot Log Parser
Reads and validates NDJSON logs from Cowrie honeypot.
"""

import json
import logging
from datetime import datetime
from typing import Iterator, Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CowrieEvent:
    """Represents a parsed Cowrie log event."""
    eventid: str
    timestamp: datetime
    src_ip: Optional[str]
    dst_ip: Optional[str]
    dst_port: Optional[int]
    session: Optional[str]
    username: Optional[str]
    password: Optional[str]
    input: Optional[str]
    url: Optional[str]
    filename: Optional[str]
    shasum: Optional[str]
    message: Optional[str]
    sensor: Optional[str]
    raw: Dict[str, Any]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CowrieEvent':
        """Create event from dictionary with safe field extraction."""
        timestamp_str = data.get('timestamp', '')
        try:
            # Handle ISO format - convert to naive UTC
            ts = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            if ts.tzinfo:
                from datetime import timezone
                ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
            timestamp = ts
        except (ValueError, TypeError):
            timestamp = datetime.utcnow()
        
        return cls(
            eventid=data.get('eventid', 'unknown'),
            timestamp=timestamp,
            src_ip=data.get('src_ip'),
            dst_ip=data.get('dst_ip'),
            dst_port=data.get('dst_port'),
            session=data.get('session'),
            username=data.get('username'),
            password=data.get('password'),
            input=data.get('input'),
            url=data.get('url'),
            filename=data.get('filename'),
            shasum=data.get('shasum'),
            message=data.get('message'),
            sensor=data.get('sensor', 'unknown'),
            raw=data
        )


class LogParser:
    """Parser for Cowrie honeypot NDJSON logs."""
    
    # Event types we care about
    INTERESTING_EVENTS = {
        'cowrie.login.failed',
        'cowrie.login.success',
        'cowrie.command.input',
        'cowrie.command.failed',
        'cowrie.session.file_download',
        'cowrie.session.file_upload',
        'cowrie.session.connect',
        'cowrie.session.closed',
        'cowrie.client.version',
        'cowrie.client.kex',
        'cowrie.direct-tcpip.request',
        'cowrie.direct-tcpip.data'
    }
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.parsed_count = 0
        self.error_count = 0
        self.filtered_count = 0
    
    def parse_line(self, line: str) -> Optional[CowrieEvent]:
        """Parse a single NDJSON line."""
        line = line.strip()
        if not line:
            return None
        
        try:
            data = json.loads(line)
        except json.JSONDecodeError as e:
            self.logger.warning(f"Malformed JSON: {e}")
            self.error_count += 1
            return None
        
        # Validate required fields
        if 'eventid' not in data:
            self.logger.debug("Skipping line without eventid")
            self.filtered_count += 1
            return None
        
        # Filter to interesting events only (optional optimization)
        # Uncomment to filter: if data['eventid'] not in self.INTERESTING_EVENTS:
        #     self.filtered_count += 1
        #     return None
        
        try:
            event = CowrieEvent.from_dict(data)
            self.parsed_count += 1
            return event
        except Exception as e:
            self.logger.error(f"Error creating event: {e}")
            self.error_count += 1
            return None
    
    def parse_file(self, filepath: str, follow: bool = False) -> Iterator[CowrieEvent]:
        """
        Parse events from a log file.
        
        Args:
            filepath: Path to the NDJSON log file
            follow: If True, tail the file for new entries (like tail -f)
        
        Yields:
            CowrieEvent objects
        """
        path = Path(filepath)
        
        if not path.exists():
            self.logger.error(f"Log file not found: {filepath}")
            return
        
        if follow:
            yield from self._tail_file(path)
        else:
            yield from self._read_file(path)
    
    def _read_file(self, path: Path) -> Iterator[CowrieEvent]:
        """Read entire file once."""
        self.logger.info(f"Reading log file: {path}")
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                event = self.parse_line(line)
                if event:
                    yield event
                
                # Progress logging for large files
                if line_num % 10000 == 0:
                    self.logger.debug(f"Processed {line_num} lines...")
        
        self.logger.info(f"Finished reading. Parsed: {self.parsed_count}, Errors: {self.error_count}")
    
    def _tail_file(self, path: Path, poll_interval: float = 1.0) -> Iterator[CowrieEvent]:
        """Tail file for new entries (follow mode)."""
        import time
        
        self.logger.info(f"Tailing log file: {path}")
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            # Seek to end initially
            f.seek(0, 2)
            
            while True:
                line = f.readline()
                if not line:
                    time.sleep(poll_interval)
                    continue
                
                event = self.parse_line(line)
                if event:
                    yield event
    
    def parse_ssh_output(self, ssh_command: str) -> Iterator[CowrieEvent]:
        """
        Parse events from SSH command output (for remote log access).
        
        Args:
            ssh_command: SSH command that outputs NDJSON (e.g., "ssh CT100 cat /var/log/cowrie/cowrie.json")
        
        Yields:
            CowrieEvent objects
        """
        import subprocess
        
        self.logger.info(f"Executing remote log read: {ssh_command}")
        
        try:
            proc = subprocess.Popen(
                ssh_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            for line in proc.stdout:
                event = self.parse_line(line)
                if event:
                    yield event
            
            proc.wait()
            if proc.returncode != 0:
                stderr = proc.stderr.read()
                self.logger.error(f"SSH command failed: {stderr}")
        
        except Exception as e:
            self.logger.error(f"Error executing SSH command: {e}")
    
    def get_stats(self) -> Dict[str, int]:
        """Return parsing statistics."""
        return {
            'parsed': self.parsed_count,
            'errors': self.error_count,
            'filtered': self.filtered_count
        }
    
    def reset_stats(self):
        """Reset statistics counters."""
        self.parsed_count = 0
        self.error_count = 0
        self.filtered_count = 0


def parse_cowrie_timestamp(ts: str) -> datetime:
    """Utility function to parse Cowrie timestamps."""
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return datetime.utcnow()


if __name__ == '__main__':
    # Simple test
    logging.basicConfig(level=logging.DEBUG)
    
    parser = LogParser()
    
    # Test with sample data
    sample = '{"eventid": "cowrie.login.failed", "timestamp": "2024-01-01T12:00:00.000Z", "src_ip": "192.168.1.1", "session": "abc123", "username": "root", "password": "password123"}'
    event = parser.parse_line(sample)
    if event:
        print(f"Parsed: {event.eventid} from {event.src_ip}")
