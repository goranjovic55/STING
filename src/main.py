"""
Honeypot Intelligence Pipeline
Main orchestration module for parsing, analyzing, and alerting.
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any

# Import pipeline components
from parser import LogParser, CowrieEvent
from analyzer import PatternAnalyzer, Alert, Severity, AlertType
from storage import Storage
from alerter import Alerter


class Pipeline:
    """Main honeypot intelligence pipeline."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        self.logger.info("=" * 60)
        self.logger.info("Honeypot Intelligence Pipeline Starting")
        self.logger.info(f"Version: 1.0.0 | Mode: {self.config.get('mode', 'batch')}")
        self.logger.info("=" * 60)
        
        # Initialize components
        self.parser = LogParser(logger=self.logger.getChild('parser'))
        self.analyzer = PatternAnalyzer(logger=self.logger.getChild('analyzer'))
        self.storage = Storage(
            db_path=self.config['db_path'],
            archive_dir=self.config['archive_dir'],
            logger=self.logger.getChild('storage')
        )
        self.alerter = Alerter(
            telegram_token=self.config.get('telegram_token'),
            telegram_chat_id=self.config.get('telegram_chat_id'),
            logger=self.logger.getChild('alerter')
        )
        
        # Statistics
        self.stats = {
            'events_processed': 0,
            'alerts_generated': 0,
            'alerts_sent': 0,
            'sessions_tracked': 0,
            'start_time': datetime.utcnow()
        }
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file and environment."""
        config = {
            # Default paths
            'db_path': '/root/honeypot-intel/data/honeypot.db',
            'archive_dir': '/root/honeypot-intel/archive',
            'log_path': '/root/honeypot-intel/logs/pipeline.log',
            
            # Source configuration
            'log_source': 'ssh',  # 'local', 'ssh', or 'sftp'
            'ssh_host': 'CT100',
            'ssh_log_path': '/var/log/cowrie/cowrie.json',
            'local_log_path': '/var/log/cowrie/cowrie.json',
            
            # Processing configuration
            'mode': 'batch',  # 'batch' or 'realtime'
            'batch_size': 1000,
            'follow_mode': False,
            
            # Alerting configuration
            'immediate_severities': ['CRITICAL', 'HIGH'],
            'digest_severities': ['MEDIUM', 'LOW'],
            'digest_interval_hours': 6,
            
            # Telegram (from environment)
            'telegram_token': os.getenv('TELEGRAM_BOT_TOKEN'),
            'telegram_chat_id': os.getenv('TELEGRAM_CHAT_ID'),
            
            # Feature flags
            'store_events': True,
            'store_alerts': True,
            'send_immediate_alerts': True,
            'send_digests': True,
        }
        
        # Load from config file if provided
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    file_config = json.load(f)
                    config.update(file_config)
                self.logger = logging.getLogger(__name__)
                self.logger.info(f"Loaded configuration from {config_path}")
            except Exception as e:
                self.logger = logging.getLogger(__name__)
                self.logger.warning(f"Failed to load config file: {e}")
        
        # Override with environment variables
        env_mappings = {
            'HONEYPOT_DB_PATH': 'db_path',
            'HONEYPOT_ARCHIVE_DIR': 'archive_dir',
            'HONEYPOT_LOG_PATH': 'log_path',
            'HONEYPOT_SSH_HOST': 'ssh_host',
            'HONEYPOT_SSH_LOG_PATH': 'ssh_log_path',
            'HONEYPOT_LOCAL_LOG_PATH': 'local_log_path',
            'HONEYPOT_MODE': 'mode',
            'TELEGRAM_BOT_TOKEN': 'telegram_token',
            'TELEGRAM_CHAT_ID': 'telegram_chat_id',
        }
        
        for env_var, config_key in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                config[config_key] = value
        
        return config
    
    def _setup_logging(self):
        """Configure logging."""
        log_path = self.config['log_path']
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_path),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def _get_log_source(self) -> str:
        """Determine how to access the log file."""
        source_type = self.config['log_source']
        
        if source_type == 'local':
            return self.config['local_log_path']
        elif source_type == 'ssh':
            return f"ssh {self.config['ssh_host']} cat {self.config['ssh_log_path']}"
        else:
            raise ValueError(f"Unknown log source type: {source_type}")
    
    def run_batch(self, since_hours: Optional[int] = None) -> Dict[str, Any]:
        """
        Run pipeline in batch mode.
        
        Args:
            since_hours: Only process events from last N hours
        
        Returns:
            Processing statistics
        """
        self.logger.info("Running in BATCH mode")
        
        cutoff_time = None
        if since_hours:
            cutoff_time = datetime.utcnow() - timedelta(hours=since_hours)
            self.logger.info(f"Processing events since {cutoff_time}")
        
        # Get log source
        log_source = self._get_log_source()
        self.logger.info(f"Log source: {log_source}")
        
        # Process events
        events_batch = []
        alerts_batch = []
        
        try:
            if self.config['log_source'] == 'ssh':
                event_iterator = self.parser.parse_ssh_output(log_source)
            else:
                event_iterator = self.parser.parse_file(log_source)
            
            for event in event_iterator:
                # Time filtering
                if cutoff_time and event.timestamp < cutoff_time:
                    continue
                
                self.stats['events_processed'] += 1
                
                # Store event
                if self.config['store_events']:
                    events_batch.append(event)
                    if len(events_batch) >= self.config['batch_size']:
                        self.storage.store_events_batch(events_batch)
                        events_batch = []
                
                # Update attacker stats
                self.storage.update_attacker_stats(event.src_ip, event.eventid, event.timestamp)
                
                # Analyze event
                alerts = self.analyzer.analyze_event(event)
                
                for alert in alerts:
                    self.stats['alerts_generated'] += 1
                    
                    # Store alert
                    if self.config['store_alerts']:
                        alerts_batch.append(alert)
                        if len(alerts_batch) >= 100:
                            for a in alerts_batch:
                                self.storage.store_alert(a)
                            alerts_batch = []
                    
                    # Send immediate alert
                    if self.config['send_immediate_alerts'] and alert.severity.value in self.config['immediate_severities']:
                        if self.alerter.send_alert(alert, self.config['immediate_severities']):
                            self.stats['alerts_sent'] += 1
                
                # Progress logging
                if self.stats['events_processed'] % 10000 == 0:
                    self.logger.info(f"Progress: {self.stats['events_processed']} events processed, "
                                   f"{self.stats['alerts_generated']} alerts generated")
        
        except KeyboardInterrupt:
            self.logger.info("Interrupted by user")
        except Exception as e:
            self.logger.error(f"Error during batch processing: {e}", exc_info=True)
        
        finally:
            # Store remaining batches
            if events_batch and self.config['store_events']:
                self.storage.store_events_batch(events_batch)
            
            if alerts_batch and self.config['store_alerts']:
                for alert in alerts_batch:
                    self.storage.store_alert(alert)
            
            # Store session summaries
            for session_id in self.analyzer.sessions:
                summary = self.analyzer.get_session_summary(session_id)
                if summary:
                    self.storage.store_session_summary(session_id, summary)
        
        # Send digest for medium/low alerts
        if self.config['send_digests']:
            self._send_pending_digests()
        
        # Generate and store summary
        self._generate_summary()
        
        return self._get_final_stats()
    
    def run_realtime(self) -> Dict[str, Any]:
        """
        Run pipeline in real-time (tail -f) mode.
        
        Returns:
            Processing statistics
        """
        self.logger.info("Running in REALTIME mode")
        self.logger.info("Press Ctrl+C to stop")
        
        log_source = self.config['local_log_path']
        
        try:
            for event in self.parser.parse_file(log_source, follow=True):
                self.stats['events_processed'] += 1
                
                # Store event
                if self.config['store_events']:
                    self.storage.store_event(event)
                
                # Update attacker stats
                self.storage.update_attacker_stats(event.src_ip, event.eventid, event.timestamp)
                
                # Analyze
                alerts = self.analyzer.analyze_event(event)
                
                for alert in alerts:
                    self.stats['alerts_generated'] += 1
                    
                    # Store alert
                    if self.config['store_alerts']:
                        self.storage.store_alert(alert)
                    
                    # Send immediate alert for critical/high
                    if (self.config['send_immediate_alerts'] and 
                        alert.severity.value in self.config['immediate_severities']):
                        if self.alerter.send_alert(alert, self.config['immediate_severities']):
                            self.stats['alerts_sent'] += 1
                
                # Periodic cleanup and digest
                if self.stats['events_processed'] % 1000 == 0:
                    self.analyzer.cleanup_old_sessions()
                    self._send_pending_digests()
        
        except KeyboardInterrupt:
            self.logger.info("Stopped by user")
        except Exception as e:
            self.logger.error(f"Error in realtime mode: {e}", exc_info=True)
        
        return self._get_final_stats()
    
    def _send_pending_digests(self):
        """Send digest for unnotified medium/low alerts."""
        try:
            alerts = self.storage.get_unnotified_alerts(self.config['digest_severities'])
            
            if len(alerts) >= 5:  # Only send if we have enough to warrant a digest
                self.logger.info(f"Sending digest for {len(alerts)} pending alerts")
                
                if self.alerter.send_digest(alerts):
                    # Mark as notified
                    alert_ids = [a['id'] for a in alerts]
                    self.storage.mark_alerts_notified(alert_ids)
                    self.stats['alerts_sent'] += 1
        except Exception as e:
            self.logger.error(f"Error sending digest: {e}")
    
    def _generate_summary(self):
        """Generate and store daily summary."""
        try:
            stats = self.storage.get_daily_stats()
            self.storage.store_daily_summary(stats)
            self.logger.info(f"Daily summary stored for {stats['date']}")
        except Exception as e:
            self.logger.error(f"Error generating summary: {e}")
    
    def send_daily_report(self) -> bool:
        """Generate and send daily summary report."""
        try:
            stats = self.storage.get_daily_stats()
            return self.alerter.send_daily_summary(stats)
        except Exception as e:
            self.logger.error(f"Error sending daily report: {e}")
            return False
    
    def _get_final_stats(self) -> Dict[str, Any]:
        """Compile final statistics."""
        self.stats['end_time'] = datetime.utcnow()
        self.stats['duration_seconds'] = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        
        # Add component stats
        self.stats['parser'] = self.parser.get_stats()
        self.stats['analyzer'] = self.analyzer.get_stats()
        self.stats['storage'] = self.storage.get_stats()
        self.stats['alerter'] = self.alerter.get_stats()
        
        return self.stats
    
    def print_summary(self):
        """Print processing summary."""
        stats = self._get_final_stats()
        
        print("\n" + "=" * 60)
        print("PIPELINE SUMMARY")
        print("=" * 60)
        print(f"Duration: {stats['duration_seconds']:.1f} seconds")
        print(f"Events Processed: {stats['events_processed']:,}")
        print(f"Alerts Generated: {stats['alerts_generated']:,}")
        print(f"Alerts Sent: {stats['alerts_sent']:,}")
        print(f"Sessions Tracked: {stats['analyzer']['sessions_tracked']:,}")
        print("-" * 60)
        print(f"Events in Database: {stats['storage']['events_in_db']:,}")
        print(f"Alerts in Database: {stats['storage']['alerts_in_db']:,}")
        print(f"Attackers Tracked: {stats['storage']['attackers_in_db']:,}")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='Honeypot Intelligence Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run batch processing for last 24 hours
  python main.py --mode batch --since 24
  
  # Run in real-time mode (tail -f)
  python main.py --mode realtime
  
  # Send daily summary report
  python main.py --daily-report
  
  # Use custom config
  python main.py --config /path/to/config.json
        """
    )
    
    parser.add_argument('--mode', choices=['batch', 'realtime'], 
                       default='batch',
                       help='Processing mode (default: batch)')
    parser.add_argument('--config', '-c',
                       help='Path to configuration file')
    parser.add_argument('--since', '-s', type=int,
                       help='Process events from last N hours')
    parser.add_argument('--daily-report', action='store_true',
                       help='Send daily summary report and exit')
    parser.add_argument('--follow', '-f', action='store_true',
                       help='Follow mode for batch (process then tail)')
    
    args = parser.parse_args()
    
    # Initialize pipeline
    pipeline = Pipeline(config_path=args.config)
    
    # Run based on mode
    if args.daily_report:
        success = pipeline.send_daily_report()
        sys.exit(0 if success else 1)
    
    if args.mode == 'realtime':
        stats = pipeline.run_realtime()
    else:
        stats = pipeline.run_batch(since_hours=args.since)
    
    pipeline.print_summary()
    
    # Return exit code based on success
    sys.exit(0)


if __name__ == '__main__':
    main()
