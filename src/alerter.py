"""
Alert Formatter for Honeypot Intelligence
Formats alerts for Telegram and other notification channels.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class Alert:
    """Alert data structure for formatter."""
    alert_type: str
    severity: str
    timestamp: datetime
    src_ip: Optional[str]
    session: Optional[str]
    description: str
    details: Dict[str, Any]
    indicators: List[str]


class Alerter:
    """Formats and sends security alerts."""
    
    # Severity emojis for visual distinction
    SEVERITY_ICONS = {
        'CRITICAL': '🚨',
        'HIGH': '⚠️',
        'MEDIUM': '⚡',
        'LOW': 'ℹ️'
    }
    
    # Alert type icons
    TYPE_ICONS = {
        'BRUTE_FORCE': '🔨',
        'SUCCESS_LOGIN': '🔓',
        'MALWARE_DOWNLOAD': '🦠',
        'COMMAND_SEQUENCE': '📝',
        'PERSISTENCE_ATTEMPT': '🔑',
        'RECONNAISSANCE': '🔍',
        'SUSPICIOUS_PATTERN': '⚠️',
        'DATA_EXFILTRATION': '📤'
    }
    
    def __init__(self, telegram_token: Optional[str] = None, 
                 telegram_chat_id: Optional[str] = None,
                 logger: Optional[logging.Logger] = None):
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        self.logger = logger or logging.getLogger(__name__)
        
        self.alerts_sent = 0
        self.last_error = None
    
    def format_alert(self, alert: Alert, compact: bool = False) -> str:
        """
        Format a single alert as Telegram-compatible markdown.
        
        Args:
            alert: The alert to format
            compact: If True, use shorter format for mobile
        
        Returns:
            Formatted markdown string
        """
        sev_icon = self.SEVERITY_ICONS.get(alert.severity, '⚪')
        type_icon = self.TYPE_ICONS.get(alert.alert_type, '📋')
        
        # Escape markdown special characters
        description = self._escape_markdown(alert.description)
        
        lines = [
            f"{sev_icon} *{alert.severity}* | {type_icon} *{alert.alert_type}*",
            f"",
            f"📝 {description}",
            f"",
            f"🕐 `{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}`",
        ]
        
        if alert.src_ip:
            lines.append(f"🌐 `{alert.src_ip}`")
        
        if alert.session:
            lines.append(f"🔌 Session: `{alert.session[:12]}...`" if len(alert.session) > 12 else f"🔌 Session: `{alert.session}`")
        
        # Add relevant details based on alert type
        if not compact:
            details_text = self._format_details(alert)
            if details_text:
                lines.append(f"")
                lines.append(f"📊 *Details:*")
                lines.append(details_text)
        
        # Add indicators
        if alert.indicators and not compact:
            indicators = [self._escape_markdown(str(i)) for i in alert.indicators[:5]]
            if indicators:
                lines.append(f"")
                lines.append(f"🎯 *Indicators:*")
                lines.append('`"' + '"` `"'.join(indicators) + '`"')
        
        return '\n'.join(lines)
    
    def format_alert_db(self, alert_row: Dict) -> str:
        """Format an alert from database row."""
        alert = Alert(
            alert_type=alert_row['alert_type'],
            severity=alert_row['severity'],
            timestamp=datetime.fromisoformat(alert_row['timestamp']),
            src_ip=alert_row['src_ip'],
            session=alert_row['session'],
            description=alert_row['description'],
            details=json.loads(alert_row['details']) if alert_row['details'] else {},
            indicators=json.loads(alert_row['indicators']) if alert_row['indicators'] else []
        )
        return self.format_alert(alert)
    
    def format_digest(self, alerts: List[Dict], time_window_hours: int = 24) -> str:
        """
        Format a batch of alerts as a digest.
        
        Args:
            alerts: List of alert rows from database
            time_window_hours: Time window for the digest
        
        Returns:
            Formatted markdown string
        """
        if not alerts:
            return "📭 *No alerts* in the specified time window."
        
        # Group by severity
        by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for alert in alerts:
            sev = alert.get('severity', 'LOW')
            if sev in by_severity:
                by_severity[sev].append(alert)
        
        lines = [
            f"📊 *Honeypot Alert Digest*",
            f"🕐 Last {time_window_hours}h | {len(alerts)} total alerts",
            f""
        ]
        
        # Summary counts
        counts = []
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = len(by_severity[sev])
            if count > 0:
                icon = self.SEVERITY_ICONS.get(sev, '⚪')
                counts.append(f"{icon} {sev}: {count}")
        
        lines.append(' | '.join(counts))
        lines.append(f"")
        
        # Recent critical/high alerts
        important = by_severity['CRITICAL'] + by_severity['HIGH']
        if important:
            lines.append(f"🔥 *Important Alerts:*")
            for alert in important[:5]:  # Top 5
                icon = self.TYPE_ICONS.get(alert.get('alert_type', ''), '📋')
                desc = self._escape_markdown(alert.get('description', 'Unknown')[:60])
                ip = alert.get('src_ip', 'unknown')
                lines.append(f"  {icon} `{ip}`: {desc}...")
            lines.append(f"")
        
        # Top attackers
        ip_counts = {}
        for alert in alerts:
            ip = alert.get('src_ip')
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        if ip_counts:
            top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            lines.append(f"🎯 *Top Attackers:*")
            for ip, count in top_ips:
                lines.append(f"  `{ip}`: {count} alerts")
            lines.append(f"")
        
        # Alert type breakdown
        type_counts = {}
        for alert in alerts:
            atype = alert.get('alert_type', 'UNKNOWN')
            type_counts[atype] = type_counts.get(atype, 0) + 1
        
        if type_counts:
            lines.append(f"📋 *Alert Types:*")
            for atype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                icon = self.TYPE_ICONS.get(atype, '📋')
                lines.append(f"  {icon} {atype}: {count}")
        
        return '\n'.join(lines)
    
    def format_daily_summary(self, stats: Dict[str, Any]) -> str:
        """
        Format daily statistics summary.
        
        Args:
            stats: Daily statistics dictionary
        
        Returns:
            Formatted markdown string
        """
        date = stats.get('date', datetime.utcnow().strftime('%Y-%m-%d'))
        events = stats.get('events', {})
        alerts = stats.get('alerts', {})
        
        lines = [
            f"📊 *Daily Honeypot Summary*",
            f"📅 {date}",
            f""
        ]
        
        # Event statistics
        lines.append(f"*Events:*")
        lines.append(f"  📈 Total: {events.get('total', 0):,}")
        lines.append(f"  👤 Unique IPs: {events.get('unique_ips', 0):,}")
        lines.append(f"  🔌 Sessions: {events.get('sessions', 0):,}")
        lines.append(f"")
        
        # Activity breakdown
        lines.append(f"*Activity:*")
        lines.append(f"  ❌ Failed logins: {events.get('failed_logins', 0):,}")
        lines.append(f"  ✅ Successful logins: {events.get('success_logins', 0):,}")
        lines.append(f"  📝 Commands: {events.get('commands', 0):,}")
        lines.append(f"  📥 Downloads: {events.get('downloads', 0):,}")
        lines.append(f"")
        
        # Alert summary
        total_alerts = (alerts.get('critical', 0) + alerts.get('high', 0) + 
                       alerts.get('medium', 0) + alerts.get('low', 0))
        
        if total_alerts > 0:
            lines.append(f"*Alerts:*")
            if alerts.get('critical', 0) > 0:
                lines.append(f"  🚨 Critical: {alerts['critical']}")
            if alerts.get('high', 0) > 0:
                lines.append(f"  ⚠️ High: {alerts['high']}")
            if alerts.get('medium', 0) > 0:
                lines.append(f"  ⚡ Medium: {alerts['medium']}")
            if alerts.get('low', 0) > 0:
                lines.append(f"  ℹ️ Low: {alerts['low']}")
            lines.append(f"")
        
        # Top attackers
        top_attackers = stats.get('top_attackers', [])
        if top_attackers:
            lines.append(f"*Top Attackers:*")
            for i, attacker in enumerate(top_attackers[:5], 1):
                ip = attacker.get('src_ip', 'unknown')
                count = attacker.get('count', 0)
                lines.append(f"  {i}. `{ip}` ({count} events)")
            lines.append(f"")
        
        # Top commands
        top_commands = stats.get('top_commands', [])
        if top_commands:
            lines.append(f"*Top Commands:*")
            for i, cmd_data in enumerate(top_commands[:5], 1):
                cmd = cmd_data.get('input', 'unknown')[:30]
                count = cmd_data.get('count', 0)
                lines.append(f"  {i}. `{cmd}` ({count}x)")
        
        return '\n'.join(lines)
    
    def _format_details(self, alert: Alert) -> str:
        """Format alert details based on type."""
        details = alert.details
        lines = []
        
        if alert.alert_type == 'BRUTE_FORCE':
            lines.append(f"• Attempts: {details.get('attempt_count', 'N/A')}")
            lines.append(f"• Window: {details.get('time_window', 'N/A')}s")
            usernames = details.get('usernames_tried', [])
            if usernames:
                lines.append(f"• Users: {', '.join(str(u) for u in usernames[:3])}")
        
        elif alert.alert_type == 'SUCCESS_LOGIN':
            lines.append(f"• Username: `{details.get('username', 'N/A')}`")
            lines.append(f"• Failed before: {details.get('failed_attempts_before_success', 0)}")
        
        elif alert.alert_type == 'MALWARE_DOWNLOAD':
            lines.append(f"• URL: `{details.get('url', 'N/A')[:50]}...`" if len(str(details.get('url', ''))) > 50 else f"• URL: `{details.get('url', 'N/A')}`")
            lines.append(f"• File: `{details.get('filename', 'N/A')}`")
            if details.get('shasum'):
                lines.append(f"• SHA256: `{details['shasum'][:16]}...`")
        
        elif alert.alert_type == 'PERSISTENCE_ATTEMPT':
            cmd = details.get('command', '')
            lines.append(f"• Command: `{cmd[:60]}...`" if len(cmd) > 60 else f"• Command: `{cmd}`")
        
        elif alert.alert_type == 'COMMAND_SEQUENCE':
            lines.append(f"• Commands: {details.get('command_count', 0)}")
            lines.append(f"• Duration: {details.get('session_duration', 0):.0f}s")
        
        elif alert.alert_type == 'RECONNAISSANCE':
            cmds = details.get('commands', [])
            lines.append(f"• Recent commands: {len(cmds)}")
        
        return '\n'.join(lines)
    
    def _escape_markdown(self, text: str) -> str:
        """Escape special markdown characters for Telegram."""
        if not text:
            return ''
        
        # Characters that need escaping in Telegram markdown
        chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
        for char in chars:
            text = text.replace(char, f'\\{char}')
        return text
    
    def send_telegram(self, message: str, chat_id: Optional[str] = None) -> bool:
        """
        Send message via Telegram bot.
        
        Args:
            message: Markdown-formatted message
            chat_id: Override default chat ID
        
        Returns:
            True if sent successfully
        """
        if not self.telegram_token:
            self.logger.warning("Telegram token not configured")
            return False
        
        chat = chat_id or self.telegram_chat_id
        if not chat:
            self.logger.warning("Telegram chat ID not configured")
            return False
        
        try:
            import requests
            
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                'chat_id': chat,
                'text': message,
                'parse_mode': 'MarkdownV2',
                'disable_web_page_preview': True
            }
            
            response = requests.post(url, json=payload, timeout=30)
            
            if response.status_code == 200:
                self.alerts_sent += 1
                self.logger.debug(f"Telegram message sent to {chat}")
                return True
            else:
                self.logger.error(f"Telegram API error: {response.status_code} - {response.text}")
                self.last_error = response.text
                return False
        
        except Exception as e:
            self.logger.error(f"Error sending Telegram message: {e}")
            self.last_error = str(e)
            return False
    
    def send_alert(self, alert: Alert, immediate_severities: List[str] = None) -> bool:
        """
        Send an alert if it meets severity criteria.
        
        Args:
            alert: The alert to send
            immediate_severities: List of severities that trigger immediate notification
        
        Returns:
            True if sent
        """
        immediate_severities = immediate_severities or ['CRITICAL', 'HIGH']
        
        if alert.severity not in immediate_severities:
            self.logger.debug(f"Alert severity {alert.severity} not in immediate list, queuing")
            return False
        
        message = self.format_alert(alert)
        return self.send_telegram(message)
    
    def send_digest(self, alerts: List[Dict]) -> bool:
        """Send a digest of multiple alerts."""
        message = self.format_digest(alerts)
        return self.send_telegram(message)
    
    def send_daily_summary(self, stats: Dict[str, Any]) -> bool:
        """Send daily summary report."""
        message = self.format_daily_summary(stats)
        return self.send_telegram(message)
    
    def get_stats(self) -> Dict[str, Any]:
        """Return alerter statistics."""
        return {
            'alerts_sent': self.alerts_sent,
            'last_error': self.last_error
        }


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    
    # Test formatting
    alerter = Alerter()
    
    test_alert = Alert(
        alert_type='BRUTE_FORCE',
        severity='HIGH',
        timestamp=datetime.utcnow(),
        src_ip='192.168.1.100',
        session='abc123',
        description='Brute force attack detected: 10 failed logins in 60s',
        details={'attempt_count': 10, 'time_window': 60, 'usernames_tried': ['root', 'admin']},
        indicators=['192.168.1.100', 'root', 'password123']
    )
    
    formatted = alerter.format_alert(test_alert)
    print("Formatted Alert:")
    print(formatted)
    print("\n" + "="*50 + "\n")
    
    # Test compact format
    compact = alerter.format_alert(test_alert, compact=True)
    print("Compact Format:")
    print(compact)
