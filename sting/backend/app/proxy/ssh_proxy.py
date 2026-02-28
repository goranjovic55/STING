# SSH Proxy - asyncssh-based transparent proxy
import asyncio
import asyncssh
from typing import Optional, Dict, Any, List
import uuid
from datetime import datetime
import sys
import os

from ..verdict.engine import get_engine
from ..verdict.session_layer import get_session, create_session
from ..core.config import settings

# Virtual filesystem for deception
VIRTUAL_FS: Dict[str, Dict[str, Any]] = {
    "/etc/passwd": {
        "type": "file",
        "content": "root:x:0:0:root:/root:/bin/bash\n"
                   "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                   "sting:x:1000:1000:sting user:/home/sting:/bin/bash\n"
    },
    "/etc/shadow": {
        "type": "file",
        "content": "root:$6$xyz:18000:0:99999:7:::\n"
                   "sting:$6$abc:18000:0:99999:7:::\n",
        "restricted": True
    },
    "/root/secrets.txt": {
        "type": "file",
        "content": "API_KEY=sk-fake-1234567890abcdef\n"
                   "DATABASE_URL=postgresql://admin:password@localhost:5432/prod\n"
                   "AWS_SECRET=fake-aws-secret-key-123456\n",
        "restricted": True
    },
    "/home/sting/.ssh/id_rsa": {
        "type": "file",
        "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAffake...\n-----END RSA PRIVATE KEY-----\n",
        "restricted": True
    },
    "/home/sting/.ssh/authorized_keys": {
        "type": "file",
        "content": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...\n",
        "restricted": True
    },
    "/var/log/messages": {
        "type": "file",
        "content": "Feb 28 12:00:00 server1 sshd[1234]: Accepted password\n" * 10
    },
    "/var/log/secure": {
        "type": "file",
        "content": "Feb 28 10:00:00 server1 sshd[1000]: Accepted publickey for root\n" * 5
    },
    "/etc/hostname": {
        "type": "file",
        "content": "victim-server\n"
    },
    "/etc/ssh/sshd_config": {
        "type": "file",
        "content": "Port 22\nPermitRootLogin yes\nPubkeyAuthentication yes\nPasswordAuthentication yes\n"
    },
    "/etc/ssh/ssh_host_rsa_key": {
        "type": "file",
        "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n",
        "restricted": True
    },
    "/proc/cpuinfo": {
        "type": "file",
        "content": "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 85\nmodel name\t: Intel(R) Xeon(R) CPU @ 2.20GHz\n"
    },
    "/proc/meminfo": {
        "type": "file",
        "content": "MemTotal:        2048000 kB\nMemFree:          500000 kB\nMemAvailable:    1500000 kB\n"
    },
    "/bin/ls": {
        "type": "file",
        "executable": True,
        "content": "#!/bin/bash\necho -e \"total 32\\ndrwxr-xr-x  2 root root 4096 Feb 28 12:00 .\"\n"
    },
    "/bin/cat": {
        "type": "file",
        "executable": True,
        "content": "#!/bin/bash\ncat \"$@\"\n"
    },
    "/bin/bash": {
        "type": "file",
        "executable": True,
        "content": "#!/bin/bash\n"
    },
    "/etc/profile": {
        "type": "file",
        "content": "PATH=/usr/local/sbin:/usr/sbin:/sbin:$PATH\nexport PATH\n"
    },
    "/root/.bashrc": {
        "type": "file",
        "content": "alias ll='ls -la'\nexport PS1='\\u@\\h:\\w\\$ '\n"
    },
    "/root/.gitconfig": {
        "type": "file",
        "content": "[user]\n\temail = admin@victim.local\n\tname = root\n",
        "restricted": True
    },
    "/home/sting/.bash_history": {
        "type": "file",
        "content": "ls -la\ncat /etc/passwd\ncd /root\n",
        "restricted": True
    },
}

FAKE_PROMPTS = [
    "victim-server:~# ",
    "root@victim:~# ",
    "[root@victim-server ~]# ",
]


class StingSSHServer(asyncssh.SSHServer):
    """SSH server that intercepts sessions for analysis"""

    def __init__(self):
        self.engine = get_engine()
        self.sessions: Dict[str, asyncssh.SSHServerSession] = {}

    def connection_made(self, conn):
        ip = conn.get_extra_info('peername')[0]
        session_id = str(uuid.uuid4())
        conn.session_id = session_id

        # Create session in verdict engine
        self.engine.create_session(session_id, ip, "ssh")

        # Create session layer
        create_session(session_id, "ssh")

        print(f"[STING] New SSH connection from {ip} session={session_id[:8]}")

    def connection_lost(self, exc: Optional[Exception]):
        if exc:
            print(f"[STING] Connection lost: {exc}")

    def begin_auth(self, username: str) -> bool:
        """Begin authentication - log the attempt"""
        # This will be called with the username
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        """Validate password - always accept for honeypot"""
        # Log the auth attempt
        print(f"[STING] Auth attempt: user={username} pass={password}")
        return True  # Accept all for deception


class StingSession(asyncssh.SSHServerSession):
    """Custom session that intercepts commands"""

    def __init__(self):
        self._chan = None
        self._session_id = None
        self._username = None
        self._engine = get_engine()
        self._command_buffer = ""
        self._prompt_idx = 0

    def initialize(self, chan, session):
        self._chan = chan
        self._session_id = chan.get_connection().session_id
        self._username = "unknown"

        # Send welcome message
        chan.write("Welcome to Ubuntu 22.04.3 LTS\n")
        chan.write(f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')}\n")
        chan.write(FAKE_PROMPTS[self._prompt_idx])

    def shell_requested(self, command: str) -> bool:
        """Handle interactive shell request"""
        return True

    def exec_requested(self, command: str) -> bool:
        """Handle command execution request"""
        self._handle_command(command)
        return True

    def _handle_command(self, command: str):
        """Process command and return fake output"""
        cmd = command.strip()

        if not cmd:
            self._write_prompt()
            return

        # Log to session layer
        session = get_session(self._session_id)
        if session:
            session.read(command)

        # Score the command
        self._engine.score_event(self._session_id, "AUTH_ATTEMPT" if cmd.startswith("su ") or cmd.startswith("sudo ") else "NORMAL_COMMAND")

        # Handle commands
        output = self._fake_execute(cmd)

        # Send output
        if output:
            self._chan.write(output)

        self._write_prompt()

    def _fake_execute(self, cmd: str) -> str:
        """Execute fake commands"""
        parts = cmd.split()
        base_cmd = parts[0] if parts else ""

        # Session layer writes
        session = get_session(self._session_id)

        if base_cmd in ["ls", "dir"]:
            return self._fake_ls(parts)
        elif base_cmd == "cat":
            return self._fake_cat(parts[1:] if len(parts) > 1 else [])
        elif base_cmd == "pwd":
            return "/root\n"
        elif base_cmd == "whoami":
            return "root\n"
        elif base_cmd == "hostname":
            return "victim-server\n"
        elif base_cmd == "uname":
            return f"Linux victim-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n"
        elif base_cmd == "id":
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        elif base_cmd == "ifconfig" or base_cmd == "ip":
            return self._fake_ifconfig()
        elif base_cmd == "ps":
            return self._fake_ps()
        elif base_cmd == "top":
            return "top: command not found\n"
        elif base_cmd == "cd":
            return ""
        elif base_cmd == "echo":
            return command.replace("echo ", "") + "\n"
        elif base_cmd in ["exit", "logout"]:
            self._chan.write("logout\n")
            self._chan.close()
            return ""
        elif base_cmd == "wget":
            # Critical - mark as suspicious
            if session:
                session.write(command, f"wget {parts[1] if len(parts) > 1 else ''}", "download")
            self._engine.score_event(self._session_id, "WGET_EXECUTABLE")
            return f"--{datetime.now().isoformat()}--  {parts[1] if len(parts) > 1 else 'url'}\n"
        elif base_cmd == "curl":
            if session:
                session.write(command, f"curl {parts[1] if len(parts) > 1 else ''}", "download")
            return f"  % Total    % Received    % Xferd  Speed\n"
        elif base_cmd in ["python", "python3"]:
            return "Python 3.10.12 (main)\n"
        elif base_cmd == "bash" or base_cmd == "sh":
            return ""
        elif base_cmd == "grep":
            return ""
        elif base_cmd == "chmod":
            return ""
        elif base_cmd == "chown":
            return ""
        elif base_cmd == "mkdir":
            return ""
        elif base_cmd == "rm":
            return ""
        elif base_cmd == "cp":
            return ""
        elif base_cmd == "mv":
            return ""
        elif base_cmd == "nano" or base_cmd == "vim" or base_cmd == "vi":
            return f"VIM - Vi IMproved\n"
        elif base_cmd == "sudo":
            return ""
        elif base_cmd == "su":
            return "Password: "
        elif base_cmd == "passwd":
            return "Enter new password: "
        elif base_cmd == "apt":
            return "E: Could not get lock /var/lib/dpkg/lock\n"
        elif base_cmd == "yum":
            return "No packages marked for update\n"
        elif base_cmd == "systemctl":
            return f"Unit {parts[1] if len(parts) > 1 else ''} could not be found.\n"
        elif base_cmd == "service":
            return f"unrecognized service: {parts[1] if len(parts) > 1 else ''}\n"
        elif base_cmd == "netstat":
            return self._fake_netstat()
        elif base_cmd == "ss":
            return self._fake_ss()
        elif base_cmd == "crontab":
            return "no crontab for root\n"
        elif base_cmd == "history":
            return "    1  ls -la\n    2  cat /etc/passwd\n"
        elif base_cmd == "env":
            return "HOME=/root\nPATH=/usr/local/sbin:/usr/sbin:/sbin\n"
        elif base_cmd == "date":
            return datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y\n')
        elif base_cmd == "uptime":
            return f" {datetime.now().strftime('%H:%M:%S')} up 15 days, 3:42, 2 users, load average: 0.00, 0.01, 0.05\n"
        elif base_cmd == "df":
            return "Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/sda1       51475068 8325652  40529636  18% /\n"
        elif base_cmd == "free":
            return "              total        used        free      shared  buff/cache   available\nMem:        1016188      234456      521732        7124      259000      618732\nSwap:             0           0           0\n"
        elif base_cmd == "lsb_release":
            return "Description:    Ubuntu 22.04.3 LTS\nRelease:        22.04\nCodename:       jammy\n"
        elif base_cmd == "cat":
            return ""
        else:
            # Check if trying to access restricted files
            if any(restricted in cmd for restricted in ["/etc/shadow", "/root/secrets", ".ssh/id_rsa"]):
                if session:
                    session.read(cmd)
                self._engine.score_event(self._session_id, "CANARY_HIT")
                return f"cat: {parts[1] if len(parts) > 1 else ''}: Permission denied\n"
            return f"{base_cmd}: command not found\n"

    def _fake_ls(self, parts: list) -> str:
        """Fake ls output"""
        long_flag = "-l" in parts or "-la" in parts or "-al" in parts
        all_flag = "-a" in parts

        files = [".", "..", "bashrc", "profile", ".bash_history", ".ssh"]

        if long_flag:
            lines = ["total 32"]
            for f in files:
                if f.startswith("."):
                    lines.append(f"drwxr-xr-x  5 root root  4096 Feb 28 12:00 {f}")
                else:
                    lines.append(f"-rw-r--r--  1 root root  4096 Feb 28 12:00 {f}")
            return "\n".join(lines) + "\n"
        return " ".join(files) + "\n"

    def _fake_cat(self, args: list) -> str:
        """Fake cat with canary detection"""
        if not args:
            return ""

        path = args[0]

        # Log read to session
        session = get_session(self._session_id)
        if session:
            session.read(path)

        if path in VIRTUAL_FS:
            file_info = VIRTUAL_FS[path]
            if file_info.get("restricted"):
                # Hit a canary!
                if session:
                    session.add_capture(path)
                self._engine.score_event(self._session_id, "CANARY_HIT")
            return file_info.get("content", "")

        # Check for canary patterns
        for canary in ["/etc/shadow", "/root/secrets", ".ssh/id_rsa", ".bash_history"]:
            if canary in path:
                if session:
                    session.add_capture(path)
                self._engine.score_event(self._session_id, "CANARY_HIT")
                return f"cat: {path}: Permission denied\n"

        return f"cat: {path}: No such file or directory\n"

    def _fake_ifconfig(self) -> str:
        return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        ether 00:0c:29:ab:cd:ef  txqueuelen 1000  (Ethernet)
        RX packets 12345  bytes 9876543 (9.4 MiB)
        TX packets 23456  bytes 12345678 (11.7 MiB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
"""

    def _fake_ps(self) -> str:
        return """  PID TTY          TIME CMD
    1 ?        00:00:05 systemd
  234 ?        00:00:00 sshd
  456 ?        00:00:01 bash
  789 pts/0    00:00:00 ps
"""

    def _fake_netstat(self) -> str:
        return """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN
"""

    def _fake_ss(self) -> str:
        return """State    Recv-Q   Send-Q   Local Address:Port    Peer Address:Port
LISTEN   0        128      0.0.0.0:22             0.0.0.0:*
LISTEN   0        128      0.0.0.0:80             0.0.0.0:*
LISTEN   0        128      127.0.0.1:5432         0.0.0.0:*
"""

    def _write_prompt(self):
        self._prompt_idx = (self._prompt_idx + 1) % len(FAKE_PROMPTS)
        self._chan.write(FAKE_PROMPTS[self._prompt_idx])

    def eof_received(self) -> bool:
        self._chan.write("logout\n")
        return False

    def connection_closed(self):
        session = get_session(self._session_id)
        if session:
            diff = session.diff()
            print(f"[STING] Session {self._session_id[:8]} closed. Verdict: {self._engine.get_verdict(self._session_id)}")
            print(f"[STING]   Reads: {len(diff['reads'])}, Writes: {len(diff['writes'])}, Captures: {len(diff['captures'])}")


async def start_ssh_proxy(host: str = "0.0.0.0", port: int = 2222):
    """Start the STING SSH proxy server"""
    # Generate temporary host key for testing
    import os
    key_path = "/tmp/sting_host_key"
    if not os.path.exists(key_path):
        key = asyncssh.generate_private_key("ssh-rsa")
        with open(key_path, "wb") as f:
            f.write(key.export_private_key())

    server = StingSSHServer()

    print(f"[STING] Starting SSH proxy on {host}:{port}")

    await asyncssh.create_server(
        lambda: StingSSHServer(),
        host,
        port,
        server_keys=[key_path],
        process_factory=StingSession,
        allow_pty=True,
        sftp_factory=StingSFTPServer,
    )

    print(f"[STING] SSH proxy listening on {host}:{port}")


class StingSFTPServer(asyncssh.SFTPServer):
    """SFTP server for virtual filesystem"""

    def __init__(self, channel):
        super().__init__(channel)
        self.session_id = channel.get_connection().session_id
        self.engine = get_engine()

    def read(self, path: str, offset: int, size: int) -> bytes:
        """Read file from virtual FS"""
        session = get_session(self.session_id)
        if session:
            session.read(path)

        # Check for canary access
        for canary in ["/etc/shadow", "/root/secrets", ".ssh/id_rsa"]:
            if canary in path:
                if session:
                    session.add_capture(path)
                self.engine.score_event(self.session_id, "CANARY_HIT")
                raise asyncssh.SFTPError(asyncssh.SFTP_PERMISSION_DENIED, "Permission denied")

        if path in VIRTUAL_FS:
            content = VIRTUAL_FS[path].get("content", b"")
            if isinstance(content, str):
                content = content.encode()
            return content[offset:offset + size]

        # Directory listing
        if path == "/" or path == "/home" or path == "/home/sting":
            return b"."

        raise asyncssh.SFTPError(asyncssh.SFTP_NO_SUCH_FILE, "No such file")

    def write(self, path: str, offset: int, data: bytes) -> None:
        """Log write operations"""
        session = get_session(self.session_id)
        if session:
            session.write(path, data.decode("utf-8", errors="ignore"), "sftp_write")
        self.engine.score_event(self.session_id, "FILE_WRITE")

    def listdir(self, path: str):
        """List directory contents"""
        session = get_session(self.session_id)
        if session:
            session.read(path)

        # Root directory
        if path == "/":
            return [
                asyncssh.SFTPName("bin", asyncssh.SFTPFileAttributes(type=2)),
                asyncssh.SFTPName("etc", asyncssh.SFTPFileAttributes(type=2)),
                asyncssh.SFTPName("home", asyncssh.SFTPFileAttributes(type=2)),
                asyncssh.SFTPName("var", asyncssh.SFTPFileAttributes(type=2)),
                asyncssh.SFTPName("root", asyncssh.SFTPFileAttributes(type=2)),
                asyncssh.SFTPName("tmp", asyncssh.SFTPFileAttributes(type=2)),
                asyncssh.SFTPName("usr", asyncssh.SFTPFileAttributes(type=2)),
                asyncssh.SFTPName("proc", asyncssh.SFTPFileAttributes(type=2)),
            ]

        # /home directory
        if path == "/home":
            return [
                asyncssh.SFTPName("sting", asyncssh.SFTPFileAttributes(type=2)),
            ]

        # /home/sting
        if path == "/home/sting":
            return [
                asyncssh.SFTPName(".bashrc", asyncssh.SFTPFileAttributes(type=1, size=100)),
                asyncssh.SFTPName(".ssh", asyncssh.SFTPFileAttributes(type=2)),
            ]

        # /home/sting/.ssh
        if path == "/home/sting/.ssh":
            return [
                asyncssh.SFTPName("authorized_keys", asyncssh.SFTPFileAttributes(type=1, size=50)),
            ]

        raise asyncssh.SFTPError(asyncssh.SFTP_NO_SUCH_FILE, "No such directory")

    def mkdir(self, path: str) -> None:
        """Log directory creation"""
        session = get_session(self.session_id)
        if session:
            session.write(path, "", "mkdir")
        self.engine.score_event(self.session_id, "FILE_WRITE")

    def rmdir(self, path: str) -> None:
        """Log directory removal"""
        self.engine.score_event(self.session_id, "FILE_DELETE")

    def remove(self, path: str) -> None:
        """Log file removal"""
        self.engine.score_event(self.session_id, "FILE_DELETE")

    def rename(self, old_path: str, new_path: str) -> None:
        """Log file rename"""
        session = get_session(self.session_id)
        if session:
            session.write(new_path, f"rename from {old_path}", "rename")


# Add key-based authentication support
class StingSSHServerWithKeys(StingSSHServer):
    """Extended SSH server with key-based auth"""

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: SSHPublicKey) -> bool:
        """Validate public key - accept all for honeypot"""
        print(f"[STING] Public key auth: user={username} key_type={key.get_name()}")
        return True  # Accept all for deception


if __name__ == "__main__":
    asyncio.run(start_ssh_proxy())
