import re
import time
import json
import logging
from datetime import datetime
from collections import defaultdict
from defensewatch.models import SSHEvent, BruteForceSession
from defensewatch.config import DetectionConfig

logger = logging.getLogger(__name__)

# ISO-8601 timestamp + hostname + sshd[pid]: message
_SSHD_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+\-]\d{2}:\d{2})\s+'
    r'(\S+)\s+sshd\[(\d+)\]:\s+(.*)$'
)

_PATTERNS = [
    # Failed password for invalid user
    (re.compile(r'Failed password for invalid user (\S+) from ([\d.]+) port (\d+)'),
     'invalid_user', lambda m: (m.group(1), m.group(2), int(m.group(3)), 'password')),

    # Failed none for invalid user (auth method "none")
    (re.compile(r'Failed none for invalid user (\S+) from ([\d.]+) port (\d+)'),
     'invalid_user', lambda m: (m.group(1), m.group(2), int(m.group(3)), 'none')),

    # Failed password for valid user
    (re.compile(r'Failed password for (\S+) from ([\d.]+) port (\d+)'),
     'failed_password', lambda m: (m.group(1), m.group(2), int(m.group(3)), 'password')),

    # Invalid user with username
    (re.compile(r'Invalid user (\S+) from ([\d.]+)(?: port (\d+))?'),
     'invalid_user', lambda m: (m.group(1), m.group(2), int(m.group(3)) if m.group(3) else None, None)),

    # Invalid user with empty username
    (re.compile(r'Invalid user\s+from ([\d.]+)(?: port (\d+))?'),
     'invalid_user', lambda m: (None, m.group(1), int(m.group(2)) if m.group(2) else None, None)),

    # Accepted password
    (re.compile(r'Accepted password for (\S+) from ([\d.]+) port (\d+)'),
     'accepted_password', lambda m: (m.group(1), m.group(2), int(m.group(3)), 'password')),

    # Accepted publickey
    (re.compile(r'Accepted publickey for (\S+) from ([\d.]+) port (\d+)'),
     'accepted_publickey', lambda m: (m.group(1), m.group(2), int(m.group(3)), 'publickey')),

    # Disconnected from invalid user (with username)
    (re.compile(r'Disconnected from invalid user (\S+) ([\d.]+) port (\d+)'),
     'disconnected', lambda m: (m.group(1), m.group(2), int(m.group(3)), None)),

    # Disconnected from invalid user (empty username)
    (re.compile(r'Disconnected from invalid user\s+([\d.]+) port (\d+)'),
     'disconnected', lambda m: (None, m.group(1), int(m.group(2)), None)),

    # Disconnected from authenticating user
    (re.compile(r'Disconnected from authenticating user (\S+) ([\d.]+) port (\d+)'),
     'disconnected', lambda m: (m.group(1), m.group(2), int(m.group(3)), None)),

    # Disconnected from user (normal disconnect)
    (re.compile(r'Disconnected from user (\S+) ([\d.]+) port (\d+)'),
     'disconnected', lambda m: (m.group(1), m.group(2), int(m.group(3)), None)),

    # Connection closed by invalid user (with username)
    (re.compile(r'Connection (?:closed|reset) by invalid user (\S+) ([\d.]+) port (\d+)'),
     'disconnected', lambda m: (m.group(1), m.group(2), int(m.group(3)), None)),

    # Connection closed by invalid user (empty username)
    (re.compile(r'Connection (?:closed|reset) by invalid user\s+([\d.]+) port (\d+)'),
     'disconnected', lambda m: (None, m.group(1), int(m.group(2)), None)),

    # Connection closed/reset by IP (no user)
    (re.compile(r'Connection (?:closed|reset) by ([\d.]+) port (\d+)'),
     'disconnected', lambda m: (None, m.group(1), int(m.group(2)), None)),

    # Failed publickey
    (re.compile(r'Failed publickey for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)'),
     'failed_publickey', lambda m: (m.group(1), m.group(2), int(m.group(3)), 'publickey')),

    # Connection timeout / auth timeout
    (re.compile(r'Timeout.*?from ([\d.]+) port (\d+)'),
     'auth_timeout', lambda m: (None, m.group(1), int(m.group(2)), None)),
]


class BruteForceTracker:
    def __init__(self, config: DetectionConfig):
        self.threshold = config.ssh_brute_threshold
        self.window = config.ssh_brute_window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._active_sessions: dict[str, BruteForceSession] = {}
        self._alerted: set[str] = set()

    def track(self, event: SSHEvent) -> BruteForceSession | None:
        if event.event_type not in ('failed_password', 'invalid_user'):
            return None

        ip = event.source_ip
        now = event.timestamp
        attempts = self._attempts[ip]
        attempts.append(now)

        # Prune old attempts
        cutoff = now - self.window
        self._attempts[ip] = [t for t in attempts if t >= cutoff]
        attempts = self._attempts[ip]

        if len(attempts) >= self.threshold:
            if ip in self._active_sessions:
                session = self._active_sessions[ip]
                session.session_end = now
                session.attempt_count = len(attempts)
                if event.username and event.username not in session.usernames_tried:
                    session.usernames_tried.append(event.username)
                return session

            usernames = []
            if event.username:
                usernames.append(event.username)
            session = BruteForceSession(
                source_ip=ip,
                session_start=attempts[0],
                session_end=now,
                attempt_count=len(attempts),
                usernames_tried=usernames,
                event_type='ssh_brute_force',
                status='active',
                service_port=event.service_port,
            )
            self._active_sessions[ip] = session
            return session

        return None

    def is_new_session(self, ip: str) -> bool:
        return ip not in self._alerted

    def mark_alerted(self, ip: str):
        self._alerted.add(ip)

    def cleanup(self) -> list[BruteForceSession]:
        """Mark expired sessions as completed and clean up stale tracking data.
        Returns list of sessions that transitioned to 'completed'."""
        now = time.time()
        cutoff = now - self.window
        completed = []

        stale_ips = []
        for ip, session in self._active_sessions.items():
            if session.session_end < cutoff:
                session.status = 'completed'
                completed.append(session)
                stale_ips.append(ip)

        for ip in stale_ips:
            del self._active_sessions[ip]
            self._alerted.discard(ip)
            self._attempts.pop(ip, None)

        # Prune empty attempt lists for IPs without active sessions
        empty = [ip for ip, att in self._attempts.items()
                 if not att and ip not in self._active_sessions]
        for ip in empty:
            del self._attempts[ip]

        return completed


def parse_ssh_line(line: str) -> SSHEvent | None:
    line = line.strip()
    if not line:
        return None

    m = _SSHD_RE.match(line)
    if not m:
        return None

    ts_str, hostname, pid_str, message = m.groups()
    try:
        ts = datetime.fromisoformat(ts_str).timestamp()
    except ValueError:
        return None

    for pattern, event_type, extractor in _PATTERNS:
        pm = pattern.search(message)
        if pm:
            username, source_ip, source_port, auth_method = extractor(pm)
            return SSHEvent(
                timestamp=ts,
                event_type=event_type,
                username=username,
                source_ip=source_ip,
                source_port=source_port,
                auth_method=auth_method,
                hostname=hostname,
                pid=int(pid_str),
                raw_line=line,
            )

    return None


class DistributedBruteForceTracker:
    """Detects multiple IPs targeting the same username within a time window."""

    def __init__(self, config: DetectionConfig):
        self.threshold = config.ssh_brute_threshold
        self.window = config.ssh_brute_window_seconds
        # username -> {ip -> [timestamps]}
        self._per_user: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
        self._alerted_users: set[str] = set()

    def track(self, event: SSHEvent) -> dict | None:
        """Returns alert dict if distributed brute force detected, else None."""
        if event.event_type not in ('failed_password', 'invalid_user'):
            return None
        if not event.username:
            return None

        username = event.username
        ip = event.source_ip
        now = event.timestamp

        self._per_user[username][ip].append(now)

        cutoff = now - self.window
        self._per_user[username][ip] = [
            t for t in self._per_user[username][ip] if t >= cutoff
        ]

        # Count distinct IPs with recent attempts for this username
        active_ips = [
            src_ip for src_ip, timestamps in self._per_user[username].items()
            if timestamps
        ]

        if len(active_ips) >= self.threshold and username not in self._alerted_users:
            self._alerted_users.add(username)
            return {
                "username": username,
                "source_ips": active_ips[:20],
                "ip_count": len(active_ips),
            }

        return None

    def cleanup(self):
        now = time.time()
        cutoff = now - self.window
        empty_users = []
        for username, ip_map in self._per_user.items():
            empty_ips = [ip for ip, ts in ip_map.items() if not ts or ts[-1] < cutoff]
            for ip in empty_ips:
                del ip_map[ip]
            if not ip_map:
                empty_users.append(username)
        for username in empty_users:
            del self._per_user[username]
            self._alerted_users.discard(username)
