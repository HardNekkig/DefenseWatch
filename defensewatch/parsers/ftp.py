"""FTP log parser — vsftpd, ProFTPD, and pure-ftpd.

Typical vsftpd entries (xferlog/vsftpd.log)::

    Tue Mar  7 12:34:56 2026 [pid 1234] [user] FAIL LOGIN: Client "1.2.3.4"
    Tue Mar  7 12:34:56 2026 [pid 1234] CONNECT: Client "1.2.3.4"

ProFTPD entries (proftpd.log / auth.log)::

    Mar  7 12:34:56 host proftpd[1234]: host (1.2.3.4[1.2.3.4]) - USER admin: no such user found
    Mar  7 12:34:56 host proftpd[1234]: host (1.2.3.4[1.2.3.4]) - USER admin (Login failed): Incorrect password.
    Mar  7 12:34:56 host proftpd[1234]: host (1.2.3.4[1.2.3.4]) - Maximum login attempts (3) exceeded

pure-ftpd entries::

    Mar  7 12:34:56 host pure-ftpd: (?@1.2.3.4) [WARNING] Authentication failed for user [admin]
"""

import re
import logging
from datetime import datetime
from defensewatch.models import ServiceEvent

logger = logging.getLogger(__name__)

# ── vsftpd ────────────────────────────────────────────────────

_VSFTPD_FAIL = re.compile(
    r"^(\w+\s+\w+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+\[pid \d+\]\s*"
    r"(?:\[(\w+)\]\s+)?FAIL LOGIN:\s*Client\s+\"([^\"]+)\""
)
_VSFTPD_CONNECT = re.compile(
    r"^(\w+\s+\w+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+\[pid \d+\]\s*"
    r"CONNECT:\s*Client\s+\"([^\"]+)\""
)

# ── ProFTPD ───────────────────────────────────────────────────

# ISO-8601 or syslog timestamp prefix
_PROFTPD_TS = re.compile(
    r"^(?:(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d+:\-]*)|"
    r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}))\s+\S+\s+proftpd\[\d+\]:\s*(.*)"
)
_PROFTPD_IP = re.compile(r"\(([^)]*\[)?([\d.]+(?:\[[\d.]+\])?)")
_PROFTPD_LOGIN_FAIL = re.compile(
    r"USER\s+(\S+).*(?:Login failed|no such user|Incorrect password)", re.I
)
_PROFTPD_MAX_ATTEMPTS = re.compile(
    r"Maximum login attempts.*exceeded", re.I
)
_PROFTPD_REFUSED = re.compile(
    r"refused connect from", re.I
)

# ── pure-ftpd ─────────────────────────────────────────────────

_PURE_AUTH_FAIL = re.compile(
    r"pure-ftpd.*\(?@?([\d.]+)\).*Authentication failed for user \[([^\]]+)\]", re.I
)
_PURE_CONNECT = re.compile(
    r"pure-ftpd.*New connection from ([\d.]+)", re.I
)
_PURE_BRUTE = re.compile(
    r"pure-ftpd.*too many connections.*from ([\d.]+)", re.I
)


def _parse_vsftpd_ts(ts_str: str) -> float | None:
    try:
        return datetime.strptime(ts_str, "%a %b %d %H:%M:%S %Y").timestamp()
    except ValueError:
        return None


def _parse_syslog_ts(ts_str: str) -> float | None:
    try:
        now = datetime.now()
        dt = datetime.strptime(f"{now.year} {ts_str}", "%Y %b %d %H:%M:%S")
        if dt.month > now.month + 1:
            dt = dt.replace(year=now.year - 1)
        return dt.timestamp()
    except ValueError:
        return None


def _extract_ip(text: str) -> str | None:
    """Pull a clean IP from proftpd-style host(ip[ip]) strings."""
    m = re.search(r"([\d.]+)", text)
    return m.group(1) if m else None


def parse_ftp_line(line: str) -> ServiceEvent | None:
    line = line.strip()
    if not line:
        return None

    # ── vsftpd ──────────────

    m = _VSFTPD_FAIL.match(line)
    if m:
        ts = _parse_vsftpd_ts(m.group(1))
        if ts is None:
            return None
        username = m.group(2)
        ip = m.group(3)
        return ServiceEvent(
            timestamp=ts, service_type="vsftpd", event_type="auth_failure",
            source_ip=ip, username=username,
            detail=f"FTP login failed for '{username or 'unknown'}'",
            severity="medium", raw_line=line,
        )

    m = _VSFTPD_CONNECT.match(line)
    if m:
        ts = _parse_vsftpd_ts(m.group(1))
        if ts is None:
            return None
        return ServiceEvent(
            timestamp=ts, service_type="vsftpd", event_type="connection",
            source_ip=m.group(2),
            detail="FTP connection",
            severity="info", raw_line=line,
        )

    # ── ProFTPD ──────────────

    m = _PROFTPD_TS.match(line)
    if m:
        ts = None
        if m.group(1):
            try:
                ts = datetime.fromisoformat(m.group(1)).timestamp()
            except ValueError:
                pass
        elif m.group(2):
            ts = _parse_syslog_ts(m.group(2))
        if ts is None:
            return None
        rest = m.group(3)
        ip = _extract_ip(rest)

        if _PROFTPD_LOGIN_FAIL.search(rest):
            user_m = re.search(r"USER\s+(\S+)", rest)
            user = user_m.group(1) if user_m else None
            return ServiceEvent(
                timestamp=ts, service_type="proftpd", event_type="auth_failure",
                source_ip=ip, username=user,
                detail=f"FTP login failed for '{user}'",
                severity="medium", raw_line=line,
            )

        if _PROFTPD_MAX_ATTEMPTS.search(rest):
            return ServiceEvent(
                timestamp=ts, service_type="proftpd", event_type="max_attempts",
                source_ip=ip,
                detail="Maximum login attempts exceeded",
                severity="high", raw_line=line,
            )

        if _PROFTPD_REFUSED.search(rest):
            return ServiceEvent(
                timestamp=ts, service_type="proftpd", event_type="connection_refused",
                source_ip=ip,
                detail="Connection refused",
                severity="medium", raw_line=line,
            )

    # ── pure-ftpd ──────────────

    m = _PURE_AUTH_FAIL.search(line)
    if m:
        ip, user = m.group(1), m.group(2)
        # Extract timestamp from syslog prefix
        ts_m = re.match(r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
        ts = _parse_syslog_ts(ts_m.group(1)) if ts_m else None
        if not ts:
            ts_iso = re.match(r"(\d{4}-\d{2}-\d{2}T\S+)", line)
            if ts_iso:
                try:
                    ts = datetime.fromisoformat(ts_iso.group(1)).timestamp()
                except ValueError:
                    pass
        if ts is None:
            return None
        return ServiceEvent(
            timestamp=ts, service_type="pure-ftpd", event_type="auth_failure",
            source_ip=ip, username=user,
            detail=f"Authentication failed for user '{user}'",
            severity="medium", raw_line=line,
        )

    m = _PURE_BRUTE.search(line)
    if m:
        ts_m = re.match(r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
        ts = _parse_syslog_ts(ts_m.group(1)) if ts_m else None
        if ts is None:
            return None
        return ServiceEvent(
            timestamp=ts, service_type="pure-ftpd", event_type="too_many_connections",
            source_ip=m.group(1),
            detail="Too many connections",
            severity="high", raw_line=line,
        )

    return None
