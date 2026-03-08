"""PostgreSQL log parser.

Typical log entries (various formats)::

    2026-03-07 12:34:56.789 UTC [1234] FATAL:  password authentication failed for user "admin"
    2026-03-07 12:34:56.789 UTC [1234] DETAIL:  Connection matched pg_hba.conf line 99: ...
    2026-03-07 12:34:56.789 UTC [1234] LOG:  connection received: host=1.2.3.4 port=5432
    2026-03-07 12:34:56.789 UTC [1234] FATAL:  no pg_hba.conf entry for host "1.2.3.4", user "postgres", database "postgres"

Also handles syslog-forwarded format::

    Mar  7 12:34:56 hostname postgres[1234]: [1-1] FATAL:  password authentication failed ...
"""

import re
import logging
from datetime import datetime, timezone
from defensewatch.models import ServiceEvent

logger = logging.getLogger(__name__)

# PostgreSQL native timestamp
_TS_PG = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*)\s+(\w+)\s+\[(\d+)\]\s+(.*)"
)

# Syslog-forwarded format
_TS_SYSLOG = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d+:]*)\s+\S+\s+postgres(?:ql)?\[(\d+)\]:\s*(.*)"
)

# Event patterns
_AUTH_FAILED = re.compile(
    r'(?:FATAL|ERROR):\s+password authentication failed for user "([^"]+)"', re.I
)
_NO_HBA_ENTRY = re.compile(
    r'FATAL:\s+no pg_hba\.conf entry for host "([^"]+)".*user "([^"]+)".*database "([^"]+)"', re.I
)
_CONNECTION_RECEIVED = re.compile(
    r'LOG:\s+connection received:\s+host=(\S+)\s+port=(\d+)', re.I
)
_CONNECTION_AUTHORIZED = re.compile(
    r'LOG:\s+connection authorized:\s+user=(\S+)\s+database=(\S+)', re.I
)
_ROLE_NOT_EXIST = re.compile(
    r'FATAL:\s+role "([^"]+)" does not exist', re.I
)
_DB_NOT_EXIST = re.compile(
    r'FATAL:\s+database "([^"]+)" does not exist', re.I
)
_TOO_MANY = re.compile(
    r'FATAL:\s+too many connections', re.I
)
_DETAIL_HOST = re.compile(
    r'Connection matched.*host=(\S+)', re.I
)
# IP extraction from DETAIL lines
_IP_FROM_HOST = re.compile(r'"?([\d.]+|[\da-fA-F:]+)"?')


def _parse_ts(line: str) -> tuple[float | None, int | None, str]:
    """Return (epoch, pid, rest_of_line)."""
    m = _TS_PG.match(line)
    if m:
        ts_str, tz_name, pid, rest = m.groups()
        try:
            fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in ts_str else "%Y-%m-%d %H:%M:%S"
            dt = datetime.strptime(ts_str, fmt)
            if tz_name == "UTC":
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp(), int(pid), rest
        except ValueError:
            pass

    m = _TS_SYSLOG.match(line)
    if m:
        ts_str, pid, rest = m.groups()
        try:
            # ISO-8601 syslog
            dt = datetime.fromisoformat(ts_str)
            return dt.timestamp(), int(pid), rest
        except ValueError:
            pass

    return None, None, line


def parse_postgresql_line(line: str) -> ServiceEvent | None:
    line = line.strip()
    if not line:
        return None

    ts, pid, rest = _parse_ts(line)
    if ts is None:
        return None

    # Auth failure
    m = _AUTH_FAILED.search(rest)
    if m:
        username = m.group(1)
        return ServiceEvent(
            timestamp=ts, service_type="postgresql", event_type="auth_failure",
            source_ip=None, username=username,
            detail=f"Password authentication failed for user \"{username}\"",
            severity="medium", raw_line=line,
        )

    # No pg_hba.conf entry (connection rejected)
    m = _NO_HBA_ENTRY.search(rest)
    if m:
        host, user, db = m.group(1), m.group(2), m.group(3)
        ip_m = _IP_FROM_HOST.match(host)
        ip = ip_m.group(1) if ip_m else None
        return ServiceEvent(
            timestamp=ts, service_type="postgresql", event_type="connection_rejected",
            source_ip=ip, username=user,
            detail=f"No pg_hba.conf entry for host \"{host}\", user \"{user}\", database \"{db}\"",
            severity="medium", raw_line=line,
        )

    # Role does not exist
    m = _ROLE_NOT_EXIST.search(rest)
    if m:
        role = m.group(1)
        return ServiceEvent(
            timestamp=ts, service_type="postgresql", event_type="role_not_found",
            source_ip=None, username=role,
            detail=f"Role \"{role}\" does not exist",
            severity="medium", raw_line=line,
        )

    # Database does not exist
    m = _DB_NOT_EXIST.search(rest)
    if m:
        db = m.group(1)
        return ServiceEvent(
            timestamp=ts, service_type="postgresql", event_type="db_not_found",
            source_ip=None,
            detail=f"Database \"{db}\" does not exist",
            severity="low", raw_line=line,
        )

    # Too many connections
    if _TOO_MANY.search(rest):
        return ServiceEvent(
            timestamp=ts, service_type="postgresql", event_type="too_many_connections",
            source_ip=None,
            detail="Too many connections",
            severity="high", raw_line=line,
        )

    # Connection received (informational, extract IP)
    m = _CONNECTION_RECEIVED.search(rest)
    if m:
        host = m.group(1)
        ip_m = _IP_FROM_HOST.match(host)
        ip = ip_m.group(1) if ip_m else None
        return ServiceEvent(
            timestamp=ts, service_type="postgresql", event_type="connection_received",
            source_ip=ip,
            detail=f"Connection received from {host}:{m.group(2)}",
            severity="info", raw_line=line,
        )

    return None
