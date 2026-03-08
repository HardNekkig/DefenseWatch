"""MySQL / MariaDB error log parser.

Typical log entries::

    2026-03-07T12:34:56.789012Z 42 [Warning] Access denied for user 'root'@'192.168.1.5' (using password: YES)
    2026-03-07 12:34:56 42 [Warning] [MY-000042] Access denied for user 'admin'@'10.0.0.1' (using password: YES)
    240307 12:34:56 [Warning] Access denied for user 'root'@'1.2.3.4' (using password: YES)

Also parses MariaDB audit plugin output and general connection events.
"""

import re
import logging
from datetime import datetime, timezone
from defensewatch.models import ServiceEvent

logger = logging.getLogger(__name__)

# Timestamp formats
_TS_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*Z?)")
_TS_DATETIME = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})")
_TS_SHORT = re.compile(r"^(\d{6}\s+\d{2}:\d{2}:\d{2})")

# Event patterns
_ACCESS_DENIED = re.compile(
    r"Access denied for user '([^']*)'@'([^']*)'", re.I
)
_CONNECT = re.compile(
    r"Connect\s+(\S+)@(\S+)\s+on", re.I
)
_ABORTED = re.compile(
    r"Aborted connection.*?host:\s*'([^']*)'", re.I
)
_HOST_BLOCKED = re.compile(
    r"Host '([^']+)' is blocked", re.I
)
_TOO_MANY_CONNECTIONS = re.compile(
    r"Too many connections from '?([^'\"]+)", re.I
)


def _parse_timestamp(line: str) -> tuple[float | None, str]:
    """Extract timestamp from a MySQL log line. Returns (epoch, remainder)."""
    m = _TS_ISO.match(line)
    if m:
        ts_str = m.group(1)
        rest = line[m.end():].strip()
        try:
            if ts_str.endswith("Z"):
                dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            elif "." in ts_str:
                dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f")
            else:
                dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
            dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp(), rest
        except ValueError:
            pass

    m = _TS_DATETIME.match(line)
    if m:
        rest = line[m.end():].strip()
        try:
            dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
            return dt.timestamp(), rest
        except ValueError:
            pass

    m = _TS_SHORT.match(line)
    if m:
        rest = line[m.end():].strip()
        try:
            dt = datetime.strptime(m.group(1), "%y%m%d %H:%M:%S")
            return dt.timestamp(), rest
        except ValueError:
            pass

    return None, line


def parse_mysql_line(line: str) -> ServiceEvent | None:
    line = line.strip()
    if not line:
        return None

    ts, rest = _parse_timestamp(line)
    if ts is None:
        return None

    # Access denied
    m = _ACCESS_DENIED.search(rest)
    if m:
        username, host = m.group(1), m.group(2)
        ip = host if re.match(r"[\d.]+$|[\da-fA-F:]+$", host) else None
        return ServiceEvent(
            timestamp=ts, service_type="mysql", event_type="auth_failure",
            source_ip=ip, username=username,
            detail=f"Access denied for '{username}'@'{host}'",
            severity="medium", raw_line=line,
        )

    # Host blocked
    m = _HOST_BLOCKED.search(rest)
    if m:
        host = m.group(1)
        ip = host if re.match(r"[\d.]+$|[\da-fA-F:]+$", host) else None
        return ServiceEvent(
            timestamp=ts, service_type="mysql", event_type="host_blocked",
            source_ip=ip,
            detail=f"Host '{host}' is blocked due to many errors",
            severity="high", raw_line=line,
        )

    # Aborted connection
    m = _ABORTED.search(rest)
    if m:
        host = m.group(1)
        ip = host if re.match(r"[\d.]+$|[\da-fA-F:]+$", host) else None
        return ServiceEvent(
            timestamp=ts, service_type="mysql", event_type="aborted_connection",
            source_ip=ip,
            detail=f"Aborted connection from '{host}'",
            severity="low", raw_line=line,
        )

    # Too many connections
    m = _TOO_MANY_CONNECTIONS.search(rest)
    if m:
        host = m.group(1)
        ip = host if re.match(r"[\d.]+$|[\da-fA-F:]+$", host) else None
        return ServiceEvent(
            timestamp=ts, service_type="mysql", event_type="too_many_connections",
            source_ip=ip,
            detail=f"Too many connections from '{host}'",
            severity="medium", raw_line=line,
        )

    return None
