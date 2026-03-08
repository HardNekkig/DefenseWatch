"""Postfix / Dovecot / mail.log parser.

Typical entries::

    Mar  7 12:34:56 mail postfix/smtpd[1234]: NOQUEUE: reject: RCPT from unknown[1.2.3.4]: 554 5.7.1 <user@example.com>: Relay access denied
    Mar  7 12:34:56 mail postfix/smtpd[1234]: warning: unknown[1.2.3.4]: SASL LOGIN authentication failed: authentication failure
    Mar  7 12:34:56 mail dovecot: imap-login: Disconnected (auth failed, 3 attempts): user=<admin>, method=PLAIN, rip=1.2.3.4
    Mar  7 12:34:56 mail dovecot: pop3-login: Aborted login (auth failed, 1 attempts): user=<user>, method=PLAIN, rip=1.2.3.4

Also handles ISO-8601 syslog timestamps.
"""

import re
import logging
from datetime import datetime
from defensewatch.models import ServiceEvent

logger = logging.getLogger(__name__)

# ── Timestamps ────────────────────────────────────────────────

_TS_ISO = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d+:\-]*)\s+(\S+)\s+(.*)"
)
_TS_SYSLOG = re.compile(
    r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)"
)

# ── Postfix patterns ─────────────────────────────────────────

_PF_SASL_FAIL = re.compile(
    r"postfix/smtpd\[\d+\]:.*?\[([^\]]+)\].*SASL\s+(\w+)\s+authentication failed", re.I
)
_PF_RELAY_DENIED = re.compile(
    r"postfix/smtpd\[\d+\]:.*?from\s+\S+\[([^\]]+)\].*Relay access denied", re.I
)
_PF_REJECT = re.compile(
    r"postfix/smtpd\[\d+\]:.*?reject:.*?from\s+\S+\[([^\]]+)\]:\s*(\d{3})\s+(.*?)(?:;|$)", re.I
)
_PF_CONNECT = re.compile(
    r"postfix/smtpd\[\d+\]:\s*connect from\s+\S+\[([^\]]+)\]", re.I
)
_PF_LOST_CONN = re.compile(
    r"postfix/smtpd\[\d+\]:.*?lost connection after (\w+) from \S+\[([^\]]+)\]", re.I
)
_PF_TOO_MANY = re.compile(
    r"postfix/smtpd\[\d+\]:.*?too many errors after.*?from\s+\S+\[([^\]]+)\]", re.I
)

# ── Dovecot patterns ─────────────────────────────────────────

_DC_AUTH_FAIL = re.compile(
    r"dovecot:?\s*(\w+-login):.*?\(auth failed.*?(\d+)\s*attempt.*?user=<?([^>,]*)>?.*?rip=([^\s,\]]+)", re.I
)
_DC_ABORTED = re.compile(
    r"dovecot:?\s*(\w+-login):.*?Aborted login.*?user=<?([^>,]*)>?.*?rip=([^\s,\]]+)", re.I
)
_DC_DISCONNECTED = re.compile(
    r"dovecot:?\s*(\w+-login):.*?Disconnected.*?rip=([^\s,\]]+)", re.I
)
_DC_NO_AUTH = re.compile(
    r"dovecot:?\s*(\w+-login):.*?Disconnected:?\s*\(no auth attempts.*?rip=([^\s,\]]+)", re.I
)


def _parse_ts(line: str) -> tuple[float | None, str, str]:
    """Return (epoch, hostname, rest_of_line)."""
    m = _TS_ISO.match(line)
    if m:
        ts_str, host, rest = m.groups()
        try:
            dt = datetime.fromisoformat(ts_str)
            return dt.timestamp(), host, rest
        except ValueError:
            pass

    m = _TS_SYSLOG.match(line)
    if m:
        ts_str, host, rest = m.groups()
        try:
            # Syslog timestamps lack year — use current year
            now = datetime.now()
            dt = datetime.strptime(f"{now.year} {ts_str}", "%Y %b %d %H:%M:%S")
            # Handle year rollover (Dec→Jan)
            if dt.month > now.month + 1:
                dt = dt.replace(year=now.year - 1)
            return dt.timestamp(), host, rest
        except ValueError:
            pass

    return None, "", line


def parse_mail_line(line: str) -> ServiceEvent | None:
    line = line.strip()
    if not line:
        return None

    ts, _host, rest = _parse_ts(line)
    if ts is None:
        return None

    # ── Postfix ────────────────────────────

    # SASL auth failure
    m = _PF_SASL_FAIL.search(rest)
    if m:
        ip, method = m.group(1), m.group(2)
        return ServiceEvent(
            timestamp=ts, service_type="postfix", event_type="auth_failure",
            source_ip=ip,
            detail=f"SASL {method} authentication failed",
            severity="medium", raw_line=line,
        )

    # Relay access denied
    m = _PF_RELAY_DENIED.search(rest)
    if m:
        return ServiceEvent(
            timestamp=ts, service_type="postfix", event_type="relay_denied",
            source_ip=m.group(1),
            detail="Relay access denied",
            severity="medium", raw_line=line,
        )

    # Generic SMTP rejection (554, 550, etc.)
    m = _PF_REJECT.search(rest)
    if m:
        ip, code, msg = m.group(1), m.group(2), m.group(3).strip()
        sev = "high" if code.startswith("5") else "medium"
        return ServiceEvent(
            timestamp=ts, service_type="postfix", event_type="smtp_reject",
            source_ip=ip,
            detail=f"{code} {msg[:120]}",
            severity=sev, raw_line=line,
        )

    # Too many errors
    m = _PF_TOO_MANY.search(rest)
    if m:
        return ServiceEvent(
            timestamp=ts, service_type="postfix", event_type="too_many_errors",
            source_ip=m.group(1),
            detail="Too many errors — connection dropped",
            severity="high", raw_line=line,
        )

    # Lost connection (suspicious stages)
    m = _PF_LOST_CONN.search(rest)
    if m:
        stage, ip = m.group(1), m.group(2)
        if stage.upper() in ("AUTH", "DATA", "EHLO", "HELO", "UNKNOWN"):
            return ServiceEvent(
                timestamp=ts, service_type="postfix", event_type="lost_connection",
                source_ip=ip,
                detail=f"Lost connection after {stage}",
                severity="low", raw_line=line,
            )

    # ── Dovecot ────────────────────────────

    # Auth failed with attempt count
    m = _DC_AUTH_FAIL.search(rest)
    if m:
        protocol, attempts, user, ip = m.group(1), m.group(2), m.group(3), m.group(4)
        return ServiceEvent(
            timestamp=ts, service_type="dovecot", event_type="auth_failure",
            source_ip=ip, username=user,
            detail=f"{protocol} auth failed ({attempts} attempts) for '{user}'",
            severity="medium", raw_line=line,
        )

    # Aborted login
    m = _DC_ABORTED.search(rest)
    if m:
        protocol, user, ip = m.group(1), m.group(2), m.group(3)
        return ServiceEvent(
            timestamp=ts, service_type="dovecot", event_type="auth_failure",
            source_ip=ip, username=user,
            detail=f"{protocol} aborted login for '{user}'",
            severity="medium", raw_line=line,
        )

    # No auth attempts (scan/probe)
    m = _DC_NO_AUTH.search(rest)
    if m:
        protocol, ip = m.group(1), m.group(2)
        return ServiceEvent(
            timestamp=ts, service_type="dovecot", event_type="probe",
            source_ip=ip,
            detail=f"{protocol} disconnected (no auth attempts)",
            severity="low", raw_line=line,
        )

    return None
