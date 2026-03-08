import re
import logging
from datetime import datetime
from defensewatch.models import HTTPEvent

logger = logging.getLogger(__name__)

# Nginx error log format:
# 2026/03/03 17:52:00 [error] 1234#0: *567 message, client: 1.2.3.4, server: example.com, ...
_ERROR_RE = re.compile(
    r'^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(\w+)\]\s+'
    r'(\d+)#\d+:\s+'
    r'\*\d+\s+(.*)'
)

_CLIENT_RE = re.compile(r'client:\s+([\d.]+)')
_SERVER_RE = re.compile(r'server:\s+(\S+)')
_REQUEST_RE = re.compile(r'request:\s+"(\S+)\s+(\S+)\s+\S+"')

# Error patterns that indicate attacks
_ERROR_ATTACK_PATTERNS = [
    ('access_forbidden', re.compile(r'access forbidden', re.I), 'medium'),
    ('upstream_error', re.compile(r'upstream (?:timed out|prematurely closed)', re.I), 'low'),
    ('ssl_error', re.compile(r'SSL_do_handshake\(\) failed|no "ssl_certificate"', re.I), 'low'),
    ('directory_index', re.compile(r'directory index of .* is forbidden', re.I), 'low'),
    ('client_body_too_large', re.compile(r'client intended to send too large body', re.I), 'medium'),
    ('invalid_request', re.compile(r'client sent invalid', re.I), 'medium'),
]


def parse_nginx_error_line(line: str, vhost: str | None = None) -> HTTPEvent | None:
    line = line.strip()
    if not line:
        return None

    m = _ERROR_RE.match(line)
    if not m:
        return None

    ts_str, level, pid, message = m.groups()

    try:
        ts = datetime.strptime(ts_str, '%Y/%m/%d %H:%M:%S').timestamp()
    except ValueError:
        return None

    client_m = _CLIENT_RE.search(message)
    if not client_m:
        return None
    ip = client_m.group(1)

    server_m = _SERVER_RE.search(message)
    server = server_m.group(1) if server_m else vhost

    req_m = _REQUEST_RE.search(message)
    method = req_m.group(1) if req_m else None
    path = req_m.group(2) if req_m else None

    attack_types = []
    severity = None
    for atype, pattern, sev in _ERROR_ATTACK_PATTERNS:
        if pattern.search(message):
            attack_types.append(atype)
            from defensewatch.parsers.http import SEVERITY_ORDER
            if severity is None or SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(severity, 0):
                severity = sev

    if not attack_types:
        return None

    return HTTPEvent(
        timestamp=ts,
        source_ip=ip,
        method=method or "ERR",
        path=path or message[:100],
        http_version="",
        status_code=0,
        response_bytes=0,
        referer=None,
        user_agent=None,
        vhost=server,
        attack_types=attack_types,
        scanner_name=None,
        severity=severity,
        raw_line=line,
    )
