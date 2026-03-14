import re
import time
import logging
from collections import defaultdict
from datetime import datetime
from defensewatch.models import HTTPEvent
from defensewatch.config import DetectionConfig
from defensewatch.parsers.ua_classifier import classify_user_agent

logger = logging.getLogger(__name__)

# Nginx combined log format
_COMBINED_RE = re.compile(
    r'^([\d.]+)\s+-\s+\S+\s+'
    r'\[([^\]]+)\]\s+'
    r'"(\S+)\s+(\S+)\s+(\S+)"\s+'
    r'(\d{3})\s+(\d+)\s+'
    r'"([^"]*)"\s+'
    r'"([^"]*)"'
)

_SCANNERS = {
    'zgrab': 'zgrab', 'nmap': 'nmap', 'nikto': 'nikto', 'sqlmap': 'sqlmap',
    'masscan': 'masscan', 'nuclei': 'nuclei', 'acunetix': 'acunetix',
    'burpsuite': 'burpsuite', 'dirbuster': 'dirbuster', 'gobuster': 'gobuster',
    'wfuzz': 'wfuzz', 'shodan': 'shodan', 'censys': 'censys',
    'qualys': 'qualys', 'nessus': 'nessus', 'openvas': 'openvas',
    'httpx': 'httpx', 'ffuf': 'ffuf', 'feroxbuster': 'feroxbuster',
    'curl/': 'curl', 'python-requests': 'python-requests', 'go-http-client': 'go-http-client',
    'wget': 'wget', 'libwww-perl': 'libwww-perl',
}

_ATTACK_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # Critical
    ('sqli', re.compile(r'(?:union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|select\s+.*\s+from|insert\s+into|drop\s+table|;\s*select|%27|\'.*(?:or|and|union|select))', re.I), 'critical'),
    ('webshell', re.compile(r'(?:eval\s*\(|base64_decode|system\s*\(|passthru|shell_exec|\.php\?cmd=|\.php\?c=|\.asp\?cmd=|backdoor|c99|r57)', re.I), 'critical'),
    ('log4shell', re.compile(r'\$\{jndi:', re.I), 'critical'),

    # High
    ('path_traversal', re.compile(r'(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self|/proc/version|%2e%2e)', re.I), 'high'),
    ('rce', re.compile(r'(?:;.*(?:cat|ls|id|whoami|wget|curl|bash|sh|nc|ncat|python|perl|ruby|php)\b|\|.*\b(?:cat|ls|id|whoami|wget|curl|bash|sh)\b|`[^`]+`)', re.I), 'high'),
    ('credential_probe', re.compile(r'(?:\.env|\.git/|\.htpasswd|\.htaccess|wp-config\.php|config\.yml|config\.json|\.aws/|\.ssh/|id_rsa|\.DS_Store)', re.I), 'high'),

    # Medium
    ('cms_probe', re.compile(r'(?:wp-login|wp-admin|xmlrpc\.php|wp-content|wp-includes|/administrator|/joomla|/drupal|/magento)', re.I), 'medium'),
    ('ssrf', re.compile(r'(?:gopher://|dict://|file://|localhost|127\.0\.0\.1|169\.254\.169\.254|0x7f)', re.I), 'medium'),
    ('actuator_probe', re.compile(r'(?:/actuator|/swagger|/api-docs|/metrics|/prometheus|/health(?:check)?|/debug|/trace|/info|/beans|/configprops)', re.I), 'medium'),

    # Low
    ('endpoint_enum', re.compile(r'(?:/admin|/phpmyadmin|/pma|/myadmin|/manager|/console|/solr|/jenkins|/\.bak|\.sql$|\.tar\.gz$|/backup|/dump|/test|/debug|/status|/server-status)', re.I), 'low'),
]

# Suspicious HTTP methods
_SUSPICIOUS_METHODS = {'PROPFIND', 'TRACE', 'TRACK', 'MKCOL', 'COPY', 'MOVE',
                       'LOCK', 'UNLOCK', 'PROPPATCH', 'SEARCH'}

# Encoding obfuscation patterns
_OBFUSCATION_RE = re.compile(
    r'(?:%00|%0[aAdD]|%25[0-9a-fA-F]{2}|'   # null bytes, double encoding
    r'\\x[0-9a-fA-F]{2}|'                      # hex escapes
    r'%u[0-9a-fA-F]{4}|'                       # unicode encoding
    r'(?:\/\.){3,})',                           # excessive dot segments
    re.I
)

# Host header poisoning patterns
_HOST_POISON_RE = re.compile(
    r'(?:127\.0\.0\.1|localhost|0\.0\.0\.0|'
    r'\[::1\]|'
    r'169\.254\.\d+\.\d+|'
    r'10\.\d+\.\d+\.\d+|'
    r'192\.168\.\d+\.\d+)',
    re.I
)

SEVERITY_ORDER = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}


def detect_scanner(user_agent: str) -> str | None:
    ua_lower = user_agent.lower()
    for keyword, name in _SCANNERS.items():
        if keyword in ua_lower:
            return name
    return None


def detect_attacks(path: str, query: str = '', user_agent: str = '',
                   method: str = '', host: str = '',
                   status_code: int | None = None) -> tuple[list[str], str | None]:
    combined = f"{path}?{query} {user_agent}"
    found_types = []
    max_severity = None

    for attack_type, pattern, severity in _ATTACK_PATTERNS:
        if pattern.search(combined):
            found_types.append(attack_type)
            if max_severity is None or SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(max_severity, 0):
                max_severity = severity

    # Suspicious HTTP method detection
    if method.upper() in _SUSPICIOUS_METHODS:
        found_types.append('method_anomaly')
        if max_severity is None or SEVERITY_ORDER.get('medium', 0) > SEVERITY_ORDER.get(max_severity, 0):
            max_severity = 'medium'

    # Encoding obfuscation
    if _OBFUSCATION_RE.search(path):
        found_types.append('encoding_obfuscation')
        if max_severity is None or SEVERITY_ORDER.get('medium', 0) > SEVERITY_ORDER.get(max_severity, 0):
            max_severity = 'medium'

    # Host header poisoning
    if host and _HOST_POISON_RE.search(host):
        found_types.append('host_header_poison')
        if max_severity is None or SEVERITY_ORDER.get('medium', 0) > SEVERITY_ORDER.get(max_severity, 0):
            max_severity = 'medium'

    return found_types, max_severity


class HTTPScanTracker:
    """Rate-based 404 enumeration detection."""

    def __init__(self, config: DetectionConfig):
        self.threshold = config.http_scan_threshold
        self.window = config.http_scan_window_seconds
        self._404_attempts: dict[str, list[float]] = defaultdict(list)

    def track(self, ip: str, status_code: int, timestamp: float) -> bool:
        """Track 404s per IP. Returns True if threshold exceeded (scan detected)."""
        if status_code != 404:
            return False

        attempts = self._404_attempts[ip]
        attempts.append(timestamp)

        cutoff = timestamp - self.window
        self._404_attempts[ip] = [t for t in attempts if t >= cutoff]

        return len(self._404_attempts[ip]) >= self.threshold

    def cleanup(self):
        now = time.time()
        cutoff = now - self.window
        stale = [ip for ip, att in self._404_attempts.items()
                 if not att or att[-1] < cutoff]
        for ip in stale:
            del self._404_attempts[ip]


def parse_http_line(line: str, vhost: str | None = None) -> HTTPEvent | None:
    line = line.strip()
    if not line:
        return None

    m = _COMBINED_RE.match(line)
    if not m:
        return None

    ip, ts_str, method, path, http_ver, status, size, referer, ua = m.groups()

    try:
        ts = datetime.strptime(ts_str, '%d/%b/%Y:%H:%M:%S %z').timestamp()
    except ValueError:
        return None

    scanner = detect_scanner(ua)
    attack_types, severity = detect_attacks(
        path, user_agent=ua, method=method, status_code=int(status))

    # Classify user agent
    ua_class = classify_user_agent(ua)

    # If scanner detected but no attack, still mark as low
    if scanner and not attack_types:
        attack_types = ['scanner']
        severity = 'low'

    return HTTPEvent(
        timestamp=ts,
        source_ip=ip,
        method=method,
        path=path,
        http_version=http_ver,
        status_code=int(status),
        response_bytes=int(size),
        referer=referer if referer != '-' else None,
        user_agent=ua if ua != '-' else None,
        vhost=vhost,
        attack_types=attack_types,
        scanner_name=scanner,
        severity=severity,
        raw_line=line,
        ua_class=ua_class,
    )
