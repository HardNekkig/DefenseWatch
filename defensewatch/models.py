from dataclasses import dataclass, field


@dataclass
class SSHEvent:
    timestamp: float
    event_type: str
    username: str | None
    source_ip: str
    source_port: int | None
    auth_method: str | None
    hostname: str | None
    pid: int | None
    raw_line: str
    service_port: int | None = None
    event_count: int = 1
    ip_id: int | None = None
    id: int | None = None
    created_at: float | None = None


@dataclass
class HTTPEvent:
    timestamp: float
    source_ip: str
    method: str
    path: str
    http_version: str
    status_code: int
    response_bytes: int
    referer: str | None
    user_agent: str | None
    vhost: str | None
    attack_types: list[str] = field(default_factory=list)
    scanner_name: str | None = None
    severity: str | None = None
    raw_line: str = ""
    service_port: int | None = None
    ua_class: str = ""
    event_count: int = 1
    ip_id: int | None = None
    id: int | None = None
    created_at: float | None = None


@dataclass
class ServiceEvent:
    """Generic event for SQL, mail, FTP, and other monitored services."""
    timestamp: float
    service_type: str       # mysql, postgresql, postfix, dovecot, vsftpd, proftpd
    event_type: str         # auth_failure, connection, relay_denied, etc.
    source_ip: str | None
    username: str | None = None
    detail: str | None = None
    severity: str | None = None
    service_port: int | None = None
    raw_line: str = ""
    ip_id: int | None = None
    id: int | None = None
    created_at: float | None = None


@dataclass
class IPIntel:
    ip: str
    rdns: str | None = None
    asn: str | None = None
    org: str | None = None
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    isp: str | None = None
    whois_raw: str | None = None
    source: str | None = None
    enriched_at: float | None = None
    id: int | None = None
    created_at: float | None = None


@dataclass
class BruteForceSession:
    source_ip: str
    session_start: float
    session_end: float
    attempt_count: int
    usernames_tried: list[str] = field(default_factory=list)
    event_type: str = "ssh_brute_force"
    status: str = "active"
    service_port: int | None = None
    ip_id: int | None = None
    id: int | None = None
    created_at: float | None = None
