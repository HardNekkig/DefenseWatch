import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8080


@dataclass
class LogEntry:
    """A log file path with its associated service port and optional vhost."""
    path: str
    port: int | None = None
    vhost: str | None = None


@dataclass
class LogsConfig:
    ssh: list[str] = field(default_factory=lambda: ["/var/log/auth.log"])
    http: list[str] = field(default_factory=list)
    nginx_error: list[str] = field(default_factory=list)
    mysql: list[str] = field(default_factory=list)
    postgresql: list[str] = field(default_factory=list)
    mail: list[str] = field(default_factory=list)
    ftp: list[str] = field(default_factory=list)
    netfilter: list[str] = field(default_factory=list)

    def ssh_entries(self) -> list[LogEntry]:
        return _normalize_log_entries(self.ssh, default_port=22)

    def http_entries(self) -> list[LogEntry]:
        return _normalize_log_entries(self.http, default_port=80)

    def nginx_error_entries(self) -> list[LogEntry]:
        return _normalize_log_entries(self.nginx_error, default_port=80)

    def mysql_entries(self) -> list[LogEntry]:
        return _normalize_log_entries(self.mysql, default_port=3306)

    def postgresql_entries(self) -> list[LogEntry]:
        return _normalize_log_entries(self.postgresql, default_port=5432)

    def mail_entries(self) -> list[LogEntry]:
        return _normalize_log_entries(self.mail, default_port=25)

    def ftp_entries(self) -> list[LogEntry]:
        return _normalize_log_entries(self.ftp, default_port=21)

    def netfilter_entries(self) -> list[LogEntry]:
        return _normalize_log_entries(self.netfilter, default_port=None)


def _normalize_log_entries(items: list, default_port: int) -> list[LogEntry]:
    """Accept both plain strings and {path, port, vhost} dicts."""
    entries = []
    for item in items:
        if isinstance(item, str):
            vhost = _extract_vhost_from_path(item)
            entries.append(LogEntry(path=item, port=default_port, vhost=vhost))
        elif isinstance(item, dict):
            # Explicit vhost in config takes precedence over extracted vhost
            vhost = item.get("vhost") or _extract_vhost_from_path(item["path"])
            entries.append(LogEntry(
                path=item["path"],
                port=item.get("port", default_port),
                vhost=vhost,
            ))
        else:
            entries.append(LogEntry(path=str(item), port=default_port))
    return entries


def _extract_vhost_from_path(path: str) -> str | None:
    """Extract vhost from log filename (e.g., example.com.access.log -> example.com)."""
    from pathlib import Path
    name = Path(path).name
    if name == 'access.log':
        return None
    # e.g. example.com.access.log -> example.com
    # e.g. mysite.org-access.log -> mysite.org
    for sep in ('.access.log', '-access.log'):
        if name.endswith(sep):
            return name[:-len(sep)]
    return None


@dataclass
class DetectionConfig:
    ssh_brute_threshold: int = 5
    ssh_brute_window_seconds: int = 300
    http_scan_threshold: int = 20
    http_scan_window_seconds: int = 60
    portscan_threshold: int = 2        # distinct ports to trigger detection (2 = more sensitive to internet scanners)
    portscan_window_seconds: int = 300  # time window for port scan detection


@dataclass
class GeoIPConfig:
    mmdb_path: str = "data/GeoLite2-City.mmdb"
    fallback_api: str = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,isp,org,as,asname,reverse"
    re_enrich_after_days: int = 7


@dataclass
class HostConfig:
    name: str = "localhost"
    latitude: float | None = None
    longitude: float | None = None


@dataclass
class DatabaseConfig:
    path: str = "data/defensewatch.db"
    wal_mode: bool = True
    retention_days: int = 30


@dataclass
class EnrichmentConfig:
    max_queue_size: int = 1000
    worker_count: int = 3
    whois_enabled: bool = True


ALL_NOTIFY_EVENTS = ["brute_force", "http_attack", "anomaly", "firewall_block", "port_scan"]


@dataclass
class NotificationConfig:
    enabled: bool = False
    webhook_url: str = ""
    min_severity: str = "high"  # low, medium, high, critical
    cooldown_seconds: int = 300
    notify_events: list[str] = field(default_factory=lambda: list(ALL_NOTIFY_EVENTS))


@dataclass
class TelegramConfig:
    enabled: bool = False
    bot_token: str = ""
    chat_ids: list[str] = field(default_factory=list)
    min_severity: str = "high"  # low, medium, high, critical
    cooldown_seconds: int = 300
    daily_reports: bool = False
    weekly_reports: bool = False
    report_hour: int = 8  # hour of day (0-23) to send reports
    notify_events: list[str] = field(default_factory=lambda: list(ALL_NOTIFY_EVENTS))


@dataclass
class ThreatIntelConfig:
    enabled: bool = False
    refresh_interval_hours: int = 6
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""


@dataclass
class ReportsConfig:
    enabled: bool = False
    interval_hours: int = 24
    webhook_url: str = ""


@dataclass
class NucleiConfig:
    enabled: bool = False
    docker_image: str = "projectdiscovery/nuclei:latest"
    severity_filter: str = ""  # e.g. "low,medium,high,critical"
    rate_limit: int = 150
    timeout_minutes: int = 30
    extra_args: list[str] = field(default_factory=list)


@dataclass
class FirewallConfig:
    auto_block_enabled: bool = False
    ssh_block_threshold: int = 20       # failed attempts within window
    brute_session_block_threshold: int = 3  # brute force sessions within window
    http_block_threshold: int = 100     # HTTP attack events within window
    score_block_threshold: int = 70     # threat score (0-100) to trigger block
    auto_block_window_seconds: int = 3600
    auto_block_duration_hours: int = 0  # 0 = permanent
    check_interval_seconds: int = 300
    whitelist: list[str] = field(default_factory=lambda: ["127.0.0.1", "::1"])


@dataclass
class ExternalAPIsConfig:
    shodan_api_key: str = ""
    virustotal_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""


@dataclass
class AuthConfig:
    enabled: bool = False
    jwt_secret: str = ""
    token_expiry_hours: int = 24
    refresh_expiry_hours: int = 168  # 7 days


DEFAULT_HONEYPOT_PATHS: list[str] = [
    "/.env", "/wp-login.php", "/wp-admin", "/phpmyadmin",
    "/admin", "/administrator", "/.git/config", "/config.php",
    "/xmlrpc.php", "/wp-config.php", "/backup.sql", "/.aws/credentials",
    "/actuator", "/solr/admin", "/manager/html", "/cgi-bin/",
]


@dataclass
class HoneypotConfig:
    enabled: bool = True
    paths: list[str] = field(default_factory=lambda: list(DEFAULT_HONEYPOT_PATHS))
    auto_block: bool = False
    score_boost: int = 25


@dataclass
class BlocklistConfig:
    enabled: bool = False
    refresh_interval_hours: int = 6
    lists: list[str] = field(
        default_factory=lambda: ["spamhaus_drop", "spamhaus_edrop", "dshield", "firehol_level1"],
    )
    auto_block: bool = False


@dataclass
class CorrelationConfig:
    enabled: bool = False
    check_interval_seconds: int = 300
    lookback_seconds: int = 3600
    min_score_for_incident: int = 60
    rules: list[str] = field(default_factory=lambda: [
        "coordinated_attack",
        "brute_then_exploit",
        "recon_to_attack",
        "multi_service",
    ])


@dataclass
class PlaybookConfig:
    enabled: bool = False
    check_interval_seconds: int = 60
    rules: list[dict] = field(default_factory=lambda: [
        {
            "name": "high_score_block",
            "description": "Block IPs with threat score >= 80",
            "condition": {"min_score": 80},
            "actions": ["block_24h", "create_incident", "notify"],
            "cooldown_seconds": 3600,
        },
        {
            "name": "honeypot_repeat_offender",
            "description": "Block IPs with 3+ honeypot hits",
            "condition": {"min_honeypot_hits": 3},
            "actions": ["block_permanent", "create_incident"],
            "cooldown_seconds": 3600,
        },
        {
            "name": "brute_force_escalation",
            "description": "Block IPs with 2+ brute force sessions",
            "condition": {"min_brute_sessions": 2},
            "actions": ["block_24h", "notify"],
            "cooldown_seconds": 1800,
        },
    ])


@dataclass
class GeoPolicyConfig:
    enabled: bool = False
    mode: str = "blacklist"
    countries: list[str] = field(default_factory=list)
    action: str = "block"
    block_duration_hours: int = 0
    exempt_ips: list[str] = field(default_factory=list)


@dataclass
class HealthMonitorConfig:
    enabled: bool = True
    sample_interval_seconds: int = 60
    ring_buffer_size: int = 1440
    deadman_threshold_seconds: int = 600


@dataclass
class DedupConfig:
    enabled: bool = False
    ssh_window_seconds: int = 60
    http_window_seconds: int = 60
    max_batch_size: int = 100


@dataclass
class AppConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    logs: LogsConfig = field(default_factory=LogsConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    geoip: GeoIPConfig = field(default_factory=GeoIPConfig)
    host: HostConfig = field(default_factory=HostConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    enrichment: EnrichmentConfig = field(default_factory=EnrichmentConfig)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    reports: ReportsConfig = field(default_factory=ReportsConfig)
    nuclei: NucleiConfig = field(default_factory=NucleiConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    external_apis: ExternalAPIsConfig = field(default_factory=ExternalAPIsConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    honeypot: HoneypotConfig = field(default_factory=HoneypotConfig)
    blocklists: BlocklistConfig = field(default_factory=BlocklistConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    playbooks: PlaybookConfig = field(default_factory=PlaybookConfig)
    geo_policy: GeoPolicyConfig = field(default_factory=GeoPolicyConfig)
    health_monitor: HealthMonitorConfig = field(default_factory=HealthMonitorConfig)
    dedup: DedupConfig = field(default_factory=DedupConfig)


def _dict_to_dataclass(cls, data: dict):
    if data is None:
        return cls()
    fieldnames = {f.name for f in cls.__dataclass_fields__.values()}
    filtered = {k: v for k, v in data.items() if k in fieldnames}
    return cls(**filtered)


def load_config(path: str = "config.yaml") -> AppConfig:
    config_path = Path(path)
    if not config_path.exists():
        return AppConfig()

    with open(config_path) as f:
        raw = yaml.safe_load(f) or {}

    config = AppConfig(
        server=_dict_to_dataclass(ServerConfig, raw.get("server")),
        logs=_dict_to_dataclass(LogsConfig, raw.get("logs")),
        detection=_dict_to_dataclass(DetectionConfig, raw.get("detection")),
        geoip=_dict_to_dataclass(GeoIPConfig, raw.get("geoip")),
        host=_dict_to_dataclass(HostConfig, raw.get("host")),
        database=_dict_to_dataclass(DatabaseConfig, raw.get("database")),
        enrichment=_dict_to_dataclass(EnrichmentConfig, raw.get("enrichment")),
        notifications=_dict_to_dataclass(NotificationConfig, raw.get("notifications")),
        telegram=_dict_to_dataclass(TelegramConfig, raw.get("telegram")),
        threat_intel=_dict_to_dataclass(ThreatIntelConfig, raw.get("threat_intel")),
        reports=_dict_to_dataclass(ReportsConfig, raw.get("reports")),
        nuclei=_dict_to_dataclass(NucleiConfig, raw.get("nuclei")),
        firewall=_dict_to_dataclass(FirewallConfig, raw.get("firewall")),
        external_apis=_dict_to_dataclass(ExternalAPIsConfig, raw.get("external_apis")),
        auth=_dict_to_dataclass(AuthConfig, raw.get("auth")),
        honeypot=_dict_to_dataclass(HoneypotConfig, raw.get("honeypot")),
        blocklists=_dict_to_dataclass(BlocklistConfig, raw.get("blocklists")),
        correlation=_dict_to_dataclass(CorrelationConfig, raw.get("correlation")),
        playbooks=_dict_to_dataclass(PlaybookConfig, raw.get("playbooks")),
        geo_policy=_dict_to_dataclass(GeoPolicyConfig, raw.get("geo_policy")),
        health_monitor=_dict_to_dataclass(HealthMonitorConfig, raw.get("health_monitor")),
        dedup=_dict_to_dataclass(DedupConfig, raw.get("dedup")),
    )

    # Environment variables override config file for sensitive API keys
    env_overrides = {
        "DEFENSEWATCH_SHODAN_API_KEY": "shodan_api_key",
        "DEFENSEWATCH_VIRUSTOTAL_API_KEY": "virustotal_api_key",
        "DEFENSEWATCH_CENSYS_API_ID": "censys_api_id",
        "DEFENSEWATCH_CENSYS_API_SECRET": "censys_api_secret",
    }
    for env_var, attr in env_overrides.items():
        val = os.environ.get(env_var)
        if val:
            setattr(config.external_apis, attr, val)

    webhook = os.environ.get("DEFENSEWATCH_WEBHOOK_URL")
    if webhook:
        config.notifications.webhook_url = webhook
        config.notifications.enabled = True

    # Threat intel API keys from env
    abuseipdb_key = os.environ.get("DEFENSEWATCH_ABUSEIPDB_API_KEY")
    if abuseipdb_key:
        config.threat_intel.abuseipdb_api_key = abuseipdb_key
    otx_key = os.environ.get("DEFENSEWATCH_OTX_API_KEY")
    if otx_key:
        config.threat_intel.otx_api_key = otx_key

    # Reports webhook from env
    reports_webhook = os.environ.get("DEFENSEWATCH_REPORTS_WEBHOOK_URL")
    if reports_webhook:
        config.reports.webhook_url = reports_webhook
        config.reports.enabled = True

    # Telegram from env
    tg_token = os.environ.get("DEFENSEWATCH_TELEGRAM_BOT_TOKEN")
    if tg_token:
        config.telegram.bot_token = tg_token
    tg_chats = os.environ.get("DEFENSEWATCH_TELEGRAM_CHAT_IDS")
    if tg_chats:
        config.telegram.chat_ids = [c.strip() for c in tg_chats.split(",") if c.strip()]
    if tg_token and tg_chats:
        config.telegram.enabled = True

    # Auth JWT secret from env
    jwt_secret = os.environ.get("DEFENSEWATCH_JWT_SECRET")
    if jwt_secret:
        config.auth.jwt_secret = jwt_secret

    return config
