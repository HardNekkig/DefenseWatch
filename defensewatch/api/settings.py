import logging
import os
import yaml
from pathlib import Path

from fastapi import APIRouter
from pydantic import BaseModel
from defensewatch.audit import log_audit

logger = logging.getLogger(__name__)

# ── .env persistence helpers ─────────────────────────────────────────

_ENV_PATH = Path(".env")


def _read_env_lines() -> list[str]:
    """Read .env file lines, or return empty list if missing."""
    if _ENV_PATH.exists():
        return _ENV_PATH.read_text().splitlines(keepends=True)
    return []


def _set_env_value(key: str, value: str):
    """Set a key=value in the .env file, updating if exists or appending."""
    lines = _read_env_lines()
    found = False
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(f"{key}=") or stripped == key:
            new_lines.append(f"{key}={value}\n")
            found = True
        else:
            new_lines.append(line if line.endswith("\n") else line + "\n")
    if not found:
        new_lines.append(f"{key}={value}\n")
    _ENV_PATH.write_text("".join(new_lines))
    # Also update the running process environment
    os.environ[key] = value

router = APIRouter(prefix="/api/settings", tags=["settings"])

_config = None


def set_settings_config(config):
    global _config
    _config = config


# ── Models ────────────────────────────────────────────────────

class WebhookSettings(BaseModel):
    notifications_enabled: bool | None = None
    webhook_url: str | None = None
    min_severity: str | None = None
    cooldown_seconds: int | None = None
    notify_events: list[str] | None = None
    reports_enabled: bool | None = None
    reports_interval_hours: int | None = None
    reports_webhook_url: str | None = None


class ApiKeySettings(BaseModel):
    abuseipdb_api_key: str | None = None
    otx_api_key: str | None = None
    shodan_api_key: str | None = None
    virustotal_api_key: str | None = None
    censys_api_id: str | None = None
    censys_api_secret: str | None = None
    threat_intel_enabled: bool | None = None
    threat_intel_refresh_hours: int | None = None


class ServiceEntry(BaseModel):
    service_type: str  # ssh, http, mysql, postgresql, mail, ftp
    path: str
    port: int | None = None
    vhost: str | None = None


class ServiceRemove(BaseModel):
    service_type: str
    path: str


class DetectionSettings(BaseModel):
    ssh_brute_threshold: int | None = None
    ssh_brute_window_seconds: int | None = None
    http_scan_threshold: int | None = None
    http_scan_window_seconds: int | None = None
    portscan_threshold: int | None = None
    portscan_window_seconds: int | None = None


class GeneralSettings(BaseModel):
    host_name: str | None = None
    host_latitude: float | None = None
    host_longitude: float | None = None
    database_retention_days: int | None = None
    enrichment_whois_enabled: bool | None = None
    geoip_re_enrich_days: int | None = None


# ── Endpoints ─────────────────────────────────────────────────

@router.get("/status")
async def settings_status():
    if not _config:
        return {"error": "Config not loaded"}

    c = _config
    default_ports = {"ssh": 22, "http": 80, "mysql": 3306, "postgresql": 5432, "mail": 25, "ftp": 21}

    services = {}
    for svc_type in ("ssh", "http", "mysql", "postgresql", "mail", "ftp"):
        entries_method = getattr(c.logs, f"{svc_type}_entries", None)
        if entries_method:
            services[svc_type] = [
                {"path": e.path, "port": e.port, "vhost": e.vhost, "default_port": default_ports.get(svc_type)}
                for e in entries_method()
            ]
        else:
            services[svc_type] = []

    return {
        "general": {
            "host_name": c.host.name,
            "host_latitude": c.host.latitude,
            "host_longitude": c.host.longitude,
            "database_retention_days": c.database.retention_days,
            "enrichment_whois_enabled": c.enrichment.whois_enabled,
            "geoip_re_enrich_days": c.geoip.re_enrich_after_days,
        },
        "webhooks": {
            "notifications_enabled": c.notifications.enabled,
            "webhook_url": c.notifications.webhook_url,
            "min_severity": c.notifications.min_severity,
            "cooldown_seconds": c.notifications.cooldown_seconds,
            "notify_events": c.notifications.notify_events,
            "reports_enabled": c.reports.enabled,
            "reports_interval_hours": c.reports.interval_hours,
            "reports_webhook_url": c.reports.webhook_url,
        },
        "api_keys": {
            "threat_intel_enabled": c.threat_intel.enabled,
            "threat_intel_refresh_hours": c.threat_intel.refresh_interval_hours,
            "abuseipdb_api_key_set": bool(c.threat_intel.abuseipdb_api_key),
            "otx_api_key_set": bool(c.threat_intel.otx_api_key),
            "shodan_api_key_set": bool(c.external_apis.shodan_api_key),
            "virustotal_api_key_set": bool(c.external_apis.virustotal_api_key),
            "censys_api_id_set": bool(c.external_apis.censys_api_id),
            "censys_api_secret_set": bool(c.external_apis.censys_api_secret),
        },
        "detection": {
            "ssh_brute_threshold": c.detection.ssh_brute_threshold,
            "ssh_brute_window_seconds": c.detection.ssh_brute_window_seconds,
            "http_scan_threshold": c.detection.http_scan_threshold,
            "http_scan_window_seconds": c.detection.http_scan_window_seconds,
            "portscan_threshold": c.detection.portscan_threshold,
            "portscan_window_seconds": c.detection.portscan_window_seconds,
        },
        "services": services,
    }


@router.patch("/general")
async def update_general(body: GeneralSettings):
    if not _config:
        return {"error": "Config not loaded"}

    if body.host_name is not None:
        _config.host.name = body.host_name
    if body.host_latitude is not None:
        _config.host.latitude = body.host_latitude
    if body.host_longitude is not None:
        _config.host.longitude = body.host_longitude
    if body.database_retention_days is not None:
        _config.database.retention_days = max(1, body.database_retention_days)
    if body.enrichment_whois_enabled is not None:
        _config.enrichment.whois_enabled = body.enrichment_whois_enabled
    if body.geoip_re_enrich_days is not None:
        _config.geoip.re_enrich_after_days = max(1, body.geoip_re_enrich_days)

    logger.info("General settings updated")
    _persist_config()
    await log_audit("settings_update", "general", "General settings updated", actor="api")
    return {"ok": True}


@router.patch("/webhooks")
async def update_webhooks(body: WebhookSettings):
    if not _config:
        return {"error": "Config not loaded"}

    nc = _config.notifications
    if body.notifications_enabled is not None:
        nc.enabled = body.notifications_enabled
    if body.webhook_url is not None:
        nc.webhook_url = body.webhook_url
        _set_env_value("DEFENSEWATCH_WEBHOOK_URL", body.webhook_url)
    if body.min_severity is not None and body.min_severity in ('low', 'medium', 'high', 'critical'):
        nc.min_severity = body.min_severity
    if body.cooldown_seconds is not None:
        nc.cooldown_seconds = max(0, body.cooldown_seconds)
    if body.notify_events is not None:
        from defensewatch.config import ALL_NOTIFY_EVENTS
        nc.notify_events = [e for e in body.notify_events if e in ALL_NOTIFY_EVENTS]

    rc = _config.reports
    if body.reports_enabled is not None:
        rc.enabled = body.reports_enabled
    if body.reports_interval_hours is not None:
        rc.interval_hours = max(1, body.reports_interval_hours)
    if body.reports_webhook_url is not None:
        rc.webhook_url = body.reports_webhook_url
        _set_env_value("DEFENSEWATCH_REPORTS_WEBHOOK_URL", body.reports_webhook_url)

    logger.info("Webhook settings updated")
    _persist_config()
    await log_audit("settings_update", "webhooks", "Webhook settings updated", actor="api")
    return {"ok": True}


@router.patch("/api-keys")
async def update_api_keys(body: ApiKeySettings):
    if not _config:
        return {"error": "Config not loaded"}

    ti = _config.threat_intel
    if body.threat_intel_enabled is not None:
        ti.enabled = body.threat_intel_enabled
    if body.threat_intel_refresh_hours is not None:
        ti.refresh_interval_hours = max(1, body.threat_intel_refresh_hours)
    if body.abuseipdb_api_key is not None:
        ti.abuseipdb_api_key = body.abuseipdb_api_key
        _set_env_value("DEFENSEWATCH_ABUSEIPDB_API_KEY", body.abuseipdb_api_key)
    if body.otx_api_key is not None:
        ti.otx_api_key = body.otx_api_key
        _set_env_value("DEFENSEWATCH_OTX_API_KEY", body.otx_api_key)

    ea = _config.external_apis
    if body.shodan_api_key is not None:
        ea.shodan_api_key = body.shodan_api_key
        _set_env_value("DEFENSEWATCH_SHODAN_API_KEY", body.shodan_api_key)
    if body.virustotal_api_key is not None:
        ea.virustotal_api_key = body.virustotal_api_key
        _set_env_value("DEFENSEWATCH_VIRUSTOTAL_API_KEY", body.virustotal_api_key)
    if body.censys_api_id is not None:
        ea.censys_api_id = body.censys_api_id
        _set_env_value("DEFENSEWATCH_CENSYS_API_ID", body.censys_api_id)
    if body.censys_api_secret is not None:
        ea.censys_api_secret = body.censys_api_secret
        _set_env_value("DEFENSEWATCH_CENSYS_API_SECRET", body.censys_api_secret)

    logger.info("API key settings updated")
    _persist_config()
    await log_audit("settings_update", "api_keys", "API key settings updated", actor="api")
    return {"ok": True}


@router.patch("/detection")
async def update_detection(body: DetectionSettings):
    if not _config:
        return {"error": "Config not loaded"}

    d = _config.detection
    if body.ssh_brute_threshold is not None:
        d.ssh_brute_threshold = max(1, body.ssh_brute_threshold)
    if body.ssh_brute_window_seconds is not None:
        d.ssh_brute_window_seconds = max(10, body.ssh_brute_window_seconds)
    if body.http_scan_threshold is not None:
        d.http_scan_threshold = max(1, body.http_scan_threshold)
    if body.http_scan_window_seconds is not None:
        d.http_scan_window_seconds = max(10, body.http_scan_window_seconds)
    if body.portscan_threshold is not None:
        d.portscan_threshold = max(2, body.portscan_threshold)
    if body.portscan_window_seconds is not None:
        d.portscan_window_seconds = max(10, body.portscan_window_seconds)

    logger.info("Detection settings updated")
    _persist_config()
    await log_audit("settings_update", "detection", "Detection settings updated", actor="api")
    return {"ok": True}


@router.post("/services")
async def add_service(body: ServiceEntry):
    if not _config:
        return {"error": "Config not loaded"}

    valid_types = ("ssh", "http", "mysql", "postgresql", "mail", "ftp")
    if body.service_type not in valid_types:
        return {"error": f"Invalid service type. Must be one of: {', '.join(valid_types)}"}

    log_list = getattr(_config.logs, body.service_type, None)
    if log_list is None:
        return {"error": f"Unknown service type: {body.service_type}"}

    # Check for duplicates
    for item in log_list:
        existing_path = item["path"] if isinstance(item, dict) else item
        if existing_path == body.path:
            return {"error": f"Path already monitored: {body.path}"}

    default_ports = {"ssh": 22, "http": 80, "mysql": 3306, "postgresql": 5432, "mail": 25, "ftp": 21}
    entry = {"path": body.path}
    port = body.port or default_ports.get(body.service_type)
    if port:
        entry["port"] = port
    if body.vhost:
        entry["vhost"] = body.vhost

    log_list.append(entry)
    logger.info(f"Added {body.service_type} service: {body.path} (port {port})")
    _persist_config()
    await log_audit("service_add", body.service_type, f"Added service: {body.path}", actor="api")
    return {"ok": True, "message": f"Added {body.service_type} service: {body.path}"}


@router.delete("/services")
async def remove_service(body: ServiceRemove):
    if not _config:
        return {"error": "Config not loaded"}

    log_list = getattr(_config.logs, body.service_type, None)
    if log_list is None:
        return {"error": f"Unknown service type: {body.service_type}"}

    new_list = []
    removed = False
    for item in log_list:
        item_path = item["path"] if isinstance(item, dict) else item
        if item_path == body.path:
            removed = True
        else:
            new_list.append(item)

    if not removed:
        return {"error": f"Path not found: {body.path}"}

    setattr(_config.logs, body.service_type, new_list)
    logger.info(f"Removed {body.service_type} service: {body.path}")
    _persist_config()
    await log_audit("service_remove", body.service_type, f"Removed service: {body.path}", actor="api")
    return {"ok": True, "message": f"Removed {body.service_type} service: {body.path}"}


def _persist_config():
    """Write current runtime config to config.yaml (fire-and-forget)."""
    if not _config:
        return
    try:
        _write_config_to_disk()
    except Exception as e:
        logger.error(f"Auto-save config failed: {e}")


def _write_config_to_disk():
    """Write non-secret config to config.yaml. Secrets stay in .env only."""
    config_path = Path("config.yaml")
    data = {
        "server": {"host": _config.server.host, "port": _config.server.port},
        "logs": {},
        "detection": {
            "ssh_brute_threshold": _config.detection.ssh_brute_threshold,
            "ssh_brute_window_seconds": _config.detection.ssh_brute_window_seconds,
            "http_scan_threshold": _config.detection.http_scan_threshold,
            "http_scan_window_seconds": _config.detection.http_scan_window_seconds,
            "portscan_threshold": _config.detection.portscan_threshold,
            "portscan_window_seconds": _config.detection.portscan_window_seconds,
        },
        "geoip": {
            "mmdb_path": _config.geoip.mmdb_path,
            "fallback_api": _config.geoip.fallback_api,
            "re_enrich_after_days": _config.geoip.re_enrich_after_days,
        },
        "host": {
            "name": _config.host.name,
            "latitude": _config.host.latitude,
            "longitude": _config.host.longitude,
        },
        "database": {
            "path": _config.database.path,
            "wal_mode": _config.database.wal_mode,
            "retention_days": _config.database.retention_days,
        },
        "enrichment": {
            "max_queue_size": _config.enrichment.max_queue_size,
            "worker_count": _config.enrichment.worker_count,
            "whois_enabled": _config.enrichment.whois_enabled,
        },
        "notifications": {
            "enabled": _config.notifications.enabled,
            "webhook_url": "",
            "min_severity": _config.notifications.min_severity,
            "cooldown_seconds": _config.notifications.cooldown_seconds,
            "notify_events": _config.notifications.notify_events,
        },
        "telegram": {
            "enabled": _config.telegram.enabled,
            "bot_token": "",
            "chat_ids": [],
            "min_severity": _config.telegram.min_severity,
            "cooldown_seconds": _config.telegram.cooldown_seconds,
            "notify_events": _config.telegram.notify_events,
            "daily_reports": _config.telegram.daily_reports,
            "weekly_reports": _config.telegram.weekly_reports,
            "report_hour": _config.telegram.report_hour,
        },
        "threat_intel": {
            "enabled": _config.threat_intel.enabled,
            "refresh_interval_hours": _config.threat_intel.refresh_interval_hours,
            "abuseipdb_api_key": "",
            "otx_api_key": "",
        },
        "reports": {
            "enabled": _config.reports.enabled,
            "interval_hours": _config.reports.interval_hours,
            "webhook_url": "",
        },
        "nuclei": {
            "enabled": _config.nuclei.enabled,
            "docker_image": _config.nuclei.docker_image,
            "severity_filter": _config.nuclei.severity_filter,
            "rate_limit": _config.nuclei.rate_limit,
            "timeout_minutes": _config.nuclei.timeout_minutes,
            "extra_args": _config.nuclei.extra_args,
        },
        "firewall": {
            "auto_block_enabled": _config.firewall.auto_block_enabled,
            "ssh_block_threshold": _config.firewall.ssh_block_threshold,
            "brute_session_block_threshold": _config.firewall.brute_session_block_threshold,
            "http_block_threshold": _config.firewall.http_block_threshold,
            "score_block_threshold": _config.firewall.score_block_threshold,
            "auto_block_window_seconds": _config.firewall.auto_block_window_seconds,
            "auto_block_duration_hours": _config.firewall.auto_block_duration_hours,
            "check_interval_seconds": _config.firewall.check_interval_seconds,
            "whitelist": _config.firewall.whitelist,
        },
        "external_apis": {
            "shodan_api_key": "",
            "virustotal_api_key": "",
            "censys_api_id": "",
            "censys_api_secret": "",
        },
        "auth": {
            "enabled": _config.auth.enabled,
            "jwt_secret": "",
            "token_expiry_hours": _config.auth.token_expiry_hours,
            "refresh_expiry_hours": _config.auth.refresh_expiry_hours,
        },
        "honeypot": {
            "enabled": _config.honeypot.enabled,
            "paths": _config.honeypot.paths,
            "auto_block": _config.honeypot.auto_block,
            "score_boost": _config.honeypot.score_boost,
        },
        "blocklists": {
            "enabled": _config.blocklists.enabled,
            "refresh_interval_hours": _config.blocklists.refresh_interval_hours,
            "lists": _config.blocklists.lists,
            "auto_block": _config.blocklists.auto_block,
        },
        "correlation": {
            "enabled": _config.correlation.enabled,
            "check_interval_seconds": _config.correlation.check_interval_seconds,
            "lookback_seconds": _config.correlation.lookback_seconds,
            "min_score_for_incident": _config.correlation.min_score_for_incident,
            "rules": _config.correlation.rules,
        },
        "playbooks": {
            "enabled": _config.playbooks.enabled,
            "check_interval_seconds": _config.playbooks.check_interval_seconds,
            "rules": _config.playbooks.rules,
        },
        "geo_policy": {
            "enabled": _config.geo_policy.enabled,
            "mode": _config.geo_policy.mode,
            "countries": _config.geo_policy.countries,
            "action": _config.geo_policy.action,
            "block_duration_hours": _config.geo_policy.block_duration_hours,
            "exempt_ips": _config.geo_policy.exempt_ips,
        },
        "health_monitor": {
            "enabled": _config.health_monitor.enabled,
            "sample_interval_seconds": _config.health_monitor.sample_interval_seconds,
            "ring_buffer_size": _config.health_monitor.ring_buffer_size,
            "deadman_threshold_seconds": _config.health_monitor.deadman_threshold_seconds,
        },
        "dedup": {
            "enabled": _config.dedup.enabled,
            "ssh_window_seconds": _config.dedup.ssh_window_seconds,
            "http_window_seconds": _config.dedup.http_window_seconds,
            "max_batch_size": _config.dedup.max_batch_size,
        },
    }

    # Build logs section
    for svc_type in ("ssh", "http", "mysql", "postgresql", "mail", "ftp"):
        raw_list = getattr(_config.logs, svc_type, [])
        if raw_list:
            data["logs"][svc_type] = []
            for item in raw_list:
                if isinstance(item, dict):
                    data["logs"][svc_type].append(item)
                else:
                    data["logs"][svc_type].append(str(item))
        else:
            data["logs"][svc_type] = []

    with open(config_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    logger.info("Configuration saved to config.yaml")


@router.post("/save-config")
async def save_config_to_file():
    """Persist current runtime config to config.yaml."""
    if not _config:
        return {"error": "Config not loaded"}
    try:
        _write_config_to_disk()
        return {"ok": True, "message": "Configuration saved to config.yaml"}
    except Exception as e:
        logger.error(f"Failed to save config: {e}")
        return {"error": f"Failed to save configuration: {e}"}
