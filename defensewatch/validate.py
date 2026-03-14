"""Configuration validation and dry-run checks for DefenseWatch."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import socket
from pathlib import Path

import aiosqlite

from defensewatch.config import AppConfig

logger = logging.getLogger(__name__)

CheckResult = dict[str, str]


def _result(check: str, target: str, status: str, message: str) -> CheckResult:
    return {"check": check, "target": target, "status": status, "message": message}


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_log_files(config: AppConfig) -> list[CheckResult]:
    """Check that configured log files exist and are readable."""
    results: list[CheckResult] = []
    entries = (
        config.logs.ssh_entries()
        + config.logs.http_entries()
        + config.logs.nginx_error_entries()
        + config.logs.mysql_entries()
        + config.logs.postgresql_entries()
        + config.logs.mail_entries()
        + config.logs.ftp_entries()
    )
    for entry in entries:
        p = Path(entry.path)
        if not p.exists():
            results.append(_result(
                "log_file_exists", entry.path, "warning",
                "File does not exist (may appear later)"))
        elif not os.access(entry.path, os.R_OK):
            results.append(_result(
                "log_file_readable", entry.path, "error",
                "File exists but is not readable (check permissions)"))
        elif p.stat().st_size == 0:
            results.append(_result(
                "log_file_nonempty", entry.path, "warning",
                "File exists and is readable but is empty"))
        else:
            results.append(_result(
                "log_file_readable", entry.path, "ok",
                "File exists and is readable"))
    return results


async def _check_database(config: AppConfig) -> list[CheckResult]:
    """Check that the database path is writable and connectable."""
    results: list[CheckResult] = []
    db_path = Path(config.database.path)
    parent = db_path.parent

    # Check parent directory
    if not parent.exists():
        results.append(_result(
            "database_dir", str(parent), "error",
            "Database directory does not exist"))
        return results

    if not os.access(str(parent), os.W_OK):
        results.append(_result(
            "database_dir_writable", str(parent), "error",
            "Database directory is not writable"))
        return results

    results.append(_result(
        "database_dir_writable", str(parent), "ok",
        "Database directory exists and is writable"))

    # Try connecting
    try:
        async with aiosqlite.connect(str(db_path)) as db:
            await db.execute("SELECT 1")
        results.append(_result(
            "database_connect", str(db_path), "ok",
            "Successfully connected to database"))
    except Exception as exc:
        results.append(_result(
            "database_connect", str(db_path), "error",
            f"Cannot connect to database: {exc}"))
    return results


def _check_geoip(config: AppConfig) -> list[CheckResult]:
    """Check that the GeoIP mmdb file exists."""
    mmdb = Path(config.geoip.mmdb_path)
    if mmdb.exists():
        return [_result("geoip_database", config.geoip.mmdb_path, "ok",
                        "GeoIP database file exists")]
    return [_result("geoip_database", config.geoip.mmdb_path, "warning",
                    "GeoIP database file not found (will use fallback API)")]


def _check_api_keys(config: AppConfig) -> list[CheckResult]:
    """Check API key validity when features require them."""
    results: list[CheckResult] = []

    # Threat intel
    if config.threat_intel.enabled:
        has_abuseipdb = bool(config.threat_intel.abuseipdb_api_key.strip())
        has_otx = bool(config.threat_intel.otx_api_key.strip())
        if not has_abuseipdb and not has_otx:
            results.append(_result(
                "api_key_threat_intel", "threat_intel",
                "warning",
                "Threat intel is enabled but no API keys (AbuseIPDB / OTX) are configured"))
        else:
            if has_abuseipdb:
                results.append(_result(
                    "api_key_abuseipdb", "abuseipdb_api_key", "ok",
                    "AbuseIPDB API key is configured"))
            if has_otx:
                results.append(_result(
                    "api_key_otx", "otx_api_key", "ok",
                    "OTX API key is configured"))

    # External APIs (informational)
    ext = config.external_apis
    for name, val in [("shodan", ext.shodan_api_key),
                      ("virustotal", ext.virustotal_api_key),
                      ("censys", ext.censys_api_id)]:
        if val.strip():
            results.append(_result(
                f"api_key_{name}", name, "ok",
                f"{name.capitalize()} API key is configured"))

    return results


def _check_nuclei(config: AppConfig) -> list[CheckResult]:
    """Check Docker availability when Nuclei scanner is enabled."""
    if not config.nuclei.enabled:
        return []

    if shutil.which("docker") is None:
        return [_result("nuclei_docker", "docker", "error",
                        "Nuclei is enabled but Docker is not available on PATH")]

    # Check docker is actually usable (daemon running)
    try:
        import subprocess
        proc = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=10)
        if proc.returncode != 0:
            return [_result("nuclei_docker", "docker", "warning",
                            "Docker is installed but the daemon may not be running")]
    except Exception:
        return [_result("nuclei_docker", "docker", "warning",
                        "Docker is installed but could not verify daemon status")]

    return [_result("nuclei_docker", "docker", "ok",
                    "Docker is available for Nuclei scanner")]


def _check_firewall(config: AppConfig) -> list[CheckResult]:
    """Check firewall backend availability when auto-block is enabled."""
    if not config.firewall.auto_block_enabled:
        return []

    from defensewatch.firewall import detect_backend
    backend = detect_backend()
    if backend:
        return [_result("firewall_backend", backend, "ok",
                        f"Firewall backend detected: {backend}")]
    return [_result("firewall_backend", "none", "error",
                    "Auto-block is enabled but no firewall backend (ufw/iptables/nftables) detected")]


def _check_port(config: AppConfig) -> list[CheckResult]:
    """Check if the configured server port is already in use."""
    host = config.server.host
    port = config.server.port
    target = f"{host}:{port}"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(("127.0.0.1", port))
        sock.close()
        if result == 0:
            return [_result("server_port", target, "warning",
                            f"Port {port} is already in use (may be this process)")]
        return [_result("server_port", target, "ok",
                        f"Port {port} is available")]
    except Exception as exc:
        return [_result("server_port", target, "warning",
                        f"Could not check port availability: {exc}")]


def _check_webhooks(config: AppConfig) -> list[CheckResult]:
    """Validate webhook URL format if notifications are enabled."""
    results: list[CheckResult] = []
    url_pattern = re.compile(r"^https?://\S+$")

    if config.notifications.enabled and config.notifications.webhook_url:
        url = config.notifications.webhook_url
        if url_pattern.match(url):
            results.append(_result("webhook_url", url, "ok",
                                   "Webhook URL format is valid"))
        else:
            results.append(_result("webhook_url", url, "error",
                                   "Webhook URL format is invalid (must start with http:// or https://)"))

    if config.reports.enabled and config.reports.webhook_url:
        url = config.reports.webhook_url
        if url_pattern.match(url):
            results.append(_result("reports_webhook_url", url, "ok",
                                   "Reports webhook URL format is valid"))
        else:
            results.append(_result("reports_webhook_url", url, "error",
                                   "Reports webhook URL format is invalid"))

    return results


def _check_telegram(config: AppConfig) -> list[CheckResult]:
    """Validate Telegram bot_token format if Telegram is enabled."""
    if not config.telegram.enabled:
        return []

    results: list[CheckResult] = []
    token = config.telegram.bot_token
    # Telegram tokens look like 123456789:ABCdefGHIjklMNOpqrsTUVwxyz
    token_pattern = re.compile(r"^\d+:[A-Za-z0-9_-]+$")

    if not token.strip():
        results.append(_result("telegram_bot_token", "telegram", "error",
                               "Telegram is enabled but bot_token is empty"))
    elif not token_pattern.match(token):
        results.append(_result("telegram_bot_token", "telegram", "warning",
                               "Telegram bot_token format looks unusual (expected digits:alphanumeric)"))
    else:
        results.append(_result("telegram_bot_token", "telegram", "ok",
                               "Telegram bot_token format is valid"))

    if not config.telegram.chat_ids:
        results.append(_result("telegram_chat_ids", "telegram", "error",
                               "Telegram is enabled but no chat_ids are configured"))
    else:
        results.append(_result("telegram_chat_ids", "telegram", "ok",
                               f"{len(config.telegram.chat_ids)} chat ID(s) configured"))

    return results


# ---------------------------------------------------------------------------
# Main validation entry point
# ---------------------------------------------------------------------------

async def validate_config(config: AppConfig) -> list[CheckResult]:
    """Run all validation checks and return a list of results.

    Each result is a dict with keys: check, target, status, message.
    Status is one of: ok, warning, error.
    """
    results: list[CheckResult] = []

    # 1. Config syntax: if we got here, it parsed fine
    results.append(_result("config_syntax", "config.yaml", "ok",
                           "Configuration loaded successfully"))

    # 2. Log files
    results.extend(_check_log_files(config))

    # 3. Database
    results.extend(await _check_database(config))

    # 4. GeoIP
    results.extend(_check_geoip(config))

    # 5. API keys
    results.extend(_check_api_keys(config))

    # 6. Nuclei / Docker
    results.extend(_check_nuclei(config))

    # 7. Firewall backend
    results.extend(_check_firewall(config))

    # 8. Server port
    results.extend(_check_port(config))

    # 9. Webhooks
    results.extend(_check_webhooks(config))

    # 10. Telegram
    results.extend(_check_telegram(config))

    return results


# ---------------------------------------------------------------------------
# CLI entry point for --validate
# ---------------------------------------------------------------------------

def run_validate_cli(config_path: str = "config.yaml") -> int:
    """Run validation from the command line. Returns exit code (0=ok, 1=errors found)."""
    from defensewatch.config import load_config

    try:
        config = load_config(config_path)
    except Exception as exc:
        print(f"FAIL  config_syntax  {config_path}  {exc}")
        return 1

    results = asyncio.run(validate_config(config))

    # Print results
    errors = 0
    warnings = 0
    for r in results:
        status = r["status"].upper()
        icon = {"OK": "PASS ", "WARNING": "WARN ", "ERROR": "FAIL "}[status]
        print(f"  {icon} {r['check']:30s}  {r['target']:40s}  {r['message']}")
        if r["status"] == "error":
            errors += 1
        elif r["status"] == "warning":
            warnings += 1

    ok = len(results) - errors - warnings
    print(f"\n  {len(results)} checks: {ok} passed, {warnings} warnings, {errors} errors")

    return 1 if errors else 0


if __name__ == "__main__":
    import sys
    sys.exit(run_validate_cli())
