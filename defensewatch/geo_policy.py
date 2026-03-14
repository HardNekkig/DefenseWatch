"""GeoIP-based access policies for DefenseWatch.

Allows blocking, alerting, or flagging traffic based on the geographic origin
of source IPs.  Supports blacklist (block listed countries) and whitelist
(block everything *except* listed countries) modes, with per-IP exemptions
including CIDR ranges.
"""

import asyncio
import ipaddress
import logging
import time
from dataclasses import asdict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from defensewatch.config import GeoPolicyConfig
from defensewatch.database import get_db
from defensewatch.firewall import block_ip
from defensewatch.audit import log_audit

logger = logging.getLogger(__name__)

# ── Common country codes (ISO 3166-1 alpha-2, ~55 most common) ──────────────

COMMON_COUNTRY_CODES: list[str] = [
    "US", "GB", "CN", "RU", "DE", "FR", "JP", "KR", "BR", "IN",
    "CA", "AU", "NL", "IT", "ES", "PL", "UA", "RO", "SE", "CH",
    "AT", "BE", "CZ", "DK", "FI", "HU", "NO", "PT", "IE", "IL",
    "SG", "MY", "TH", "ID", "VN", "PH", "TW", "HK", "BD", "PK",
    "IR", "IQ", "TR", "SA", "AE", "EG", "ZA", "NG", "KE", "AR",
    "MX", "CO", "CL", "PE", "VE",
]


# ── Module-level state ──────────────────────────────────────────────────────

_config: GeoPolicyConfig | None = None
_manager = None  # broadcast.ConnectionManager


def set_geo_policy_deps(config: GeoPolicyConfig, manager) -> None:
    """Inject dependencies (called during app lifespan)."""
    global _config, _manager
    _config = config
    _manager = manager


def _get_config() -> GeoPolicyConfig:
    if _config is None:
        return GeoPolicyConfig()
    return _config


# ── Helpers ─────────────────────────────────────────────────────────────────


def _is_exempt(ip: str, exempt_ips: list[str]) -> bool:
    """Check if *ip* is covered by any entry in the exemption list.

    Entries can be plain IPs (``1.2.3.4``) or CIDR ranges (``10.0.0.0/8``).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for entry in exempt_ips:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if addr == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


# ── Core logic ──────────────────────────────────────────────────────────────


async def check_geo_policy(ip: str, config: GeoPolicyConfig) -> dict | None:
    """Evaluate *ip* against the geo-policy.

    Returns a result dict when the policy triggers, ``None`` otherwise.
    Only uses the ``ip_intel`` table (fast path); if the IP has not been
    enriched yet, it is silently skipped.
    """
    if not config.enabled:
        return None

    if _is_exempt(ip, config.exempt_ips):
        return None

    db = get_db()
    row = await db.execute(
        "SELECT country_code FROM ip_intel WHERE ip = ?", (ip,)
    )
    row = await row.fetchone()
    if row is None:
        return None

    country_code: str = row[0] or ""
    if not country_code:
        return None

    cc_upper = country_code.upper()
    countries_upper = [c.upper() for c in config.countries]

    triggered = False
    if config.mode == "blacklist":
        triggered = cc_upper in countries_upper
    elif config.mode == "whitelist":
        triggered = cc_upper not in countries_upper
    else:
        logger.warning("Unknown geo-policy mode: %s", config.mode)
        return None

    if not triggered:
        return None

    mode_label = "blacklisted" if config.mode == "blacklist" else "not whitelisted"
    reason = f"Geo-policy: country {cc_upper} is {mode_label}"

    return {
        "ip": ip,
        "country_code": cc_upper,
        "action": config.action,
        "reason": reason,
    }


async def enforce_geo_policy(
    ip: str,
    policy_result: dict,
    config: GeoPolicyConfig,
) -> dict:
    """Carry out the action specified by a geo-policy check result."""
    action = policy_result["action"]
    reason = policy_result["reason"]
    cc = policy_result["country_code"]

    if action == "block":
        duration = config.block_duration_hours if config.block_duration_hours > 0 else None
        result = await block_ip(
            ip,
            reason=reason,
            source="geo_policy",
            duration_hours=duration,
        )
        policy_result["block_result"] = result

        await log_audit(
            action="geo_block",
            target=ip,
            detail=f"Blocked by geo-policy (country={cc}, duration={duration or 'permanent'})",
            actor="geo_policy",
        )

        if _manager is not None:
            await _manager.broadcast("geo_policy", {
                "action": "block",
                "ip": ip,
                "country_code": cc,
                "reason": reason,
            })

    elif action == "alert":
        await log_audit(
            action="geo_alert",
            target=ip,
            detail=f"Alert by geo-policy (country={cc})",
            actor="geo_policy",
        )

        if _manager is not None:
            await _manager.broadcast("geo_policy", {
                "action": "alert",
                "ip": ip,
                "country_code": cc,
                "reason": reason,
            })

    elif action == "flag":
        await log_audit(
            action="geo_flag",
            target=ip,
            detail=f"Flagged by geo-policy for manual review (country={cc})",
            actor="geo_policy",
        )

    else:
        logger.warning("Unknown geo-policy action: %s", action)

    return policy_result


async def evaluate_geo_policies_batch(config: GeoPolicyConfig) -> list[dict]:
    """Evaluate the geo-policy against all unique IPs seen in the last hour
    that have not yet been geo-checked.

    Returns a list of enforced results.
    """
    if not config.enabled:
        return []

    db = get_db()
    one_hour_ago = time.time() - 3600

    # Gather unique IPs from recent SSH + HTTP events that have intel but
    # haven't been geo-checked (no recent audit entry for geo_*).
    rows = await db.execute_fetchall(
        """
        SELECT DISTINCT ii.ip, ii.country_code
        FROM ip_intel ii
        WHERE ii.ip IN (
            SELECT DISTINCT source_ip FROM ssh_events
            WHERE created_at >= ?
            UNION
            SELECT DISTINCT source_ip FROM http_events
            WHERE created_at >= ?
        )
        AND ii.country_code IS NOT NULL
        AND ii.country_code != ''
        AND ii.ip NOT IN (
            SELECT target FROM audit_log
            WHERE action IN ('geo_block', 'geo_alert', 'geo_flag')
            AND timestamp >= ?
        )
        """,
        (one_hour_ago, one_hour_ago, one_hour_ago),
    )

    enforced: list[dict] = []
    for row in rows:
        ip = row[0] if not isinstance(row, dict) else row["ip"]
        result = await check_geo_policy(ip, config)
        if result is not None:
            result = await enforce_geo_policy(ip, result, config)
            enforced.append(result)

    return enforced


# ── Background loop ─────────────────────────────────────────────────────────

_CHECK_INTERVAL = 300  # 5 minutes


async def geo_policy_loop(config: GeoPolicyConfig, manager) -> None:
    """Background task that periodically evaluates geo-policies."""
    set_geo_policy_deps(config, manager)
    logger.info("Geo-policy background loop started (interval=%ds)", _CHECK_INTERVAL)

    while True:
        try:
            await asyncio.sleep(_CHECK_INTERVAL)
            if not config.enabled:
                continue
            results = await evaluate_geo_policies_batch(config)
            if results:
                logger.info("Geo-policy batch: enforced %d actions", len(results))
        except asyncio.CancelledError:
            logger.info("Geo-policy loop cancelled")
            break
        except Exception:
            logger.exception("Error in geo-policy loop")


# ── API router ──────────────────────────────────────────────────────────────

router = APIRouter(prefix="/api/geo-policy", tags=["geo-policy"])


class GeoPolicyUpdate(BaseModel):
    enabled: bool | None = None
    mode: str | None = None
    countries: list[str] | None = None
    action: str | None = None
    block_duration_hours: int | None = None
    exempt_ips: list[str] | None = None


@router.get("/status")
async def get_status():
    """Return current geo-policy config and recent enforcement count."""
    config = _get_config()
    db = get_db()

    one_hour_ago = time.time() - 3600
    row = await db.execute(
        """SELECT COUNT(*) FROM audit_log
           WHERE action IN ('geo_block', 'geo_alert', 'geo_flag')
           AND timestamp >= ?""",
        (one_hour_ago,),
    )
    row = await row.fetchone()
    recent_count = row[0] if row else 0

    return {
        "config": asdict(config),
        "recent_enforcements": recent_count,
    }


@router.get("/check/{ip}")
async def check_ip(ip: str):
    """Check a specific IP against the current geo-policy."""
    config = _get_config()

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")

    result = await check_geo_policy(ip, config)
    if result is None:
        return {
            "ip": ip,
            "triggered": False,
            "detail": "No policy match (IP may not be enriched yet)",
        }
    return {
        "ip": ip,
        "triggered": True,
        **result,
    }


@router.patch("/config")
async def update_config(body: GeoPolicyUpdate):
    """Update geo-policy configuration."""
    config = _get_config()

    if body.enabled is not None:
        config.enabled = body.enabled
    if body.mode is not None:
        if body.mode not in ("blacklist", "whitelist"):
            raise HTTPException(status_code=400, detail="mode must be 'blacklist' or 'whitelist'")
        config.mode = body.mode
    if body.countries is not None:
        config.countries = [c.upper() for c in body.countries]
    if body.action is not None:
        if body.action not in ("block", "alert", "flag"):
            raise HTTPException(status_code=400, detail="action must be 'block', 'alert', or 'flag'")
        config.action = body.action
    if body.block_duration_hours is not None:
        config.block_duration_hours = body.block_duration_hours
    if body.exempt_ips is not None:
        # Validate each entry
        for entry in body.exempt_ips:
            try:
                if "/" in entry:
                    ipaddress.ip_network(entry, strict=False)
                else:
                    ipaddress.ip_address(entry)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid IP/CIDR in exempt_ips: {entry}",
                )
        config.exempt_ips = body.exempt_ips

    await log_audit(
        action="geo_policy_config_update",
        target="geo_policy",
        detail=f"Updated: {body.model_dump(exclude_none=True)}",
        actor="api",
    )

    return {"ok": True, "config": asdict(config)}


@router.get("/countries")
async def list_countries():
    """Return all distinct country codes present in ip_intel (for UI picker)."""
    db = get_db()
    rows = await db.execute_fetchall(
        """SELECT DISTINCT country_code FROM ip_intel
           WHERE country_code IS NOT NULL AND country_code != ''
           ORDER BY country_code"""
    )
    seen = [row[0] for row in rows]
    return {
        "known": seen,
        "common": COMMON_COUNTRY_CODES,
    }
