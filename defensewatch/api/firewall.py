import logging
from fastapi import APIRouter, Query
from pydantic import BaseModel
from defensewatch.firewall import (
    block_ip, unblock_ip, list_blocked, block_history, detect_backend,
    list_system_rules,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/firewall", tags=["firewall"])

_config = None


def set_firewall_config(config):
    global _config
    _config = config


class BlockRequest(BaseModel):
    ip: str
    reason: str = ""
    duration_hours: int | None = None


class AutoBlockSettings(BaseModel):
    auto_block_enabled: bool | None = None
    ssh_block_threshold: int | None = None
    brute_session_block_threshold: int | None = None
    http_block_threshold: int | None = None
    score_block_threshold: int | None = None
    auto_block_window_seconds: int | None = None
    auto_block_duration_hours: int | None = None


@router.get("/status")
async def firewall_status():
    """Return firewall backend info and auto-block configuration."""
    backend = detect_backend()
    blocked = await list_blocked()
    system_rules = await list_system_rules()
    # Merge counts
    db_ips = {b["ip"] for b in blocked}
    extra_system = [r for r in system_rules if r["ip"] not in db_ips]
    total_blocked = len(blocked) + len(extra_system)
    fw = _config.firewall if _config else None

    # Test if we can actually execute firewall commands
    can_execute = False
    if backend:
        from defensewatch.firewall import _run
        if backend == "ufw":
            rc, _, _ = await _run(["sudo", "-n", "ufw", "status"])
            can_execute = rc == 0
        elif backend == "iptables":
            rc, _, _ = await _run(["sudo", "-n", "iptables", "-L", "-n"])
            can_execute = rc == 0
        elif backend == "nftables":
            rc, _, _ = await _run(["sudo", "-n", "nft", "list", "ruleset"])
            can_execute = rc == 0

    return {
        "backend": backend,
        "available": backend is not None,
        "blocked_count": total_blocked,
        "can_execute": can_execute,
        "auto_block": {
            "enabled": fw.auto_block_enabled if fw else False,
            "ssh_block_threshold": fw.ssh_block_threshold if fw else 20,
            "brute_session_block_threshold": fw.brute_session_block_threshold if fw else 3,
            "http_block_threshold": fw.http_block_threshold if fw else 100,
            "score_block_threshold": fw.score_block_threshold if fw else 70,
            "auto_block_window_seconds": fw.auto_block_window_seconds if fw else 3600,
            "auto_block_duration_hours": fw.auto_block_duration_hours if fw else 0,
            "whitelist": fw.whitelist if fw else [],
        } if fw else {},
    }


@router.post("/block")
async def api_block_ip(body: BlockRequest):
    """Manually block an IP address."""
    result = await block_ip(
        body.ip, reason=body.reason, source="manual",
        duration_hours=body.duration_hours,
    )
    return result


@router.post("/unblock")
async def api_unblock_ip(body: BlockRequest):
    """Unblock an IP address."""
    result = await unblock_ip(body.ip)
    return result


@router.get("/blocked")
async def api_list_blocked():
    """List all currently blocked IPs (DB-tracked + live system rules merged)."""
    blocked = await list_blocked()
    system_rules = await list_system_rules()

    # Merge: add system rules that aren't already in the DB list
    db_ips = {b["ip"] for b in blocked}
    for rule in system_rules:
        ip = rule["ip"]
        if ip not in db_ips:
            blocked.append({
                "id": None,
                "ip": ip,
                "reason": rule.get("rule", ""),
                "source": "system",
                "blocked_at": None,
                "expires_at": None,
                "country_code": None,
                "org": None,
                "city": None,
            })
            db_ips.add(ip)

    return {"blocked": blocked}


@router.get("/history")
async def api_block_history(limit: int = Query(100, ge=1, le=1000)):
    """Return block/unblock history."""
    history = await block_history(limit)
    return {"history": history}


@router.patch("/settings")
async def update_autoblock_settings(body: AutoBlockSettings):
    """Update auto-block settings and persist to config.yaml."""
    if _config is None:
        return {"error": "Config not loaded"}

    fw = _config.firewall
    if body.auto_block_enabled is not None:
        fw.auto_block_enabled = body.auto_block_enabled
    if body.ssh_block_threshold is not None:
        fw.ssh_block_threshold = body.ssh_block_threshold
    if body.brute_session_block_threshold is not None:
        fw.brute_session_block_threshold = body.brute_session_block_threshold
    if body.http_block_threshold is not None:
        fw.http_block_threshold = body.http_block_threshold
    if body.score_block_threshold is not None:
        fw.score_block_threshold = body.score_block_threshold
    if body.auto_block_window_seconds is not None:
        fw.auto_block_window_seconds = body.auto_block_window_seconds
    if body.auto_block_duration_hours is not None:
        fw.auto_block_duration_hours = body.auto_block_duration_hours

    from defensewatch.api.settings import _persist_config
    _persist_config()
    logger.info(f"Auto-block settings updated: enabled={fw.auto_block_enabled}")
    return {"ok": True, "auto_block": {
        "enabled": fw.auto_block_enabled,
        "ssh_block_threshold": fw.ssh_block_threshold,
        "brute_session_block_threshold": fw.brute_session_block_threshold,
        "http_block_threshold": fw.http_block_threshold,
        "score_block_threshold": fw.score_block_threshold,
        "auto_block_window_seconds": fw.auto_block_window_seconds,
        "auto_block_duration_hours": fw.auto_block_duration_hours,
    }}
