"""API endpoints for IP reputation blocklist management."""

import logging

from fastapi import APIRouter
from pydantic import BaseModel

from defensewatch.enrichment.blocklists import get_blocklist_manager, BLOCKLIST_SOURCES

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/blocklists", tags=["blocklists"])

_config = None


def set_blocklists_config(config):
    global _config
    _config = config


# ── Request models ───────────────────────────────────────────────────

class BlocklistConfigUpdate(BaseModel):
    enabled: bool | None = None
    refresh_interval_hours: int | None = None
    lists: list[str] | None = None
    auto_block: bool | None = None


# ── Endpoints ────────────────────────────────────────────────────────

@router.get("/status")
async def blocklists_status():
    """Return status and stats for all configured blocklists."""
    mgr = get_blocklist_manager()
    if mgr is None:
        return {"enabled": False, "error": "Blocklist manager not initialized"}
    return mgr.get_stats()


@router.post("/refresh")
async def blocklists_refresh():
    """Trigger a manual refresh of all enabled blocklists."""
    mgr = get_blocklist_manager()
    if mgr is None:
        return {"error": "Blocklist manager not initialized"}

    try:
        await mgr.refresh()
        return {"ok": True, "stats": mgr.get_stats()}
    except Exception as exc:
        logger.error("Manual blocklist refresh failed: %s", exc)
        return {"error": f"Refresh failed: {exc}"}


@router.get("/check/{ip}")
async def blocklists_check(ip: str):
    """Check if an IP address appears on any loaded blocklist."""
    mgr = get_blocklist_manager()
    if mgr is None:
        return {"ip": ip, "listed": False, "error": "Blocklist manager not initialized"}

    matches = mgr.check_ip(ip)
    return {
        "ip": ip,
        "listed": len(matches) > 0,
        "matches": matches,
        "lists_checked": len(mgr.config.lists),
    }


@router.patch("/config")
async def blocklists_update_config(body: BlocklistConfigUpdate):
    """Update blocklist configuration and persist to config.yaml."""
    mgr = get_blocklist_manager()
    if mgr is None:
        return {"error": "Blocklist manager not initialized"}

    cfg = mgr.config

    if body.enabled is not None:
        cfg.enabled = body.enabled
    if body.refresh_interval_hours is not None:
        cfg.refresh_interval_hours = max(1, body.refresh_interval_hours)
    if body.lists is not None:
        valid = [name for name in body.lists if name in BLOCKLIST_SOURCES]
        cfg.lists = valid if valid else cfg.lists
    if body.auto_block is not None:
        cfg.auto_block = body.auto_block

    # Persist to config.yaml
    if _config is not None:
        try:
            from defensewatch.api.settings import _persist_config
            _persist_config()
        except Exception as exc:
            logger.error("Failed to persist blocklist config: %s", exc)

    # If toggled on and no refresh task is running, start it
    if cfg.enabled and (mgr._refresh_task is None or mgr._refresh_task.done()):
        import asyncio
        mgr._running = True
        mgr._refresh_task = asyncio.create_task(mgr._refresh_loop())
        logger.info("Blocklist refresh loop started")
    elif not cfg.enabled and mgr._refresh_task and not mgr._refresh_task.done():
        mgr._refresh_task.cancel()
        mgr._refresh_task = None
        logger.info("Blocklist refresh loop stopped")

    return {
        "ok": True,
        "config": {
            "enabled": cfg.enabled,
            "refresh_interval_hours": cfg.refresh_interval_hours,
            "lists": cfg.lists,
            "auto_block": cfg.auto_block,
        },
    }
