import logging
from fastapi import APIRouter
from pydantic import BaseModel
from defensewatch.fail2ban import (
    is_installed, get_server_status, get_jail_status,
    ban_ip, unban_ip, unban_ip_all,
    read_jail_config, update_jail_param,
    generate_recommended_config, reload_fail2ban,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/fail2ban", tags=["fail2ban"])

_config = None


def set_fail2ban_config(config):
    global _config
    _config = config


class BanRequest(BaseModel):
    jail: str
    ip: str


class UnbanRequest(BaseModel):
    ip: str
    jail: str | None = None  # None = unban from all jails


class JailParamUpdate(BaseModel):
    jail: str
    param: str    # bantime | findtime | maxretry
    value: str


@router.get("/status")
async def f2b_status():
    """Full fail2ban status with all jail details."""
    if not is_installed():
        return {"installed": False}
    return await get_server_status()


@router.get("/jail/{jail}")
async def f2b_jail(jail: str):
    """Detailed status for a specific jail."""
    return await get_jail_status(jail)


@router.post("/ban")
async def f2b_ban(body: BanRequest):
    """Manually ban an IP in a specific jail."""
    return await ban_ip(body.jail, body.ip)


@router.post("/unban")
async def f2b_unban(body: UnbanRequest):
    """Unban an IP from a specific jail or all jails."""
    if body.jail:
        return await unban_ip(body.jail, body.ip)
    return await unban_ip_all(body.ip)


@router.get("/config")
async def f2b_config():
    """Read the current fail2ban jail configuration files."""
    if not is_installed():
        return {"installed": False}
    return read_jail_config()


@router.get("/recommended")
async def f2b_recommended():
    """Generate recommended jail configs based on DefenseWatch's monitored services."""
    if _config is None:
        return {"error": "Config not loaded"}
    return generate_recommended_config(_config)


@router.patch("/jail")
async def f2b_update_jail(body: JailParamUpdate):
    """Update a jail parameter at runtime (bantime, findtime, maxretry)."""
    return await update_jail_param(body.jail, body.param, body.value)


@router.post("/reload")
async def f2b_reload():
    """Reload fail2ban configuration."""
    return await reload_fail2ban()
