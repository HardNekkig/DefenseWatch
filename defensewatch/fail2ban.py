"""Fail2Ban integration — query status, jails, bans, and manage configuration.

Interacts with ``fail2ban-client`` via subprocess.  Requires the DefenseWatch
process user to have password-less sudo for ``/usr/bin/fail2ban-client``.

Add a sudoers drop-in::

    defensewatch ALL=(root) NOPASSWD: /usr/bin/fail2ban-client
"""

import asyncio
import logging
import re
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

_JAIL_LOCAL = Path("/etc/fail2ban/jail.local")
_JAIL_D = Path("/etc/fail2ban/jail.d")
_FILTER_D = Path("/etc/fail2ban/filter.d")

# ── detection ────────────────────────────────────────────────


def is_installed() -> bool:
    return shutil.which("fail2ban-client") is not None


async def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return -1, "", "Command timed out"
    return proc.returncode, stdout.decode().strip(), stderr.decode().strip()


# ── service status ───────────────────────────────────────────


async def get_server_status() -> dict:
    """Return fail2ban server status and jail list."""
    if not is_installed():
        return {"installed": False}

    rc, out, err = await _run(["sudo", "-n", "fail2ban-client", "status"])
    if rc != 0:
        return {"installed": True, "running": False, "error": err or out}

    jails = []
    total_banned = 0
    jail_match = re.search(r"Jail list:\s*(.+)", out)
    if jail_match:
        jail_names = [j.strip() for j in jail_match.group(1).split(",") if j.strip()]
        for name in jail_names:
            jail_info = await get_jail_status(name)
            jails.append(jail_info)
            total_banned += jail_info.get("currently_banned", 0)

    # Version
    rc_v, ver_out, _ = await _run(["sudo", "-n", "fail2ban-client", "version"])
    version = ver_out if rc_v == 0 else "unknown"

    return {
        "installed": True,
        "running": True,
        "version": version,
        "jail_count": len(jails),
        "total_banned": total_banned,
        "jails": jails,
    }


async def get_jail_status(jail: str) -> dict:
    """Return detailed status for a specific jail."""
    rc, out, err = await _run(["sudo", "-n", "fail2ban-client", "status", jail])
    if rc != 0:
        return {"name": jail, "error": err or out}

    info: dict = {"name": jail}

    # Parse the status output
    filter_match = re.search(r"Currently failed:\s*(\d+)", out)
    total_failed_match = re.search(r"Total failed:\s*(\d+)", out)
    banned_match = re.search(r"Currently banned:\s*(\d+)", out)
    total_banned_match = re.search(r"Total banned:\s*(\d+)", out)
    banned_list_match = re.search(r"Banned IP list:\s*(.*?)$", out, re.MULTILINE)
    file_list_match = re.search(r"File list:\s*(.*?)$", out, re.MULTILINE)

    info["currently_failed"] = int(filter_match.group(1)) if filter_match else 0
    info["total_failed"] = int(total_failed_match.group(1)) if total_failed_match else 0
    info["currently_banned"] = int(banned_match.group(1)) if banned_match else 0
    info["total_banned"] = int(total_banned_match.group(1)) if total_banned_match else 0
    info["banned_ips"] = (
        [ip.strip() for ip in banned_list_match.group(1).split() if ip.strip()]
        if banned_list_match and banned_list_match.group(1).strip()
        else []
    )
    info["log_files"] = (
        [f.strip() for f in file_list_match.group(1).split() if f.strip()]
        if file_list_match and file_list_match.group(1).strip()
        else []
    )

    # Get jail configuration parameters
    for param in ("bantime", "findtime", "maxretry"):
        rc_p, val, _ = await _run(
            ["sudo", "-n", "fail2ban-client", "get", jail, param]
        )
        if rc_p == 0:
            try:
                info[param] = int(val)
            except ValueError:
                info[param] = val

    return info


# ── ban / unban ──────────────────────────────────────────────


async def ban_ip(jail: str, ip: str) -> dict:
    """Ban an IP in a specific jail."""
    rc, out, err = await _run(
        ["sudo", "-n", "fail2ban-client", "set", jail, "banip", ip]
    )
    if rc != 0:
        return {"ok": False, "error": err or out}
    logger.info(f"Fail2Ban: banned {ip} in jail {jail}")
    return {"ok": True, "jail": jail, "ip": ip}


async def unban_ip(jail: str, ip: str) -> dict:
    """Unban an IP from a specific jail."""
    rc, out, err = await _run(
        ["sudo", "-n", "fail2ban-client", "set", jail, "unbanip", ip]
    )
    if rc != 0:
        return {"ok": False, "error": err or out}
    logger.info(f"Fail2Ban: unbanned {ip} from jail {jail}")
    return {"ok": True, "jail": jail, "ip": ip}


async def unban_ip_all(ip: str) -> dict:
    """Unban an IP from all jails."""
    rc, out, err = await _run(
        ["sudo", "-n", "fail2ban-client", "unban", ip]
    )
    if rc != 0:
        return {"ok": False, "error": err or out}
    logger.info(f"Fail2Ban: unbanned {ip} from all jails")
    return {"ok": True, "ip": ip}


# ── configuration reading ────────────────────────────────────


def read_jail_config() -> dict:
    """Read and parse jail.local and jail.d/*.conf files."""
    result = {"defaults": {}, "jails": {}, "files": []}

    # Read jail.local
    if _JAIL_LOCAL.exists():
        content = _JAIL_LOCAL.read_text(errors="replace")
        result["files"].append(str(_JAIL_LOCAL))
        parsed = _parse_ini(content)
        if "DEFAULT" in parsed:
            result["defaults"] = parsed["DEFAULT"]
        for section, values in parsed.items():
            if section != "DEFAULT":
                result["jails"][section] = values

    # Read jail.d/*.conf and *.local
    if _JAIL_D.exists():
        for p in sorted(_JAIL_D.glob("*.conf")) + sorted(_JAIL_D.glob("*.local")):
            content = p.read_text(errors="replace")
            result["files"].append(str(p))
            parsed = _parse_ini(content)
            for section, values in parsed.items():
                if section == "DEFAULT":
                    result["defaults"].update(values)
                else:
                    if section in result["jails"]:
                        result["jails"][section].update(values)
                    else:
                        result["jails"][section] = values

    return result


def _parse_ini(content: str) -> dict[str, dict[str, str]]:
    """Simple INI parser that handles fail2ban's config format."""
    sections: dict[str, dict[str, str]] = {}
    current_section = None

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue

        section_match = re.match(r"^\[(.+)]$", stripped)
        if section_match:
            current_section = section_match.group(1)
            sections.setdefault(current_section, {})
            continue

        if current_section is not None and "=" in stripped:
            key, _, value = stripped.partition("=")
            sections[current_section][key.strip()] = value.strip()

    return sections


# ── configuration writing ────────────────────────────────────


async def update_jail_param(jail: str, param: str, value: str) -> dict:
    """Update a jail parameter at runtime via fail2ban-client."""
    allowed = ("bantime", "findtime", "maxretry")
    if param not in allowed:
        return {"ok": False, "error": f"Parameter must be one of: {', '.join(allowed)}"}

    rc, out, err = await _run(
        ["sudo", "-n", "fail2ban-client", "set", jail, param, value]
    )
    if rc != 0:
        return {"ok": False, "error": err or out}

    logger.info(f"Fail2Ban: set {jail} {param}={value}")
    return {"ok": True, "jail": jail, "param": param, "value": value}


# ── recommended config generation ────────────────────────────


def generate_recommended_config(app_config) -> dict:
    """Generate recommended fail2ban jail configurations based on
    DefenseWatch's monitored services."""
    jails = {}

    # SSH jails — one per monitored log/port
    for entry in app_config.logs.ssh_entries():
        port = entry.port or 22
        name = "sshd" if port == 22 else f"sshd-{port}"
        jails[name] = {
            "config": _format_jail(
                name=name,
                enabled=True,
                port=str(port),
                filter_name="sshd",
                logpath=entry.path,
                maxretry=app_config.detection.ssh_brute_threshold,
                findtime=app_config.detection.ssh_brute_window_seconds,
                bantime=7200,
                backend="auto",
            ),
            "description": f"SSH brute-force protection on port {port}",
            "filter_exists": (_FILTER_D / "sshd.conf").exists(),
        }

    # HTTP jails — nginx access logs
    seen_ports = set()
    for entry in app_config.logs.http_entries():
        port = entry.port or 80
        if port in seen_ports:
            continue
        seen_ports.add(port)

        port_str = "http,https" if port in (80, 443) else str(port)

        # Bot search / scanner jail
        bot_name = "nginx-botsearch" if port in (80, 443) else f"nginx-botsearch-{port}"
        jails[bot_name] = {
            "config": _format_jail(
                name=bot_name,
                enabled=True,
                port=port_str,
                filter_name="nginx-botsearch",
                logpath=entry.path,
                maxretry=2,
                findtime=3600,
                bantime=86400,
            ),
            "description": f"Nginx scanner/bot detection on port {port}",
            "filter_exists": (_FILTER_D / "nginx-botsearch.conf").exists(),
        }

        # 4xx flood jail
        fourxx_name = "nginx-4xx" if port in (80, 443) else f"nginx-4xx-{port}"
        jails[fourxx_name] = {
            "config": _format_jail(
                name=fourxx_name,
                enabled=True,
                port=port_str,
                filter_name="nginx-4xx",
                logpath=entry.path,
                maxretry=app_config.detection.http_scan_threshold,
                findtime=app_config.detection.http_scan_window_seconds,
                bantime=3600,
            ),
            "description": f"Nginx 4xx enumeration flood on port {port}",
            "filter_exists": (_FILTER_D / "nginx-4xx.conf").exists(),
        }

    # Custom filter for nginx-4xx if it doesn't exist
    custom_filters = {}
    if not (_FILTER_D / "nginx-4xx.conf").exists():
        custom_filters["nginx-4xx"] = {
            "path": str(_FILTER_D / "nginx-4xx.conf"),
            "content": (
                "[Definition]\n"
                "failregex = ^<HOST> - .* \"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) .* HTTP/.*\" (400|401|403|404|405|444) .*$\n"
                "ignoreregex =\n"
            ),
        }

    return {
        "jails": jails,
        "custom_filters": custom_filters,
        "defaults": {
            "config": (
                "[DEFAULT]\n"
                f"bantime  = 3600\n"
                f"findtime = 600\n"
                f"maxretry = 5\n"
                f"banaction = nftables\n"
                f"banaction_allports = nftables[type=allports]\n"
            ),
            "description": "Recommended defaults for DefenseWatch integration",
        },
    }


def _format_jail(*, name, enabled, port, filter_name, logpath,
                 maxretry, findtime, bantime, backend="auto") -> str:
    lines = [
        f"[{name}]",
        f"enabled  = {'true' if enabled else 'false'}",
        f"port     = {port}",
        f"filter   = {filter_name}",
        f"logpath  = {logpath}",
        f"maxretry = {maxretry}",
        f"findtime = {findtime}",
        f"bantime  = {bantime}",
    ]
    if backend != "auto":
        lines.append(f"backend  = {backend}")
    return "\n".join(lines)


# ── service control ──────────────────────────────────────────


async def reload_fail2ban() -> dict:
    """Reload fail2ban to pick up config changes."""
    rc, out, err = await _run(["sudo", "-n", "fail2ban-client", "reload"])
    if rc != 0:
        return {"ok": False, "error": err or out}
    logger.info("Fail2Ban: configuration reloaded")
    return {"ok": True}
