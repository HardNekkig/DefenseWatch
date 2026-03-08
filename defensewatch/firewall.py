"""Firewall management — block / unblock IPs via ufw, nftables, or iptables.

All rule mutations run through subprocess so they require the DefenseWatch
process (or the invoking user) to have permission to execute
``ufw`` / ``nft`` / ``iptables``.  The recommended approach is to grant
password-less sudo for the specific commands via a sudoers drop-in, e.g.::

    defensewatch ALL=(root) NOPASSWD: /usr/sbin/ufw
    defensewatch ALL=(root) NOPASSWD: /usr/sbin/nft
    defensewatch ALL=(root) NOPASSWD: /usr/sbin/iptables
"""

import asyncio
import ipaddress
import logging
import shutil
import time

from defensewatch.database import get_db

logger = logging.getLogger(__name__)

# ── backend detection ────────────────────────────────────────

_backend: str | None = None  # "ufw" | "nftables" | "iptables" | None

_NFT_TABLE = "defensewatch"
_NFT_CHAIN = "blocklist"


def detect_backend() -> str | None:
    """Return the firewall backend available on this host."""
    global _backend
    if _backend is not None:
        return _backend
    if shutil.which("ufw"):
        _backend = "ufw"
    elif shutil.which("nft"):
        _backend = "nftables"
    elif shutil.which("iptables"):
        _backend = "iptables"
    else:
        _backend = None
    return _backend


# ── helpers ──────────────────────────────────────────────────

def _validate_ip(ip: str) -> str:
    """Return a validated IP string or raise ValueError."""
    return str(ipaddress.ip_address(ip))


async def _run(cmd: list[str]) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode, stdout.decode().strip(), stderr.decode().strip()


# ── nftables helpers ─────────────────────────────────────────

_nft_initialised = False


async def _ensure_nft_table():
    """Create the defensewatch nftables table and chain if they don't exist."""
    global _nft_initialised
    if _nft_initialised:
        return

    # Create table (idempotent — nft errors if it exists, so ignore rc)
    await _run(["sudo", "nft", "add", "table", "inet", _NFT_TABLE])

    # Create input chain hooked into the input path
    # Use 'add' which is idempotent for existing chains with same params
    await _run([
        "sudo", "nft", "add", "chain", "inet", _NFT_TABLE, _NFT_CHAIN,
        "{ type filter hook input priority 0 ; policy accept ; }",
    ])

    _nft_initialised = True
    logger.info(f"nftables table inet/{_NFT_TABLE} chain {_NFT_CHAIN} ready")


async def _nft_delete_rule(ip: str) -> tuple[int, str, str]:
    """Find and delete the nftables rule for *ip* by its comment handle."""
    # List rules with handles in JSON to find ours
    rc, out, err = await _run([
        "sudo", "nft", "-a", "list", "chain", "inet", _NFT_TABLE, _NFT_CHAIN,
    ])
    if rc != 0:
        return rc, out, err

    # Parse output for our comment-tagged rule to get its handle number
    # nft -a output lines look like:  ip saddr 1.2.3.4 drop comment "defensewatch:1.2.3.4" # handle 5
    target_comment = f"defensewatch:{ip}"
    for line in out.splitlines():
        if target_comment in line and "# handle" in line:
            handle = line.rsplit("# handle", 1)[1].strip()
            return await _run([
                "sudo", "nft", "delete", "rule", "inet",
                _NFT_TABLE, _NFT_CHAIN, "handle", handle,
            ])

    # Fallback: no matching rule found
    return 1, "", f"No nftables rule found for {ip}"


# ── core operations ──────────────────────────────────────────

async def block_ip(ip: str, reason: str = "", source: str = "manual",
                   duration_hours: int | None = None) -> dict:
    """Insert a DENY rule for *ip* and record in the DB."""
    ip = _validate_ip(ip)
    backend = detect_backend()
    if backend is None:
        return {"ok": False, "error": "No firewall backend (ufw/nftables/iptables) found"}

    # Check if already blocked
    db = get_db()
    existing = await db.execute_fetchall(
        "SELECT id FROM firewall_blocks WHERE ip=? AND active=1", (ip,)
    )
    if existing:
        return {"ok": False, "error": f"{ip} is already blocked"}

    if backend == "ufw":
        # Try insert at position 1 first; fall back to plain deny if no rules exist yet
        rc, out, err = await _run(["sudo", "ufw", "insert", "1", "deny", "from", ip])
        if rc != 0 and "Invalid position" in (err or out):
            rc, out, err = await _run(["sudo", "ufw", "deny", "from", ip])
    elif backend == "nftables":
        await _ensure_nft_table()
        family = "ip6" if ":" in ip else "ip"
        rc, out, err = await _run([
            "sudo", "nft", "add", "rule", "inet", _NFT_TABLE, _NFT_CHAIN,
            family, "saddr", ip, "drop",
            "comment", f'"defensewatch:{ip}"',
        ])
    else:
        rc, out, err = await _run([
            "sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"
        ])

    if rc != 0:
        logger.error(f"Firewall block failed for {ip}: {err}")
        return {"ok": False, "error": err or out}

    now = time.time()
    expires_at = now + (duration_hours * 3600) if duration_hours else None

    await db.execute(
        """INSERT INTO firewall_blocks
           (ip, reason, source, blocked_at, expires_at, active)
           VALUES (?, ?, ?, ?, ?, 1)""",
        (ip, reason, source, now, expires_at),
    )
    await db.commit()

    logger.info(f"Blocked {ip} via {backend} (source={source}, reason={reason})")
    return {"ok": True, "ip": ip, "backend": backend}


async def unblock_ip(ip: str) -> dict:
    """Remove the DENY rule for *ip* and deactivate in the DB."""
    ip = _validate_ip(ip)
    backend = detect_backend()
    if backend is None:
        return {"ok": False, "error": "No firewall backend found"}

    if backend == "ufw":
        rc, out, err = await _run(["sudo", "ufw", "delete", "deny", "from", ip])
    elif backend == "nftables":
        rc, out, err = await _nft_delete_rule(ip)
    else:
        rc, out, err = await _run([
            "sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"
        ])

    if rc != 0:
        logger.warning(f"Firewall unblock may have failed for {ip}: {err}")

    db = get_db()
    await db.execute(
        "UPDATE firewall_blocks SET active=0, unblocked_at=? WHERE ip=? AND active=1",
        (time.time(), ip),
    )
    await db.commit()

    logger.info(f"Unblocked {ip} via {backend}")
    return {"ok": True, "ip": ip, "backend": backend}


async def list_blocked() -> list[dict]:
    """Return all currently blocked IPs from the DB."""
    db = get_db()
    rows = await db.execute_fetchall(
        """SELECT b.id, b.ip, b.reason, b.source, b.blocked_at, b.expires_at,
                  i.country_code, i.org, i.city
           FROM firewall_blocks b
           LEFT JOIN ip_intel i ON i.ip = b.ip
           WHERE b.active = 1
           ORDER BY b.blocked_at DESC"""
    )
    return [
        {
            "id": r[0], "ip": r[1], "reason": r[2], "source": r[3],
            "blocked_at": r[4], "expires_at": r[5],
            "country_code": r[6], "org": r[7], "city": r[8],
        }
        for r in rows
    ]


async def block_history(limit: int = 100) -> list[dict]:
    """Return recent block/unblock history."""
    db = get_db()
    rows = await db.execute_fetchall(
        """SELECT b.id, b.ip, b.reason, b.source, b.blocked_at,
                  b.unblocked_at, b.active,
                  i.country_code, i.org
           FROM firewall_blocks b
           LEFT JOIN ip_intel i ON i.ip = b.ip
           ORDER BY b.blocked_at DESC LIMIT ?""",
        (limit,),
    )
    return [
        {
            "id": r[0], "ip": r[1], "reason": r[2], "source": r[3],
            "blocked_at": r[4], "unblocked_at": r[5], "active": bool(r[6]),
            "country_code": r[7], "org": r[8],
        }
        for r in rows
    ]


async def list_system_rules() -> list[dict]:
    """Query the actual firewall backend for all active DENY/DROP rules.

    Returns a list of dicts with at least {ip, action} for each rule
    found, regardless of which tool created them.
    Tries with sudo first, falls back to without sudo.
    """
    backend = detect_backend()
    if backend is None:
        return []

    import re
    rules = []
    try:
        if backend == "ufw":
            # Try with sudo, fall back to without
            rc, out, _ = await _run(["sudo", "ufw", "status", "numbered"])
            if rc != 0:
                rc, out, _ = await _run(["ufw", "status", "numbered"])
            if rc == 0:
                for line in out.splitlines():
                    m = re.search(
                        r'\[\s*(\d+)\]\s+.*?DENY\s+IN\s+(\S+)',
                        line,
                    )
                    if m:
                        rules.append({
                            "number": int(m.group(1)),
                            "ip": m.group(2),
                            "action": "DENY",
                            "rule": line.strip(),
                        })
                        continue
                    m = re.search(
                        r'(\S+)\s+DENY\s+IN\s+(\S+)',
                        line,
                    )
                    if m:
                        rules.append({
                            "ip": m.group(2),
                            "action": "DENY",
                            "rule": line.strip(),
                        })

            # Also parse iptables as fallback (ufw uses iptables underneath)
            iptables_rules = await _parse_iptables_rules()
            existing_ips = {r["ip"] for r in rules}
            for r in iptables_rules:
                if r["ip"] not in existing_ips:
                    rules.append(r)
                    existing_ips.add(r["ip"])

        elif backend == "iptables":
            rules = await _parse_iptables_rules()

        elif backend == "nftables":
            rc, out, _ = await _run(["sudo", "nft", "list", "ruleset"])
            if rc != 0:
                rc, out, _ = await _run(["nft", "list", "ruleset"])
            if rc == 0:
                for line in out.splitlines():
                    m = re.search(
                        r'(?:ip6?\s+saddr)\s+(\S+)\s+(drop|reject)',
                        line,
                    )
                    if m:
                        rules.append({
                            "ip": m.group(1),
                            "action": m.group(2).upper(),
                            "rule": line.strip(),
                        })

    except Exception as e:
        logger.error(f"Failed to list system firewall rules: {e}")

    return rules


async def _parse_iptables_rules() -> list[dict]:
    """Parse iptables INPUT chain for DROP/REJECT rules."""
    rules = []
    # Try sudo first, then without
    rc, out, _ = await _run([
        "sudo", "iptables", "-L", "INPUT", "-n", "--line-numbers",
    ])
    if rc != 0:
        rc, out, _ = await _run([
            "iptables", "-L", "INPUT", "-n", "--line-numbers",
        ])
    if rc != 0:
        return rules

    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[1] in ("DROP", "REJECT"):
            try:
                num = int(parts[0])
            except ValueError:
                continue
            rules.append({
                "number": num,
                "ip": parts[4],
                "action": parts[1],
                "rule": " ".join(parts),
            })
    return rules


# ── auto-block evaluation ───────────────────────────────────

async def evaluate_ip_for_autoblock(ip: str, config) -> dict | None:
    """Check whether *ip* should be auto-blocked based on configured
    thresholds.  Returns a dict with the reason if blocked, else None."""
    if not config.firewall.auto_block_enabled:
        return None

    db = get_db()

    # Already blocked?
    existing = await db.execute_fetchall(
        "SELECT 1 FROM firewall_blocks WHERE ip=? AND active=1", (ip,)
    )
    if existing:
        return None

    # Whitelisted?
    for prefix in config.firewall.whitelist:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            if ipaddress.ip_address(ip) in net:
                return None
        except ValueError:
            if ip == prefix:
                return None

    reasons = []
    fw = config.firewall

    # SSH brute force: total failed attempts within the window
    window = time.time() - fw.auto_block_window_seconds
    rows = await db.execute_fetchall(
        """SELECT COUNT(*) FROM ssh_events
           WHERE source_ip=? AND event_type IN ('failed_password','invalid_user')
             AND timestamp > ?""",
        (ip, window),
    )
    ssh_fails = rows[0][0] if rows else 0
    if ssh_fails >= fw.ssh_block_threshold:
        reasons.append(f"{ssh_fails} SSH failures in {fw.auto_block_window_seconds}s")

    # Brute force sessions
    rows = await db.execute_fetchall(
        "SELECT COUNT(*) FROM brute_force_sessions WHERE source_ip=? AND session_start > ?",
        (ip, window),
    )
    brute_count = rows[0][0] if rows else 0
    if brute_count >= fw.brute_session_block_threshold:
        reasons.append(f"{brute_count} brute force sessions")

    # HTTP scanning / enumeration attacks
    rows = await db.execute_fetchall(
        """SELECT COUNT(*) FROM http_events
           WHERE source_ip=? AND timestamp > ?""",
        (ip, window),
    )
    http_attacks = rows[0][0] if rows else 0
    if http_attacks >= fw.http_block_threshold:
        reasons.append(f"{http_attacks} HTTP attack events")

    # Threat score based blocking
    if fw.score_block_threshold > 0:
        from defensewatch.scoring import compute_threat_score
        score_data = await compute_threat_score(ip)
        if score_data["score"] >= fw.score_block_threshold:
            reasons.append(f"Threat score {score_data['score']}/100")

    if not reasons:
        return None

    reason_str = "; ".join(reasons)
    result = await block_ip(
        ip, reason=reason_str, source="auto",
        duration_hours=fw.auto_block_duration_hours or None,
    )

    if result.get("ok"):
        logger.warning(f"Auto-blocked {ip}: {reason_str}")
        return {"ip": ip, "reason": reason_str}

    return None


async def expire_blocks():
    """Unblock IPs whose temporary blocks have expired."""
    db = get_db()
    now = time.time()
    expired = await db.execute_fetchall(
        "SELECT ip FROM firewall_blocks WHERE active=1 AND expires_at IS NOT NULL AND expires_at < ?",
        (now,),
    )
    for r in expired:
        await unblock_ip(r[0])
        logger.info(f"Auto-unblocked {r[0]} (block expired)")
