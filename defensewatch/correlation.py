"""Multi-stage attack correlation engine for DefenseWatch.

Periodically scans recent events across all tables, applies correlation rules
to identify multi-stage attacks, and auto-creates incidents when patterns are
detected.
"""

import asyncio
import json
import logging
import time

from defensewatch.audit import log_audit
from defensewatch.config import CorrelationConfig
from defensewatch.database import get_db

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_config: CorrelationConfig | None = None
_manager = None  # ConnectionManager from broadcast.py


def set_correlation_deps(config: CorrelationConfig, manager) -> None:
    """Inject runtime dependencies (called from main.py lifespan)."""
    global _config, _manager
    _config = config
    _manager = manager


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _highest_severity(severities: list[str]) -> str:
    """Return the highest severity from a list of severity strings."""
    best = "medium"
    for s in severities:
        if _SEVERITY_ORDER.get(s, 0) > _SEVERITY_ORDER.get(best, 0):
            best = s
    return best


# ---------------------------------------------------------------------------
# Correlation rules
#
# Each rule is an async function:
#   (db, ip, lookback_start) -> (matched: bool, description: str, severity: str)
#
# ``lookback_start`` is a UNIX timestamp; the rule should consider events
# with timestamps >= lookback_start.
# ---------------------------------------------------------------------------


async def _rule_coordinated_attack(
    db, ip: str, lookback_start: float,
) -> tuple[bool, str, str]:
    """IP has events in 3+ different event tables within the window."""
    tables_hit: list[str] = []

    count = (await db.execute_fetchall(
        "SELECT COUNT(*) FROM ssh_events WHERE source_ip = ? AND timestamp >= ?",
        (ip, lookback_start),
    ))[0][0]
    if count:
        tables_hit.append("ssh_events")

    count = (await db.execute_fetchall(
        "SELECT COUNT(*) FROM http_events WHERE source_ip = ? AND timestamp >= ?",
        (ip, lookback_start),
    ))[0][0]
    if count:
        tables_hit.append("http_events")

    count = (await db.execute_fetchall(
        "SELECT COUNT(*) FROM port_scan_events WHERE source_ip = ? AND detected_at >= ?",
        (ip, lookback_start),
    ))[0][0]
    if count:
        tables_hit.append("port_scan_events")

    count = (await db.execute_fetchall(
        "SELECT COUNT(*) FROM brute_force_sessions WHERE source_ip = ? AND session_start >= ?",
        (ip, lookback_start),
    ))[0][0]
    if count:
        tables_hit.append("brute_force_sessions")

    count = (await db.execute_fetchall(
        "SELECT COUNT(*) FROM honeypot_events WHERE source_ip = ? AND timestamp >= ?",
        (ip, lookback_start),
    ))[0][0]
    if count:
        tables_hit.append("honeypot_events")

    count = (await db.execute_fetchall(
        "SELECT COUNT(*) FROM service_events WHERE source_ip = ? AND timestamp >= ?",
        (ip, lookback_start),
    ))[0][0]
    if count:
        tables_hit.append("service_events")

    if len(tables_hit) >= 3:
        desc = (
            f"Coordinated attack: IP {ip} has activity across "
            f"{len(tables_hit)} event sources ({', '.join(tables_hit)})"
        )
        return True, desc, "critical"

    return False, "", "critical"


async def _rule_brute_then_exploit(
    db, ip: str, lookback_start: float,
) -> tuple[bool, str, str]:
    """IP has a brute-force session followed by an HTTP attack within the window."""
    brute_rows = await db.execute_fetchall(
        """SELECT session_start FROM brute_force_sessions
           WHERE source_ip = ? AND session_start >= ?
           ORDER BY session_start ASC LIMIT 1""",
        (ip, lookback_start),
    )
    if not brute_rows:
        return False, "", "high"

    brute_start = brute_rows[0][0]

    http_attack_rows = await db.execute_fetchall(
        """SELECT id FROM http_events
           WHERE source_ip = ? AND timestamp >= ? AND timestamp >= ?
             AND attack_types IS NOT NULL AND attack_types != '[]' AND attack_types != ''
           LIMIT 1""",
        (ip, lookback_start, brute_start),
    )
    if http_attack_rows:
        desc = (
            f"Brute-force-then-exploit: IP {ip} launched a brute-force "
            f"session followed by HTTP attack(s)"
        )
        return True, desc, "high"

    return False, "", "high"


async def _rule_recon_to_attack(
    db, ip: str, lookback_start: float,
) -> tuple[bool, str, str]:
    """IP has a port scan followed by any attack (SSH fail or HTTP attack)."""
    scan_rows = await db.execute_fetchall(
        """SELECT detected_at FROM port_scan_events
           WHERE source_ip = ? AND detected_at >= ?
           ORDER BY detected_at ASC LIMIT 1""",
        (ip, lookback_start),
    )
    if not scan_rows:
        return False, "", "high"

    scan_time = scan_rows[0][0]

    # Check for SSH failed auth after scan
    ssh_fail = await db.execute_fetchall(
        """SELECT id FROM ssh_events
           WHERE source_ip = ? AND timestamp >= ?
             AND event_type IN ('failed_password', 'invalid_user', 'failed_none',
                                'failed_publickey', 'break_in_attempt')
           LIMIT 1""",
        (ip, scan_time),
    )
    if ssh_fail:
        desc = (
            f"Recon-to-attack: IP {ip} performed port scan "
            f"followed by SSH brute-force attempts"
        )
        return True, desc, "high"

    # Check for HTTP attack after scan
    http_attack = await db.execute_fetchall(
        """SELECT id FROM http_events
           WHERE source_ip = ? AND timestamp >= ?
             AND attack_types IS NOT NULL AND attack_types != '[]' AND attack_types != ''
           LIMIT 1""",
        (ip, scan_time),
    )
    if http_attack:
        desc = (
            f"Recon-to-attack: IP {ip} performed port scan "
            f"followed by HTTP attack(s)"
        )
        return True, desc, "high"

    return False, "", "high"


async def _rule_multi_service(
    db, ip: str, lookback_start: float,
) -> tuple[bool, str, str]:
    """IP hit 2+ different service types within the window."""
    service_types: set[str] = set()

    count = (await db.execute_fetchall(
        "SELECT COUNT(*) FROM ssh_events WHERE source_ip = ? AND timestamp >= ?",
        (ip, lookback_start),
    ))[0][0]
    if count:
        service_types.add("ssh")

    count = (await db.execute_fetchall(
        "SELECT COUNT(*) FROM http_events WHERE source_ip = ? AND timestamp >= ?",
        (ip, lookback_start),
    ))[0][0]
    if count:
        service_types.add("http")

    # service_events stores explicit service_type
    svc_rows = await db.execute_fetchall(
        """SELECT DISTINCT service_type FROM service_events
           WHERE source_ip = ? AND timestamp >= ?""",
        (ip, lookback_start),
    )
    for row in svc_rows:
        service_types.add(row[0])

    if len(service_types) >= 2:
        sorted_types = sorted(service_types)
        desc = (
            f"Multi-service targeting: IP {ip} hit {len(service_types)} "
            f"service types ({', '.join(sorted_types)})"
        )
        return True, desc, "medium"

    return False, "", "medium"


# Rule registry
_RULES: dict[str, callable] = {
    "coordinated_attack": _rule_coordinated_attack,
    "brute_then_exploit": _rule_brute_then_exploit,
    "recon_to_attack": _rule_recon_to_attack,
    "multi_service": _rule_multi_service,
}


# ---------------------------------------------------------------------------
# Incident creation
# ---------------------------------------------------------------------------


async def create_correlation_incident(
    db, ip: str, matches: list[tuple[str, str, str]],
) -> dict:
    """Create an incident from correlation matches.

    Parameters
    ----------
    db : aiosqlite.Connection
    ip : str
        Source IP that triggered the correlation.
    matches : list[tuple[str, str, str]]
        List of ``(rule_name, description, severity)`` tuples.

    Returns
    -------
    dict with ``id``, ``title``, ``severity``, ``descriptions``.
    """
    severity = _highest_severity([m[2] for m in matches])
    title = f"Correlated attack from {ip}"
    descriptions = [m[1] for m in matches]
    description = "Auto-correlated incident:\n" + "\n".join(
        f"- {d}" for d in descriptions
    )

    now = time.time()
    cursor = await db.execute(
        """INSERT INTO incidents
           (title, description, severity, status, source_ips, created_at, updated_at)
           VALUES (?, ?, ?, 'open', ?, ?, ?)""",
        (title, description, severity, json.dumps([ip]), now, now),
    )
    incident_id = cursor.lastrowid

    # Auto-link related events from this IP
    for tbl, etype, ts_col in (
        ("ssh_events", "ssh", "timestamp"),
        ("http_events", "http", "timestamp"),
        ("brute_force_sessions", "brute_force", "session_start"),
        ("port_scan_events", "port_scan", "detected_at"),
    ):
        rows = await db.execute_fetchall(
            f"SELECT id FROM {tbl} WHERE source_ip = ? ORDER BY {ts_col} DESC LIMIT 100",
            (ip,),
        )
        for row in rows:
            await db.execute(
                "INSERT OR IGNORE INTO incident_events (incident_id, event_type, event_id) VALUES (?, ?, ?)",
                (incident_id, etype, row[0]),
            )

    await db.commit()

    await log_audit(
        "correlation_incident_create",
        str(incident_id),
        f"Auto-created correlated incident for {ip}: {', '.join(r[0] for r in matches)}",
        actor="correlation_engine",
    )

    return {
        "id": incident_id,
        "title": title,
        "severity": severity,
        "descriptions": descriptions,
    }


# ---------------------------------------------------------------------------
# Main evaluation loop
# ---------------------------------------------------------------------------


async def evaluate_correlations(
    db, lookback_seconds: int, enabled_rules: list[str] | None = None,
) -> list[dict]:
    """Run correlation rules against all recently-active IPs.

    Returns a list of newly created incident dicts.
    """
    lookback_start = time.time() - lookback_seconds

    # Collect all IPs active in the lookback window
    ip_rows = await db.execute_fetchall(
        """SELECT DISTINCT source_ip FROM (
               SELECT source_ip FROM ssh_events WHERE timestamp >= ?
               UNION
               SELECT source_ip FROM http_events WHERE timestamp >= ?
               UNION
               SELECT source_ip FROM port_scan_events WHERE detected_at >= ?
           )""",
        (lookback_start, lookback_start, lookback_start),
    )

    active_ips = [row[0] for row in ip_rows if row[0]]
    if not active_ips:
        return []

    # Determine which rules to run
    if enabled_rules is None:
        enabled_rules = list(_RULES.keys())
    rules_to_run = [
        (name, fn) for name, fn in _RULES.items() if name in enabled_rules
    ]

    new_incidents: list[dict] = []

    for ip in active_ips:
        matches: list[tuple[str, str, str]] = []

        for rule_name, rule_fn in rules_to_run:
            try:
                matched, description, severity = await rule_fn(
                    db, ip, lookback_start,
                )
                if matched:
                    matches.append((rule_name, description, severity))
            except Exception:
                logger.exception("Correlation rule %s failed for IP %s", rule_name, ip)

        if not matches:
            continue

        # Check for an existing open/investigating incident for this IP
        existing = await db.execute_fetchall(
            """SELECT id FROM incidents
               WHERE status IN ('open', 'investigating')
                 AND source_ips LIKE ?""",
            (f'%"{ip}"%',),
        )
        if existing:
            logger.debug(
                "Skipping incident creation for %s – open incident %d exists",
                ip,
                existing[0][0],
            )
            continue

        incident = await create_correlation_incident(db, ip, matches)
        new_incidents.append(incident)

    return new_incidents


# ---------------------------------------------------------------------------
# Background loop
# ---------------------------------------------------------------------------


async def correlation_loop(config: CorrelationConfig, manager) -> None:
    """Long-running task: evaluate correlations on a fixed interval.

    Meant to be launched via ``asyncio.create_task(correlation_loop(...))``.
    """
    logger.info(
        "Correlation engine started (interval=%ds, lookback=%ds, rules=%s)",
        config.check_interval_seconds,
        config.lookback_seconds,
        config.rules,
    )

    while True:
        try:
            await asyncio.sleep(config.check_interval_seconds)

            if not config.enabled:
                continue

            db = get_db()
            new_incidents = await evaluate_correlations(
                db,
                lookback_seconds=config.lookback_seconds,
                enabled_rules=config.rules,
            )

            for incident in new_incidents:
                logger.info(
                    "Correlation incident created: #%d %s (%s)",
                    incident["id"],
                    incident["title"],
                    incident["severity"],
                )
                if manager is not None:
                    try:
                        await manager.broadcast("correlation_alert", {
                            "incident_id": incident["id"],
                            "title": incident["title"],
                            "severity": incident["severity"],
                            "descriptions": incident["descriptions"],
                        })
                    except Exception:
                        logger.exception("Failed to broadcast correlation alert")

        except asyncio.CancelledError:
            logger.info("Correlation engine stopped")
            return
        except Exception:
            logger.exception("Correlation engine error; will retry next cycle")
