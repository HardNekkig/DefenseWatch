import time
import json
import logging
import httpx
from defensewatch.config import ReportsConfig
from defensewatch.database import get_db

logger = logging.getLogger(__name__)


async def generate_report() -> dict:
    """Generate a summary report of the last reporting period."""
    db = get_db()
    now = time.time()
    day_ago = now - 86400

    # SSH summary
    ssh_rows = await db.execute_fetchall(
        "SELECT COUNT(*) FROM ssh_events WHERE timestamp > ?", (day_ago,)
    )
    ssh_total = ssh_rows[0][0] if ssh_rows else 0

    ssh_type_rows = await db.execute_fetchall(
        """SELECT event_type, COUNT(*) FROM ssh_events
           WHERE timestamp > ? GROUP BY event_type ORDER BY COUNT(*) DESC""",
        (day_ago,)
    )
    ssh_by_type = {r[0]: r[1] for r in ssh_type_rows}

    # HTTP summary
    http_rows = await db.execute_fetchall(
        "SELECT COUNT(*) FROM http_events WHERE timestamp > ?", (day_ago,)
    )
    http_total = http_rows[0][0] if http_rows else 0

    http_sev_rows = await db.execute_fetchall(
        """SELECT severity, COUNT(*) FROM http_events
           WHERE timestamp > ? GROUP BY severity ORDER BY COUNT(*) DESC""",
        (day_ago,)
    )
    http_by_severity = {r[0]: r[1] for r in http_sev_rows}

    # Brute force sessions
    brute_rows = await db.execute_fetchall(
        "SELECT COUNT(*) FROM brute_force_sessions WHERE session_start > ?", (day_ago,)
    )
    brute_count = brute_rows[0][0] if brute_rows else 0

    # Top attacking IPs
    top_ips = await db.execute_fetchall(
        """SELECT t.ip, cnt, i.country_code, i.org FROM (
           SELECT source_ip as ip, COUNT(*) as cnt FROM (
               SELECT source_ip FROM ssh_events WHERE timestamp > ?
               UNION ALL SELECT source_ip FROM http_events WHERE timestamp > ?
           ) GROUP BY source_ip ORDER BY cnt DESC LIMIT 10
        ) t LEFT JOIN ip_intel i ON i.ip = t.ip""",
        (day_ago, day_ago)
    )
    top_attackers = [
        {"ip": r[0], "event_count": r[1], "country": r[2], "org": r[3]}
        for r in top_ips
    ]

    # Unique IPs
    unique_rows = await db.execute_fetchall(
        """SELECT COUNT(DISTINCT ip) FROM (
           SELECT source_ip as ip FROM ssh_events WHERE timestamp > ?
           UNION SELECT source_ip as ip FROM http_events WHERE timestamp > ?)""",
        (day_ago, day_ago)
    )
    unique_ips = unique_rows[0][0] if unique_rows else 0

    # Active incidents
    incident_rows = await db.execute_fetchall(
        "SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'investigating')"
    )
    active_incidents = incident_rows[0][0] if incident_rows else 0

    # Anomalies in last 24h
    anomaly_rows = await db.execute_fetchall(
        "SELECT COUNT(*) FROM anomaly_alerts WHERE detected_at > ?", (day_ago,)
    )
    anomaly_count = anomaly_rows[0][0] if anomaly_rows else 0

    return {
        "period_start": day_ago,
        "period_end": now,
        "ssh": {"total": ssh_total, "by_type": ssh_by_type},
        "http": {"total": http_total, "by_severity": http_by_severity},
        "brute_force_sessions": brute_count,
        "unique_attacking_ips": unique_ips,
        "top_attackers": top_attackers,
        "active_incidents": active_incidents,
        "anomalies_detected": anomaly_count,
    }


async def send_report(config: ReportsConfig):
    """Generate and send a report via webhook."""
    if not config.enabled or not config.webhook_url:
        return

    report = await generate_report()

    # Format as readable text
    text_lines = [
        "*DefenseWatch Daily Report*",
        f"Period: {time.strftime('%Y-%m-%d %H:%M', time.localtime(report['period_start']))} — {time.strftime('%Y-%m-%d %H:%M', time.localtime(report['period_end']))}",
        "",
        f"SSH events: {report['ssh']['total']}",
        f"HTTP attacks: {report['http']['total']}",
        f"Brute force sessions: {report['brute_force_sessions']}",
        f"Unique attacking IPs: {report['unique_attacking_ips']}",
        f"Active incidents: {report['active_incidents']}",
        f"Anomalies detected: {report['anomalies_detected']}",
        "",
        "*Top Attackers:*",
    ]
    for a in report["top_attackers"][:5]:
        text_lines.append(
            f"  `{a['ip']}` — {a['event_count']} events ({a.get('country') or '??'}, {a.get('org') or 'unknown'})"
        )

    payload = {
        "text": "\n".join(text_lines),
        "event_type": "daily_report",
        "report": report,
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(config.webhook_url, json=payload)
            if resp.status_code >= 400:
                logger.warning(f"Report webhook returned {resp.status_code}")
            else:
                logger.info("Daily report sent")
    except Exception as e:
        logger.error(f"Report delivery failed: {e}")
