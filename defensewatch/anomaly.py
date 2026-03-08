import time
import logging
import math
from defensewatch.database import get_db

logger = logging.getLogger(__name__)


async def compute_baselines():
    """Compute hourly baselines for SSH and HTTP event rates over the last 7 days."""
    db = get_db()
    cutoff = time.time() - (7 * 86400)

    # SSH events per hour baseline
    rows = await db.execute_fetchall(
        """SELECT CAST((timestamp - ?) / 3600 AS INTEGER) % 168 AS hour_slot,
                  COUNT(*) as cnt
           FROM ssh_events WHERE timestamp > ?
           GROUP BY hour_slot""",
        (cutoff, cutoff)
    )
    ssh_by_hour = {}
    for r in rows:
        ssh_by_hour[r[0]] = r[1]

    # HTTP events per hour baseline
    rows = await db.execute_fetchall(
        """SELECT CAST((timestamp - ?) / 3600 AS INTEGER) % 168 AS hour_slot,
                  COUNT(*) as cnt
           FROM http_events WHERE timestamp > ?
           GROUP BY hour_slot""",
        (cutoff, cutoff)
    )
    http_by_hour = {}
    for r in rows:
        http_by_hour[r[0]] = r[1]

    # Compute mean and stddev for each hour
    now = time.time()

    for event_type, by_hour in [("ssh", ssh_by_hour), ("http", http_by_hour)]:
        values = list(by_hour.values()) if by_hour else [0]
        mean = sum(values) / max(len(values), 1)
        variance = sum((v - mean) ** 2 for v in values) / max(len(values), 1)
        stddev = math.sqrt(variance) if variance > 0 else 1.0

        await db.execute(
            """INSERT INTO baselines (metric, mean, stddev, sample_count, computed_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(metric) DO UPDATE SET
               mean=excluded.mean, stddev=excluded.stddev,
               sample_count=excluded.sample_count, computed_at=excluded.computed_at""",
            (f"{event_type}_hourly_rate", mean, stddev, len(values), now)
        )

    # Unique IPs per hour
    rows = await db.execute_fetchall(
        """SELECT COUNT(DISTINCT source_ip) FROM ssh_events WHERE timestamp > ?
           UNION ALL
           SELECT COUNT(DISTINCT source_ip) FROM http_events WHERE timestamp > ?""",
        (cutoff, cutoff)
    )
    unique_ips = sum(r[0] for r in rows)
    hours = max(168, 1)
    ips_per_hour = unique_ips / hours

    await db.execute(
        """INSERT INTO baselines (metric, mean, stddev, sample_count, computed_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(metric) DO UPDATE SET
           mean=excluded.mean, stddev=excluded.stddev,
           sample_count=excluded.sample_count, computed_at=excluded.computed_at""",
        ("unique_ips_hourly", ips_per_hour, ips_per_hour * 0.5, unique_ips, now)
    )

    await db.commit()
    logger.info("Baselines recomputed")


async def check_anomalies() -> list[dict]:
    """Check current hour's activity against baselines, return any anomalies."""
    db = get_db()
    anomalies = []
    now = time.time()
    hour_ago = now - 3600

    # Load baselines
    baseline_rows = await db.execute_fetchall("SELECT metric, mean, stddev FROM baselines")
    baselines = {r[0]: {"mean": r[1], "stddev": r[2]} for r in baseline_rows}

    if not baselines:
        return anomalies

    # SSH rate check
    rows = await db.execute_fetchall(
        "SELECT COUNT(*) FROM ssh_events WHERE timestamp > ?", (hour_ago,)
    )
    ssh_count = rows[0][0] if rows else 0
    bl = baselines.get("ssh_hourly_rate")
    if bl and bl["stddev"] > 0:
        z_score = (ssh_count - bl["mean"]) / bl["stddev"]
        if z_score > 3:
            anomalies.append({
                "metric": "ssh_hourly_rate",
                "current": ssh_count,
                "baseline_mean": round(bl["mean"], 1),
                "z_score": round(z_score, 2),
                "severity": "critical" if z_score > 5 else "high",
                "message": f"SSH event rate {ssh_count}/hr is {z_score:.1f} std devs above baseline ({bl['mean']:.0f}/hr)",
            })

    # HTTP rate check
    rows = await db.execute_fetchall(
        "SELECT COUNT(*) FROM http_events WHERE timestamp > ?", (hour_ago,)
    )
    http_count = rows[0][0] if rows else 0
    bl = baselines.get("http_hourly_rate")
    if bl and bl["stddev"] > 0:
        z_score = (http_count - bl["mean"]) / bl["stddev"]
        if z_score > 3:
            anomalies.append({
                "metric": "http_hourly_rate",
                "current": http_count,
                "baseline_mean": round(bl["mean"], 1),
                "z_score": round(z_score, 2),
                "severity": "critical" if z_score > 5 else "high",
                "message": f"HTTP event rate {http_count}/hr is {z_score:.1f} std devs above baseline ({bl['mean']:.0f}/hr)",
            })

    # Unique IPs check
    rows = await db.execute_fetchall(
        """SELECT COUNT(DISTINCT source_ip) FROM (
           SELECT source_ip FROM ssh_events WHERE timestamp > ?
           UNION SELECT source_ip FROM http_events WHERE timestamp > ?)""",
        (hour_ago, hour_ago)
    )
    unique_ips = rows[0][0] if rows else 0
    bl = baselines.get("unique_ips_hourly")
    if bl and bl["stddev"] > 0:
        z_score = (unique_ips - bl["mean"]) / bl["stddev"]
        if z_score > 3:
            anomalies.append({
                "metric": "unique_ips_hourly",
                "current": unique_ips,
                "baseline_mean": round(bl["mean"], 1),
                "z_score": round(z_score, 2),
                "severity": "critical" if z_score > 5 else "high",
                "message": f"Unique attacking IPs {unique_ips}/hr is {z_score:.1f} std devs above baseline ({bl['mean']:.0f}/hr)",
            })

    # Store anomalies
    for a in anomalies:
        await db.execute(
            """INSERT INTO anomaly_alerts (metric, current_value, baseline_mean, z_score,
               severity, message, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (a["metric"], a["current"], a["baseline_mean"], a["z_score"],
             a["severity"], a["message"], now)
        )
    if anomalies:
        await db.commit()

    return anomalies
