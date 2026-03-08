import json
import time
from fastapi import APIRouter, Query
from defensewatch.database import get_db

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("/summary")
async def get_summary():
    db = get_db()
    ssh_count = (await db.execute_fetchall("SELECT COUNT(*) FROM ssh_events"))[0][0]
    http_count = (await db.execute_fetchall("SELECT COUNT(*) FROM http_events"))[0][0]
    svc_count = (await db.execute_fetchall("SELECT COUNT(*) FROM service_events"))[0][0]
    unique_ips = (await db.execute_fetchall(
        """SELECT COUNT(DISTINCT ip) FROM (
           SELECT source_ip as ip FROM ssh_events
           UNION SELECT source_ip as ip FROM http_events
           UNION SELECT source_ip as ip FROM service_events WHERE source_ip IS NOT NULL
           UNION SELECT source_ip as ip FROM port_scan_events)"""
    ))[0][0]
    brute_forces = (await db.execute_fetchall("SELECT COUNT(*) FROM brute_force_sessions"))[0][0]
    port_scans = (await db.execute_fetchall("SELECT COUNT(*) FROM port_scan_events"))[0][0]
    countries = (await db.execute_fetchall(
        "SELECT COUNT(DISTINCT country_code) FROM ip_intel WHERE country_code IS NOT NULL"
    ))[0][0]

    return {
        "ssh_events": ssh_count,
        "http_events": http_count,
        "service_events": svc_count,
        "unique_ips": unique_ips,
        "brute_forces": brute_forces,
        "port_scans": port_scans,
        "countries": countries,
    }


@router.get("/ssh")
async def get_ssh_stats(hours: int = Query(24, ge=1, le=8760)):
    db = get_db()
    since = time.time() - (hours * 3600)

    # Time series (attempts per hour)
    timeseries = await db.execute_fetchall(
        """SELECT CAST((timestamp / 3600) AS INTEGER) * 3600 as hour, COUNT(*)
           FROM ssh_events WHERE timestamp >= ?
           GROUP BY hour ORDER BY hour""",
        (since,)
    )

    # Top usernames
    top_users = await db.execute_fetchall(
        """SELECT username, COUNT(*) as cnt FROM ssh_events
           WHERE username IS NOT NULL AND event_type IN ('failed_password', 'invalid_user')
           GROUP BY username ORDER BY cnt DESC LIMIT 15"""
    )

    # Top source IPs
    top_ips = await db.execute_fetchall(
        """SELECT s.source_ip, COUNT(*) as cnt, i.country_code, i.org
           FROM ssh_events s LEFT JOIN ip_intel i ON s.ip_id = i.id
           WHERE s.event_type IN ('failed_password', 'invalid_user')
           GROUP BY s.source_ip ORDER BY cnt DESC LIMIT 15"""
    )

    return {
        "timeseries": [{"hour": r[0], "count": r[1]} for r in timeseries],
        "top_usernames": [{"username": r[0], "count": r[1]} for r in top_users],
        "top_ips": [{"ip": r[0], "count": r[1], "country_code": r[2], "org": r[3]} for r in top_ips],
    }


@router.get("/http")
async def get_http_stats(hours: int = Query(24, ge=1, le=8760)):
    db = get_db()
    since = time.time() - (hours * 3600)

    timeseries = await db.execute_fetchall(
        """SELECT CAST((timestamp / 3600) AS INTEGER) * 3600 as hour, COUNT(*)
           FROM http_events WHERE timestamp >= ?
           GROUP BY hour ORDER BY hour""",
        (since,)
    )

    # Top attacked endpoints
    top_paths = await db.execute_fetchall(
        """SELECT path, COUNT(*) as cnt FROM http_events
           GROUP BY path ORDER BY cnt DESC LIMIT 15"""
    )

    # Attack type breakdown
    attack_rows = await db.execute_fetchall(
        "SELECT attack_types FROM http_events WHERE attack_types IS NOT NULL"
    )
    attack_counts: dict[str, int] = {}
    for r in attack_rows:
        try:
            types = json.loads(r[0])
            for t in types:
                attack_counts[t] = attack_counts.get(t, 0) + 1
        except (json.JSONDecodeError, TypeError):
            pass

    # Scanner breakdown
    scanners = await db.execute_fetchall(
        """SELECT scanner_name, COUNT(*) as cnt FROM http_events
           WHERE scanner_name IS NOT NULL
           GROUP BY scanner_name ORDER BY cnt DESC LIMIT 10"""
    )

    return {
        "timeseries": [{"hour": r[0], "count": r[1]} for r in timeseries],
        "top_paths": [{"path": r[0], "count": r[1]} for r in top_paths],
        "attack_types": [{"type": k, "count": v} for k, v in sorted(attack_counts.items(), key=lambda x: -x[1])],
        "scanners": [{"name": r[0], "count": r[1]} for r in scanners],
    }


@router.get("/top-ips")
async def get_top_ips(hours: int = Query(24, ge=1, le=8760), limit: int = Query(15, ge=1, le=50)):
    """Most active IPs across SSH and HTTP, with multi-attack flagging."""
    db = get_db()
    since = time.time() - (hours * 3600)

    rows = await db.execute_fetchall(
        """SELECT combined.ip, combined.ssh_cnt, combined.http_cnt, combined.brute_cnt,
                  combined.portscan_cnt,
                  i.country_code, i.country_name, i.org,
                  (combined.ssh_cnt + combined.http_cnt) as total
           FROM (
               SELECT ip,
                      SUM(ssh_cnt) as ssh_cnt,
                      SUM(http_cnt) as http_cnt,
                      SUM(brute_cnt) as brute_cnt,
                      SUM(portscan_cnt) as portscan_cnt
               FROM (
                   SELECT source_ip as ip, COUNT(*) as ssh_cnt, 0 as http_cnt, 0 as brute_cnt, 0 as portscan_cnt
                   FROM ssh_events WHERE timestamp >= ? GROUP BY source_ip
                   UNION ALL
                   SELECT source_ip as ip, 0, COUNT(*), 0, 0
                   FROM http_events WHERE timestamp >= ? GROUP BY source_ip
                   UNION ALL
                   SELECT source_ip as ip, 0, 0, COUNT(*), 0
                   FROM brute_force_sessions WHERE session_start >= ? GROUP BY source_ip
                   UNION ALL
                   SELECT source_ip as ip, 0, 0, 0, COUNT(*)
                   FROM port_scan_events WHERE detected_at >= ? GROUP BY source_ip
               )
               GROUP BY ip
           ) combined
           LEFT JOIN ip_intel i ON combined.ip = i.ip
           ORDER BY total DESC
           LIMIT ?""",
        (since, since, since, since, limit),
    )

    ips = []
    for r in rows:
        ssh_cnt = r[1] or 0
        http_cnt = r[2] or 0
        brute_cnt = r[3] or 0
        portscan_cnt = r[4] or 0
        attack_types = []
        if ssh_cnt > 0:
            attack_types.append("ssh")
        if http_cnt > 0:
            attack_types.append("http")
        if brute_cnt > 0:
            attack_types.append("brute_force")
        if portscan_cnt > 0:
            attack_types.append("port_scan")
        ips.append({
            "ip": r[0],
            "ssh_count": ssh_cnt,
            "http_count": http_cnt,
            "brute_count": brute_cnt,
            "portscan_count": portscan_cnt,
            "total": ssh_cnt + http_cnt,
            "country_code": r[5],
            "country_name": r[6],
            "org": r[7],
            "attack_types": attack_types,
            "multi_attack": len(attack_types) > 1,
        })
    return {"ips": ips}


@router.get("/geo")
async def get_geo_stats():
    db = get_db()
    rows = await db.execute_fetchall(
        """SELECT country_code, country_name, COUNT(*) as cnt
           FROM ip_intel WHERE country_code IS NOT NULL
           GROUP BY country_code ORDER BY cnt DESC"""
    )
    return {
        "countries": [{"code": r[0], "name": r[1], "count": r[2]} for r in rows],
    }
