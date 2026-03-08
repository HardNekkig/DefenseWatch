import json
import time
from fastapi import APIRouter, Query
from defensewatch.database import get_db
from defensewatch.config import AppConfig

router = APIRouter(prefix="/api/ips", tags=["ips"])

_config: AppConfig | None = None


def set_config(config: AppConfig):
    global _config
    _config = config


@router.get("")
async def get_ips(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    search: str | None = None,
):
    db = get_db()
    conditions = []
    params = []

    if search:
        conditions.append("(ip LIKE ? OR rdns LIKE ? OR org LIKE ? OR country_name LIKE ?)")
        s = f"%{search}%"
        params.extend([s, s, s, s])

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    offset = (page - 1) * limit

    total = (await db.execute_fetchall(f"SELECT COUNT(*) FROM ip_intel {where}", params))[0][0]

    rows = await db.execute_fetchall(
        f"""SELECT i.*,
            COALESCE(sc.cnt, 0) as ssh_count,
            COALESCE(hc.cnt, 0) as http_count
            FROM ip_intel i
            LEFT JOIN (SELECT source_ip, COUNT(*) as cnt FROM ssh_events GROUP BY source_ip) sc ON sc.source_ip = i.ip
            LEFT JOIN (SELECT source_ip, COUNT(*) as cnt FROM http_events GROUP BY source_ip) hc ON hc.source_ip = i.ip
            {where}
            ORDER BY i.enriched_at DESC LIMIT ? OFFSET ?""",
        params + [limit, offset]
    )

    ips = []
    for r in rows:
        ips.append({
            "id": r[0], "ip": r[1], "rdns": r[2], "asn": r[3], "org": r[4],
            "country_code": r[5], "country_name": r[6], "city": r[7],
            "latitude": r[8], "longitude": r[9], "isp": r[10],
            "source": r[12], "enriched_at": r[13],
            "ssh_count": r[18], "http_count": r[19],
        })

    return {"total": total, "page": page, "limit": limit, "ips": ips}


@router.get("/{ip}")
async def get_ip_detail(ip: str):
    db = get_db()

    intel_rows = await db.execute_fetchall("SELECT * FROM ip_intel WHERE ip=?", (ip,))
    intel = None
    shodan_data = None
    virustotal_data = None
    censys_data = None
    if intel_rows:
        r = intel_rows[0]
        intel = {
            "id": r[0], "ip": r[1], "rdns": r[2], "asn": r[3], "org": r[4],
            "country_code": r[5], "country_name": r[6], "city": r[7],
            "latitude": r[8], "longitude": r[9], "isp": r[10],
            "whois_raw": r[11], "source": r[12], "enriched_at": r[13],
        }
        try:
            shodan_data = json.loads(r["shodan_data"]) if r["shodan_data"] else None
        except (json.JSONDecodeError, TypeError, IndexError):
            pass
        try:
            virustotal_data = json.loads(r["virustotal_data"]) if r["virustotal_data"] else None
        except (json.JSONDecodeError, TypeError, IndexError):
            pass
        try:
            censys_data = json.loads(r["censys_data"]) if r["censys_data"] else None
        except (json.JSONDecodeError, TypeError, IndexError):
            pass

    ssh_rows = await db.execute_fetchall(
        """SELECT id, timestamp, event_type, username, source_port, auth_method
           FROM ssh_events WHERE source_ip=? ORDER BY timestamp DESC LIMIT 100""",
        (ip,)
    )
    ssh_events = [
        {"id": r[0], "timestamp": r[1], "event_type": r[2],
         "username": r[3], "source_port": r[4], "auth_method": r[5]}
        for r in ssh_rows
    ]

    http_rows = await db.execute_fetchall(
        """SELECT id, timestamp, method, path, status_code, attack_types, severity, scanner_name
           FROM http_events WHERE source_ip=? ORDER BY timestamp DESC LIMIT 100""",
        (ip,)
    )
    http_events = []
    for r in http_rows:
        attack_types = []
        try:
            attack_types = json.loads(r[5]) if r[5] else []
        except (json.JSONDecodeError, TypeError):
            pass
        http_events.append({
            "id": r[0], "timestamp": r[1], "method": r[2], "path": r[3],
            "status_code": r[4], "attack_types": attack_types,
            "severity": r[6], "scanner_name": r[7],
        })

    brute_rows = await db.execute_fetchall(
        """SELECT id, session_start, session_end, attempt_count, usernames_tried, status
           FROM brute_force_sessions WHERE source_ip=? ORDER BY session_end DESC LIMIT 20""",
        (ip,)
    )
    brute_sessions = []
    for r in brute_rows:
        usernames = []
        try:
            usernames = json.loads(r[4]) if r[4] else []
        except (json.JSONDecodeError, TypeError):
            pass
        brute_sessions.append({
            "id": r[0], "session_start": r[1], "session_end": r[2],
            "attempt_count": r[3], "usernames_tried": usernames, "status": r[5],
        })

    # Port scan events
    ps_rows = await db.execute_fetchall(
        """SELECT id, detected_at, ports_hit, port_count, status
           FROM port_scan_events WHERE source_ip=? ORDER BY detected_at DESC LIMIT 20""",
        (ip,)
    )
    port_scans = []
    for r in ps_rows:
        ports = []
        try:
            ports = json.loads(r[2]) if r[2] else []
        except (json.JSONDecodeError, TypeError):
            pass
        port_scans.append({
            "id": r[0], "detected_at": r[1], "ports_hit": ports,
            "port_count": r[3], "status": r[4],
        })

    # Activity summary
    ssh_count = (await db.execute_fetchall(
        "SELECT COUNT(*) FROM ssh_events WHERE source_ip=?", (ip,)))[0][0]
    http_count = (await db.execute_fetchall(
        "SELECT COUNT(*) FROM http_events WHERE source_ip=?", (ip,)))[0][0]

    first_seen_rows = await db.execute_fetchall(
        """SELECT MIN(ts) FROM (
           SELECT MIN(timestamp) as ts FROM ssh_events WHERE source_ip=?
           UNION ALL SELECT MIN(timestamp) as ts FROM http_events WHERE source_ip=?)""",
        (ip, ip)
    )
    last_seen_rows = await db.execute_fetchall(
        """SELECT MAX(ts) FROM (
           SELECT MAX(timestamp) as ts FROM ssh_events WHERE source_ip=?
           UNION ALL SELECT MAX(timestamp) as ts FROM http_events WHERE source_ip=?)""",
        (ip, ip)
    )

    summary = {
        "ssh_count": ssh_count,
        "http_count": http_count,
        "brute_force_count": len(brute_sessions),
        "port_scan_count": len(port_scans),
        "first_seen": first_seen_rows[0][0] if first_seen_rows else None,
        "last_seen": last_seen_rows[0][0] if last_seen_rows else None,
    }

    # Threat intel
    threat_intel = None
    try:
        ti_rows = await db.execute_fetchall(
            "SELECT data, checked_at FROM threat_intel_hits WHERE ip=? ORDER BY checked_at DESC LIMIT 1",
            (ip,)
        )
        if ti_rows and ti_rows[0][0]:
            threat_intel = {"data": json.loads(ti_rows[0][0]), "checked_at": ti_rows[0][1]}
    except Exception:
        pass

    return {
        "intel": intel, "summary": summary,
        "ssh_events": ssh_events, "http_events": http_events,
        "brute_sessions": brute_sessions, "port_scans": port_scans,
        "shodan": shodan_data, "virustotal": virustotal_data, "censys": censys_data,
        "threat_intel": threat_intel,
    }


@router.post("/{ip}/enrich/shodan")
async def enrich_shodan(ip: str):
    if not _config or not _config.external_apis.shodan_api_key:
        return {"error": "Shodan API key not configured", "status": "error"}

    from defensewatch.enrichment.shodan import lookup_shodan
    result = await lookup_shodan(ip, _config.external_apis.shodan_api_key)
    if result is None:
        return {"error": "Shodan lookup failed", "status": "error"}

    db = get_db()
    await db.execute(
        "UPDATE ip_intel SET shodan_data=? WHERE ip=?",
        (json.dumps(result), ip)
    )
    await db.commit()
    return {"status": "ok", "shodan": result}


@router.post("/{ip}/enrich/virustotal")
async def enrich_virustotal(ip: str):
    if not _config or not _config.external_apis.virustotal_api_key:
        return {"error": "VirusTotal API key not configured", "status": "error"}

    from defensewatch.enrichment.virustotal import lookup_virustotal
    result = await lookup_virustotal(ip, _config.external_apis.virustotal_api_key)
    if result is None:
        return {"error": "VirusTotal lookup failed", "status": "error"}

    db = get_db()
    await db.execute(
        "UPDATE ip_intel SET virustotal_data=? WHERE ip=?",
        (json.dumps(result), ip)
    )
    await db.commit()
    return {"status": "ok", "virustotal": result}


@router.post("/{ip}/enrich/censys")
async def enrich_censys(ip: str):
    if not _config or not _config.external_apis.censys_api_id or not _config.external_apis.censys_api_secret:
        return {"error": "Censys API credentials not configured", "status": "error"}

    from defensewatch.enrichment.censys import lookup_censys
    result = await lookup_censys(ip, _config.external_apis.censys_api_id, _config.external_apis.censys_api_secret)
    if result is None:
        return {"error": "Censys lookup failed", "status": "error"}

    db = get_db()
    await db.execute(
        "UPDATE ip_intel SET censys_data=? WHERE ip=?",
        (json.dumps(result), ip)
    )
    await db.commit()
    return {"status": "ok", "censys": result}


@router.post("/{ip}/enrich/threat-intel")
async def enrich_threat_intel(ip: str):
    if not _config or not _config.threat_intel.enabled:
        return {"error": "Threat intel not enabled", "status": "error"}

    from defensewatch.enrichment.threat_intel import enrich_ip_threat_intel
    result = await enrich_ip_threat_intel(ip, _config.threat_intel)
    if result is None:
        return {"error": "No threat intel data found", "status": "error"}
    return {"status": "ok", "threat_intel": {"data": result, "checked_at": time.time()}}


@router.get("/{ip}/timeline")
async def get_ip_timeline(ip: str, limit: int = Query(200, ge=1, le=1000)):
    """Unified timeline of SSH + HTTP events for a single IP, sorted chronologically."""
    db = get_db()

    ssh_rows = await db.execute_fetchall(
        """SELECT 'ssh' as source, id, timestamp, event_type as detail, username, NULL as path,
           NULL as severity, auth_method
           FROM ssh_events WHERE source_ip=? ORDER BY timestamp DESC LIMIT ?""",
        (ip, limit)
    )
    http_rows = await db.execute_fetchall(
        """SELECT 'http' as source, id, timestamp, method || ' ' || path as detail,
           NULL as username, path, severity, NULL as auth_method
           FROM http_events WHERE source_ip=? ORDER BY timestamp DESC LIMIT ?""",
        (ip, limit)
    )

    events = []
    for r in ssh_rows:
        events.append({
            "source": r[0], "id": r[1], "timestamp": r[2], "detail": r[3],
            "username": r[4], "path": r[5], "severity": r[6], "auth_method": r[7],
        })
    for r in http_rows:
        events.append({
            "source": r[0], "id": r[1], "timestamp": r[2], "detail": r[3],
            "username": r[4], "path": r[5], "severity": r[6], "auth_method": r[7],
        })

    events.sort(key=lambda x: x["timestamp"], reverse=True)
    return {"ip": ip, "events": events[:limit]}


@router.get("/{ip}/timeline24h")
async def get_ip_timeline_24h(ip: str):
    """Hourly-bucketed attack counts over the last 24 hours for an IP."""
    import time as _time
    from datetime import datetime, timedelta, timezone

    db = get_db()
    now = _time.time()
    since = now - 24 * 3600

    ssh_rows = await db.execute_fetchall(
        """SELECT timestamp, event_type FROM ssh_events
           WHERE source_ip=? AND timestamp>=? ORDER BY timestamp""",
        (ip, since),
    )
    http_rows = await db.execute_fetchall(
        """SELECT timestamp, severity FROM http_events
           WHERE source_ip=? AND timestamp>=? ORDER BY timestamp""",
        (ip, since),
    )
    brute_rows = await db.execute_fetchall(
        """SELECT session_start, attempt_count FROM brute_force_sessions
           WHERE source_ip=? AND session_start>=? ORDER BY session_start""",
        (ip, since),
    )
    portscan_rows = await db.execute_fetchall(
        """SELECT detected_at, port_count FROM port_scan_events
           WHERE source_ip=? AND detected_at>=? ORDER BY detected_at""",
        (ip, since),
    )

    # Build 24 hourly buckets
    since_dt = datetime.fromtimestamp(since, tz=timezone.utc)
    buckets = []
    for i in range(24):
        h = since_dt + timedelta(hours=i)
        buckets.append({
            "hour": h.isoformat(),
            "ssh": 0,
            "http": 0,
            "brute_attempts": 0,
            "port_scans": 0,
        })

    def bucket_index(ts):
        try:
            ts_f = float(ts)
            idx = int((ts_f - since) // 3600)
            return max(0, min(23, idx))
        except Exception:
            return 0

    for r in ssh_rows:
        buckets[bucket_index(r[0])]["ssh"] += 1
    for r in http_rows:
        buckets[bucket_index(r[0])]["http"] += 1
    for r in brute_rows:
        buckets[bucket_index(r[0])]["brute_attempts"] += (r[1] or 1)
    for r in portscan_rows:
        buckets[bucket_index(r[0])]["port_scans"] += 1

    total = {
        "ssh": len(ssh_rows), "http": len(http_rows),
        "brute_sessions": len(brute_rows), "port_scans": len(portscan_rows),
    }
    return {"ip": ip, "since": since, "buckets": buckets, "totals": total}


@router.get("/{ip}/score")
async def get_threat_score(ip: str):
    from defensewatch.scoring import compute_threat_score
    return await compute_threat_score(ip)
