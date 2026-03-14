import json
import time
from fastapi import APIRouter, Query
from pydantic import BaseModel
from defensewatch.audit import log_audit
from defensewatch.database import get_db

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


class IncidentCreate(BaseModel):
    title: str
    description: str = ""
    severity: str = "medium"
    source_ips: list[str] = []


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    status: str | None = None


class IncidentLinkEvents(BaseModel):
    ssh_event_ids: list[int] = []
    http_event_ids: list[int] = []
    brute_force_ids: list[int] = []


@router.get("")
async def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
):
    db = get_db()
    conditions = []
    params = []
    if status:
        conditions.append("status = ?")
        params.append(status)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    offset = (page - 1) * limit

    total = (await db.execute_fetchall(
        f"SELECT COUNT(*) FROM incidents {where}", params
    ))[0][0]

    rows = await db.execute_fetchall(
        f"""SELECT id, title, description, severity, status, source_ips,
            created_at, updated_at
            FROM incidents {where}
            ORDER BY created_at DESC LIMIT ? OFFSET ?""",
        params + [limit, offset]
    )

    incidents = []
    for r in rows:
        source_ips = []
        try:
            source_ips = json.loads(r[5]) if r[5] else []
        except (json.JSONDecodeError, TypeError):
            pass
        incidents.append({
            "id": r[0], "title": r[1], "description": r[2],
            "severity": r[3], "status": r[4], "source_ips": source_ips,
            "created_at": r[6], "updated_at": r[7],
        })

    return {"total": total, "page": page, "limit": limit, "incidents": incidents}


@router.post("")
async def create_incident(body: IncidentCreate):
    db = get_db()
    now = time.time()
    cursor = await db.execute(
        """INSERT INTO incidents (title, description, severity, status, source_ips, created_at, updated_at)
           VALUES (?, ?, ?, 'open', ?, ?, ?)""",
        (body.title, body.description, body.severity,
         json.dumps(body.source_ips), now, now)
    )
    incident_id = cursor.lastrowid

    # Auto-link events from source IPs
    if body.source_ips:
        for ip in body.source_ips:
            # Link SSH events
            ssh_rows = await db.execute_fetchall(
                "SELECT id FROM ssh_events WHERE source_ip = ? ORDER BY timestamp DESC LIMIT 100",
                (ip,)
            )
            for row in ssh_rows:
                await db.execute(
                    "INSERT OR IGNORE INTO incident_events (incident_id, event_type, event_id) VALUES (?, 'ssh', ?)",
                    (incident_id, row[0])
                )

            # Link HTTP events
            http_rows = await db.execute_fetchall(
                "SELECT id FROM http_events WHERE source_ip = ? ORDER BY timestamp DESC LIMIT 100",
                (ip,)
            )
            for row in http_rows:
                await db.execute(
                    "INSERT OR IGNORE INTO incident_events (incident_id, event_type, event_id) VALUES (?, 'http', ?)",
                    (incident_id, row[0])
                )

            # Link brute force sessions
            brute_rows = await db.execute_fetchall(
                "SELECT id FROM brute_force_sessions WHERE source_ip = ? ORDER BY start_time DESC LIMIT 50",
                (ip,)
            )
            for row in brute_rows:
                await db.execute(
                    "INSERT OR IGNORE INTO incident_events (incident_id, event_type, event_id) VALUES (?, 'brute_force', ?)",
                    (incident_id, row[0])
                )

            # Link port scans
            portscan_rows = await db.execute_fetchall(
                "SELECT id FROM port_scan_events WHERE source_ip = ? ORDER BY timestamp DESC LIMIT 50",
                (ip,)
            )
            for row in portscan_rows:
                await db.execute(
                    "INSERT OR IGNORE INTO incident_events (incident_id, event_type, event_id) VALUES (?, 'port_scan', ?)",
                    (incident_id, row[0])
                )

    await db.commit()
    await log_audit("incident_create", str(incident_id), f"Created incident: {body.title}", actor="api")
    return {"id": incident_id, "status": "created"}


@router.get("/{incident_id}")
async def get_incident(incident_id: int):
    db = get_db()
    rows = await db.execute_fetchall(
        """SELECT id, title, description, severity, status, source_ips,
           created_at, updated_at FROM incidents WHERE id=?""",
        (incident_id,)
    )
    if not rows:
        return {"error": "Incident not found"}

    r = rows[0]
    source_ips = []
    try:
        source_ips = json.loads(r[5]) if r[5] else []
    except (json.JSONDecodeError, TypeError):
        pass

    # Get linked events with details
    event_rows = await db.execute_fetchall(
        "SELECT event_type, event_id FROM incident_events WHERE incident_id=?",
        (incident_id,)
    )
    linked_events = []

    for event_type, event_id in event_rows:
        event_detail = {"event_type": event_type, "event_id": event_id}

        if event_type == "ssh":
            ssh_rows = await db.execute_fetchall(
                """SELECT timestamp, event_type, source_ip, username, source_port, auth_method
                   FROM ssh_events WHERE id=?""",
                (event_id,)
            )
            if ssh_rows:
                r = ssh_rows[0]
                event_detail.update({
                    "timestamp": r[0],
                    "type": r[1],
                    "source_ip": r[2],
                    "username": r[3],
                    "source_port": r[4],
                    "auth_method": r[5],
                })

        elif event_type == "http":
            http_rows = await db.execute_fetchall(
                """SELECT timestamp, source_ip, method, path, status_code, attack_types, severity, scanner_name
                   FROM http_events WHERE id=?""",
                (event_id,)
            )
            if http_rows:
                r = http_rows[0]
                attack_types = []
                try:
                    attack_types = json.loads(r[5]) if r[5] else []
                except (json.JSONDecodeError, TypeError):
                    pass
                event_detail.update({
                    "timestamp": r[0],
                    "source_ip": r[1],
                    "method": r[2],
                    "path": r[3],
                    "status_code": r[4],
                    "attack_types": attack_types,
                    "severity": r[6],
                    "scanner_name": r[7],
                })

        elif event_type == "brute_force":
            brute_rows = await db.execute_fetchall(
                """SELECT source_ip, session_start, session_end, attempt_count, usernames_tried, status
                   FROM brute_force_sessions WHERE id=?""",
                (event_id,)
            )
            if brute_rows:
                r = brute_rows[0]
                usernames = []
                try:
                    usernames = json.loads(r[4]) if r[4] else []
                except (json.JSONDecodeError, TypeError):
                    pass
                event_detail.update({
                    "source_ip": r[0],
                    "session_start": r[1],
                    "session_end": r[2],
                    "attempt_count": r[3],
                    "usernames_tried": usernames,
                    "status": r[5],
                })

        elif event_type == "port_scan":
            ps_rows = await db.execute_fetchall(
                """SELECT source_ip, detected_at, ports_hit, port_count, status
                   FROM port_scan_events WHERE id=?""",
                (event_id,)
            )
            if ps_rows:
                r = ps_rows[0]
                ports = []
                try:
                    ports = json.loads(r[2]) if r[2] else []
                except (json.JSONDecodeError, TypeError):
                    pass
                event_detail.update({
                    "source_ip": r[0],
                    "timestamp": r[1],
                    "ports_hit": ports,
                    "port_count": r[3],
                    "status": r[4],
                })

        linked_events.append(event_detail)

    # Get enrichment data for source IPs
    enrichment_data = {}
    for ip in source_ips:
        intel_rows = await db.execute_fetchall(
            """SELECT country_code, country_name, city, org, asn, isp, rdns,
               shodan_data, virustotal_data, censys_data, enriched_at
               FROM ip_intel WHERE ip = ?""",
            (ip,)
        )
        if intel_rows:
            intel = intel_rows[0]
            enrichment_data[ip] = {
                "country_code": intel[0],
                "country_name": intel[1],
                "city": intel[2],
                "org": intel[3],
                "asn": intel[4],
                "isp": intel[5],
                "rdns": intel[6],
                "shodan_data": json.loads(intel[7]) if intel[7] else None,
                "virustotal_data": json.loads(intel[8]) if intel[8] else None,
                "censys_data": json.loads(intel[9]) if intel[9] else None,
                "enriched_at": intel[10],
            }

    return {
        "id": r[0], "title": r[1], "description": r[2],
        "severity": r[3], "status": r[4], "source_ips": source_ips,
        "created_at": r[6], "updated_at": r[7],
        "linked_events": linked_events,
        "enrichment_data": enrichment_data,
    }


@router.patch("/{incident_id}")
async def update_incident(incident_id: int, body: IncidentUpdate):
    db = get_db()
    updates = []
    params = []
    if body.title is not None:
        updates.append("title=?")
        params.append(body.title)
    if body.description is not None:
        updates.append("description=?")
        params.append(body.description)
    if body.severity is not None:
        updates.append("severity=?")
        params.append(body.severity)
    if body.status is not None:
        if body.status not in ("open", "investigating", "resolved", "closed"):
            return {"error": "Invalid status"}
        updates.append("status=?")
        params.append(body.status)

    if not updates:
        return {"error": "No fields to update"}

    updates.append("updated_at=?")
    params.append(time.time())
    params.append(incident_id)

    await db.execute(
        f"UPDATE incidents SET {', '.join(updates)} WHERE id=?", params
    )
    await db.commit()
    await log_audit("incident_update", str(incident_id), f"Updated incident", actor="api")
    return {"status": "updated"}


@router.post("/{incident_id}/events")
async def link_events(incident_id: int, body: IncidentLinkEvents):
    db = get_db()

    # Verify incident exists
    rows = await db.execute_fetchall("SELECT id FROM incidents WHERE id=?", (incident_id,))
    if not rows:
        return {"error": "Incident not found"}

    linked = 0
    for eid in body.ssh_event_ids:
        await db.execute(
            """INSERT OR IGNORE INTO incident_events (incident_id, event_type, event_id)
               VALUES (?, 'ssh', ?)""",
            (incident_id, eid)
        )
        linked += 1
    for eid in body.http_event_ids:
        await db.execute(
            """INSERT OR IGNORE INTO incident_events (incident_id, event_type, event_id)
               VALUES (?, 'http', ?)""",
            (incident_id, eid)
        )
        linked += 1
    for eid in body.brute_force_ids:
        await db.execute(
            """INSERT OR IGNORE INTO incident_events (incident_id, event_type, event_id)
               VALUES (?, 'brute_force', ?)""",
            (incident_id, eid)
        )
        linked += 1

    await db.commit()
    await log_audit("incident_link", str(incident_id), f"Linked events", actor="api")
    return {"status": "linked", "events_linked": linked}


@router.delete("/{incident_id}/events/{event_type}/{event_id}")
async def unlink_event(incident_id: int, event_type: str, event_id: int):
    db = get_db()
    await db.execute(
        "DELETE FROM incident_events WHERE incident_id=? AND event_type=? AND event_id=?",
        (incident_id, event_type, event_id)
    )
    await db.commit()
    return {"status": "unlinked"}


@router.delete("/{incident_id}")
async def delete_incident(incident_id: int):
    """Delete an incident and all its linked events."""
    db = get_db()

    # Verify incident exists
    rows = await db.execute_fetchall("SELECT id FROM incidents WHERE id=?", (incident_id,))
    if not rows:
        return {"error": "Incident not found"}

    # Delete linked events first
    await db.execute("DELETE FROM incident_events WHERE incident_id=?", (incident_id,))

    # Delete the incident
    await db.execute("DELETE FROM incidents WHERE id=?", (incident_id,))

    await db.commit()
    await log_audit("incident_delete", str(incident_id), "Deleted incident", actor="api")
    return {"status": "deleted"}


@router.post("/{incident_id}/enrich/all")
async def enrich_incident_all(incident_id: int):
    """Enrich all source IPs in an incident using all configured APIs."""
    from defensewatch.config import get_config
    config = get_config()

    db = get_db()
    # Get incident source IPs
    rows = await db.execute_fetchall("SELECT source_ips FROM incidents WHERE id=?", (incident_id,))
    if not rows:
        return {"error": "Incident not found"}

    source_ips = []
    try:
        source_ips = json.loads(rows[0][0]) if rows[0][0] else []
    except (json.JSONDecodeError, TypeError):
        pass

    if not source_ips:
        return {"error": "No source IPs to enrich", "status": "error"}

    results = {}

    # Shodan enrichment
    if config and config.external_apis.shodan_api_key:
        from defensewatch.enrichment.shodan import lookup_shodan
        for ip in source_ips:
            if ip not in results:
                results[ip] = {}
            result = await lookup_shodan(ip, config.external_apis.shodan_api_key)
            if result:
                await db.execute(
                    "UPDATE ip_intel SET shodan_data=? WHERE ip=?",
                    (json.dumps(result), ip)
                )
                results[ip]["shodan"] = "ok"
            else:
                results[ip]["shodan"] = "failed"

    # VirusTotal enrichment
    if config and config.external_apis.virustotal_api_key:
        from defensewatch.enrichment.virustotal import lookup_virustotal
        for ip in source_ips:
            if ip not in results:
                results[ip] = {}
            result = await lookup_virustotal(ip, config.external_apis.virustotal_api_key)
            if result:
                await db.execute(
                    "UPDATE ip_intel SET virustotal_data=? WHERE ip=?",
                    (json.dumps(result), ip)
                )
                results[ip]["virustotal"] = "ok"
            else:
                results[ip]["virustotal"] = "failed"

    # Censys enrichment
    if config and config.external_apis.censys_api_id and config.external_apis.censys_api_secret:
        from defensewatch.enrichment.censys import lookup_censys
        for ip in source_ips:
            if ip not in results:
                results[ip] = {}
            result = await lookup_censys(ip, config.external_apis.censys_api_id, config.external_apis.censys_api_secret)
            if result:
                await db.execute(
                    "UPDATE ip_intel SET censys_data=? WHERE ip=?",
                    (json.dumps(result), ip)
                )
                results[ip]["censys"] = "ok"
            else:
                results[ip]["censys"] = "failed"

    # Threat intel enrichment
    if config and config.threat_intel.enabled:
        from defensewatch.enrichment.threat_intel import enrich_ip_threat_intel
        for ip in source_ips:
            if ip not in results:
                results[ip] = {}
            result = await enrich_ip_threat_intel(ip, config.threat_intel)
            if result:
                results[ip]["threat_intel"] = "ok"
            else:
                results[ip]["threat_intel"] = "no_data"

    await db.commit()
    return {"status": "ok", "results": results}


@router.post("/{incident_id}/enrich/shodan")
async def enrich_incident_shodan(incident_id: int):
    """Enrich all source IPs in an incident using Shodan API."""
    from defensewatch.config import get_config
    config = get_config()

    if not config or not config.external_apis.shodan_api_key:
        return {"error": "Shodan API key not configured", "status": "error"}

    db = get_db()
    # Get incident source IPs
    rows = await db.execute_fetchall("SELECT source_ips FROM incidents WHERE id=?", (incident_id,))
    if not rows:
        return {"error": "Incident not found"}

    source_ips = []
    try:
        source_ips = json.loads(rows[0][0]) if rows[0][0] else []
    except (json.JSONDecodeError, TypeError):
        pass

    if not source_ips:
        return {"error": "No source IPs to enrich", "status": "error"}

    from defensewatch.enrichment.shodan import lookup_shodan
    results = {}
    for ip in source_ips:
        result = await lookup_shodan(ip, config.external_apis.shodan_api_key)
        if result:
            await db.execute(
                "UPDATE ip_intel SET shodan_data=? WHERE ip=?",
                (json.dumps(result), ip)
            )
            results[ip] = {"status": "ok"}
        else:
            results[ip] = {"status": "failed"}

    await db.commit()
    return {"status": "ok", "results": results}


@router.post("/{incident_id}/enrich/virustotal")
async def enrich_incident_virustotal(incident_id: int):
    """Enrich all source IPs in an incident using VirusTotal API."""
    from defensewatch.config import get_config
    config = get_config()

    if not config or not config.external_apis.virustotal_api_key:
        return {"error": "VirusTotal API key not configured", "status": "error"}

    db = get_db()
    # Get incident source IPs
    rows = await db.execute_fetchall("SELECT source_ips FROM incidents WHERE id=?", (incident_id,))
    if not rows:
        return {"error": "Incident not found"}

    source_ips = []
    try:
        source_ips = json.loads(rows[0][0]) if rows[0][0] else []
    except (json.JSONDecodeError, TypeError):
        pass

    if not source_ips:
        return {"error": "No source IPs to enrich", "status": "error"}

    from defensewatch.enrichment.virustotal import lookup_virustotal
    results = {}
    for ip in source_ips:
        result = await lookup_virustotal(ip, config.external_apis.virustotal_api_key)
        if result:
            await db.execute(
                "UPDATE ip_intel SET virustotal_data=? WHERE ip=?",
                (json.dumps(result), ip)
            )
            results[ip] = {"status": "ok"}
        else:
            results[ip] = {"status": "failed"}

    await db.commit()
    return {"status": "ok", "results": results}


@router.post("/{incident_id}/enrich/censys")
async def enrich_incident_censys(incident_id: int):
    """Enrich all source IPs in an incident using Censys API."""
    from defensewatch.config import get_config
    config = get_config()

    if not config or not config.external_apis.censys_api_id or not config.external_apis.censys_api_secret:
        return {"error": "Censys API credentials not configured", "status": "error"}

    db = get_db()
    # Get incident source IPs
    rows = await db.execute_fetchall("SELECT source_ips FROM incidents WHERE id=?", (incident_id,))
    if not rows:
        return {"error": "Incident not found"}

    source_ips = []
    try:
        source_ips = json.loads(rows[0][0]) if rows[0][0] else []
    except (json.JSONDecodeError, TypeError):
        pass

    if not source_ips:
        return {"error": "No source IPs to enrich", "status": "error"}

    from defensewatch.enrichment.censys import lookup_censys
    results = {}
    for ip in source_ips:
        result = await lookup_censys(ip, config.external_apis.censys_api_id, config.external_apis.censys_api_secret)
        if result:
            await db.execute(
                "UPDATE ip_intel SET censys_data=? WHERE ip=?",
                (json.dumps(result), ip)
            )
            results[ip] = {"status": "ok"}
        else:
            results[ip] = {"status": "failed"}

    await db.commit()
    return {"status": "ok", "results": results}


@router.post("/{incident_id}/enrich/threat-intel")
async def enrich_incident_threat_intel(incident_id: int):
    """Enrich all source IPs in an incident using threat intel feeds."""
    from defensewatch.config import get_config
    config = get_config()

    if not config or not config.threat_intel.enabled:
        return {"error": "Threat intel not enabled", "status": "error"}

    db = get_db()
    # Get incident source IPs
    rows = await db.execute_fetchall("SELECT source_ips FROM incidents WHERE id=?", (incident_id,))
    if not rows:
        return {"error": "Incident not found"}

    source_ips = []
    try:
        source_ips = json.loads(rows[0][0]) if rows[0][0] else []
    except (json.JSONDecodeError, TypeError):
        pass

    if not source_ips:
        return {"error": "No source IPs to enrich", "status": "error"}

    from defensewatch.enrichment.threat_intel import enrich_ip_threat_intel
    results = {}
    for ip in source_ips:
        result = await enrich_ip_threat_intel(ip, config.threat_intel)
        if result:
            results[ip] = {"status": "ok", "data": result}
        else:
            results[ip] = {"status": "no_data"}

    return {"status": "ok", "results": results}
