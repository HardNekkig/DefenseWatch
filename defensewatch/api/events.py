import csv
import io
import json
from fastapi import APIRouter, Query
from starlette.responses import StreamingResponse
from defensewatch.database import get_db

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("/ssh")
async def get_ssh_events(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    ip: str | None = None,
    type: str | None = None,
    since: float | None = None,
    sort: str | None = None,
    order: str = Query("desc", pattern="^(asc|desc)$"),
):
    db = get_db()
    conditions = []
    params = []

    if ip:
        conditions.append("source_ip = ?")
        params.append(ip)
    if type:
        conditions.append("event_type = ?")
        params.append(type)
    if since:
        conditions.append("timestamp >= ?")
        params.append(since)

    valid_sort_cols = {
        "timestamp": "s.timestamp", "event_type": "s.event_type", "username": "s.username",
        "source_ip": "s.source_ip", "source_port": "s.source_port", "service_port": "s.service_port",
    }
    order_col = valid_sort_cols.get(sort, "s.timestamp")
    order_dir = "ASC" if order == "asc" else "DESC"

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    offset = (page - 1) * limit

    count_rows = await db.execute_fetchall(f"SELECT COUNT(*) FROM ssh_events {where}", params)
    total = count_rows[0][0]

    rows = await db.execute_fetchall(
        f"""SELECT s.*, i.country_code, i.org, i.city
            FROM ssh_events s LEFT JOIN ip_intel i ON s.ip_id = i.id
            {where} ORDER BY {order_col} {order_dir} LIMIT ? OFFSET ?""",
        params + [limit, offset]
    )

    events = []
    for r in rows:
        events.append({
            "id": r["id"], "timestamp": r["timestamp"], "event_type": r["event_type"],
            "username": r["username"], "source_ip": r["source_ip"], "source_port": r["source_port"],
            "auth_method": r["auth_method"], "hostname": r["hostname"], "pid": r["pid"],
            "service_port": r["service_port"],
            "country_code": r["country_code"], "org": r["org"], "city": r["city"],
        })

    return {"total": total, "page": page, "limit": limit, "events": events}


@router.get("/http")
async def get_http_events(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    ip: str | None = None,
    severity: str | None = None,
    vhost: str | None = None,
    since: float | None = None,
    sort: str | None = None,
    order: str = Query("desc", pattern="^(asc|desc)$"),
):
    db = get_db()
    conditions = []
    params = []

    if ip:
        conditions.append("source_ip = ?")
        params.append(ip)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if vhost:
        conditions.append("vhost = ?")
        params.append(vhost)
    if since:
        conditions.append("timestamp >= ?")
        params.append(since)

    valid_sort_cols = {
        "timestamp": "h.timestamp", "source_ip": "h.source_ip", "method": "h.method",
        "path": "h.path", "status_code": "h.status_code", "severity": "h.severity",
        "vhost": "h.vhost", "service_port": "h.service_port", "scanner_name": "h.scanner_name",
    }
    order_col = valid_sort_cols.get(sort, "h.timestamp")
    order_dir = "ASC" if order == "asc" else "DESC"

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    offset = (page - 1) * limit

    count_rows = await db.execute_fetchall(f"SELECT COUNT(*) FROM http_events {where}", params)
    total = count_rows[0][0]

    rows = await db.execute_fetchall(
        f"""SELECT h.*, i.country_code, i.org, i.city
            FROM http_events h LEFT JOIN ip_intel i ON h.ip_id = i.id
            {where} ORDER BY {order_col} {order_dir} LIMIT ? OFFSET ?""",
        params + [limit, offset]
    )

    events = []
    for r in rows:
        attack_types = []
        try:
            attack_types = json.loads(r["attack_types"]) if r["attack_types"] else []
        except (json.JSONDecodeError, TypeError):
            pass
        events.append({
            "id": r["id"], "timestamp": r["timestamp"], "source_ip": r["source_ip"],
            "method": r["method"], "path": r["path"], "status_code": r["status_code"],
            "response_bytes": r["response_bytes"], "user_agent": r["user_agent"], "vhost": r["vhost"],
            "attack_types": attack_types, "scanner_name": r["scanner_name"],
            "severity": r["severity"], "service_port": r["service_port"],
            "country_code": r["country_code"], "org": r["org"], "city": r["city"],
        })

    return {"total": total, "page": page, "limit": limit, "events": events}


@router.get("/services")
async def get_service_events(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    ip: str | None = None,
    service_type: str | None = None,
    event_type: str | None = None,
    since: float | None = None,
):
    db = get_db()
    conditions = []
    params = []

    if ip:
        conditions.append("source_ip = ?")
        params.append(ip)
    if service_type:
        conditions.append("service_type = ?")
        params.append(service_type)
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)
    if since:
        conditions.append("timestamp >= ?")
        params.append(since)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    offset = (page - 1) * limit

    count_rows = await db.execute_fetchall(
        f"SELECT COUNT(*) FROM service_events {where}", params
    )
    total = count_rows[0][0]

    rows = await db.execute_fetchall(
        f"""SELECT s.*, i.country_code, i.org, i.city
            FROM service_events s LEFT JOIN ip_intel i ON s.ip_id = i.id
            {where} ORDER BY s.timestamp DESC LIMIT ? OFFSET ?""",
        params + [limit, offset]
    )

    events = []
    for r in rows:
        events.append({
            "id": r["id"], "timestamp": r["timestamp"],
            "service_type": r["service_type"], "event_type": r["event_type"],
            "source_ip": r["source_ip"], "username": r["username"],
            "detail": r["detail"], "severity": r["severity"],
            "service_port": r["service_port"],
            "country_code": r["country_code"], "org": r["org"], "city": r["city"],
        })

    return {"total": total, "page": page, "limit": limit, "events": events}


@router.get("/services/summary")
async def get_service_summary():
    """Aggregate counts by service_type."""
    db = get_db()
    rows = await db.execute_fetchall(
        """SELECT service_type, COUNT(*) as cnt,
           SUM(CASE WHEN severity IN ('high','critical') THEN 1 ELSE 0 END) as critical_high
           FROM service_events GROUP BY service_type ORDER BY cnt DESC"""
    )
    return {"services": [
        {"service_type": r[0], "count": r[1], "critical_high": r[2]}
        for r in rows
    ]}


@router.get("/http/vhosts")
async def get_http_vhosts():
    """List distinct vhosts seen in HTTP events."""
    db = get_db()
    rows = await db.execute_fetchall(
        "SELECT DISTINCT vhost FROM http_events WHERE vhost IS NOT NULL AND vhost != '' ORDER BY vhost"
    )
    return {"vhosts": [r[0] for r in rows]}


@router.get("/portscans")
async def get_portscan_events(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    ip: str | None = None,
    status: str | None = None,
    since: float | None = None,
    sort: str | None = None,
    order: str = Query("desc", pattern="^(asc|desc)$"),
):
    db = get_db()
    conditions = []
    params = []

    if ip:
        conditions.append("source_ip = ?")
        params.append(ip)
    if status:
        conditions.append("status = ?")
        params.append(status)
    if since:
        conditions.append("detected_at >= ?")
        params.append(since)

    valid_sort_cols = {
        "detected_at": "p.detected_at", "source_ip": "p.source_ip",
        "port_count": "p.port_count", "status": "p.status",
    }
    order_col = valid_sort_cols.get(sort, "p.detected_at")
    order_dir = "ASC" if order == "asc" else "DESC"

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    offset = (page - 1) * limit

    count_rows = await db.execute_fetchall(
        f"SELECT COUNT(*) FROM port_scan_events {where}", params
    )
    total = count_rows[0][0]

    rows = await db.execute_fetchall(
        f"""SELECT p.id, p.source_ip, p.detected_at, p.ports_hit, p.port_count,
                   p.window_seconds, p.status, i.country_code, i.org, i.city
            FROM port_scan_events p LEFT JOIN ip_intel i ON p.ip_id = i.id
            {where} ORDER BY {order_col} {order_dir} LIMIT ? OFFSET ?""",
        params + [limit, offset]
    )

    events = []
    for r in rows:
        ports = []
        try:
            ports = json.loads(r[3]) if r[3] else []
        except (json.JSONDecodeError, TypeError):
            pass
        events.append({
            "id": r[0], "source_ip": r[1], "detected_at": r[2],
            "ports_hit": ports, "port_count": r[4],
            "window_seconds": r[5], "status": r[6],
            "country_code": r[7], "org": r[8], "city": r[9],
        })

    return {"total": total, "page": page, "limit": limit, "events": events}


@router.get("/recent")
async def get_recent_events(limit: int = Query(50, ge=1, le=200)):
    db = get_db()

    ssh_rows = await db.execute_fetchall(
        """SELECT 'ssh' as src, id, timestamp, event_type as detail, source_ip,
           username, NULL as path, NULL as severity
           FROM ssh_events ORDER BY timestamp DESC LIMIT ?""",
        (limit,)
    )
    http_rows = await db.execute_fetchall(
        """SELECT 'http' as src, id, timestamp, method || ' ' || path as detail, source_ip,
           NULL as username, path, severity
           FROM http_events ORDER BY timestamp DESC LIMIT ?""",
        (limit,)
    )
    svc_rows = await db.execute_fetchall(
        """SELECT service_type as src, id, timestamp, detail, source_ip,
           username, NULL as path, severity
           FROM service_events ORDER BY timestamp DESC LIMIT ?""",
        (limit,)
    )
    ps_rows = await db.execute_fetchall(
        """SELECT 'port_scan' as src, id, detected_at as timestamp,
           'Port scan: ' || port_count || ' ports' as detail, source_ip,
           NULL as username, NULL as path, 'high' as severity
           FROM port_scan_events ORDER BY detected_at DESC LIMIT ?""",
        (limit,)
    )

    combined = []
    for r in list(ssh_rows) + list(http_rows) + list(svc_rows) + list(ps_rows):
        combined.append({
            "source": r[0], "id": r[1], "timestamp": r[2],
            "detail": r[3], "source_ip": r[4], "username": r[5],
            "path": r[6], "severity": r[7],
        })

    combined.sort(key=lambda x: x["timestamp"], reverse=True)
    return {"events": combined[:limit]}


def _build_where(ip: str | None, type_or_sev: str | None, since: float | None,
                 field_name: str) -> tuple[str, list]:
    conditions = []
    params = []
    if ip:
        conditions.append("source_ip = ?")
        params.append(ip)
    if type_or_sev:
        conditions.append(f"{field_name} = ?")
        params.append(type_or_sev)
    if since:
        conditions.append("timestamp >= ?")
        params.append(since)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    return where, params


def _csv_response(rows: list[dict], filename: str) -> StreamingResponse:
    if not rows:
        return StreamingResponse(
            iter(["No data\n"]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/ssh/export")
async def export_ssh_events(
    format: str = Query("csv", pattern="^(csv|json)$"),
    ip: str | None = None,
    type: str | None = None,
    since: float | None = None,
    limit: int = Query(10000, ge=1, le=100000),
):
    db = get_db()
    where, params = _build_where(ip, type, since, "event_type")

    rows = await db.execute_fetchall(
        f"""SELECT s.id, s.timestamp, s.event_type, s.username, s.source_ip,
            s.source_port, s.auth_method, s.hostname, s.service_port,
            i.country_code, i.org, i.city
            FROM ssh_events s LEFT JOIN ip_intel i ON s.ip_id = i.id
            {where} ORDER BY s.timestamp DESC LIMIT ?""",
        params + [limit]
    )

    events = []
    for r in rows:
        events.append({
            "id": r[0], "timestamp": r[1], "event_type": r[2],
            "username": r[3], "source_ip": r[4], "source_port": r[5],
            "auth_method": r[6], "hostname": r[7], "service_port": r[8],
            "country_code": r[9], "org": r[10], "city": r[11],
        })

    if format == "json":
        return {"events": events}
    return _csv_response(events, "ssh_events.csv")


@router.get("/http/export")
async def export_http_events(
    format: str = Query("csv", pattern="^(csv|json)$"),
    ip: str | None = None,
    severity: str | None = None,
    since: float | None = None,
    limit: int = Query(10000, ge=1, le=100000),
):
    db = get_db()
    where, params = _build_where(ip, severity, since, "severity")

    rows = await db.execute_fetchall(
        f"""SELECT h.id, h.timestamp, h.source_ip, h.method, h.path,
            h.status_code, h.response_bytes, h.user_agent, h.vhost,
            h.attack_types, h.scanner_name, h.severity, h.service_port,
            i.country_code, i.org, i.city
            FROM http_events h LEFT JOIN ip_intel i ON h.ip_id = i.id
            {where} ORDER BY h.timestamp DESC LIMIT ?""",
        params + [limit]
    )

    events = []
    for r in rows:
        attack_types = ""
        try:
            attack_types = ",".join(json.loads(r[9])) if r[9] else ""
        except (json.JSONDecodeError, TypeError):
            pass
        events.append({
            "id": r[0], "timestamp": r[1], "source_ip": r[2],
            "method": r[3], "path": r[4], "status_code": r[5],
            "response_bytes": r[6], "user_agent": r[7], "vhost": r[8],
            "attack_types": attack_types, "scanner_name": r[10],
            "severity": r[11], "service_port": r[12],
            "country_code": r[13], "org": r[14], "city": r[15],
        })

    if format == "json":
        return {"events": events}
    return _csv_response(events, "http_events.csv")
