import json
import os
import time

from fastapi import APIRouter, Query
from defensewatch.api import events, stats, ips, map as map_router, ws, incidents, scanner, firewall, fail2ban, telegram, settings
from defensewatch.database import get_db


api_router = APIRouter()

# Health endpoint
@api_router.get("/api/health")
async def health():
    from defensewatch.main import _watcher_manager, _enrichment_pipeline, _start_time
    db = get_db()
    db_path = None
    db_size = 0
    try:
        rows = await db.execute_fetchall("PRAGMA database_list")
        if rows:
            db_path = rows[0][2]
            if db_path and os.path.exists(db_path):
                db_size = os.path.getsize(db_path)
    except Exception:
        pass

    watcher_status = _watcher_manager.status if _watcher_manager else {}
    queue_depth = _enrichment_pipeline.queue_depth if _enrichment_pipeline else 0

    return {
        "status": "ok",
        "uptime_seconds": round(time.time() - _start_time, 1) if _start_time else 0,
        "db_size_bytes": db_size,
        "watchers": watcher_status,
        "enrichment_queue_depth": queue_depth,
    }

# Anomaly detection endpoint
@api_router.get("/api/anomalies")
async def get_anomalies(hours: int = Query(24, ge=1, le=168)):
    db = get_db()
    cutoff = time.time() - (hours * 3600)
    rows = await db.execute_fetchall(
        """SELECT id, metric, current_value, baseline_mean, z_score, severity, message, detected_at
           FROM anomaly_alerts WHERE detected_at > ? ORDER BY detected_at DESC""",
        (cutoff,)
    )
    return {"anomalies": [
        {"id": r[0], "metric": r[1], "current_value": r[2], "baseline_mean": r[3],
         "z_score": r[4], "severity": r[5], "message": r[6], "detected_at": r[7]}
        for r in rows
    ]}


# Threat intel lookup endpoint
@api_router.get("/api/threat-intel/{ip}")
async def get_threat_intel(ip: str):
    from defensewatch.enrichment.threat_intel import get_cached_threat_intel
    cached = await get_cached_threat_intel(ip)
    if cached:
        return cached
    return {"data": None, "message": "No threat intel data cached for this IP"}


# Report generation endpoint
@api_router.get("/api/reports/latest")
async def get_latest_report():
    from defensewatch.reports import generate_report
    return await generate_report()


# Brute force endpoint
@api_router.get("/api/brute-force")
async def get_brute_force():
    db = get_db()
    rows = await db.execute_fetchall(
        """SELECT b.*, i.country_code, i.org, i.city
           FROM brute_force_sessions b
           LEFT JOIN ip_intel i ON b.ip_id = i.id
           ORDER BY b.session_end DESC LIMIT 100"""
    )
    sessions = []
    for r in rows:
        usernames = []
        try:
            usernames = json.loads(r[5]) if r[5] else []
        except (json.JSONDecodeError, TypeError):
            pass
        sessions.append({
            "id": r[0], "source_ip": r[1], "session_start": r[2],
            "session_end": r[3], "attempt_count": r[4],
            "usernames_tried": usernames, "event_type": r[6],
            "status": r[7], "service_port": r[8],
            "country_code": r[11], "org": r[12], "city": r[13],
        })
    return {"sessions": sessions}


def mount_routers(app):
    app.include_router(events.router)
    app.include_router(stats.router)
    app.include_router(ips.router)
    app.include_router(map_router.router)
    app.include_router(ws.router)
    app.include_router(incidents.router)
    app.include_router(scanner.router)
    app.include_router(firewall.router)
    app.include_router(fail2ban.router)
    app.include_router(telegram.router)
    app.include_router(settings.router)
    app.include_router(api_router)
