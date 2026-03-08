from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query
from defensewatch.database import get_db
from defensewatch.config import AppConfig

router = APIRouter(prefix="/api/map", tags=["map"])

_config: AppConfig | None = None

# Attacks within this many minutes are considered "active" (blinking)
ACTIVE_MINUTES = 10


def set_config(config: AppConfig):
    global _config
    _config = config


@router.get("/arcs")
async def get_arcs(hours: int = Query(24, ge=1, le=168)):
    db = get_db()

    import time as _time
    now = _time.time()
    since = now - hours * 3600
    active_since = now - ACTIVE_MINUTES * 60

    rows = await db.execute_fetchall(
        """SELECT i.ip, i.latitude, i.longitude, i.country_code, i.org,
           COALESCE(sc.cnt, 0) as ssh_count,
           COALESCE(hc.cnt, 0) as http_count,
           MAX(COALESCE(sc.last_seen, 0), COALESCE(hc.last_seen, 0)) as last_seen
           FROM ip_intel i
           LEFT JOIN (
               SELECT source_ip, COUNT(*) as cnt, MAX(timestamp) as last_seen
               FROM ssh_events WHERE timestamp >= ?
               GROUP BY source_ip
           ) sc ON sc.source_ip = i.ip
           LEFT JOIN (
               SELECT source_ip, COUNT(*) as cnt, MAX(timestamp) as last_seen
               FROM http_events WHERE timestamp >= ?
               GROUP BY source_ip
           ) hc ON hc.source_ip = i.ip
           WHERE i.latitude IS NOT NULL AND i.longitude IS NOT NULL""",
        (since, since),
    )

    if not _config or _config.host.latitude is None:
        # Default to coordinates of 0,0 if not configured
        dst_lat, dst_lon = 0.0, 0.0
    else:
        dst_lat = _config.host.latitude
        dst_lon = _config.host.longitude

    arcs = []
    for r in rows:
        ssh_count = r[5] or 0
        http_count = r[6] or 0
        total = ssh_count + http_count
        if total == 0:
            continue

        last_seen = r[7] or 0
        active = last_seen >= active_since if last_seen else False

        if ssh_count > 0 and http_count > 0:
            arc_type = "mixed"
        elif ssh_count > 0:
            arc_type = "ssh"
        else:
            arc_type = "http"

        arcs.append({
            "ip": r[0],
            "src_lat": r[1],
            "src_lon": r[2],
            "dst_lat": dst_lat,
            "dst_lon": dst_lon,
            "count": total,
            "country": r[3],
            "org": r[4],
            "type": arc_type,
            "ssh_count": ssh_count,
            "http_count": http_count,
            "last_seen": last_seen,
            "active": active,
        })

    return {"arcs": arcs, "since": since, "active_threshold_min": ACTIVE_MINUTES}


@router.get("/host")
async def get_host():
    if not _config or _config.host.latitude is None:
        return {"latitude": 0.0, "longitude": 0.0, "name": "server"}
    return {
        "latitude": _config.host.latitude,
        "longitude": _config.host.longitude,
        "name": _config.host.name,
    }
