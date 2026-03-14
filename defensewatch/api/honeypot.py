import json
import logging
import time

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

from defensewatch.config import HoneypotConfig, DEFAULT_HONEYPOT_PATHS
from defensewatch.database import get_db

logger = logging.getLogger(__name__)


# ── Module-level deps (set via set_honeypot_deps) ───────────

_manager = None
_config = None


def set_honeypot_deps(manager, config):
    """Called from main.py lifespan to inject the broadcast manager and config."""
    global _manager, _config
    _manager = manager
    _config = config


def _get_honeypot_config() -> HoneypotConfig:
    """Return the HoneypotConfig from app config or a default."""
    if _config and hasattr(_config, "honeypot"):
        hp = _config.honeypot
        return HoneypotConfig(
            enabled=getattr(hp, "enabled", True),
            paths=getattr(hp, "paths", None) or list(DEFAULT_HONEYPOT_PATHS),
            auto_block=getattr(hp, "auto_block", False),
            score_boost=getattr(hp, "score_boost", 25),
        )
    return HoneypotConfig()


# ── DB helpers ───────────────────────────────────────────────

_TABLE_CREATED = False


async def _ensure_table():
    """Create honeypot_events table if it doesn't exist yet."""
    global _TABLE_CREATED
    if _TABLE_CREATED:
        return
    db = get_db()
    await db.executescript("""
        CREATE TABLE IF NOT EXISTS honeypot_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            source_ip TEXT NOT NULL,
            method TEXT,
            path TEXT NOT NULL,
            user_agent TEXT,
            headers TEXT,
            status_code INTEGER NOT NULL DEFAULT 403,
            auto_blocked INTEGER NOT NULL DEFAULT 0,
            ip_id INTEGER REFERENCES ip_intel(id),
            created_at REAL NOT NULL DEFAULT (unixepoch('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_honeypot_timestamp ON honeypot_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_honeypot_source_ip ON honeypot_events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_honeypot_path ON honeypot_events(path);

        CREATE TRIGGER IF NOT EXISTS fill_honeypot_ip_id
        AFTER INSERT ON honeypot_events
        WHEN NEW.ip_id IS NULL AND NEW.source_ip IS NOT NULL
        BEGIN
            UPDATE honeypot_events
            SET ip_id = (SELECT id FROM ip_intel WHERE ip = NEW.source_ip)
            WHERE id = NEW.id;
        END;
    """)
    await db.commit()
    _TABLE_CREATED = True


async def _record_hit(source_ip: str, method: str, path: str,
                      user_agent: str, headers_json: str,
                      status_code: int, auto_blocked: bool) -> dict:
    """Insert a honeypot hit into the DB and return the event dict."""
    await _ensure_table()
    db = get_db()
    now = time.time()
    cursor = await db.execute(
        """INSERT INTO honeypot_events
           (timestamp, source_ip, method, path, user_agent, headers, status_code, auto_blocked)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (now, source_ip, method, path, user_agent, headers_json, status_code, int(auto_blocked)),
    )
    await db.commit()
    event_id = cursor.lastrowid

    event = {
        "id": event_id,
        "timestamp": now,
        "source_ip": source_ip,
        "method": method,
        "path": path,
        "user_agent": user_agent,
        "status_code": status_code,
        "auto_blocked": auto_blocked,
    }
    return event


# ── Fake response generators ────────────────────────────────

_FAKE_WP_LOGIN = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Log In &lsaquo; WordPress</title>
<style>body{background:#f1f1f1;font-family:-apple-system,BlinkMacSystemFont,sans-serif}
.login{width:320px;margin:8% auto;padding:20px;background:#fff;border:1px solid #c3c4c7;border-radius:4px}
h1{text-align:center;margin-bottom:24px}label{display:block;margin:10px 0 4px;font-size:14px}
input[type=text],input[type=password]{width:100%;padding:6px 8px;font-size:14px;border:1px solid #8c8f94;border-radius:3px;box-sizing:border-box}
input[type=submit]{margin-top:16px;width:100%;padding:8px;background:#2271b1;color:#fff;border:none;border-radius:3px;font-size:14px;cursor:pointer}
</style></head>
<body><div class="login"><h1>WordPress</h1>
<form method="post"><label>Username or Email Address</label><input type="text" name="log">
<label>Password</label><input type="password" name="pwd">
<input type="submit" value="Log In"></form></div></body></html>"""


def _fake_response(path: str) -> Response:
    """Return a realistic-looking decoy response for the given honeypot path."""
    lower = path.lower().rstrip("/")

    if lower == "/wp-login.php":
        return HTMLResponse(content=_FAKE_WP_LOGIN, status_code=200)

    if lower in ("/.env", "/phpmyadmin", "/wp-admin", "/administrator",
                  "/manager/html", "/solr/admin"):
        return Response(content="Forbidden", status_code=403,
                        media_type="text/plain")

    return Response(content="Not Found", status_code=404,
                    media_type="text/plain")


def _status_for_path(path: str) -> int:
    """Determine the HTTP status code a honeypot path will return."""
    lower = path.lower().rstrip("/")
    if lower == "/wp-login.php":
        return 200
    if lower in ("/.env", "/phpmyadmin", "/wp-admin", "/administrator",
                  "/manager/html", "/solr/admin"):
        return 403
    return 404


# ── Core handler (called by each honeypot route) ────────────

async def _handle_honeypot_hit(request: Request, path: str) -> Response:
    """Process a honeypot hit: log, store, broadcast, optionally block."""
    source_ip = request.client.host if request.client else "unknown"
    method = request.method
    user_agent = request.headers.get("user-agent", "")

    # Collect a subset of interesting headers
    safe_headers = {}
    for hdr in ("host", "referer", "origin", "accept", "accept-language",
                "x-forwarded-for", "x-real-ip", "cookie"):
        val = request.headers.get(hdr)
        if val:
            safe_headers[hdr] = val
    headers_json = json.dumps(safe_headers)

    hp_conf = _get_honeypot_config()
    status_code = _status_for_path(path)

    # Auto-block check
    auto_blocked = False
    if hp_conf.auto_block:
        try:
            from defensewatch.firewall import block_ip, detect_backend
            if detect_backend() and source_ip != "unknown":
                await block_ip(source_ip, reason=f"Honeypot hit: {path}",
                               source="honeypot")
                auto_blocked = True
                logger.info(f"Auto-blocked {source_ip} via honeypot ({path})")
        except Exception as e:
            logger.error(f"Honeypot auto-block failed for {source_ip}: {e}")

    # Record in DB
    event = await _record_hit(
        source_ip=source_ip,
        method=method,
        path=path,
        user_agent=user_agent,
        headers_json=headers_json,
        status_code=status_code,
        auto_blocked=auto_blocked,
    )

    logger.warning(f"Honeypot hit: {source_ip} -> {method} {path}")

    # WebSocket broadcast
    if _manager:
        try:
            await _manager.broadcast("honeypot_hit", event)
        except Exception as e:
            logger.error(f"Honeypot broadcast error: {e}")

    return _fake_response(path)


# ── Factory: mount honeypot catch-all routes on the app ──────

def create_honeypot_routes(app, paths: list[str] | None = None, config=None):
    """Register honeypot trap routes on the FastAPI app.

    Must be called AFTER API routers are mounted but BEFORE static files,
    so honeypot paths are matched before the static file fallback but do
    not shadow /api/* routes.
    """
    if paths is None:
        if config and hasattr(config, "honeypot"):
            paths = getattr(config.honeypot, "paths", None) or list(DEFAULT_HONEYPOT_PATHS)
        else:
            paths = list(DEFAULT_HONEYPOT_PATHS)

    for trap_path in paths:
        # Normalise: ensure leading slash, strip trailing slash for matching
        trap_path = trap_path if trap_path.startswith("/") else f"/{trap_path}"

        # Skip anything that could collide with the real API
        if trap_path.startswith("/api/") or trap_path.startswith("/api"):
            logger.warning(f"Skipping honeypot path that collides with API: {trap_path}")
            continue

        # Use a closure to capture the current trap_path value
        def _make_handler(p: str):
            async def _trap(request: Request):
                return await _handle_honeypot_hit(request, p)
            # FastAPI needs unique operation ids
            _trap.__name__ = f"honeypot_{p.replace('/', '_').replace('.', '_')}"
            return _trap

        handler = _make_handler(trap_path)

        # Register for all common methods
        for method in ("GET", "POST", "HEAD", "PUT"):
            app.add_api_route(
                trap_path,
                handler,
                methods=[method],
                include_in_schema=False,
            )

    logger.info(f"Honeypot routes registered: {len(paths)} trap paths")


# ── API router (management endpoints) ───────────────────────

router = APIRouter(prefix="/api/honeypot", tags=["honeypot"])


class HoneypotConfigUpdate(BaseModel):
    enabled: bool | None = None
    paths: list[str] | None = None
    auto_block: bool | None = None
    score_boost: int | None = None


@router.get("/events")
async def list_honeypot_events(
    ip: str | None = Query(None, description="Filter by source IP"),
    path: str | None = Query(None, description="Filter by honeypot path"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List honeypot hit events, paginated and filterable."""
    await _ensure_table()
    db = get_db()

    conditions = []
    params: list = []
    if ip:
        conditions.append("h.source_ip = ?")
        params.append(ip)
    if path:
        conditions.append("h.path = ?")
        params.append(path)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    # Total count
    count_row = await db.execute_fetchall(
        f"SELECT COUNT(*) FROM honeypot_events h {where}", params
    )
    total = count_row[0][0] if count_row else 0

    # Fetch page with IP intel join
    rows = await db.execute_fetchall(
        f"""SELECT h.id, h.timestamp, h.source_ip, h.method, h.path,
                   h.user_agent, h.headers, h.status_code, h.auto_blocked,
                   i.country_code, i.org, i.city
            FROM honeypot_events h
            LEFT JOIN ip_intel i ON h.ip_id = i.id
            {where}
            ORDER BY h.timestamp DESC
            LIMIT ? OFFSET ?""",
        params + [limit, offset],
    )

    events = []
    for r in rows:
        headers_parsed = {}
        try:
            headers_parsed = json.loads(r[6]) if r[6] else {}
        except (json.JSONDecodeError, TypeError):
            pass
        events.append({
            "id": r[0],
            "timestamp": r[1],
            "source_ip": r[2],
            "method": r[3],
            "path": r[4],
            "user_agent": r[5],
            "headers": headers_parsed,
            "status_code": r[7],
            "auto_blocked": bool(r[8]),
            "country_code": r[9],
            "org": r[10],
            "city": r[11],
        })

    return {"events": events, "total": total}


@router.get("/stats")
async def honeypot_stats():
    """Summary statistics for honeypot activity."""
    await _ensure_table()
    db = get_db()

    # Total hits
    row = await db.execute_fetchall("SELECT COUNT(*) FROM honeypot_events")
    total_hits = row[0][0] if row else 0

    # Unique IPs
    row = await db.execute_fetchall(
        "SELECT COUNT(DISTINCT source_ip) FROM honeypot_events"
    )
    unique_ips = row[0][0] if row else 0

    # Auto-blocked count
    row = await db.execute_fetchall(
        "SELECT COUNT(*) FROM honeypot_events WHERE auto_blocked = 1"
    )
    auto_blocked = row[0][0] if row else 0

    # Top paths (top 10)
    top_paths_rows = await db.execute_fetchall(
        """SELECT path, COUNT(*) as cnt
           FROM honeypot_events
           GROUP BY path ORDER BY cnt DESC LIMIT 10"""
    )
    top_paths = [{"path": r[0], "count": r[1]} for r in top_paths_rows]

    # Top IPs (top 10)
    top_ips_rows = await db.execute_fetchall(
        """SELECT h.source_ip, COUNT(*) as cnt, i.country_code
           FROM honeypot_events h
           LEFT JOIN ip_intel i ON h.ip_id = i.id
           GROUP BY h.source_ip ORDER BY cnt DESC LIMIT 10"""
    )
    top_ips = [
        {"ip": r[0], "count": r[1], "country_code": r[2]}
        for r in top_ips_rows
    ]

    # Hits in last 24h
    cutoff_24h = time.time() - 86400
    row = await db.execute_fetchall(
        "SELECT COUNT(*) FROM honeypot_events WHERE timestamp > ?", (cutoff_24h,)
    )
    hits_24h = row[0][0] if row else 0

    return {
        "total_hits": total_hits,
        "unique_ips": unique_ips,
        "auto_blocked": auto_blocked,
        "hits_24h": hits_24h,
        "top_paths": top_paths,
        "top_ips": top_ips,
    }


@router.get("/config")
async def get_honeypot_config():
    """Return current honeypot configuration."""
    hp = _get_honeypot_config()
    return {
        "enabled": hp.enabled,
        "paths": hp.paths,
        "auto_block": hp.auto_block,
        "score_boost": hp.score_boost,
    }


@router.patch("/config")
async def update_honeypot_config(body: HoneypotConfigUpdate):
    """Update honeypot configuration at runtime."""
    if not _config:
        return {"error": "Config not loaded"}

    # Ensure _config has a honeypot attribute; create one if needed
    if not hasattr(_config, "honeypot"):
        # Attach a simple namespace object
        class _Ns:
            pass
        _config.honeypot = _Ns()
        _config.honeypot.enabled = True
        _config.honeypot.paths = list(DEFAULT_HONEYPOT_PATHS)
        _config.honeypot.auto_block = False
        _config.honeypot.score_boost = 25

    hp = _config.honeypot

    if body.enabled is not None:
        hp.enabled = body.enabled
    if body.paths is not None:
        # Validate: each path must start with /
        hp.paths = [p if p.startswith("/") else f"/{p}" for p in body.paths]
    if body.auto_block is not None:
        hp.auto_block = body.auto_block
    if body.score_boost is not None:
        hp.score_boost = max(0, min(100, body.score_boost))

    logger.info("Honeypot config updated")

    # Persist to config.yaml via the settings helper
    try:
        from defensewatch.api.settings import _persist_config
        _persist_config()
    except Exception as e:
        logger.error(f"Failed to persist honeypot config: {e}")

    return {
        "ok": True,
        "enabled": hp.enabled,
        "paths": hp.paths,
        "auto_block": hp.auto_block,
        "score_boost": hp.score_boost,
    }


# ── Score boost integration ─────────────────────────────────

async def honeypot_score_boost(ip: str) -> tuple[int, list[str]]:
    """Return (score_points, reasons) for honeypot hits by this IP.

    Intended to be called from defensewatch.scoring.compute_threat_score
    to add points for IPs that triggered honeypot traps.
    """
    try:
        await _ensure_table()
    except Exception:
        return 0, []

    db = get_db()
    rows = await db.execute_fetchall(
        """SELECT COUNT(*), COUNT(DISTINCT path)
           FROM honeypot_events WHERE source_ip = ?""",
        (ip,),
    )
    if not rows or rows[0][0] == 0:
        return 0, []

    hit_count = rows[0][0]
    path_count = rows[0][1]

    hp = _get_honeypot_config()
    boost = hp.score_boost

    # Scale: base boost for first hit, extra for multiple paths
    points = boost
    if path_count > 1:
        points = min(boost + (path_count - 1) * 5, 50)

    reasons = [f"{hit_count} honeypot hits ({path_count} paths)"]
    return points, reasons
