"""Self-monitoring and health metrics for DefenseWatch."""

import asyncio
import logging
import os
import time
from collections import deque

from fastapi import APIRouter, Query
from defensewatch.config import HealthMonitorConfig
from defensewatch.database import get_db

logger = logging.getLogger(__name__)


# ── Metrics Store ──────────────────────────────────────────────────────


class MetricsStore:
    """Thread-safe ring-buffer metrics store."""

    def __init__(self, max_samples: int = 1440):
        self.max_samples = max_samples
        self._samples: deque[dict] = deque(maxlen=max_samples)
        self._watcher_last_event: dict[str, float] = {}  # file_path -> last_event_time
        self._event_counters: dict[str, int] = {}  # "ssh"/"http"/"service" -> total count
        self._prev_db_size: int | None = None  # for DB growth rate calculation

    def record_sample(self, sample: dict):
        """Add a timestamped sample to the ring buffer."""
        self._samples.append(sample)

    def record_event(self, event_type: str, file_path: str | None = None):
        """Record that an event was processed (called from handlers)."""
        now = time.time()
        self._event_counters[event_type] = self._event_counters.get(event_type, 0) + 1
        if file_path:
            self._watcher_last_event[file_path] = now

    def get_event_counts(self) -> dict[str, int]:
        return dict(self._event_counters)

    def get_watcher_last_events(self) -> dict[str, float]:
        return dict(self._watcher_last_event)

    def get_samples(self, last_n: int | None = None) -> list[dict]:
        if last_n is None:
            return list(self._samples)
        return list(self._samples)[-last_n:]

    def get_deadman_alerts(self, threshold_seconds: int, watched_files: list[str]) -> list[dict]:
        """Return alerts for watchers that haven't produced events recently."""
        now = time.time()
        alerts = []
        for fpath in watched_files:
            last = self._watcher_last_event.get(fpath)
            if last is None:
                # Never produced an event - only alert if system has been up > threshold
                continue
            gap = now - last
            if gap > threshold_seconds:
                alerts.append({
                    "file_path": fpath,
                    "last_event_ago_seconds": round(gap),
                    "threshold_seconds": threshold_seconds,
                    "status": "stale",
                })
        return alerts


# ── Module-level singleton ─────────────────────────────────────────────

_store: MetricsStore | None = None
_config: HealthMonitorConfig | None = None


def get_metrics_store() -> MetricsStore:
    global _store
    if _store is None:
        _store = MetricsStore()
    return _store


def set_health_config(config: HealthMonitorConfig):
    global _config
    _config = config


def get_health_config() -> HealthMonitorConfig:
    return _config or HealthMonitorConfig()


# ── Background sampling loop ──────────────────────────────────────────


async def health_monitor_loop(config: HealthMonitorConfig) -> None:
    """Background task: periodically sample system metrics."""
    store = get_metrics_store()
    logger.info("Health monitor started (interval=%ds)", config.sample_interval_seconds)

    while True:
        try:
            await asyncio.sleep(config.sample_interval_seconds)
            if not config.enabled:
                continue

            now = time.time()
            db = get_db()

            # Table counts
            ssh_count = (await db.execute_fetchall("SELECT COUNT(*) FROM ssh_events"))[0][0]
            http_count = (await db.execute_fetchall("SELECT COUNT(*) FROM http_events"))[0][0]
            svc_count = (await db.execute_fetchall("SELECT COUNT(*) FROM service_events"))[0][0]
            brute_count = (await db.execute_fetchall("SELECT COUNT(*) FROM brute_force_sessions"))[0][0]

            # Recent event rates (last 5 min)
            five_min_ago = now - 300
            ssh_rate = (await db.execute_fetchall(
                "SELECT COUNT(*) FROM ssh_events WHERE created_at >= ?", (five_min_ago,)))[0][0]
            http_rate = (await db.execute_fetchall(
                "SELECT COUNT(*) FROM http_events WHERE created_at >= ?", (five_min_ago,)))[0][0]

            # DB size
            db_size = 0
            try:
                rows = await db.execute_fetchall("PRAGMA database_list")
                if rows:
                    db_path = rows[0][2]
                    if db_path and os.path.exists(db_path):
                        db_size = os.path.getsize(db_path)
            except Exception:
                pass

            # DB growth rate (bytes per sample interval)
            db_growth_rate = 0
            if store._prev_db_size is not None:
                db_growth_rate = db_size - store._prev_db_size
            store._prev_db_size = db_size

            # Enrichment queue depth
            enrichment_depth = 0
            try:
                from defensewatch.main import _enrichment_pipeline
                if _enrichment_pipeline:
                    enrichment_depth = _enrichment_pipeline.queue_depth
            except Exception:
                pass

            sample = {
                "timestamp": now,
                "ssh_total": ssh_count,
                "http_total": http_count,
                "service_total": svc_count,
                "brute_total": brute_count,
                "ssh_rate_5m": ssh_rate,
                "http_rate_5m": http_rate,
                "db_size_bytes": db_size,
                "db_growth_bytes": db_growth_rate,
                "enrichment_queue_depth": enrichment_depth,
                "event_counters": store.get_event_counts(),
            }
            store.record_sample(sample)

        except asyncio.CancelledError:
            logger.info("Health monitor stopped")
            return
        except Exception:
            logger.exception("Health monitor sampling error")


# ── API ────────────────────────────────────────────────────────────────

router = APIRouter(prefix="/api/health-monitor", tags=["health-monitor"])


@router.get("/metrics")
async def get_metrics(last: int = Query(60, ge=1, le=1440)):
    """Return recent metric samples."""
    store = get_metrics_store()
    config = get_health_config()
    samples = store.get_samples(last_n=last)
    return {
        "enabled": config.enabled,
        "sample_count": len(samples),
        "samples": samples,
    }


@router.get("/status")
async def get_health_status():
    """Comprehensive health status with deadman alerts."""
    store = get_metrics_store()
    config = get_health_config()

    # Get watcher info
    watched_files: list[str] = []
    watchers_active = 0
    observer_alive = False
    try:
        from defensewatch.main import _watcher_manager
        if _watcher_manager:
            ws = _watcher_manager.status
            watched_files = ws.get("watched_files", [])
            watchers_active = ws.get("active_watchers", 0)
            observer_alive = ws.get("observer_alive", False)
    except Exception:
        pass

    # Uptime
    uptime_seconds = 0
    try:
        from defensewatch.main import _start_time
        if _start_time:
            uptime_seconds = round(time.time() - _start_time, 1)
    except Exception:
        pass

    # Enrichment queue depth (live, not from sample)
    enrichment_queue = 0
    try:
        from defensewatch.main import _enrichment_pipeline
        if _enrichment_pipeline:
            enrichment_queue = _enrichment_pipeline.queue_depth
    except Exception:
        pass

    # DB size (live)
    db_size_bytes = 0
    try:
        db = get_db()
        rows = await db.execute_fetchall("PRAGMA database_list")
        if rows:
            db_path = rows[0][2]
            if db_path and os.path.exists(db_path):
                db_size_bytes = os.path.getsize(db_path)
    except Exception:
        pass

    deadman_alerts = store.get_deadman_alerts(config.deadman_threshold_seconds, watched_files)
    event_counts = store.get_event_counts()
    watcher_last_events = store.get_watcher_last_events()

    # Latest sample for current snapshot
    samples = store.get_samples(last_n=1)
    latest = samples[0] if samples else {}

    # Format uptime as human-readable
    def _fmt_uptime(secs: float) -> str:
        s = int(secs)
        days, s = divmod(s, 86400)
        hours, s = divmod(s, 3600)
        minutes, s = divmod(s, 60)
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        if not parts:
            parts.append(f"{s}s")
        return " ".join(parts)

    # Format bytes
    def _fmt_bytes(b: int) -> str:
        if b < 1024:
            return f"{b} B"
        if b < 1024 * 1024:
            return f"{b / 1024:.1f} KB"
        if b < 1024 * 1024 * 1024:
            return f"{b / (1024 * 1024):.1f} MB"
        return f"{b / (1024 * 1024 * 1024):.1f} GB"

    # Deadman formatted
    now = time.time()
    formatted_deadman = []
    for a in deadman_alerts:
        ago = a["last_event_ago_seconds"]
        formatted_deadman.append({
            "file_path": a["file_path"],
            "last_event_ago": _fmt_uptime(ago),
            "last_event_ago_seconds": ago,
            "status": "alert",
        })
    # Add watched files that have never seen events (informational)
    alerted_files = {a["file_path"] for a in deadman_alerts}
    for fp in watched_files:
        if fp not in alerted_files:
            last = watcher_last_events.get(fp)
            formatted_deadman.append({
                "file_path": fp,
                "last_event_ago": _fmt_uptime(now - last) if last else "awaiting first event",
                "last_event_ago_seconds": round(now - last) if last else None,
                "status": "ok",
            })

    return {
        "enabled": config.enabled,
        "uptime": _fmt_uptime(uptime_seconds),
        "uptime_seconds": uptime_seconds,
        "db_size": _fmt_bytes(db_size_bytes),
        "db_size_bytes": db_size_bytes,
        "enrichment_queue": enrichment_queue,
        "watchers_active": watchers_active,
        "observer_alive": observer_alive,
        "watched_files": watched_files,
        "deadman_alerts": formatted_deadman,
        "event_counters": event_counts,
        "watcher_last_events": watcher_last_events,
        "latest_sample": latest,
        "total_samples": len(store.get_samples()),
    }


@router.get("/db-growth")
async def get_db_growth(last: int = Query(60, ge=1, le=1440)):
    """Return DB size history for charting."""
    store = get_metrics_store()
    samples = store.get_samples(last_n=last)

    def _fmt_ts(ts):
        import datetime
        return datetime.datetime.fromtimestamp(ts).strftime("%H:%M")

    return {
        "points": [
            {
                "time": _fmt_ts(s["timestamp"]),
                "timestamp": s["timestamp"],
                "size": s.get("db_size_bytes", 0),
                "db_size_bytes": s.get("db_size_bytes", 0),
                "db_growth_bytes": s.get("db_growth_bytes", 0),
            }
            for s in samples
        ]
    }


@router.get("/event-rates")
async def get_event_rates(last: int = Query(60, ge=1, le=1440)):
    """Return event rate history for charting."""
    store = get_metrics_store()
    samples = store.get_samples(last_n=last)

    def _fmt_ts(ts):
        import datetime
        return datetime.datetime.fromtimestamp(ts).strftime("%H:%M")

    return {
        "points": [
            {
                "time": _fmt_ts(s["timestamp"]),
                "timestamp": s["timestamp"],
                "count": s.get("ssh_rate_5m", 0) + s.get("http_rate_5m", 0),
                "ssh_rate_5m": s.get("ssh_rate_5m", 0),
                "http_rate_5m": s.get("http_rate_5m", 0),
            }
            for s in samples
        ]
    }
