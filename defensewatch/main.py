import json as _json
import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import FileResponse

from defensewatch.config import load_config
from defensewatch.database import init_db, close_db, cleanup_old_data
from defensewatch.broadcast import ConnectionManager
from defensewatch.watchers.manager import WatcherManager
from defensewatch.enrichment.geoip import init_geoip, close_geoip
from defensewatch.enrichment.pipeline import EnrichmentPipeline
from defensewatch.api.router import mount_routers
from defensewatch.telegram import TelegramNotifier


class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return _json.dumps(log_entry)


def _setup_logging():
    use_json = os.environ.get("DEFENSEWATCH_LOG_FORMAT", "").lower() == "json"
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    if use_json:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    root.addHandler(handler)


_setup_logging()
logger = logging.getLogger(__name__)

_watcher_manager: WatcherManager | None = None
_enrichment_pipeline: EnrichmentPipeline | None = None
_start_time: float | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _watcher_manager, _enrichment_pipeline, _start_time
    _start_time = time.time()

    config = load_config()
    logger.info(f"DefenseWatch starting on {config.server.host}:{config.server.port}")

    # Init database
    await init_db(config)
    logger.info("Database initialized")

    # Init GeoIP
    init_geoip(config.geoip.mmdb_path)

    # Broadcast manager
    manager = ConnectionManager()
    manager.start_pinger()

    # Enrichment queue and pipeline
    enrichment_queue = asyncio.Queue(maxsize=config.enrichment.max_queue_size)
    _enrichment_pipeline = EnrichmentPipeline(config, enrichment_queue, manager)
    await _enrichment_pipeline.start()

    # Telegram notifier
    telegram_notifier = TelegramNotifier(config.telegram)
    if telegram_notifier.is_configured:
        logger.info("Telegram notifications enabled")

    # Configure API dependencies
    from defensewatch.api import ws, map as map_router, ips as ips_router, scanner as scanner_router, firewall as firewall_router, fail2ban as fail2ban_router, telegram as telegram_router, settings as settings_router
    ws.set_manager(manager)
    map_router.set_config(config)
    ips_router.set_config(config)
    scanner_router.set_scanner_deps(config, manager)
    firewall_router.set_firewall_config(config)
    fail2ban_router.set_fail2ban_config(config)
    telegram_router.set_telegram_deps(config, telegram_notifier)
    settings_router.set_settings_config(config)

    # Start watchers
    loop = asyncio.get_event_loop()
    _watcher_manager = WatcherManager(config, manager, loop, enrichment_queue,
                                       telegram_notifier=telegram_notifier)
    await _watcher_manager.start()

    # Enrich IPs already in the database that aren't enriched yet
    asyncio.create_task(_backfill_enrichment(enrichment_queue))

    # Periodic data retention cleanup
    asyncio.create_task(_retention_cleanup(config))

    # Anomaly detection and baseline computation
    asyncio.create_task(_anomaly_loop(config, manager))

    # Threat intel enrichment for high-score IPs
    if config.threat_intel.enabled:
        asyncio.create_task(_threat_intel_loop(config))
        logger.info("Threat intel feed enabled")

    # Scheduled reports
    if config.reports.enabled:
        asyncio.create_task(_report_loop(config))
        logger.info(f"Scheduled reports enabled (every {config.reports.interval_hours}h)")

    # Telegram scheduled reports
    if config.telegram.enabled and (config.telegram.daily_reports or config.telegram.weekly_reports):
        asyncio.create_task(_telegram_report_loop(config, telegram_notifier))
        schedules = []
        if config.telegram.daily_reports:
            schedules.append("daily")
        if config.telegram.weekly_reports:
            schedules.append("weekly")
        logger.info(f"Telegram reports enabled ({', '.join(schedules)} at {config.telegram.report_hour}:00)")

    # Firewall auto-block loop
    from defensewatch.firewall import detect_backend
    fw_backend = detect_backend()
    if fw_backend:
        asyncio.create_task(_firewall_loop(config, manager))
        logger.info(f"Firewall backend: {fw_backend}, auto-block: {config.firewall.auto_block_enabled}")
    else:
        logger.warning("No firewall backend (ufw/iptables) detected — blocking disabled")

    yield

    # Shutdown
    if _watcher_manager:
        _watcher_manager.stop()
    if _enrichment_pipeline:
        await _enrichment_pipeline.stop()
    close_geoip()
    await close_db()
    logger.info("DefenseWatch shutdown complete")


async def _retention_cleanup(config):
    while True:
        await asyncio.sleep(3600)
        try:
            await cleanup_old_data(config.database.retention_days)
            logger.info("Data retention cleanup completed")
        except Exception as e:
            logger.error(f"Retention cleanup error: {e}")


async def _anomaly_loop(config, manager):
    """Periodically compute baselines and check for anomalies."""
    from defensewatch.anomaly import compute_baselines, check_anomalies
    await asyncio.sleep(60)  # Let initial data accumulate
    while True:
        try:
            await compute_baselines()
            anomalies = await check_anomalies()
            for a in anomalies:
                await manager.broadcast("anomaly_alert", a)
                logger.warning(f"Anomaly detected: {a['message']}")
                # Telegram anomaly alert
                if config.telegram.enabled:
                    tg = TelegramNotifier(config.telegram)
                    await tg.notify_anomaly(a)
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
        await asyncio.sleep(3600)  # Check hourly


async def _threat_intel_loop(config):
    """Periodically enrich top attacking IPs with threat intel."""
    from defensewatch.enrichment.threat_intel import enrich_ip_threat_intel
    from defensewatch.database import get_db
    await asyncio.sleep(30)
    while True:
        try:
            db = get_db()
            # Get IPs with most activity that haven't been checked recently
            cutoff = time.time() - (config.threat_intel.refresh_interval_hours * 3600)
            rows = await db.execute_fetchall(
                """SELECT ip, cnt FROM (
                    SELECT source_ip as ip, COUNT(*) as cnt FROM (
                        SELECT source_ip FROM ssh_events
                        UNION ALL SELECT source_ip FROM http_events
                    ) GROUP BY source_ip ORDER BY cnt DESC LIMIT 100
                ) t WHERE ip NOT IN (
                    SELECT ip FROM threat_intel_hits WHERE checked_at > ?
                ) LIMIT 20""",
                (cutoff,)
            )
            for r in rows:
                await enrich_ip_threat_intel(r[0], config.threat_intel)
                await asyncio.sleep(2)  # Rate limit
            if rows:
                logger.info(f"Threat intel enriched {len(rows)} IPs")
        except Exception as e:
            logger.error(f"Threat intel loop error: {e}")
        await asyncio.sleep(config.threat_intel.refresh_interval_hours * 3600)


async def _report_loop(config):
    """Periodically generate and send reports."""
    from defensewatch.reports import send_report
    await asyncio.sleep(60)
    while True:
        await asyncio.sleep(config.reports.interval_hours * 3600)
        try:
            await send_report(config.reports)
        except Exception as e:
            logger.error(f"Report generation error: {e}")


async def _firewall_loop(config, manager):
    """Periodically evaluate top offending IPs for auto-blocking and expire temp blocks."""
    from defensewatch.firewall import evaluate_ip_for_autoblock, expire_blocks
    from defensewatch.database import get_db
    await asyncio.sleep(30)
    while True:
        try:
            # Expire temporary blocks first
            await expire_blocks()

            if config.firewall.auto_block_enabled:
                db = get_db()
                window = time.time() - config.firewall.auto_block_window_seconds
                # Get IPs with most activity in the window
                rows = await db.execute_fetchall(
                    """SELECT ip, total FROM (
                        SELECT source_ip as ip, COUNT(*) as total FROM ssh_events
                        WHERE event_type IN ('failed_password','invalid_user')
                          AND timestamp > ? GROUP BY source_ip
                        UNION ALL
                        SELECT source_ip as ip, COUNT(*) as total FROM http_events
                        WHERE timestamp > ? GROUP BY source_ip
                    ) GROUP BY ip ORDER BY SUM(total) DESC LIMIT 50""",
                    (window, window),
                )
                for r in rows:
                    result = await evaluate_ip_for_autoblock(r[0], config)
                    if result and manager:
                        await manager.broadcast("firewall_block", result)
                        # Telegram firewall block alert
                        if config.telegram.enabled:
                            tg = TelegramNotifier(config.telegram)
                            await tg.notify_firewall_block(result)
        except Exception as e:
            logger.error(f"Firewall loop error: {e}")
        await asyncio.sleep(config.firewall.check_interval_seconds)


async def _telegram_report_loop(config, telegram_notifier: TelegramNotifier):
    """Send daily/weekly reports via Telegram at the configured hour."""
    from defensewatch.reports import generate_report
    import datetime
    await asyncio.sleep(60)
    last_daily = None
    last_weekly = None
    while True:
        try:
            now = datetime.datetime.now()
            if now.hour == config.telegram.report_hour:
                today = now.date()
                # Daily report
                if config.telegram.daily_reports and last_daily != today:
                    report = await generate_report()
                    await telegram_notifier.send_report(report)
                    last_daily = today
                    logger.info("Telegram daily report sent")

                # Weekly report (Monday)
                if config.telegram.weekly_reports and now.weekday() == 0 and last_weekly != today:
                    report = await generate_report()
                    await telegram_notifier.send_report(report)
                    last_weekly = today
                    logger.info("Telegram weekly report sent")
        except Exception as e:
            logger.error(f"Telegram report loop error: {e}")
        await asyncio.sleep(300)  # Check every 5 minutes


async def _backfill_enrichment(queue: asyncio.Queue):
    from defensewatch.database import get_db
    await asyncio.sleep(2)
    try:
        db = get_db()
        rows = await db.execute_fetchall(
            """SELECT DISTINCT ip FROM (
               SELECT source_ip as ip FROM ssh_events WHERE ip_id IS NULL
               UNION SELECT source_ip as ip FROM http_events WHERE ip_id IS NULL
               UNION SELECT source_ip as ip FROM service_events WHERE ip_id IS NULL AND source_ip IS NOT NULL
            ) LIMIT 500"""
        )
        for r in rows:
            try:
                queue.put_nowait(r[0])
            except asyncio.QueueFull:
                break
        if rows:
            logger.info(f"Queued {len(rows)} IPs for enrichment backfill")
    except Exception as e:
        logger.error(f"Enrichment backfill error: {e}")


app = FastAPI(title="DefenseWatch", lifespan=lifespan)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ.get("DEFENSEWATCH_CORS_ORIGIN", "*")],
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)


# Security headers middleware
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Mount API routers FIRST (before static files)
mount_routers(app)

# Static files - serve at /static and serve index.html at root as fallback
static_dir = Path(__file__).parent.parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static_assets")

    @app.get("/")
    async def serve_index():
        return FileResponse(str(static_dir / "index.html"))

    @app.get("/health")
    async def health_check():
        return {"status": "ok"}
