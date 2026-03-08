import logging
from fastapi import APIRouter
from pydantic import BaseModel
from defensewatch.telegram import TelegramNotifier

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/telegram", tags=["telegram"])

_config = None
_notifier: TelegramNotifier | None = None


def set_telegram_deps(config, notifier: TelegramNotifier):
    global _config, _notifier
    _config = config
    _notifier = notifier


class TelegramSettings(BaseModel):
    enabled: bool | None = None
    bot_token: str | None = None
    chat_ids: list[str] | None = None
    min_severity: str | None = None
    cooldown_seconds: int | None = None
    notify_events: list[str] | None = None
    daily_reports: bool | None = None
    weekly_reports: bool | None = None
    report_hour: int | None = None


@router.get("/status")
async def telegram_status():
    if not _config or not _notifier:
        return {"configured": False}

    tc = _config.telegram
    bot_info = await _notifier.get_bot_info() if tc.bot_token else {"ok": False}

    return {
        "configured": bool(tc.bot_token and tc.chat_ids),
        "enabled": tc.enabled,
        "bot_token_set": bool(tc.bot_token),
        "bot_info": bot_info if bot_info.get("ok") else None,
        "chat_ids": tc.chat_ids,
        "min_severity": tc.min_severity,
        "cooldown_seconds": tc.cooldown_seconds,
        "notify_events": tc.notify_events,
        "daily_reports": tc.daily_reports,
        "weekly_reports": tc.weekly_reports,
        "report_hour": tc.report_hour,
    }


@router.post("/test")
async def telegram_test():
    if not _notifier:
        return {"ok": False, "error": "Telegram not initialized"}
    return await _notifier.send_test_message()


@router.patch("/settings")
async def update_telegram_settings(body: TelegramSettings):
    if _config is None:
        return {"error": "Config not loaded"}

    tc = _config.telegram
    if body.enabled is not None:
        tc.enabled = body.enabled
    if body.bot_token is not None:
        tc.bot_token = body.bot_token
        from defensewatch.api.settings import _set_env_value
        _set_env_value("DEFENSEWATCH_TELEGRAM_BOT_TOKEN", body.bot_token)
    if body.chat_ids is not None:
        tc.chat_ids = body.chat_ids
        from defensewatch.api.settings import _set_env_value
        _set_env_value("DEFENSEWATCH_TELEGRAM_CHAT_IDS", ",".join(body.chat_ids))
    if body.min_severity is not None and body.min_severity in ('low', 'medium', 'high', 'critical'):
        tc.min_severity = body.min_severity
    if body.cooldown_seconds is not None:
        tc.cooldown_seconds = max(0, body.cooldown_seconds)
    if body.notify_events is not None:
        from defensewatch.config import ALL_NOTIFY_EVENTS
        tc.notify_events = [e for e in body.notify_events if e in ALL_NOTIFY_EVENTS]
    if body.daily_reports is not None:
        tc.daily_reports = body.daily_reports
    if body.weekly_reports is not None:
        tc.weekly_reports = body.weekly_reports
    if body.report_hour is not None:
        tc.report_hour = max(0, min(23, body.report_hour))

    # Rebuild notifier min level
    if _notifier:
        from defensewatch.telegram import SEVERITY_ORDER
        _notifier._min_level = SEVERITY_ORDER.get(tc.min_severity, 3)
        _notifier.config = tc

    from defensewatch.api.settings import _persist_config
    _persist_config()
    logger.info(f"Telegram settings updated: enabled={tc.enabled}")
    return {"ok": True, "settings": {
        "enabled": tc.enabled,
        "bot_token_set": bool(tc.bot_token),
        "chat_ids": tc.chat_ids,
        "min_severity": tc.min_severity,
        "cooldown_seconds": tc.cooldown_seconds,
        "notify_events": tc.notify_events,
        "daily_reports": tc.daily_reports,
        "weekly_reports": tc.weekly_reports,
        "report_hour": tc.report_hour,
    }}


@router.post("/report")
async def send_report_now():
    if not _notifier:
        return {"ok": False, "error": "Telegram not initialized"}
    if not _notifier.config.bot_token or not _notifier.config.chat_ids:
        return {"ok": False, "error": "Telegram not configured (missing token or chat IDs)"}

    try:
        from defensewatch.reports import generate_report
        report = await generate_report()
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        return {"ok": False, "error": f"Failed to generate report: {e}"}

    try:
        result = await _notifier.send_report(report)
        if result and not result.get("ok"):
            return result
        return {"ok": True, "message": "Report sent via Telegram"}
    except Exception as e:
        logger.error(f"Failed to send report via Telegram: {e}")
        return {"ok": False, "error": f"Failed to send report: {e}"}
