"""Audit logging for DefenseWatch.

Records every mutating action with timestamp, actor, action type, target,
detail, and IP address.  The main entry point ``log_audit`` is designed to be
fire-and-forget safe – it swallows all exceptions so callers never need to
worry about error handling.
"""

import logging
import time

from defensewatch.database import get_db

logger = logging.getLogger(__name__)

# ── Table bootstrap ─────────────────────────────────────────────────────────

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    actor TEXT NOT NULL DEFAULT 'system',
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL DEFAULT (unixepoch('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);
"""


async def ensure_table() -> None:
    """Create the audit_log table if it does not yet exist."""
    try:
        db = get_db()
        await db.executescript(CREATE_TABLE_SQL)
        await db.commit()
    except Exception:
        logger.exception("Failed to create audit_log table")


# ── Public API ──────────────────────────────────────────────────────────────

async def log_audit(
    action: str,
    target: str,
    detail: str = "",
    actor: str = "system",
    ip_address: str = "",
) -> None:
    """Insert an audit log entry.

    This function is intentionally fire-and-forget safe: it catches every
    exception internally and logs it, but **never** raises.
    """
    try:
        db = get_db()
        await db.execute(
            """INSERT INTO audit_log (timestamp, actor, action, target, detail, ip_address)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (time.time(), actor, action, target, detail, ip_address),
        )
        await db.commit()
    except Exception:
        logger.exception("Failed to write audit log entry action=%s target=%s", action, target)
