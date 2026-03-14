"""Automated response playbook engine for DefenseWatch.

Evaluates configurable rules against IP threat signals and executes
response actions (block, create incident, notify) automatically.
"""

import asyncio
import json
import logging
import time

from fastapi import APIRouter, Query
from pydantic import BaseModel

from defensewatch.audit import log_audit
from defensewatch.broadcast import ConnectionManager
from defensewatch.config import PlaybookConfig
from defensewatch.database import get_db
from defensewatch.firewall import block_ip
from defensewatch.scoring import compute_threat_score

logger = logging.getLogger(__name__)


# ── Engine ──────────────────────────────────────────────────────────────────


class PlaybookEngine:
    """Evaluates playbook rules against IPs and executes response actions."""

    def __init__(self, config: PlaybookConfig) -> None:
        self.config = config
        self._cooldowns: dict[str, float] = {}

    # ── condition checks ────────────────────────────────────────

    async def _check_condition(self, condition: dict, ip: str) -> tuple[bool, str]:
        """Check whether *condition* is satisfied for *ip*.

        Returns ``(matched, detail_string)``.
        """
        db = get_db()

        if "min_score" in condition:
            result = await compute_threat_score(ip)
            score = result.get("score", 0)
            if score >= condition["min_score"]:
                return True, f"threat_score={score}"
            return False, ""

        if "min_honeypot_hits" in condition:
            rows = await db.execute_fetchall(
                "SELECT COUNT(*) FROM honeypot_events WHERE source_ip = ?",
                (ip,),
            )
            count = rows[0][0] if rows else 0
            if count >= condition["min_honeypot_hits"]:
                return True, f"honeypot_hits={count}"
            return False, ""

        if "min_brute_sessions" in condition:
            rows = await db.execute_fetchall(
                "SELECT COUNT(*) FROM brute_force_sessions WHERE source_ip = ?",
                (ip,),
            )
            count = rows[0][0] if rows else 0
            if count >= condition["min_brute_sessions"]:
                return True, f"brute_sessions={count}"
            return False, ""

        if "min_ssh_failures" in condition:
            rows = await db.execute_fetchall(
                """SELECT COUNT(*) FROM ssh_events
                   WHERE source_ip = ? AND event_type IN ('failed_password', 'invalid_user')""",
                (ip,),
            )
            count = rows[0][0] if rows else 0
            if count >= condition["min_ssh_failures"]:
                return True, f"ssh_failures={count}"
            return False, ""

        if "min_http_attacks" in condition:
            rows = await db.execute_fetchall(
                "SELECT COUNT(*) FROM http_events WHERE source_ip = ?",
                (ip,),
            )
            count = rows[0][0] if rows else 0
            if count >= condition["min_http_attacks"]:
                return True, f"http_attacks={count}"
            return False, ""

        if "country_not_in" in condition:
            rows = await db.execute_fetchall(
                "SELECT country_code FROM ip_intel WHERE ip = ?",
                (ip,),
            )
            if not rows or not rows[0][0]:
                return False, ""
            cc = rows[0][0]
            if cc not in condition["country_not_in"]:
                return True, f"country={cc} not in allowed list"
            return False, ""

        if "country_in" in condition:
            rows = await db.execute_fetchall(
                "SELECT country_code FROM ip_intel WHERE ip = ?",
                (ip,),
            )
            if not rows or not rows[0][0]:
                return False, ""
            cc = rows[0][0]
            if cc in condition["country_in"]:
                return True, f"country={cc} in blocked list"
            return False, ""

        logger.warning("Unknown playbook condition keys: %s", list(condition.keys()))
        return False, ""

    # ── cooldown ────────────────────────────────────────────────

    def _cooldown_key(self, rule_name: str, ip: str) -> str:
        return f"{rule_name}:{ip}"

    def _is_in_cooldown(self, rule_name: str, ip: str, cooldown_seconds: int) -> bool:
        key = self._cooldown_key(rule_name, ip)
        last = self._cooldowns.get(key, 0.0)
        return (time.time() - last) < cooldown_seconds

    def _set_cooldown(self, rule_name: str, ip: str) -> None:
        key = self._cooldown_key(rule_name, ip)
        self._cooldowns[key] = time.time()

    # ── action execution ────────────────────────────────────────

    async def _execute_actions(
        self, rule: dict, ip: str, context: str
    ) -> list[str]:
        """Run each action defined in *rule* for *ip*.

        Returns a list of action names that were successfully executed.
        """
        executed: list[str] = []
        reason = f"playbook:{rule['name']} — {context}"

        for action in rule.get("actions", []):
            try:
                if action == "block_24h":
                    await block_ip(ip, reason=reason, source="playbook", duration_hours=24)
                    executed.append("block_24h")

                elif action == "block_permanent":
                    await block_ip(ip, reason=reason, source="playbook")
                    executed.append("block_permanent")

                elif action == "create_incident":
                    db = get_db()
                    now = time.time()
                    await db.execute(
                        """INSERT INTO incidents
                           (title, description, severity, status, source_ips, created_at, updated_at)
                           VALUES (?, ?, ?, 'open', ?, ?, ?)""",
                        (
                            f"Playbook: {rule['name']}",
                            f"Auto-created by playbook rule '{rule['name']}' "
                            f"for IP {ip}. {context}",
                            "high",
                            json.dumps([ip]),
                            now,
                            now,
                        ),
                    )
                    await db.commit()
                    executed.append("create_incident")

                elif action == "notify":
                    if _manager is not None:
                        await _manager.broadcast("playbook_action", {
                            "rule": rule["name"],
                            "ip": ip,
                            "actions": rule.get("actions", []),
                            "detail": context,
                        })
                    executed.append("notify")

                else:
                    logger.warning("Unknown playbook action: %s", action)

            except Exception:
                logger.exception(
                    "Playbook action '%s' failed for rule=%s ip=%s",
                    action, rule["name"], ip,
                )

        return executed

    # ── main evaluation ─────────────────────────────────────────

    async def evaluate_ip(self, ip: str) -> list[dict]:
        """Evaluate all playbook rules against *ip*.

        Returns a list of execution result dicts for rules that fired.
        """
        results: list[dict] = []

        for rule in self.config.rules:
            rule_name = rule.get("name", "unnamed")
            cooldown = rule.get("cooldown_seconds", 3600)
            condition = rule.get("condition", {})

            if self._is_in_cooldown(rule_name, ip, cooldown):
                continue

            try:
                matched, detail = await self._check_condition(condition, ip)
            except Exception:
                logger.exception("Condition check failed for rule=%s ip=%s", rule_name, ip)
                continue

            if not matched:
                continue

            # Execute actions
            executed = await self._execute_actions(rule, ip, detail)
            self._set_cooldown(rule_name, ip)

            # Record execution
            now = time.time()
            db = get_db()
            try:
                await db.execute(
                    """INSERT INTO playbook_executions
                       (rule_name, source_ip, actions_taken, detail, executed_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (rule_name, ip, json.dumps(executed), detail, now),
                )
                await db.commit()
            except Exception:
                logger.exception("Failed to record playbook execution")

            await log_audit(
                action="playbook_execute",
                target=ip,
                detail=f"rule={rule_name} actions={executed} {detail}",
                actor="playbook",
            )

            results.append({
                "rule": rule_name,
                "ip": ip,
                "actions_taken": executed,
                "detail": detail,
                "executed_at": now,
            })

        return results


# ── Evaluate all active IPs ────────────────────────────────────────────────


async def evaluate_all_active_ips(engine: PlaybookEngine) -> list[dict]:
    """Gather IPs active in the last hour across all event tables and evaluate."""
    db = get_db()
    one_hour_ago = time.time() - 3600
    ips: set[str] = set()

    queries = [
        "SELECT DISTINCT source_ip FROM ssh_events WHERE created_at >= ?",
        "SELECT DISTINCT source_ip FROM http_events WHERE created_at >= ?",
        "SELECT DISTINCT source_ip FROM brute_force_sessions WHERE created_at >= ?",
    ]

    # honeypot_events may not exist yet
    try:
        rows = await db.execute_fetchall(
            "SELECT DISTINCT source_ip FROM honeypot_events WHERE created_at >= ?",
            (one_hour_ago,),
        )
        for row in rows:
            if row[0]:
                ips.add(row[0])
    except Exception:
        pass

    for q in queries:
        try:
            rows = await db.execute_fetchall(q, (one_hour_ago,))
            for row in rows:
                if row[0]:
                    ips.add(row[0])
        except Exception:
            logger.debug("Playbook IP query failed: %s", q)

    all_results: list[dict] = []
    for ip in ips:
        try:
            results = await engine.evaluate_ip(ip)
            all_results.extend(results)
        except Exception:
            logger.exception("Playbook evaluation failed for ip=%s", ip)

    if all_results:
        logger.info(
            "Playbook cycle complete: %d actions across %d IPs",
            len(all_results), len(ips),
        )
    return all_results


# ── Background loop ─────────────────────────────────────────────────────────


async def playbook_loop(config: PlaybookConfig, manager: ConnectionManager) -> None:
    """Background task: periodically evaluate all active IPs."""
    global _manager
    _manager = manager

    engine = PlaybookEngine(config)

    global _engine
    _engine = engine

    logger.info(
        "Playbook engine started (enabled=%s, interval=%ds, rules=%d)",
        config.enabled, config.check_interval_seconds, len(config.rules),
    )

    while True:
        await asyncio.sleep(config.check_interval_seconds)
        if not config.enabled:
            continue
        try:
            await evaluate_all_active_ips(engine)
        except Exception:
            logger.exception("Playbook evaluation cycle failed")


# ── Module-level state ──────────────────────────────────────────────────────

_engine: PlaybookEngine | None = None
_manager: ConnectionManager | None = None


def set_playbook_deps(config: PlaybookConfig, manager: ConnectionManager) -> None:
    """Set module-level dependencies (called during app startup)."""
    global _engine, _manager
    _manager = manager
    _engine = PlaybookEngine(config)


def get_playbook_engine() -> PlaybookEngine | None:
    """Return the current engine instance, if initialised."""
    return _engine


# ── API router ──────────────────────────────────────────────────────────────

router = APIRouter(prefix="/api/playbooks", tags=["playbooks"])

_playbook_config: PlaybookConfig | None = None


def set_playbook_config(config: PlaybookConfig) -> None:
    """Store a reference to the live PlaybookConfig for the API."""
    global _playbook_config
    _playbook_config = config


class PlaybookConfigPatch(BaseModel):
    enabled: bool | None = None
    check_interval_seconds: int | None = None
    rules: list[dict] | None = None


@router.get("/status")
async def playbook_status():
    """Return engine status and rule list."""
    engine = get_playbook_engine()
    cfg = _playbook_config
    if engine is None or cfg is None:
        return {
            "running": False,
            "enabled": False,
            "rules": [],
            "check_interval_seconds": 60,
            "cooldown_entries": 0,
        }
    return {
        "running": True,
        "enabled": cfg.enabled,
        "rules": cfg.rules,
        "check_interval_seconds": cfg.check_interval_seconds,
        "cooldown_entries": len(engine._cooldowns),
    }


@router.get("/executions")
async def list_executions(
    rule_name: str | None = Query(None),
    ip: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Paginated list of playbook executions with optional filters."""
    db = get_db()
    conditions: list[str] = []
    params: list = []

    if rule_name:
        conditions.append("rule_name = ?")
        params.append(rule_name)
    if ip:
        conditions.append("source_ip = ?")
        params.append(ip)

    where = f" WHERE {' AND '.join(conditions)}" if conditions else ""

    count_rows = await db.execute_fetchall(
        f"SELECT COUNT(*) FROM playbook_executions{where}",
        params,
    )
    total = count_rows[0][0] if count_rows else 0

    rows = await db.execute_fetchall(
        f"""SELECT id, rule_name, source_ip, actions_taken, detail, executed_at, created_at
            FROM playbook_executions{where}
            ORDER BY executed_at DESC
            LIMIT ? OFFSET ?""",
        params + [limit, offset],
    )

    items = []
    for r in rows:
        actions = r[3]
        try:
            actions = json.loads(actions)
        except (json.JSONDecodeError, TypeError):
            pass
        items.append({
            "id": r[0],
            "rule_name": r[1],
            "source_ip": r[2],
            "actions_taken": actions,
            "detail": r[4],
            "executed_at": r[5],
            "created_at": r[6],
        })

    return {"total": total, "items": items}


@router.get("/config")
async def get_config():
    """Return current playbook configuration."""
    cfg = _playbook_config
    if cfg is None:
        return {"enabled": False, "check_interval_seconds": 60, "rules": []}
    return {
        "enabled": cfg.enabled,
        "check_interval_seconds": cfg.check_interval_seconds,
        "rules": cfg.rules,
    }


@router.patch("/config")
async def patch_config(body: PlaybookConfigPatch):
    """Update playbook configuration at runtime."""
    cfg = _playbook_config
    if cfg is None:
        return {"error": "Playbook engine not initialised"}, 503

    if body.enabled is not None:
        cfg.enabled = body.enabled
    if body.check_interval_seconds is not None:
        cfg.check_interval_seconds = max(10, body.check_interval_seconds)
    if body.rules is not None:
        cfg.rules = body.rules

    # Update engine's config reference if available
    engine = get_playbook_engine()
    if engine is not None:
        engine.config = cfg

    await log_audit(
        action="playbook_config_update",
        target="playbooks",
        detail=json.dumps({
            "enabled": cfg.enabled,
            "check_interval_seconds": cfg.check_interval_seconds,
            "rule_count": len(cfg.rules),
        }),
        actor="api",
    )

    return {
        "enabled": cfg.enabled,
        "check_interval_seconds": cfg.check_interval_seconds,
        "rules": cfg.rules,
    }
