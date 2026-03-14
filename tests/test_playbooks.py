import json
import time
import pytest
from unittest.mock import AsyncMock, patch
from defensewatch.config import PlaybookConfig
from defensewatch.database import get_db
from defensewatch.playbooks import PlaybookEngine, evaluate_all_active_ips


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_config(**overrides):
    defaults = dict(enabled=True, check_interval_seconds=60, rules=[])
    defaults.update(overrides)
    return PlaybookConfig(**defaults)


def _make_rule(name="test_rule", condition=None, actions=None, cooldown=3600):
    return {
        "name": name,
        "description": f"Test rule {name}",
        "condition": condition or {"min_score": 80},
        "actions": actions or ["notify"],
        "cooldown_seconds": cooldown,
    }


async def _insert_ssh(db, ip, ts):
    await db.execute(
        """INSERT INTO ssh_events (timestamp, event_type, username, source_ip,
           source_port, auth_method, hostname, pid, raw_line)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (ts, "failed_password", "root", ip, 22, "password", "host", 1, "test"),
    )


async def _insert_brute(db, ip, ts, count=1):
    for i in range(count):
        await db.execute(
            """INSERT INTO brute_force_sessions (source_ip, session_start, session_end,
               attempt_count, usernames_tried, event_type, status)
               VALUES (?,?,?,?,?,?,?)""",
            (ip, ts + i * 60, ts + i * 60 + 30, 10, json.dumps(["root"]),
             "ssh_brute_force", "completed"),
        )


async def _insert_honeypot(db, ip, ts, count=1):
    for i in range(count):
        await db.execute(
            """INSERT INTO honeypot_events (timestamp, source_ip, method, path, status_code)
               VALUES (?,?,?,?,?)""",
            (ts + i, ip, "GET", "/.env", 403),
        )


# ── Engine Tests ─────────────────────────────────────────────────────────────


class TestPlaybookEngineCooldown:
    def test_no_cooldown_initially(self):
        config = _make_config()
        engine = PlaybookEngine(config)
        assert engine._is_in_cooldown("rule1", "1.2.3.4", 3600) is False

    def test_cooldown_after_set(self):
        config = _make_config()
        engine = PlaybookEngine(config)
        engine._set_cooldown("rule1", "1.2.3.4")
        assert engine._is_in_cooldown("rule1", "1.2.3.4", 3600) is True

    def test_different_ip_no_cooldown(self):
        config = _make_config()
        engine = PlaybookEngine(config)
        engine._set_cooldown("rule1", "1.2.3.4")
        assert engine._is_in_cooldown("rule1", "5.6.7.8", 3600) is False

    def test_different_rule_no_cooldown(self):
        config = _make_config()
        engine = PlaybookEngine(config)
        engine._set_cooldown("rule1", "1.2.3.4")
        assert engine._is_in_cooldown("rule2", "1.2.3.4", 3600) is False


class TestPlaybookConditionChecks:
    @pytest.mark.asyncio
    async def test_min_honeypot_hits_matched(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_honeypot(db, "10.0.0.1", now, count=3)
        await db.commit()

        rule = _make_rule(condition={"min_honeypot_hits": 3})
        config = _make_config(rules=[rule])
        engine = PlaybookEngine(config)
        matched, detail = await engine._check_condition(rule["condition"], "10.0.0.1")
        assert matched is True
        assert "honeypot_hits=3" in detail

    @pytest.mark.asyncio
    async def test_min_honeypot_hits_not_matched(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_honeypot(db, "10.0.0.1", now, count=1)
        await db.commit()

        config = _make_config()
        engine = PlaybookEngine(config)
        matched, _ = await engine._check_condition({"min_honeypot_hits": 3}, "10.0.0.1")
        assert matched is False

    @pytest.mark.asyncio
    async def test_min_brute_sessions_matched(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_brute(db, "10.0.0.1", now, count=3)
        await db.commit()

        config = _make_config()
        engine = PlaybookEngine(config)
        matched, detail = await engine._check_condition({"min_brute_sessions": 2}, "10.0.0.1")
        assert matched is True
        assert "brute_sessions=3" in detail

    @pytest.mark.asyncio
    async def test_min_brute_sessions_not_matched(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_brute(db, "10.0.0.1", now, count=1)
        await db.commit()

        config = _make_config()
        engine = PlaybookEngine(config)
        matched, _ = await engine._check_condition({"min_brute_sessions": 2}, "10.0.0.1")
        assert matched is False

    @pytest.mark.asyncio
    async def test_min_ssh_failures_matched(self, test_db):
        db = get_db()
        now = time.time()
        for i in range(5):
            await _insert_ssh(db, "10.0.0.1", now + i)
        await db.commit()

        config = _make_config()
        engine = PlaybookEngine(config)
        matched, detail = await engine._check_condition({"min_ssh_failures": 5}, "10.0.0.1")
        assert matched is True

    @pytest.mark.asyncio
    async def test_country_in_matched(self, test_db):
        db = get_db()
        await db.execute(
            "INSERT INTO ip_intel (ip, country_code) VALUES (?, ?)",
            ("10.0.0.1", "CN"),
        )
        await db.commit()

        config = _make_config()
        engine = PlaybookEngine(config)
        matched, detail = await engine._check_condition({"country_in": ["CN", "RU"]}, "10.0.0.1")
        assert matched is True
        assert "CN" in detail

    @pytest.mark.asyncio
    async def test_country_in_not_matched(self, test_db):
        db = get_db()
        await db.execute(
            "INSERT INTO ip_intel (ip, country_code) VALUES (?, ?)",
            ("10.0.0.1", "US"),
        )
        await db.commit()

        config = _make_config()
        engine = PlaybookEngine(config)
        matched, _ = await engine._check_condition({"country_in": ["CN", "RU"]}, "10.0.0.1")
        assert matched is False

    @pytest.mark.asyncio
    async def test_unknown_condition_no_match(self, test_db):
        config = _make_config()
        engine = PlaybookEngine(config)
        matched, _ = await engine._check_condition({"nonexistent_key": 99}, "10.0.0.1")
        assert matched is False


class TestPlaybookEvaluateIP:
    @pytest.mark.asyncio
    async def test_executes_actions_on_match(self, test_db, mock_manager):
        import defensewatch.playbooks as pb_mod
        pb_mod._manager = mock_manager

        db = get_db()
        now = time.time()
        await _insert_honeypot(db, "10.0.0.1", now, count=5)
        await db.commit()

        rule = _make_rule(
            name="test_hp",
            condition={"min_honeypot_hits": 3},
            actions=["notify"],
        )
        config = _make_config(rules=[rule])
        engine = PlaybookEngine(config)

        results = await engine.evaluate_ip("10.0.0.1")
        assert len(results) == 1
        assert results[0]["rule"] == "test_hp"
        assert "notify" in results[0]["actions_taken"]

        # Verify execution was recorded in DB
        rows = await db.execute_fetchall("SELECT COUNT(*) FROM playbook_executions")
        assert rows[0][0] == 1

    @pytest.mark.asyncio
    async def test_respects_cooldown(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_honeypot(db, "10.0.0.1", now, count=5)
        await db.commit()

        rule = _make_rule(
            condition={"min_honeypot_hits": 3},
            actions=["notify"],
            cooldown=3600,
        )
        config = _make_config(rules=[rule])
        engine = PlaybookEngine(config)

        # First evaluation triggers
        results1 = await engine.evaluate_ip("10.0.0.1")
        assert len(results1) == 1

        # Second evaluation should be in cooldown
        results2 = await engine.evaluate_ip("10.0.0.1")
        assert len(results2) == 0

    @pytest.mark.asyncio
    async def test_no_match_no_execution(self, test_db):
        db = get_db()
        rule = _make_rule(condition={"min_honeypot_hits": 100}, actions=["notify"])
        config = _make_config(rules=[rule])
        engine = PlaybookEngine(config)

        results = await engine.evaluate_ip("10.0.0.1")
        assert len(results) == 0


class TestPlaybookCreateIncident:
    @pytest.mark.asyncio
    async def test_create_incident_action(self, test_db):
        import defensewatch.playbooks as pb_mod
        pb_mod._manager = None

        db = get_db()
        now = time.time()
        await _insert_honeypot(db, "10.0.0.1", now, count=5)
        await db.commit()

        rule = _make_rule(
            name="inc_rule",
            condition={"min_honeypot_hits": 3},
            actions=["create_incident"],
        )
        config = _make_config(rules=[rule])
        engine = PlaybookEngine(config)

        results = await engine.evaluate_ip("10.0.0.1")
        assert len(results) == 1
        assert "create_incident" in results[0]["actions_taken"]

        rows = await db.execute_fetchall("SELECT title, status FROM incidents")
        assert len(rows) == 1
        assert "inc_rule" in rows[0][0]
        assert rows[0][1] == "open"


class TestEvaluateAllActiveIPs:
    @pytest.mark.asyncio
    async def test_gathers_active_ips(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_ssh(db, "10.0.0.1", now)
        await _insert_honeypot(db, "10.0.0.2", now, count=5)
        await db.commit()

        rule = _make_rule(condition={"min_honeypot_hits": 3}, actions=["notify"])
        config = _make_config(rules=[rule])
        engine = PlaybookEngine(config)

        import defensewatch.playbooks as pb_mod
        pb_mod._manager = None

        results = await evaluate_all_active_ips(engine)
        # 10.0.0.2 should match (5 honeypot hits), 10.0.0.1 should not
        assert len(results) == 1
        assert results[0]["ip"] == "10.0.0.2"
