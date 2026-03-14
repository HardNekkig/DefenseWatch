import json
import time
import pytest
from defensewatch.config import GeoPolicyConfig
from defensewatch.database import get_db
from defensewatch.geo_policy import (
    check_geo_policy,
    _is_exempt,
    enforce_geo_policy,
    evaluate_geo_policies_batch,
    set_geo_policy_deps,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_config(**overrides):
    defaults = dict(enabled=True, mode="blacklist", countries=["CN", "RU"], action="block")
    defaults.update(overrides)
    return GeoPolicyConfig(**defaults)


async def _insert_ip_intel(db, ip, country_code):
    await db.execute(
        "INSERT OR REPLACE INTO ip_intel (ip, country_code) VALUES (?, ?)",
        (ip, country_code),
    )


async def _insert_ssh(db, ip, ts):
    await db.execute(
        """INSERT INTO ssh_events (timestamp, event_type, username, source_ip,
           source_port, auth_method, hostname, pid, raw_line)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (ts, "failed_password", "root", ip, 22, "password", "host", 1, "test"),
    )


# ── Tests ────────────────────────────────────────────────────────────────────


class TestIsExempt:
    def test_exact_ip_match(self):
        assert _is_exempt("10.0.0.1", ["10.0.0.1"]) is True

    def test_no_match(self):
        assert _is_exempt("10.0.0.2", ["10.0.0.1"]) is False

    def test_cidr_match(self):
        assert _is_exempt("10.0.0.5", ["10.0.0.0/24"]) is True

    def test_cidr_no_match(self):
        assert _is_exempt("192.168.1.1", ["10.0.0.0/24"]) is False

    def test_empty_list(self):
        assert _is_exempt("10.0.0.1", []) is False

    def test_invalid_ip(self):
        assert _is_exempt("not-an-ip", ["10.0.0.0/24"]) is False

    def test_ipv6(self):
        assert _is_exempt("::1", ["::1"]) is True

    def test_mixed_entries(self):
        exempts = ["10.0.0.1", "192.168.0.0/16"]
        assert _is_exempt("192.168.5.10", exempts) is True
        assert _is_exempt("10.0.0.1", exempts) is True
        assert _is_exempt("172.16.0.1", exempts) is False


class TestCheckGeoPolicy:
    @pytest.mark.asyncio
    async def test_disabled_returns_none(self, test_db):
        config = _make_config(enabled=False)
        result = await check_geo_policy("10.0.0.1", config)
        assert result is None

    @pytest.mark.asyncio
    async def test_exempt_ip_returns_none(self, test_db):
        db = get_db()
        await _insert_ip_intel(db, "10.0.0.1", "CN")
        await db.commit()

        config = _make_config(exempt_ips=["10.0.0.1"])
        result = await check_geo_policy("10.0.0.1", config)
        assert result is None

    @pytest.mark.asyncio
    async def test_blacklist_triggers_for_listed_country(self, test_db):
        db = get_db()
        await _insert_ip_intel(db, "10.0.0.1", "CN")
        await db.commit()

        config = _make_config(mode="blacklist", countries=["CN", "RU"])
        result = await check_geo_policy("10.0.0.1", config)
        assert result is not None
        assert result["country_code"] == "CN"
        assert result["action"] == "block"
        assert "blacklisted" in result["reason"]

    @pytest.mark.asyncio
    async def test_blacklist_no_trigger_for_unlisted_country(self, test_db):
        db = get_db()
        await _insert_ip_intel(db, "10.0.0.1", "US")
        await db.commit()

        config = _make_config(mode="blacklist", countries=["CN", "RU"])
        result = await check_geo_policy("10.0.0.1", config)
        assert result is None

    @pytest.mark.asyncio
    async def test_whitelist_triggers_for_unlisted_country(self, test_db):
        db = get_db()
        await _insert_ip_intel(db, "10.0.0.1", "CN")
        await db.commit()

        config = _make_config(mode="whitelist", countries=["US", "GB", "DE"])
        result = await check_geo_policy("10.0.0.1", config)
        assert result is not None
        assert "not whitelisted" in result["reason"]

    @pytest.mark.asyncio
    async def test_whitelist_no_trigger_for_listed_country(self, test_db):
        db = get_db()
        await _insert_ip_intel(db, "10.0.0.1", "US")
        await db.commit()

        config = _make_config(mode="whitelist", countries=["US", "GB"])
        result = await check_geo_policy("10.0.0.1", config)
        assert result is None

    @pytest.mark.asyncio
    async def test_unknown_ip_returns_none(self, test_db):
        config = _make_config()
        result = await check_geo_policy("99.99.99.99", config)
        assert result is None

    @pytest.mark.asyncio
    async def test_empty_country_code_returns_none(self, test_db):
        db = get_db()
        await _insert_ip_intel(db, "10.0.0.1", "")
        await db.commit()

        config = _make_config()
        result = await check_geo_policy("10.0.0.1", config)
        assert result is None

    @pytest.mark.asyncio
    async def test_case_insensitive_country_match(self, test_db):
        db = get_db()
        await _insert_ip_intel(db, "10.0.0.1", "cn")
        await db.commit()

        config = _make_config(mode="blacklist", countries=["CN"])
        result = await check_geo_policy("10.0.0.1", config)
        assert result is not None


class TestEnforceGeoPolicy:
    @pytest.mark.asyncio
    async def test_alert_action_logs_audit(self, test_db):
        db = get_db()
        set_geo_policy_deps(_make_config(), None)

        policy_result = {
            "ip": "10.0.0.1",
            "country_code": "CN",
            "action": "alert",
            "reason": "test alert",
        }
        config = _make_config(action="alert")
        result = await enforce_geo_policy("10.0.0.1", policy_result, config)
        assert result["action"] == "alert"

        rows = await db.execute_fetchall(
            "SELECT action FROM audit_log WHERE action = 'geo_alert'"
        )
        assert len(rows) == 1

    @pytest.mark.asyncio
    async def test_flag_action_logs_audit(self, test_db):
        db = get_db()
        set_geo_policy_deps(_make_config(), None)

        policy_result = {
            "ip": "10.0.0.1",
            "country_code": "CN",
            "action": "flag",
            "reason": "test flag",
        }
        config = _make_config(action="flag")
        result = await enforce_geo_policy("10.0.0.1", policy_result, config)

        rows = await db.execute_fetchall(
            "SELECT action FROM audit_log WHERE action = 'geo_flag'"
        )
        assert len(rows) == 1


class TestEvaluateGeoPoliciesBatch:
    @pytest.mark.asyncio
    async def test_disabled_returns_empty(self, test_db):
        config = _make_config(enabled=False)
        results = await evaluate_geo_policies_batch(config)
        assert results == []

    @pytest.mark.asyncio
    async def test_processes_recent_ips(self, test_db):
        db = get_db()
        now = time.time()
        set_geo_policy_deps(_make_config(), None)

        await _insert_ip_intel(db, "10.0.0.1", "CN")
        await _insert_ssh(db, "10.0.0.1", now)
        await db.commit()

        config = _make_config(action="alert")
        results = await evaluate_geo_policies_batch(config)
        assert len(results) == 1
        assert results[0]["country_code"] == "CN"

    @pytest.mark.asyncio
    async def test_skips_already_checked_ips(self, test_db):
        db = get_db()
        now = time.time()
        set_geo_policy_deps(_make_config(), None)

        await _insert_ip_intel(db, "10.0.0.1", "CN")
        await _insert_ssh(db, "10.0.0.1", now)
        # Insert a recent geo_alert audit entry (simulating already checked)
        await db.execute(
            "INSERT INTO audit_log (timestamp, actor, action, target) VALUES (?,?,?,?)",
            (now, "geo_policy", "geo_alert", "10.0.0.1"),
        )
        await db.commit()

        config = _make_config(action="alert")
        results = await evaluate_geo_policies_batch(config)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_trigger_for_safe_countries(self, test_db):
        db = get_db()
        now = time.time()
        set_geo_policy_deps(_make_config(), None)

        await _insert_ip_intel(db, "10.0.0.1", "US")
        await _insert_ssh(db, "10.0.0.1", now)
        await db.commit()

        config = _make_config(mode="blacklist", countries=["CN", "RU"], action="alert")
        results = await evaluate_geo_policies_batch(config)
        assert len(results) == 0
