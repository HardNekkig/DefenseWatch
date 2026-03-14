import json
import time
import pytest
from defensewatch.config import CorrelationConfig
from defensewatch.database import get_db
from defensewatch.correlation import (
    evaluate_correlations,
    _rule_coordinated_attack,
    _rule_brute_then_exploit,
    _rule_recon_to_attack,
    _rule_multi_service,
    set_correlation_deps,
    _highest_severity,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _default_config(**overrides):
    defaults = dict(enabled=True, check_interval_seconds=60, lookback_seconds=3600)
    defaults.update(overrides)
    return CorrelationConfig(**defaults)


async def _insert_ssh(db, ip, ts, event_type="failed_password"):
    await db.execute(
        """INSERT INTO ssh_events (timestamp, event_type, username, source_ip,
           source_port, auth_method, hostname, pid, raw_line)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (ts, event_type, "root", ip, 22, "password", "host", 1, "test"),
    )


async def _insert_http(db, ip, ts, attack_types=None):
    await db.execute(
        """INSERT INTO http_events (timestamp, source_ip, method, path, http_version,
           status_code, response_bytes, referer, user_agent, vhost,
           attack_types, scanner_name, severity, raw_line)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (ts, ip, "GET", "/test", "HTTP/1.1", 200, 0, None, "curl", None,
         json.dumps(attack_types or []), None, "high" if attack_types else None, "test"),
    )


async def _insert_portscan(db, ip, ts):
    await db.execute(
        """INSERT INTO port_scan_events (source_ip, detected_at, ports_hit, port_count)
           VALUES (?,?,?,?)""",
        (ip, ts, json.dumps([22, 80, 443]), 3),
    )


async def _insert_brute(db, ip, ts):
    await db.execute(
        """INSERT INTO brute_force_sessions (source_ip, session_start, session_end,
           attempt_count, usernames_tried, event_type, status)
           VALUES (?,?,?,?,?,?,?)""",
        (ip, ts, ts + 60, 10, json.dumps(["root"]), "ssh_brute_force", "completed"),
    )


async def _insert_honeypot(db, ip, ts):
    await db.execute(
        """INSERT INTO honeypot_events (timestamp, source_ip, method, path, status_code)
           VALUES (?,?,?,?,?)""",
        (ts, ip, "GET", "/.env", 403),
    )


async def _insert_service(db, ip, ts, service_type="mysql"):
    await db.execute(
        """INSERT INTO service_events (timestamp, service_type, event_type, source_ip, detail)
           VALUES (?,?,?,?,?)""",
        (ts, service_type, "auth_failure", ip, "test"),
    )


# ── Tests ────────────────────────────────────────────────────────────────────


class TestHighestSeverity:
    def test_single(self):
        assert _highest_severity(["high"]) == "high"

    def test_mixed(self):
        assert _highest_severity(["low", "critical", "medium"]) == "critical"

    def test_empty_defaults_medium(self):
        assert _highest_severity([]) == "medium"


class TestCoordinatedAttack:
    @pytest.mark.asyncio
    async def test_triggers_on_three_tables(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_ssh(db, "10.0.0.1", now)
        await _insert_http(db, "10.0.0.1", now)
        await _insert_portscan(db, "10.0.0.1", now)
        await db.commit()

        matched, desc, sev = await _rule_coordinated_attack(db, "10.0.0.1", now - 60)
        assert matched is True
        assert sev == "critical"
        assert "3" in desc

    @pytest.mark.asyncio
    async def test_no_trigger_on_two_tables(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_ssh(db, "10.0.0.1", now)
        await _insert_http(db, "10.0.0.1", now)
        await db.commit()

        matched, _, _ = await _rule_coordinated_attack(db, "10.0.0.1", now - 60)
        assert matched is False


class TestBruteThenExploit:
    @pytest.mark.asyncio
    async def test_triggers_on_brute_then_http_attack(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_brute(db, "10.0.0.1", now - 120)
        await _insert_http(db, "10.0.0.1", now, attack_types=["sqli"])
        await db.commit()

        matched, desc, sev = await _rule_brute_then_exploit(db, "10.0.0.1", now - 300)
        assert matched is True
        assert sev == "high"

    @pytest.mark.asyncio
    async def test_no_trigger_without_http_attack(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_brute(db, "10.0.0.1", now - 120)
        await _insert_http(db, "10.0.0.1", now, attack_types=[])
        await db.commit()

        matched, _, _ = await _rule_brute_then_exploit(db, "10.0.0.1", now - 300)
        assert matched is False

    @pytest.mark.asyncio
    async def test_no_trigger_without_brute(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_http(db, "10.0.0.1", now, attack_types=["xss"])
        await db.commit()

        matched, _, _ = await _rule_brute_then_exploit(db, "10.0.0.1", now - 300)
        assert matched is False


class TestReconToAttack:
    @pytest.mark.asyncio
    async def test_triggers_on_scan_then_ssh_attack(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_portscan(db, "10.0.0.1", now - 120)
        await _insert_ssh(db, "10.0.0.1", now)
        await db.commit()

        matched, desc, sev = await _rule_recon_to_attack(db, "10.0.0.1", now - 300)
        assert matched is True
        assert "SSH" in desc

    @pytest.mark.asyncio
    async def test_triggers_on_scan_then_http_attack(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_portscan(db, "10.0.0.1", now - 120)
        await _insert_http(db, "10.0.0.1", now, attack_types=["path_traversal"])
        await db.commit()

        matched, desc, sev = await _rule_recon_to_attack(db, "10.0.0.1", now - 300)
        assert matched is True
        assert "HTTP" in desc

    @pytest.mark.asyncio
    async def test_no_trigger_without_scan(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_ssh(db, "10.0.0.1", now)
        await db.commit()

        matched, _, _ = await _rule_recon_to_attack(db, "10.0.0.1", now - 300)
        assert matched is False


class TestMultiService:
    @pytest.mark.asyncio
    async def test_triggers_on_two_services(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_ssh(db, "10.0.0.1", now)
        await _insert_http(db, "10.0.0.1", now)
        await db.commit()

        matched, desc, sev = await _rule_multi_service(db, "10.0.0.1", now - 60)
        assert matched is True
        assert sev == "medium"

    @pytest.mark.asyncio
    async def test_no_trigger_on_single_service(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_ssh(db, "10.0.0.1", now)
        await db.commit()

        matched, _, _ = await _rule_multi_service(db, "10.0.0.1", now - 60)
        assert matched is False


class TestEvaluateCorrelations:
    @pytest.mark.asyncio
    async def test_creates_incident_for_correlated_attack(self, test_db):
        db = get_db()
        now = time.time()
        # Set up a coordinated attack: SSH + HTTP + portscan
        await _insert_ssh(db, "10.0.0.1", now)
        await _insert_http(db, "10.0.0.1", now, attack_types=["sqli"])
        await _insert_portscan(db, "10.0.0.1", now)
        await _insert_brute(db, "10.0.0.1", now - 30)
        await db.commit()

        incidents = await evaluate_correlations(db, lookback_seconds=120)
        assert len(incidents) >= 1
        assert incidents[0]["severity"] in ("high", "critical")
        assert "10.0.0.1" in incidents[0]["title"]

        # Verify incident was written to DB
        rows = await db.execute_fetchall("SELECT COUNT(*) FROM incidents")
        assert rows[0][0] >= 1

    @pytest.mark.asyncio
    async def test_skips_ip_with_existing_open_incident(self, test_db):
        db = get_db()
        now = time.time()
        # Create existing open incident for this IP
        await db.execute(
            """INSERT INTO incidents (title, description, severity, status, source_ips, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?)""",
            ("Existing", "test", "high", "open", json.dumps(["10.0.0.1"]), now, now),
        )
        await _insert_ssh(db, "10.0.0.1", now)
        await _insert_http(db, "10.0.0.1", now)
        await _insert_portscan(db, "10.0.0.1", now)
        await db.commit()

        incidents = await evaluate_correlations(db, lookback_seconds=120)
        assert len(incidents) == 0

    @pytest.mark.asyncio
    async def test_no_incidents_when_no_active_ips(self, test_db):
        db = get_db()
        incidents = await evaluate_correlations(db, lookback_seconds=120)
        assert incidents == []

    @pytest.mark.asyncio
    async def test_filters_rules(self, test_db):
        db = get_db()
        now = time.time()
        await _insert_ssh(db, "10.0.0.1", now)
        await _insert_http(db, "10.0.0.1", now)
        await db.commit()

        # Only run multi_service rule (should trigger), exclude coordinated_attack
        incidents = await evaluate_correlations(
            db, lookback_seconds=120, enabled_rules=["multi_service"]
        )
        assert len(incidents) == 1
