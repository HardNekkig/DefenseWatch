import json
import time
import pytest
import pytest_asyncio
from defensewatch.database import get_db


@pytest.mark.asyncio
async def test_ssh_events_empty(test_db):
    from defensewatch.api.events import get_ssh_events
    result = await get_ssh_events(page=1, limit=50)
    assert result["total"] == 0
    assert result["events"] == []


@pytest.mark.asyncio
async def test_ssh_events_with_data(test_db):
    db = get_db()
    now = time.time()
    await db.execute(
        """INSERT INTO ssh_events (timestamp, event_type, username, source_ip,
           source_port, auth_method, hostname, pid, raw_line)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (now, "failed_password", "root", "10.0.0.1", 22, "password", "host", 1, "test")
    )
    await db.commit()

    from defensewatch.api.events import get_ssh_events
    result = await get_ssh_events(page=1, limit=50)
    assert result["total"] == 1
    assert result["events"][0]["source_ip"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_ssh_events_filter_by_ip(test_db):
    db = get_db()
    now = time.time()
    for ip in ["10.0.0.1", "10.0.0.2"]:
        await db.execute(
            """INSERT INTO ssh_events (timestamp, event_type, username, source_ip,
               source_port, auth_method, hostname, pid, raw_line)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (now, "failed_password", "root", ip, 22, "password", "host", 1, "test")
        )
    await db.commit()

    from defensewatch.api.events import get_ssh_events
    result = await get_ssh_events(page=1, limit=50, ip="10.0.0.1")
    assert result["total"] == 1


@pytest.mark.asyncio
async def test_http_events_empty(test_db):
    from defensewatch.api.events import get_http_events
    result = await get_http_events(page=1, limit=50)
    assert result["total"] == 0


@pytest.mark.asyncio
async def test_http_events_with_data(test_db):
    db = get_db()
    now = time.time()
    await db.execute(
        """INSERT INTO http_events (timestamp, source_ip, method, path, http_version,
           status_code, response_bytes, referer, user_agent, vhost,
           attack_types, scanner_name, severity, raw_line)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (now, "10.0.0.1", "GET", "/etc/passwd", "HTTP/1.1", 404, 0,
         None, "curl/7.0", None, json.dumps(["path_traversal"]), None, "high", "test")
    )
    await db.commit()

    from defensewatch.api.events import get_http_events
    result = await get_http_events(page=1, limit=50)
    assert result["total"] == 1
    assert result["events"][0]["severity"] == "high"


@pytest.mark.asyncio
async def test_ssh_export_csv(test_db):
    db = get_db()
    now = time.time()
    await db.execute(
        """INSERT INTO ssh_events (timestamp, event_type, username, source_ip,
           source_port, auth_method, hostname, pid, raw_line)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (now, "failed_password", "root", "10.0.0.1", 22, "password", "host", 1, "test")
    )
    await db.commit()

    from defensewatch.api.events import export_ssh_events
    result = await export_ssh_events(format="csv", limit=10000)
    assert hasattr(result, "media_type")
    assert result.media_type == "text/csv"


@pytest.mark.asyncio
async def test_ssh_export_json(test_db):
    db = get_db()
    now = time.time()
    await db.execute(
        """INSERT INTO ssh_events (timestamp, event_type, username, source_ip,
           source_port, auth_method, hostname, pid, raw_line)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (now, "failed_password", "root", "10.0.0.1", 22, "password", "host", 1, "test")
    )
    await db.commit()

    from defensewatch.api.events import export_ssh_events
    result = await export_ssh_events(format="json", limit=10000)
    assert len(result["events"]) == 1


@pytest.mark.asyncio
async def test_data_retention_cleanup(test_db):
    from defensewatch.database import cleanup_old_data
    db = get_db()
    old_ts = time.time() - (31 * 86400)  # 31 days ago
    recent_ts = time.time()

    await db.execute(
        """INSERT INTO ssh_events (timestamp, event_type, username, source_ip,
           source_port, auth_method, hostname, pid, raw_line)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (old_ts, "failed_password", "root", "10.0.0.1", 22, "password", "host", 1, "old")
    )
    await db.execute(
        """INSERT INTO ssh_events (timestamp, event_type, username, source_ip,
           source_port, auth_method, hostname, pid, raw_line)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (recent_ts, "failed_password", "root", "10.0.0.2", 22, "password", "host", 1, "new")
    )
    await db.commit()

    await cleanup_old_data(30)

    rows = await db.execute_fetchall("SELECT COUNT(*) FROM ssh_events")
    assert rows[0][0] == 1  # Only recent event remains
