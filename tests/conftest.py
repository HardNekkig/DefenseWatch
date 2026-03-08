import asyncio
import pytest
import aiosqlite
from unittest.mock import AsyncMock, MagicMock
from defensewatch.config import AppConfig, DetectionConfig
from defensewatch.broadcast import ConnectionManager
import defensewatch.database as db_module


@pytest.fixture
def detection_config():
    return DetectionConfig(
        ssh_brute_threshold=5,
        ssh_brute_window_seconds=300,
        http_scan_threshold=20,
        http_scan_window_seconds=60,
    )


@pytest.fixture
def app_config():
    return AppConfig()


@pytest.fixture
def mock_manager():
    mgr = MagicMock(spec=ConnectionManager)
    mgr.broadcast = AsyncMock()
    return mgr


@pytest.fixture
async def test_db(tmp_path):
    config = AppConfig()
    config.database.path = str(tmp_path / "test.db")
    conn = await db_module.init_db(config)
    yield conn
    await db_module.close_db()
