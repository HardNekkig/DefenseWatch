import time
import pytest
from defensewatch.config import DedupConfig
from defensewatch.dedup import EventDeduplicator


def _make_config(enabled=True, ssh_window=60, http_window=60, max_batch=100):
    return DedupConfig(
        enabled=enabled,
        ssh_window_seconds=ssh_window,
        http_window_seconds=http_window,
        max_batch_size=max_batch,
    )


def _ssh_event(ip="1.2.3.4", event_type="failed_password", username="root",
               port=22, extra=None):
    data = {"source_ip": ip, "event_type": event_type, "username": username}
    if extra:
        data.update(extra)
    return ip, event_type, username, port, data


class TestDisabled:
    def test_disabled_always_returns_event(self):
        dedup = EventDeduplicator(_make_config(enabled=False))
        ip, etype, user, port, data = _ssh_event()
        result = dedup.track_ssh(ip, etype, user, port, data, time.time())
        assert result is not None
        assert result["event_count"] == 1

    def test_disabled_never_absorbs(self):
        dedup = EventDeduplicator(_make_config(enabled=False))
        ts = time.time()
        for _ in range(5):
            ip, etype, user, port, data = _ssh_event()
            result = dedup.track_ssh(ip, etype, user, port, data, ts)
            assert result is not None
            assert result["event_count"] == 1


class TestSSHTracking:
    def test_first_event_returns_event(self):
        dedup = EventDeduplicator(_make_config())
        ip, etype, user, port, data = _ssh_event()
        result = dedup.track_ssh(ip, etype, user, port, data, 1000.0)
        assert result is not None
        assert result["event_count"] == 1

    def test_second_identical_event_absorbed(self):
        dedup = EventDeduplicator(_make_config())
        ip, etype, user, port, data = _ssh_event()
        dedup.track_ssh(ip, etype, user, port, data, 1000.0)

        ip2, etype2, user2, port2, data2 = _ssh_event()
        result = dedup.track_ssh(ip2, etype2, user2, port2, data2, 1001.0)
        assert result is None

    def test_event_after_window_expires_flushes(self):
        dedup = EventDeduplicator(_make_config(ssh_window=10))
        ip, etype, user, port, data = _ssh_event()
        dedup.track_ssh(ip, etype, user, port, data, 1000.0)

        # Absorb a second event
        ip2, etype2, user2, port2, data2 = _ssh_event()
        dedup.track_ssh(ip2, etype2, user2, port2, data2, 1005.0)

        # Third event after window: should flush the bucket (count=2)
        ip3, etype3, user3, port3, data3 = _ssh_event()
        result = dedup.track_ssh(ip3, etype3, user3, port3, data3, 1011.0)
        assert result is not None
        assert result["event_count"] == 2

    def test_event_after_max_batch_flushes(self):
        dedup = EventDeduplicator(_make_config(max_batch=3))
        ts = 1000.0

        # First event: returned immediately
        ip, etype, user, port, data = _ssh_event()
        dedup.track_ssh(ip, etype, user, port, data, ts)

        # Second and third: absorbed
        for i in range(1, 3):
            ip, etype, user, port, data = _ssh_event()
            result = dedup.track_ssh(ip, etype, user, port, data, ts + i)
        assert result is None  # 3rd event absorbed (count == max_batch)

        # Fourth event triggers flush (count >= max_batch)
        ip, etype, user, port, data = _ssh_event()
        result = dedup.track_ssh(ip, etype, user, port, data, ts + 3)
        assert result is not None
        assert result["event_count"] == 3

    def test_different_keys_tracked_separately(self):
        dedup = EventDeduplicator(_make_config())
        ts = 1000.0

        ip1, etype1, user1, port1, data1 = _ssh_event(ip="1.1.1.1")
        ip2, etype2, user2, port2, data2 = _ssh_event(ip="2.2.2.2")

        r1 = dedup.track_ssh(ip1, etype1, user1, port1, data1, ts)
        r2 = dedup.track_ssh(ip2, etype2, user2, port2, data2, ts)

        # Both should be returned (new keys)
        assert r1 is not None
        assert r2 is not None

    def test_different_ips_dont_interfere(self):
        dedup = EventDeduplicator(_make_config())
        ts = 1000.0

        # First event from IP1
        ip1, etype1, user1, port1, data1 = _ssh_event(ip="1.1.1.1")
        dedup.track_ssh(ip1, etype1, user1, port1, data1, ts)

        # Second event from IP1 (absorbed)
        ip1b, etype1b, user1b, port1b, data1b = _ssh_event(ip="1.1.1.1")
        assert dedup.track_ssh(ip1b, etype1b, user1b, port1b, data1b, ts + 1) is None

        # Event from IP2 should still be returned
        ip2, etype2, user2, port2, data2 = _ssh_event(ip="2.2.2.2")
        result = dedup.track_ssh(ip2, etype2, user2, port2, data2, ts + 1)
        assert result is not None


class TestHTTPTracking:
    def test_http_track_works_similarly(self):
        dedup = EventDeduplicator(_make_config())
        data1 = {"source_ip": "1.2.3.4", "method": "GET", "path": "/login"}
        result = dedup.track_http("1.2.3.4", "GET", "/login", 80, data1, 1000.0)
        assert result is not None
        assert result["event_count"] == 1

    def test_http_second_event_absorbed(self):
        dedup = EventDeduplicator(_make_config())
        data1 = {"source_ip": "1.2.3.4", "method": "GET", "path": "/login"}
        dedup.track_http("1.2.3.4", "GET", "/login", 80, data1, 1000.0)

        data2 = {"source_ip": "1.2.3.4", "method": "GET", "path": "/login"}
        result = dedup.track_http("1.2.3.4", "GET", "/login", 80, data2, 1001.0)
        assert result is None


class TestFlushAll:
    def test_flush_returns_pending_buckets(self):
        dedup = EventDeduplicator(_make_config())
        ts = 1000.0

        # Create bucket with 3 events (first returned, 2 absorbed)
        ip, etype, user, port, data = _ssh_event()
        dedup.track_ssh(ip, etype, user, port, data, ts)
        for i in range(1, 3):
            ip, etype, user, port, data = _ssh_event()
            dedup.track_ssh(ip, etype, user, port, data, ts + i)

        flushed = dedup.flush_all()
        assert len(flushed) == 1
        assert flushed[0]["event_count"] == 3

    def test_flush_clears_buckets(self):
        dedup = EventDeduplicator(_make_config())
        ip, etype, user, port, data = _ssh_event()
        dedup.track_ssh(ip, etype, user, port, data, 1000.0)
        ip2, etype2, user2, port2, data2 = _ssh_event()
        dedup.track_ssh(ip2, etype2, user2, port2, data2, 1001.0)

        dedup.flush_all()
        assert dedup.stats["ssh_buckets"] == 0
        assert dedup.stats["http_buckets"] == 0

    def test_flush_skips_single_event_buckets(self):
        """Buckets with count==1 are not returned (already stored on first track)."""
        dedup = EventDeduplicator(_make_config())
        ip, etype, user, port, data = _ssh_event()
        dedup.track_ssh(ip, etype, user, port, data, 1000.0)

        flushed = dedup.flush_all()
        assert len(flushed) == 0


class TestCleanup:
    def test_cleanup_removes_stale_buckets(self):
        dedup = EventDeduplicator(_make_config())
        # Create a bucket with an old timestamp
        ip, etype, user, port, data = _ssh_event()
        dedup.track_ssh(ip, etype, user, port, data, time.time() - 600)

        assert dedup.stats["ssh_buckets"] == 1
        dedup.cleanup(max_age=300)
        assert dedup.stats["ssh_buckets"] == 0


class TestStats:
    def test_stats_returns_correct_counts(self):
        dedup = EventDeduplicator(_make_config())
        ts = 1000.0

        # 2 SSH buckets (different IPs)
        for ip_suffix in ("1.1.1.1", "2.2.2.2"):
            ip, etype, user, port, data = _ssh_event(ip=ip_suffix)
            dedup.track_ssh(ip, etype, user, port, data, ts)

        # 1 HTTP bucket
        data_h = {"source_ip": "3.3.3.3", "method": "GET", "path": "/"}
        dedup.track_http("3.3.3.3", "GET", "/", 80, data_h, ts)

        stats = dedup.stats
        assert stats["enabled"] is True
        assert stats["ssh_buckets"] == 2
        assert stats["http_buckets"] == 1
        assert stats["ssh_pending_events"] == 2
        assert stats["http_pending_events"] == 1
