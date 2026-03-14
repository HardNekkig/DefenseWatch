import time
import pytest
from defensewatch.health_monitor import MetricsStore, get_metrics_store, _store
import defensewatch.health_monitor as hm_module


class TestRecordSample:
    def test_adds_to_ring_buffer(self):
        store = MetricsStore(max_samples=100)
        store.record_sample({"timestamp": 1000, "value": 42})
        assert len(store.get_samples()) == 1
        assert store.get_samples()[0]["value"] == 42

    def test_multiple_samples(self):
        store = MetricsStore(max_samples=100)
        for i in range(5):
            store.record_sample({"timestamp": 1000 + i, "idx": i})
        assert len(store.get_samples()) == 5


class TestRingBufferOverflow:
    def test_respects_max_size(self):
        store = MetricsStore(max_samples=3)
        for i in range(5):
            store.record_sample({"timestamp": 1000 + i, "idx": i})
        samples = store.get_samples()
        assert len(samples) == 3
        # Oldest samples (idx 0, 1) should have been dropped
        assert samples[0]["idx"] == 2
        assert samples[1]["idx"] == 3
        assert samples[2]["idx"] == 4


class TestGetSamples:
    def test_returns_all_when_no_limit(self):
        store = MetricsStore(max_samples=100)
        for i in range(10):
            store.record_sample({"idx": i})
        assert len(store.get_samples()) == 10

    def test_returns_last_n(self):
        store = MetricsStore(max_samples=100)
        for i in range(10):
            store.record_sample({"idx": i})
        samples = store.get_samples(last_n=3)
        assert len(samples) == 3
        assert samples[0]["idx"] == 7
        assert samples[1]["idx"] == 8
        assert samples[2]["idx"] == 9

    def test_empty_store_returns_empty(self):
        store = MetricsStore(max_samples=100)
        assert store.get_samples() == []
        assert store.get_samples(last_n=5) == []


class TestRecordEvent:
    def test_updates_counters(self):
        store = MetricsStore()
        store.record_event("ssh")
        store.record_event("ssh")
        store.record_event("http")
        counts = store.get_event_counts()
        assert counts["ssh"] == 2
        assert counts["http"] == 1

    def test_records_watcher_last_event(self):
        store = MetricsStore()
        before = time.time()
        store.record_event("ssh", file_path="/var/log/auth.log")
        after = time.time()
        last_events = store.get_watcher_last_events()
        assert "/var/log/auth.log" in last_events
        assert before <= last_events["/var/log/auth.log"] <= after

    def test_no_file_path_skips_watcher_tracking(self):
        store = MetricsStore()
        store.record_event("ssh")
        assert store.get_watcher_last_events() == {}


class TestDeadmanAlerts:
    def test_returns_stale_watchers(self):
        store = MetricsStore()
        # Record an event long ago
        store._watcher_last_event["/var/log/auth.log"] = time.time() - 1000
        alerts = store.get_deadman_alerts(
            threshold_seconds=600,
            watched_files=["/var/log/auth.log"],
        )
        assert len(alerts) == 1
        assert alerts[0]["file_path"] == "/var/log/auth.log"
        assert alerts[0]["status"] == "stale"

    def test_no_alert_for_recent_watcher(self):
        store = MetricsStore()
        store._watcher_last_event["/var/log/auth.log"] = time.time()
        alerts = store.get_deadman_alerts(
            threshold_seconds=600,
            watched_files=["/var/log/auth.log"],
        )
        assert len(alerts) == 0

    def test_no_alert_for_never_seen_watcher(self):
        """Watchers that never produced events don't trigger alerts."""
        store = MetricsStore()
        alerts = store.get_deadman_alerts(
            threshold_seconds=600,
            watched_files=["/var/log/auth.log"],
        )
        assert len(alerts) == 0

    def test_only_watched_files_checked(self):
        store = MetricsStore()
        store._watcher_last_event["/var/log/auth.log"] = time.time() - 1000
        # Ask about a different file
        alerts = store.get_deadman_alerts(
            threshold_seconds=600,
            watched_files=["/var/log/nginx/access.log"],
        )
        assert len(alerts) == 0


class TestGetMetricsStoreSingleton:
    def test_returns_singleton(self):
        # Reset module-level singleton
        old_store = hm_module._store
        hm_module._store = None
        try:
            store1 = get_metrics_store()
            store2 = get_metrics_store()
            assert store1 is store2
        finally:
            hm_module._store = old_store
