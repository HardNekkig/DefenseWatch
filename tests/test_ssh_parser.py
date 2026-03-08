import pytest
from defensewatch.parsers.ssh import parse_ssh_line, BruteForceTracker, DistributedBruteForceTracker
from defensewatch.models import SSHEvent


class TestParseSSHLine:
    def test_failed_password_invalid_user(self):
        line = "2026-03-03T17:52:00.825029+01:00 myhost sshd[1234]: Failed password for invalid user admin from 192.168.1.1 port 54321 ssh2"
        event = parse_ssh_line(line)
        assert event is not None
        assert event.event_type == "invalid_user"
        assert event.username == "admin"
        assert event.source_ip == "192.168.1.1"
        assert event.source_port == 54321
        assert event.auth_method == "password"
        assert event.hostname == "myhost"
        assert event.pid == 1234

    def test_failed_password_valid_user(self):
        line = "2026-03-03T17:52:00.825029+01:00 myhost sshd[1234]: Failed password for root from 10.0.0.1 port 22222 ssh2"
        event = parse_ssh_line(line)
        assert event is not None
        assert event.event_type == "failed_password"
        assert event.username == "root"
        assert event.source_ip == "10.0.0.1"

    def test_invalid_user_empty_username(self):
        line = "2026-03-03T17:52:00.825029+01:00 myhost sshd[1234]: Invalid user  from 192.168.1.1 port 54321"
        event = parse_ssh_line(line)
        assert event is not None
        assert event.event_type == "invalid_user"
        assert event.username is None
        assert event.source_ip == "192.168.1.1"

    def test_accepted_password(self):
        line = "2026-03-03T17:52:00.825029+01:00 myhost sshd[1234]: Accepted password for user1 from 10.0.0.5 port 55555 ssh2"
        event = parse_ssh_line(line)
        assert event is not None
        assert event.event_type == "accepted_password"
        assert event.auth_method == "password"

    def test_accepted_publickey(self):
        line = "2026-03-03T17:52:00.825029+01:00 myhost sshd[1234]: Accepted publickey for deploy from 10.0.0.5 port 55555 ssh2"
        event = parse_ssh_line(line)
        assert event is not None
        assert event.event_type == "accepted_publickey"
        assert event.auth_method == "publickey"

    def test_failed_publickey(self):
        line = "2026-03-03T17:52:00.825029+01:00 myhost sshd[1234]: Failed publickey for root from 10.0.0.1 port 22222 ssh2"
        event = parse_ssh_line(line)
        assert event is not None
        assert event.event_type == "failed_publickey"
        assert event.auth_method == "publickey"

    def test_disconnected_invalid_user(self):
        line = "2026-03-03T17:52:00.825029+01:00 myhost sshd[1234]: Disconnected from invalid user admin 192.168.1.1 port 54321"
        event = parse_ssh_line(line)
        assert event is not None
        assert event.event_type == "disconnected"
        assert event.username == "admin"

    def test_empty_line(self):
        assert parse_ssh_line("") is None
        assert parse_ssh_line("   ") is None

    def test_non_sshd_line(self):
        line = "2026-03-03T17:52:00.825029+01:00 myhost systemd[1]: Started service"
        assert parse_ssh_line(line) is None

    def test_malformed_timestamp(self):
        line = "not-a-timestamp myhost sshd[1234]: Failed password for root from 10.0.0.1 port 22222"
        assert parse_ssh_line(line) is None


class TestBruteForceTracker:
    def _make_event(self, ip="1.2.3.4", username="root", ts=1000.0):
        return SSHEvent(
            timestamp=ts, event_type="failed_password", username=username,
            source_ip=ip, source_port=22, auth_method="password",
            hostname="host", pid=1, raw_line="test",
        )

    def test_no_session_below_threshold(self, detection_config):
        tracker = BruteForceTracker(detection_config)
        for i in range(4):
            result = tracker.track(self._make_event(ts=1000.0 + i))
        assert result is None

    def test_session_at_threshold(self, detection_config):
        tracker = BruteForceTracker(detection_config)
        for i in range(5):
            result = tracker.track(self._make_event(ts=1000.0 + i))
        assert result is not None
        assert result.attempt_count == 5
        assert result.source_ip == "1.2.3.4"

    def test_is_new_session(self, detection_config):
        tracker = BruteForceTracker(detection_config)
        for i in range(5):
            tracker.track(self._make_event(ts=1000.0 + i))
        assert tracker.is_new_session("1.2.3.4") is True
        tracker.mark_alerted("1.2.3.4")
        assert tracker.is_new_session("1.2.3.4") is False

    def test_session_updates_on_continued_attempts(self, detection_config):
        tracker = BruteForceTracker(detection_config)
        for i in range(5):
            tracker.track(self._make_event(ts=1000.0 + i))
        tracker.mark_alerted("1.2.3.4")

        result = tracker.track(self._make_event(ts=1006.0, username="admin"))
        assert result is not None
        assert result.attempt_count == 6
        assert "admin" in result.usernames_tried

    def test_cleanup_completes_expired_sessions(self, detection_config):
        tracker = BruteForceTracker(detection_config)
        for i in range(5):
            tracker.track(self._make_event(ts=1000.0 + i))
        tracker.mark_alerted("1.2.3.4")

        # Simulate time passing beyond window
        import time
        original_time = time.time
        time.time = lambda: 1000.0 + 400  # 400s > 300s window
        completed = tracker.cleanup()
        time.time = original_time

        assert len(completed) == 1
        assert completed[0].status == "completed"
        assert "1.2.3.4" not in tracker._active_sessions
        assert "1.2.3.4" not in tracker._alerted

    def test_ignores_non_failure_events(self, detection_config):
        tracker = BruteForceTracker(detection_config)
        event = SSHEvent(
            timestamp=1000.0, event_type="accepted_password", username="root",
            source_ip="1.2.3.4", source_port=22, auth_method="password",
            hostname="host", pid=1, raw_line="test",
        )
        assert tracker.track(event) is None

    def test_window_expiry_prunes_attempts(self, detection_config):
        tracker = BruteForceTracker(detection_config)
        # 4 attempts at time 0
        for i in range(4):
            tracker.track(self._make_event(ts=1000.0 + i))
        # 1 attempt at time 400 (beyond 300s window)
        result = tracker.track(self._make_event(ts=1400.0))
        assert result is None  # Only 1 recent attempt


class TestDistributedBruteForceTracker:
    def _make_event(self, ip, username="root", ts=1000.0):
        return SSHEvent(
            timestamp=ts, event_type="failed_password", username=username,
            source_ip=ip, source_port=22, auth_method="password",
            hostname="host", pid=1, raw_line="test",
        )

    def test_detects_distributed_attack(self, detection_config):
        tracker = DistributedBruteForceTracker(detection_config)
        result = None
        for i in range(5):
            result = tracker.track(self._make_event(
                ip=f"10.0.0.{i+1}", username="root", ts=1000.0 + i))
        assert result is not None
        assert result["username"] == "root"
        assert result["ip_count"] == 5

    def test_no_alert_below_threshold(self, detection_config):
        tracker = DistributedBruteForceTracker(detection_config)
        for i in range(4):
            result = tracker.track(self._make_event(
                ip=f"10.0.0.{i+1}", username="root", ts=1000.0 + i))
        assert result is None

    def test_only_alerts_once(self, detection_config):
        tracker = DistributedBruteForceTracker(detection_config)
        for i in range(5):
            tracker.track(self._make_event(
                ip=f"10.0.0.{i+1}", username="root", ts=1000.0 + i))
        # 6th IP should not re-alert
        result = tracker.track(self._make_event(
            ip="10.0.0.6", username="root", ts=1006.0))
        assert result is None
