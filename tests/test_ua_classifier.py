import pytest
from defensewatch.parsers.ua_classifier import (
    classify_user_agent,
    UA_BROWSER,
    UA_BOT,
    UA_CRAWLER,
    UA_ATTACK_TOOL,
    UA_LIBRARY,
    UA_UNKNOWN,
)


class TestClassifyBrowsers:
    def test_chrome(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        assert classify_user_agent(ua) == UA_BROWSER

    def test_firefox(self):
        ua = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
        assert classify_user_agent(ua) == UA_BROWSER

    def test_safari(self):
        ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
        assert classify_user_agent(ua) == UA_BROWSER

    def test_edge(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edge/120.0.0.0"
        assert classify_user_agent(ua) == UA_BROWSER


class TestClassifyAttackTools:
    def test_nikto(self):
        assert classify_user_agent("Nikto/2.1.6") == UA_ATTACK_TOOL

    def test_sqlmap(self):
        assert classify_user_agent("sqlmap/1.7#stable") == UA_ATTACK_TOOL

    def test_nmap(self):
        assert classify_user_agent("Nmap Scripting Engine") == UA_ATTACK_TOOL

    def test_masscan(self):
        assert classify_user_agent("masscan/1.3") == UA_ATTACK_TOOL

    def test_nuclei(self):
        assert classify_user_agent("Nuclei - Open-source project") == UA_ATTACK_TOOL


class TestClassifyBots:
    def test_googlebot(self):
        assert classify_user_agent("Googlebot/2.1 (+http://www.google.com/bot.html)") == UA_BOT

    def test_bingbot(self):
        assert classify_user_agent("Mozilla/5.0 (compatible; bingbot/2.0)") == UA_BOT

    def test_uptimerobot(self):
        assert classify_user_agent("UptimeRobot/2.0") == UA_BOT


class TestClassifyCrawlers:
    def test_wget(self):
        assert classify_user_agent("Wget/1.21.4") == UA_CRAWLER

    def test_scrapy(self):
        assert classify_user_agent("Scrapy/2.11.0 (+https://scrapy.org)") == UA_CRAWLER

    def test_selenium(self):
        assert classify_user_agent("selenium/4.16.0 (python)") == UA_CRAWLER


class TestClassifyLibraries:
    def test_python_requests(self):
        assert classify_user_agent("python-requests/2.31.0") == UA_LIBRARY

    def test_curl(self):
        assert classify_user_agent("curl/8.4.0") == UA_LIBRARY

    def test_go_http_client(self):
        assert classify_user_agent("Go-http-client/2.0") == UA_LIBRARY


class TestClassifyUnknown:
    def test_none(self):
        assert classify_user_agent(None) == UA_UNKNOWN

    def test_empty_string(self):
        assert classify_user_agent("") == UA_UNKNOWN

    def test_dash(self):
        assert classify_user_agent("-") == UA_UNKNOWN

    def test_short_ua(self):
        assert classify_user_agent("abc") == UA_UNKNOWN

    def test_short_ua_boundary(self):
        # 14 chars is below the 15-char threshold
        assert classify_user_agent("SomeRandomTool") == UA_UNKNOWN


class TestClassifyPriority:
    def test_attack_tool_takes_priority_over_browser(self):
        """A browser-like UA containing an attack tool name should be classified as attack_tool."""
        ua = "Mozilla/5.0 (compatible; Nikto/2.1.6)"
        assert classify_user_agent(ua) == UA_ATTACK_TOOL

    def test_attack_tool_over_crawler(self):
        ua = "sqlmap crawler spider"
        assert classify_user_agent(ua) == UA_ATTACK_TOOL

    def test_crawler_over_bot(self):
        """Crawlers are checked before bots in priority order."""
        ua = "Googlebot-spider-crawler"
        # "crawler" matches _CRAWLERS, "Googlebot" matches _BOTS
        # but _CRAWLERS is checked before _BOTS
        assert classify_user_agent(ua) == UA_CRAWLER

    def test_library_over_browser(self):
        """python-requests with Mozilla prefix: library patterns are checked before browser."""
        ua = "python-requests/2.31.0"
        assert classify_user_agent(ua) == UA_LIBRARY
