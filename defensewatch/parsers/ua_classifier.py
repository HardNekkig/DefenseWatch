"""User-Agent fingerprinting and bot classification."""

import re

# Classification categories
UA_BROWSER = "browser"
UA_BOT = "bot"
UA_CRAWLER = "crawler"
UA_ATTACK_TOOL = "attack_tool"
UA_LIBRARY = "library"
UA_UNKNOWN = "unknown"

# ── Attack tools (highest priority) ──
_ATTACK_TOOLS = re.compile(
    r'(?:nikto|sqlmap|nmap|masscan|acunetix|burpsuite|dirbuster|gobuster|'
    r'wfuzz|ffuf|feroxbuster|hydra|medusa|metasploit|w3af|zap/|'
    r'havij|commix|xsstrike|nuclei|openvas|nessus|qualys)',
    re.I,
)

# ── Known bots (search engines, etc) ──
_BOTS = re.compile(
    r'(?:googlebot|bingbot|slurp|duckduckbot|baiduspider|yandexbot|'
    r'sogou|exabot|facebot|ia_archiver|mj12bot|ahrefsbot|semrushbot|'
    r'dotbot|rogerbot|blexbot|uptimerobot|pingdom|statuscake|'
    r'monitoring|healthcheck|nagios|zabbix|datadog|newrelic|'
    r'facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegram|discord|slack)',
    re.I,
)

# ── Crawlers / spiders ──
_CRAWLERS = re.compile(
    r'(?:spider|crawler|scraper|wget|httrack|scrapy|phantomjs|headless|'
    r'puppeteer|selenium|playwright|splash|archive\.org|heritrix|nutch)',
    re.I,
)

# ── HTTP libraries ──
_LIBRARIES = re.compile(
    r'(?:python-requests|python-urllib|python/|aiohttp|httpx|'
    r'curl/|libcurl|java/|apache-httpclient|okhttp|'
    r'go-http-client|net/http|axios|node-fetch|undici|'
    r'ruby|perl|lwp|libwww-perl|php/|guzzle)',
    re.I,
)

# ── Major browsers ──
_BROWSERS = re.compile(
    r'(?:mozilla/5\.0.*(?:chrome|firefox|safari|edge|opera|opr|vivaldi|brave|msie|trident))',
    re.I,
)


def classify_user_agent(ua: str | None) -> str:
    """Classify a User-Agent string.

    Returns one of: browser, bot, crawler, attack_tool, library, unknown
    """
    if not ua or ua == '-':
        return UA_UNKNOWN

    # Check in priority order: attack tools first
    if _ATTACK_TOOLS.search(ua):
        return UA_ATTACK_TOOL
    if _CRAWLERS.search(ua):
        return UA_CRAWLER
    if _BOTS.search(ua):
        return UA_BOT
    if _LIBRARIES.search(ua):
        return UA_LIBRARY
    if _BROWSERS.search(ua):
        return UA_BROWSER

    # Heuristic: very short UAs or missing standard browser markers are suspicious
    if len(ua) < 15:
        return UA_UNKNOWN

    return UA_UNKNOWN
