import asyncio
import json
import time
import logging
import httpx
from defensewatch.config import ThreatIntelConfig
from defensewatch.database import get_db

logger = logging.getLogger(__name__)

_ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"
_OTX_INDICATOR = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"


async def check_abuseipdb(ip: str, api_key: str, timeout: float = 10.0) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                _ABUSEIPDB_CHECK,
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            if resp.status_code != 200:
                logger.debug(f"AbuseIPDB returned {resp.status_code} for {ip}")
                return None
            data = resp.json().get("data", {})
            return {
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "is_tor": data.get("isTor", False),
                "last_reported": data.get("lastReportedAt"),
            }
    except Exception as e:
        logger.debug(f"AbuseIPDB lookup failed for {ip}: {e}")
        return None


async def check_otx(ip: str, api_key: str, timeout: float = 10.0) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                _OTX_INDICATOR.format(ip=ip),
                headers={"X-OTX-API-KEY": api_key},
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            pulses = data.get("pulse_info", {})
            return {
                "pulse_count": pulses.get("count", 0),
                "reputation": data.get("reputation", 0),
                "tags": list(set(
                    tag for p in pulses.get("pulses", [])[:10]
                    for tag in p.get("tags", [])[:5]
                ))[:20],
            }
    except Exception as e:
        logger.debug(f"OTX lookup failed for {ip}: {e}")
        return None


async def enrich_ip_threat_intel(ip: str, config: ThreatIntelConfig) -> dict | None:
    """Run all configured threat intel checks for an IP and cache results."""
    if not config.enabled:
        return None

    result = {}
    tasks = []

    if config.abuseipdb_api_key:
        tasks.append(("abuseipdb", check_abuseipdb(ip, config.abuseipdb_api_key)))
    if config.otx_api_key:
        tasks.append(("otx", check_otx(ip, config.otx_api_key)))

    if not tasks:
        return None

    names = [t[0] for t in tasks]
    coros = [t[1] for t in tasks]
    results = await asyncio.gather(*coros, return_exceptions=True)

    for name, res in zip(names, results):
        if isinstance(res, Exception):
            logger.debug(f"Threat intel {name} failed for {ip}: {res}")
            continue
        if res:
            result[name] = res

    if not result:
        return None

    # Store in database
    try:
        db = get_db()
        await db.execute(
            """INSERT INTO threat_intel_hits (ip, source, data, checked_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(ip, source) DO UPDATE SET data=excluded.data, checked_at=excluded.checked_at""",
            (ip, "combined", json.dumps(result), time.time())
        )
        await db.commit()
    except Exception as e:
        logger.error(f"Failed to store threat intel for {ip}: {e}")

    return result


async def get_cached_threat_intel(ip: str) -> dict | None:
    """Retrieve cached threat intel for an IP."""
    try:
        db = get_db()
        rows = await db.execute_fetchall(
            "SELECT data, checked_at FROM threat_intel_hits WHERE ip=? ORDER BY checked_at DESC LIMIT 1",
            (ip,)
        )
        if rows:
            return {"data": json.loads(rows[0][0]), "checked_at": rows[0][1]}
    except Exception as e:
        logger.debug(f"Failed to get cached threat intel for {ip}: {e}")
    return None
