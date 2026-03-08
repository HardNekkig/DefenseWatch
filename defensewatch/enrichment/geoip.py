import asyncio
import logging
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

_reader = None
_has_geoip2 = False

try:
    import geoip2.database
    _has_geoip2 = True
except ImportError:
    pass


def init_geoip(mmdb_path: str):
    global _reader
    if not _has_geoip2:
        logger.warning("geoip2 not installed, using fallback API only")
        return
    if not Path(mmdb_path).exists():
        logger.warning(f"GeoLite2 DB not found at {mmdb_path}, using fallback API")
        return
    _reader = geoip2.database.Reader(mmdb_path)
    logger.info(f"GeoLite2 loaded from {mmdb_path}")


def close_geoip():
    global _reader
    if _reader:
        _reader.close()
        _reader = None


async def lookup_geoip(ip: str, fallback_url: str | None = None) -> dict | None:
    # Try local MaxMind first
    if _reader:
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, _reader.city, ip
            )
            return {
                "country_code": result.country.iso_code,
                "country_name": result.country.name,
                "city": result.city.name,
                "latitude": result.location.latitude,
                "longitude": result.location.longitude,
                "org": result.traits.organization,
                "isp": result.traits.isp if hasattr(result.traits, 'isp') else None,
                "asn": f"AS{result.traits.autonomous_system_number}" if hasattr(result.traits, 'autonomous_system_number') and result.traits.autonomous_system_number else None,
                "source": "maxmind",
            }
        except Exception as e:
            logger.debug(f"MaxMind lookup failed for {ip}: {e}")

    # Fallback to ip-api.com
    if fallback_url:
        try:
            url = fallback_url.format(ip=ip)
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        return {
                            "country_code": data.get("countryCode"),
                            "country_name": data.get("country"),
                            "city": data.get("city"),
                            "latitude": data.get("lat"),
                            "longitude": data.get("lon"),
                            "isp": data.get("isp"),
                            "org": data.get("org"),
                            "asn": data.get("as", "").split()[0] if data.get("as") else None,
                            "rdns": data.get("reverse"),
                            "source": "ip-api",
                        }
        except Exception as e:
            logger.debug(f"ip-api fallback failed for {ip}: {e}")

    return None
