import asyncio
import logging
import httpx

logger = logging.getLogger(__name__)

_RDAP_BOOTSTRAP = "https://rdap.org/ip/{ip}"


async def lookup_whois(ip: str, timeout: float = 10.0) -> dict | None:
    """Look up IP registration info via RDAP (replacing legacy python-whois)."""
    try:
        url = _RDAP_BOOTSTRAP.format(ip=ip)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None

            data = resp.json()
            org = None
            whois_parts = []

            # Extract org/name from entities
            for entity in data.get("entities", []):
                vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []
                for field in vcard:
                    if field[0] == "org":
                        org = field[3]
                    elif field[0] == "fn":
                        if not org:
                            org = field[3]
                roles = entity.get("roles", [])
                handle = entity.get("handle", "")
                if handle:
                    whois_parts.append(f"{handle} ({', '.join(roles)})")

            # Extract name from top-level
            name = data.get("name", "")
            if name and not org:
                org = name

            whois_raw = f"RDAP: {data.get('name', '')} | {' | '.join(whois_parts)}"

            return {
                "org": org,
                "asn": None,
                "whois_raw": whois_raw[:2000],
            }

    except httpx.TimeoutException:
        logger.debug(f"RDAP timeout for {ip}")
    except Exception as e:
        logger.debug(f"RDAP lookup failed for {ip}: {e}")
    return None
