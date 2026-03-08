import logging

import httpx

logger = logging.getLogger(__name__)

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}?key={key}"


async def lookup_shodan(ip: str, api_key: str, timeout: float = 15.0) -> dict | None:
    if not api_key:
        return None
    try:
        url = SHODAN_HOST_URL.format(ip=ip, key=api_key)
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "ip": data.get("ip_str"),
                    "hostnames": data.get("hostnames", []),
                    "os": data.get("os"),
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "tags": data.get("tags", []),
                    "org": data.get("org"),
                    "isp": data.get("isp"),
                    "asn": data.get("asn"),
                    "country_code": data.get("country_code"),
                    "city": data.get("city"),
                    "last_update": data.get("last_update"),
                    "services": [
                        {
                            "port": s.get("port"),
                            "transport": s.get("transport"),
                            "product": s.get("product"),
                            "version": s.get("version"),
                            "cpe": s.get("cpe", []),
                        }
                        for s in data.get("data", [])[:20]
                    ],
                }
            elif resp.status_code == 404:
                return {"ip": ip, "error": "No information available"}
            else:
                logger.warning(f"Shodan API returned {resp.status_code} for {ip}")
    except Exception as e:
        logger.error(f"Shodan lookup failed for {ip}: {e}")
    return None
