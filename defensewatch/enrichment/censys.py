import base64
import logging

import httpx

logger = logging.getLogger(__name__)

CENSYS_HOST_URL = "https://api.platform.censys.io/v3/global/asset/host/{ip}"


async def lookup_censys(ip: str, api_id: str, api_secret: str, timeout: float = 15.0) -> dict | None:
    if not api_secret:
        return None
    try:
        url = CENSYS_HOST_URL.format(ip=ip)
        # In the Platform API, the secret acts as the full Bearer token
        headers = {"Authorization": f"Bearer {api_secret}"}
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                result = resp.json().get("result", {}).get("resource", {})
                services = []
                for s in result.get("services", [])[:20]:
                    services.append({
                        "port": s.get("port"),
                        "service_name": s.get("protocol") or s.get("service_name"),
                        "transport_protocol": s.get("transport_protocol"),
                        "software": [
                            sw.get("product", "") for sw in s.get("software", [])
                        ] if "software" in s else [],
                    })
                return {
                    "ip": ip,
                    "services": services,
                    "operating_system": result.get("operating_system", {}).get("product"),
                    "autonomous_system": {
                        "asn": result.get("autonomous_system", {}).get("asn"),
                        "name": result.get("autonomous_system", {}).get("name"),
                        "bgp_prefix": result.get("autonomous_system", {}).get("bgp_prefix"),
                    },
                    "location": {
                        "country": result.get("location", {}).get("country"),
                        "city": result.get("location", {}).get("city"),
                    },
                    "last_updated_at": result.get("scan_time") or result.get("last_updated_at"),
                    "labels": result.get("labels", []),
                }
            elif resp.status_code == 404:
                return {"ip": ip, "error": "No information available"}
            else:
                logger.warning(f"Censys API returned {resp.status_code} for {ip}")
    except Exception as e:
        logger.error(f"Censys lookup failed for {ip}: {e}")
    return None
