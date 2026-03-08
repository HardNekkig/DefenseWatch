import logging

import httpx

logger = logging.getLogger(__name__)

VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


async def lookup_virustotal(ip: str, api_key: str, timeout: float = 15.0) -> dict | None:
    if not api_key:
        return None
    try:
        url = VT_IP_URL.format(ip=ip)
        headers = {"x-apikey": api_key}
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "ip": ip,
                    "as_owner": attrs.get("as_owner"),
                    "asn": attrs.get("asn"),
                    "country": attrs.get("country"),
                    "reputation": attrs.get("reputation"),
                    "network": attrs.get("network"),
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_votes": attrs.get("total_votes", {}),
                    "tags": attrs.get("tags", []),
                    "whois": (attrs.get("whois") or "")[:2000],
                    "last_analysis_date": attrs.get("last_analysis_date"),
                }
            else:
                logger.warning(f"VirusTotal API returned {resp.status_code} for {ip}")
    except Exception as e:
        logger.error(f"VirusTotal lookup failed for {ip}: {e}")
    return None
