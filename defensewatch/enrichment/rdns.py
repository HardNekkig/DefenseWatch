import logging
import dns.asyncresolver
import dns.reversename

logger = logging.getLogger(__name__)


async def lookup_rdns(ip: str) -> str | None:
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = await dns.asyncresolver.resolve(rev_name, "PTR")
        if answers:
            return str(answers[0]).rstrip('.')
    except Exception as e:
        logger.debug(f"rDNS lookup failed for {ip}: {e}")
    return None
