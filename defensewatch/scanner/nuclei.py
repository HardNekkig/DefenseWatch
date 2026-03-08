"""
Nuclei vulnerability scanner integration via Docker.

Runs the projectdiscovery/nuclei container against specified targets and
parses the JSON-lines output into structured findings.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Severity ordering for sorting / filtering
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Remediation hints per common template tag / category
_REMEDIATION_HINTS = {
    "cve": "Apply the vendor security patch for this CVE. Check the reference URLs for the advisory.",
    "misconfig": "Review and harden the service configuration. Disable unnecessary features and default credentials.",
    "exposure": "Restrict access to this endpoint using firewall rules or authentication. It should not be publicly reachable.",
    "default-login": "Change default credentials immediately. Use strong, unique passwords and enable MFA if supported.",
    "xss": "Sanitize and encode all user input. Implement a Content-Security-Policy header.",
    "sqli": "Use parameterized queries / prepared statements. Never interpolate user input into SQL.",
    "rce": "Patch the affected software immediately. Restrict network access to the service.",
    "lfi": "Validate and sanitize file path inputs. Use chroot or restrict the web server's filesystem access.",
    "ssrf": "Validate URLs on the server side. Block internal/private IP ranges in outbound requests.",
    "cors": "Restrict Access-Control-Allow-Origin to trusted domains only. Never use wildcard (*) with credentials.",
    "ssl": "Upgrade to TLS 1.2+, disable weak ciphers, and renew expired certificates.",
    "header": "Add missing security headers: HSTS, X-Content-Type-Options, X-Frame-Options, CSP.",
    "takeover": "Remove dangling DNS records pointing to deprovisioned services.",
    "tech-detect": "Informational — technology detected. Ensure it is up to date and properly configured.",
    "token": "Rotate the exposed secret/token immediately and audit its usage.",
    "unauth": "Enforce authentication on this endpoint. Review access control policies.",
}


@dataclass
class NucleiConfig:
    enabled: bool = False
    docker_image: str = "projectdiscovery/nuclei:latest"
    severity_filter: str = ""  # e.g. "low,medium,high,critical" — empty = all
    rate_limit: int = 150  # requests per second
    timeout_minutes: int = 30
    extra_args: list[str] = field(default_factory=list)


@dataclass
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    host: str
    matched_url: str
    description: str
    tags: list[str]
    reference: list[str]
    matcher_name: str
    curl_command: str
    remediation: str
    raw_json: str
    protocol: str = ""
    ip: str = ""
    request: str = ""
    response: str = ""
    extracted_results: list[str] = field(default_factory=list)
    found_at: float = 0.0


def _derive_remediation(tags: list[str], name: str, description: str) -> str:
    """Pick the most relevant remediation hint based on template tags."""
    for tag in tags:
        tag_lower = tag.lower()
        if tag_lower in _REMEDIATION_HINTS:
            return _REMEDIATION_HINTS[tag_lower]
    # Fallback: scan name / description for keywords
    combined = f"{name} {description}".lower()
    for keyword, hint in _REMEDIATION_HINTS.items():
        if keyword in combined:
            return hint
    return "Review the finding details and reference URLs. Apply patches or restrict access as appropriate."


def _parse_finding(line: str) -> NucleiFinding | None:
    """Parse a single JSON-lines entry from Nuclei output."""
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    info = obj.get("info", {})
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    name = info.get("name", obj.get("template-id", "unknown"))
    description = info.get("description", "")
    reference = info.get("reference") or []
    if isinstance(reference, str):
        reference = [reference]

    extracted = obj.get("extracted-results") or []
    if isinstance(extracted, str):
        extracted = [extracted]

    return NucleiFinding(
        template_id=obj.get("template-id", ""),
        name=name,
        severity=info.get("severity", "info").lower(),
        host=obj.get("host", ""),
        matched_url=obj.get("matched-at", obj.get("host", "")),
        description=description,
        tags=tags,
        reference=reference,
        matcher_name=obj.get("matcher-name", ""),
        curl_command=obj.get("curl-command", ""),
        remediation=_derive_remediation(tags, name, description),
        raw_json=line.strip(),
        protocol=obj.get("type", ""),
        ip=obj.get("ip", ""),
        request=obj.get("request", ""),
        response=obj.get("response", ""),
        extracted_results=extracted,
        found_at=time.time(),
    )


async def run_nuclei_scan(
    targets: list[str],
    config: NucleiConfig,
    on_finding=None,
    tags: list[str] | None = None,
    cancel_event: asyncio.Event | None = None,
) -> list[NucleiFinding]:
    """
    Run a Nuclei scan via Docker against the given targets.

    Args:
        targets: List of URLs or host:port to scan (e.g. ["https://10.0.0.1:443", "ssh://10.0.0.1:22"])
        config: NucleiConfig with Docker image, severity filter, etc.
        on_finding: Optional async callback called for each finding as it arrives
        tags: Nuclei template tags to include (e.g. ["wordpress", "nginx", "cve"])
        cancel_event: Optional asyncio.Event — when set, the scan is killed

    Returns:
        List of parsed findings
    """
    if not targets:
        return []

    target_str = ",".join(targets)

    cmd = [
        "docker", "run", "--rm", "--network=host",
        config.docker_image,
        "-target", target_str,
        "-jsonl",
        "-rate-limit", str(config.rate_limit),
        "-silent",
        "-no-color",
    ]

    if config.severity_filter:
        cmd.extend(["-severity", config.severity_filter])

    if tags:
        cmd.extend(["-tags", ",".join(tags)])

    if config.extra_args:
        cmd.extend(config.extra_args)

    logger.info(f"Starting Nuclei scan: targets={targets}")

    timeout = config.timeout_minutes * 60
    findings: list[NucleiFinding] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def read_output():
            while True:
                if cancel_event and cancel_event.is_set():
                    logger.info("Nuclei scan cancelled by user")
                    proc.kill()
                    raise asyncio.CancelledError()
                line = await proc.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").strip()
                if not decoded:
                    continue
                finding = _parse_finding(decoded)
                if finding:
                    findings.append(finding)
                    if on_finding:
                        await on_finding(finding)

        try:
            await asyncio.wait_for(read_output(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(f"Nuclei scan timed out after {config.timeout_minutes}m, killing")
            proc.kill()
        except asyncio.CancelledError:
            pass  # already killed in read_output

        await proc.wait()

        # Log stderr for debugging
        stderr = await proc.stderr.read()
        if stderr:
            stderr_text = stderr.decode("utf-8", errors="replace").strip()
            # Nuclei prints progress to stderr — only log errors
            for line in stderr_text.splitlines():
                if "error" in line.lower() or "fatal" in line.lower():
                    logger.error(f"Nuclei stderr: {line}")

        if cancel_event and cancel_event.is_set():
            logger.info(f"Nuclei scan stopped: {len(findings)} findings before cancellation")
        else:
            logger.info(f"Nuclei scan complete: {len(findings)} findings")

    except FileNotFoundError:
        logger.error("Docker not found. Install Docker to use Nuclei scanning.")
    except Exception as e:
        logger.error(f"Nuclei scan failed: {e}")

    return findings
