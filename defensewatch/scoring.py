import json
import logging
from defensewatch.database import get_db

logger = logging.getLogger(__name__)


async def compute_threat_score(ip: str) -> dict:
    """Compute a 0-100 threat score for an IP based on multiple signals."""
    db = get_db()
    score = 0
    reasons = []

    # SSH failed attempts
    rows = await db.execute_fetchall(
        """SELECT COUNT(*) FROM ssh_events
           WHERE source_ip=? AND event_type IN ('failed_password', 'invalid_user')""",
        (ip,)
    )
    ssh_fails = rows[0][0] if rows else 0
    if ssh_fails >= 50:
        score += 30
        reasons.append(f"{ssh_fails} SSH failures")
    elif ssh_fails >= 10:
        score += 20
        reasons.append(f"{ssh_fails} SSH failures")
    elif ssh_fails >= 1:
        score += 10
        reasons.append(f"{ssh_fails} SSH failures")

    # Brute force sessions
    rows = await db.execute_fetchall(
        "SELECT COUNT(*) FROM brute_force_sessions WHERE source_ip=?", (ip,)
    )
    brute_count = rows[0][0] if rows else 0
    if brute_count > 0:
        score += min(brute_count * 10, 20)
        reasons.append(f"{brute_count} brute force sessions")

    # HTTP attacks
    rows = await db.execute_fetchall(
        "SELECT severity, COUNT(*) FROM http_events WHERE source_ip=? GROUP BY severity",
        (ip,)
    )
    severity_weights = {'critical': 15, 'high': 10, 'medium': 5, 'low': 2}
    for r in rows:
        sev = r[0]
        cnt = r[1]
        w = severity_weights.get(sev, 0)
        points = min(cnt * w, 25)
        if points > 0:
            score += points
            reasons.append(f"{cnt} {sev} HTTP attacks")

    # Port scanning
    rows = await db.execute_fetchall(
        "SELECT COUNT(*), MAX(port_count) FROM port_scan_events WHERE source_ip=?",
        (ip,)
    )
    ps_count = rows[0][0] if rows else 0
    ps_max_ports = rows[0][1] if rows and rows[0][1] else 0
    if ps_count > 0:
        points = min(10 + ps_max_ports * 2, 20)
        score += points
        reasons.append(f"{ps_count} port scans ({ps_max_ports} ports max)")

    # VirusTotal malicious score
    rows = await db.execute_fetchall(
        "SELECT virustotal_data FROM ip_intel WHERE ip=?", (ip,)
    )
    if rows and rows[0][0]:
        try:
            vt = json.loads(rows[0][0])
            malicious = vt.get("malicious", 0) or 0
            if malicious > 5:
                score += 20
                reasons.append(f"VT: {malicious} malicious detections")
            elif malicious > 0:
                score += 10
                reasons.append(f"VT: {malicious} malicious detections")
        except (json.JSONDecodeError, TypeError):
            pass

    # Shodan vulnerabilities
    shodan_rows = await db.execute_fetchall(
        "SELECT shodan_data FROM ip_intel WHERE ip=?", (ip,)
    )
    if shodan_rows and shodan_rows[0][0]:
        try:
            shodan = json.loads(shodan_rows[0][0])
            vulns = shodan.get("vulns", [])
            if vulns:
                score += min(len(vulns) * 3, 15)
                reasons.append(f"Shodan: {len(vulns)} CVEs")
        except (json.JSONDecodeError, TypeError):
            pass

    # Threat intel feeds
    ti_rows = await db.execute_fetchall(
        "SELECT data FROM threat_intel_hits WHERE ip=? ORDER BY checked_at DESC LIMIT 1",
        (ip,)
    )
    if ti_rows and ti_rows[0][0]:
        try:
            ti_data = json.loads(ti_rows[0][0])
            abuse = ti_data.get("abuseipdb", {})
            if abuse.get("abuse_confidence", 0) >= 80:
                score += 20
                reasons.append(f"AbuseIPDB: {abuse['abuse_confidence']}% confidence")
            elif abuse.get("abuse_confidence", 0) >= 30:
                score += 10
                reasons.append(f"AbuseIPDB: {abuse['abuse_confidence']}% confidence")
            if abuse.get("is_tor"):
                score += 5
                reasons.append("Tor exit node")

            otx = ti_data.get("otx", {})
            if otx.get("pulse_count", 0) > 0:
                score += min(otx["pulse_count"] * 3, 15)
                reasons.append(f"OTX: {otx['pulse_count']} threat pulses")
        except (json.JSONDecodeError, TypeError):
            pass

    score = min(score, 100)

    if score >= 70:
        recommendation = "block"
    elif score >= 40:
        recommendation = "monitor"
    else:
        recommendation = "allow"

    return {
        "ip": ip,
        "score": score,
        "recommendation": recommendation,
        "reasons": reasons,
    }
