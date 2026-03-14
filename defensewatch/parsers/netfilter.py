"""Parse iptables/netfilter LOG lines to detect SYN scans (nmap -sS).

Requires an iptables rule that logs SYN packets with the DWSYN: prefix:

    iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -j LOG \
        --log-prefix "DWSYN:" --log-level 4

Lines appear in /var/log/kern.log or /var/log/syslog depending on distro.
"""

import re
import time
import logging
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

_PREFIX = "DWSYN:"

# Extract fields from iptables LOG output
_SRC_RE = re.compile(r"SRC=([\d.]+)")
_DPT_RE = re.compile(r"DPT=(\d+)")

# Syslog timestamp: "Mar 14 10:23:45"
_SYSLOG_TS_RE = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+"
)

# ISO-8601 timestamp (systemd/journald)
_ISO_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+\-]\d{2}:\d{2})\s+"
)


@dataclass
class NetfilterSYNEvent:
    source_ip: str
    dest_port: int
    timestamp: float


def _parse_syslog_ts(match: re.Match) -> float:
    month_str, day_str, time_str = match.group(1), match.group(2), match.group(3)
    year = datetime.now().year
    try:
        dt = datetime.strptime(f"{year} {month_str} {day_str} {time_str}", "%Y %b %d %H:%M:%S")
        return dt.timestamp()
    except ValueError:
        return time.time()


def parse_netfilter_line(line: str) -> NetfilterSYNEvent | None:
    """Parse an iptables LOG line with DWSYN: prefix. Returns None if not a matching SYN packet."""
    if _PREFIX not in line:
        return None

    # Must be TCP SYN without ACK (reject SYN-ACK from our own services)
    proto_pos = line.find("PROTO=TCP")
    if proto_pos == -1:
        return None
    flags_section = line[proto_pos:]
    if " SYN " not in flags_section and not flags_section.endswith(" SYN"):
        return None
    if " ACK" in flags_section:
        return None

    src = _SRC_RE.search(line)
    dpt = _DPT_RE.search(line)
    if not src or not dpt:
        return None

    # Parse timestamp
    iso_m = _ISO_TS_RE.match(line)
    if iso_m:
        try:
            ts = datetime.fromisoformat(iso_m.group(1)).timestamp()
        except ValueError:
            ts = time.time()
    else:
        syslog_m = _SYSLOG_TS_RE.match(line)
        if syslog_m:
            ts = _parse_syslog_ts(syslog_m)
        else:
            ts = time.time()

    return NetfilterSYNEvent(
        source_ip=src.group(1),
        dest_port=int(dpt.group(1)),
        timestamp=ts,
    )
