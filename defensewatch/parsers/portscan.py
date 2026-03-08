"""Port scan detection — tracks IPs hitting multiple distinct service ports."""

import time
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from defensewatch.config import DetectionConfig

logger = logging.getLogger(__name__)


@dataclass
class PortScanEvent:
    source_ip: str
    detected_at: float
    ports_hit: list[int]
    port_count: int
    window_seconds: int
    status: str = "active"


class PortScanTracker:
    """Detects port scanning by tracking distinct service ports an IP connects to."""

    def __init__(self, config: DetectionConfig):
        self.threshold = config.portscan_threshold
        self.window = config.portscan_window_seconds
        # ip -> [(timestamp, port), ...]
        self._hits: dict[str, list[tuple[float, int]]] = defaultdict(list)
        self._alerted: set[str] = set()

    def track(self, ip: str, port: int, timestamp: float) -> PortScanEvent | None:
        """Record a port hit. Returns a PortScanEvent if scan threshold is reached."""
        if port is None:
            return None

        hits = self._hits[ip]
        hits.append((timestamp, port))

        # Prune old hits
        cutoff = timestamp - self.window
        self._hits[ip] = [(t, p) for t, p in hits if t >= cutoff]
        hits = self._hits[ip]

        # Count distinct ports
        distinct_ports = sorted(set(p for _, p in hits))

        if len(distinct_ports) >= self.threshold and ip not in self._alerted:
            self._alerted.add(ip)
            return PortScanEvent(
                source_ip=ip,
                detected_at=timestamp,
                ports_hit=distinct_ports,
                port_count=len(distinct_ports),
                window_seconds=self.window,
            )

        return None

    def cleanup(self):
        """Remove stale tracking data."""
        now = time.time()
        cutoff = now - self.window
        stale = []
        for ip, hits in self._hits.items():
            self._hits[ip] = [(t, p) for t, p in hits if t >= cutoff]
            if not self._hits[ip]:
                stale.append(ip)
        for ip in stale:
            del self._hits[ip]
            self._alerted.discard(ip)
