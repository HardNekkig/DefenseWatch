"""Event deduplication and aggregation for DefenseWatch.

Aggregates repeated events within time windows to reduce DB bloat
under heavy attack conditions.
"""

import logging
import time
from dataclasses import dataclass, field

from fastapi import APIRouter
from defensewatch.config import DedupConfig

logger = logging.getLogger(__name__)


@dataclass
class AggregatedEvent:
    """An aggregated event bucket."""
    event_count: int = 1
    first_seen: float = 0.0
    last_seen: float = 0.0
    # Store the first event's data for the DB insert
    event_data: dict = field(default_factory=dict)


class EventDeduplicator:
    """Aggregates repeated events within a time window.

    Usage:
        dedup = EventDeduplicator(config)

        # In handler, instead of direct DB insert:
        result = dedup.track_ssh(key_tuple, event_data_dict, timestamp)
        if result is None:
            pass  # event was absorbed into existing bucket
        else:
            # result is the aggregated event to store (with event_count)
            store_to_db(result)
    """

    def __init__(self, config: DedupConfig):
        self.config = config
        # Separate buckets for SSH and HTTP
        self._ssh_buckets: dict[tuple, AggregatedEvent] = {}
        self._http_buckets: dict[tuple, AggregatedEvent] = {}

    def track_ssh(self, source_ip: str, event_type: str, username: str | None,
                  service_port: int | None, event_data: dict,
                  timestamp: float) -> dict | None:
        """Track an SSH event. Returns aggregated event dict to store, or None if absorbed.

        Returns the event_data dict with added 'event_count' field when:
        - This is a new event (first occurrence)
        - The window has expired for the previous batch
        - The batch hit max_batch_size
        """
        if not self.config.enabled:
            event_data["event_count"] = 1
            return event_data

        key = (source_ip, event_type, username or "", service_port or 0)
        return self._track(key, event_data, timestamp,
                           self._ssh_buckets, self.config.ssh_window_seconds)

    def track_http(self, source_ip: str, method: str, path: str,
                   service_port: int | None, event_data: dict,
                   timestamp: float) -> dict | None:
        """Track an HTTP event. Returns aggregated event dict to store, or None if absorbed."""
        if not self.config.enabled:
            event_data["event_count"] = 1
            return event_data

        # Normalize path to first 100 chars for grouping
        path_key = path[:100] if path else ""
        key = (source_ip, method, path_key, service_port or 0)
        return self._track(key, event_data, timestamp,
                           self._http_buckets, self.config.http_window_seconds)

    def _track(self, key: tuple, event_data: dict, timestamp: float,
               buckets: dict[tuple, AggregatedEvent],
               window_seconds: int) -> dict | None:
        """Core tracking logic."""
        if key in buckets:
            bucket = buckets[key]
            age = timestamp - bucket.first_seen

            if age > window_seconds or bucket.event_count >= self.config.max_batch_size:
                # Window expired or batch full: flush the old bucket, start new one
                flushed = dict(bucket.event_data)
                flushed["event_count"] = bucket.event_count
                flushed["timestamp"] = bucket.last_seen  # use last seen time

                # Start new bucket with current event
                buckets[key] = AggregatedEvent(
                    event_count=1,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    event_data=event_data,
                )
                return flushed
            else:
                # Absorb into existing bucket
                bucket.event_count += 1
                bucket.last_seen = timestamp
                return None
        else:
            # New event - create bucket and return event for immediate storage
            buckets[key] = AggregatedEvent(
                event_count=1,
                first_seen=timestamp,
                last_seen=timestamp,
                event_data=event_data,
            )
            event_data["event_count"] = 1
            return event_data

    def flush_all(self) -> list[dict]:
        """Flush all pending buckets. Returns list of events to store."""
        flushed = []
        for buckets in (self._ssh_buckets, self._http_buckets):
            for key, bucket in list(buckets.items()):
                if bucket.event_count > 1:
                    ev = dict(bucket.event_data)
                    ev["event_count"] = bucket.event_count
                    ev["timestamp"] = bucket.last_seen
                    flushed.append(ev)
            buckets.clear()
        return flushed

    def cleanup(self, max_age: float = 300):
        """Remove stale buckets older than max_age seconds."""
        now = time.time()
        for buckets in (self._ssh_buckets, self._http_buckets):
            stale_keys = [
                k for k, v in buckets.items()
                if (now - v.last_seen) > max_age
            ]
            for k in stale_keys:
                bucket = buckets.pop(k)
                # Events in stale buckets with count > 1 are lost
                # This is acceptable as they represent old aggregated noise
                if bucket.event_count > 1:
                    logger.debug(
                        "Stale dedup bucket dropped: %s (count=%d)",
                        k, bucket.event_count,
                    )

    @property
    def stats(self) -> dict:
        """Return current dedup statistics."""
        ssh_pending = sum(b.event_count for b in self._ssh_buckets.values())
        http_pending = sum(b.event_count for b in self._http_buckets.values())
        return {
            "enabled": self.config.enabled,
            "ssh_buckets": len(self._ssh_buckets),
            "http_buckets": len(self._http_buckets),
            "ssh_pending_events": ssh_pending,
            "http_pending_events": http_pending,
            "ssh_window_seconds": self.config.ssh_window_seconds,
            "http_window_seconds": self.config.http_window_seconds,
        }


# ── Module-level singleton ─────────────────────────────────────────────

_dedup: EventDeduplicator | None = None


def get_deduplicator() -> EventDeduplicator | None:
    return _dedup


def set_dedup_config(config: DedupConfig) -> EventDeduplicator:
    global _dedup
    _dedup = EventDeduplicator(config)
    return _dedup


# ── API ────────────────────────────────────────────────────────────────

from fastapi import APIRouter

router = APIRouter(prefix="/api/dedup", tags=["dedup"])


@router.get("/stats")
async def dedup_stats():
    """Return current deduplication statistics."""
    dedup = get_deduplicator()
    if dedup is None:
        return {"enabled": False}
    return dedup.stats
