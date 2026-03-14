"""IP reputation blocklist downloads and checking.

Downloads and caches well-known IP blocklists (Spamhaus DROP/EDROP,
DShield Top 20, Firehol Level 1) and provides fast in-memory lookups
using the Python ipaddress module.
"""

import asyncio
import ipaddress
import logging
import time

import httpx

from defensewatch.config import BlocklistConfig
from defensewatch.database import get_db

logger = logging.getLogger(__name__)

# ── Blocklist source definitions ──────────────────────────────────────

BLOCKLIST_SOURCES = {
    "spamhaus_drop": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "description": "Spamhaus DROP (Don't Route Or Peer)",
        "parser": "_parse_spamhaus",
    },
    "spamhaus_edrop": {
        "url": "https://www.spamhaus.org/drop/edrop.txt",
        "description": "Spamhaus EDROP (Extended DROP)",
        "parser": "_parse_spamhaus",
    },
    "dshield": {
        "url": "https://feeds.dshield.org/block.txt",
        "description": "DShield Top 20 Attacking Networks",
        "parser": "_parse_dshield",
    },
    "firehol_level1": {
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "description": "Firehol Level 1 (aggregated worst-of-the-worst)",
        "parser": "_parse_firehol",
    },
}


# ── Parsers ──────────────────────────────────────────────────────────

def _parse_spamhaus(text: str) -> list[tuple[str, str]]:
    """Parse Spamhaus DROP/EDROP format.

    Lines look like:  ``1.2.3.0/24 ; SBL123456``
    """
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split(";", 1)
        network_str = parts[0].strip()
        description = parts[1].strip() if len(parts) > 1 else ""
        try:
            ipaddress.ip_network(network_str, strict=False)
            entries.append((network_str, description))
        except ValueError:
            continue
    return entries


def _parse_dshield(text: str) -> list[tuple[str, str]]:
    """Parse DShield block.txt format.

    Data lines (after comment header) look like:
    ``10.0.0.0\t10.255.255.255\t8\tattacks\tname\tcountry\temail``
    The third column is the CIDR prefix length.
    """
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        start_ip = parts[0].strip()
        prefix_len = parts[2].strip()
        try:
            network_str = f"{start_ip}/{prefix_len}"
            ipaddress.ip_network(network_str, strict=False)
            entries.append((network_str, "DShield Top 20"))
        except ValueError:
            continue
    return entries


def _parse_firehol(text: str) -> list[tuple[str, str]]:
    """Parse Firehol netset format.

    Lines are CIDR networks; comments start with ``#``.
    """
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_network(line, strict=False)
            entries.append((line, "Firehol Level 1"))
        except ValueError:
            continue
    return entries


_PARSERS = {
    "_parse_spamhaus": _parse_spamhaus,
    "_parse_dshield": _parse_dshield,
    "_parse_firehol": _parse_firehol,
}


# ── DB helpers ───────────────────────────────────────────────────────

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS blocklist_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    list_name TEXT NOT NULL,
    network TEXT NOT NULL,
    description TEXT DEFAULT '',
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blocklist_list ON blocklist_entries(list_name);
"""


async def _ensure_table(db):
    await db.executescript(_CREATE_TABLE_SQL)
    await db.commit()


# ── Manager ──────────────────────────────────────────────────────────

class BlocklistManager:
    """Manages blocklist downloads, DB persistence, and in-memory lookup cache."""

    def __init__(self, config: BlocklistConfig | None = None):
        self.config = config or BlocklistConfig()
        # In-memory cache: list_name -> list[ipaddress.IPv4Network | IPv6Network]
        self._networks: dict[str, list[ipaddress.ip_network]] = {}
        self._last_refresh: float | None = None
        self._stats: dict[str, int] = {}
        self._refresh_task: asyncio.Task | None = None
        self._running = False

    # ── Public API ───────────────────────────────────────────────

    async def start(self):
        """Start the background refresh loop."""
        db = get_db()
        await _ensure_table(db)
        # Load existing entries from DB into memory cache
        await self._load_from_db()
        self._running = True
        if self.config.enabled:
            self._refresh_task = asyncio.create_task(self._refresh_loop())
            logger.info("Blocklist manager started (refresh every %dh)", self.config.refresh_interval_hours)

    async def stop(self):
        """Stop the background refresh loop."""
        self._running = False
        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
            self._refresh_task = None
        logger.info("Blocklist manager stopped")

    async def refresh(self):
        """Download and update all enabled blocklists."""
        logger.info("Refreshing blocklists...")
        db = get_db()
        await _ensure_table(db)

        now = time.time()
        total_new = 0

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            for list_name in self.config.lists:
                source = BLOCKLIST_SOURCES.get(list_name)
                if not source:
                    logger.warning("Unknown blocklist: %s", list_name)
                    continue

                try:
                    resp = await client.get(source["url"])
                    resp.raise_for_status()
                    text = resp.text
                except Exception as exc:
                    logger.warning("Failed to download %s: %s", list_name, exc)
                    continue

                parser_fn = _PARSERS.get(source["parser"])
                if not parser_fn:
                    logger.warning("No parser for %s", list_name)
                    continue

                entries = parser_fn(text)
                if not entries:
                    logger.warning("No entries parsed from %s", list_name)
                    continue

                # Replace all entries for this list in a single transaction
                await db.execute("DELETE FROM blocklist_entries WHERE list_name=?", (list_name,))
                await db.executemany(
                    "INSERT INTO blocklist_entries (list_name, network, description, updated_at) VALUES (?,?,?,?)",
                    [(list_name, net, desc, now) for net, desc in entries],
                )
                await db.commit()

                # Update in-memory cache
                networks = []
                for net_str, _ in entries:
                    try:
                        networks.append(ipaddress.ip_network(net_str, strict=False))
                    except ValueError:
                        pass
                self._networks[list_name] = networks
                self._stats[list_name] = len(entries)
                total_new += len(entries)
                logger.info("Blocklist %s: %d entries loaded", list_name, len(entries))

        self._last_refresh = now
        logger.info("Blocklist refresh complete: %d total entries across %d lists", total_new, len(self.config.lists))

    def check_ip(self, ip: str) -> list[dict]:
        """Check if an IP is on any loaded blocklist.

        Returns a list of dicts with keys: list_name, network, description.
        Fast in-memory check using ipaddress containment.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return []

        matches = []
        for list_name, networks in self._networks.items():
            for net in networks:
                if addr in net:
                    source = BLOCKLIST_SOURCES.get(list_name, {})
                    matches.append({
                        "list_name": list_name,
                        "network": str(net),
                        "description": source.get("description", list_name),
                    })
                    break  # one match per list is enough
        return matches

    def get_stats(self) -> dict:
        """Return stats: entries per list and last refresh time."""
        return {
            "enabled": self.config.enabled,
            "last_refresh": self._last_refresh,
            "refresh_interval_hours": self.config.refresh_interval_hours,
            "auto_block": self.config.auto_block,
            "lists": {
                name: {
                    "entries": self._stats.get(name, 0),
                    "url": BLOCKLIST_SOURCES.get(name, {}).get("url", ""),
                    "description": BLOCKLIST_SOURCES.get(name, {}).get("description", ""),
                    "loaded": name in self._networks,
                }
                for name in self.config.lists
            },
            "total_entries": sum(self._stats.values()),
            "configured_lists": self.config.lists,
            "available_lists": list(BLOCKLIST_SOURCES.keys()),
        }

    # ── Internal ─────────────────────────────────────────────────

    async def _load_from_db(self):
        """Load cached blocklist entries from DB into memory."""
        db = get_db()
        try:
            rows = await db.execute_fetchall(
                "SELECT list_name, network, updated_at FROM blocklist_entries ORDER BY list_name"
            )
        except Exception:
            # Table might not exist yet on first run
            return

        networks_by_list: dict[str, list] = {}
        counts: dict[str, int] = {}
        latest_ts: float = 0

        for row in rows:
            list_name = row[0]
            net_str = row[1]
            ts = row[2] or 0
            if ts > latest_ts:
                latest_ts = ts

            if list_name not in networks_by_list:
                networks_by_list[list_name] = []
                counts[list_name] = 0

            try:
                networks_by_list[list_name].append(ipaddress.ip_network(net_str, strict=False))
                counts[list_name] += 1
            except ValueError:
                continue

        self._networks = networks_by_list
        self._stats = counts
        if latest_ts > 0:
            self._last_refresh = latest_ts

        total = sum(counts.values())
        if total:
            logger.info("Loaded %d blocklist entries from DB cache (%d lists)", total, len(counts))

    async def _refresh_loop(self):
        """Background loop that refreshes blocklists on the configured interval."""
        while self._running:
            try:
                await self.refresh()
            except Exception as exc:
                logger.error("Blocklist refresh error: %s", exc)

            interval = self.config.refresh_interval_hours * 3600
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break


# ── Scoring integration ──────────────────────────────────────────────

# Module-level reference set by main.py lifespan or similar
_manager: BlocklistManager | None = None


def set_blocklist_manager(manager: BlocklistManager):
    global _manager
    _manager = manager


def get_blocklist_manager() -> BlocklistManager | None:
    return _manager


def blocklist_score_boost(ip: str) -> tuple[int, list[str]]:
    """Return (score_points, reasons) for scoring integration.

    Called synchronously from the scoring module.  Returns (0, []) when
    blocklists are disabled or the IP is clean.
    """
    if _manager is None:
        return 0, []

    matches = _manager.check_ip(ip)
    if not matches:
        return 0, []

    list_names = [m["list_name"] for m in matches]
    # Scale points by number of lists the IP appears on
    if len(matches) >= 3:
        points = 25
    elif len(matches) >= 2:
        points = 20
    else:
        points = 15

    reasons = [f"Blocklisted on {', '.join(list_names)}"]
    return points, reasons
