import asyncio
import time
import logging
from defensewatch.enrichment.geoip import lookup_geoip
from defensewatch.enrichment.rdns import lookup_rdns
from defensewatch.enrichment.whois_lookup import lookup_whois
from defensewatch.database import get_db
from defensewatch.broadcast import ConnectionManager
from defensewatch.config import AppConfig

logger = logging.getLogger(__name__)

_api_semaphore = asyncio.Semaphore(45)


class EnrichmentPipeline:
    def __init__(self, config: AppConfig, queue: asyncio.Queue, manager: ConnectionManager):
        self.config = config
        self.queue = queue
        self.manager = manager
        self._workers: list[asyncio.Task] = []
        self._running = False

    async def start(self):
        self._running = True
        for i in range(self.config.enrichment.worker_count):
            task = asyncio.create_task(self._worker(i))
            self._workers.append(task)
        logger.info(f"Enrichment pipeline started with {len(self._workers)} workers")

    async def stop(self):
        self._running = False
        for task in self._workers:
            task.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    async def _worker(self, worker_id: int):
        while self._running:
            try:
                ip = await asyncio.wait_for(self.queue.get(), timeout=5.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            try:
                await self._enrich_ip(ip)
            except Exception as e:
                logger.error(f"Worker {worker_id} error enriching {ip}: {e}")
            finally:
                self.queue.task_done()

    async def _enrich_ip(self, ip: str):
        db = get_db()
        # Check if already enriched recently
        rows = await db.execute_fetchall(
            "SELECT enriched_at FROM ip_intel WHERE ip=?", (ip,)
        )
        if rows:
            enriched_at = rows[0][0]
            if enriched_at and (time.time() - enriched_at) < self.config.geoip.re_enrich_after_days * 86400:
                return

        # Run lookups in parallel
        async with _api_semaphore:
            tasks = [lookup_geoip(ip, self.config.geoip.fallback_api)]
            tasks.append(lookup_rdns(ip))
            if self.config.enrichment.whois_enabled:
                tasks.append(lookup_whois(ip))
            else:
                tasks.append(asyncio.coroutine(lambda: None)() if False else asyncio.sleep(0))

            results = await asyncio.gather(*tasks, return_exceptions=True)

        geo = results[0] if not isinstance(results[0], Exception) else None
        rdns_result = results[1] if not isinstance(results[1], Exception) else None
        whois_result = results[2] if len(results) > 2 and not isinstance(results[2], Exception) else None

        # Merge results
        intel = {
            "ip": ip,
            "rdns": None,
            "asn": None,
            "org": None,
            "country_code": None,
            "country_name": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "isp": None,
            "whois_raw": None,
            "source": None,
            "enriched_at": time.time(),
        }

        if geo:
            intel.update({k: v for k, v in geo.items() if v is not None})
        if rdns_result:
            intel["rdns"] = rdns_result
        if isinstance(whois_result, dict):
            if whois_result.get("org") and not intel["org"]:
                intel["org"] = whois_result["org"]
            if whois_result.get("whois_raw"):
                intel["whois_raw"] = whois_result["whois_raw"][:2000]

        # Upsert
        await db.execute(
            """INSERT INTO ip_intel (ip, rdns, asn, org, country_code, country_name, city,
               latitude, longitude, isp, whois_raw, source, enriched_at)
               VALUES (:ip, :rdns, :asn, :org, :country_code, :country_name, :city,
               :latitude, :longitude, :isp, :whois_raw, :source, :enriched_at)
               ON CONFLICT(ip) DO UPDATE SET
               rdns=excluded.rdns, asn=excluded.asn, org=excluded.org,
               country_code=excluded.country_code, country_name=excluded.country_name,
               city=excluded.city, latitude=excluded.latitude, longitude=excluded.longitude,
               isp=excluded.isp, whois_raw=excluded.whois_raw, source=excluded.source,
               enriched_at=excluded.enriched_at""",
            intel
        )

        # Get the ip_intel id and update FK on events
        rows = await db.execute_fetchall(
            "SELECT id FROM ip_intel WHERE ip=?", (ip,)
        )
        if rows:
            ip_id = rows[0][0]
            await db.execute("UPDATE ssh_events SET ip_id=? WHERE source_ip=? AND ip_id IS NULL", (ip_id, ip))
            await db.execute("UPDATE http_events SET ip_id=? WHERE source_ip=? AND ip_id IS NULL", (ip_id, ip))
            await db.execute("UPDATE brute_force_sessions SET ip_id=? WHERE source_ip=? AND ip_id IS NULL", (ip_id, ip))

        await db.commit()

        # Broadcast enrichment
        await self.manager.broadcast("ip_enriched", {
            "ip": ip,
            "country_code": intel["country_code"],
            "country_name": intel["country_name"],
            "city": intel["city"],
            "org": intel["org"],
            "isp": intel["isp"],
            "rdns": intel["rdns"],
            "latitude": intel["latitude"],
            "longitude": intel["longitude"],
        })

        logger.debug(f"Enriched {ip}: {intel['country_code']} / {intel['org']}")

    @property
    def queue_depth(self) -> int:
        return self.queue.qsize()
