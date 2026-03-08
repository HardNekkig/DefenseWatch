import os
import asyncio
import logging
from pathlib import Path
from watchdog.observers.polling import PollingObserver
from defensewatch.watchers.handlers import SSHLogHandler, HTTPLogHandler, NginxErrorLogHandler, ServiceLogHandler
from defensewatch.parsers.portscan import PortScanTracker
from defensewatch.broadcast import ConnectionManager
from defensewatch.config import AppConfig
from defensewatch.notifications import Notifier
from defensewatch.telegram import TelegramNotifier

logger = logging.getLogger(__name__)


class WatcherManager:
    def __init__(self, config: AppConfig, manager: ConnectionManager,
                 loop: asyncio.AbstractEventLoop, enrichment_queue: asyncio.Queue,
                 telegram_notifier: TelegramNotifier | None = None):
        self.config = config
        self.manager = manager
        self.loop = loop
        self.enrichment_queue = enrichment_queue
        self.notifier = Notifier(config.notifications, telegram=telegram_notifier)
        self.portscan_tracker = PortScanTracker(config.detection)
        self.observer = PollingObserver(timeout=2)
        self.handlers: list = []

    def _extract_vhost(self, path: str) -> str | None:
        name = Path(path).name
        if name == 'access.log':
            return None
        # e.g. example.com.access.log -> example.com
        # e.g. mysite.org-access.log -> mysite.org
        for sep in ('.access.log', '-access.log'):
            if name.endswith(sep):
                return name[:-len(sep)]
        return None

    async def start(self):
        # Set up SSH watchers
        for entry in self.config.logs.ssh_entries():
            if not os.path.exists(entry.path):
                logger.warning(f"SSH log not found: {entry.path}")
                continue
            handler = SSHLogHandler(
                entry.path, self.loop, self.manager,
                self.config.detection, self.enrichment_queue,
                notifier=self.notifier,
                service_port=entry.port,
                whitelist=self.config.firewall.whitelist,
                portscan_tracker=self.portscan_tracker,
            )
            self.handlers.append(handler)
            watch_dir = str(Path(entry.path).parent)
            self.observer.schedule(handler, watch_dir, recursive=False)
            logger.info(f"Watching SSH log: {entry.path} (port={entry.port})")

        # Set up HTTP watchers
        for entry in self.config.logs.http_entries():
            if not os.path.exists(entry.path):
                logger.warning(f"HTTP log not found: {entry.path}")
                continue
            vhost = self._extract_vhost(entry.path)
            handler = HTTPLogHandler(
                entry.path, self.loop, self.manager,
                self.config.detection,
                vhost=vhost, enrichment_queue=self.enrichment_queue,
                notifier=self.notifier,
                service_port=entry.port,
                whitelist=self.config.firewall.whitelist,
                portscan_tracker=self.portscan_tracker,
            )
            self.handlers.append(handler)
            watch_dir = str(Path(entry.path).parent)
            self.observer.schedule(handler, watch_dir, recursive=False)
            logger.info(f"Watching HTTP log: {entry.path} (vhost={vhost}, port={entry.port})")

        # Set up nginx error watchers
        for entry in self.config.logs.nginx_error_entries():
            if not os.path.exists(entry.path):
                logger.warning(f"Nginx error log not found: {entry.path}")
                continue
            handler = NginxErrorLogHandler(
                entry.path, self.loop, self.manager,
                enrichment_queue=self.enrichment_queue,
                notifier=self.notifier,
                service_port=entry.port,
                whitelist=self.config.firewall.whitelist,
            )
            self.handlers.append(handler)
            watch_dir = str(Path(entry.path).parent)
            self.observer.schedule(handler, watch_dir, recursive=False)
            logger.info(f"Watching nginx error log: {entry.path} (port={entry.port})")

        # Set up service log watchers (MySQL, PostgreSQL, mail, FTP)
        _service_configs = [
            ("mysql", self.config.logs.mysql_entries()),
            ("postgresql", self.config.logs.postgresql_entries()),
            ("mail", self.config.logs.mail_entries()),
            ("ftp", self.config.logs.ftp_entries()),
        ]
        for svc_category, entries in _service_configs:
            for entry in entries:
                if not os.path.exists(entry.path):
                    logger.warning(f"{svc_category} log not found: {entry.path}")
                    continue
                handler = ServiceLogHandler(
                    entry.path, self.loop, self.manager,
                    service_category=svc_category,
                    enrichment_queue=self.enrichment_queue,
                    notifier=self.notifier,
                    service_port=entry.port,
                    whitelist=self.config.firewall.whitelist,
                    portscan_tracker=self.portscan_tracker,
                )
                self.handlers.append(handler)
                watch_dir = str(Path(entry.path).parent)
                self.observer.schedule(handler, watch_dir, recursive=False)
                logger.info(f"Watching {svc_category} log: {entry.path} (port={entry.port})")

        # Backfill existing logs
        for handler in self.handlers:
            await handler.backfill()

        self.observer.start()
        logger.info(f"WatcherManager started with {len(self.handlers)} watchers")

    def stop(self):
        self.observer.stop()
        self.observer.join(timeout=5)
        logger.info("WatcherManager stopped")

    @property
    def status(self) -> dict:
        return {
            "active_watchers": len(self.handlers),
            "observer_alive": self.observer.is_alive(),
            "watched_files": [h.file_path for h in self.handlers],
        }
