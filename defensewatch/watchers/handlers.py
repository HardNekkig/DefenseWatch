import os
import json
import time
import asyncio
import logging
import ipaddress
from pathlib import Path
from watchdog.events import FileSystemEventHandler, FileModifiedEvent
from defensewatch.parsers.ssh import parse_ssh_line, BruteForceTracker, DistributedBruteForceTracker
from defensewatch.parsers.http import parse_http_line, HTTPScanTracker
from defensewatch.parsers.portscan import PortScanTracker
from defensewatch.parsers.nginx_error import parse_nginx_error_line
from defensewatch.parsers.mysql import parse_mysql_line
from defensewatch.parsers.postgresql import parse_postgresql_line
from defensewatch.parsers.mail import parse_mail_line
from defensewatch.parsers.ftp import parse_ftp_line
from defensewatch.database import get_db
from defensewatch.broadcast import ConnectionManager
from defensewatch.config import DetectionConfig
from defensewatch.notifications import Notifier

logger = logging.getLogger(__name__)

_SEEN_IP_MAX_AGE = 7 * 86400  # 7 days


def _is_whitelisted(ip: str | None, whitelist: list[str] | None) -> bool:
    if not ip or not whitelist:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for prefix in whitelist:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            if ip_obj in net:
                return True
        except ValueError:
            if ip == prefix:
                return True
    return False


class LogHandler(FileSystemEventHandler):
    def __init__(self, file_path: str, loop: asyncio.AbstractEventLoop):
        self.file_path = file_path
        self.loop = loop
        self._offset = 0
        self._inode = None

    def _check_rotation(self):
        try:
            stat = os.stat(self.file_path)
            current_inode = stat.st_ino
            if self._inode is not None and current_inode != self._inode:
                logger.info(f"Log rotation detected for {self.file_path}")
                self._offset = 0
            self._inode = current_inode
        except FileNotFoundError:
            pass

    def on_modified(self, event):
        if not isinstance(event, FileModifiedEvent):
            return
        if event.src_path != self.file_path and not event.src_path.endswith(Path(self.file_path).name):
            return
        self._check_rotation()
        self._read_new_lines()

    def _read_new_lines(self):
        try:
            with open(self.file_path, 'r', errors='replace') as f:
                f.seek(self._offset)
                new_lines = f.readlines()
                self._offset = f.tell()

            for line in new_lines:
                self._process_line(line)
        except FileNotFoundError:
            logger.warning(f"File not found: {self.file_path}")
        except Exception as e:
            logger.error(f"Error reading {self.file_path}: {e}")

    def _process_line(self, line: str):
        raise NotImplementedError

    async def backfill(self):
        db = get_db()
        row = await db.execute_fetchall(
            "SELECT byte_offset, inode FROM log_state WHERE file_path=?",
            (self.file_path,)
        )
        if row:
            self._offset = row[0][0]
            self._inode = row[0][1]
        else:
            self._offset = 0

        self._check_rotation()
        self._read_new_lines()
        await self._save_state()

    async def _save_state(self):
        db = get_db()
        await db.execute(
            """INSERT INTO log_state (file_path, inode, byte_offset, last_seen, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(file_path) DO UPDATE SET
               inode=excluded.inode, byte_offset=excluded.byte_offset,
               last_seen=excluded.last_seen, updated_at=excluded.updated_at""",
            (self.file_path, self._inode, self._offset, time.time(), time.time())
        )
        await db.commit()


def _should_enrich(seen_ips: dict[str, float], ip: str) -> bool:
    now = time.time()
    if len(seen_ips) > 1000:
        cutoff = now - _SEEN_IP_MAX_AGE
        to_remove = [k for k, v in seen_ips.items() if v <= cutoff]
        for k in to_remove:
            del seen_ips[k]
    if ip in seen_ips:
        return False
    seen_ips[ip] = now
    return True


async def _store_portscan(ps, manager: ConnectionManager, notifier: Notifier | None = None):
    """Store a detected port scan event and broadcast via WebSocket."""
    try:
        db = get_db()
        await db.execute(
            """INSERT INTO port_scan_events
               (source_ip, detected_at, ports_hit, port_count, window_seconds, status)
               VALUES (?,?,?,?,?,?)""",
            (ps.source_ip, ps.detected_at, json.dumps(ps.ports_hit),
             ps.port_count, ps.window_seconds, ps.status)
        )
        await db.commit()
        await manager.broadcast("port_scan", {
            "source_ip": ps.source_ip,
            "detected_at": ps.detected_at,
            "ports_hit": ps.ports_hit,
            "port_count": ps.port_count,
        })
        if notifier:
            await notifier.notify_port_scan(
                ps.source_ip, ps.ports_hit, ps.port_count)
        logger.warning(f"Port scan detected from {ps.source_ip}: {ps.port_count} ports ({ps.ports_hit})")
    except Exception as e:
        logger.error(f"Error storing port scan event: {e}")


class SSHLogHandler(LogHandler):
    def __init__(self, file_path: str, loop: asyncio.AbstractEventLoop,
                 manager: ConnectionManager, detection: DetectionConfig,
                 enrichment_queue: asyncio.Queue | None = None,
                 notifier: Notifier | None = None,
                 service_port: int | None = 22,
                 whitelist: list[str] | None = None,
                 portscan_tracker: PortScanTracker | None = None):
        super().__init__(file_path, loop)
        self.manager = manager
        self.brute_tracker = BruteForceTracker(detection)
        self.distributed_tracker = DistributedBruteForceTracker(detection)
        self.enrichment_queue = enrichment_queue
        self.notifier = notifier
        self.service_port = service_port
        self.whitelist = whitelist or []
        self.portscan_tracker = portscan_tracker
        self._seen_ips: dict[str, float] = {}
        self._event_counter = 0

    def _process_line(self, line: str):
        event = parse_ssh_line(line)
        if event is None:
            return
        if _is_whitelisted(event.source_ip, self.whitelist):
            return
        event.service_port = self.service_port

        asyncio.run_coroutine_threadsafe(
            self._store_and_broadcast(event), self.loop
        )

    async def _store_and_broadcast(self, event):
        try:
            db = get_db()
            cursor = await db.execute(
                """INSERT INTO ssh_events (timestamp, event_type, username, source_ip, source_port,
                   auth_method, hostname, pid, raw_line, service_port) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (event.timestamp, event.event_type, event.username, event.source_ip,
                 event.source_port, event.auth_method, event.hostname, event.pid,
                 event.raw_line, event.service_port)
            )
            event.id = cursor.lastrowid
            await db.commit()

            await self.manager.broadcast("ssh_event", {
                "id": event.id,
                "timestamp": event.timestamp,
                "event_type": event.event_type,
                "username": event.username,
                "source_ip": event.source_ip,
                "source_port": event.source_port,
                "service_port": event.service_port,
            })

            # Brute force detection
            session = self.brute_tracker.track(event)
            if session and self.brute_tracker.is_new_session(event.source_ip):
                self.brute_tracker.mark_alerted(event.source_ip)
                await self._store_brute_force(session)
                await self.manager.broadcast("brute_force", {
                    "source_ip": session.source_ip,
                    "attempt_count": session.attempt_count,
                    "usernames_tried": session.usernames_tried,
                })
                if self.notifier:
                    await self.notifier.notify_brute_force(
                        session.source_ip, session.attempt_count,
                        session.usernames_tried)
            elif session:
                await self._update_brute_force(session)

            # Distributed brute force detection
            dist_alert = self.distributed_tracker.track(event)
            if dist_alert:
                await self.manager.broadcast("distributed_brute_force", dist_alert)

            # Port scan detection
            if self.portscan_tracker and self.service_port:
                ps = self.portscan_tracker.track(
                    event.source_ip, self.service_port, event.timestamp)
                if ps:
                    await _store_portscan(ps, self.manager, self.notifier if hasattr(self, 'notifier') else None)

            # Periodic cleanup
            self._event_counter += 1
            if self._event_counter % 100 == 0:
                completed = self.brute_tracker.cleanup()
                for s in completed:
                    await self._complete_brute_force(s)
                self.distributed_tracker.cleanup()
                if self.portscan_tracker:
                    self.portscan_tracker.cleanup()

            # Enrichment queue
            if _should_enrich(self._seen_ips, event.source_ip) and self.enrichment_queue:
                try:
                    self.enrichment_queue.put_nowait(event.source_ip)
                except asyncio.QueueFull:
                    pass

        except Exception as e:
            logger.error(f"Error storing SSH event: {e}")

    async def _store_brute_force(self, session):
        db = get_db()
        await db.execute(
            """INSERT INTO brute_force_sessions (source_ip, session_start, session_end,
               attempt_count, usernames_tried, event_type, status, service_port)
               VALUES (?,?,?,?,?,?,?,?)""",
            (session.source_ip, session.session_start, session.session_end,
             session.attempt_count, json.dumps(session.usernames_tried),
             session.event_type, session.status, session.service_port)
        )
        await db.commit()

    async def _update_brute_force(self, session):
        db = get_db()
        await db.execute(
            """UPDATE brute_force_sessions SET session_end=?, attempt_count=?,
               usernames_tried=? WHERE source_ip=? AND status='active'""",
            (session.session_end, session.attempt_count,
             json.dumps(session.usernames_tried), session.source_ip)
        )
        await db.commit()

    async def _complete_brute_force(self, session):
        db = get_db()
        await db.execute(
            """UPDATE brute_force_sessions SET status='completed'
               WHERE source_ip=? AND status='active'""",
            (session.source_ip,)
        )
        await db.commit()


class HTTPLogHandler(LogHandler):
    def __init__(self, file_path: str, loop: asyncio.AbstractEventLoop,
                 manager: ConnectionManager, detection: DetectionConfig,
                 vhost: str | None = None,
                 enrichment_queue: asyncio.Queue | None = None,
                 notifier: Notifier | None = None,
                 service_port: int | None = 80,
                 whitelist: list[str] | None = None,
                 portscan_tracker: PortScanTracker | None = None):
        super().__init__(file_path, loop)
        self.manager = manager
        self.vhost = vhost
        self.enrichment_queue = enrichment_queue
        self.notifier = notifier
        self.service_port = service_port
        self.whitelist = whitelist or []
        self.scan_tracker = HTTPScanTracker(detection)
        self.portscan_tracker = portscan_tracker
        self._seen_ips: dict[str, float] = {}
        self._event_counter = 0

    def _process_line(self, line: str):
        event = parse_http_line(line, vhost=self.vhost)
        if event is None:
            return
        if _is_whitelisted(event.source_ip, self.whitelist):
            return
        event.service_port = self.service_port

        # Rate-based 404 scan detection
        if not event.attack_types:
            is_scan = self.scan_tracker.track(
                event.source_ip, event.status_code, event.timestamp)
            if is_scan:
                event.attack_types = ['404_enumeration']
                event.severity = 'low'
            else:
                return

        asyncio.run_coroutine_threadsafe(
            self._store_and_broadcast(event), self.loop
        )

    async def _store_and_broadcast(self, event):
        try:
            db = get_db()
            cursor = await db.execute(
                """INSERT INTO http_events (timestamp, source_ip, method, path, http_version,
                   status_code, response_bytes, referer, user_agent, vhost,
                   attack_types, scanner_name, severity, raw_line, service_port)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (event.timestamp, event.source_ip, event.method, event.path,
                 event.http_version, event.status_code, event.response_bytes,
                 event.referer, event.user_agent, event.vhost,
                 json.dumps(event.attack_types), event.scanner_name,
                 event.severity, event.raw_line, event.service_port)
            )
            event.id = cursor.lastrowid
            await db.commit()

            await self.manager.broadcast("http_event", {
                "id": event.id,
                "timestamp": event.timestamp,
                "source_ip": event.source_ip,
                "method": event.method,
                "path": event.path,
                "status_code": event.status_code,
                "attack_types": event.attack_types,
                "severity": event.severity,
                "scanner_name": event.scanner_name,
                "service_port": event.service_port,
            })

            if self.notifier and event.severity:
                await self.notifier.notify_http_attack(
                    event.source_ip, event.path,
                    event.attack_types, event.severity)

            # Port scan detection
            if self.portscan_tracker and self.service_port:
                ps = self.portscan_tracker.track(
                    event.source_ip, self.service_port, event.timestamp)
                if ps:
                    await _store_portscan(ps, self.manager, self.notifier if hasattr(self, 'notifier') else None)

            self._event_counter += 1
            if self._event_counter % 100 == 0:
                self.scan_tracker.cleanup()
                if self.portscan_tracker:
                    self.portscan_tracker.cleanup()

            if _should_enrich(self._seen_ips, event.source_ip) and self.enrichment_queue:
                try:
                    self.enrichment_queue.put_nowait(event.source_ip)
                except asyncio.QueueFull:
                    pass

        except Exception as e:
            logger.error(f"Error storing HTTP event: {e}")


class NginxErrorLogHandler(LogHandler):
    """Watches nginx error logs and stores attack-relevant entries as HTTP events."""

    def __init__(self, file_path: str, loop: asyncio.AbstractEventLoop,
                 manager: ConnectionManager, vhost: str | None = None,
                 enrichment_queue: asyncio.Queue | None = None,
                 notifier: Notifier | None = None,
                 service_port: int | None = 80,
                 whitelist: list[str] | None = None):
        super().__init__(file_path, loop)
        self.manager = manager
        self.vhost = vhost
        self.enrichment_queue = enrichment_queue
        self.notifier = notifier
        self.service_port = service_port
        self.whitelist = whitelist or []
        self._seen_ips: dict[str, float] = {}

    def _process_line(self, line: str):
        event = parse_nginx_error_line(line, vhost=self.vhost)
        if event is None:
            return
        if _is_whitelisted(event.source_ip, self.whitelist):
            return
        event.service_port = self.service_port
        asyncio.run_coroutine_threadsafe(
            self._store_and_broadcast(event), self.loop
        )

    async def _store_and_broadcast(self, event):
        try:
            db = get_db()
            cursor = await db.execute(
                """INSERT INTO http_events (timestamp, source_ip, method, path, http_version,
                   status_code, response_bytes, referer, user_agent, vhost,
                   attack_types, scanner_name, severity, raw_line, service_port)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (event.timestamp, event.source_ip, event.method, event.path,
                 event.http_version, event.status_code, event.response_bytes,
                 event.referer, event.user_agent, event.vhost,
                 json.dumps(event.attack_types), event.scanner_name,
                 event.severity, event.raw_line, event.service_port)
            )
            event.id = cursor.lastrowid
            await db.commit()

            await self.manager.broadcast("http_event", {
                "id": event.id,
                "timestamp": event.timestamp,
                "source_ip": event.source_ip,
                "method": event.method,
                "path": event.path,
                "status_code": event.status_code,
                "attack_types": event.attack_types,
                "severity": event.severity,
                "scanner_name": event.scanner_name,
                "service_port": event.service_port,
            })

            if self.notifier and event.severity:
                await self.notifier.notify_http_attack(
                    event.source_ip, event.path,
                    event.attack_types, event.severity)

            if _should_enrich(self._seen_ips, event.source_ip) and self.enrichment_queue:
                try:
                    self.enrichment_queue.put_nowait(event.source_ip)
                except asyncio.QueueFull:
                    pass

        except Exception as e:
            logger.error(f"Error storing nginx error event: {e}")


# Parser dispatch table for service logs
_SERVICE_PARSERS = {
    "mysql": parse_mysql_line,
    "postgresql": parse_postgresql_line,
    "mail": parse_mail_line,
    "ftp": parse_ftp_line,
}


class ServiceLogHandler(LogHandler):
    """Generic handler for SQL, mail, and FTP service logs."""

    def __init__(self, file_path: str, loop: asyncio.AbstractEventLoop,
                 manager: ConnectionManager, service_category: str,
                 enrichment_queue: asyncio.Queue | None = None,
                 notifier: Notifier | None = None,
                 service_port: int | None = None,
                 whitelist: list[str] | None = None,
                 portscan_tracker: PortScanTracker | None = None):
        super().__init__(file_path, loop)
        self.manager = manager
        self.service_category = service_category
        self.enrichment_queue = enrichment_queue
        self.notifier = notifier
        self.service_port = service_port
        self.whitelist = whitelist or []
        self.portscan_tracker = portscan_tracker
        self._seen_ips: dict[str, float] = {}
        self._parser = _SERVICE_PARSERS.get(service_category)
        if self._parser is None:
            raise ValueError(f"Unknown service category: {service_category}")

    def _process_line(self, line: str):
        event = self._parser(line)
        if event is None:
            return
        if _is_whitelisted(event.source_ip, self.whitelist):
            return
        event.service_port = self.service_port
        asyncio.run_coroutine_threadsafe(
            self._store_and_broadcast(event), self.loop
        )

    async def _store_and_broadcast(self, event):
        try:
            db = get_db()
            cursor = await db.execute(
                """INSERT INTO service_events
                   (timestamp, service_type, event_type, source_ip, username,
                    detail, severity, service_port, raw_line)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (event.timestamp, event.service_type, event.event_type,
                 event.source_ip, event.username, event.detail,
                 event.severity, event.service_port, event.raw_line)
            )
            event.id = cursor.lastrowid
            await db.commit()

            await self.manager.broadcast("service_event", {
                "id": event.id,
                "timestamp": event.timestamp,
                "service_type": event.service_type,
                "event_type": event.event_type,
                "source_ip": event.source_ip,
                "username": event.username,
                "detail": event.detail,
                "severity": event.severity,
                "service_port": event.service_port,
            })

            # Port scan detection
            if self.portscan_tracker and self.service_port and event.source_ip:
                ps = self.portscan_tracker.track(
                    event.source_ip, self.service_port, event.timestamp)
                if ps:
                    await _store_portscan(ps, self.manager, self.notifier if hasattr(self, 'notifier') else None)

            if event.source_ip and _should_enrich(self._seen_ips, event.source_ip) and self.enrichment_queue:
                try:
                    self.enrichment_queue.put_nowait(event.source_ip)
                except asyncio.QueueFull:
                    pass

        except Exception as e:
            logger.error(f"Error storing service event: {e}")
