import time
import logging
import httpx
from defensewatch.config import NotificationConfig
from defensewatch.telegram import TelegramNotifier

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


class Notifier:
    def __init__(self, config: NotificationConfig, telegram: TelegramNotifier | None = None):
        self.config = config
        self.telegram = telegram
        self._cooldowns: dict[str, float] = {}
        self._min_level = SEVERITY_ORDER.get(config.min_severity, 3)

    def _check_cooldown(self, key: str) -> bool:
        now = time.time()
        last = self._cooldowns.get(key, 0)
        if now - last < self.config.cooldown_seconds:
            return False
        self._cooldowns[key] = now
        return True

    async def notify_brute_force(self, source_ip: str, attempt_count: int,
                                 usernames: list[str]):
        if not self.config.enabled or not self.config.webhook_url:
            # Still try telegram even if webhook is disabled
            if self.telegram:
                await self.telegram.notify_brute_force(source_ip, attempt_count, usernames)
            return
        if "brute_force" not in self.config.notify_events:
            if self.telegram:
                await self.telegram.notify_brute_force(source_ip, attempt_count, usernames)
            return
        if self._min_level > SEVERITY_ORDER['high']:
            return
        if not self._check_cooldown(f"brute:{source_ip}"):
            return

        payload = {
            "text": (
                f":rotating_light: *SSH Brute Force Detected*\n"
                f"IP: `{source_ip}`\n"
                f"Attempts: {attempt_count}\n"
                f"Usernames: {', '.join(usernames[:10])}"
            ),
            "event_type": "brute_force",
            "source_ip": source_ip,
            "attempt_count": attempt_count,
            "severity": "high",
        }
        await self._send(payload)
        if self.telegram:
            await self.telegram.notify_brute_force(source_ip, attempt_count, usernames)

    async def notify_http_attack(self, source_ip: str, path: str,
                                 attack_types: list[str], severity: str):
        if not self.config.enabled or not self.config.webhook_url:
            if self.telegram:
                await self.telegram.notify_http_attack(source_ip, path, attack_types, severity)
            return
        if "http_attack" not in self.config.notify_events:
            if self.telegram:
                await self.telegram.notify_http_attack(source_ip, path, attack_types, severity)
            return
        level = SEVERITY_ORDER.get(severity, 0)
        if level < self._min_level:
            return
        if not self._check_cooldown(f"http:{source_ip}:{severity}"):
            return

        payload = {
            "text": (
                f":warning: *HTTP Attack — {severity.upper()}*\n"
                f"IP: `{source_ip}`\n"
                f"Path: `{path}`\n"
                f"Types: {', '.join(attack_types)}"
            ),
            "event_type": "http_attack",
            "source_ip": source_ip,
            "attack_types": attack_types,
            "severity": severity,
        }
        await self._send(payload)
        if self.telegram:
            await self.telegram.notify_http_attack(source_ip, path, attack_types, severity)

    async def notify_port_scan(self, source_ip: str, ports_hit: list[int],
                              port_count: int):
        # Always forward to telegram
        if self.telegram:
            await self.telegram.notify_port_scan(source_ip, ports_hit, port_count)
        if not self.config.enabled or not self.config.webhook_url:
            return
        if "port_scan" not in self.config.notify_events:
            return
        if not self._check_cooldown(f"portscan:{source_ip}"):
            return

        payload = {
            "text": (
                f":mag: *Port Scan Detected*\n"
                f"IP: `{source_ip}`\n"
                f"Ports: {port_count} ({', '.join(str(p) for p in ports_hit[:15])})"
            ),
            "event_type": "port_scan",
            "source_ip": source_ip,
            "ports_hit": ports_hit,
            "port_count": port_count,
            "severity": "medium",
        }
        await self._send(payload)

    async def _send(self, payload: dict):
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self.config.webhook_url, json=payload)
                if resp.status_code >= 400:
                    logger.warning(f"Webhook returned {resp.status_code}")
        except Exception as e:
            logger.error(f"Webhook notification failed: {e}")
