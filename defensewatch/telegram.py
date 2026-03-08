import time
import logging
import httpx
from defensewatch.config import TelegramConfig

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

SEVERITY_EMOJI = {
    'critical': '\U0001f6a8',  # rotating light
    'high': '\u26a0\ufe0f',     # warning
    'medium': '\U0001f536',     # large orange diamond
    'low': '\U0001f539',        # small blue diamond
}


class TelegramNotifier:
    BASE_URL = "https://api.telegram.org/bot{token}"

    def __init__(self, config: TelegramConfig):
        self.config = config
        self._cooldowns: dict[str, float] = {}
        self._min_level = SEVERITY_ORDER.get(config.min_severity, 3)

    @property
    def is_configured(self) -> bool:
        return bool(self.config.enabled and self.config.bot_token and self.config.chat_ids)

    def _check_cooldown(self, key: str) -> bool:
        now = time.time()
        last = self._cooldowns.get(key, 0)
        if now - last < self.config.cooldown_seconds:
            return False
        self._cooldowns[key] = now
        return True

    async def notify_brute_force(self, source_ip: str, attempt_count: int,
                                 usernames: list[str]):
        if not self.is_configured:
            return
        if "brute_force" not in self.config.notify_events:
            return
        if self._min_level > SEVERITY_ORDER['high']:
            return
        if not self._check_cooldown(f"tg:brute:{source_ip}"):
            return

        text = (
            f"\U0001f6a8 <b>SSH Brute Force Detected</b>\n\n"
            f"\U0001f310 IP: <code>{source_ip}</code>\n"
            f"\U0001f4ca Attempts: <b>{attempt_count}</b>\n"
            f"\U0001f464 Usernames: <code>{', '.join(usernames[:10])}</code>\n"
            f"\u23f0 {time.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        await self._send_to_all(text)

    async def notify_http_attack(self, source_ip: str, path: str,
                                 attack_types: list[str], severity: str):
        if not self.is_configured:
            return
        if "http_attack" not in self.config.notify_events:
            return
        level = SEVERITY_ORDER.get(severity, 0)
        if level < self._min_level:
            return
        if not self._check_cooldown(f"tg:http:{source_ip}:{severity}"):
            return

        emoji = SEVERITY_EMOJI.get(severity, '\u26a0\ufe0f')
        text = (
            f"{emoji} <b>HTTP Attack \u2014 {severity.upper()}</b>\n\n"
            f"\U0001f310 IP: <code>{source_ip}</code>\n"
            f"\U0001f4c1 Path: <code>{_escape_html(path)}</code>\n"
            f"\U0001f3af Types: {', '.join(attack_types)}\n"
            f"\u23f0 {time.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        await self._send_to_all(text)

    async def notify_anomaly(self, anomaly: dict):
        if not self.is_configured:
            return
        if "anomaly" not in self.config.notify_events:
            return
        severity = anomaly.get('severity', 'high')
        level = SEVERITY_ORDER.get(severity, 0)
        if level < self._min_level:
            return
        if not self._check_cooldown(f"tg:anomaly:{anomaly.get('metric', '')}"):
            return

        emoji = SEVERITY_EMOJI.get(severity, '\u26a0\ufe0f')
        text = (
            f"{emoji} <b>Anomaly Detected \u2014 {severity.upper()}</b>\n\n"
            f"\U0001f4ca Metric: {anomaly.get('metric', 'unknown')}\n"
            f"\U0001f4c8 Value: {anomaly.get('current_value', '?')} "
            f"(baseline: {anomaly.get('baseline_mean', '?')})\n"
            f"\U0001f4ac {anomaly.get('message', '')}\n"
            f"\u23f0 {time.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        await self._send_to_all(text)

    async def notify_port_scan(self, source_ip: str, ports_hit: list[int],
                              port_count: int):
        if not self.is_configured:
            return
        if "port_scan" not in self.config.notify_events:
            return
        if self._min_level > SEVERITY_ORDER['medium']:
            return
        if not self._check_cooldown(f"tg:portscan:{source_ip}"):
            return

        text = (
            f"\U0001f50d <b>Port Scan Detected</b>\n\n"
            f"\U0001f310 IP: <code>{source_ip}</code>\n"
            f"\U0001f4ca Ports: <b>{port_count}</b> ({', '.join(str(p) for p in ports_hit[:15])})\n"
            f"\u23f0 {time.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        await self._send_to_all(text)

    async def notify_firewall_block(self, block_data: dict):
        if not self.is_configured:
            return
        if "firewall_block" not in self.config.notify_events:
            return
        if not self._check_cooldown(f"tg:block:{block_data.get('ip', '')}"):
            return

        text = (
            f"\U0001f6e1\ufe0f <b>IP Auto-Blocked</b>\n\n"
            f"\U0001f310 IP: <code>{block_data.get('ip', '?')}</code>\n"
            f"\U0001f4ac Reason: {_escape_html(block_data.get('reason', '-'))}\n"
            f"\u23f0 {time.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        await self._send_to_all(text)

    async def send_report(self, report: dict) -> dict:
        if not self.config.bot_token or not self.config.chat_ids:
            return {"ok": False, "error": "Bot token or chat IDs not configured"}

        period_start = time.strftime('%Y-%m-%d %H:%M', time.localtime(report['period_start']))
        period_end = time.strftime('%Y-%m-%d %H:%M', time.localtime(report['period_end']))

        lines = [
            f"\U0001f4cb <b>DefenseWatch Report</b>",
            f"\U0001f4c5 {period_start} \u2014 {period_end}",
            "",
            f"\U0001f5a5 SSH events: <b>{report['ssh']['total']}</b>",
            f"\U0001f310 HTTP attacks: <b>{report['http']['total']}</b>",
            f"\U0001f510 Brute force sessions: <b>{report['brute_force_sessions']}</b>",
            f"\U0001f465 Unique attacking IPs: <b>{report['unique_attacking_ips']}</b>",
            f"\U0001f4c2 Active incidents: <b>{report['active_incidents']}</b>",
            f"\u26a0\ufe0f Anomalies: <b>{report['anomalies_detected']}</b>",
        ]

        # Top attackers
        top = report.get('top_attackers', [])[:5]
        if top:
            lines.append("")
            lines.append("<b>Top Attackers:</b>")
            for i, a in enumerate(top, 1):
                country = a.get('country') or '??'
                org = a.get('org') or 'unknown'
                lines.append(
                    f"  {i}. <code>{a['ip']}</code> \u2014 {a['event_count']} events "
                    f"({country}, {_escape_html(org)})"
                )

        # SSH breakdown
        ssh_types = report.get('ssh', {}).get('by_type', {})
        if ssh_types:
            lines.append("")
            lines.append("<b>SSH Breakdown:</b>")
            for t, c in sorted(ssh_types.items(), key=lambda x: -x[1]):
                lines.append(f"  \u2022 {t}: {c}")

        # HTTP severity breakdown
        http_sev = report.get('http', {}).get('by_severity', {})
        if http_sev:
            lines.append("")
            lines.append("<b>HTTP by Severity:</b>")
            for s, c in sorted(http_sev.items(), key=lambda x: -SEVERITY_ORDER.get(x[0], 0)):
                emoji = SEVERITY_EMOJI.get(s, '')
                lines.append(f"  {emoji} {s}: {c}")

        results = await self._send_to_all("\n".join(lines))
        if all(r.get("ok") for r in results):
            return {"ok": True, "message": f"Report sent to {len(results)} chat(s)"}
        errors = [r.get("error", "unknown") for r in results if not r.get("ok")]
        return {"ok": False, "error": "; ".join(errors)}

    async def send_test_message(self) -> dict:
        if not self.config.bot_token or not self.config.chat_ids:
            return {"ok": False, "error": "Bot token or chat IDs not configured"}

        text = (
            f"\u2705 <b>DefenseWatch Telegram Test</b>\n\n"
            f"Connection successful!\n"
            f"\u23f0 {time.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        results = await self._send_to_all(text)
        if all(r.get("ok") for r in results):
            return {"ok": True, "message": f"Test message sent to {len(results)} chat(s)"}
        errors = [r.get("error", "unknown") for r in results if not r.get("ok")]
        return {"ok": False, "error": "; ".join(errors)}

    async def get_bot_info(self) -> dict:
        if not self.config.bot_token:
            return {"ok": False, "error": "Bot token not configured"}
        try:
            url = f"{self.BASE_URL.format(token=self.config.bot_token)}/getMe"
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url)
                data = resp.json()
                if data.get("ok"):
                    bot = data["result"]
                    return {"ok": True, "username": bot.get("username"), "name": bot.get("first_name")}
                return {"ok": False, "error": data.get("description", "API error")}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    async def _send_to_all(self, text: str) -> list[dict]:
        results = []
        for chat_id in self.config.chat_ids:
            result = await self._send_message(chat_id, text)
            results.append(result)
        return results

    async def _send_message(self, chat_id: str, text: str) -> dict:
        url = f"{self.BASE_URL.format(token=self.config.bot_token)}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(url, json=payload)
                data = resp.json()
                if not data.get("ok"):
                    logger.warning(f"Telegram send failed for chat {chat_id}: {data.get('description')}")
                    return {"ok": False, "error": data.get("description", "API error")}
                return {"ok": True}
        except Exception as e:
            logger.error(f"Telegram notification failed for chat {chat_id}: {e}")
            return {"ok": False, "error": str(e)}


def _escape_html(text: str) -> str:
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))
