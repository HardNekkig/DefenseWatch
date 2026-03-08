import json
import logging
import time
import asyncio
from collections import deque
from fastapi import WebSocket

logger = logging.getLogger(__name__)

_REPLAY_BUFFER_SIZE = 50
_PING_INTERVAL = 30


class ConnectionManager:
    def __init__(self):
        self._connections: list[WebSocket] = []
        self._recent: deque[str] = deque(maxlen=_REPLAY_BUFFER_SIZE)
        self._ping_task: asyncio.Task | None = None

    def start_pinger(self):
        if self._ping_task is None:
            self._ping_task = asyncio.create_task(self._ping_loop())

    async def _ping_loop(self):
        while True:
            await asyncio.sleep(_PING_INTERVAL)
            dead = []
            for ws in self._connections:
                try:
                    await ws.send_json({"type": "ping", "timestamp": time.time()})
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.disconnect(ws)

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)
        # Replay recent events to new client
        for msg in self._recent:
            try:
                await ws.send_text(msg)
            except Exception:
                break
        logger.info(f"WebSocket connected, total: {len(self._connections)}")

    def disconnect(self, ws: WebSocket):
        if ws in self._connections:
            self._connections.remove(ws)
        logger.info(f"WebSocket disconnected, total: {len(self._connections)}")

    async def broadcast(self, msg_type: str, data: dict):
        message = json.dumps({
            "type": msg_type,
            "data": data,
            "timestamp": time.time(),
        })
        self._recent.append(message)
        dead = []
        for ws in self._connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    @property
    def count(self) -> int:
        return len(self._connections)
