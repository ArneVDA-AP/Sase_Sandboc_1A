"""
WebSocket fan-out: één bron (NATS-sub + score-poller) -> alle verbonden browsers.

Dit is precies de capaciteit die Grafana niet had en waarvoor we custom gaan:
echte live push naar elke collega die de pagina open heeft.
"""
import asyncio
import json
import logging
from typing import Any

from starlette.websockets import WebSocket

log = logging.getLogger("soc.ws")


class WSManager:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)
        log.info("ws client verbonden (totaal=%d)", len(self._clients))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)
        log.info("ws client weg (totaal=%d)", len(self._clients))

    async def broadcast(self, msg_type: str, payload: Any) -> None:
        if not self._clients:
            return
        data = json.dumps({"type": msg_type, "data": payload}, default=str)
        dead = []
        async with self._lock:
            targets = list(self._clients)
        for ws in targets:
            try:
                await ws.send_text(data)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._clients.discard(ws)

    @property
    def count(self) -> int:
        return len(self._clients)
