"""
NATS core-subscribe op security.alert.> en identity.> — geen JetStream consumers,
geen serverside state, nul footprint op de bestaande stack.
Reconnect-resilient (max_reconnect=-1, 2s backoff), zelfde patroon als V36.
"""
import asyncio
import json
import logging
import time
from typing import Callable, Optional, TYPE_CHECKING

import nats
from nats.aio.client import Client as NATS

from app import config

if TYPE_CHECKING:
    from app.identity import IdentityResolver
    from app.store import Store
    from app.ws import WSManager

log = logging.getLogger("soc.bus")


class Bus:
    def __init__(self) -> None:
        self._nc: Optional[NATS] = None
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    async def start(
        self,
        on_event: Callable,  # async (ev: dict) -> None
    ) -> None:
        async def error_cb(e):
            log.error("NATS fout: %s", e)

        async def disconnected_cb():
            self._connected = False
            log.warning("NATS verbroken; her-verbinden...")

        async def reconnected_cb():
            self._connected = True
            log.info("NATS her-verbonden op %s", self._nc.connected_url.netloc)

        self._nc = await nats.connect(
            servers=[config.NATS_URL],
            user=config.NATS_USER,
            password=config.NATS_PASS,
            max_reconnect_attempts=-1,
            reconnect_time_wait=2,
            error_cb=error_cb,
            disconnected_cb=disconnected_cb,
            reconnected_cb=reconnected_cb,
        )
        self._connected = True
        log.info("NATS verbonden: %s (user=%s)", config.NATS_URL, config.NATS_USER)

        async def _handler(msg):
            try:
                await on_event(msg.subject, msg.data)
            except Exception as exc:  # noqa: BLE001
                log.warning("event-handler fout op %s: %s", msg.subject, exc)

        await self._nc.subscribe(config.SECURITY_SUBJECT, cb=_handler)
        await self._nc.subscribe(config.IDENTITY_SUBJECT, cb=_handler)
        await self._nc.subscribe(config.ACTION_FAILED_SUBJECT, cb=_handler)
        log.info("geabonneerd: %s | %s | %s",
                 config.SECURITY_SUBJECT, config.IDENTITY_SUBJECT,
                 config.ACTION_FAILED_SUBJECT)

    async def stop(self) -> None:
        if self._nc and not self._nc.is_closed:
            await self._nc.drain()
