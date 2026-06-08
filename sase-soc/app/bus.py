"""
NATS JetStream subscribe — replay + live.
Geen ordered_consumer (want dat vereist $js.fc.* publish-recht die de
daemon-account niet heeft). In plaats daarvan: expliciet ConsumerConfig
met deliver_policy=ALL + ack_policy=NONE + geen flow control.
"""
import asyncio
import logging
from typing import Callable, Optional

import nats
from nats.aio.client import Client as NATS
from nats.js.api import ConsumerConfig, DeliverPolicy, AckPolicy

from app import config

log = logging.getLogger("soc.bus")

# ConsumerConfig zonder flow_control of idle_heartbeat:
# -> geen $js.fc.* publish nodig -> werkt met daemon-account
_REPLAY_CFG = ConsumerConfig(
    deliver_policy=DeliverPolicy.ALL,
    ack_policy=AckPolicy.NONE,
)


class Bus:
    def __init__(self) -> None:
        self._nc: Optional[NATS] = None
        self._connected = False
        self._live = False
        self._on_replay_done: Optional[Callable] = None

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def live(self) -> bool:
        return self._live

    async def start(self, on_event: Callable,
                    on_replay_done: Optional[Callable] = None) -> None:
        self._on_replay_done = on_replay_done

        async def error_cb(e):
            log.error("NATS fout: %s", e)

        async def disconnected_cb():
            self._connected = False
            log.warning("NATS verbroken; herverbinden...")

        async def reconnected_cb():
            self._connected = True
            log.info("NATS herverbonden op %s", self._nc.connected_url.netloc)

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

        js = self._nc.jetstream()

        async def _sec_handler(msg):
            is_replay = not self._live
            try:
                await on_event(msg.subject, msg.data, is_replay=is_replay)
            except Exception as exc:  # noqa: BLE001
                log.warning("sec-handler fout: %s", exc)
            # Detecteer einde replay via num_pending metadata
            if not self._live:
                try:
                    if msg.metadata.num_pending == 0:
                        self._live = True
                        log.info("=== SECURITY replay klaar — live mode actief ===")
                        if self._on_replay_done:
                            asyncio.create_task(self._on_replay_done())
                except Exception:  # noqa: BLE001
                    pass

        async def _id_handler(msg):
            try:
                await on_event(msg.subject, msg.data, is_replay=False)
            except Exception as exc:  # noqa: BLE001
                log.warning("id-handler fout: %s", exc)

        await js.subscribe(config.SECURITY_SUBJECT, cb=_sec_handler,
                           config=_REPLAY_CFG)
        await js.subscribe(config.IDENTITY_SUBJECT, cb=_id_handler,
                           config=ConsumerConfig(
                               deliver_policy=DeliverPolicy.ALL,
                               ack_policy=AckPolicy.NONE,
                           ))

        log.info("geabonneerd (JetStream, geen flow control): %s | %s",
                 config.SECURITY_SUBJECT, config.IDENTITY_SUBJECT)
        log.info("replay loopt — events worden opgeslagen in SQLite...")

    async def stop(self) -> None:
        if self._nc and not self._nc.is_closed:
            await self._nc.drain()
