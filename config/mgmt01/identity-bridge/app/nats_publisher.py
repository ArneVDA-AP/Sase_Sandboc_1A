#!/usr/bin/env python3
"""
SASE PoC — thread-safe NATS JetStream publisher voor de DLP ICAP-server.

De ICAP-server is een threaded blocking server (socketserver.ThreadingMixIn:
per request een thread); nats-py is asyncio. Deze helper overbrugt dat: een
persistente asyncio-loop + NATS-connectie in een achtergrond-thread, en een
non-blocking publish() die de sync request-handlers vanuit hun eigen thread
aanroepen.

Ontwerp-eisen (Addendum J §J.5 + sessie-afspraken):
- Fail-safe: publish() blokkeert de request-handler NOOIT. De 403 valt altijd,
  ook als NATS weg is. Events gaan op een bounded queue; vol = droppen + loggen.
- Herbruikte connectie: een NATS-connectie voor alle request-threads, met
  oneindige reconnect en retry op de initiele connect (NATS hoeft niet al te
  draaien wanneer de DLP-server start).
- Leverbewijs: js.publish met PubAck wordt in de achtergrond afgehandeld
  (gelogd), buiten het request-pad.
"""

import asyncio
import json
import logging
import threading

import nats
from nats.errors import TimeoutError as NatsTimeoutError

logger = logging.getLogger("dlp-icap.nats")


class NatsPublisher:
    def __init__(self, url, user, password, name="dlp-producer",
                 maxsize=1000, publish_timeout=5.0):
        self._url = url
        self._user = user
        self._password = password
        self._name = name
        self._maxsize = maxsize
        self._publish_timeout = publish_timeout
        self._loop = None
        self._queue = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        # Wacht kort zodat de server-start ~synchroon loopt met NATS-readiness,
        # maar blokkeer niet hard: als NATS traag is start de DLP-server toch.
        self._ready.wait(timeout=10)

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._main())
        except Exception as e:
            logger.error(f"[nats] publisher-thread gestopt: {e}")

    async def _main(self):
        self._queue = asyncio.Queue(maxsize=self._maxsize)

        # Retry de initiele connect zonder ooit de DLP-server te blokkeren.
        while True:
            try:
                nc = await nats.connect(
                    self._url, user=self._user, password=self._password,
                    name=self._name,
                    reconnect_time_wait=2, max_reconnect_attempts=-1,
                    error_cb=self._err_cb,
                    disconnected_cb=self._disc_cb,
                    reconnected_cb=self._recon_cb,
                )
                break
            except Exception as e:
                logger.warning(f"[nats] connect mislukt ({e}); retry over 5s")
                await asyncio.sleep(5)

        js = nc.jetstream()
        logger.info(f"[nats] verbonden als {self._user} -> {self._url}")
        self._ready.set()

        while True:
            subject, payload = await self._queue.get()
            try:
                await js.publish(subject, json.dumps(payload).encode(),
                                 timeout=self._publish_timeout)
            except NatsTimeoutError:
                logger.warning(f"[nats] PubAck timeout subj={subject}")
            except Exception as e:
                logger.error(f"[nats] publish-fout subj={subject}: {e}")

    async def _err_cb(self, e):
        logger.error(f"[nats] error: {e}")

    async def _disc_cb(self):
        logger.warning("[nats] disconnected")

    async def _recon_cb(self):
        logger.info("[nats] reconnected")

    def publish(self, subject, payload):
        """Non-blocking. Aanroepbaar vanuit elke (sync) request-thread.
        Events tijdens de connect-retry-window worden gebufferd (tot maxsize)
        en geflushd zodra de connectie staat."""
        loop = self._loop
        if loop is None:
            return
        loop.call_soon_threadsafe(self._enqueue, subject, payload)

    def _enqueue(self, subject, payload):  # draait op de loop-thread
        if self._queue is None:
            return
        try:
            self._queue.put_nowait((subject, payload))
        except asyncio.QueueFull:
            logger.warning("[nats] queue vol — DLP-event gedropt (bus traag/down)")
