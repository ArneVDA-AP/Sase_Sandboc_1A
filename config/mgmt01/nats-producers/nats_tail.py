"""SASE PoC — gedeelde rotation-aware async tail-helper voor de pop01 NATS-producers.
Draait op pop01 (OPNsense/FreeBSD). Hergebruikt door suricata_producer.py,
squid_producer.py en (later) de c-icap-producer.

Gedrag / ontwerpkeuzes:
- Koude start: seek naar EOF (alleen nieuwe regels). Events tijdens een
  producer-herstart worden gemist. Bewuste, gedocumenteerde 3b-beperking
  (operator-geinitieerde, korte gap). Een positie-state-file zou dit dichten;
  buiten 3b-scope.
- Rotation-aware: detecteert zowel rename+create (inode-wijziging, newsyslog)
  als in-place truncatie (copytruncate / ">logfile"). Bij rename trekt de tail
  eerst de staart van het oude handle leeg vooraleer te heropenen, om de race
  tussen onze laatste read en de rename te dichten. Dit elimineert het
  "stil doof na rotatie"-gat van een naieve open-handle-tail.
- Fail-safe: pad weg tijdens de rotatie-gap -> wachten + retry, geen crash.
"""

import asyncio
import os


async def tail_file(filepath, poll_interval=0.5, from_start=False):
    """Async generator: yield nieuwe regels (gestript), rotatie- en
    truncatie-bewust. from_start=True leest het bestaande bestand vanaf regel 1
    (i.p.v. EOF) — handig voor eenmalige tests, niet voor productie."""
    f = None
    inode = None

    def _open(seek_end):
        fh = open(filepath, "r")
        if seek_end:
            fh.seek(0, os.SEEK_END)
        return fh

    try:
        while True:
            if f is None:
                try:
                    f = _open(seek_end=not from_start)
                    inode = os.fstat(f.fileno()).st_ino
                except FileNotFoundError:
                    await asyncio.sleep(poll_interval)
                    continue

            line = f.readline()
            if line:
                yield line.strip()
                continue

            # Geen nieuwe data — slaap, dan rotatie/truncatie checken
            await asyncio.sleep(poll_interval)
            try:
                disk_st = os.stat(filepath)
            except FileNotFoundError:
                # Pad weg tijdens rotatie-gap; oude handle loslaten en opnieuw proberen
                f.close()
                f = None
                continue

            if disk_st.st_ino != inode:
                # rename+create: trek eerst de staart van het oude bestand leeg
                while True:
                    leftover = f.readline()
                    if not leftover:
                        break
                    yield leftover.strip()
                f.close()
                # vers bestand vanaf regel 1 (de eerste regels zijn echte events)
                f = _open(seek_end=False)
                inode = os.fstat(f.fileno()).st_ino
            elif disk_st.st_size < f.tell():
                # in-place truncatie: terug naar begin
                f.seek(0, os.SEEK_SET)
    finally:
        if f is not None:
            f.close()
