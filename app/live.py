"""Live figures: pages that refresh themselves without hitting the switch harder.

A browser that picked an interval (Live, 3 s ... 60 s) asks NXray for a page's
figures again and again (``app/routes/live.py``). NXray does not pass each ask
on to the switch: ``LiveCache`` keeps the newest answer per switch and kind of
figure, and reads the switch again only when that answer is older than the
floor for that kind (``NXRAY_LIVE_MIN_INTERVAL``, and a slower one for the
MAC and ARP tables). Ten browsers cost the switch what one does, and with
nobody watching nothing is read at all: reads happen only on a request, and
an answer nobody asked for in a few minutes is dropped.

Only read-only readers go through it. When the switch fails, the last good
answer is kept and the next read waits longer each time, so a struggling
NX-API is left alone.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

from app.ports import Port

# The choices in the top bar. "live" is as fast as the floor allows.
LIVE_CHOICES = {
    "off": "Off",
    "live": "Live",
    "3": "3 s",
    "5": "5 s",
    "10": "10 s",
    "15": "15 s",
    "30": "30 s",
    "60": "60 s",
}
DEFAULT_CHOICE = "off"

# Kinds of figure, each with its own floor. The name is the cache key's second
# half and the page's ``data-live-kind``.
HEALTH = "health"  # CPU, memory, temperatures, fans, power
PORTS = "ports"  # state, rates, errors
CLIENTS = "clients"  # MAC table, ARP, neighbours

# Seconds an unread answer is kept before it is dropped.
KEEP_UNWATCHED_SECONDS = 300
# The most the wait after failures grows to.
MAX_BACKOFF_SECONDS = 60


@dataclass
class LiveAnswer:
    """What the cache hands a page: the value, when it was read, and how it went."""

    value: Any
    read_at: float
    # Set when the newest attempt failed; ``value`` is then the last good one
    # (or None when there has never been one).
    problem: str = ""
    # Seconds until NXray will ask the switch again after a failure.
    retry_in: int = 0


@dataclass
class _Entry:
    lock: threading.Lock = field(default_factory=threading.Lock)
    value: Any = None
    read_at: float = 0.0
    failures: int = 0
    next_try: float = 0.0
    problem: str = ""
    last_asked: float = 0.0


class LiveCache:
    """The newest answer per (switch id, kind), read from the switch at most once per floor."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._entries: dict[tuple[int, str], _Entry] = {}
        self._guard = threading.Lock()

    def _entry(self, key: tuple[int, str]) -> _Entry:
        now = self._clock()
        with self._guard:
            for old in [
                k for k, e in self._entries.items() if now - e.last_asked > KEEP_UNWATCHED_SECONDS
            ]:
                del self._entries[old]
            entry = self._entries.setdefault(key, _Entry())
            entry.last_asked = now
            return entry

    def get(
        self,
        switch_id: int,
        kind: str,
        floor: int,
        reader: Callable[[Any], tuple[Any, str]],
    ) -> LiveAnswer:
        """The newest answer for this switch and kind.

        ``reader(previous)`` reads the switch and returns (value, problem):
        ``previous`` is the last good value (None the first time), so a reader
        can work out a rate from two readings. A non-empty problem means the
        read failed; the value is then ignored. Only one read per key runs at
        a time; the others wait and share its result.
        """
        entry = self._entry((switch_id, kind))
        with entry.lock:
            now = self._clock()
            waiting_off = now < entry.next_try
            fresh = entry.read_at and now - entry.read_at < floor and not entry.problem
            if not fresh and not waiting_off:
                value, problem = reader(entry.value)
                now = self._clock()
                if problem:
                    entry.failures += 1
                    entry.problem = problem
                    entry.next_try = now + min(MAX_BACKOFF_SECONDS, floor * 2**entry.failures)
                    if entry.read_at == 0.0:
                        entry.read_at = now
                else:
                    entry.value, entry.read_at = value, now
                    entry.failures, entry.problem, entry.next_try = 0, "", 0.0
            retry = max(0, round(entry.next_try - now)) if entry.problem else 0
            return LiveAnswer(entry.value, entry.read_at, entry.problem, retry)

    def clear(self) -> None:
        """Forget every answer (tests, and a switch whose login changed)."""
        with self._guard:
            self._entries.clear()


def pick_interval(choice: str, floor: int) -> int:
    """Seconds between a page's refreshes: the chosen one, never below ``floor``.

    0 for Off or anything unknown; "live" is the floor itself.
    """
    if choice == "live":
        return floor
    if choice in LIVE_CHOICES and choice != "off":
        return max(int(choice), floor)
    return 0


# The longest gap between two readings that still gives a rate worth calling
# live; after a longer pause (nobody was watching) the first reading has none.
MAX_RATE_WINDOW_SECONDS = 120
MIN_RATE_WINDOW_SECONDS = 0.5


@dataclass(frozen=True)
class PortReading:
    """One reading of every port, with the two kinds of rate.

    ``ports`` carries the switch's own figures: In and Out are its average
    over the last 30 seconds. ``live`` is the same ports with In and Out
    worked out from how far the byte counters moved since the reading before,
    over ``window`` seconds (0 when there was no usable earlier reading, and
    then ``live`` is ``ports``).
    """

    ports: list[Port]
    live: list[Port]
    window: float
    at: float


def measure_rates(previous: PortReading | None, ports: list[Port], now: float) -> PortReading:
    """The reading for ``ports`` taken at ``now``, with rates from the change
    since ``previous``. A port that was down before, or whose counters went
    backwards (cleared), keeps the switch's own figure."""
    if previous is None:
        return PortReading(ports, ports, 0.0, now)
    window = now - previous.at
    if not MIN_RATE_WINDOW_SECONDS <= window <= MAX_RATE_WINDOW_SECONDS:
        return PortReading(ports, ports, 0.0, now)
    before = {port.name: port for port in previous.ports}
    live = []
    for port in ports:
        old = before.get(port.name)
        if (
            old is not None
            and old.up
            and port.up
            and port.in_bytes >= old.in_bytes
            and port.out_bytes >= old.out_bytes
        ):
            live.append(
                replace(
                    port,
                    in_bits_per_second=round((port.in_bytes - old.in_bytes) * 8 / window),
                    out_bits_per_second=round((port.out_bytes - old.out_bytes) * 8 / window),
                )
            )
        else:
            live.append(port)
    return PortReading(ports, live, window, now)
