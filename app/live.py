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

Each entry also keeps a short trail: a few figures from every fresh reading of
the last ``TRAIL_SECONDS``, in memory only, so a page can draw a small chart
of the last few minutes without writing every reading to the database. The
trail goes with its entry when nobody has asked for it for a few minutes, and
with NXray's restart; the stored history (app/history.py) is separate.
"""

from __future__ import annotations

import statistics
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from app.charts import Line
from app.history import ChartView, chart_view, percent_text, rate_text
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
# How far back each entry's trail of figures reaches, for the live charts.
TRAIL_SECONDS = 600


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
    # (read at, figures) of each fresh reading in the last TRAIL_SECONDS, oldest first.
    trail: tuple[tuple[float, Any], ...] = ()


@dataclass
class _Entry:
    lock: threading.Lock = field(default_factory=threading.Lock)
    value: Any = None
    read_at: float = 0.0
    failures: int = 0
    next_try: float = 0.0
    problem: str = ""
    last_asked: float = 0.0
    trail: deque[tuple[float, Any]] = field(default_factory=deque)


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
        figures: Callable[[Any], Any] | None = None,
    ) -> LiveAnswer:
        """The newest answer for this switch and kind.

        ``reader(previous)`` reads the switch and returns (value, problem):
        ``previous`` is the last good value (None the first time), so a reader
        can work out a rate from two readings. A non-empty problem means the
        read failed; the value is then ignored. Only one read per key runs at
        a time; the others wait and share its result.

        ``figures(value)``, when given, picks what the trail keeps of each
        fresh reading (a few numbers, not the whole reading).
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
                    if figures is not None:
                        entry.trail.append((now, figures(value)))
                while entry.trail and entry.trail[0][0] < now - TRAIL_SECONDS:
                    entry.trail.popleft()
            retry = max(0, round(entry.next_try - now)) if entry.problem else 0
            return LiveAnswer(entry.value, entry.read_at, entry.problem, retry, tuple(entry.trail))

    def trail(self, switch_id: int, kind: str) -> tuple[tuple[float, Any], ...]:
        """The trail kept for this switch and kind, without reading the switch
        and without counting as someone watching; () when there is none."""
        now = self._clock()
        with self._guard:
            entry = self._entries.get((switch_id, kind))
            if entry is None or now - entry.last_asked > KEEP_UNWATCHED_SECONDS:
                return ()
            return tuple(item for item in entry.trail if item[0] >= now - TRAIL_SECONDS)

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


# ---- the trail: figures of the last few minutes ----------------------------------


@dataclass(frozen=True)
class PortFigures:
    """What the trail keeps of one port per reading: its In and Out as the
    switch averages them, and as measured from the byte counters (None when
    that reading had no earlier one to measure from)."""

    up: bool
    in_average: int
    out_average: int
    in_measured: int | None = None
    out_measured: int | None = None


def port_figures(reading: PortReading) -> dict[str, PortFigures]:
    """Each port's figures from one reading, for the trail."""
    measured = {port.name: port for port in reading.live} if reading.window > 0 else {}
    found = {}
    for port in reading.ports:
        live = measured.get(port.name)
        found[port.name] = PortFigures(
            up=port.up,
            in_average=port.in_bits_per_second,
            out_average=port.out_bits_per_second,
            in_measured=live.in_bits_per_second if live is not None else None,
            out_measured=live.out_bits_per_second if live is not None else None,
        )
    return found


def trail_spacing(trail: Sequence[tuple[float, Any]], floor: int) -> float:
    """The usual gap between two readings of a trail, in seconds: the chart
    breaks its line where a gap is much longer (nobody was watching, or the
    switch did not answer). ``floor`` when there are too few readings."""
    gaps = [later[0] - earlier[0] for earlier, later in zip(trail, trail[1:], strict=False)]
    return max(float(floor), statistics.median(gaps)) if gaps else float(floor)


TRAIL_EMPTY = (
    "Nothing to draw yet. NXray keeps the last {minutes} minutes in memory only while a "
    "page with a refresh on is open for this switch: choose Live or an interval in the "
    "top bar, and this chart fills in as the figures come."
)


def _trail_minutes() -> int:
    return TRAIL_SECONDS // 60


def port_trail_chart(
    trail: Sequence[tuple[float, Any]], name: str, *, measured: bool, now: float, floor: int
) -> ChartView:
    """One port's In and Out over the last few minutes, from the trail.

    ``measured`` draws the rates measured from the byte counters (Live);
    otherwise the switch's own averages. A reading where the port was down,
    or (measured) had nothing to measure from, leaves a gap.
    """
    in_points, out_points = [], []
    for moment, figures in trail:
        port = figures.get(name) if isinstance(figures, dict) else None
        if port is None or not port.up:
            continue
        if measured:
            if port.in_measured is None or port.out_measured is None:
                continue
            in_points.append((moment, float(port.in_measured)))
            out_points.append((moment, float(port.out_measured)))
        else:
            in_points.append((moment, float(port.in_average)))
            out_points.append((moment, float(port.out_average)))
    kind = (
        "measured from the byte counters between readings"
        if measured
        else "as the switch averages them"
    )
    return chart_view(
        f"Last {_trail_minutes()} minutes",
        [Line("In", in_points), Line("Out", out_points)],
        start=now - TRAIL_SECONDS,
        end=now,
        bucket=trail_spacing(trail, floor),
        fmt=rate_text,
        note=(
            f"In and Out {kind}, at each reading of the live refresh. Kept in memory only, "
            "not in the history: a gap means nobody was watching, the port was down or the "
            "switch did not answer. Times are UTC."
        ),
        empty=TRAIL_EMPTY.format(minutes=_trail_minutes()),
        anchor="live-trail",
    )


def health_figures(value: Any) -> tuple[float | None, float | None]:
    """What the trail keeps of a dashboard reading, (status, Dashboard): the
    CPU and memory in use, in percent (None for one the switch did not give)."""
    data = value[1] if isinstance(value, tuple) and len(value) == 2 else None
    resources = getattr(data, "resources", None)
    if resources is None:
        return None, None
    return resources.cpu_used_percent, resources.memory_used_percent


def health_trail_chart(trail: Sequence[tuple[float, Any]], *, now: float, floor: int) -> ChartView:
    """The switch's CPU and memory over the last few minutes, from the trail
    of (cpu percent, memory percent) pairs; a figure the switch did not give
    leaves a gap."""
    cpu, memory = [], []
    for moment, figures in trail:
        if not isinstance(figures, tuple) or len(figures) != 2:
            continue
        if figures[0] is not None:
            cpu.append((moment, float(figures[0])))
        if figures[1] is not None:
            memory.append((moment, float(figures[1])))
    return chart_view(
        f"CPU and memory, last {_trail_minutes()} minutes",
        [Line("CPU", cpu), Line("Memory", memory)],
        start=now - TRAIL_SECONDS,
        end=now,
        bucket=trail_spacing(trail, floor),
        fmt=percent_text,
        y_max=100,
        note=(
            "At each reading of the live refresh. Kept in memory only, not in the history; "
            "the History page has the last 30 days. Times are UTC."
        ),
        empty=TRAIL_EMPTY.format(minutes=_trail_minutes()),
        anchor="live-trail",
    )
