"""History: sampling the switch once a minute, and drawing what was recorded.

A background thread asks the switch for temperatures, power, fans, CPU,
memory and every port's traffic and errors, and stores the numbers in the
``history`` table. Rows older than ``KEEP_DAYS`` are deleted. The pages read
only that table; opening them costs the switch nothing.

The three show commands per sample are the ones the dashboard already runs
on every page load.
"""

from __future__ import annotations

import logging
import math
import sqlite3
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import httpx

from app.charts import SERIES_COLOURS, Line, Point, line_chart
from app.config import Settings
from app.db import open_db
from app.nxapi import NxapiClient
from app.ports import Port, human_rate, parse_ports
from app.switch import Environment, Resources, parse_environment, parse_resources
from app.switch_connection import DecryptionError, get_connection, load_target
from app.switch_setup import KEY_CHANGED_MESSAGE, read_switch

log = logging.getLogger("nxray.history")

KEEP_DAYS = 30
HISTORY_COMMANDS = ("show environment", "show system resources", "show interface")

# What is stored. A row is (metric, item, value); item names the sensor or
# port and is empty for whole-switch numbers.
TEMPERATURE = "temperature"  # item: sensor name, degrees C
CPU = "cpu"  # percent
MEMORY = "memory"  # percent
POWER = "power"  # watts drawn in total
FAN = "fan"  # fan speed, percent
TRAFFIC_IN = "traffic_in"  # bits per second, all ports together
TRAFFIC_OUT = "traffic_out"
PORT_IN = "port_in"  # item: port name, bits per second; only while the port is up
PORT_OUT = "port_out"
PORT_ERRORS = "port_errors"  # item: port name, errors since the previous sample; only when above 0

Row = tuple[str, str, float]

# Chart ranges, by the name used in ?range=.
RANGES = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
RANGE_LABELS = {
    "1h": "1 hour",
    "6h": "6 hours",
    "24h": "24 hours",
    "7d": "7 days",
    "30d": "30 days",
}
DEFAULT_RANGE = "24h"
# One chart point is never narrower than a sample, and a chart never has more
# than this many, so 30 days of rows are averaged into buckets.
MIN_BUCKET_SECONDS = 60
MAX_POINTS = 500
_PURGE_EVERY_SECONDS = 3600


def _read(client: NxapiClient) -> tuple[Environment, Resources, list[Port]]:
    environment, resources, interfaces = client.show(*HISTORY_COMMANDS)
    return (
        parse_environment(environment),
        parse_resources(resources),
        parse_ports(interfaces, {}, {}),
    )


def build_rows(
    environment: Environment,
    resources: Resources,
    ports: Sequence[Port],
    previous_errors: dict[str, int],
) -> tuple[list[Row], dict[str, int]]:
    """The rows one sample stores, and each port's error total for the next sample.

    A port's errors are stored as the increase since the previous sample, and
    only when there was one. With no earlier total (the first sample after
    NXray starts) or a total that went down (the counters were cleared) there
    is nothing honest to store.
    """
    rows: list[Row] = []
    for sensor in environment.temperatures:
        if sensor.current_c is not None:
            rows.append((TEMPERATURE, sensor.name, float(sensor.current_c)))
    if resources.cpu_used_percent is not None:
        rows.append((CPU, "", resources.cpu_used_percent))
    if resources.memory_used_percent is not None:
        rows.append((MEMORY, "", resources.memory_used_percent))
    if environment.total_draw_w is not None:
        rows.append((POWER, "", float(environment.total_draw_w)))
    if environment.fan_speed_percent is not None:
        rows.append((FAN, "", float(environment.fan_speed_percent)))
    rows.append((TRAFFIC_IN, "", float(sum(port.in_bits_per_second for port in ports))))
    rows.append((TRAFFIC_OUT, "", float(sum(port.out_bits_per_second for port in ports))))

    errors = {port.name: port.errors for port in ports}
    for port in ports:
        if port.up:
            rows.append((PORT_IN, port.name, float(port.in_bits_per_second)))
            rows.append((PORT_OUT, port.name, float(port.out_bits_per_second)))
        before = previous_errors.get(port.name)
        if before is not None and port.errors > before:
            rows.append((PORT_ERRORS, port.name, float(port.errors - before)))
    return rows, errors


def record(conn: sqlite3.Connection, moment: float, rows: Sequence[Row]) -> None:
    """Store one sample's rows."""
    conn.executemany(
        "INSERT INTO history (ts, metric, item, value) VALUES (?, ?, ?, ?)",
        [(moment, metric, item, value) for metric, item, value in rows],
    )
    conn.commit()


def purge(conn: sqlite3.Connection, now: float, keep_days: int = KEEP_DAYS) -> int:
    """Delete rows older than ``keep_days``. Returns how many went."""
    cursor = conn.execute("DELETE FROM history WHERE ts < ?", (now - keep_days * 86400,))
    conn.commit()
    return cursor.rowcount


def last_sample_time(conn: sqlite3.Connection) -> float | None:
    """When the newest row was stored, or None when nothing has been."""
    return conn.execute("SELECT MAX(ts) FROM history").fetchone()[0]


class Sampler:
    """Takes samples. Remembers each port's error total between them."""

    def __init__(
        self,
        settings: Settings,
        transport: Callable[[], httpx.BaseTransport | None] = lambda: None,
    ) -> None:
        self._settings = settings
        self._transport = transport
        self._errors: dict[str, int] = {}

    def sample_once(self, now: float | None = None) -> str | None:
        """Read the switch and store one sample.

        None when it was stored, and also when there was nothing to do (no
        switch set up, or NXray is leaving the switch alone while it applies
        a new role). Otherwise the reason it failed, in words.
        """
        moment = time.time() if now is None else now
        with open_db(self._settings.db_path) as conn:
            connection = get_connection(conn)
            if connection is None or connection.paused_seconds(moment):
                return None
            try:
                target = load_target(conn, self._settings.secret_key)
            except DecryptionError:
                return KEY_CHANGED_MESSAGE
        # Outside the database block: the switch can take seconds to answer.
        status, data = read_switch(target, _read, self._transport())
        if data is None:
            return status.message
        rows, self._errors = build_rows(*data, self._errors)
        with open_db(self._settings.db_path) as conn:
            record(conn, moment, rows)
        return None


def start_sampler(
    settings: Settings, transport: Callable[[], httpx.BaseTransport | None]
) -> threading.Event | None:
    """Sample on its own thread until the returned event is set.

    None when ``NXRAY_HISTORY_INTERVAL`` is 0 and history is off. A failure is
    logged when it starts and when it ends, not every minute.
    """
    interval = settings.history_interval
    if not interval:
        return None
    stop = threading.Event()
    sampler = Sampler(settings, transport)

    def _loop() -> None:
        problem: str | None = None
        last_purge = 0.0
        while not stop.is_set():
            began = time.monotonic()
            try:
                failed = sampler.sample_once()
                if time.time() - last_purge >= _PURGE_EVERY_SECONDS:
                    with open_db(settings.db_path) as conn:
                        removed = purge(conn, time.time())
                    last_purge = time.time()
                    if removed:
                        log.info("deleted %d history rows older than %d days", removed, KEEP_DAYS)
            except Exception:
                log.exception("history sample failed")
                failed = "unexpected error, see the log"
            if failed != problem:
                if failed:
                    log.warning("history is not being recorded: %s", failed)
                else:
                    log.info("history is being recorded again")
                problem = failed
            stop.wait(max(0.0, interval - (time.monotonic() - began)))

    threading.Thread(target=_loop, daemon=True, name="history").start()
    return stop


# ---- reading it back ----


def range_key(value: str | None) -> str:
    """A valid ?range= value; the default for anything else."""
    return value if value in RANGES else DEFAULT_RANGE


def bucket_seconds(span: int) -> int:
    """How wide one chart point is for a chart covering ``span`` seconds."""
    return max(MIN_BUCKET_SECONDS, math.ceil(span / MAX_POINTS))


def read_series(
    conn: sqlite3.Connection,
    metric: str,
    *,
    start: float,
    end: float,
    bucket: int,
    item: str | None = None,
    total: bool = False,
) -> dict[str, list[Point]]:
    """A metric's rows averaged into buckets, by item: {item: [(time, value)]}.

    ``total`` adds the rows of each bucket up instead (for counts such as
    errors). Each point sits in the middle of its bucket.
    """
    function = "SUM" if total else "AVG"  # chosen here, never from the request
    sql = (
        f"SELECT item, CAST((ts - ?) / ? AS INTEGER) AS slot, {function}(value) AS value "
        "FROM history WHERE metric = ? AND ts >= ? AND ts < ?"
    )
    args: list[object] = [start, bucket, metric, start, end]
    if item is not None:
        sql += " AND item = ?"
        args.append(item)
    sql += " GROUP BY item, slot ORDER BY item, slot"
    series: dict[str, list[Point]] = {}
    for row in conn.execute(sql, args):
        series.setdefault(row["item"], []).append(
            (start + (row["slot"] + 0.5) * bucket, row["value"])
        )
    return series


def fill_zeros(points: Sequence[Point], start: float, end: float, bucket: int) -> list[Point]:
    """Every bucket of start..end, with 0 where ``points`` has none."""
    present = {int((moment - start) // bucket): value for moment, value in points}
    slots = math.ceil((end - start) / bucket)
    return [(start + (slot + 0.5) * bucket, present.get(slot, 0.0)) for slot in range(slots)]


@dataclass(frozen=True)
class LegendEntry:
    label: str
    colour: int
    summary: str


@dataclass(frozen=True)
class ChartView:
    """What a template needs to show one chart. ``svg`` is None when there is no data."""

    title: str
    svg: object | None
    legend: list[LegendEntry]
    # Shown under a chart that has data / in place of one that has none.
    note: str = ""
    empty: str = "No data in this range yet."


def _latest_and_highest(fmt: Callable[[float], str]) -> Callable[[Sequence[Point]], str]:
    def _summary(points: Sequence[Point]) -> str:
        return f"now {fmt(points[-1][1])}, highest {fmt(max(value for _, value in points))}"

    return _summary


def _chart(
    title: str,
    lines: list[Line],
    *,
    start: float,
    end: float,
    bucket: int,
    fmt: Callable[[float], str],
    summarize: Callable[[Sequence[Point]], str] | None = None,
    note: str = "",
    empty: str = "No data in this range yet.",
    zero_based: bool = True,
    y_max: float | None = None,
) -> ChartView:
    lines = [line for line in lines if line.points]
    if not lines:
        return ChartView(title, None, [], note, empty)
    summarize = summarize or _latest_and_highest(fmt)
    svg = line_chart(
        lines,
        start=start,
        end=end,
        bucket=bucket,
        fmt=fmt,
        zero_based=zero_based,
        y_max=y_max,
        label=title,
    )
    legend = [
        LegendEntry(line.label, number % SERIES_COLOURS, summarize(line.points))
        for number, line in enumerate(lines)
    ]
    return ChartView(title, svg, legend, note, empty)


def _short(value: float) -> str:
    """At most one decimal: 45.5591 -> "45.6", 150.0 -> "150"."""
    return f"{round(value, 1):g}"


def _degrees(value: float) -> str:
    return f"{_short(value)}°C"


def _percent(value: float) -> str:
    return f"{_short(value)}%"


def _watts(value: float) -> str:
    return f"{_short(value)} W"


def _rate(value: float) -> str:
    """ "500.0 Mb/s" -> "500 Mb/s"."""
    return human_rate(int(value)).replace(".0 ", " ")


def _count(value: float) -> str:
    return f"{value:g}"


def system_charts(conn: sqlite3.Connection, key: str, now: float) -> list[ChartView]:
    """The History page's charts for the range named ``key``."""
    span = RANGES[key]
    start, end, bucket = now - span, now, bucket_seconds(span)

    def read(metric: str) -> dict[str, list[Point]]:
        return read_series(conn, metric, start=start, end=end, bucket=bucket)

    def one(metric: str, label: str) -> Line:
        return Line(label, read(metric).get("", []))

    temperatures = read(TEMPERATURE)
    common = {"start": start, "end": end, "bucket": bucket}
    return [
        _chart(
            "Temperatures",
            [Line(name, points) for name, points in sorted(temperatures.items())],
            fmt=_degrees,
            zero_based=False,
            **common,
        ),
        _chart(
            "CPU and memory",
            [one(CPU, "CPU"), one(MEMORY, "Memory")],
            fmt=_percent,
            y_max=100,
            **common,
        ),
        _chart("Power draw", [one(POWER, "Total draw")], fmt=_watts, **common),
        _chart("Fan speed", [one(FAN, "Fans")], fmt=_percent, y_max=100, **common),
        _chart(
            "Traffic through all ports",
            [one(TRAFFIC_IN, "In"), one(TRAFFIC_OUT, "Out")],
            fmt=_rate,
            **common,
        ),
    ]


def port_charts(conn: sqlite3.Connection, port: str, key: str, now: float) -> list[ChartView]:
    """One port's traffic and errors for the range named ``key``."""
    span = RANGES[key]
    start, end, bucket = now - span, now, bucket_seconds(span)
    common = {"start": start, "end": end, "bucket": bucket}

    def read(metric: str, *, total: bool = False) -> list[Point]:
        found = read_series(
            conn, metric, start=start, end=end, bucket=bucket, item=port, total=total
        )
        return found.get(port, [])

    errors = read(PORT_ERRORS, total=True)
    seen = bool(errors)
    return [
        _chart(
            "Traffic over time",
            [Line("In", read(PORT_IN)), Line("Out", read(PORT_OUT))],
            fmt=_rate,
            note="A gap means the port was down, or NXray could not reach the switch.",
            **common,
        ),
        _chart(
            "Errors and discards over time",
            [Line("Errors", fill_zeros(errors, start, end, bucket))] if seen else [],
            fmt=_count,
            summarize=lambda points: f"{_count(sum(value for _, value in points))} in this range",
            empty="No errors were recorded for this port in this range.",
            **common,
        ),
    ]
