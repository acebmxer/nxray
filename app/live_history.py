"""The History page's Live window: its charts drawn from the live trails.

The last 40 minutes at the pace of the live refresh (every few seconds) instead
of the sampler's one minute. The newest part is what the live cache's trails
hold (``app/live.py``: the dashboard reading's CPU, memory, power, fans and
temperatures, and the port reading's measured In and Out); the part before the
trail begins (NXray was just started, or nobody had the page open) is the
stored samples, so a chart is never empty while the history has the minutes.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from typing import Any

from app.charts import Line, Point
from app.history import (
    CPU,
    FAN,
    LIVE_SPAN,
    MEMORY,
    POWER,
    TEMPERATURE,
    TRAFFIC_IN,
    TRAFFIC_OUT,
    VLAN_IN,
    VLAN_OUT,
    ChartView,
    chart_view,
    degrees_text,
    percent_text,
    rate_text,
    read_series,
    stitch,
    vlan_chart_views,
    watts_text,
)
from app.live import HealthFigures, PortFigures

Trail = Sequence[tuple[float, Any]]

# The stored samples are a minute apart; the chart breaks its line where two
# points are further apart than a few of these.
STORED_BUCKET = 60


def _health_points(trail: Trail, pick: Callable[[HealthFigures], float | None]) -> list[Point]:
    points = []
    for moment, figures in trail:
        if isinstance(figures, HealthFigures):
            value = pick(figures)
            if value is not None:
                points.append((moment, float(value)))
    return points


def _temperature_points(trail: Trail) -> dict[str, list[Point]]:
    found: dict[str, list[Point]] = {}
    for moment, figures in trail:
        if isinstance(figures, HealthFigures):
            for name, degrees in figures.temperatures:
                found.setdefault(name, []).append((moment, degrees))
    return found


def _measured_ports(trail: Trail) -> list[tuple[float, list[PortFigures]]]:
    """The readings of the ports trail that have rates measured from the byte
    counters (the first reading after a pause has none), with the ports that are up."""
    readings = []
    for moment, figures in trail:
        if not isinstance(figures, dict):
            continue
        up = [port for port in figures.values() if port.up]
        if up and all(port.in_measured is not None for port in up):
            readings.append((moment, up))
    return readings


def _traffic_points(trail: Trail) -> tuple[list[Point], list[Point]]:
    """All ports' In and Out added up, per reading."""
    ins, outs = [], []
    for moment, up in _measured_ports(trail):
        ins.append((moment, float(sum(port.in_measured or 0 for port in up))))
        outs.append((moment, float(sum(port.out_measured or 0 for port in up))))
    return ins, outs


def _vlan_points(trail: Trail) -> dict[str, dict[str, list[Point]]]:
    """Each VLAN's access ports that are up added up, per reading, the same
    estimate the sampler stores: ``{VLAN_IN: {vlan: points}, VLAN_OUT: ...}``."""
    found: dict[str, dict[str, list[Point]]] = {VLAN_IN: {}, VLAN_OUT: {}}
    for moment, up in _measured_ports(trail):
        sums: dict[int, list[int]] = {}
        for port in up:
            if port.vlan is None:
                continue
            pair = sums.setdefault(port.vlan, [0, 0])
            pair[0] += port.in_measured or 0
            pair[1] += port.out_measured or 0
        for vlan, (in_bits, out_bits) in sums.items():
            found[VLAN_IN].setdefault(str(vlan), []).append((moment, float(in_bits)))
            found[VLAN_OUT].setdefault(str(vlan), []).append((moment, float(out_bits)))
    return found


def live_system_charts(
    conn: sqlite3.Connection, switch_id: int, health: Trail, ports: Trail, now: float
) -> list[ChartView]:
    """The History page's system charts for the Live window."""
    start = now - LIVE_SPAN
    common = {"start": start, "end": now, "bucket": STORED_BUCKET}

    def stored(metric: str) -> dict[str, list[Point]]:
        return read_series(conn, switch_id, metric, start=start, end=now, bucket=STORED_BUCKET)

    def line(label: str, metric: str, live: list[Point]) -> Line:
        return Line(label, stitch(stored(metric).get("", []), live))

    stored_temperatures = stored(TEMPERATURE)
    live_temperatures = _temperature_points(health)
    names = sorted(set(stored_temperatures) | set(live_temperatures))
    traffic_in, traffic_out = _traffic_points(ports)
    return [
        chart_view(
            "Temperatures",
            [
                Line(
                    name,
                    stitch(stored_temperatures.get(name, []), live_temperatures.get(name, [])),
                )
                for name in names
            ],
            fmt=degrees_text,
            zero_based=False,
            **common,
        ),
        chart_view(
            "CPU and memory",
            [
                line("CPU", CPU, _health_points(health, lambda f: f.cpu)),
                line("Memory", MEMORY, _health_points(health, lambda f: f.memory)),
            ],
            fmt=percent_text,
            y_max=100,
            **common,
        ),
        chart_view(
            "Power draw",
            [line("Total draw", POWER, _health_points(health, lambda f: f.power))],
            fmt=watts_text,
            **common,
        ),
        chart_view(
            "Fan speed",
            [line("Fans", FAN, _health_points(health, lambda f: f.fan))],
            fmt=percent_text,
            y_max=100,
            **common,
        ),
        chart_view(
            "Traffic through all ports",
            [line("In", TRAFFIC_IN, traffic_in), line("Out", TRAFFIC_OUT, traffic_out)],
            fmt=rate_text,
            **common,
        ),
    ]


def live_vlan_charts(
    conn: sqlite3.Connection, switch_id: int, ports: Trail, now: float
) -> list[ChartView]:
    """The History page's two Traffic per VLAN charts for the Live window."""
    start = now - LIVE_SPAN
    live = _vlan_points(ports)
    found = {}
    for metric in (VLAN_IN, VLAN_OUT):
        older = read_series(conn, switch_id, metric, start=start, end=now, bucket=STORED_BUCKET)
        found[metric] = {
            item: stitch(older.get(item, []), live[metric].get(item, []))
            for item in set(older) | set(live[metric])
        }
    return vlan_chart_views(found, {"start": start, "end": now, "bucket": STORED_BUCKET})
