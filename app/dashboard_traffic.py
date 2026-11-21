"""The Dashboard's traffic cards: In and Out of the busiest ports and port-channels.

One card per port or port-channel, drawn like a network interface card in
TrueNAS: the name and the newest In and Out on the left, and beside them the
last 40 minutes with In as a filled area above the zero line and Out below it.

The newest part of each card is the port reading's trail in the live cache
(``app/live.py``: In and Out measured from the byte counters at each refresh,
every few seconds). The part before the trail begins (NXray was just started,
or nobody had a page open) is the stored samples, one a minute
(``app/history.py``), so a card shows the whole window as soon as the page
opens. A port-channel's card adds up its member ports, which then get no card
of their own. Nothing here reads the switch.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from markupsafe import Markup

from app.charts import Point, in_out_chart
from app.history import LIVE_SPAN, PORT_IN, PORT_OUT, rate_text, read_series, stitch
from app.live import PortFigures
from app.neighbors import PortChannel
from app.ports import port_sort_key

# The most cards the Dashboard shows, the busiest first.
MAX_CARDS = 8
# The stored samples are a minute apart; a card breaks its areas where two
# points are further apart than a few of these.
STORED_BUCKET = 60


@dataclass(frozen=True)
class TrafficCard:
    """One port's or port-channel's card."""

    name: str  # "Ethernet1/5" or "port-channel41"
    note: str  # the port's label or description, or a port-channel's member ports
    up: bool | None  # the link, from the newest reading; None before there is one
    now_in: str
    now_out: str
    svg: Markup

    @property
    def is_channel(self) -> bool:
        return self.name.startswith("port-channel")


def _short(port: str) -> str:
    return port.replace("Ethernet", "Eth", 1)


def card_items(ports: Sequence[str], channels: Sequence[PortChannel]) -> dict[str, tuple[str, ...]]:
    """Each card's name and the ports it adds up: a port-channel stands for its
    member ports, every other port for itself."""
    items: dict[str, tuple[str, ...]] = {}
    bundled: set[str] = set()
    for channel in channels:
        if channel.members:
            items[channel.name] = channel.members
            bundled.update(channel.members)
    for port in ports:
        if port not in bundled:
            items[port] = (port,)
    return items


def _live_points(
    trail: Sequence[tuple[float, Any]], members: tuple[str, ...], start: float
) -> tuple[list[Point], list[Point]]:
    """In and Out of ``members`` added up, per reading of the trail that has rates
    measured from the byte counters for at least one of them that is up."""
    ins, outs = [], []
    for moment, figures in trail:
        if moment < start or not isinstance(figures, dict):
            continue
        measured: list[PortFigures] = [
            port
            for name in members
            if (port := figures.get(name)) is not None
            and port.up
            and port.in_measured is not None
            and port.out_measured is not None
        ]
        if measured:
            ins.append((moment, float(sum(port.in_measured or 0 for port in measured))))
            outs.append((moment, float(sum(port.out_measured or 0 for port in measured))))
    return ins, outs


def _stored_points(series: dict[str, list[Point]], members: tuple[str, ...]) -> list[Point]:
    """The stored minutes of ``members`` added up, minute by minute."""
    sums: dict[float, float] = {}
    for name in members:
        for moment, value in series.get(name, []):
            sums[moment] = sums.get(moment, 0.0) + value
    return sorted(sums.items())


def window_average(points: Sequence[Point]) -> float:
    """The average of a series over the time it covers: each point counts for
    as long as it lasts, so a stored minute weighs as much as the 30 live
    readings of a minute. Ranking by it keeps the cards in place from one
    refresh to the next."""
    if len(points) < 2:
        return points[0][1] if points else 0.0
    area = sum(
        (later[0] - earlier[0]) * (earlier[1] + later[1]) / 2
        for earlier, later in zip(points, points[1:], strict=False)
    )
    span = points[-1][0] - points[0][0]
    return area / span if span > 0 else points[-1][1]


def _link_up(
    name: str,
    members: tuple[str, ...],
    newest: dict[str, PortFigures] | None,
    channels: Sequence[PortChannel],
) -> bool | None:
    channel = next((c for c in channels if c.name == name), None)
    if channel is not None:
        return channel.up
    if newest is None or name not in newest:
        return None
    return any(newest[port].up for port in members if port in newest)


def traffic_cards(
    conn: sqlite3.Connection,
    switch_id: int,
    trail: Sequence[tuple[float, Any]],
    *,
    channels: Sequence[PortChannel],
    notes: dict[str, str],
    now: float,
) -> list[TrafficCard]:
    """A card for each of the busiest ports and port-channels over the last 40
    minutes, busiest first (In and Out added up, ``window_average``).

    ``trail`` is the port reading's trail (``{port: PortFigures}`` per reading),
    ``channels`` the switch's port-channels (empty when unknown: each member
    port then has its own card), ``notes`` each port's label or description.
    A port or port-channel with no point in the window (down all along) gets
    no card.
    """
    start = now - LIVE_SPAN
    stored_in = read_series(conn, switch_id, PORT_IN, start=start, end=now, bucket=STORED_BUCKET)
    stored_out = read_series(conn, switch_id, PORT_OUT, start=start, end=now, bucket=STORED_BUCKET)
    newest = next((figures for _, figures in reversed(trail) if isinstance(figures, dict)), None)
    names = set(stored_in) | set(stored_out) | set(newest or {})
    items = card_items(sorted(names, key=port_sort_key), channels)

    drawn: list[tuple[float, str, list[Point], list[Point]]] = []
    for name, members in items.items():
        live_in, live_out = _live_points(trail, members, start)
        ins = stitch(_stored_points(stored_in, members), live_in)
        outs = stitch(_stored_points(stored_out, members), live_out)
        if not ins and not outs:
            continue
        drawn.append((window_average(ins) + window_average(outs), name, ins, outs))
    # Busiest first; equal ones in port order, so the cards do not swap places.
    channel_numbers = {c.name: i for i, c in enumerate(channels)}
    drawn.sort(key=lambda d: (-d[0], channel_numbers.get(d[1], 1_000), port_sort_key(d[1])))

    cards = []
    for _average, name, ins, outs in drawn[:MAX_CARDS]:
        members = items[name]
        note = (
            ", ".join(_short(port) for port in members)
            if name in channel_numbers
            else notes.get(name, "")
        )
        cards.append(
            TrafficCard(
                name=name,
                note=note,
                up=_link_up(name, members, newest, channels),
                now_in=rate_text(ins[-1][1]) if ins else "unknown",
                now_out=rate_text(outs[-1][1]) if outs else "unknown",
                svg=in_out_chart(
                    ins,
                    outs,
                    start=start,
                    end=now,
                    bucket=STORED_BUCKET,
                    fmt=rate_text,
                    label=f"{name}: In above the line, Out below, over the last 40 minutes",
                ),
            )
        )
    return cards
