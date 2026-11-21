"""Line charts drawn on the server as inline SVG.

No script and no chart library: the page's Content-Security-Policy allows
neither inline script nor inline style, so every colour and font comes from
CSS classes in static/style.css and every position from SVG attributes.

Pure functions over plain numbers, so they are tested without a browser.
Every label that reaches the markup goes through ``html.escape``.
"""

from __future__ import annotations

import html
import math
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from markupsafe import Markup

WIDTH = 720
HEIGHT = 240
_LEFT = 72
_RIGHT = 12
_TOP = 12
_BOTTOM = 28
# How many differently coloured lines style.css defines (.s0 to .s7).
SERIES_COLOURS = 8
# A gap of more than this many buckets between two samples breaks the line.
_GAP_BUCKETS = 2.5

Point = tuple[float, float]


@dataclass(frozen=True)
class Line:
    """One series: its legend name and (unix seconds, value) points, oldest first."""

    label: str
    points: Sequence[Point]


def nice_ticks(low: float, high: float, target: int = 5) -> list[float]:
    """Round axis values covering low..high, about ``target`` of them."""
    span = high - low
    if span <= 0:
        span = abs(high) or 1.0
    raw = span / target
    magnitude = 10 ** math.floor(math.log10(raw))
    step = magnitude
    for factor in (1, 2, 2.5, 5, 10):
        step = factor * magnitude
        if raw <= step:
            break
    first = math.floor(low / step)
    last = math.ceil(high / step)
    return [round(index * step, 10) for index in range(first, last + 1)]


# Spacing between time labels, smallest first: a minute (for the live charts
# of the last few minutes) up to 5 days.
_TIME_STEPS = (
    *(60, 120, 300, 600, 1800),
    *(3600, 7200, 10800, 21600, 43200),
    *(86400, 2 * 86400, 5 * 86400),
)
_MAX_TIME_LABELS = 7


def time_ticks(start: float, end: float) -> tuple[list[float], int]:
    """Round clock times (UTC) to label an axis, and the gap between them in seconds.

    The smallest step that gives at most seven labels, each on a multiple of
    the step, so a day chart reads 04:00, 08:00, 12:00 and a week chart
    labels each midnight.
    """
    for step in _TIME_STEPS:
        first = math.ceil(start / step)
        last = math.floor(end / step)
        if last - first + 1 <= _MAX_TIME_LABELS:
            break
    return [index * step for index in range(first, last + 1)], step


def time_label(moment: float, step: int) -> str:
    """A clock time, or the date when the labels are a day or more apart or at midnight (UTC)."""
    if step >= 86400 or moment % 86400 == 0:
        pattern = "%b %d"
    else:
        pattern = "%H:%M"
    return time.strftime(pattern, time.gmtime(moment))


def _segments(points: Sequence[Point], bucket: float) -> list[list[Point]]:
    """Split a series wherever samples are missing for longer than a gap."""
    segments: list[list[Point]] = []
    for point in points:
        if segments and point[0] - segments[-1][-1][0] <= bucket * _GAP_BUCKETS:
            segments[-1].append(point)
        else:
            segments.append([point])
    return segments


def line_chart(
    lines: Sequence[Line],
    *,
    start: float,
    end: float,
    bucket: float,
    fmt: Callable[[float], str],
    zero_based: bool = True,
    y_max: float | None = None,
    label: str = "",
) -> Markup:
    """The SVG for lines drawn over start..end.

    ``fmt`` writes an axis value ("45", "12.5 Mb/s"). ``zero_based`` keeps the
    bottom of the axis at 0; otherwise the axis hugs the data, which is what a
    temperature wants. ``y_max`` fixes the top, for percentages.
    """
    values = [value for line in lines for _, value in line.points]
    low = 0.0 if zero_based else (min(values) if values else 0.0)
    high = y_max if y_max is not None else (max(values) if values else 1.0)
    if high <= low:
        high = low + 1.0
    ticks = nice_ticks(low, high)
    bottom_value, top_value = ticks[0], ticks[-1]
    if zero_based:
        bottom_value = min(bottom_value, 0.0)
    if y_max is not None:
        top_value = max(top_value, y_max)

    plot_width = WIDTH - _LEFT - _RIGHT
    plot_height = HEIGHT - _TOP - _BOTTOM

    def x_of(moment: float) -> float:
        return _LEFT + (moment - start) / (end - start) * plot_width

    def y_of(value: float) -> float:
        return _TOP + (top_value - value) / (top_value - bottom_value) * plot_height

    parts = [
        f'<svg class="chart" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" '
        f'aria-label="{html.escape(label)}" xmlns="http://www.w3.org/2000/svg">'
    ]
    for tick in ticks:
        if not bottom_value <= tick <= top_value:
            continue
        y = y_of(tick)
        parts.append(
            f'<line class="chart-grid" x1="{_LEFT}" x2="{WIDTH - _RIGHT}" '
            f'y1="{y:.1f}" y2="{y:.1f}"/>'
        )
        parts.append(
            f'<text class="chart-text" x="{_LEFT - 6}" y="{y + 4:.1f}" text-anchor="end">'
            f"{html.escape(fmt(tick))}</text>"
        )
    moments, step = time_ticks(start, end)
    for moment in moments:
        parts.append(
            f'<text class="chart-text" x="{x_of(moment):.1f}" y="{HEIGHT - 8}" '
            f'text-anchor="middle">{html.escape(time_label(moment, step))}</text>'
        )
    for number, line in enumerate(lines):
        colour = f"s{number % SERIES_COLOURS}"
        for segment in _segments(line.points, bucket):
            if len(segment) == 1:
                moment, value = segment[0]
                parts.append(
                    f'<circle class="chart-dot {colour}" cx="{x_of(moment):.1f}" '
                    f'cy="{y_of(value):.1f}" r="2"/>'
                )
                continue
            path = " ".join(
                f"{'M' if index == 0 else 'L'}{x_of(moment):.1f},{y_of(value):.1f}"
                for index, (moment, value) in enumerate(segment)
            )
            parts.append(f'<path class="chart-line {colour}" d="{path}"/>')
    parts.append("</svg>")
    return Markup("".join(parts))  # noqa: S704 - every label above went through html.escape


# A small filled chart for one series (a VLAN's card on the Traffic page): short
# and wide, the value axis on the right, no legend of its own.
AREA_WIDTH = 520
AREA_HEIGHT = 150
_AREA_LEFT = 8
_AREA_RIGHT = 70
_AREA_TOP = 8
_AREA_BOTTOM = 22


def area_chart(
    points: Sequence[Point],
    *,
    start: float,
    end: float,
    bucket: float,
    fmt: Callable[[float], str],
    colour: int = 0,
    label: str = "",
) -> Markup:
    """The SVG of one series as a filled area over start..end, from zero up.

    Same drawing rules as ``line_chart`` (gaps break the area, labels are
    escaped), but a short chart with the value axis on the right.
    """
    high = max((value for _, value in points), default=0.0)
    ticks = nice_ticks(0.0, high if high > 0 else 1.0, target=3)
    top_value = ticks[-1]
    plot_width = AREA_WIDTH - _AREA_LEFT - _AREA_RIGHT
    plot_height = AREA_HEIGHT - _AREA_TOP - _AREA_BOTTOM
    base = _AREA_TOP + plot_height
    class_colour = f"s{colour % SERIES_COLOURS}"

    def x_of(moment: float) -> float:
        return _AREA_LEFT + (moment - start) / (end - start) * plot_width

    def y_of(value: float) -> float:
        return _AREA_TOP + (top_value - value) / top_value * plot_height

    parts = [
        f'<svg class="chart chart-area-svg" viewBox="0 0 {AREA_WIDTH} {AREA_HEIGHT}" '
        f'role="img" aria-label="{html.escape(label)}" xmlns="http://www.w3.org/2000/svg">'
    ]
    right_edge = _AREA_LEFT + plot_width
    for tick in ticks:
        y = y_of(tick)
        parts.append(
            f'<line class="chart-grid" x1="{_AREA_LEFT}" x2="{right_edge}" '
            f'y1="{y:.1f}" y2="{y:.1f}"/>'
        )
        parts.append(
            f'<text class="chart-text" x="{right_edge + 6}" y="{y + 4:.1f}" '
            f'text-anchor="start">{html.escape(fmt(tick))}</text>'
        )
    moments, step = time_ticks(start, end)
    for moment in moments:
        parts.append(
            f'<text class="chart-text" x="{x_of(moment):.1f}" y="{AREA_HEIGHT - 6}" '
            f'text-anchor="middle">{html.escape(time_label(moment, step))}</text>'
        )
    parts.extend(_filled_segments(points, bucket, x_of, y_of, base, class_colour))
    parts.append("</svg>")
    return Markup("".join(parts))  # noqa: S704 - every label above went through html.escape


def _filled_segments(
    points: Sequence[Point],
    bucket: float,
    x_of: Callable[[float], float],
    y_of: Callable[[float], float],
    base: float,
    class_colour: str,
) -> list[str]:
    """The SVG of one series filled between its line and ``base`` (a y position),
    broken where samples are missing; a lone sample is a dot."""
    parts = []
    for segment in _segments(points, bucket):
        if len(segment) == 1:
            moment, value = segment[0]
            parts.append(
                f'<circle class="chart-dot {class_colour}" cx="{x_of(moment):.1f}" '
                f'cy="{y_of(value):.1f}" r="2"/>'
            )
            continue
        edge = " ".join(f"L{x_of(m):.1f},{y_of(v):.1f}" for m, v in segment)
        first, last = x_of(segment[0][0]), x_of(segment[-1][0])
        parts.append(
            f'<path class="chart-area {class_colour}" '
            f'd="M{first:.1f},{base:.1f} {edge} L{last:.1f},{base:.1f} Z"/>'
        )
        line = " ".join(
            f"{'M' if index == 0 else 'L'}{x_of(m):.1f},{y_of(v):.1f}"
            for index, (m, v) in enumerate(segment)
        )
        parts.append(f'<path class="chart-line {class_colour}" d="{line}"/>')
    return parts


# The Dashboard's traffic cards: In above the zero line and Out below it, as a
# network interface is drawn in TrueNAS. Narrower than ``area_chart`` (a card
# shows it about 360px wide, so its text stays readable) and a little taller,
# for the two sides.
IN_OUT_WIDTH = 420
IN_OUT_HEIGHT = 170


def in_out_chart(
    ins: Sequence[Point],
    outs: Sequence[Point],
    *,
    start: float,
    end: float,
    bucket: float,
    fmt: Callable[[float], str],
    label: str = "",
) -> Markup:
    """The SVG of In as a filled area above the zero line and Out as one below it.

    One scale for both sides, so the larger reaches further; the value axis on
    the right writes both sides without a minus sign. In takes the first
    series colour and Out the second, the colours of the legend beside it.
    Gaps break the areas as in ``area_chart``.
    """
    in_high = max((value for _, value in ins), default=0.0)
    out_high = max((value for _, value in outs), default=0.0)
    if in_high <= 0 and out_high <= 0:
        in_high = 1.0
    ticks = nice_ticks(-out_high, in_high, target=4)
    top_value, bottom_value = max(ticks[-1], 0.0), min(ticks[0], 0.0)
    plot_width = IN_OUT_WIDTH - _AREA_LEFT - _AREA_RIGHT
    plot_height = IN_OUT_HEIGHT - _AREA_TOP - _AREA_BOTTOM

    def x_of(moment: float) -> float:
        return _AREA_LEFT + (moment - start) / (end - start) * plot_width

    def y_of(value: float) -> float:
        return _AREA_TOP + (top_value - value) / (top_value - bottom_value) * plot_height

    def y_below(value: float) -> float:
        return y_of(-value)

    parts = [
        f'<svg class="chart chart-area-svg" viewBox="0 0 {IN_OUT_WIDTH} {IN_OUT_HEIGHT}" '
        f'role="img" aria-label="{html.escape(label)}" xmlns="http://www.w3.org/2000/svg">'
    ]
    right_edge = _AREA_LEFT + plot_width
    for tick in ticks:
        y = y_of(tick)
        kind = "chart-grid chart-zero" if tick == 0 else "chart-grid"
        parts.append(
            f'<line class="{kind}" x1="{_AREA_LEFT}" x2="{right_edge}" y1="{y:.1f}" y2="{y:.1f}"/>'
        )
        parts.append(
            f'<text class="chart-text" x="{right_edge + 6}" y="{y + 4:.1f}" '
            f'text-anchor="start">{html.escape(fmt(abs(tick)))}</text>'
        )
    moments, step = time_ticks(start, end)
    for moment in moments:
        parts.append(
            f'<text class="chart-text" x="{x_of(moment):.1f}" y="{IN_OUT_HEIGHT - 6}" '
            f'text-anchor="middle">{html.escape(time_label(moment, step))}</text>'
        )
    zero = y_of(0.0)
    parts.extend(_filled_segments(ins, bucket, x_of, y_of, zero, "s0"))
    parts.extend(_filled_segments(outs, bucket, x_of, y_below, zero, "s1"))
    parts.append("</svg>")
    return Markup("".join(parts))  # noqa: S704 - every label above went through html.escape
