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


# Spacing between time labels, smallest first: 10 minutes up to 5 days.
_TIME_STEPS = (600, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 2 * 86400, 5 * 86400)
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
