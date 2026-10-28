"""The SVG charts: axis values, gaps, and escaping."""

from __future__ import annotations

import re

from app.charts import Line, line_chart, nice_ticks, time_label, time_ticks


def _fmt(value: float) -> str:
    return f"{value:g}"


def test_nice_ticks_are_round_and_cover_the_data() -> None:
    assert nice_ticks(0, 87) == [0, 20, 40, 60, 80, 100]
    assert nice_ticks(31, 47) == [30, 35, 40, 45, 50]


def test_time_ticks_are_round_times_and_at_most_seven() -> None:
    day = 1_700_006_400  # a UTC midnight, 2023-11-15
    for span in (3600, 6 * 3600, 86400, 7 * 86400, 30 * 86400):
        moments, step = time_ticks(day - span, day)
        assert 2 <= len(moments) <= 7
        assert all(moment % step == 0 for moment in moments)
        assert all(day - span <= moment <= day for moment in moments)
    noon = day + 12 * 3600
    assert time_ticks(noon - 7 * 86400, noon)[1] == 86400  # a week: one label a day


def test_time_labels_are_clock_times_or_dates() -> None:
    midnight = 1_700_006_400
    assert time_label(midnight + 4 * 3600, 4 * 3600) == "04:00"
    assert time_label(midnight, 4 * 3600) == "Nov 15"  # a day boundary shows the date
    assert time_label(midnight + 5 * 3600, 86400) == "Nov 15"
    assert time_label(midnight + 600, 600) == "00:10"


def test_a_line_becomes_one_path() -> None:
    svg = str(
        line_chart(
            [Line("a", [(10, 1), (70, 2), (130, 3)])],
            start=0,
            end=200,
            bucket=60,
            fmt=_fmt,
        )
    )
    assert svg.count("<path") == 1
    assert 'class="chart-line s0"' in svg


def test_a_long_gap_breaks_the_line() -> None:
    svg = str(
        line_chart(
            [Line("a", [(10, 1), (70, 2), (1000, 3), (1060, 4)])],
            start=0,
            end=1200,
            bucket=60,
            fmt=_fmt,
        )
    )
    assert svg.count("<path") == 2


def test_a_lone_point_is_a_dot() -> None:
    svg = str(line_chart([Line("a", [(10, 1)])], start=0, end=100, bucket=60, fmt=_fmt))
    assert "<circle" in svg
    assert "<path" not in svg


def test_each_line_gets_its_own_colour() -> None:
    svg = str(
        line_chart(
            [Line("a", [(10, 1), (70, 2)]), Line("b", [(10, 3), (70, 4)])],
            start=0,
            end=100,
            bucket=60,
            fmt=_fmt,
        )
    )
    assert "chart-line s0" in svg and "chart-line s1" in svg


def test_every_point_stays_inside_the_chart() -> None:
    svg = str(
        line_chart(
            [Line("a", [(0, 5), (100, 95)])], start=0, end=100, bucket=60, fmt=_fmt, y_max=100
        )
    )
    points = re.findall(r"[ML]([\d.]+),([\d.]+)", svg)
    assert len(points) == 2
    assert all(0 <= float(x) <= 720 and 0 <= float(y) <= 240 for x, y in points)


def test_labels_are_escaped() -> None:
    svg = str(
        line_chart(
            [Line("a", [(10, 1), (70, 2)])],
            start=0,
            end=100,
            bucket=60,
            fmt=lambda value: "<script>",
            label='"><script>alert(1)</script>',
        )
    )
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg


def test_a_temperature_axis_follows_the_data_not_zero() -> None:
    svg = str(
        line_chart(
            [Line("t", [(10, 40), (70, 44)])],
            start=0,
            end=100,
            bucket=60,
            fmt=_fmt,
            zero_based=False,
        )
    )
    labels = re.findall(r'text-anchor="end">([\d.]+)<', svg)
    assert labels and min(float(label) for label in labels) >= 35
