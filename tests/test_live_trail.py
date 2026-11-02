"""The live charts of the last few minutes: the trail each cache entry keeps
in memory, the figures it keeps, and the charts drawn from it."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import replace
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.live import (
    KEEP_UNWATCHED_SECONDS,
    TRAIL_SECONDS,
    LiveCache,
    PortFigures,
    health_figures,
    health_trail_chart,
    measure_rates,
    port_figures,
    port_trail_chart,
    trail_spacing,
)
from app.ports import parse_ports
from app.switch import parse_resources
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _counting(problem: str = "") -> Callable[[object], tuple[object, str]]:
    calls: list[object] = []

    def read(previous: object) -> tuple[object, str]:
        calls.append(previous)
        return (len(calls), "") if not problem else (None, problem)

    return read


def _ports():
    return [replace(port, up=True) for port in _parse()]


def _parse():
    return parse_ports(
        load_fixture("show_interface"),
        load_fixture("show_interface_status"),
        load_fixture("show_interface_transceiver"),
    )


# ---- the trail in the cache ------------------------------------------------------


def test_only_fresh_readings_go_on_the_trail() -> None:
    clock = Clock()
    cache = LiveCache(clock)
    for _ in range(3):
        answer = cache.get(1, "health", 2, _counting(), figures=lambda v: v * 10)
    assert answer.trail == ((1000.0, 10),)
    clock.now += 2
    answer = cache.get(1, "health", 2, _counting(), figures=lambda v: v * 10)
    assert [at for at, _ in answer.trail] == [1000.0, 1002.0]


def test_a_failed_reading_leaves_a_gap() -> None:
    clock = Clock()
    cache = LiveCache(clock)
    cache.get(1, "health", 2, _counting(), figures=lambda v: v)
    clock.now += 2
    failed = cache.get(1, "health", 2, _counting("timed out"), figures=lambda v: v)
    assert len(failed.trail) == 1 and failed.problem == "timed out"


def test_no_figures_means_no_trail() -> None:
    cache = LiveCache(Clock())
    assert cache.get(1, "ports", 2, _counting()).trail == ()


def test_the_trail_keeps_only_the_last_minutes() -> None:
    clock = Clock()
    cache = LiveCache(clock)
    for _ in range(4):
        cache.get(1, "health", 2, _counting(), figures=lambda v: v)
        clock.now += TRAIL_SECONDS / 2
    answer = cache.get(1, "health", 2, _counting(), figures=lambda v: v)
    assert all(at >= clock.now - TRAIL_SECONDS for at, _ in answer.trail)
    assert len(answer.trail) == 3


def test_peeking_at_the_trail_reads_nothing_and_goes_with_its_entry() -> None:
    clock = Clock()
    cache = LiveCache(clock)
    assert cache.trail(1, "health") == ()
    cache.get(1, "health", 2, _counting(), figures=lambda v: v)
    assert len(cache.trail(1, "health")) == 1
    assert cache.trail(2, "health") == () and cache.trail(1, "ports") == ()
    clock.now += KEEP_UNWATCHED_SECONDS + 1
    # Nobody asked for it for a while: gone, and peeking does not keep it alive.
    assert cache.trail(1, "health") == ()


# ---- what the trail keeps --------------------------------------------------------


def test_port_figures_keep_both_kinds_of_rate() -> None:
    ports = _ports()
    first = measure_rates(None, ports, 100.0)
    only_average = port_figures(first)
    name = next(p.name for p in ports if p.up)
    assert only_average[name].in_measured is None
    moved = [replace(p, in_bytes=p.in_bytes + 1000, out_bytes=p.out_bytes + 500) for p in ports]
    both = port_figures(measure_rates(first, moved, 102.0))
    figures = both[name]
    assert figures.up and figures.in_measured == 4000 and figures.out_measured == 2000
    assert figures.in_average == next(p for p in ports if p.name == name).in_bits_per_second


def test_health_figures_are_cpu_and_memory() -> None:
    resources = parse_resources(load_fixture("show_system_resources"))
    data = SimpleNamespace(resources=resources)
    cpu, memory = health_figures((None, data))
    assert cpu == resources.cpu_used_percent and cpu is not None
    assert memory == resources.memory_used_percent
    assert health_figures(None) == (None, None)


def test_spacing_is_the_usual_gap_never_below_the_floor() -> None:
    assert trail_spacing([], 2) == 2.0
    assert trail_spacing([(0, 1)], 2) == 2.0
    assert trail_spacing([(0, 1), (5, 1), (10, 1), (100, 1)], 2) == 5.0
    assert trail_spacing([(0, 1), (1, 1), (2, 1)], 2) == 2.0


# ---- the charts ------------------------------------------------------------------


def _trail(name: str, *, measured: bool = True) -> list[tuple[float, dict[str, PortFigures]]]:
    return [
        (
            1000.0 + 2 * step,
            {
                name: PortFigures(
                    up=True,
                    in_average=1_000_000,
                    out_average=2_000_000,
                    in_measured=3_000_000 + step if measured else None,
                    out_measured=4_000_000 if measured else None,
                )
            },
        )
        for step in range(5)
    ]


def test_an_empty_trail_says_how_to_fill_it() -> None:
    view = port_trail_chart((), "Ethernet1/1", measured=False, now=1000.0, floor=2)
    assert view.svg is None
    assert "choose Live or an interval" in view.empty and "10 minutes" in view.empty


def test_the_port_chart_draws_the_averages_or_the_measured_rates() -> None:
    trail = _trail("Ethernet1/1")
    average = port_trail_chart(trail, "Ethernet1/1", measured=False, now=1010.0, floor=2)
    assert average.svg is not None and average.title == "Last 10 minutes"
    assert [entry.label for entry in average.legend] == ["In", "Out"]
    assert average.legend[0].summary.startswith("now 1 Mb/s")
    measured = port_trail_chart(trail, "Ethernet1/1", measured=True, now=1010.0, floor=2)
    assert measured.legend[0].summary.startswith("now 3 Mb/s")
    assert "byte counters" in measured.note and "Times are UTC" in measured.note
    assert "<script" not in str(measured.svg)


def test_the_port_chart_skips_what_cannot_be_drawn() -> None:
    no_measure = _trail("Ethernet1/1", measured=False)
    assert port_trail_chart(no_measure, "Ethernet1/1", measured=True, now=1010, floor=2).svg is None
    assert (
        port_trail_chart(no_measure, "Ethernet1/2", measured=False, now=1010, floor=2).svg is None
    )
    down = [(at, {"Ethernet1/1": replace(f["Ethernet1/1"], up=False)}) for at, f in no_measure]
    assert port_trail_chart(down, "Ethernet1/1", measured=False, now=1010, floor=2).svg is None


def test_the_health_chart_is_in_percent() -> None:
    trail = [(1000.0, (10.0, 50.0)), (1002.0, (12.5, None)), (1004.0, (11.0, 51.0))]
    view = health_trail_chart(trail, now=1010.0, floor=2)
    assert view.svg is not None and [e.label for e in view.legend] == ["CPU", "Memory"]
    assert view.legend[0].summary == "now 11%, highest 12.5%"
    assert health_trail_chart((), now=1010.0, floor=2).svg is None


# ---- the pages -------------------------------------------------------------------


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    body = load_fixture("show_interface")
    for row in body["TABLE_interface"]["ROW_interface"]:
        if row["interface"] == "Ethernet1/1":
            row["state"] = "up"
    fake = FakeSwitch(bodies={"show interface": body})
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', logged_in.get("/switch").text)
    assert csrf
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": csrf.group(1),
            "host": "192.0.2.10",
            "port": "443",
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "account_name": "nxray",
            "confirm_save": "yes",
        },
    )
    fake.requests.clear()
    return fake


def _age_readings(client: TestClient, seconds: float) -> None:
    """Make every cached reading (and its trail) older, as if time went by."""
    cache = client.app.state.live_cache  # type: ignore[attr-defined]
    for entry in cache._entries.values():
        entry.read_at -= seconds
        entry.trail = type(entry.trail)((at - seconds, f) for at, f in entry.trail)


def test_the_port_page_and_its_answer_carry_the_trail(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    page = logged_in.get("/ports/detail?name=Ethernet1/1").text
    assert 'data-live-region="trail"' in page and "Nothing to draw yet" in page
    first = logged_in.get("/live/port?name=Ethernet1/1").text
    assert first.count('data-live-region="trail"') == 1
    _age_readings(logged_in, 3)
    second = logged_in.get("/live/port?name=Ethernet1/1").text
    assert "Last 10 minutes" in second and '<svg class="chart"' in second
    # A page opened now draws what the others' refresh has kept.
    again = logged_in.get("/ports/detail?name=Ethernet1/1").text
    assert "Nothing to draw yet" not in again.split('data-live-region="trail"')[1][:2000]


def test_the_dashboard_and_its_answer_carry_the_trail(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    assert "CPU and memory, last 10 minutes" in logged_in.get("/").text
    logged_in.get("/live/dashboard")
    _age_readings(logged_in, 3)
    answer = logged_in.get("/live/dashboard").text
    assert "CPU and memory, last 10 minutes" in answer
    assert '<svg class="chart"' in answer
