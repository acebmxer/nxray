"""The Dashboard's live traffic cards (#107): In above the line and Out below it,
for the busiest ports and port-channels over the last 40 minutes."""

from __future__ import annotations

import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.charts import in_out_chart
from app.dashboard_traffic import MAX_CARDS, card_items, traffic_cards, window_average
from app.db import init_db, open_db
from app.history import LIVE_SPAN, PORT_IN, PORT_OUT, rate_text, record
from app.live import PortFigures
from app.neighbors import PortChannel
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

# ---- the chart -------------------------------------------------------------------


def _ys(svg: str, colour: str) -> list[float]:
    """Every y position of the filled area drawn in ``colour``."""
    path = re.search(rf'class="chart-area {colour}" d="([^"]+)"', svg)
    assert path, f"no {colour} area"
    return [float(y) for y in re.findall(r"[ML][\d.]+,([\d.]+)", path.group(1))]


def _zero_line(svg: str) -> float:
    found = re.search(r'class="chart-grid chart-zero"[^>]*y1="([\d.]+)"', svg)
    assert found
    return float(found.group(1))


def test_in_is_drawn_above_the_zero_line_and_out_below_it() -> None:
    ins = [(100.0 + i, 5_000_000.0) for i in range(5)]
    outs = [(100.0 + i, 1_000_000.0) for i in range(5)]
    svg = str(in_out_chart(ins, outs, start=100, end=104, bucket=1, fmt=rate_text))
    zero = _zero_line(svg)
    assert all(y <= zero for y in _ys(svg, "s0")) and min(_ys(svg, "s0")) < zero
    assert all(y >= zero for y in _ys(svg, "s1")) and max(_ys(svg, "s1")) > zero
    # One scale: In, five times Out, reaches five times as far from the line.
    assert (zero - min(_ys(svg, "s0"))) == pytest.approx(5 * (max(_ys(svg, "s1")) - zero), 0.01)
    # Both sides are labelled without a minus sign.
    labels = re.findall(r'text-anchor="start">([^<]+)<', svg)
    assert "0 b/s" in labels and any("Mb/s" in label for label in labels)
    assert not any(label.startswith("-") for label in labels)


def test_an_idle_or_empty_chart_still_has_an_axis() -> None:
    svg = str(in_out_chart([], [], start=0, end=60, bucket=1, fmt=rate_text, label="a <b>"))
    assert "chart-zero" in svg and 'class="chart-area ' not in svg
    assert 'aria-label="a &lt;b&gt;"' in svg
    idle = str(in_out_chart([(1.0, 0.0), (2.0, 0.0)], [], start=0, end=60, bucket=1, fmt=rate_text))
    assert 'class="chart-area s0"' in idle


def test_a_gap_breaks_the_areas() -> None:
    ins = [(0.0, 1.0), (1.0, 1.0), (50.0, 1.0), (51.0, 1.0)]
    svg = str(in_out_chart(ins, [], start=0, end=60, bucket=1, fmt=rate_text))
    assert svg.count('class="chart-area s0"') == 2


# ---- which cards -------------------------------------------------------------------


def test_a_port_channel_stands_for_its_member_ports() -> None:
    channel = PortChannel("port-channel41", ("Ethernet1/41", "Ethernet1/42"), "LACP", True)
    items = card_items(["Ethernet1/1", "Ethernet1/41", "Ethernet1/42"], [channel])
    assert items == {
        "port-channel41": ("Ethernet1/41", "Ethernet1/42"),
        "Ethernet1/1": ("Ethernet1/1",),
    }
    # An empty port-channel is no card, and its would-be members keep theirs.
    empty = PortChannel("port-channel9", (), "NONE", False)
    assert card_items(["Ethernet1/1"], [empty]) == {"Ethernet1/1": ("Ethernet1/1",)}


@pytest.fixture
def db(tmp_path) -> sqlite3.Connection:
    path = tmp_path / "nxray.db"
    init_db(path)
    with open_db(path) as conn:
        yield conn


def _measured(rate_in: int, rate_out: int, up: bool = True) -> PortFigures:
    return PortFigures(up, rate_in, rate_out, rate_in, rate_out)


def test_cards_stitch_the_stored_minutes_to_the_live_readings(db: sqlite3.Connection) -> None:
    now = time.time()
    # Stored minutes from 30 to 5 minutes ago, then a live reading every 2 s.
    for minutes in range(30, 4, -1):
        record(
            db,
            1,
            now - minutes * 60,
            [(PORT_IN, "Ethernet1/5", 1e6), (PORT_OUT, "Ethernet1/5", 2e5)],
        )
    trail = [
        (now - seconds, {"Ethernet1/5": _measured(8_000_000, 400_000)})
        for seconds in range(240, -1, -2)
    ]
    (card,) = traffic_cards(db, 1, trail, channels=[], notes={"Ethernet1/5": "nas"}, now=now)
    assert card.name == "Ethernet1/5" and card.note == "nas" and card.up is True
    assert (card.now_in, card.now_out) == ("8 Mb/s", "400 kb/s")
    svg = str(card.svg)
    # One unbroken area per side: the stored minutes run into the live part.
    assert svg.count('class="chart-area s0"') == 1 and svg.count('class="chart-area s1"') == 1


def test_a_reading_without_measured_rates_draws_nothing_new(db: sqlite3.Connection) -> None:
    now = time.time()
    first = PortFigures(True, 5_000, 5_000)  # the first reading: no earlier one to measure from
    assert (
        traffic_cards(db, 1, [(now, {"Ethernet1/5": first})], channels=[], notes={}, now=now) == []
    )


def test_the_busiest_come_first_and_at_most_eight(db: sqlite3.Connection) -> None:
    now = time.time()
    trail = [
        (
            now - seconds,
            {f"Ethernet1/{n}": _measured(n * 1_000, n * 100) for n in range(1, 13)}
            | {"Ethernet1/20": _measured(9, 9, up=False)},
        )
        for seconds in (4, 2, 0)
    ]
    cards = traffic_cards(db, 1, trail, channels=[], notes={}, now=now)
    assert len(cards) == MAX_CARDS
    assert [card.name for card in cards] == [f"Ethernet1/{n}" for n in range(12, 4, -1)]


def test_a_minute_of_live_readings_weighs_as_much_as_a_stored_minute() -> None:
    stored = [(0.0, 100.0), (60.0, 100.0)]
    live = [(60.0 + seconds, 0.0) for seconds in range(2, 62, 2)]
    # Counted point by point the 30 live readings would swamp the stored minute.
    assert window_average(stored + live) == pytest.approx((60 * 100 + 2 * 50) / 120)
    assert window_average([]) == 0.0 and window_average([(5.0, 7.0)]) == 7.0


def test_a_port_channel_card_adds_up_its_members(db: sqlite3.Connection) -> None:
    now = time.time()
    channel = PortChannel("port-channel41", ("Ethernet1/41", "Ethernet1/42"), "LACP", True)
    trail = [
        (
            now - seconds,
            {
                "Ethernet1/41": _measured(3_000_000, 1_000_000),
                "Ethernet1/42": _measured(2_000_000, 500_000),
                "Ethernet1/1": _measured(1_000, 1_000),
            },
        )
        for seconds in (4, 2, 0)
    ]
    cards = traffic_cards(db, 1, trail, channels=[channel], notes={}, now=now)
    assert [card.name for card in cards] == ["port-channel41", "Ethernet1/1"]
    assert cards[0].is_channel and cards[0].note == "Eth1/41, Eth1/42"
    assert (cards[0].now_in, cards[0].now_out) == ("5 Mb/s", "1.5 Mb/s")


def test_a_port_that_went_down_keeps_its_card_and_says_so(db: sqlite3.Connection) -> None:
    now = time.time()
    trail = [
        (now - 4, {"Ethernet1/7": _measured(1_000, 1_000)}),
        (now - 2, {"Ethernet1/7": _measured(1_000, 1_000)}),
        (now, {"Ethernet1/7": PortFigures(False, 0, 0)}),
    ]
    (card,) = traffic_cards(db, 1, trail, channels=[], notes={}, now=now)
    assert card.up is False


def test_only_the_last_forty_minutes_count(db: sqlite3.Connection) -> None:
    now = time.time()
    record(
        db,
        1,
        now - LIVE_SPAN - 120,
        [(PORT_IN, "Ethernet1/5", 1e6), (PORT_OUT, "Ethernet1/5", 1e6)],
    )
    assert traffic_cards(db, 1, [], channels=[], notes={}, now=now) == []
    assert traffic_cards(db, 2, [], channels=[], notes={}, now=now) == []


# ---- the pages -----------------------------------------------------------------------


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', logged_in.get("/switch").text)
    assert csrf
    response = logged_in.post(
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
    assert "NXray created the account" in response.text
    fake.requests.clear()
    return fake


def _store_minutes(client: TestClient, ports: dict[str, float]) -> None:
    """Stored minutes of the last 20 minutes for ``ports`` (name -> In and Out)."""
    now = time.time()
    with open_db(client.app.state.settings.db_path) as conn:  # type: ignore[attr-defined]
        switch_id = conn.execute("SELECT id FROM switch_connection").fetchone()[0]
        for minutes in range(20, 0, -1):
            rows = [
                (metric, name, rate)
                for name, rate in ports.items()
                for metric in (PORT_IN, PORT_OUT)
            ]
            record(conn, switch_id, now - minutes * 60, rows)


def test_the_dashboard_opens_on_live_with_its_traffic_cards(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    _store_minutes(logged_in, {"Ethernet1/43": 2e6, "Ethernet1/44": 1e6, "Ethernet1/1": 5e3})
    page = logged_in.get("/").text
    assert 'data-live-url="/live/dashboard"' in page
    assert '<option value="live" selected>' in page  # the browser's choice was Off
    assert "Traffic, last 40 minutes" in page
    # Ethernet1/43-44 are port-channel43: one card for both, from the first view.
    assert ">port-channel43</a>" in page and "Eth1/43, Eth1/44" in page
    assert ">Ethernet1/43</a>" not in page and ">Ethernet1/1</a>" in page
    assert page.index("port-channel43") < page.index("Ethernet1/1")
    assert page.count('class="card traffic-card"') == 2
    # Opening the page asks for the dashboard figures and the port-channels only.
    assert switch.requests[1:] == [["show port-channel summary"]]
    # The refresh reads the ports too, and draws the same cards.
    answer = logged_in.get("/live/dashboard").text
    assert answer.lstrip().startswith('<div data-live-region="health"')
    assert ">port-channel43</a>" in answer and answer.count('class="card traffic-card"') == 2
    # Within the minute the port-channels are not asked for again.
    logged_in.get("/")
    asked = [cmd for request in switch.requests for cmd in request]
    assert asked.count("show port-channel summary") == 1


def test_the_dashboard_without_traffic_says_the_cards_fill_in(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    page = logged_in.get("/").text
    assert "Traffic, last 40 minutes" in page and "No traffic to draw yet." in page


def test_the_port_channels_are_read_once_a_minute(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    for _ in range(3):
        logged_in.get("/live/dashboard")
    asked = [cmd for request in switch.requests for cmd in request]
    assert asked.count("show port-channel summary") == 1


def test_a_browser_set_to_off_reads_the_dashboard_figures_less_often(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    logged_in.get("/live/dashboard")
    cache = logged_in.app.state.live_cache  # type: ignore[attr-defined]
    for entry in cache._entries.values():
        entry.read_at -= 3  # past the 2 s floor, short of 10 s
    switch.requests.clear()
    logged_in.get("/live/dashboard")
    asked = [cmd for request in switch.requests for cmd in request]
    assert "show interface" in asked and "show environment" not in asked
