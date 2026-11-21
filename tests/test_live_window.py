"""The Live window of the Traffic and History pages (#106): the last 40 minutes,
drawn from what NXray holds in memory and moving by itself."""

from __future__ import annotations

import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app import history
from app.db import init_db, open_db
from app.history import LIVE, LIVE_SPAN, fill_gaps, page_range_key, range_seconds, stitch
from app.live import HealthFigures, PortFigures
from app.live_history import live_system_charts, live_vlan_charts
from app.sflow import (
    RECENT_KEEP_SECONDS,
    VLAN,
    SflowCollector,
    SflowRow,
    store_rows,
    vlan_cards,
)
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch
from tests.test_sflow import AGENT, _one


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


# ---- the range names ---------------------------------------------------------


def test_the_live_window_is_the_default_and_only_the_pages_have_it() -> None:
    assert page_range_key(None) == LIVE and page_range_key("") == LIVE
    assert page_range_key("live") == LIVE
    assert page_range_key("7d") == "7d"
    assert page_range_key("forever") == history.DEFAULT_RANGE
    # The port page and the alerts keep the stored ranges only.
    assert history.range_key("live") == history.DEFAULT_RANGE
    assert LIVE not in history.RANGES
    assert range_seconds(LIVE) == LIVE_SPAN == 2400 and range_seconds("1h") == 3600


def test_the_stored_part_ends_where_the_live_part_begins() -> None:
    older = [(10.0, 1.0), (20.0, 2.0), (30.0, 3.0)]
    assert stitch(older, [(25.0, 9.0), (35.0, 8.0)]) == [
        (10.0, 1.0),
        (20.0, 2.0),
        (25.0, 9.0),
        (35.0, 8.0),
    ]
    assert stitch(older, []) == older
    assert stitch([], [(1.0, 1.0)]) == [(1.0, 1.0)]


def test_the_stored_part_fills_only_the_holes_of_the_live_part() -> None:
    older = [(30.0, 1.0), (90.0, 2.0), (150.0, 3.0), (210.0, 4.0)]
    newer = [(0.0, 9.0), (10.0, 9.0), (200.0, 8.0)]
    assert fill_gaps(older, newer, 30) == [
        (0.0, 9.0),
        (10.0, 9.0),
        (90.0, 2.0),
        (150.0, 3.0),
        (200.0, 8.0),
    ]
    assert fill_gaps(older, [], 30) == older
    assert fill_gaps([], newer, 30) == newer


# ---- the collector's recent view ----------------------------------------------


def _collector() -> SflowCollector:
    collector = SflowCollector()
    collector.set_agents({AGENT: 1})
    return collector


def test_nothing_recent_before_a_sample_is_heard() -> None:
    recent = _collector().recent_vlans(1, now=1000.0)
    assert recent.series == {} and recent.since == 0.0


def test_recent_points_are_ten_seconds_apart_and_average_the_last_thirty() -> None:
    collector = _collector()
    # 1500-byte frames at the default rate of 4096: 6,144,000 bytes each. The first
    # frame (another VLAN) sets where the view begins; VLAN 10's is well inside it.
    collector.receive(_one(vlan=20, size=1500), now=1000.0, sender=AGENT)
    collector.receive(_one(vlan=10, size=1500), now=1050.0, sender=AGENT)
    recent = collector.recent_vlans(1, now=1100.0)
    points = recent.series["10"]
    steps = [b[0] - a[0] for a, b in zip(points, points[1:], strict=False)]
    assert steps and set(steps) == {10.0}
    assert points[-1][0] == 1100.0  # the slot still open is not drawn
    carrying = [value for _, value in points if value]
    assert len(carrying) == 3  # one slot counts in the three points that average it
    assert carrying[0] == 1500 * 4096 * 8 / 30
    # Each VLAN's line begins at its own first frame (as the stored one does).
    assert recent.since == recent.series["20"][0][0] < points[0][0]


def test_recent_view_drops_what_is_older_than_the_window() -> None:
    collector = _collector()
    collector.receive(_one(vlan=10), now=1000.0, sender=AGENT)
    later = 1000.0 + RECENT_KEEP_SECONDS + 100
    collector.receive(_one(vlan=20), now=later, sender=AGENT)
    recent = collector.recent_vlans(1, now=later + 20)
    assert "10" not in recent.series and "20" in recent.series
    # Another switch has none of it.
    assert collector.recent_vlans(2, now=later + 20).series == {}


# ---- the cards and charts -------------------------------------------------------


@pytest.fixture
def db(tmp_path) -> sqlite3.Connection:
    path = tmp_path / "nxray.db"
    init_db(path)
    with open_db(path) as conn:
        yield conn


def test_live_cards_come_from_the_collector_with_the_stored_minutes_before(
    db: sqlite3.Connection,
) -> None:
    now = time.time()
    collector = _collector()
    collector.receive(_one(vlan=10, size=1500), now=now - 120, sender=AGENT)
    minute = int(now // 60) * 60 - 1800
    store_rows(db, [SflowRow(1, minute, VLAN, "20", 6000, 1)])
    cards = vlan_cards(db, 1, LIVE, now, collector)
    assert {card.label for card in cards} == {"VLAN 10", "VLAN 20"}
    assert all(card.now and card.highest and card.average for card in cards)
    assert 'class="chart-area s0"' in str(cards[0].svg)


def test_live_cards_still_draw_the_stored_minutes_without_a_collector(
    db: sqlite3.Connection,
) -> None:
    now = time.time()
    store_rows(db, [SflowRow(1, int(now // 60) * 60 - 300, VLAN, "20", 6000, 1)])
    assert [card.label for card in vlan_cards(db, 1, LIVE, now, None)] == ["VLAN 20"]
    assert vlan_cards(db, 2, LIVE, now, None) == []


def _port(up: bool = True, vlan: int | None = None, rate: int = 1_000_000) -> PortFigures:
    return PortFigures(up, rate, rate, rate, rate // 2, vlan)


def test_live_system_charts_draw_the_trails(db: sqlite3.Connection) -> None:
    now = time.time()
    health = [
        (now - 10 * n, HealthFigures(20.0 + n, 50.0, 300.0, 40.0, (("Sensor 1", 30.0 + n),)))
        for n in range(5)
    ]
    ports = [
        (now - 10 * n, {"Ethernet1/1": _port(), "Ethernet1/2": _port(vlan=5)}) for n in range(5)
    ]
    charts = live_system_charts(db, 1, health[::-1], ports[::-1], now)
    assert [c.title for c in charts] == [
        "Temperatures",
        "CPU and memory",
        "Power draw",
        "Fan speed",
        "Traffic through all ports",
    ]
    assert all(c.svg is not None for c in charts)


def test_live_system_charts_have_no_line_for_a_reading_without_rates(
    db: sqlite3.Connection,
) -> None:
    now = time.time()
    unmeasured = {"Ethernet1/1": PortFigures(True, 5, 5, None, None, None)}
    traffic = live_system_charts(db, 1, [], [(now - 5, unmeasured)], now)[-1]
    assert traffic.svg is None


def test_live_vlan_charts_add_up_each_vlans_access_ports(db: sqlite3.Connection) -> None:
    now = time.time()
    ports = [
        (
            now - 10 * n,
            {
                "Ethernet1/1": _port(vlan=5),
                "Ethernet1/2": _port(vlan=5),
                "Ethernet1/3": _port(up=False, vlan=7),
                "Ethernet1/4": _port(vlan=None),
            },
        )
        for n in (3, 2, 1)
    ]
    charts = live_vlan_charts(db, 1, ports, now)
    assert len(charts) == 2
    labels = {entry.label for chart in charts for entry in chart.legend}
    assert labels == {"VLAN 5"}  # the port that is down and the one in no access VLAN add none


# ---- the pages ----------------------------------------------------------------


def test_the_history_page_opens_on_live_and_asks_for_its_own_small_answer(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    page = logged_in.get("/history").text
    assert 'data-live-url="/live/history"' in page
    assert 'data-live-region="history-live"' in page
    assert "data-live-whole" not in page
    assert '<option value="live" selected>' in page  # the browser's choice was Off
    assert "Live, 40 minutes" in page
    # The fake switch's ports are all down, so there is no traffic to draw.
    assert page.count('<svg class="chart"') == 4


def test_a_stored_range_of_the_history_page_refreshes_whole_as_before(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    page = logged_in.get("/history?range=1h").text
    assert "data-live-whole" in page and "/live/history" not in page
    assert 'data-live-region="history-live"' not in page
    assert '<option value="off" selected>' in page


def test_the_live_history_answer_is_the_charts_alone(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    answer = logged_in.get("/live/history")
    assert answer.status_code == 200
    assert answer.headers["cache-control"] == "no-store"
    assert answer.text.count('data-live-region="history-live"') == 1
    assert "<html" not in answer.text and 'data-live-at="' in answer.text
    assert answer.text.count('<svg class="chart"') == 4


def test_the_live_answers_need_a_login_and_a_switch(client: TestClient) -> None:
    for path in ("/live/history", "/live/traffic"):
        assert client.get(path, follow_redirects=False).status_code in (303, 401)


def test_the_live_answers_are_empty_without_a_switch(logged_in: TestClient) -> None:
    assert logged_in.get("/live/history").status_code == 204


def test_the_traffic_page_opens_on_live_and_its_answer_is_the_cards_alone(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    now = time.time()
    collector: SflowCollector = logged_in.app.state.sflow_collector  # type: ignore[attr-defined]
    collector.set_agents({AGENT: 1})
    collector.receive(_one(vlan=10, size=1500), now=now - 60, sender=AGENT)
    page = logged_in.get("/traffic").text
    assert 'data-live-url="/live/traffic"' in page and "Live, 40 minutes" in page
    assert 'data-live-region="vlan-cards"' in page and "VLAN 10" in page
    answer = logged_in.get("/live/traffic")
    assert answer.status_code == 200 and "<html" not in answer.text
    assert answer.text.count('data-live-region="vlan-cards"') == 1 and "VLAN 10" in answer.text
    assert answer.headers["cache-control"] == "no-store"
    # Another range is drawn from the stored minutes and refreshes whole.
    stored = logged_in.get("/traffic?range=1h").text
    assert "/live/traffic" not in stored and "data-live-whole" in stored


def test_a_page_shown_after_a_form_does_not_refresh_as_live(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    from app.live import live_window_context

    class Posted:
        method = "POST"

    assert live_window_context(Posted(), LIVE, "/live/traffic") == {}
    assert live_window_context(Posted(), "1h", "/live/traffic") == {}
