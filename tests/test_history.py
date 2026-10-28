"""History: what a sample stores, how it is read back, and the pages that draw it."""

from __future__ import annotations

import dataclasses
import re
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from app import history
from app.config import Settings
from app.db import init_db, open_db
from app.ports import parse_ports
from app.switch import parse_environment, parse_resources
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

HOUR = 3600


def _parsed(errors_on_3: int = 0, up: tuple[str, ...] = ("Ethernet1/3",)):
    interfaces = load_fixture("show_interface")
    for row in interfaces["TABLE_interface"]["ROW_interface"]:
        if row["interface"] in up:
            row.update(
                {
                    "state": "up",
                    "eth_inrate1_bits": "8000000",
                    "eth_outrate1_bits": "2000000",
                    "eth_inerr": str(errors_on_3),
                }
            )
    return (
        parse_environment(load_fixture("show_environment")),
        parse_resources(load_fixture("show_system_resources")),
        parse_ports(interfaces, {}, {}),
    )


def _by_metric(rows):
    found: dict[str, list[tuple[str, float]]] = {}
    for metric, item, value in rows:
        found.setdefault(metric, []).append((item, value))
    return found


def test_a_sample_holds_every_kind_of_number() -> None:
    rows, _ = history.build_rows(*_parsed(), {})
    found = _by_metric(rows)
    for metric in (
        history.TEMPERATURE,
        history.CPU,
        history.MEMORY,
        history.POWER,
        history.FAN,
        history.TRAFFIC_IN,
        history.TRAFFIC_OUT,
    ):
        assert metric in found, metric
    assert [item for item, _ in found[history.TEMPERATURE]]  # named by sensor


def test_only_ports_that_are_up_get_traffic_rows() -> None:
    rows, _ = history.build_rows(*_parsed(), {})
    found = _by_metric(rows)
    assert found[history.PORT_IN] == [("Ethernet1/3", 8_000_000.0)]
    assert found[history.PORT_OUT] == [("Ethernet1/3", 2_000_000.0)]


def test_total_traffic_adds_up_every_port() -> None:
    rows, _ = history.build_rows(*_parsed(up=("Ethernet1/3", "Ethernet1/4")), {})
    found = _by_metric(rows)
    assert found[history.TRAFFIC_IN] == [("", 16_000_000.0)]
    assert found[history.TRAFFIC_OUT] == [("", 4_000_000.0)]


def test_errors_are_stored_as_the_increase_since_the_last_sample() -> None:
    _, totals = history.build_rows(*_parsed(errors_on_3=4), {})
    assert totals["Ethernet1/3"] == 4
    rows, totals = history.build_rows(*_parsed(errors_on_3=9), totals)
    assert _by_metric(rows)[history.PORT_ERRORS] == [("Ethernet1/3", 5.0)]
    assert totals["Ethernet1/3"] == 9


def test_the_first_sample_stores_no_errors_for_want_of_a_baseline() -> None:
    rows, _ = history.build_rows(*_parsed(errors_on_3=40), {})
    assert history.PORT_ERRORS not in _by_metric(rows)


def test_no_new_errors_and_cleared_counters_store_nothing() -> None:
    _, totals = history.build_rows(*_parsed(errors_on_3=9), {})
    same, _ = history.build_rows(*_parsed(errors_on_3=9), totals)
    cleared, _ = history.build_rows(*_parsed(errors_on_3=2), totals)
    assert history.PORT_ERRORS not in _by_metric(same)
    assert history.PORT_ERRORS not in _by_metric(cleared)


def test_rows_older_than_thirty_days_are_deleted(settings: Settings) -> None:
    init_db(settings.db_path)
    now = 1_700_000_000.0
    with open_db(settings.db_path) as conn:
        history.record(conn, now - 31 * 86400, [(history.CPU, "", 1.0)])
        history.record(conn, now - 29 * 86400, [(history.CPU, "", 2.0)])
        assert history.purge(conn, now) == 1
        left = conn.execute("SELECT value FROM history").fetchall()
    assert [row["value"] for row in left] == [2.0]


def test_read_series_averages_each_bucket(settings: Settings) -> None:
    init_db(settings.db_path)
    start = 1_700_000_000.0
    with open_db(settings.db_path) as conn:
        for offset, value in ((10, 10.0), (20, 30.0), (70, 50.0)):
            history.record(conn, start + offset, [(history.CPU, "", value)])
        series = history.read_series(conn, history.CPU, start=start, end=start + 120, bucket=60)
    assert series[""] == [(start + 30, 20.0), (start + 90, 50.0)]


def test_read_series_can_add_each_bucket_up(settings: Settings) -> None:
    init_db(settings.db_path)
    start = 1_700_000_000.0
    with open_db(settings.db_path) as conn:
        for offset in (10, 20):
            history.record(conn, start + offset, [(history.PORT_ERRORS, "Ethernet1/3", 3.0)])
        history.record(conn, start + 20, [(history.PORT_ERRORS, "Ethernet1/4", 7.0)])
        series = history.read_series(
            conn,
            history.PORT_ERRORS,
            start=start,
            end=start + 60,
            bucket=60,
            item="Ethernet1/3",
            total=True,
        )
    assert series == {"Ethernet1/3": [(start + 30, 6.0)]}


def test_missing_buckets_are_filled_with_zero() -> None:
    filled = history.fill_zeros([(150.0, 4.0)], 0, 300, 60)
    assert [value for _, value in filled] == [0.0, 0.0, 4.0, 0.0, 0.0]


def test_a_long_range_is_averaged_into_at_most_500_points() -> None:
    assert history.bucket_seconds(HOUR) == 60
    assert history.bucket_seconds(30 * 86400) * history.MAX_POINTS >= 30 * 86400
    assert history.bucket_seconds(30 * 86400) > 60


def test_an_unknown_range_falls_back_to_the_default() -> None:
    assert history.range_key("7d") == "7d"
    assert history.range_key("forever") == history.DEFAULT_RANGE
    assert history.range_key(None) == history.DEFAULT_RANGE


# ---- the sampler, against the pretend switch ----


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
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


def _rows(settings: Settings) -> list[tuple[str, str, float]]:
    with open_db(settings.db_path) as conn:
        return [
            (row["metric"], row["item"], row["value"])
            for row in conn.execute("SELECT metric, item, value FROM history")
        ]


def test_the_sampler_stores_one_sample_with_one_request(
    settings: Settings, switch: FakeSwitch
) -> None:
    sampler = history.Sampler(settings, switch.transport)
    assert sampler.sample_once() is None
    assert len(switch.requests) == 1  # all three commands in one NX-API request
    assert {metric for metric, _, _ in _rows(settings)} >= {history.CPU, history.TEMPERATURE}


def test_the_sampler_does_nothing_without_a_switch(
    settings: Settings, logged_in: TestClient
) -> None:
    assert history.Sampler(settings).sample_once() is None
    assert _rows(settings) == []


def test_the_sampler_leaves_the_switch_alone_while_a_role_is_applied(
    settings: Settings, switch: FakeSwitch
) -> None:
    with open_db(settings.db_path) as conn:
        conn.execute("UPDATE switch_connection SET paused_until = ?", (time.time() + 600,))
        conn.commit()
    assert history.Sampler(settings, switch.transport).sample_once() is None
    assert switch.requests == []
    assert _rows(settings) == []


def test_an_unreachable_switch_is_reported_and_nothing_is_stored(
    settings: Settings, switch: FakeSwitch
) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    sampler = history.Sampler(settings, lambda: httpx.MockTransport(refuse))
    message = sampler.sample_once()
    assert message and "192.0.2.10" in message
    assert _rows(settings) == []


def test_a_failed_sample_keeps_the_error_baseline(settings: Settings, switch: FakeSwitch) -> None:
    sampler = history.Sampler(settings, switch.transport)
    sampler.sample_once()
    before = dict(sampler._errors)
    assert before

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    sampler._transport = lambda: httpx.MockTransport(refuse)
    assert sampler.sample_once()
    assert sampler._errors == before


def test_history_off_starts_no_thread(settings: Settings) -> None:
    assert history.start_sampler(settings, lambda: None) is None


def test_the_thread_takes_a_sample_and_stops_when_told(
    settings: Settings, switch: FakeSwitch
) -> None:
    fast = dataclasses.replace(settings, history_interval=10)
    stop = history.start_sampler(fast, switch.transport)
    assert stop is not None
    try:
        deadline = time.time() + 5
        while not _rows(settings) and time.time() < deadline:
            time.sleep(0.05)
        assert _rows(settings)
    finally:
        stop.set()


# ---- the pages ----


def test_the_history_page_says_so_without_a_switch(logged_in: TestClient) -> None:
    body = logged_in.get("/history").text
    assert "No switch connected yet" in body


def test_the_history_page_has_a_chart_for_each_recorded_kind(
    settings: Settings, logged_in: TestClient, switch: FakeSwitch
) -> None:
    now = time.time()
    with open_db(settings.db_path) as conn:
        for minute in range(30):
            rows, _ = history.build_rows(*_parsed(), {})
            history.record(conn, now - minute * 60, rows)
    body = logged_in.get("/history").text
    for title in ("Temperatures", "CPU and memory", "Power draw", "Fan speed", "Traffic through"):
        assert title in body
    assert body.count("<svg") == 5
    assert "History is turned off" in body  # the test settings switch the sampler off


def test_the_range_links_pick_the_range_and_a_bad_one_is_ignored(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    page = logged_in.get("/history?range=7d").text
    assert re.search(r'filter filter-on" href="/history\?range=7d"', page)
    fallback = logged_in.get("/history?range=forever").text
    assert re.search(r'filter filter-on" href="/history\?range=24h"', fallback)


def test_a_range_with_no_rows_says_there_is_no_data(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    body = logged_in.get("/history").text
    assert "No data in this range yet." in body
    assert "<svg" not in body


def test_the_port_page_draws_that_ports_traffic_and_errors(
    settings: Settings, logged_in: TestClient, switch: FakeSwitch
) -> None:
    now = time.time()
    with open_db(settings.db_path) as conn:
        for minute in range(30):
            rows, _ = history.build_rows(*_parsed(), {})
            history.record(conn, now - minute * 60, rows)
        history.record(conn, now - 120, [(history.PORT_ERRORS, "Ethernet1/3", 4.0)])
    page = logged_in.get("/ports/detail?name=Ethernet1/3&range=6h").text
    assert "Traffic over time" in page
    assert "Errors and discards over time" in page
    assert page.count("<svg") == 2
    assert "4 in this range" in page
    assert re.search(r'filter filter-on" href="/ports/detail\?name=Ethernet1/3&amp;range=6h"', page)


def test_a_port_with_no_errors_says_so(
    settings: Settings, logged_in: TestClient, switch: FakeSwitch
) -> None:
    page = logged_in.get("/ports/detail?name=Ethernet1/3").text
    assert "No errors were recorded for this port in this range." in page


def test_numbers_in_the_legend_have_at_most_one_decimal() -> None:
    assert history._degrees(45.5591) == "45.6°C"
    assert history._percent(5.88) == "5.9%"
    assert history._watts(150.0) == "150 W"


def test_axis_rates_drop_a_needless_decimal() -> None:
    assert history._rate(500_000_000) == "500 Mb/s"
    assert history._rate(1_500_000_000) == "1.5 Gb/s"
