"""Figures that refresh themselves: the shared cache, the intervals, the dashboard answer."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import ConfigError, load_settings
from app.db import open_db
from app.live import LIVE_CHOICES, LiveCache, measure_rates, pick_interval
from app.ports import Port, parse_ports
from app.preferences import LIVE_COOKIE
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _reader(calls: list[object], problem: str = "") -> Callable[[object], tuple[object, str]]:
    def read(previous: object) -> tuple[object, str]:
        calls.append(previous)
        return (f"reading {len(calls)}", "") if not problem else (None, problem)

    return read


def test_the_cache_reads_the_switch_once_per_floor() -> None:
    clock = Clock()
    cache, calls = LiveCache(clock), []
    for _ in range(5):
        answer = cache.get(1, "ports", 2, _reader(calls))
    assert len(calls) == 1 and answer.value == "reading 1"
    clock.now += 2
    assert cache.get(1, "ports", 2, _reader(calls)).value == "reading 2"
    # The reader gets the last good value to work a rate out from.
    assert calls == [None, "reading 1"]


def test_each_switch_and_kind_has_its_own_answer() -> None:
    cache, calls = LiveCache(Clock()), []
    cache.get(1, "ports", 2, _reader(calls))
    cache.get(2, "ports", 2, _reader(calls))
    cache.get(1, "clients", 10, _reader(calls))
    assert len(calls) == 3


def test_a_failing_switch_is_left_alone_for_longer_each_time() -> None:
    clock = Clock()
    cache, calls = LiveCache(clock), []
    good = cache.get(1, "ports", 2, _reader(calls))
    clock.now += 2
    bad = cache.get(1, "ports", 2, _reader(calls, "timed out"))
    assert bad.problem == "timed out" and bad.value == good.value and bad.retry_in == 4
    # Asking again at once does not reach the switch.
    cache.get(1, "ports", 2, _reader(calls, "timed out"))
    assert len(calls) == 2
    clock.now += 4
    again = cache.get(1, "ports", 2, _reader(calls, "timed out"))
    assert len(calls) == 3 and again.retry_in == 8
    clock.now += 8
    healed = cache.get(1, "ports", 2, _reader(calls))
    assert healed.problem == "" and healed.value == "reading 4"


def test_the_wait_after_failures_is_capped() -> None:
    clock = Clock()
    cache, calls = LiveCache(clock), []
    for _ in range(12):
        answer = cache.get(1, "ports", 2, _reader(calls, "down"))
        clock.now += 100
    assert answer.retry_in <= 60


def test_an_answer_nobody_asks_for_is_dropped() -> None:
    clock = Clock()
    cache, calls = LiveCache(clock), []
    cache.get(1, "ports", 2, _reader(calls))
    clock.now += 1000
    cache.get(2, "ports", 2, _reader(calls))
    assert (1, "ports") not in cache._entries


def test_intervals_never_go_below_the_floor() -> None:
    assert pick_interval("off", 2) == 0
    assert pick_interval("nonsense", 2) == 0
    assert pick_interval("live", 2) == 2
    assert pick_interval("3", 2) == 3
    assert pick_interval("3", 10) == 10
    assert pick_interval("live", 10) == 10
    assert pick_interval("60", 10) == 60
    assert list(LIVE_CHOICES) == ["off", "live", "3", "5", "10", "15", "30", "60"]


def test_the_floors_come_from_the_environment(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("NXRAY_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NXRAY_ADMIN_PASSWORD_HASH", "$argon2id$x")
    assert load_settings().live_min_interval == 2
    assert load_settings().live_clients_min_interval == 10
    monkeypatch.setenv("NXRAY_LIVE_MIN_INTERVAL", "5")
    monkeypatch.setenv("NXRAY_LIVE_CLIENTS_MIN_INTERVAL", "30")
    assert load_settings().live_min_interval == 5
    assert load_settings().live_clients_min_interval == 30
    monkeypatch.setenv("NXRAY_LIVE_MIN_INTERVAL", "0")
    with pytest.raises(ConfigError):
        load_settings()


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


def _csrf(client: TestClient) -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get("/account").text)
    assert match
    return match.group(1)


def test_the_picker_remembers_the_interval_and_starts_off(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    page = logged_in.get("/").text
    assert 'data-live-picker data-live-url="/live/dashboard"' in page
    assert '<option value="off" selected>' in page
    assert "/static/live.js" in page
    logged_in.post("/preferences", data={"csrf": _csrf(logged_in), "live": "5"})
    assert logged_in.cookies.get(LIVE_COOKIE) == "5"
    assert '<option value="5" selected>' in logged_in.get("/").text
    logged_in.post("/preferences", data={"csrf": _csrf(logged_in), "live": "7"})
    assert logged_in.cookies.get(LIVE_COOKIE) == "5"


def test_pages_without_live_figures_have_no_picker(logged_in: TestClient) -> None:
    page = logged_in.get("/account").text
    assert "data-live-picker" not in page and "live.js" not in page


def test_the_dashboard_answer_is_the_figures_alone(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    response = logged_in.get("/live/dashboard")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.text.lstrip().startswith('<div data-live-region="health"')
    assert "<html" not in response.text and "Temperatures" in response.text


def test_many_asks_cost_the_switch_one_read(logged_in: TestClient, switch: FakeSwitch) -> None:
    for _ in range(6):
        assert logged_in.get("/live/dashboard").status_code == 200
    assert len(switch.requests) == 1
    assert all(cmd.startswith("show") for cmd in switch.requests[0])


def test_a_silent_switch_keeps_the_old_figures_and_says_so(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    logged_in.get("/live/dashboard")
    cache = logged_in.app.state.live_cache  # type: ignore[attr-defined]
    for entry in cache._entries.values():
        entry.read_at -= 100

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    logged_in.app.state.nxapi_transport = httpx.MockTransport(refuse)  # type: ignore[attr-defined]
    text = logged_in.get("/live/dashboard").text
    assert "The switch did not answer" in text and "Trying again in" in text
    assert "data-live-problem" in text
    assert "Temperatures" in text  # the last good figures stay


def test_no_switch_set_up_is_an_empty_answer(logged_in: TestClient) -> None:
    assert logged_in.get("/live/dashboard").status_code == 204


def test_a_signed_out_page_is_sent_to_the_sign_in_page(client: TestClient) -> None:
    response = client.get("/live/dashboard")
    assert response.status_code == 303 and response.headers["location"].startswith("/login")


def test_refreshing_does_not_extend_the_session(logged_in: TestClient, switch: FakeSwitch) -> None:
    path = logged_in.app.state.settings.db_path  # type: ignore[attr-defined]
    with open_db(path) as conn:
        conn.execute("UPDATE sessions SET expires_at = ?", (time.time() + 60,))
        conn.commit()
    logged_in.get("/live/dashboard")
    with open_db(path) as conn:
        assert conn.execute("SELECT expires_at FROM sessions").fetchone()[0] < time.time() + 120
    logged_in.get("/")  # an ordinary page does slide it
    with open_db(path) as conn:
        assert conn.execute("SELECT expires_at FROM sessions").fetchone()[0] > time.time() + 3600


def _ports() -> list[Port]:
    """The recorded ports, the first one made an up port with some traffic counted."""
    ports = parse_ports(
        load_fixture("show_interface"),
        load_fixture("show_interface_status"),
        load_fixture("show_interface_transceiver"),
    )
    return [replace(ports[0], up=True, in_bytes=10_000, out_bytes=20_000), *ports[1:]]


def test_live_rates_come_from_the_change_in_the_byte_counters() -> None:
    ports = _ports()
    up = ports[0]
    first = measure_rates(None, ports, 100.0)
    assert first.window == 0 and first.live is ports
    moved = [
        replace(p, in_bytes=p.in_bytes + 1250, out_bytes=p.out_bytes + 2500) if p is up else p
        for p in ports
    ]
    second = measure_rates(first, moved, 102.0)
    assert second.window == 2.0
    live = next(p for p in second.live if p.name == up.name)
    assert (live.in_bits_per_second, live.out_bits_per_second) == (5000, 10000)
    # The switch's own figures stay available beside them.
    same = next(p for p in second.ports if p.name == up.name)
    assert same.in_bits_per_second == up.in_bits_per_second


def test_live_rates_leave_alone_what_cannot_be_measured() -> None:
    ports = _ports()
    up = ports[0]
    first = measure_rates(None, ports, 100.0)
    cleared = [replace(p, in_bytes=0, out_bytes=0) if p is up else p for p in ports]
    kept = next(p for p in measure_rates(first, cleared, 102.0).live if p.name == up.name)
    assert kept.in_bits_per_second == up.in_bits_per_second
    # Too long a gap (nobody was watching) gives no rate at all.
    assert measure_rates(first, ports, 100.0 + 10_000).window == 0
    assert measure_rates(first, ports, 100.0).window == 0


def test_the_ports_page_offers_live_figures(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/ports?show=up&color=traffic").text
    assert 'data-live-url="/live/ports?show=up&amp;color=traffic"' in page
    for name in ("banner", "kpis", "face", "rows", "ratenote"):
        assert f'data-live-region="{name}"' in page
    assert "average over the last 30 seconds" in page


def test_the_ports_answer_carries_each_region_once(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    response = logged_in.get("/live/ports?show=all&color=state")
    assert response.status_code == 200 and "<html" not in response.text
    for name in ("banner", "kpis", "face", "rows", "ratenote"):
        assert response.text.count(f'data-live-region="{name}"') == 1
    assert "Ethernet1/1" in response.text


def test_ports_asks_cost_the_switch_one_read_each_for_ports_and_clients(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    for _ in range(5):
        assert logged_in.get("/live/ports").status_code == 200
    reads = [cmd for batch in switch.requests for cmd in batch]
    assert reads.count("show interface") == 1
    assert all(cmd.startswith("show") for cmd in reads)


def test_the_vlan_colouring_is_left_out_of_the_ports_answer(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    text = logged_in.get("/live/ports?color=vlan").text
    assert 'data-live-region="face"' not in text and 'data-live-region="rows"' in text


def test_a_result_page_is_never_refreshed(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/ports?select=all").text
    assert "data-live-picker" not in page


def test_a_port_page_offers_live_figures(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/ports/detail?name=Ethernet1/1").text
    assert 'data-live-url="/live/port?name=Ethernet1%2F1"' in page
    for name in ("banner", "port-state", "traffic", "counters", "ratenote"):
        assert f'data-live-region="{name}"' in page


def test_the_port_answer_carries_each_region_once(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    response = logged_in.get("/live/port?name=Ethernet1/1")
    assert response.status_code == 200 and "<html" not in response.text
    for name in ("banner", "port-state", "traffic", "counters", "devices-macs", "ratenote"):
        assert response.text.count(f'data-live-region="{name}"') == 1, name
    assert logged_in.get("/live/port?name=Ethernet9/99").status_code == 204


def test_the_neighbors_page_offers_live_figures(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/neighbors?q=0c").text
    assert 'data-live-url="/live/neighbors?q=0c"' in page
    for name in ("banner", "announced", "busiest", "macs"):
        assert f'data-live-region="{name}"' in page


def test_the_neighbors_answer_follows_the_search(logged_in: TestClient, switch: FakeSwitch) -> None:
    everything = logged_in.get("/live/neighbors").text
    nothing = logged_in.get("/live/neighbors?q=zzzz-no-such").text
    for name in ("banner", "announced", "busiest", "macs"):
        assert everything.count(f'data-live-region="{name}"') == 1
    assert 'No entry matches "zzzz-no-such"' in nothing and "<html" not in everything


def test_clients_are_read_at_the_slower_pace(logged_in: TestClient, switch: FakeSwitch) -> None:
    logged_in.get("/live/ports")
    first = len(switch.requests)
    cache = logged_in.app.state.live_cache  # type: ignore[attr-defined]
    # Ports read 5 s ago: the Ports page would read again (floor 2 s), the
    # Neighbors page, with its 10 s floor for clients, does not.
    for entry in cache._entries.values():
        entry.read_at -= 5
    logged_in.get("/live/neighbors")
    assert len(switch.requests) == first
    logged_in.get("/live/ports")
    assert len(switch.requests) > first
