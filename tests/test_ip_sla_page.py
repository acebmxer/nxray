"""The IP SLA page, end to end against the fake switch: reading it with sla sender off and
on, who may change it, and changes from asking to sent."""

from __future__ import annotations

import html
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _db(settings: Settings, sql: str) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(sql)
    conn.commit()
    conn.close()


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


def _setup_form(client: TestClient, **extra: str) -> dict[str, str]:
    return {
        "csrf": _csrf(client, "/switch"),
        "host": "192.0.2.10",
        "port": "443",
        "admin_user": "admin",
        "admin_password": ADMIN_PASSWORD,
        "account_name": "nxray",
        "confirm_save": "yes",
        **extra,
    }


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    """A switch that has been set up (read-only account nxray), sla sender off."""
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post("/switch/setup", data=_setup_form(logged_in))
    fake.requests.clear()
    return fake


@pytest.fixture
def on(switch: FakeSwitch) -> FakeSwitch:
    """sla sender on, with the entries recorded on cisco-25gb."""
    switch.feature_state["sla_sender"] = True
    switch.bodies["show ip sla configuration"] = load_fixture("show_ip_sla_configuration")
    switch.bodies["show ip sla statistics details"] = load_fixture(
        "show_ip_sla_statistics_details_results"
    )
    switch.sla_lines += [
        "ip sla 9001 ; icmp-echo 192.0.2.1",
        "ip sla 9001 ; frequency 30",
        "ip sla schedule 9001 life 300 start-time now",
        "ip sla reaction-configuration 9001 react timeout threshold-type immediate",
        "ip sla 9002 ; udp-jitter 192.0.2.1 5000 num-packets 5",
    ]
    return switch


@pytest.fixture
def enabled(logged_in: TestClient, on: FakeSwitch, settings: Settings) -> FakeSwitch:
    """Changes on with the broad role, and the wait over."""
    response = logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "role_mode": "broad",
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    on.requests.clear()
    on.saved = False
    return on


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/ip-sla/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/ip-sla", follow_redirects=False).status_code == 303


def test_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/ip-sla").text)


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/ip-sla"' in logged_in.get("/").text


def test_with_the_feature_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/ip-sla")
    assert page.status_code == 200, _text(page.text)
    assert "sla sender is off on the switch" in _text(page.text)
    assert switch.requests == [["show feature", "show vrf"]]


def test_page_reads_the_switch(logged_in: TestClient, on: FakeSwitch) -> None:
    page = logged_in.get("/ip-sla")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "9001 icmp-echo 192.0.2.1 default 30 s Active Timeout 0 / 1" in text
    assert "life 300 start-time now" in text
    assert on.requests[1] == ["show ip sla configuration", "show ip sla statistics details"]
    assert on.requests[2] == ["show running-config sla sender"]
    assert "/ip-sla/change" not in page.text  # changes are off


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, on: FakeSwitch, settings: Settings
) -> None:
    logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    on.requests.clear()
    assert "IP SLA changes are off" in _text(logged_in.get("/ip-sla").text)
    refused = _change(
        logged_in,
        scope="entry",
        setting="icmp_echo",
        action="set",
        id_entry="10",
        v_target="192.0.2.1",
    )
    assert refused.status_code == 400
    assert _config_requests(on) == []


def test_enabled_page_offers_the_settings(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/ip-sla")
    for setting in ("icmp_echo", "udp_jitter", "http", "frequency", "vrf", "schedule", "reaction"):
        assert f'name="setting" value="{setting}"' in page.text
    assert '<option value="management"' in page.text


def test_making_an_entry_asks_first_then_sends(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {
        "scope": "entry",
        "setting": "icmp_echo",
        "action": "set",
        "id_entry": "10",
        "v_target": "192.0.2.1",
    }
    asked = _change(logged_in, confirm=False, **fields)
    assert asked.status_code == 200
    assert "icmp-echo 192.0.2.1" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["ip sla 10", "icmp-echo 192.0.2.1"]]
    assert "ip sla 10 ; icmp-echo 192.0.2.1" in enabled.sla_lines


def test_a_running_entry_refuses_changes(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _change(
        logged_in,
        scope="entry",
        setting="frequency",
        action="set",
        id_entry="9001",
        v_seconds="20",
    )
    assert refused.status_code == 400
    assert "Entry already running" in _text(refused.text)
    removed = _change(
        logged_in, scope="schedule", setting="schedule", action="remove", id_sla="9001"
    )
    assert removed.status_code == 200, _text(removed.text)
    done = _change(
        logged_in,
        scope="entry",
        setting="frequency",
        action="set",
        id_entry="9001",
        v_seconds="20",
    )
    assert done.status_code == 200, _text(done.text)
    assert "ip sla 9001 ; frequency 20" in enabled.sla_lines


def test_a_schedule_for_an_entry_the_switch_lacks_is_refused(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    refused = _change(
        logged_in,
        scope="schedule",
        setting="schedule",
        action="set",
        id_sla="77",
        v_start="now",
    )
    assert refused.status_code == 400
    assert "no IP SLA entry 77" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_a_reaction_is_sent(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(
        logged_in,
        scope="reaction",
        setting="reaction",
        action="set",
        id_sla="9002",
        v_event="jitterAvg",
        v_upper="10",
        v_lower="5",
        v_when="xofy",
        v_count="3",
        v_of="5",
        v_action="triggerOnly",
    )
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [
        [
            "ip sla reaction-configuration 9002 react jitterAvg threshold-value 10 5 "
            "threshold-type xofy 3 5 action-type triggerOnly"
        ]
    ]


def test_deleting_an_entry_takes_its_schedule_and_reactions(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    done = _change(logged_in, scope="entry", action="delete", id_entry="9001")
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["no ip sla 9001"]]
    assert not any("9001" in line for line in enabled.sla_lines)


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _change(
        logged_in,
        scope="entry",
        setting="icmp_echo",
        action="set",
        id_entry="10",
        v_target="192.0.2.1",
    )
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "ip-sla"})
    assert saved.status_code == 200
    assert "IP SLA" in _text(saved.text) and enabled.saved
