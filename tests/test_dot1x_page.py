"""The 802.1X page, end to end against the fake switch: reading it with the feature off and
on, who may change it, and a change from asking to sent."""

from __future__ import annotations

import html
import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
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


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    """A switch that has been set up (read-only account nxray), dot1x off."""
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post("/switch/setup", data=_setup_form(logged_in))
    fake.requests.clear()
    return fake


@pytest.fixture
def on(switch: FakeSwitch) -> FakeSwitch:
    """dot1x on, answering with text shaped after Cisco's guide."""
    switch.feature_state["dot1x"] = True
    switch.texts["show dot1x"] = (FIXTURES / "show_dot1x_doc.txt").read_text()
    switch.texts["show dot1x all details"] = (
        FIXTURES / "show_dot1x_all_details_doc.txt"
    ).read_text()
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
    return client.post("/dot1x/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/dot1x", follow_redirects=False).status_code == 303


def test_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/dot1x").text)


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/dot1x"' in logged_in.get("/").text


def test_with_the_feature_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/dot1x")
    assert page.status_code == 200
    assert "off on the switch, so 802.1X is not running" in _text(page.text)
    assert switch.requests == [["show feature", "show interface brief"]]


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "dot1x"})
    assert saved.status_code == 200
    assert "Signed-in devices" in _text(saved.text) and enabled.saved


def test_page_reads_the_switch(logged_in: TestClient, on: FakeSwitch) -> None:
    page = logged_in.get("/dot1x")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "00:00:5E:00:53:01" in text and "MULTI AUTH" in text and "Remote Server" in text
    assert on.requests == [
        ["show feature", "show interface brief"],
        ["show dot1x"],
        ["show dot1x all details"],
    ]
    assert "/dot1x/change" not in page.text  # changes are off


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
    assert "802.1X changes are off" in _text(logged_in.get("/dot1x").text)
    refused = _change(
        logged_in,
        scope="dot1x_port",
        setting="port_control",
        action="set",
        id_port="Ethernet1/5",
        v_control="auto",
    )
    assert refused.status_code == 400
    assert _config_requests(on) == []


def test_enabled_page_offers_the_settings(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/dot1x")
    for setting in ("auth_group", "system_auth", "port_control", "host_mode", "mab", "timeout"):
        assert f'name="setting" value="{setting}"' in page.text
    assert '<option value="port-channel' not in page.text


def test_port_control_asks_first_and_warns(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {
        "scope": "dot1x_port",
        "setting": "port_control",
        "action": "set",
        "id_port": "Ethernet1/5",
        "v_control": "auto",
    }
    asked = _change(logged_in, confirm=False, **fields)
    assert asked.status_code == 200
    assert "dot1x port-control auto" in _text(asked.text) and "cut off" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["interface Ethernet1/5", "dot1x port-control auto"]]


def test_the_radius_group_and_a_timer(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(
        logged_in, scope="dot1x_switch", setting="auth_group", action="set", v_group="radius"
    )
    assert done.status_code == 200, _text(done.text)
    done = _change(
        logged_in,
        scope="dot1x_port",
        setting="timeout",
        action="set",
        id_port="Ethernet1/5",
        v_timer="tx-period",
        v_seconds="10",
    )
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [
        ["aaa authentication dot1x default group radius"],
        ["interface Ethernet1/5", "dot1x timeout tx-period 10"],
    ]


def test_a_port_channel_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _change(
        logged_in,
        scope="dot1x_port",
        setting="port_control",
        action="set",
        id_port="port-channel20",
        v_control="auto",
    )
    assert refused.status_code == 400
    assert _config_requests(enabled) == []
