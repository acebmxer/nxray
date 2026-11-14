"""The Monitor sessions page, end to end against the fake switch: reading it, who may
change it, and a change from asking to sent."""

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
    """A switch that has been set up (read-only account nxray), with two sessions."""
    fake = FakeSwitch()
    fake.bodies["show monitor session all"] = load_fixture("show_monitor_session_all")
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post("/switch/setup", data=_setup_form(logged_in))
    fake.requests.clear()
    return fake


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
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
    switch.requests.clear()
    switch.saved = False
    return switch


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/monitor/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/monitor", follow_redirects=False).status_code == 303


def test_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/monitor").text)


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/monitor"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/monitor")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "Session 30" in text and "Session 31" in text
    assert "Session admin shut" in text and "Ethernet1/53" in text
    assert "10.250.250.1" in text
    assert switch.requests[0] == ["show interface brief", "show feature"]
    assert switch.requests[1] == ["show monitor session all"]
    assert "/monitor/change" not in page.text  # changes are off


def test_no_session_is_said_plainly(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.bodies["show monitor session all"] = {}
    assert "No monitor sessions" in _text(logged_in.get("/monitor").text)


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
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
    switch.requests.clear()
    assert "Monitor session changes are off" in _text(logged_in.get("/monitor").text)
    refused = _change(logged_in, scope="span", action="create", id_session="30")
    assert refused.status_code == 400
    assert "Monitor session changes are off" in _text(refused.text)
    assert _config_requests(switch) == []


def test_enabled_page_offers_the_settings(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/monitor")
    for setting in ("source_interface", "destination_interface", "destination_ip", "erspan_id"):
        assert f'name="setting" value="{setting}"' in page.text
    assert '<option value="Ethernet1/1"' in page.text


def test_make_a_session_asks_first_then_sends(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {"scope": "span", "action": "create", "id_session": "5"}
    asked = _change(logged_in, confirm=False, **fields)
    assert asked.status_code == 200
    assert "monitor session 5" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["monitor session 5"]]


def test_a_source_port_and_an_erspan_setting(logged_in: TestClient, enabled: FakeSwitch) -> None:
    source = _change(
        logged_in,
        scope="span",
        setting="source_interface",
        action="set",
        id_session="30",
        v_port="Ethernet1/54",
        v_direction="rx",
    )
    assert source.status_code == 200, _text(source.text)
    erspan = _change(
        logged_in,
        scope="erspan",
        setting="erspan_id",
        action="set",
        id_session="31",
        v_id="7",
    )
    assert erspan.status_code == 200, _text(erspan.text)
    assert _config_requests(enabled) == [
        ["monitor session 30", "source interface Ethernet1/54 rx"],
        ["monitor session 31 type erspan-source", "erspan-id 7"],
    ]


def test_destination_port_and_origin(logged_in: TestClient, enabled: FakeSwitch) -> None:
    port = _change(
        logged_in, scope="dest_port", setting="monitor", action="set", id_port="Ethernet1/53"
    )
    assert port.status_code == 200, _text(port.text)
    origin = _change(
        logged_in, scope="origin", setting="origin", action="set", v_address="192.0.2.1"
    )
    assert origin.status_code == 200, _text(origin.text)
    assert _config_requests(enabled) == [
        ["interface Ethernet1/53", "switchport monitor"],
        ["monitor erspan origin ip-address 192.0.2.1 global"],
    ]
    assert "192.0.2.1" in _text(logged_in.get("/monitor").text)


def test_a_port_the_switch_lacks_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _change(
        logged_in, scope="dest_port", setting="monitor", action="set", id_port="Ethernet1/99"
    )
    assert refused.status_code == 400
    assert _config_requests(enabled) == []
