"""The Private VLANs page, end to end against the fake switch: reading it with the feature
off and on, who may change it, and a change from asking to sent."""

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
    """A switch that has been set up (read-only account nxray), private-vlan off."""
    fake = FakeSwitch()
    fake.vlans.update({250: "VLAN0250", 251: "VLAN0251", 252: "VLAN0252"})
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post("/switch/setup", data=_setup_form(logged_in))
    fake.requests.clear()
    return fake


@pytest.fixture
def on(switch: FakeSwitch) -> FakeSwitch:
    """private-vlan on, with VLAN 250 primary, 251 isolated, 252 community and ports in them."""
    switch.feature_state["private-vlan"] = True
    switch.bodies["show interface switchport"] = load_fixture(
        "show_interface_switchport_private-vlan"
    )
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
    return client.post("/private-vlans/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/private-vlans", follow_redirects=False).status_code == 303


def test_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/private-vlans").text)


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/private-vlans"' in logged_in.get("/").text


def test_with_the_feature_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/private-vlans")
    assert page.status_code == 200, _text(page.text)
    assert "private-vlan is off on the switch" in _text(page.text)
    assert switch.requests == [["show feature", "show vlan brief", "show interface brief"]]


def test_page_reads_the_switch(logged_in: TestClient, on: FakeSwitch) -> None:
    page = logged_in.get("/private-vlans")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "250 251 isolated Ethernet1/51, Ethernet1/53 Ethernet1/52, Ethernet1/54" in text
    assert "Private-vlan" not in text and "trunk promiscuous" in text
    assert on.requests[1] == [
        "show vlan private-vlan type",
        "show vlan private-vlan",
        "show interface switchport",
    ]
    assert on.requests[2] == ["show interface private-vlan mapping"]
    assert "/private-vlans/change" not in page.text  # changes are off


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
    assert "Private VLAN changes are off" in _text(logged_in.get("/private-vlans").text)
    refused = _change(
        logged_in, scope="vlan", setting="type", action="set", id_vlan="250", v_type="primary"
    )
    assert refused.status_code == 400
    assert _config_requests(on) == []


def test_enabled_page_offers_the_settings(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/private-vlans")
    for setting in ("type", "association", "mode", "host", "mapping", "trunk_native"):
        assert f'name="setting" value="{setting}"' in page.text
    assert '<option value="250"' in page.text and '<option value="1"' not in page.text


def test_a_vlan_type_asks_first_then_sends(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {
        "scope": "vlan",
        "setting": "type",
        "action": "set",
        "id_vlan": "252",
        "v_type": "community",
    }
    asked = _change(logged_in, confirm=False, **fields)
    assert asked.status_code == 200
    assert "private-vlan community" in _text(asked.text)
    assert "can stop passing its traffic" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["vlan 252", "private-vlan community"]]
    assert "vlan 252 ; private-vlan community" in enabled.pvlan_lines


def test_a_host_port(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(
        logged_in,
        scope="port",
        setting="host",
        action="set",
        id_port="Ethernet1/5",
        v_primary="250",
        v_secondary="251",
    )
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [
        ["interface Ethernet1/5", "switchport private-vlan host-association 250 251"]
    ]


def test_a_vlan_the_switch_lacks_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _change(
        logged_in, scope="vlan", setting="type", action="set", id_vlan="300", v_type="primary"
    )
    assert refused.status_code == 400
    assert "make it on the VLANs page first" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_a_vlan_interface_the_switch_lacks_is_refused(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    refused = _change(
        logged_in,
        scope="svi",
        setting="mapping",
        action="set",
        id_interface="Vlan250",
        v_secondary="251",
    )
    assert refused.status_code == 400
    assert "make it on the Routing page first" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _change(logged_in, scope="vlan", setting="type", action="set", id_vlan="250", v_type="primary")
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "private-vlans"})
    assert saved.status_code == 200
    assert "Private VLANs" in _text(saved.text) and enabled.saved
