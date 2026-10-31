"""The Routing page: VLAN interfaces, routed ports and their addresses, end to end
against the fake switch."""

from __future__ import annotations

import html
import re
import sqlite3
import time

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


def _enable_changes(client: TestClient):
    return client.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(client, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    """A switch that has been set up (read-only account nxray), with VLAN 10."""
    fake = FakeSwitch()
    fake.vlans[10] = "Servers"
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": _csrf(logged_in, "/switch"),
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


def _vlan_interfaces_on(switch: FakeSwitch) -> None:
    """interface-vlan on, as the switch has it right after ``feature interface-vlan``."""
    switch.feature_state["interface-vlan"] = True
    switch.svis = {1}
    switch.port_state["Vlan1"] = {"routed": True, "admin_up": False}


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    """All changes on, the wait over, and VLAN interfaces on on the switch."""
    assert _enable_changes(logged_in).status_code == 200
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    _vlan_interfaces_on(switch)
    switch.requests.clear()
    switch.saved = False
    return switch


def _post(client: TestClient, path: str, confirm: bool = False, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post(path, data=data)


def _make_vlan10(client: TestClient, **fields):
    data = {
        "vlan": "10",
        "ipv4": "192.0.2.1/24",
        "ipv6": "2001:db8:a::1/64",
        "description": "servers gateway",
        "mtu": "",
        "enabled": "yes",
        **fields,
    }
    return _post(client, "/routing/vlan-interface/create", confirm=True, **data)


def test_page_says_when_vlan_interfaces_are_off(logged_in: TestClient, switch: FakeSwitch):
    response = logged_in.get("/routing")
    assert response.status_code == 200
    text = _text(response.text)
    assert "VLAN interfaces are off on the switch" in text
    assert "No front port or port-channel is routed" in text
    # Port changes are off, so no forms.
    assert "/routing/vlan-interface/create" not in response.text
    assert 'href="/routing"' in response.text  # in the menu


def test_make_change_and_delete_a_vlan_interface(logged_in: TestClient, enabled: FakeSwitch):
    page = logged_in.get("/routing").text
    assert "Make a VLAN interface" in page and 'value="10"' in page
    # Without confirm: the confirm page, nothing sent.
    ask = _post(
        logged_in, "/routing/vlan-interface/create", vlan="10", ipv4="192.0.2.1/24", ipv6="",
        description="", mtu="", enabled="yes",
    )  # fmt: skip
    assert "Make a VLAN interface for VLAN 10 (Vlan10)." in _text(ask.text)
    assert _config_requests(enabled) == []

    done = _make_vlan10(logged_in)
    assert done.status_code == 200
    assert "Done: Make a VLAN interface for VLAN 10" in _text(done.text)
    assert _config_requests(enabled)[-1] == [
        "interface vlan10",
        "ip address 192.0.2.1/24",
        "ipv6 address 2001:db8:a::1/64",
        "description servers gateway",
        "no shutdown",
    ]
    text = _text(done.text)
    assert "Vlan10" in text and "192.0.2.1/24" in text and "2001:db8:a::1/64" in text
    assert "servers gateway" in text

    changed = _post(
        logged_in, "/routing/vlan-interface/settings", confirm=True, vlan="10",
        ipv4="192.0.2.1/24", description="servers gateway", mtu="9000", state="off",
    )  # fmt: skip
    assert changed.status_code == 200
    assert _config_requests(enabled)[-1] == ["interface vlan10", "mtu 9000", "shutdown"]

    deleted = _post(logged_in, "/routing/vlan-interface/delete", confirm=True, vlan="10")
    assert deleted.status_code == 200
    assert _config_requests(enabled)[-1] == ["no interface vlan10"]
    assert 10 not in enabled.svis and 10 in enabled.vlans


def test_extra_addresses_on_a_vlan_interface(logged_in: TestClient, enabled: FakeSwitch):
    _make_vlan10(logged_in)
    added = _post(
        logged_in, "/routing/address/add", confirm=True, name="Vlan10", address="203.0.113.1/24"
    )
    assert added.status_code == 200
    assert _config_requests(enabled)[-1] == [
        "interface Vlan10",
        "ip address 203.0.113.1/24 secondary",
    ]
    refused = _post(
        logged_in, "/routing/address/remove", confirm=True, name="Vlan10", address="192.0.2.1/24"
    )
    assert refused.status_code == 400
    assert "remove its extra IPv4 addresses first" in _text(refused.text)
    removed = _post(
        logged_in, "/routing/address/remove", confirm=True, name="Vlan10", address="203.0.113.1/24"
    )
    assert removed.status_code == 200
    assert _config_requests(enabled)[-1] == [
        "interface Vlan10",
        "no ip address 203.0.113.1/24 secondary",
    ]
    overlap = _post(
        logged_in, "/routing/address/add", confirm=True, name="Vlan1", address="192.0.2.9/24"
    )
    assert overlap.status_code == 400 and "same network as 192.0.2.1/24 on Vlan10" in _text(
        overlap.text
    )


def test_refusals_before_anything_is_sent(logged_in: TestClient, enabled: FakeSwitch):
    for fields, words in (
        ({"vlan": "30"}, "create it on the VLANs page first"),
        ({"vlan": "1"}, "has a VLAN interface already"),
        ({"ipv6": "fe80::1/64"}, "link-local"),
        ({"ipv4": "2001:db8::1/64"}, "put the IPv6 address in the IPv6 box"),
        ({"mtu": "70000"}, "the MTU is a number"),
    ):
        response = _make_vlan10(logged_in, **fields)
        assert response.status_code == 400 and words in _text(response.text), words
    assert _config_requests(enabled) == []
    keep = _post(logged_in, "/routing/vlan-interface/delete", confirm=True, vlan="1")
    assert keep.status_code == 400 and "keeps the VLAN 1 interface" in _text(keep.text)


def test_vlans_page_links_and_refuses_deleting_a_vlan_with_an_interface(
    logged_in: TestClient, enabled: FakeSwitch
):
    page = logged_in.get("/vlans").text
    assert 'href="/routing?vlan=10"' in page
    _make_vlan10(logged_in)
    page = logged_in.get("/vlans").text
    assert 'href="/routing#Vlan10"' in page
    refused = _post(logged_in, "/vlans/delete", confirm=True, vlan_id="10")
    assert refused.status_code == 400
    assert "has a VLAN interface (Vlan10)" in _text(refused.text)
    assert 10 in enabled.vlans
    # ?vlan= picks that VLAN in the make form.
    _post(logged_in, "/routing/vlan-interface/delete", confirm=True, vlan="10")
    assert 'value="10" selected' in logged_in.get("/routing?vlan=10").text


def test_routed_port_addresses_and_back_to_switched(logged_in: TestClient, enabled: FakeSwitch):
    enabled.port_state["Ethernet1/54"] = {"routed": True, "ip": "198.51.100.1/24"}
    page = _text(logged_in.get("/routing").text)
    assert "Ethernet1/54" in page and "198.51.100.1/24" in page
    for address in ("198.51.100.2/24", "2001:db8:54::1/64"):
        response = _post(
            logged_in, "/routing/address/add", confirm=True, name="Ethernet1/54", address=address
        )
        assert response.status_code == 200, _text(response.text)[:3000]
    assert enabled.port_state["Ethernet1/54"]["secondaries"] == ["198.51.100.2/24"]
    assert enabled.port_state["Ethernet1/54"]["ipv6"] == ["2001:db8:54::1/64"]
    port = _text(logged_in.get("/ports/detail?name=Ethernet1/54").text)
    assert "Extra IPv4 addresses 198.51.100.2/24" in port
    assert "IPv6 addresses 2001:db8:54::1/64" in port

    switched = _post(
        logged_in, "/ports/settings", confirm=True, name="Ethernet1/54", layer="switched",
        ip_address="", mtu="1500",
    )  # fmt: skip
    assert switched.status_code == 200, _text(switched.text)
    assert _config_requests(enabled)[-1][:5] == [
        "interface Ethernet1/54",
        "no ip address 198.51.100.2/24 secondary",
        "no ipv6 address 2001:db8:54::1/64",
        "no ip address 198.51.100.1/24",
        "switchport",
    ]
    assert enabled.port_state["Ethernet1/54"]["routed"] is False


def test_viewer_can_look_but_not_change(
    logged_in: TestClient, enabled: FakeSwitch, make_client, settings: Settings
):
    _make_vlan10(logged_in)
    from app.db import open_db
    from app.users import create_user

    with open_db(settings.db_path) as conn:
        create_user(conn, "viewer1", "viewer-password-1", "viewer-password-1", "viewer")
    viewer = make_client(settings)
    viewer.app.state.nxapi_transport = enabled.transport()
    viewer.post("/login", data={"username": "viewer1", "password": "viewer-password-1"})
    page = viewer.get("/routing")
    assert page.status_code == 200 and "Vlan10" in page.text
    assert "/routing/vlan-interface/settings" not in page.text
    assert "can look at routing but not change it" in _text(page.text)
    response = viewer.post(
        "/routing/vlan-interface/delete",
        data={"csrf": _csrf(viewer), "vlan": "10", "confirm": "yes"},
    )
    assert response.status_code == 403
    assert 10 in enabled.svis


def test_an_older_role_offers_vlan_interface_changes_without_a_wait(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
):
    _db(settings, "UPDATE switch_connection SET role_version = 6")
    page = _text(logged_in.get("/routing").text)
    assert "VLAN interface changes are off" in page
    switch_page = _text(logged_in.get("/switch").text)
    assert "Turn on VLAN interface changes" in switch_page
    enabled.ssh_lines.clear()
    response = _enable_changes(logged_in)
    text = _text(response.text)
    assert "VLAN interface changes are on: nxray may now also make, change and delete VLAN" in text
    assert "there is no wait" in text
    # The role's port list gains the VLAN interfaces, so the check and save go over SSH.
    assert "permit interface Vlan1-4094" in enabled.ssh_lines
    assert enabled.ssh_lines[-1] == "copy running-config startup-config"
    assert "Make a VLAN interface" in logged_in.get("/routing").text


def test_save_config_from_the_routing_page_stays_there(logged_in: TestClient, enabled: FakeSwitch):
    _make_vlan10(logged_in)
    response = _post(logged_in, "/switch/save", back="routing")
    assert response.status_code == 200
    assert "<title>Routing" in response.text and enabled.saved
