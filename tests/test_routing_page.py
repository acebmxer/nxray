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
    """VLAN interfaces on on the switch, then all changes on and the wait over."""
    _vlan_interfaces_on(switch)
    assert _enable_changes(logged_in).status_code == 200
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
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
    assert "Turn on VLAN interface, VRF and static route changes" in switch_page
    enabled.ssh_lines.clear()
    response = _enable_changes(logged_in)
    text = _text(response.text)
    assert (
        "VLAN interface, VRF and static route changes are on: nxray may now also make, change and "
        "delete VLAN" in text
    )
    assert "there is no wait" in text
    # The role's port list gains the VLAN interfaces, so the check and save go over SSH.
    assert "permit interface Vlan1-254" in enabled.ssh_lines
    assert enabled.ssh_lines[-1] == "copy running-config startup-config"
    assert "Make a VLAN interface" in logged_in.get("/routing").text


def test_turning_on_with_interface_vlan_off_then_updating_the_port_list(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
):
    """Issue #10: the switch refuses "permit interface Vlan1-254" while
    interface-vlan is off, so the turn-on leaves it out and says what to do."""
    response = _enable_changes(logged_in)
    text = _text(response.text)
    assert response.status_code == 200 and "refused" not in text
    assert "turn interface-vlan on on the Features page, then press Update the port list" in text
    assert "vlan1-254" not in switch.roles["nxray-ports"].interfaces
    assert "rule 50 permit command conf t ; no interface Vlan *" in switch.ssh_lines
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    assert "NXray's role does not name the VLAN interfaces yet" in _text(
        logged_in.get("/switch").text
    )

    # interface-vlan on: the Routing page says the port list needs updating and
    # offers no VLAN interface forms; the VLAN interface changes are refused.
    _vlan_interfaces_on(switch)
    page = _text(logged_in.get("/routing").text)
    assert "does not name the VLAN interfaces yet" in page
    assert "Make a VLAN interface" not in page
    refused = _make_vlan10(logged_in)
    assert refused.status_code == 400 and "Update the port list" in _text(refused.text)
    assert _config_requests(switch) == []

    switch.ssh_lines.clear()
    updated = _text(_enable_changes(logged_in).text)
    assert "front ports the switch has now and the VLAN interfaces" in updated
    assert "permit interface Vlan1-254" in switch.ssh_lines
    assert switch.ssh_lines[-1] == "copy running-config startup-config"
    assert "vlan1-254" in switch.roles["nxray-ports"].interfaces
    assert "Make a VLAN interface" in logged_in.get("/routing").text
    assert _make_vlan10(logged_in).status_code == 200


def test_save_config_from_the_routing_page_stays_there(logged_in: TestClient, enabled: FakeSwitch):
    _make_vlan10(logged_in)
    response = _post(logged_in, "/switch/save", back="routing")
    assert response.status_code == 200
    assert "<title>Routing" in response.text and enabled.saved


def test_vrfs_make_move_and_delete(logged_in: TestClient, enabled: FakeSwitch):
    page = _text(logged_in.get("/routing").text)
    assert "default (the switch's own)" in page and "management (the switch's own)" in page
    assert "mgmt0" in page

    ask = _post(logged_in, "/routing/vrf/create", name="lab")
    assert "Make the VRF lab." in _text(ask.text) and _config_requests(enabled) == []
    made = _post(logged_in, "/routing/vrf/create", confirm=True, name="lab")
    assert made.status_code == 200 and _config_requests(enabled)[-1] == ["vrf context lab"]
    assert "lab" in enabled.vrfs and "Delete lab" in made.text

    _make_vlan10(logged_in)
    ask = _text(_post(logged_in, "/routing/vrf/move", name="Vlan10", vrf="lab").text)
    assert "Move Vlan10 from VRF default to VRF lab." in ask
    assert (
        "The switch deletes every address on Vlan10 when its VRF changes: 192.0.2.1/24, "
        "2001:db8:a::1/64." in ask
    )
    moved = _post(logged_in, "/routing/vrf/move", confirm=True, name="Vlan10", vrf="lab")
    assert moved.status_code == 200, _text(moved.text)[:2000]
    assert _config_requests(enabled)[-1] == ["interface Vlan10", "vrf member lab"]
    assert "ip" not in enabled.port_state["Vlan10"] and enabled.port_state["Vlan10"]["vrf"] == "lab"
    # Its card now shows it in lab, and the same network is free in default again.
    assert 'value="lab" selected' in moved.text

    refused = _post(logged_in, "/routing/vrf/delete", confirm=True, name="lab")
    assert refused.status_code == 400
    assert "Vlan10 is in VRF lab; move it to another VRF first" in _text(refused.text)
    back = _post(logged_in, "/routing/vrf/move", confirm=True, name="Vlan10", vrf="default")
    assert back.status_code == 200
    assert _config_requests(enabled)[-1] == ["interface Vlan10", "no vrf member lab"]
    deleted = _post(logged_in, "/routing/vrf/delete", confirm=True, name="lab")
    assert deleted.status_code == 200 and _config_requests(enabled)[-1] == ["no vrf context lab"]
    assert enabled.vrfs == []


def test_a_vlan_interface_made_in_a_vrf(logged_in: TestClient, enabled: FakeSwitch):
    enabled.vrfs.append("lab")
    page = logged_in.get("/routing").text
    assert 'id="new_vrf_member"' in page
    done = _make_vlan10(logged_in, vrf="lab")
    assert done.status_code == 200, _text(done.text)[:2000]
    assert _config_requests(enabled)[-1][:3] == [
        "interface vlan10",
        "vrf member lab",
        "ip address 192.0.2.1/24",
    ]
    assert enabled.port_state["Vlan10"]["vrf"] == "lab" and enabled.port_state["Vlan10"]["ip"]


def test_vrf_refusals_before_anything_is_sent(logged_in: TestClient, enabled: FakeSwitch):
    for path, fields, words in (
        ("/routing/vrf/create", {"name": "management"}, "keeps the VRF name"),
        ("/routing/vrf/create", {"name": "a b"}, "a VRF name is 1 to 32"),
        ("/routing/vrf/delete", {"name": "default"}, "keeps the VRF name"),
        ("/routing/vrf/move", {"name": "Vlan1", "vrf": "blue"}, "has no VRF blue"),
        ("/routing/vrf/move", {"name": "mgmt0", "vrf": "default"}, "Not moved"),
    ):
        response = _post(logged_in, path, confirm=True, **fields)
        assert response.status_code == 400 and words in _text(response.text), words
    assert _config_requests(enabled) == []


def test_role_version_7_offers_vrf_changes_without_a_wait(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
):
    _db(settings, "UPDATE switch_connection SET role_version = 7")
    page = logged_in.get("/routing").text
    assert "VRF changes are off" in _text(page) and "/routing/vrf/create" not in page
    assert "/routing/vrf/move" not in page
    refused = _post(logged_in, "/routing/vrf/create", confirm=True, name="lab")
    assert refused.status_code == 400 and "VRF changes are off" in _text(refused.text)
    switch_page = _text(logged_in.get("/switch").text)
    assert "Turn on VRF and static route changes" in switch_page
    assert "this version of NXray can also make and delete VRFs and move" in switch_page
    enabled.ssh_lines.clear()
    text = _text(_enable_changes(logged_in).text)
    assert "VRF and static route changes are on: nxray may now also make and delete VRFs" in text
    assert "there is no wait" in text
    # Only rules change: checked and saved over NX-API, no SSH save.
    assert "rule 53 permit command conf t ; interface * ; vrf member *" in enabled.ssh_lines
    assert "copy running-config startup-config" not in enabled.ssh_lines and enabled.saved
    assert "/routing/vrf/create" in logged_in.get("/routing").text


def test_static_routes_add_and_remove(logged_in: TestClient, enabled: FakeSwitch):
    page = _text(logged_in.get("/routing").text)
    assert "management 0.0.0.0/0 203.0.113.254" in page and "the switch's own" in page
    _make_vlan10(logged_in)
    ask = _text(
        _post(logged_in, "/routing/route/add", vrf="default", prefix="0.0.0.0/0",
              next_hop="192.0.2.254").text
    )  # fmt: skip
    assert "traffic for 0.0.0.0/0 goes to 192.0.2.254" in ask and "default route" in ask
    assert _config_requests(enabled)[-1][0] == "interface vlan10"  # nothing sent yet
    added = _post(
        logged_in, "/routing/route/add", confirm=True, vrf="default", prefix="0.0.0.0/0",
        next_hop="192.0.2.254",
    )  # fmt: skip
    assert added.status_code == 200, _text(added.text)[:2000]
    assert _config_requests(enabled)[-1] == ["ip route 0.0.0.0/0 192.0.2.254"]
    assert "default 0.0.0.0/0 192.0.2.254 yes" in _text(added.text)

    enabled.vrfs.append("lab")
    in_lab = _post(
        logged_in, "/routing/route/add", confirm=True, vrf="lab", prefix="2001:db8:9::/48",
        next_hop="2001:db8:a::fe",
    )  # fmt: skip
    assert in_lab.status_code == 200
    assert _config_requests(enabled)[-1] == [
        "vrf context lab",
        "ipv6 route 2001:db8:9::/48 2001:db8:a::fe",
    ]
    refused = _post(logged_in, "/routing/vrf/delete", confirm=True, name="lab")
    assert refused.status_code == 400 and "has static routes" in _text(refused.text)

    removed = _post(
        logged_in, "/routing/route/remove", confirm=True, vrf="lab", prefix="2001:db8:9::/48",
        next_hop="2001:db8:a::fe",
    )  # fmt: skip
    assert removed.status_code == 200
    assert _config_requests(enabled)[-1] == [
        "vrf context lab",
        "no ipv6 route 2001:db8:9::/48 2001:db8:a::fe",
    ]
    keep = _post(
        logged_in, "/routing/route/remove", confirm=True, vrf="management", prefix="0.0.0.0/0",
        next_hop="203.0.113.254",
    )  # fmt: skip
    assert keep.status_code == 400 and ("management", "0.0.0.0/0", "203.0.113.254") in (
        enabled.static_routes
    )


def test_role_version_8_offers_static_route_changes(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
):
    _db(settings, "UPDATE switch_connection SET role_version = 8")
    page = logged_in.get("/routing").text
    assert "Static route changes are off" in _text(page) and "/routing/route/add" not in page
    refused = _post(
        logged_in, "/routing/route/add", confirm=True, vrf="default", prefix="0.0.0.0/0",
        next_hop="192.0.2.254",
    )  # fmt: skip
    assert refused.status_code == 400 and "Static route changes are off" in _text(refused.text)
    assert "Turn on static route changes" in _text(logged_in.get("/switch").text)
    text = _text(_enable_changes(logged_in).text)
    assert "Static route changes are on: nxray may now also add and remove static routes" in text
    assert "there is no wait" in text
    assert "/routing/route/add" in logged_in.get("/routing").text
