"""The Routing protocols pages, end to end against the fake switch: the overview
with the route table, one protocol's page, and a change from asking to sent."""

from __future__ import annotations

import html
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.routing_protocols import ALL_PROTOCOLS
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


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    """VLAN interfaces on, all changes on (role version 10) and the wait over, with
    VLAN interface 10 made through the Routing page."""
    switch.feature_state["interface-vlan"] = True
    switch.svis = {1}
    switch.port_state["Vlan1"] = {"routed": True, "admin_up": False}
    response = logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    made = _post(
        logged_in,
        "/routing/vlan-interface/create",
        confirm=True,
        vlan="10",
        ipv4="192.0.2.1/24",
        ipv6="",
        description="",
        mtu="",
        enabled="yes",
    )
    assert made.status_code == 200, _text(made.text)
    switch.requests.clear()
    switch.saved = False
    return switch


def _post(client: TestClient, path: str, confirm: bool = False, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post(path, data=data)


def _change(client: TestClient, key: str, confirm: bool = True, **fields: str):
    return _post(client, f"/routing/protocols/{key}/change", confirm=confirm, **fields)


# ---- the overview --------------------------------------------------------------------


def test_overview_needs_login(client: TestClient) -> None:
    response = client.get("/routing/protocols", follow_redirects=False)
    assert response.status_code == 303


def test_overview_without_a_switch(logged_in: TestClient) -> None:
    text = _text(logged_in.get("/routing/protocols").text)
    assert "No switch connected yet" in text


def test_overview_lists_every_protocol_and_the_route_table(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    switch.feature_state["ospf"] = True
    page = logged_in.get("/routing/protocols")
    assert page.status_code == 200
    for proto in ALL_PROTOCOLS:
        assert f'href="/routing/protocols/{proto.key}"' in page.text
    text = _text(page.text)
    assert "OSPF on" in text
    assert "BGP off feature bgp" in text
    assert "Routing policy always there" in text
    # The recorded route table (scrubbed): only management had routes then.
    assert "Route table" in text
    assert "VRF management" in text
    assert "0.0.0.0/0" in text and "203.0.113.254" in text
    assert switch.requests == [["show feature", "show ip route vrf all", "show ipv6 route vrf all"]]


def test_menu_and_routing_page_link_to_protocols(logged_in: TestClient) -> None:
    assert 'href="/routing/protocols"' in logged_in.get("/routing").text


# ---- one protocol's page ----------------------------------------------------------------


def test_unknown_protocol_page(logged_in: TestClient, switch: FakeSwitch) -> None:
    response = logged_in.get("/routing/protocols/nosuch")
    assert response.status_code == 404
    assert "no page called nosuch" in _text(response.text)


def test_protocol_whose_feature_is_off_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    text = _text(logged_in.get("/routing/protocols/bgp").text)
    assert "bgp is off on the switch" in text
    assert "Features" in text
    # Only the shared request: the protocol's own show commands are not sent.
    assert switch.requests == [
        ["show feature", "show interface brief", "show vrf", "show vrf interface"]
    ]


def test_hsrp_names_its_feature_as_typed(logged_in: TestClient, switch: FakeSwitch) -> None:
    assert "hsrp is off on the switch" in _text(logged_in.get("/routing/protocols/hsrp").text)


def test_ospf_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["ospf"] = True
    page = logged_in.get("/routing/protocols/ospf")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "OSPF process" in text
    assert switch.requests[1] == [
        "show ip ospf vrf all",
        "show ip ospf interface vrf all",
        "show ip ospf neighbors vrf all",
        "show ip ospf summary-address vrf all",
    ]


@pytest.mark.parametrize("proto", ALL_PROTOCOLS, ids=lambda p: p.key)
def test_every_protocol_page_renders_when_on(
    logged_in: TestClient, enabled: FakeSwitch, proto
) -> None:
    for name in proto.features:
        enabled.feature_state[name] = True
    page = logged_in.get(f"/routing/protocols/{proto.key}")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert proto.name in text
    # Every scope has its section and every setting its form.
    for scope in proto.scopes:
        assert f'id="{scope.key}"' in page.text
        for setting in scope.settings:
            assert f'name="setting" value="{setting.key}"' in page.text


def test_policy_page_needs_no_feature(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/routing/protocols/policy")
    assert page.status_code == 200
    assert "is off on the switch" not in _text(page.text)


def test_viewer_sees_no_forms(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    enabled.feature_state["ospf"] = True
    _db(settings, "UPDATE users SET role = 'viewer'")
    text = logged_in.get("/routing/protocols/ospf").text
    assert "/routing/protocols/ospf/change" not in text
    assert "can look at routing protocols but not change them" in _text(text)


def test_old_role_shows_changes_off(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["ospf"] = True
    text = logged_in.get("/routing/protocols/ospf").text
    assert "/routing/protocols/ospf/change" not in text
    assert "Routing protocol changes are off" in _text(text)


# ---- changes -------------------------------------------------------------------------------


def test_change_refused_before_role_version_10(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    enabled.feature_state["ospf"] = True
    _db(settings, "UPDATE switch_connection SET role_version = 9")
    response = _change(logged_in, "ospf", scope="process", action="create", id_tag="core")
    assert response.status_code == 400
    assert "Routing protocol changes are off" in _text(response.text)
    assert _config_requests(enabled) == []


def test_change_refused_while_the_feature_is_off(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    response = _change(logged_in, "ospf", scope="process", action="create", id_tag="core")
    assert response.status_code == 400
    assert "ospf is off on the switch" in _text(response.text)
    assert _config_requests(enabled) == []


def test_make_an_ospf_process_asks_first_then_sends(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.feature_state["ospf"] = True
    asked = _change(
        logged_in, "ospf", confirm=False, scope="process", action="create", id_tag="core"
    )
    assert asked.status_code == 200
    text = _text(asked.text)
    assert "OSPF: make OSPF process (Process core)." in text
    assert "router ospf core" in text
    assert _config_requests(enabled) == []

    done = _change(logged_in, "ospf", scope="process", action="create", id_tag="core")
    assert done.status_code == 200, _text(done.text)
    assert "Done: OSPF: make OSPF process" in _text(done.text)
    assert "router ospf core" in enabled.protocol_lines
    assert _config_requests(enabled) == [["router ospf core"]]
    switch_page = _text(logged_in.get("/routing/protocols/ospf").text)
    assert "NXray changed the switch since its configuration was last saved" in switch_page


def test_set_and_remove_a_process_setting(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.feature_state["ospf"] = True
    fields = {"scope": "process", "setting": "router_id", "id_tag": "core"}
    done = _change(logged_in, "ospf", action="set", v_router_id="192.0.2.1", **fields)
    assert done.status_code == 200, _text(done.text)
    assert "router ospf core ; router-id 192.0.2.1" in enabled.protocol_lines
    gone = _change(logged_in, "ospf", action="remove", v_router_id="192.0.2.1", **fields)
    assert gone.status_code == 200, _text(gone.text)
    assert "router ospf core ; router-id 192.0.2.1" not in enabled.protocol_lines


def test_interface_setting_on_a_vlan_interface(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.feature_state["ospf"] = True
    done = _change(
        logged_in,
        "ospf",
        scope="interface",
        setting="cost",
        action="set",
        id_interface="Vlan10",
        v_cost="10",
    )
    assert done.status_code == 200, _text(done.text)
    assert "interface Vlan10 ; ip ospf cost 10" in enabled.protocol_lines


def test_interface_not_on_the_switch_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.feature_state["ospf"] = True
    response = _change(
        logged_in,
        "ospf",
        scope="interface",
        setting="cost",
        action="set",
        id_interface="Vlan20",
        v_cost="10",
    )
    assert response.status_code == 400
    text = _text(response.text)
    assert "Vlan20 is not a VLAN interface" in text and "Vlan10" in text
    assert _config_requests(enabled) == []


@pytest.mark.parametrize("interface", ["mgmt0", "Vlan300", "Ethernet1/1; reload"])
def test_interfaces_nxray_never_changes(
    logged_in: TestClient, enabled: FakeSwitch, interface: str
) -> None:
    enabled.feature_state["ospf"] = True
    response = _change(
        logged_in,
        "ospf",
        scope="interface",
        setting="cost",
        action="set",
        id_interface=interface,
        v_cost="10",
    )
    assert response.status_code == 400
    assert _config_requests(enabled) == []


def test_management_vrf_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.feature_state["ospf"] = True
    response = _change(
        logged_in, "ospf", scope="vrf", action="create", id_tag="core", id_vrf="management"
    )
    assert response.status_code == 400
    assert _config_requests(enabled) == []


def test_bad_value_keeps_the_form(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.feature_state["ospf"] = True
    response = _change(
        logged_in,
        "ospf",
        scope="process",
        setting="router_id",
        action="set",
        id_tag="core",
        v_router_id="not-an-address",
    )
    assert response.status_code == 400
    assert "Not changed:" in _text(response.text)
    assert _config_requests(enabled) == []


def test_secret_never_shown_on_confirm_or_in_a_switch_error(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.feature_state["ospf"] = True
    fields = {
        "scope": "interface",
        "setting": "password",
        "action": "set",
        "id_interface": "Vlan10",
        "v_password": "Sekr1tPw",
    }
    asked = _change(logged_in, "ospf", confirm=False, **fields)
    assert asked.status_code == 200
    # Only in the hidden field that carries it to the confirmed post, never on screen.
    assert "Sekr1tPw" not in _text(asked.text)
    assert asked.text.count("Sekr1tPw") == 1
    assert "ip ospf authentication-key ***" in _text(asked.text)

    enabled.reject.add("ip ospf authentication-key")
    refused = _change(logged_in, "ospf", **fields)
    assert refused.status_code == 400
    assert "Sekr1tPw" not in refused.text


def test_removing_a_password_needs_no_password(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.feature_state["ospf"] = True
    done = _change(
        logged_in,
        "ospf",
        scope="interface",
        setting="password",
        action="remove",
        id_interface="Vlan10",
    )
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled)[-1][-1] == "no ip ospf authentication-key"


def test_policy_prefix_list_lengths_are_checked(logged_in: TestClient, enabled: FakeSwitch) -> None:
    proto = next(p for p in ALL_PROTOCOLS if p.key == "policy")
    scope = next(s for s in proto.scopes if s.setting("entry") is not None and "prefix" in s.key)
    response = _change(
        logged_in,
        "policy",
        scope=scope.key,
        setting="entry",
        action="set",
        v_list="lab",
        v_seq="5",
        v_action="permit",
        v_prefix="192.0.2.0/24",
        v_ge="28",
        v_le="26",
        **{f"id_{f.name}": "lab" for f in scope.ident},
    )
    assert response.status_code == 400
    assert "cannot be more than" in _text(response.text)
    assert _config_requests(enabled) == []


def test_viewer_cannot_post_a_change(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    enabled.feature_state["ospf"] = True
    _db(settings, "UPDATE users SET role = 'viewer'")
    response = _change(logged_in, "ospf", scope="process", action="create", id_tag="core")
    assert response.status_code == 403
    assert _config_requests(enabled) == []


def test_change_needs_csrf(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.feature_state["ospf"] = True
    response = logged_in.post(
        "/routing/protocols/ospf/change",
        data={"csrf": "0" * 32, "scope": "process", "action": "create", "id_tag": "core"},
    )
    assert response.status_code == 403
    assert _config_requests(enabled) == []


def test_save_config_returns_to_the_protocol_page(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.feature_state["ospf"] = True
    _change(logged_in, "ospf", scope="process", action="create", id_tag="core")
    saved = _post(logged_in, "/switch/save", back="protocol", protocol="ospf")
    assert saved.status_code == 200
    text = _text(saved.text)
    assert "OSPF process" in text
    assert enabled.saved
