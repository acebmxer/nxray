"""The VXLAN page, end to end against the fake switch: reading it, the role version it
needs, the NVE interface in the role's port list, and a change from asking to sent."""

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


def _setup(logged_in: TestClient, fake: FakeSwitch) -> None:
    fake.bodies["show nve interface"] = load_fixture("show_nve_interface_doc")
    fake.bodies["show nve peers"] = load_fixture("show_nve_peers_doc")
    fake.bodies["show nve vni"] = load_fixture("show_nve_vni_doc")
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


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    """A switch that has been set up (read-only account nxray), with VXLAN turned on."""
    fake = FakeSwitch()
    fake.feature_state.update({"nve": True, "vnseg_vlan": True, "hmm": True})
    _setup(logged_in, fake)
    return fake


def _enable(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
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
    switch.requests.clear()
    switch.saved = False
    return switch


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    """All changes on and the wait over."""
    return _enable(logged_in, switch, settings)


def _change(client: TestClient, confirm: bool = True, **fields):  # type: ignore[no-untyped-def]
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/vxlan/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/vxlan", follow_redirects=False).status_code == 303


def test_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/vxlan").text)


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/vxlan"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/vxlan")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "192.0.2.2" in text and "5254.0012.3456" in text  # a peer
    assert "10010" in text and "L3 [tenant]" in text  # the VNIs
    assert switch.requests[0] == ["show feature", "show vlan brief", "show vrf"]
    assert switch.requests[1] == ["show nve interface", "show nve peers", "show nve vni"]
    # The role at setup (read-only) may not read the configuration text.
    assert "does not let it read the VXLAN settings" in text
    assert "/vxlan/change" not in page.text  # changes are off


def test_feature_off_says_which(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["nve"] = False
    text = _text(logged_in.get("/vxlan").text)
    assert "nv overlay is off on the switch, so VXLAN is not running" in text
    assert 'href="/features"' in logged_in.get("/vxlan").text


def test_changes_off_before_role_version_20(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 19")
    assert "VXLAN changes are off" in _text(logged_in.get("/vxlan").text)
    refused = _change(logged_in, scope="nve", action="create", id_nve="1")
    assert refused.status_code == 400
    assert "VXLAN changes are off" in _text(refused.text)
    assert _config_requests(enabled) == []
    assert "Turn on VXLAN changes" in _text(logged_in.get("/switch").text)


def test_the_role_names_the_nve_interface(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    assert "nve1" in enabled.roles["nxray-ports"].interfaces
    conn = sqlite3.connect(settings.db_path)
    assert conn.execute("SELECT role_nve FROM switch_connection").fetchone()[0] == 1
    conn.close()


def test_changes_off_while_the_role_lacks_the_nve_interface(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    """A role written while the nve feature was off cannot enter nve1."""
    _db(settings, "UPDATE switch_connection SET role_nve = 0")
    assert "VXLAN changes are off" in _text(logged_in.get("/vxlan").text)


def test_a_role_written_with_nve_off_gets_it_on_update(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    switch.feature_state["nve"] = False
    enabled = _enable(logged_in, switch, settings)
    assert "nve1" not in enabled.roles["nxray-ports"].interfaces
    assert "VXLAN changes are off" in _text(logged_in.get("/vxlan").text)
    enabled.feature_state["nve"] = True
    updated = logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )
    assert updated.status_code == 200
    assert "the NVE interface" in _text(updated.text)
    assert "nve1" in enabled.roles["nxray-ports"].interfaces
    assert "VXLAN changes are off" not in _text(logged_in.get("/vxlan").text)


def test_enabled_page_offers_the_settings(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/vxlan")
    assert "does not let it read" not in _text(page.text)
    for setting in ("evpn", "vni", "source_interface", "suppress_arp", "rd", "rt_both_auto"):
        assert f'name="setting" value="{setting}"' in page.text
    assert enabled.requests[2] == ["show running-config vxlan"]
    assert '<option value="management"' in page.text


def test_make_the_nve_interface_asks_first_then_sends(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    fields = {"scope": "nve", "action": "create", "id_nve": "1"}
    asked = _change(logged_in, confirm=False, **fields)
    assert asked.status_code == 200
    assert "interface nve1" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["interface nve1"]]
    assert "interface nve1" in enabled.vxlan_lines
    assert "NXray changed the switch since its configuration was last saved" in _text(
        logged_in.get("/vxlan").text
    )


def test_source_interface_and_the_setting_shows_back(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    done = _change(
        logged_in,
        scope="nve",
        setting="source_interface",
        action="set",
        id_nve="1",
        v_source="loopback1",
    )
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["interface nve1", "source-interface loopback1"]]
    assert 'value="loopback1"' in logged_in.get("/vxlan").text


def test_shutdown_state_is_kept(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _change(logged_in, scope="nve", setting="admin_up", action="set", id_nve="1")
    assert "interface nve1 ; no shutdown" in enabled.vxlan_lines
    _change(logged_in, scope="nve", setting="admin_down", action="set", id_nve="1")
    assert "interface nve1 ; shutdown" in enabled.vxlan_lines
    assert "interface nve1 ; no shutdown" not in enabled.vxlan_lines


def test_a_member_vni_with_its_settings(logged_in: TestClient, enabled: FakeSwitch) -> None:
    made = _change(logged_in, scope="l2vni", action="create", id_nve="1", id_vni="10010")
    assert made.status_code == 200, _text(made.text)
    arp = _change(logged_in, scope="l2vni", setting="suppress_arp", action="set",
                  id_nve="1", id_vni="10010")  # fmt: skip
    assert arp.status_code == 200, _text(arp.text)
    assert _config_requests(enabled) == [
        ["interface nve1", "member vni 10010"],
        ["interface nve1", "member vni 10010", "suppress-arp"],
    ]
    assert "interface nve1 ; member vni 10010 ; suppress-arp" in enabled.vxlan_lines
    gone = _change(logged_in, scope="l2vni", action="delete", id_nve="1", id_vni="10010")
    assert gone.status_code == 200
    assert not [p for p in enabled.vxlan_lines if "member vni 10010" in p]


def test_a_vlan_gets_its_vni(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.vlans[10] = "users"
    done = _change(
        logged_in, scope="vlan", setting="vni", action="set", id_vlan="10", v_vni="10010"
    )
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["vlan 10", "vn-segment 10010"]]
    assert 'value="10010"' in logged_in.get("/vxlan").text


def test_evpn_settings_of_a_vni(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(logged_in, scope="evpn", setting="rd", action="set", id_vni="10010",
                   v_target="auto")  # fmt: skip
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["evpn", "vni 10010 l2", "rd auto"]]
    assert "evpn ; vni 10010 l2 ; rd auto" in enabled.vxlan_lines


def test_the_whole_switch_lines(logged_in: TestClient, enabled: FakeSwitch) -> None:
    on = _change(logged_in, scope="switch", setting="evpn", action="set")
    assert on.status_code == 200, _text(on.text)
    assert "The EVPN control plane is on." in _text(logged_in.get("/vxlan").text)
    mac = _change(logged_in, scope="switch", setting="anycast_mac", action="set",
                  v_mac="2020.0000.00aa")  # fmt: skip
    assert mac.status_code == 200, _text(mac.text)
    assert "fabric forwarding anycast-gateway-mac 2020.0000.00aa" in enabled.vxlan_lines


def test_a_vrf_vni_and_route_targets(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.vrfs.append("tenant")
    done = _change(logged_in, scope="vrf", setting="vni", action="set", id_vrf="tenant",
                   v_vni="50000")  # fmt: skip
    assert done.status_code == 200, _text(done.text)
    both = _change(logged_in, scope="vrf_af", setting="rt_both_auto", action="set",
                   id_vrf="tenant", id_af="ipv4")  # fmt: skip
    assert both.status_code == 200, _text(both.text)
    assert _config_requests(enabled) == [
        ["vrf context tenant", "vni 50000"],
        ["vrf context tenant", "address-family ipv4 unicast", "route-target both auto evpn"],
    ]


def test_a_vlan_or_vrf_the_switch_lacks_is_refused(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    vlan = _change(logged_in, scope="vlan", setting="vni", action="set", id_vlan="999",
                   v_vni="10999")  # fmt: skip
    assert vlan.status_code == 400
    assert "no VLAN 999" in _text(vlan.text)
    vrf = _change(logged_in, scope="vrf", setting="vni", action="set", id_vrf="nothere",
                  v_vni="50000")  # fmt: skip
    assert vrf.status_code == 400
    assert "no VRF nothere" in _text(vrf.text)
    assert _config_requests(enabled) == []


def test_bad_values_are_refused_before_anything_is_sent(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    refused = _change(logged_in, scope="l2vni", action="create", id_nve="1", id_vni="0")
    assert refused.status_code == 400
    assert _config_requests(enabled) == []


def test_viewer_sees_no_forms_and_cannot_post(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE users SET role = 'viewer'")
    page = logged_in.get("/vxlan").text
    assert "/vxlan/change" not in page
    assert "can look at VXLAN but not change it" in _text(page)
    response = _change(logged_in, scope="nve", action="create", id_nve="1")
    assert response.status_code == 403
    assert _config_requests(enabled) == []


def test_change_needs_csrf(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = logged_in.post(
        "/vxlan/change",
        data={"csrf": "0" * 32, "scope": "nve", "action": "create", "id_nve": "1",
              "confirm": "yes"},
    )  # fmt: skip
    assert response.status_code == 403
    assert _config_requests(enabled) == []


def test_switch_error_is_shown(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.reject.add("interface nve")
    response = _change(logged_in, scope="nve", action="create", id_nve="1")
    assert response.status_code == 400
    assert "Rejected by the fake switch" in _text(response.text)


def test_turning_on_the_feature_says_to_update_the_port_list(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    switch.feature_state["nve"] = False
    _enable(logged_in, switch, settings)
    page = logged_in.get("/features")
    assert page.status_code == 200
    done = logged_in.post(
        "/features/set",
        data={"csrf": _csrf(logged_in, "/features"), "name": "nve", "state": "on",
              "confirm": "yes"},
    )  # fmt: skip
    assert "Update the port list" in _text(done.text), _text(done.text)


def test_save_config_returns_to_the_page(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _change(logged_in, scope="nve", action="create", id_nve="1")
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "vxlan"})
    assert saved.status_code == 200
    assert "Peers" in _text(saved.text)
    assert enabled.saved
