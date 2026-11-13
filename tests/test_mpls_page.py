"""The MPLS page (#78: static MPLS, and Layer 3 VPNs over segment routing), end to end
against the fake switch, and its parser."""

from __future__ import annotations

import html
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.mpls import (
    COMMANDS,
    CONFIG_COMMAND,
    NO_LICENCE,
    PAGE_COMMANDS,
    SET_COMMAND,
    MplsPage,
    VpnVrf,
    build_mpls_change,
    check_mpls_place,
    licence_installed,
    parse_feature_set,
    parse_mpls,
    parse_mpls_config,
)
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

# Shaped after Cisco's NX-OS 9.3 Label Switching Configuration Guide ("Configuring Static
# MPLS"): never recorded, as the switch refuses static MPLS while VXLAN is on.
FEATURE_SET = """Feature Set Name      ID        State
--------------------  --------  --------
fcoe                  1         uninstalled
mpls                  4         enabled
"""
CONFIG = """
version 9.3(16)
install feature-set mpls
feature-set mpls
feature mpls static
mpls label range 17 99 static 100 10000
interface Ethernet1/23
  no switchport
  mpls ip forwarding
  ip address 192.0.2.1/30
interface Ethernet1/24
  no switchport
mpls static configuration
  address-family ipv4 unicast
    local-label 2000 prefix 1.255.200.0/32
      next-hop 1.31.1.1 out-label implicit-null
      next-hop backup Po34 1.34.1.1 out-label 2000
    local-label 100 prefix 192.168.0.1 255.255.255.255 next-hop auto-resolve out-label 200
"""
SWITCHING = {
    "TABLE_vrf": {
        "ROW_vrf": {
            "TABLE_inlabel": {
                "ROW_inlabel": {
                    "in_label": "100",
                    "out_label_stack": "200",
                    "ipv4_prefix": "192.168.0.1/32",
                    "out_interface": "Eth1/23",
                    "ipv4_next_hop": "1.12.23.2",
                    "nhlfe_p2p_flag": "",
                }
            }
        }
    }
}


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


# ---- parsing and lines --------------------------------------------------------------------


def test_the_feature_set_state() -> None:
    assert parse_feature_set(FEATURE_SET) == "enabled"
    assert parse_feature_set("fcoe 1 uninstalled\n") == ""


def test_the_configuration() -> None:
    parsed = parse_mpls_config(CONFIG)
    assert parsed.label_range == "17 99 static 100 10000"
    assert parsed.interfaces == ("Ethernet1/23",)
    first, second = parsed.bindings
    assert first == (
        "ipv4",
        "2000",
        "1.255.200.0/32",
        (
            "next-hop 1.31.1.1 out-label implicit-null",
            "next-hop backup Po34 1.34.1.1 out-label 2000",
        ),
    )
    # The one-line form, with a mask, as the guide prints the running configuration.
    assert second == ("ipv4", "100", "192.168.0.1/32", ("next-hop auto-resolve out-label 200",))


def test_the_page_view() -> None:
    view = parse_mpls(SWITCHING, CONFIG, "enabled", True)
    (switch,) = view.of("switch")
    assert switch.values["label_range"] == {
        "low": "17",
        "high": "99",
        "static_low": "100",
        "static_high": "10000",
    }
    assert {"install", "feature_set", "static"} <= set(switch.values)
    (port,) = view.of("interface")
    assert port.ident == {"interface": "Ethernet1/23"}
    pop, swap = view.of("binding")
    assert pop.ident == {"family": "ipv4", "label": "2000", "prefix": "1.255.200.0/32"}
    assert pop.values["pop"] == {"address": "1.31.1.1"}
    assert pop.values["backup"] == {"interface": "Po34", "address": "1.34.1.1", "out": "2000"}
    assert swap.values == {"swap": {"out": "200"}}
    (labels,) = view.tables
    assert labels.rows == (("100", "200", "192.168.0.1/32", "Eth1/23", "1.12.23.2"),)


def test_with_mpls_off_only_the_switch_wide_lines_show() -> None:
    view = parse_mpls(None, None, "uninstalled", False)
    (switch,) = view.of("switch")
    assert switch.values == {} and dict(switch.facts)["Static MPLS"] == "off"
    assert view.of("binding") == []


def test_the_lines() -> None:
    def lines(scope: str, setting: str, action: str, ident=None, **values: str):
        return build_mpls_change(scope, setting, action, ident or {}, values).lines

    assert lines("switch", "install", "set") == ("install feature-set mpls",)
    assert lines("switch", "install", "remove") == ("no install feature-set mpls",)
    assert lines("switch", "feature_set", "set") == ("feature-set mpls",)
    assert lines("switch", "static", "remove") == ("no feature mpls static",)
    assert lines("switch", "label_range", "set", low="17", high="99") == ("mpls label range 17 99",)
    assert lines(
        "switch", "label_range", "set", low="17", high="99", static_low="100",
        static_high="10000",
    ) == ("mpls label range 17 99 static 100 10000",)  # fmt: skip
    port = {"interface": "Ethernet1/23"}
    assert lines("interface", "forwarding", "set", port) == (
        "interface Ethernet1/23",
        "mpls ip forwarding",
    )
    assert lines("interface", "forwarding", "remove", port)[-1] == "no mpls ip forwarding"
    binding = {"family": "ipv4", "label": "2000", "prefix": "192.0.2.1/32"}
    enter = (
        "mpls static configuration",
        "address-family ipv4 unicast",
        "local-label 2000 prefix 192.0.2.1/32",
    )
    assert lines("binding", "", "create", binding) == enter
    assert lines("binding", "", "delete", binding) == (
        *enter[:2],
        "no local-label 2000 prefix 192.0.2.1/32",
    )
    assert lines("binding", "swap", "set", binding, out="3000") == (
        *enter,
        "next-hop auto-resolve out-label 3000",
    )
    assert lines("binding", "pop", "set", binding, address="192.0.2.2")[-1] == (
        "next-hop 192.0.2.2 out-label implicit-null"
    )
    assert lines(
        "binding", "backup", "set", binding, interface="Ethernet1/24", address="192.0.2.6",
        out="2001",
    )[-1] == "next-hop backup Ethernet1/24 192.0.2.6 out-label 2001"  # fmt: skip


def _binding(family: str = "ipv4", label: str = "20", prefix: str = "192.0.2.1/32") -> dict:
    return {"family": family, "label": label, "prefix": prefix}


@pytest.mark.parametrize(
    ("scope", "setting", "ident", "values"),
    [
        ("switch", "label_range", {}, {"low": "15", "high": "99"}),
        ("switch", "label_range", {}, {"low": "17", "high": "471805"}),
        ("binding", "swap", _binding(label="15"), {"out": "1"}),  # below the label range
        ("binding", "swap", _binding(prefix="192.0.2.1"), {"out": "1"}),  # no prefix length
        ("binding", "swap", _binding(family="ip"), {"out": "1"}),
        ("binding", "pop", _binding(), {"address": "x"}),
    ],
)  # fmt: skip
def test_wrong_values_are_refused(
    scope: str, setting: str, ident: dict[str, str], values: dict[str, str]
) -> None:
    with pytest.raises(ValueError):
        build_mpls_change(scope, setting, "set", ident, values)


# ---- the page -----------------------------------------------------------------------------


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
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
    fake.feature_state["interface-vlan"] = True
    fake.svis = {250}
    fake.port_state["Vlan250"] = {"routed": True, "admin_up": True}
    fake.bodies["show mpls switching"] = SWITCHING
    fake.requests.clear()
    return fake


def _enable(client: TestClient, settings: Settings, fake: FakeSwitch, mode: str) -> FakeSwitch:
    response = client.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(client, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "role_mode": mode,
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    fake.requests.clear()
    fake.signed_in.clear()
    return fake


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    return _enable(logged_in, settings, switch, "broad")


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/mpls/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/mpls", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/mpls"' in logged_in.get("/").text


def test_with_mpls_off_the_page_offers_to_turn_it_on(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    page = logged_in.get("/mpls")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "MPLS feature set uninstalled" in text and "Install the MPLS feature set" in text
    assert enabled.requests == [list(PAGE_COMMANDS), [SET_COMMAND]]


def test_with_vxlan_on_the_page_says_it_must_go_first(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    switch.feature_state["vnseg_vlan"] = True
    assert "VXLAN (feature nv overlay or vn-segment-vlan-based) is on" in _text(
        logged_in.get("/mpls").text
    )


def test_turning_mpls_on_step_by_step_then_a_binding(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    # A binding before static MPLS is on is refused by NXray, not sent.
    early = _change(
        logged_in, scope="binding", action="create", id_family="ipv4", id_label="2000",
        id_prefix="192.0.2.1/32",
    )  # fmt: skip
    assert early.status_code == 400 and "static MPLS is off" in _text(early.text)
    assert _config_requests(enabled) == []
    for setting in ("install", "feature_set", "static"):
        done = _change(logged_in, scope="switch", setting=setting, action="set")
        assert done.status_code == 200, _text(done.text)
    assert enabled.mpls_set == "enabled" and enabled.feature_state["mpls_static"]
    swap = _change(
        logged_in, scope="binding", setting="swap", action="set", id_family="ipv4",
        id_label="2000", id_prefix="192.0.2.1/32", v_out="3000",
    )  # fmt: skip
    assert swap.status_code == 200, _text(swap.text)
    port = _change(
        logged_in,
        scope="interface",
        setting="forwarding",
        action="set",
        id_interface="Vlan250",
    )
    assert port.status_code == 200, _text(port.text)
    assert _config_requests(enabled) == [
        ["install feature-set mpls"],
        ["feature-set mpls"],
        ["feature mpls static"],
        [
            "mpls static configuration",
            "address-family ipv4 unicast",
            "local-label 2000 prefix 192.0.2.1/32",
            "next-hop auto-resolve out-label 3000",
        ],
        ["interface Vlan250", "mpls ip forwarding"],
    ]
    text = _text(port.text)
    # Read back from the running configuration and show mpls switching.
    assert "Label 2000 for 192.0.2.1/32" in text and "next-hop auto-resolve out-label 3000" in text
    assert "MPLS forwarding on" in text and "1.12.23.2" in text
    assert enabled.requests[-1] == [CONFIG_COMMAND] and list(COMMANDS) in enabled.requests


def test_static_mpls_is_refused_while_vxlan_is_on(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.mpls_set = "enabled"
    enabled.feature_state["vnseg_vlan"] = True
    refused = _change(logged_in, scope="switch", setting="static", action="set")
    assert refused.status_code == 400 and "vn-segment-vlan-based" in _text(refused.text)


def test_with_the_admin_login_stored_the_change_is_sent_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "stored")
    done = _change(logged_in, scope="switch", setting="install", action="set")
    assert done.status_code == 200, _text(done.text)
    assert "admin" in switch.signed_in and switch.mpls_set == "installed"


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    refused = _change(logged_in, scope="switch", setting="install", action="set")
    assert refused.status_code == 400 and "MPLS changes are off" in _text(refused.text)
    assert _config_requests(switch) == []


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "mpls"})
    assert saved.status_code == 200
    assert "Install the MPLS feature set" in _text(saved.text) and enabled.saved


# ---- Layer 3 VPNs over segment routing --------------------------------------------------

# Shaped after Cisco's NX-OS 9.3 Label Switching Configuration Guide ("Configuring Segment
# Routing", its show running-config segment-routing and the stitching example): never
# recorded, as the switch refuses segment routing while VXLAN is on.
SR_CONFIG = """
version 9.3(16)
install feature-set mpls
feature-set mpls
feature mpls segment-routing
feature mpls l3vpn
vrf context management
  ip route 0.0.0.0/0 192.0.2.254
vrf context Customer1
  rd auto
  address-family ipv4 unicast
    route-target import 100:100
    route-target export 100:100
    route-target import 100:100 evpn
    route-target export 100:100 evpn
  address-family ipv6 unicast
    route-target import 100:200
vrf context lab
interface Ethernet1/13
  no switchport
  mpls ip forwarding
segment-routing
  mpls
    global-block 17000 24999
    connected-prefix-sid-map
      address-family ipv4
        2.1.1.1/32 absolute 100100
        1.1.1.1/32 index 10
"""


def test_the_segment_routing_and_vpn_configuration() -> None:
    parsed = parse_mpls_config(SR_CONFIG)
    assert parsed.segment_routing and parsed.global_block == "17000 24999"
    assert parsed.prefix_sids == (
        ("2.1.1.1/32", "absolute", "100100"),
        ("1.1.1.1/32", "index", "10"),
    )
    assert parsed.interfaces == ("Ethernet1/13",)
    # The EVPN route-targets are the VXLAN page's; management is never a VPN.
    assert parsed.vrfs == (
        VpnVrf(
            "Customer1",
            "auto",
            (("ipv4", ("100:100",), ("100:100",)), ("ipv6", ("100:200",), ())),
        ),
        VpnVrf("lab"),
    )
    # NX-OS before 9.3(1) wrote "segment-routing mpls" on one line.
    old = parse_mpls_config("segment-routing mpls\n  global-block 16000 20000\n")
    assert old.segment_routing and old.global_block == "16000 20000"
    assert not parse_mpls_config(CONFIG).segment_routing


def test_the_segment_routing_page_view() -> None:
    view = parse_mpls(None, SR_CONFIG, "enabled", False, sr_on=True, l3vpn_on=True, licence=False)
    (switch,) = view.of("switch")
    assert {"segment_routing", "l3vpn"} <= set(switch.values) and "static" not in switch.values
    facts = dict(switch.facts)
    assert facts["Segment routing"] == "on" and facts["VPN Fabric licence"] == "not installed"
    (sr,) = view.of("sr")
    assert sr.values == {"global_block": {"low": "17000", "high": "24999"}}
    assert [i.ident for i in view.of("prefix_sid")] == [
        {"prefix": "2.1.1.1/32", "kind": "absolute", "sid": "100100"},
        {"prefix": "1.1.1.1/32", "kind": "index", "sid": "10"},
    ]
    customer, lab = view.of("vrf")
    assert customer.values == {"rd": {"target": "auto"}} and lab.values == {}
    v4, v6 = view.of("vrf_af")
    assert v4.values == {"rt_import": {"target": "100:100"}, "rt_export": {"target": "100:100"}}
    assert v6.values == {"rt_import": {"target": "100:200"}}
    assert NO_LICENCE in view.notes
    # With Layer 3 VPNs off the VRFs are not offered; with the licence there, no note.
    quiet = parse_mpls(None, SR_CONFIG, "enabled", False, sr_on=True, licence=True)
    assert quiet.of("vrf") == [] and NO_LICENCE not in quiet.notes


def test_the_licence() -> None:
    def usage(installed: str) -> dict:
        row = {"feature_name": "VPN_FABRIC", "lic_installed": installed}
        return {"TABLE_show_lic_usage": {"ROW_show_lic_usage": [row]}}

    assert licence_installed(usage("No")) is False
    assert licence_installed(usage("Yes")) is True
    assert licence_installed({}) is None


def test_the_segment_routing_and_vpn_lines() -> None:
    def lines(scope: str, setting: str, action: str, ident=None, **values: str):
        return build_mpls_change(scope, setting, action, ident or {}, values).lines

    assert lines("switch", "segment_routing", "set") == ("feature mpls segment-routing",)
    assert lines("switch", "l3vpn", "remove") == ("no feature mpls l3vpn",)
    assert lines("sr", "", "create") == ("segment-routing", "mpls")
    assert lines("sr", "", "delete") == ("no segment-routing",)
    assert lines("sr", "global_block", "set", low="16000", high="471804") == (
        "segment-routing",
        "mpls",
        "global-block 16000 471804",
    )
    sid = {"prefix": "192.0.2.1/32", "kind": "index", "sid": "10"}
    enter = ("segment-routing", "mpls", "connected-prefix-sid-map", "address-family ipv4")
    assert lines("prefix_sid", "", "create", sid) == (*enter, "192.0.2.1/32 index 10")
    assert lines("prefix_sid", "", "delete", sid) == (*enter, "no 192.0.2.1/32 index 10")
    tenant = {"vrf": "tenant"}
    assert lines("vrf", "rd", "set", tenant, target="65000:1") == (
        "vrf context tenant",
        "rd 65000:1",
    )
    assert lines("vrf", "rd", "remove", tenant, target="65000:1")[-1] == "no rd 65000:1"
    assert lines("vrf_af", "rt_export", "set", {**tenant, "af": "ipv6"}, target="65000:1") == (
        "vrf context tenant",
        "address-family ipv6 unicast",
        "route-target export 65000:1",
    )


@pytest.mark.parametrize(
    ("scope", "setting", "ident", "values"),
    [
        ("sr", "global_block", {}, {"low": "15999", "high": "20000"}),
        ("sr", "global_block", {}, {"low": "20000", "high": "20000"}),
        ("prefix_sid", "", {"prefix": "192.0.2.1", "kind": "index", "sid": "1"}, {}),
        ("prefix_sid", "", {"prefix": "2001:db8::1/128", "kind": "index", "sid": "1"}, {}),
        ("prefix_sid", "", {"prefix": "192.0.2.1/32", "kind": "label", "sid": "1"}, {}),
        ("vrf_af", "rt_import", {"vrf": "tenant", "af": "ipv4"}, {"target": "auto"}),
        ("vrf_af", "rt_import", {"vrf": "tenant", "af": "ipv4"}, {"target": "x:y"}),
        ("vrf", "rd", {"vrf": "default"}, {"target": "auto"}),
    ],
)  # fmt: skip
def test_wrong_vpn_values_are_refused(
    scope: str, setting: str, ident: dict[str, str], values: dict[str, str]
) -> None:
    action = "create" if scope == "prefix_sid" else "set"
    with pytest.raises(ValueError):
        build_mpls_change(scope, setting, action, ident, values)


def test_places_are_refused_until_their_feature_is_on() -> None:
    from app.mpls import MPLS
    from app.protocols import ProtocolView

    off = MplsPage(MPLS, ProtocolView(), ("Ethernet1/13",), vrfs=("tenant",))
    sid = {"prefix": "192.0.2.1/32", "kind": "index", "sid": "10"}
    for ident, wanted in (
        ({"interface": "Ethernet1/13"}, "static MPLS and segment routing are off"),
        (sid, "segment routing is off"),
        ({"vrf": "tenant"}, "Layer 3 VPNs are off"),
    ):
        with pytest.raises(ValueError, match=wanted):
            check_mpls_place(off, ident)
    on = MplsPage(
        MPLS, ProtocolView(), ("Ethernet1/13",), sr_on=True, l3vpn_on=True, vrfs=("tenant",)
    )
    check_mpls_place(on, {"interface": "Ethernet1/13"})
    check_mpls_place(on, sid)
    check_mpls_place(on, {"vrf": "tenant", "af": "ipv4"})
    for ident, wanted in (
        ({**sid, "sid": "471789"}, "an index is 0 to 471788"),
        ({**sid, "kind": "absolute", "sid": "15999"}, "an absolute label is 16000"),
        ({"vrf": "other"}, "no VRF other"),
        ({"vrf": "default"}, "no VRF default"),
    ):
        with pytest.raises(ValueError, match=wanted):
            check_mpls_place(on, ident)


def test_layer3_vpn_over_segment_routing_end_to_end(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.vrfs = ["tenant"]
    for setting in ("install", "feature_set", "segment_routing", "l3vpn"):
        done = _change(logged_in, scope="switch", setting=setting, action="set")
        assert done.status_code == 200, _text(done.text)
    assert enabled.feature_state["segment-routing"] and enabled.feature_state["l3vpn"]
    # Static MPLS and segment routing are never on together.
    refused = _change(logged_in, scope="switch", setting="static", action="set")
    assert refused.status_code == 400 and "cannot be enabled at the same time" in _text(
        refused.text
    )
    steps = (
        {"scope": "sr", "action": "create"},
        {"scope": "sr", "setting": "global_block", "action": "set", "v_low": "16000",
         "v_high": "30000"},
        {"scope": "prefix_sid", "action": "create", "id_prefix": "192.0.2.1/32",
         "id_kind": "index", "id_sid": "10"},
        {"scope": "interface", "setting": "forwarding", "action": "set",
         "id_interface": "Vlan250"},
        {"scope": "vrf", "setting": "rd", "action": "set", "id_vrf": "tenant",
         "v_target": "auto"},
        {"scope": "vrf_af", "setting": "rt_import", "action": "set", "id_vrf": "tenant",
         "id_af": "ipv4", "v_target": "65000:100"},
    )  # fmt: skip
    for step in steps:
        done = _change(logged_in, **step)
        assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled)[-6:] == [
        ["segment-routing", "mpls"],
        ["segment-routing", "mpls", "global-block 16000 30000"],
        [
            "segment-routing",
            "mpls",
            "connected-prefix-sid-map",
            "address-family ipv4",
            "192.0.2.1/32 index 10",
        ],
        ["interface Vlan250", "mpls ip forwarding"],
        ["vrf context tenant", "rd auto"],
        ["vrf context tenant", "address-family ipv4 unicast", "route-target import 65000:100"],
    ]
    text = _text(done.text)
    # Read back from the running configuration, with the licence the switch lacks.
    assert "16000 to 30000" in text and "192.0.2.1/32: index 10" in text
    assert "VRF tenant, IPv4 unicast" in text and "65000:100" in text
    assert "VPN Fabric licence not installed" in text and NO_LICENCE in text
    # Turning segment routing off takes its block and MPLS forwarding with it.
    off = _change(logged_in, scope="switch", setting="segment_routing", action="remove")
    assert off.status_code == 200, _text(off.text)
    assert "192.0.2.1/32: index 10" not in _text(off.text)


def test_segment_routing_is_refused_while_vxlan_is_on(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.mpls_set = "enabled"
    enabled.feature_state["vnseg_vlan"] = True
    refused = _change(logged_in, scope="switch", setting="segment_routing", action="set")
    assert refused.status_code == 400 and "vn-segment-vlan-based" in _text(refused.text)
    assert "segment routing and Layer 3 VPNs only while both are off" in _text(refused.text)
