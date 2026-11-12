"""The MPLS page (#78, static MPLS), end to end against the fake switch, and its parser."""

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
    PAGE_COMMANDS,
    SET_COMMAND,
    build_mpls_change,
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
