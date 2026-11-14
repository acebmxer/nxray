"""The Multicast over VXLAN page (#95), end to end against the fake switch, its parser, and
the overlay families it adds to the BGP page."""

from __future__ import annotations

import html
import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.protocols_bgp import NEIGHBOR_FAMILIES
from app.routing_protocols import build_protocol_change
from app.trm import PAGE_COMMANDS, VXLAN_OFF, build_trm_change, parse_trm, parse_trm_config
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"

# Shaped after Cisco's 9.3 VXLAN guide; part of it was typed on cisco-25gb (see the file).
CONFIG = (FIXTURES / "show_running_config_trm_doc.txt").read_text()


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


def _lines(scope, setting, action, ident, values=None):
    return list(build_trm_change(scope, setting, action, ident, values or {}).lines)


# ---- parsing and lines ----------------------------------------------------------------------


def test_the_configuration_is_read():
    found = parse_trm_config(CONFIG)
    assert found.global_values == {
        "overlay_spt_only": {},
        "overlay_distributed_dr": {},
        "advertise_evpn_multicast": {},
        "evpn_border_leaf": {},
    }
    assert found.nves == {"1": {"mcast_override": {"source": "loopback10"}}}
    assert found.l3vnis == {("1", "50001"): "239.3.3.3", ("1", "50002"): ""}
    assert found.vrfs["red"]["values"] == {"s_g_hash": {}}
    assert found.vrfs["red"]["af_values"] == {
        "rt_both_auto": {},
        "rt_import": {"target": "65001:50001"},
    }
    assert found.asn == "65001"
    assert found.bgp_afs == {
        "ipv4 mvpn": {"retain_rt": {}},
        "l2vpn evpn": {"advertise_pip": {}, "maximum_paths": {"paths": "4"}},
    }


def test_overlay_spt_only_off_is_written_as_its_no_form():
    found = parse_trm_config("no ip multicast overlay-spt-only\n")
    assert "overlay_spt_only" not in found.global_values


def test_the_page_view():
    view = parse_trm(CONFIG)
    (table,) = view.tables
    assert table.rows == (
        ("50001", "red", "239.3.3.3", "yes", "auto, import"),
        ("50002", "blue", "-", "no", "none"),
    )
    assert {i.title for i in view.of("bgp_af")} == {
        "BGP AS 65001: ipv4 mvpn",
        "BGP AS 65001: l2vpn evpn",
    }
    assert "did not show its configuration" in parse_trm(None).notes[0]


def test_the_lines():
    assert _lines("global", "overlay_spt_only", "remove", {}) == [
        "no ip multicast overlay-spt-only"
    ]
    assert _lines(
        "l3vni", "mcast_group", "set", {"nve": "1", "vni": "50001"}, {"group": "239.3.3.3"}
    ) == [  # fmt: skip
        "interface nve1",
        "member vni 50001 associate-vrf",
        "mcast-group 239.3.3.3",
    ]
    assert _lines("vrf_af", "rt_both_auto", "set", {"vrf": "red"}) == [
        "vrf context red",
        "address-family ipv4 unicast",
        "route-target both auto mvpn",
    ]
    assert _lines("bgp_af", "", "create", {"asn": "65001", "af": "ipv4 mvpn"}) == [
        "router bgp 65001",
        "address-family ipv4 mvpn",
    ]
    assert _lines("bgp_af", "advertise_pip", "set", {"asn": "65001", "af": "l2vpn evpn"})[-1] == (
        "advertise-pip"
    )
    with pytest.raises(ValueError, match="l2vpn evpn family"):
        build_trm_change("bgp_af", "advertise_pip", "set", {"asn": "65001", "af": "ipv4 mvpn"}, {})
    with pytest.raises(ValueError, match="auto, ASN:number"):
        build_trm_change("vrf_af", "rt_import", "set", {"vrf": "red"}, {"target": "nonsense"})


def test_the_bgp_page_takes_the_overlay_families_on_a_neighbor():
    assert {"ipv4 mvpn", "l2vpn evpn"} <= set(NEIGHBOR_FAMILIES)
    ident = {"asn": "65001", "vrf": "", "address": "192.0.2.1", "af": "ipv4 mvpn"}
    made = build_protocol_change("bgp", "neighbor_af", "", "create", ident, {})
    assert list(made.lines) == [
        "router bgp 65001",
        "neighbor 192.0.2.1",
        "address-family ipv4 mvpn",
    ]
    sent = build_protocol_change("bgp", "neighbor_af", "rewrite_rt_asn", "set", ident, {})
    assert list(sent.lines)[-1] == "rewrite-rt-asn"


# ---- the page ---------------------------------------------------------------------------------


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
    for name in ("ngmvpn", "nve", "vnseg_vlan"):
        fake.feature_state[name] = True
    fake.vxlan_lines += [
        "interface nve1",
        "interface nve1 ; member vni 50001 associate-vrf",
    ]
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
    return client.post("/trm/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/trm", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/trm"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/trm")
    assert page.status_code == 200, _text(page.text)
    assert "Layer 3 VNI 50001" in _text(page.text)
    assert enabled.requests == [list(PAGE_COMMANDS), ["show running-config"]]


def test_with_ngmvpn_and_vxlan_off_the_page_says_so(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    switch.feature_state["ngmvpn"] = False
    switch.feature_state["nve"] = False
    text = _text(logged_in.get("/trm").text)
    assert "ngmvpn is off on the switch" in text and VXLAN_OFF in text


def test_switch_wide_lines_and_a_vnis_group(logged_in: TestClient, enabled: FakeSwitch) -> None:
    off = _change(logged_in, scope="global", setting="overlay_spt_only", action="remove")
    assert off.status_code == 200, _text(off.text)
    assert "ip multicast overlay-spt-only" not in enabled.mcast_lines
    assert "no ip multicast overlay-spt-only" in enabled.mcast_lines
    group = _change(
        logged_in, scope="l3vni", setting="mcast_group", action="set", id_nve="1",
        id_vni="50001", v_group="239.3.3.3",
    )  # fmt: skip
    assert group.status_code == 200, _text(group.text)
    assert (
        "interface nve1 ; member vni 50001 associate-vrf ; mcast-group 239.3.3.3"
        in enabled.vxlan_lines
    )
    assert "Multicast group 239.3.3.3" in _text(group.text)


def test_places_the_vxlan_page_has_not_made_are_refused(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    vni = _change(
        logged_in, scope="l3vni", setting="mcast_group", action="set", id_nve="1",
        id_vni="50009", v_group="239.3.3.3",
    )  # fmt: skip
    assert vni.status_code == 400 and "no layer 3 VNI 50009" in _text(vni.text)
    vrf = _change(logged_in, scope="vrf", setting="s_g_hash", action="set", id_vrf="nosuch")
    assert vrf.status_code == 400 and "no VRF nosuch" in _text(vrf.text)
    bgp = _change(logged_in, scope="bgp_af", action="create", id_asn="65001", id_af="ipv4 mvpn")
    assert bgp.status_code == 400 and "no BGP process" in _text(bgp.text)
    assert _config_requests(enabled) == []


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    refused = _change(logged_in, scope="global", setting="advertise_evpn_multicast", action="set")
    assert refused.status_code == 400
    assert "Multicast over VXLAN changes are off" in _text(refused.text)
    assert _config_requests(switch) == []


def test_with_the_admin_login_stored_the_change_is_sent_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "stored")
    done = _change(logged_in, scope="global", setting="advertise_evpn_multicast", action="set")
    assert done.status_code == 200, _text(done.text)
    assert "admin" in switch.signed_in and "advertise evpn multicast" in switch.mcast_lines


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "trm"})
    assert saved.status_code == 200
    assert "Add an overlay address family to BGP" in _text(saved.text) and enabled.saved
