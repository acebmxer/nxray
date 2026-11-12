"""The Tunnels page (#79), end to end against the fake switch, and its parser.

Changes need the stored admin login: NXray's roles cannot name tunnel interfaces."""

from __future__ import annotations

import html
import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.tunnels import (
    COMMANDS,
    CONFIG_COMMAND,
    PAGE_COMMANDS,
    build_tunnel_change,
    parse_tunnel_config,
    parse_tunnel_view,
    parse_tunnels,
)
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"
# Shaped after the examples in Cisco's NX-OS 9.3 Interfaces Configuration Guide ("Configuring
# IP Tunnels"): never recorded, as the switch refuses feature tunnel while VXLAN is on.
CONFIG = (FIXTURES / "show_running_config_tunnels_doc.txt").read_text()


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


def test_the_configuration_gives_each_tunnel() -> None:
    assert sorted(parse_tunnel_config(CONFIG)) == [0, 1]
    first, second = parse_tunnels({}, CONFIG)
    assert (first.number, first.mode, first.source, first.destination) == (
        0,
        "gre ip",
        "ethernet 1/2",
        "192.0.2.2",
    )
    # The guide's example writes the age timer and minimum MTU without their keywords.
    assert (first.pmtud_age, first.pmtud_min, first.shutdown) == ("25", "1500", False)
    assert (second.description, second.shutdown, second.vrf, second.ipv4) == (
        "to branch",
        True,
        "RemoteOfficeVRF",
        "203.0.113.1/30",
    )
    assert (second.mtu, second.use_vrf, second.ttl, second.source) == (
        "1400",
        "blue",
        "100",
        "198.51.100.10",
    )


def test_the_page_view() -> None:
    brief = {"TABLE_interface": {"ROW_interface": [{"interface": "Tunnel0", "state": "up"}]}}
    first, second = parse_tunnel_view(brief, CONFIG).of("tunnel")
    assert first.ident == {"number": "0"} and first.title == "tunnel0"
    assert dict(first.facts)["State"] == "up"
    assert first.values["source_interface"] == {"source": "ethernet 1/2"}
    # Not in the brief: the state comes from the configuration.
    assert dict(second.facts)["State"] == "off"
    assert second.values["source_address"] == {"address": "198.51.100.10"}
    assert second.values["vrf"] == {"vrf": "RemoteOfficeVRF"}
    assert "source_interface" not in second.values


def test_a_tunnel_with_no_mode_line_is_gre_and_one_only_in_the_brief_is_listed() -> None:
    config = "interface Tunnel5\n  tunnel destination 192.0.2.9\n"
    brief = {"TABLE_interface": {"ROW_interface": {"interface": "Tunnel7", "state": "down"}}}
    five, seven = parse_tunnel_view(brief, config).of("tunnel")
    assert dict(five.facts)["Mode"] == "gre ip (default)"
    assert seven.title == "tunnel7" and dict(seven.facts)["State"] == "down"
    # Without the configuration text and not in the brief, the state is unknown.
    assert parse_tunnel_view({}, None).instances == ()


def test_the_lines() -> None:
    def lines(setting: str, action: str, number: str = "1", **values: str) -> tuple[str, ...]:
        return build_tunnel_change("tunnel", setting, action, {"number": number}, values).lines

    assert lines("", "create", "3") == ("interface tunnel 3",)
    assert lines("", "delete", "3") == ("no interface tunnel 3",)
    assert lines("mode", "set", mode="ipip ip") == ("interface tunnel 1", "tunnel mode ipip ip")
    assert lines("mode", "remove")[-1] == "no tunnel mode"
    assert lines("source_interface", "set", source="loopback0")[-1] == "tunnel source loopback0"
    assert lines("source_address", "set", address="192.0.2.1")[-1] == "tunnel source 192.0.2.1"
    assert lines("source_address", "remove")[-1] == "no tunnel source"
    assert lines("destination", "set", address="198.51.100.1")[-1] == (
        "tunnel destination 198.51.100.1"
    )
    assert lines("destination", "remove")[-1] == "no tunnel destination"
    assert lines("use_vrf", "set", vrf="blue")[-1] == "tunnel use-vrf blue"
    assert lines("use_vrf", "remove")[-1] == "no tunnel use-vrf"
    assert lines("ttl", "set", ttl="100")[-1] == "tunnel ttl 100"
    assert lines("ipv4", "set", address="203.0.113.1/30")[-1] == "ip address 203.0.113.1/30"
    assert lines("ipv4", "remove", address="203.0.113.1/30")[-1] == "no ip address 203.0.113.1/30"
    assert lines("mtu", "set", mtu="1400")[-1] == "mtu 1400"
    assert lines("vrf", "set", vrf="blue")[-1] == "vrf member blue"
    assert lines("pmtud_age", "set", minutes="25")[-1] == "tunnel path-mtu-discovery age-timer 25"
    assert lines("pmtud_min", "remove", bytes="1500")[-1] == (
        "no tunnel path-mtu-discovery min-mtu 1500"
    )
    assert lines("admin_down", "set")[-1] == "shutdown"
    assert lines("admin_up", "set")[-1] == "no shutdown"
    assert build_tunnel_change(
        "tunnel", "vrf", "set", {"number": "1"}, {"vrf": "blue"}
    ).warning.startswith("The switch deletes the tunnel's address")


@pytest.mark.parametrize(
    ("setting", "number", "values"),
    [
        ("mtu", "65536", {"mtu": "1400"}),  # past the numbers NXray takes
        ("mode", "1", {"mode": "gre ipv6"}),  # not a mode the 9.3 guide lists
        ("ttl", "1", {"ttl": "0"}),
        ("ttl", "1", {"ttl": "256"}),
        ("mtu", "1", {"mtu": "63"}),
        ("mtu", "1", {"mtu": "9193"}),
        ("pmtud_age", "1", {"minutes": "9"}),
        ("pmtud_min", "1", {"bytes": "9193"}),
        ("destination", "1", {"address": "2001:db8::1"}),  # IPv4 only
        ("destination", "1", {"address": "224.0.0.1"}),
        ("source_address", "1", {"address": "192.0.2.1/32"}),  # an address, no length
        ("ipv4", "1", {"address": "203.0.113.1"}),  # no prefix length
        ("use_vrf", "1", {"vrf": "default"}),
        ("vrf", "1", {"vrf": "management"}),
        ("description", "1", {"text": "a ; b"}),
    ],
)
def test_wrong_values_are_refused(setting: str, number: str, values: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        build_tunnel_change("tunnel", setting, "set", {"number": number}, values)


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
    fake.feature_state["tunnel"] = True
    fake.tunnels[0] = ["description to the lab", "tunnel source loopback0"]
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
def stored(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    return _enable(logged_in, settings, switch, "stored")


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/tunnels/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/tunnels", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/tunnels"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, stored: FakeSwitch) -> None:
    page = logged_in.get("/tunnels")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "tunnel0" in text and "to the lab" in text and "loopback0" in text
    assert stored.requests == [list(PAGE_COMMANDS), list(COMMANDS), [CONFIG_COMMAND]]
    assert "/tunnels/change" in page.text


def test_before_changes_are_on_the_brief_still_lists_the_tunnels(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    # NXray's account may not read the configuration until its role is written.
    page = logged_in.get("/tunnels")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "tunnel0" in text and "The switch did not show the tunnels' settings" in text
    assert "to the lab" not in text
    assert "/tunnels/change" not in page.text  # changes are off


def test_with_tunnel_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["tunnel"] = False
    text = _text(logged_in.get("/tunnels").text)
    assert "tunnel is off on the switch, so Tunnels is not running" in text
    assert "VXLAN (feature nv overlay) is on" not in text
    assert switch.requests == [list(PAGE_COMMANDS)]


def test_with_vxlan_on_the_page_says_it_must_go_first(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    switch.feature_state.update(tunnel=False, nve=True)
    text = _text(logged_in.get("/tunnels").text)
    assert "VXLAN (feature nv overlay) is on" in text and "tunnel is off on the switch" in text


def test_the_broad_role_cannot_change_tunnels(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "broad")
    refused = _change(logged_in, scope="tunnel", action="create", id_number="1")
    assert refused.status_code == 400 and "need the stored admin login" in _text(refused.text)
    assert _config_requests(switch) == []


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    refused = _change(logged_in, scope="tunnel", action="create", id_number="1")
    assert refused.status_code == 400 and "need the stored admin login" in _text(refused.text)
    assert _config_requests(switch) == []


def test_making_a_tunnel_asks_first_then_sends_with_the_admin_login(
    logged_in: TestClient, stored: FakeSwitch
) -> None:
    fields = {"scope": "tunnel", "action": "create", "id_number": "2"}
    asked = _change(logged_in, confirm=False, **fields)
    assert "interface tunnel 2" in _text(asked.text)
    assert _config_requests(stored) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(stored) == [["interface tunnel 2"]]
    # NXray's own account has only the limited rules here, and no role may name a tunnel:
    # the line went through because it was sent with the admin login.
    assert "admin" in stored.signed_in
    assert 2 in stored.tunnels and "tunnel2" in _text(done.text)


def test_setting_the_ends_and_address_then_deleting(
    logged_in: TestClient, stored: FakeSwitch
) -> None:
    for setting, values in (
        ("source_address", {"v_address": "192.0.2.1"}),
        ("destination", {"v_address": "198.51.100.1"}),
        ("ipv4", {"v_address": "203.0.113.1/30"}),
    ):
        done = _change(
            logged_in, scope="tunnel", setting=setting, action="set", id_number="0", **values
        )
        assert done.status_code == 200, _text(done.text)
    # The source address replaced the source interface.
    assert stored.tunnels[0] == [
        "description to the lab",
        "tunnel source 192.0.2.1",
        "tunnel destination 198.51.100.1",
        "ip address 203.0.113.1/30",
    ]
    text = _text(done.text)
    assert "198.51.100.1" in text and "203.0.113.1/30" in text
    gone = _change(logged_in, scope="tunnel", action="delete", id_number="0")
    assert gone.status_code == 200, _text(gone.text)
    assert 0 not in stored.tunnels
    assert _config_requests(stored)[-1] == ["no interface tunnel 0"]


def test_a_switch_error_is_shown(logged_in: TestClient, stored: FakeSwitch) -> None:
    refused = _change(
        logged_in, scope="tunnel", setting="vrf", action="set", id_number="0", v_vrf="nowhere"
    )
    assert refused.status_code == 400
    assert "VRF nowhere does not exist" in _text(refused.text)


def test_changes_need_the_feature(logged_in: TestClient, stored: FakeSwitch) -> None:
    stored.feature_state["tunnel"] = False
    refused = _change(logged_in, scope="tunnel", action="create", id_number="1")
    assert refused.status_code == 400 and "tunnel is off on the switch" in _text(refused.text)
    assert _config_requests(stored) == []


def test_save_config_comes_back_here(logged_in: TestClient, stored: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "tunnels"})
    assert saved.status_code == 200
    assert "Make a tunnel" in _text(saved.text) and stored.saved
