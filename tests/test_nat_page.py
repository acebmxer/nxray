"""The NAT page (#95), end to end against the fake switch, and its parsers."""

from __future__ import annotations

import html
import json
import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.nat import (
    COMMANDS,
    PAGE_COMMANDS,
    build_nat_change,
    nat_regions,
    parse_lists_in_use,
    parse_nat,
    parse_nat_config,
    parse_statistics,
    parse_translations,
)
from app.port_changes import BROAD_RULES, NAT_CLEAR_RULES, ROLE_NAME
from app.switch_connection import BROAD_NAT_VERSION
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"


def _body(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


# Recorded on cisco-25gb (NX-OS 9.3(16)) during the probe, ACL and pool names changed.
TRANSLATIONS = _body("show_ip_nat_translations_verbose")
STATISTICS = _body("show_ip_nat_statistics")
MAXIMA = _body("show_ip_nat_max")
CONFIG = (FIXTURES / "show_running_config_nat.txt").read_text()
TCAM = (FIXTURES / "show_hardware_access_list_tcam_region.txt").read_text()
TCAM_COMMAND = "show hardware access-list tcam region"


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


def test_the_configuration() -> None:
    found = parse_nat_config(CONFIG + "interface Vlan250\n  ip nat inside\n")
    assert found.sides == {"Vlan250": {"inside"}}
    tcp = next(s for s in found.statics if s["protocol"] == "tcp")
    assert tcp == {
        "side": "inside",
        "protocol": "tcp",
        "real": "10.250.0.12",
        "real_port": "80",
        "translated": "198.51.100.12",
        "translated_port": "8080",
        "vrf": "",
        "match_in_vrf": "",
        "add_route": "",
    }
    in_vrf = next(s for s in found.statics if s["real"] == "10.250.0.15")
    assert (in_vrf["vrf"], in_vrf["match_in_vrf"]) == ("management", "match-in-vrf")
    routed = next(s for s in found.statics if s["real"] == "198.51.100.21")
    assert (routed["side"], routed["add_route"]) == ("outside", "add-route")
    grouped = next(s for s in found.statics if s["real"] == "10.250.0.16")
    assert grouped["translated"] == "198.51.100.16" and grouped["vrf"] == ""
    pools = {p["name"]: p for p in found.pools}
    assert pools["inside-pool"] == {
        "name": "inside-pool",
        "first": "198.51.100.100",
        "last": "198.51.100.110",
        "length": "24",
    }
    assert pools["outside-pool"]["length"] == "24"  # written with a netmask
    inside = next(d for d in found.dynamics if d["acl"] == "nat-inside")
    assert (inside["pool"], inside["overload"], inside["vrf"]) == ("inside-pool", "overload", "")
    mgmt = next(d for d in found.dynamics if d["acl"] == "nat-mgmt")
    assert (mgmt["vrf"], mgmt["overload"]) == ("management", "overload")
    back = next(d for d in found.dynamics if d["acl"] == "nat-back")
    assert (back["side"], back["add_route"]) == ("outside", "add-route")
    assert found.overloads == [{"acl": "nat-pat", "interface": "loopback250"}]
    assert found.limits == {
        "tcp": "172800",
        "udp": "600",
        "timeout": "86401",
        "max_entries": "1023",
        "all_host": "100",
        "icmp": "60",
    }


def test_the_translations_and_counters() -> None:
    rows = parse_translations(TRANSLATIONS)
    assert len(rows) == 9
    assert rows[0] == (
        "any", "-", "-", "10.250.0.20", "198.51.100.20", "default", "0", "0", "never",
    )  # fmt: skip
    tcp = next(r for r in rows if r[0] == "tcp")
    assert tcp[1:3] == ("10.250.0.12:80", "198.51.100.12:8080")
    assert any(r[5] == "management" for r in rows)
    counters = dict(parse_statistics(STATISTICS, MAXIMA))
    assert counters["Active translations"] == "9" and counters["Static"] == "9"
    assert counters["Most dynamic translations"] == "1023"
    assert counters["Most dynamic translations per host"] == "100"
    assert counters["Counted since"].startswith("Fri Nov 13")
    lists = parse_lists_in_use(STATISTICS)
    assert ("inside", "nat-inside", "pool inside-pool", "yes", "11", "0", "0") in lists
    assert ("inside", "nat-pat", "loopback250 (198.51.100.1)", "yes", "-", "-", "-") in lists
    assert ("outside", "nat-outside", "pool outside-pool", "no", "11", "0", "0") in lists
    assert parse_translations(None) == [] and parse_statistics(None, None) == []


def test_the_tcam_regions() -> None:
    assert nat_regions(TCAM) == [
        ("nat", "NAT ACL", "0"),
        ("tcp-nat", "TCP NAT ACL", "0"),
        ("mcast-nat", "MCAST NAT ACL", "0"),
    ]
    assert nat_regions(None) == []


def test_the_page_view() -> None:
    view = parse_nat([TRANSLATIONS, STATISTICS, MAXIMA], CONFIG, nat_regions(TCAM))
    statics = view.of("static")
    assert len(statics) == 10
    assert any(s.title == "Inside TCP 10.250.0.12:80 to 198.51.100.12:8080" for s in statics)
    (limits,) = view.of("limits")
    assert limits.values["udp"] == {"seconds": "600"}
    assert limits.values["max_entries"] == {"count": "1023"}
    assert dict(limits.facts)["UDP"] == "600 seconds"
    assert len(view.of("clear")) == 1
    titles = [t.title for t in view.tables]
    assert titles == [
        "TCAM space for NAT",
        "Translations",
        "Dynamic translations in use",
        "Counters",
    ]
    unread = parse_nat([None, None, None], None)
    assert unread.notes and not unread.of("static")


def test_the_lines() -> None:
    def lines(scope: str, action: str, ident=None, setting: str = "", **values: str):
        return build_nat_change(scope, setting, action, ident or {}, values).lines

    static = {"side": "inside", "real": "10.250.0.10", "translated": "198.51.100.10"}
    assert lines("static", "create", static) == (
        "ip nat inside source static 10.250.0.10 198.51.100.10",
    )
    full = {
        **static,
        "protocol": "tcp",
        "real_port": "80",
        "translated_port": "8080",
        "vrf": "lab",
        "match_in_vrf": "yes",
        "add_route": "yes",
    }
    assert lines("static", "create", full) == (
        "ip nat inside source static tcp 10.250.0.10 80 198.51.100.10 8080 vrf lab match-in-vrf "
        "add-route",
    )
    # Removing names the addresses, ports and VRF only, as the switch wants it.
    assert lines("static", "delete", full) == (
        "no ip nat inside source static tcp 10.250.0.10 80 198.51.100.10 8080 vrf lab",
    )
    assert lines("static", "delete", {**static, "vrf": "default"}) == (
        "no ip nat inside source static 10.250.0.10 198.51.100.10",
    )
    pool = {"name": "web", "first": "198.51.100.100", "last": "198.51.100.110", "length": "24"}
    assert lines("pool", "create", pool) == (
        "ip nat pool web 198.51.100.100 198.51.100.110 prefix-length 24",
    )
    assert lines("pool", "delete", pool) == ("no ip nat pool web",)
    dynamic = {"side": "inside", "acl": "nat-in", "pool": "web", "overload": "yes"}
    assert lines("dynamic", "create", dynamic) == (
        "ip nat inside source list nat-in pool web overload",
    )
    assert lines("dynamic", "delete", {**dynamic, "vrf": "lab"}) == (
        "no ip nat inside source list nat-in pool web vrf lab overload",
    )
    outside = {"side": "outside", "acl": "nat-out", "pool": "web", "add_route": "yes"}
    assert lines("dynamic", "create", outside) == (
        "ip nat outside source list nat-out pool web add-route",
    )
    pat = {"acl": "nat-in", "interface": "Vlan10"}
    assert lines("overload", "create", pat) == (
        "ip nat inside source list nat-in interface Vlan10 overload",
    )
    assert lines("overload", "delete", pat) == (
        "no ip nat inside source list nat-in interface Vlan10 overload",
    )
    port = {"interface": "Vlan250"}
    assert lines("interface", "set", port, "inside") == ("interface Vlan250", "ip nat inside")
    assert lines("interface", "remove", port, "outside")[-1] == "no ip nat outside"
    assert lines("limits", "set", None, "timeout", seconds="3600") == (
        "ip nat translation timeout 3600",
    )
    assert lines("limits", "remove", None, "timeout", seconds="3600") == (
        "no ip nat translation timeout",
    )
    # Its no form needs a number, as on the switch.
    assert lines("limits", "remove", None, "tcp", seconds="3600") == (
        "no ip nat translation tcp-timeout 3600",
    )
    assert lines("limits", "set", None, "all_host", count="100") == (
        "ip nat translation max-entries all-host 100",
    )
    assert lines("limits", "remove", None, "max_entries", count="100") == (
        "no ip nat translation max-entries",
    )
    assert lines("clear", "set", None, "all") == ("clear ip nat translation all",)
    assert lines(
        "clear", "set", None, "inside", inside_global="198.51.100.10", inside_local="10.0.0.1"
    ) == ("clear ip nat translation inside 198.51.100.10 10.0.0.1",)
    assert lines("clear", "set", None, "statistics") == ("clear ip nat statistics",)
    assert not build_nat_change("clear", "all", "set", {}, {}).config


@pytest.mark.parametrize(
    ("scope", "action", "setting", "ident", "values"),
    [
        # A port without tcp or udp, and tcp without both ports.
        ("static", "create", "", {"side": "inside", "real": "10.0.0.1", "real_port": "80",
                                  "translated": "198.51.100.1", "translated_port": "80"}, {}),
        ("static", "create", "", {"side": "inside", "protocol": "tcp", "real": "10.0.0.1",
                                  "translated": "198.51.100.1"}, {}),
        ("static", "create", "", {"side": "inside", "real": "10.0.0.1",
                                  "translated": "198.51.100.1", "match_in_vrf": "yes"}, {}),
        ("static", "create", "", {"side": "inside", "real": "2001:db8::1",
                                  "translated": "198.51.100.1"}, {}),
        ("dynamic", "create", "", {"side": "outside", "acl": "a", "pool": "p",
                                   "overload": "yes"}, {}),
        ("dynamic", "create", "", {"side": "inside", "acl": "a", "pool": "p",
                                   "add_route": "yes"}, {}),
        ("pool", "create", "", {"name": "p", "first": "198.51.100.20", "last": "198.51.100.10",
                                "length": "24"}, {}),
        ("limits", "set", "timeout", {}, {"seconds": "59"}),
        ("limits", "set", "tcp", {}, {"seconds": "172801"}),
        ("limits", "set", "max_entries", {}, {"count": "1024"}),
        ("interface", "set", "inside", {"interface": "loopback0"}, {}),
    ],
)  # fmt: skip
def test_wrong_values_are_refused(
    scope: str, action: str, setting: str, ident: dict[str, str], values: dict[str, str]
) -> None:
    with pytest.raises(ValueError):
        build_nat_change(scope, setting, action, ident, values)


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
    fake.feature_state.update({"nat": True, "interface-vlan": True})
    fake.svis = {250}
    fake.port_state["Vlan250"] = {"routed": True, "admin_up": True}
    fake.nat_lines += [
        "ip nat inside source static 10.250.0.10 198.51.100.10",
        "ip nat pool inside-pool 198.51.100.100 198.51.100.110 prefix-length 24",
        "ip nat inside source list nat-inside pool inside-pool overload",
    ]
    fake.bodies.update(
        {
            "show ip nat translations verbose": TRANSLATIONS,
            "show ip nat statistics": STATISTICS,
            "show ip nat max": MAXIMA,
        }
    )
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
    return client.post("/nat/change", data=data)


def _carve(switch: FakeSwitch) -> None:
    switch.security_lines.append("hardware access-list tcam region nat 256")


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/nat", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/nat"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/nat")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "Inside 10.250.0.10 to 198.51.100.10" in text
    assert "inside-pool" in text and "198.51.100.12:8080" in text
    assert "Active translations" in text
    # The region has no space: the page says so plainly.
    assert "The switch has no TCAM space for NAT" in text
    assert enabled.requests == [
        list(PAGE_COMMANDS),
        [TCAM_COMMAND],
        list(COMMANDS),
        ["show running-config"],
    ]
    assert "/nat/change" in page.text


def test_before_changes_are_on_only_the_state_shows(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    # NXray's account may not read the configuration text before it has its role.
    page = logged_in.get("/nat")
    text = _text(page.text)
    assert "did not show NAT's settings" in text and "198.51.100.12:8080" in text
    assert "/nat/change" not in page.text  # changes are off


def test_with_tcam_space_the_page_does_not_warn(logged_in: TestClient, switch: FakeSwitch) -> None:
    _carve(switch)
    text = _text(logged_in.get("/nat").text)
    assert "no TCAM space" not in text and "TCAM space for NAT" in text


def test_with_nat_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["nat"] = False
    text = _text(logged_in.get("/nat").text)
    assert "nat is off on the switch" in text
    assert "The switch has no TCAM space for NAT" in text
    assert switch.requests == [list(PAGE_COMMANDS), [TCAM_COMMAND]]


def test_the_switch_refuses_an_inside_interface_without_tcam_space(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    refused = _change(
        logged_in, scope="interface", setting="inside", action="set", id_interface="Vlan250"
    )
    assert refused.status_code == 400 and "Nat tcam not carved" in _text(refused.text)
    _carve(enabled)
    done = _change(
        logged_in, scope="interface", setting="inside", action="set", id_interface="Vlan250"
    )
    assert done.status_code == 200, _text(done.text)
    assert enabled.nat_sides == {"Vlan250": {"inside"}}
    assert "Side inside" in _text(done.text)


def test_static_translations(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {
        "id_side": "inside", "id_protocol": "tcp", "id_real": "10.250.0.12",
        "id_real_port": "80", "id_translated": "198.51.100.12", "id_translated_port": "8080",
        "id_vrf": "default", "id_add_route": "yes",
    }  # fmt: skip
    asked = _change(logged_in, confirm=False, scope="static", action="create", **fields)
    line = "ip nat inside source static tcp 10.250.0.12 80 198.51.100.12 8080 add-route"
    assert line in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, scope="static", action="create", **fields)
    assert done.status_code == 200, _text(done.text)
    assert line in enabled.nat_lines
    gone = _change(logged_in, scope="static", action="delete", **fields)
    assert gone.status_code == 200, _text(gone.text)
    assert _config_requests(enabled)[-1] == [
        "no ip nat inside source static tcp 10.250.0.12 80 198.51.100.12 8080"
    ]
    assert line not in enabled.nat_lines


def test_a_vrf_the_switch_lacks_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _change(
        logged_in, scope="static", action="create", id_side="inside", id_real="10.0.0.1",
        id_translated="198.51.100.1", id_vrf="nosuch",
    )  # fmt: skip
    assert refused.status_code == 400 and "has no VRF nosuch" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_dynamic_translations(logged_in: TestClient, enabled: FakeSwitch) -> None:
    pool = _change(
        logged_in, scope="pool", action="create", id_name="web", id_first="198.51.100.120",
        id_last="198.51.100.130", id_length="24",
    )  # fmt: skip
    assert pool.status_code == 200, _text(pool.text)
    # One ACL goes with one pool: the switch's answer is shown.
    again = _change(
        logged_in, scope="dynamic", action="create", id_side="inside", id_acl="nat-inside",
        id_pool="web", id_vrf="default",
    )  # fmt: skip
    assert again.status_code == 400 and "already mapped" in _text(again.text)
    pat = _change(
        logged_in, scope="overload", action="create", id_acl="nat-pat", id_interface="Vlan250"
    )
    assert pat.status_code == 200, _text(pat.text)
    assert "ip nat inside source list nat-pat interface Vlan250 overload" in enabled.nat_lines
    assert "ACL nat-pat to Vlan250's address" in _text(pat.text)


def test_timeouts(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(logged_in, scope="limits", setting="udp", action="set", v_seconds="600")
    assert done.status_code == 200, _text(done.text)
    assert "ip nat translation udp-timeout 600" in enabled.nat_lines
    # The SYN timeout needs the tcp-nat region: the switch's refusal is shown.
    refused = _change(logged_in, scope="limits", setting="syn", action="set", v_seconds="60")
    assert refused.status_code == 400 and "TCP-NAT tcam not configured" in _text(refused.text)
    gone = _change(logged_in, scope="limits", setting="udp", action="remove", v_seconds="600")
    assert gone.status_code == 200, _text(gone.text)
    assert not any("udp-timeout" in line for line in enabled.nat_lines)


def test_clearing_is_typed_outside_configuration_mode(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    done = _change(logged_in, scope="clear", setting="all", action="set")
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["clear ip nat translation all"]]
    assert enabled.nat_cleared == ["clear ip nat translation all"]
    # Nothing to save: clearing is not configuration.
    assert "Not saved yet" not in _text(done.text)


def test_the_broad_role_allows_clearing() -> None:
    assert set(NAT_CLEAR_RULES) <= set(BROAD_RULES)


def test_a_broad_role_written_before_clearing_is_refused_until_updated(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    for rule in NAT_CLEAR_RULES:
        enabled.roles[ROLE_NAME].entities.discard(rule.split(" command ", 1)[1])
    _db(settings, f"UPDATE switch_connection SET role_version = {BROAD_NAT_VERSION - 1}")
    refused = _change(logged_in, scope="clear", setting="statistics", action="set")
    assert refused.status_code == 400 and "Update the port list" in _text(refused.text)
    assert _config_requests(enabled) == []
    assert "allowed clearing NAT's" in _text(logged_in.get("/switch").text)
    # The rest of the page still changes.
    done = _change(logged_in, scope="limits", setting="timeout", action="set", v_seconds="3600")
    assert done.status_code == 200, _text(done.text)
    updated = logged_in.post(
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
    assert "The role now also allows clearing NAT's translations" in _text(updated.text)
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    done = _change(logged_in, scope="clear", setting="statistics", action="set")
    assert done.status_code == 200, _text(done.text)
    assert enabled.nat_cleared == ["clear ip nat statistics"]


def test_with_the_admin_login_stored_the_change_is_sent_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "stored")
    done = _change(logged_in, scope="clear", setting="all", action="set")
    assert done.status_code == 200, _text(done.text)
    assert "admin" in switch.signed_in


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    refused = _change(logged_in, scope="clear", setting="all", action="set")
    assert refused.status_code == 400 and "NAT changes are off" in _text(refused.text)
    assert _config_requests(switch) == []


def test_a_viewer_looks_only(logged_in: TestClient, enabled: FakeSwitch) -> None:
    password = "another-long-password"
    logged_in.post(
        "/users/create",
        data={
            "csrf": _csrf(logged_in, "/users"),
            "new_username": "vera",
            "password": password,
            "confirm_password": password,
            "role": "viewer",
        },
    )
    vera = TestClient(logged_in.app, follow_redirects=False)
    vera.post("/login", data={"username": "vera", "password": password, "next": "/"})
    page = vera.get("/nat")
    assert page.status_code == 200 and "Inside 10.250.0.10 to 198.51.100.10" in _text(page.text)
    assert "/nat/change" not in page.text
    assert "can look at NAT but not change it" in _text(page.text)
    refused = vera.post("/nat/change", data={"csrf": _csrf(vera), "scope": "clear"})
    assert refused.status_code in (303, 403)
    assert _config_requests(enabled) == []


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "nat"})
    assert saved.status_code == 200
    assert "Add a static translation" in _text(saved.text) and enabled.saved
