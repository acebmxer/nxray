"""The Policy-based routing page (#81), end to end against the fake switch, and its parser."""

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
from app.pbr import COMMANDS, PAGE_COMMANDS, build_pbr_change, parse_pbr, parse_statistics
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"


def _body(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


# Shaped with the keys show route-map, show ip policy and the pbr-statistics output had
# on cisco-25gb (NX-OS 9.3(16)) during the probe; names and addresses are made up.
ROUTE_MAPS = _body("show_route_map_pbr")
POLICY = _body("show_ip_policy_pbr")
STATISTICS = _body("show_route_map_pbr_statistics")


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


def test_the_route_maps_policies_and_counters() -> None:
    view = parse_pbr([ROUTE_MAPS, POLICY, None], {"pbr-web": STATISTICS})
    web, v6 = view.of("route_map")
    assert dict(web.facts) == {"Entries": "2", "Applied on": "Vlan250"}
    assert web.values == {"statistics": {"on": "yes"}}
    assert dict(v6.facts)["Applied on"] == "no interface" and v6.values == {}
    first, second, third = view.of("entry")
    assert first.ident == {"name": "pbr-web", "seq": "10", "action": "permit"}
    assert first.values["match_ip"] == {"acl": "web-acl"}
    assert first.values["next_hop"] == {
        "hops": "198.51.100.10 198.51.100.11",
        "load_share": "load-share",
        "force_order": "",
        "drop_on_fail": "",
    }
    assert first.values["description"] == {"text": "web to the firewall"}
    assert "null" in second.values
    assert third.values["next_hop6"]["hops"] == "2001:db8::10"
    (place,) = view.of("interface")
    assert place.ident == {"interface": "Vlan250"} and place.values == {
        "policy": {"map": "pbr-web"}
    }
    applied, counters = view.tables
    assert applied.rows == (("Vlan250", "IPv4", "pbr-web", "Active", "default"),)
    assert counters.rows[-1] == ("pbr-web", "-", "routing table", "7")


def test_the_counters() -> None:
    assert parse_statistics(STATISTICS) == [
        ("pbr-web", "10", "permit", "120"),
        ("pbr-web", "20", "permit", "3"),
        ("pbr-web", "-", "routing table", "7"),
    ]
    assert parse_statistics(None) == []


def test_nothing_made_gives_an_empty_page() -> None:
    view = parse_pbr([{}, None, None])
    assert view.instances == ()
    assert view.tables[0].rows == ()


def test_the_lines() -> None:
    entry = {"name": "pbr-web", "seq": "10", "action": "permit"}

    def lines(scope: str, setting: str, action: str, ident=None, **values: str):
        return build_pbr_change(scope, setting, action, ident or entry, values).lines

    assert lines("entry", "", "create") == ("route-map pbr-web permit 10",)
    assert lines("entry", "", "delete") == ("no route-map pbr-web permit 10",)
    assert lines("entry", "match_ip", "set", acl="web-acl")[-1] == "match ip address web-acl"
    assert lines("entry", "match_ip", "remove", acl="web-acl")[-1] == (
        "no match ip address web-acl"
    )
    assert lines("entry", "next_hop", "set", hops="192.0.2.1, 192.0.2.2")[-1] == (
        "set ip next-hop 192.0.2.1 192.0.2.2"
    )
    # The bare no form removes nothing on the switch: the whole line goes back.
    assert (
        lines(
            "entry", "next_hop", "remove", hops="192.0.2.1", load_share="yes", drop_on_fail="yes"
        )[-1]
        == "no set ip next-hop 192.0.2.1 load-share drop-on-fail"
    )
    assert lines("entry", "next_hop6", "set", hops="2001:db8::1", force_order="yes")[-1] == (
        "set ipv6 next-hop 2001:db8::1 force-order"
    )
    assert lines("entry", "null", "set")[-1] == "set interface null0"
    whole = {"name": "pbr-web"}
    assert lines("route_map", "statistics", "set", whole) == ("route-map pbr-web pbr-statistics",)
    assert lines("route_map", "statistics", "remove", whole) == (
        "no route-map pbr-web pbr-statistics",
    )
    assert lines("route_map", "", "delete", whole) == ("no route-map pbr-web",)
    port = {"interface": "Vlan250"}
    assert lines("interface", "policy", "set", port, map="pbr-web") == (
        "interface Vlan250",
        "ip policy route-map pbr-web",
    )
    assert lines("interface", "policy6", "remove", port, map="pbr-v6")[-1] == (
        "no ipv6 policy route-map pbr-v6"
    )


@pytest.mark.parametrize(
    ("scope", "setting", "ident", "values"),
    [
        ("entry", "next_hop", {"name": "a", "seq": "10", "action": "permit"}, {"hops": ""}),
        (
            "entry",
            "next_hop",
            {"name": "a", "seq": "10", "action": "permit"},
            {"hops": "2001:db8::1"},  # IPv6 in the IPv4 line
        ),
        (
            "entry",
            "next_hop",
            {"name": "a", "seq": "10", "action": "permit"},
            {"hops": " ".join(f"192.0.2.{n}" for n in range(1, 18))},  # 17 next hops
        ),
        ("entry", "match_ip", {"name": "a", "seq": "0", "action": "permit"}, {"acl": "x"}),
        ("entry", "match_ip", {"name": "a", "seq": "10", "action": "allow"}, {"acl": "x"}),
        ("interface", "policy", {"interface": "loopback0"}, {"map": "a"}),
    ],
)
def test_wrong_values_are_refused(
    scope: str, setting: str, ident: dict[str, str], values: dict[str, str]
) -> None:
    with pytest.raises(ValueError):
        build_pbr_change(scope, setting, "set", ident, values)


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
    fake.feature_state.update({"pbr": True, "interface-vlan": True})
    fake.svis = {250}
    fake.port_state["Vlan250"] = {"routed": True, "admin_up": True}
    fake.bodies.update(
        {
            "show route-map": ROUTE_MAPS,
            "show ip policy": POLICY,
            "show ipv6 policy": None,  # as on cisco-25gb with no policy applied
            "show route-map pbr-web pbr-statistics": STATISTICS,
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
    return client.post("/pbr/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/pbr", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/pbr"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/pbr")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "pbr-web permit 10" in text and "web to the firewall" in text
    assert "Vlan250" in text and "120" in text
    assert switch.requests == [
        list(PAGE_COMMANDS),
        list(COMMANDS),
        ["show route-map pbr-web pbr-statistics"],
    ]
    assert "/pbr/change" not in page.text  # changes are off


def test_with_pbr_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["pbr"] = False
    text = _text(logged_in.get("/pbr").text)
    assert "pbr is off on the switch" in text
    assert switch.requests == [list(PAGE_COMMANDS)]


def test_adding_an_entry_and_applying_it(logged_in: TestClient, enabled: FakeSwitch) -> None:
    entry = {"id_name": "lab", "id_seq": "10", "id_action": "permit"}
    asked = _change(
        logged_in, confirm=False, scope="entry", setting="next_hop", action="set",
        v_hops="192.0.2.1", **entry,
    )  # fmt: skip
    assert "set ip next-hop 192.0.2.1" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(
        logged_in, scope="entry", setting="next_hop", action="set", v_hops="192.0.2.1", **entry
    )
    assert done.status_code == 200, _text(done.text)
    applied = _change(
        logged_in,
        scope="interface",
        setting="policy",
        action="set",
        id_interface="Vlan250",
        v_map="lab",
    )
    assert applied.status_code == 200, _text(applied.text)
    assert _config_requests(enabled) == [
        ["route-map lab permit 10", "set ip next-hop 192.0.2.1"],
        ["interface Vlan250", "ip policy route-map lab"],
    ]
    assert "route-map lab permit 10 ; set ip next-hop 192.0.2.1" in enabled.protocol_lines
    assert "interface Vlan250 ; ip policy route-map lab" in enabled.protocol_lines


def test_an_interface_the_switch_lacks_is_refused(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    refused = _change(
        logged_in,
        scope="interface",
        setting="policy",
        action="set",
        id_interface="Vlan99",
        v_map="lab",
    )
    assert refused.status_code == 400 and "Vlan99 is not a VLAN interface" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_counting_and_deleting_a_route_map(logged_in: TestClient, enabled: FakeSwitch) -> None:
    on = _change(
        logged_in, scope="route_map", setting="statistics", action="set", id_name="pbr-web"
    )
    assert on.status_code == 200, _text(on.text)
    gone = _change(logged_in, scope="route_map", action="delete", id_name="pbr-web")
    assert gone.status_code == 200, _text(gone.text)
    assert _config_requests(enabled) == [
        ["route-map pbr-web pbr-statistics"],
        ["no route-map pbr-web"],
    ]


def test_with_the_admin_login_stored_the_change_is_sent_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "stored")
    done = _change(
        logged_in, scope="entry", action="create", id_name="lab", id_seq="10", id_action="permit"
    )
    assert done.status_code == 200, _text(done.text)
    assert "admin" in switch.signed_in


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    refused = _change(
        logged_in, scope="entry", action="create", id_name="lab", id_seq="10", id_action="permit"
    )
    assert refused.status_code == 400 and "changes are off" in _text(refused.text)
    assert _config_requests(switch) == []


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "pbr"})
    assert saved.status_code == 200
    assert "Add a route-map entry" in _text(saved.text) and enabled.saved
