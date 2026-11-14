"""The IGMP snooping page (#95), end to end against the fake switch, and its parsers."""

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
from app.igmp_snooping import (
    COMMANDS,
    MROUTER_COMMAND,
    build_snooping_change,
    parse_mrouter,
    parse_snooping,
    parse_snooping_config,
    parse_snooping_counters,
)
from app.port_changes import BROAD_RULES, ROLE_NAME, SNOOPING_CLEAR_RULES
from app.switch_connection import BROAD_SNOOPING_CLEAR_VERSION
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"

# Recorded on cisco-25gb (NX-OS 9.3(16)): VLANs 1 and 10 as they are, VLAN 250 during the
# probe; the group's reporter address replaced with a documentation one.
STATE = json.loads((FIXTURES / "show_ip_igmp_snooping.json").read_text())
GROUPS = json.loads((FIXTURES / "show_ip_igmp_snooping_groups_detail.json").read_text())
QUERIERS = json.loads((FIXTURES / "show_ip_igmp_snooping_querier.json").read_text())
CONFIG = (FIXTURES / "show_running_config_igmp_snooping.txt").read_text()
MROUTER = (FIXTURES / "show_ip_igmp_snooping_mrouter.txt").read_text()
# Recorded on cisco-25gb (NX-OS 9.3(16), 2026-11-13): VLANs 1 and 10 as they are.
COUNTERS = json.loads((FIXTURES / "show_ip_igmp_snooping_statistics.json").read_text())


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
    return list(build_snooping_change(scope, setting, action, ident, values or {}).lines)


def _view():
    return parse_snooping([STATE, GROUPS, QUERIERS], CONFIG, MROUTER)


# ---- parsing and lines ----------------------------------------------------------------------


def test_the_vlan_configuration_is_read():
    (block,) = parse_snooping_config(CONFIG)
    assert block.vlan == "250" and block.snooping
    values = block.values
    assert values["fast_leave"] == {} and values["group_timeout_never"] == {}
    assert values["querier"] == {"address": "192.0.2.250"}
    assert values["proxy_queries"] == {"mrt": "7"}
    assert values["query_interval"] == {"seconds": "100"}
    assert values["robustness_variable"] == {"count": "3"}
    # Default-on settings are written only as their no forms.
    assert "report_suppression" not in values and "link_local_suppression" not in values
    assert "explicit_tracking" in values
    assert dict(block.places)["mrouter"] == {"port": "Ethernet1/53"}
    statics = [ident for scope, ident in block.places if scope == "static"]
    assert {"group": "232.1.2.3", "source": "192.0.2.10", "port": "Ethernet1/53"} in statics
    assert {"group": "239.1.2.3", "source": "", "port": "Ethernet1/53"} in statics
    filters = [ident for scope, ident in block.places if scope == "filter"]
    assert filters == [
        {
            "command": "report-policy",
            "kind": "route-map",
            "name": "nxprobe-rm",
            "port": "Ethernet1/53",
        }
    ]


def test_a_vlan_with_snooping_off():
    (block,) = parse_snooping_config("vlan configuration 20\n  no ip igmp snooping\n")
    assert not block.snooping


def test_the_page_view():
    view = _view()
    (whole,) = view.of("global")
    assert dict(whole.facts)["Snooping"] == "yes"
    assert dict(whole.facts)["IGMPv3 report suppression"] == "no"
    assert "report_suppression" in whole.values and "v3_report_suppression" not in whole.values
    vlans = {i.ident["vlan"]: i for i in view.of("vlan")}
    assert set(vlans) == {"1", "10", "250"}
    assert dict(vlans["250"].facts)["Querier"] == "192.0.2.250"
    assert vlans["250"].values["fast_leave"] == {}
    # A VLAN with no block of its own has the defaults.
    assert set(vlans["1"].values) == {
        "explicit_tracking",
        "report_suppression",
        "link_local_suppression",
    }
    titles = {i.title for i in view.instances}
    assert "VLAN 250: router port Ethernet1/53" in titles
    assert "VLAN 250: 232.1.2.3 from 192.0.2.10 on Ethernet1/53" in titles
    groups = next(t for t in view.tables if t.title == "Groups")
    assert groups.rows[0][:5] == ("10", "239.255.255.250", "3", "learned", "192.0.2.200")
    assert "Ethernet1/47 (00:03:08)" in groups.rows[0][5]
    queriers = next(t for t in view.tables if t.title == "Queriers")
    assert queriers.rows == (("250", "192.0.2.250", "v3", "00:00:09", "Switch querier"),)
    routers = next(t for t in view.tables if t.title == "Router ports")
    assert routers.rows == ()  # none up on the probe switch


def test_router_port_rows_follow_the_heading():
    text = MROUTER + "250   Eth1/53       S         00:10:02    never\n"
    assert parse_mrouter(text) == [("250", "Ethernet1/53", "S", "00:10:02", "never")]
    assert parse_mrouter(None) == []


def test_without_the_configuration_the_page_says_so():
    view = parse_snooping([STATE, GROUPS, QUERIERS], None)
    assert "did not show its configuration" in view.notes[0]
    assert not view.of("static")


def test_the_lines():
    vlan = {"vlan": "250"}
    assert _lines("vlan", "querier", "set", vlan, {"address": "192.0.2.1"}) == [
        "vlan configuration 250",
        "ip igmp snooping querier 192.0.2.1",
    ]
    assert _lines("vlan", "querier", "remove", vlan) == [
        "vlan configuration 250",
        "no ip igmp snooping querier",
    ]
    assert _lines("vlan", "snooping_off", "set", vlan) == [
        "vlan configuration 250",
        "no ip igmp snooping",
    ]
    assert _lines("vlan", "report_suppression", "remove", vlan)[-1] == (
        "no ip igmp snooping report-suppression"
    )
    assert _lines("vlan", "group_timeout", "remove", vlan, {"minutes": "10"})[-1] == (
        "no ip igmp snooping group-timeout 10"
    )
    assert _lines("vlan", "proxy_queries", "set", vlan, {"mrt": ""})[-1] == (
        "ip igmp snooping proxy general-queries"
    )
    static = {"vlan": "250", "group": "239.1.1.1", "source": "", "port": "eth1/5"}
    assert _lines("static", "", "create", static) == [
        "vlan configuration 250",
        "ip igmp snooping static-group 239.1.1.1 interface Ethernet1/5",
    ]
    assert _lines("static", "", "delete", {**static, "source": "192.0.2.9"})[-1] == (
        "no ip igmp snooping static-group 239.1.1.1 source 192.0.2.9 interface Ethernet1/5"
    )
    assert _lines("global", "event_history", "set", {}, {"buffer": "vlan", "size": "large"}) == [
        "ip igmp snooping event-history vlan size large"
    ]
    assert _lines("global", "vxlan", "set", {}) == ["ip igmp snooping vxlan"]


@pytest.mark.parametrize(
    ("scope", "setting", "ident", "values", "message"),
    [
        ("vlan", "query_interval", {"vlan": "250"}, {"seconds": "18001"}, "1 to 18000"),
        ("vlan", "robustness_variable", {"vlan": "250"}, {"count": "8"}, "1 to 7"),
        ("vlan", "group_timeout", {"vlan": "250"}, {"minutes": "10081"}, "1 to 10080"),
        ("vlan", "version", {"vlan": "250"}, {"version": "1"}, "one of 2, 3"),
        ("vlan", "querier", {"vlan": "4000"}, {"address": "192.0.2.1"}, "switch's own"),
    ],
)
def test_wrong_values_are_refused(scope, setting, ident, values, message):
    with pytest.raises(ValueError, match=message):
        build_snooping_change(scope, setting, "set", ident, values)


def test_reserved_groups_are_refused():
    with pytest.raises(ValueError, match="kept for routers"):
        build_snooping_change(
            "static", "", "create", {"vlan": "250", "group": "224.0.0.5", "port": "Ethernet1/5"}, {}
        )


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
    fake.bodies.update(
        {
            "show ip igmp snooping": STATE,
            "show ip igmp snooping groups detail": GROUPS,
            "show ip igmp snooping querier": QUERIERS,
            "show ip igmp snooping statistics": COUNTERS,
        }
    )
    fake.vlans.update({10: "VLAN0010", 250: "VLAN0250"})
    fake.texts[MROUTER_COMMAND] = MROUTER
    fake.mcast_lines += [
        "vlan configuration 250",
        "vlan configuration 250 ; ip igmp snooping fast-leave",
        "vlan configuration 250 ; ip igmp snooping mrouter interface Ethernet1/5",
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
    return client.post("/igmp-snooping/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/igmp-snooping", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/igmp-snooping"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/igmp-snooping")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "VLAN 250: router port Ethernet1/5" in text
    assert "239.255.255.250" in text and "Switch querier" in text
    assert enabled.requests == [list(COMMANDS), [MROUTER_COMMAND], ["show running-config"]]
    assert "/igmp-snooping/change" in page.text


def test_vlan_settings_and_places(logged_in: TestClient, enabled: FakeSwitch) -> None:
    asked = _change(
        logged_in, confirm=False, scope="vlan", setting="querier", action="set",
        id_vlan="250", v_address="192.0.2.1",
    )  # fmt: skip
    assert "ip igmp snooping querier 192.0.2.1" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(
        logged_in, scope="vlan", setting="querier", action="set", id_vlan="250",
        v_address="192.0.2.1",
    )  # fmt: skip
    assert done.status_code == 200, _text(done.text)
    off = _change(
        logged_in, scope="vlan", setting="report_suppression", action="remove", id_vlan="250"
    )
    assert off.status_code == 200, _text(off.text)
    static = _change(
        logged_in, scope="static", action="create", id_vlan="250", id_group="239.1.1.1",
        id_source="", id_port="eth1/6",
    )  # fmt: skip
    assert static.status_code == 200, _text(static.text)
    assert "vlan configuration 250 ; ip igmp snooping querier 192.0.2.1" in enabled.mcast_lines
    assert "vlan configuration 250 ; no ip igmp snooping report-suppression" in enabled.mcast_lines
    assert (
        "vlan configuration 250 ; ip igmp snooping static-group 239.1.1.1 interface Ethernet1/6"
        in enabled.mcast_lines
    )
    gone = _change(
        logged_in, scope="mrouter", action="delete", id_vlan="250", id_port="Ethernet1/5"
    )
    assert gone.status_code == 200, _text(gone.text)
    assert not any("mrouter" in line for line in enabled.mcast_lines)


def test_a_vlan_or_port_the_switch_lacks_is_refused(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    vlan = _change(logged_in, scope="vlan", setting="fast_leave", action="set", id_vlan="99")
    assert vlan.status_code == 400 and "no VLAN 99" in _text(vlan.text)
    port = _change(
        logged_in, scope="mrouter", action="create", id_vlan="250", id_port="port-channel4000"
    )
    assert port.status_code == 400 and "no port port-channel4000" in _text(port.text)
    assert _config_requests(enabled) == []


def test_switch_wide_settings(logged_in: TestClient, enabled: FakeSwitch) -> None:
    asked = _change(logged_in, confirm=False, scope="global", setting="snooping_off", action="set")
    assert "floods multicast to all its ports" in _text(asked.text)
    done = _change(logged_in, scope="global", setting="group_timeout", action="set", v_minutes="30")
    assert done.status_code == 200, _text(done.text)
    again = _change(
        logged_in, scope="global", setting="group_timeout", action="set", v_minutes="60"
    )
    assert again.status_code == 200, _text(again.text)
    assert [line for line in enabled.mcast_lines if "group-timeout" in line] == [
        "ip igmp snooping group-timeout 60"
    ]


def test_with_the_admin_login_stored_the_change_is_sent_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "stored")
    done = _change(logged_in, scope="vlan", setting="fast_leave", action="remove", id_vlan="250")
    assert done.status_code == 200, _text(done.text)
    assert "admin" in switch.signed_in
    assert "vlan configuration 250 ; ip igmp snooping fast-leave" not in switch.mcast_lines


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    refused = _change(logged_in, scope="vlan", setting="fast_leave", action="set", id_vlan="250")
    assert refused.status_code == 400 and "IGMP snooping changes are off" in _text(refused.text)
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
    page = vera.get("/igmp-snooping")
    assert page.status_code == 200 and "VLAN 250" in _text(page.text)
    assert "/igmp-snooping/change" not in page.text


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "igmp-snooping"})
    assert saved.status_code == 200
    assert "Add a static group" in _text(saved.text) and enabled.saved


# ---- clearing (E4) ----------------------------------------------------------------------------


def test_the_counters_are_read() -> None:
    assert parse_snooping_counters(COUNTERS) == [
        ("1", "0/0/26", "0/0/0", "0", "0", "0/0", "never cleared"),
        ("10", "0/855/60097", "0/0/0", "855", "0", "0/0", "never cleared"),
    ]
    view = parse_snooping([STATE, GROUPS, QUERIERS, COUNTERS], CONFIG)
    assert [t.title for t in view.tables][-1] == "Counters"
    assert {i.title for i in view.of("clear")} == {"VLAN 1", "VLAN 10", "VLAN 250"}


def test_the_clear_lines() -> None:
    assert _lines("clear", "groups", "set", {"vlan": "250"}) == [
        "clear ip igmp snooping groups * vlan 250"
    ]
    assert _lines(
        "clear", "group", "set", {"vlan": "250"}, {"group": "239.1.1.1", "source": "192.0.2.10"}
    ) == ["clear ip igmp snooping groups 239.1.1.1 192.0.2.10 vlan 250"]
    assert _lines("clear", "group", "set", {"vlan": "250"}, {"group": "239.1.1.1"}) == [
        "clear ip igmp snooping groups 239.1.1.1 vlan 250"
    ]
    assert _lines("clear", "statistics", "set", {"vlan": "10"}) == [
        "clear ip igmp snooping statistics vlan 10"
    ]
    assert _lines("clear", "explicit_tracking", "set", {"vlan": "10"}) == [
        "clear ip igmp snooping explicit-tracking vlan 10"
    ]
    with pytest.raises(ValueError, match="routers talking"):
        build_snooping_change("clear", "group", "set", {"vlan": "10"}, {"group": "224.0.0.5"})
    with pytest.raises(ValueError, match="cannot be removed"):
        build_snooping_change("clear", "statistics", "remove", {"vlan": "10"}, {})


def test_clearing_is_typed_outside_configuration_mode(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    asked = _change(logged_in, confirm=False, scope="clear", setting="groups", action="set",
                    id_vlan="10")  # fmt: skip
    assert "clear ip igmp snooping groups * vlan 10" in _text(asked.text)
    assert "may stop until they report again" in _text(asked.text)
    done = _change(logged_in, scope="clear", setting="groups", action="set", id_vlan="10")
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["clear ip igmp snooping groups * vlan 10"]]
    assert enabled.l2_ran == ["clear ip igmp snooping groups * vlan 10"]
    # Nothing to save: clearing is not configuration.
    assert "Not saved yet" not in _text(done.text)
    missing = _change(logged_in, scope="clear", setting="statistics", action="set",
                      id_vlan="300")  # fmt: skip
    assert missing.status_code == 400 and "no VLAN 300" in _text(missing.text)


def test_the_broad_role_allows_clearing() -> None:
    assert set(SNOOPING_CLEAR_RULES) <= set(BROAD_RULES)


def test_a_broad_role_written_before_clearing_is_refused_until_updated(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    for rule in SNOOPING_CLEAR_RULES:
        enabled.roles[ROLE_NAME].entities.discard(rule.split(" command ", 1)[1])
    _db(settings, f"UPDATE switch_connection SET role_version = {BROAD_SNOOPING_CLEAR_VERSION - 1}")
    refused = _change(logged_in, scope="clear", setting="statistics", action="set", id_vlan="10")
    assert refused.status_code == 400 and "Update the port list" in _text(refused.text)
    assert _config_requests(enabled) == []
    assert "allowed clearing IGMP snooping's" in _text(logged_in.get("/switch").text)
    # The rest of the page still changes.
    done = _change(logged_in, scope="vlan", setting="fast_leave", action="set", id_vlan="250")
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
    assert "also allows clearing IGMP snooping's groups and counters" in _text(updated.text)
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    done = _change(logged_in, scope="clear", setting="statistics", action="set", id_vlan="10")
    assert done.status_code == 200, _text(done.text)
    assert enabled.l2_ran == ["clear ip igmp snooping statistics vlan 10"]
