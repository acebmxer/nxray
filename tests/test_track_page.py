"""The Tracked objects page (#95), end to end against the fake switch, and its parsers."""

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
from app.protocols_fhrp import HSRP
from app.track import (
    COMMANDS,
    PAGE_COMMANDS,
    TRACK_HINT,
    TRACK_MAX,
    build_track_change,
    parse_track,
    parse_track_config,
    parse_track_state,
)
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"

# Recorded on cisco-25gb (NX-OS 9.3(16)) during the probe, with throwaway objects.
STATE = json.loads((FIXTURES / "show_track.json").read_text())
CONFIG = (FIXTURES / "show_running_config_track.txt").read_text()


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


def test_the_state() -> None:
    states = {s.number: s for s in parse_track_state(STATE)}
    assert len(states) == 18
    first = states["250"]
    assert (first.kind, first.follows, first.state) == (
        "Interface",
        "loopback250 line-protocol",
        "UP",
    )
    assert first.used_by == (
        "Track List 258",
        "Track List 259",
        "Track List 260",
        "Track List 261",
    )
    assert states["253"].vrf == "management" and states["253"].kind == "IPv4 route"
    assert states["254"].kind == "IPv6 route"
    assert states["255"].follows == "entry 250"
    weight = states["260"]
    assert weight.kind == "List: by weight" and weight.threshold == "Threshold weight up 30 down 5"
    assert weight.members[0] == "object 253 weight 10 DOWN"
    # One member comes as a string, not a list.
    assert states["259"].members == ("object 250 UP",)
    assert parse_track_state(None) == []


def test_the_configuration() -> None:
    blocks = {b.ident["number"]: b for b in parse_track_config(CONFIG)}
    assert blocks["250"].scope == "interface"
    assert blocks["250"].ident == {
        "number": "250",
        "interface": "loopback250",
        "what": "line-protocol",
    }
    assert blocks["251"].ident["what"] == "ip routing"
    assert blocks["253"].ident == {"number": "253", "family": "ip", "prefix": "198.51.100.0/24"}
    assert blocks["254"].ident["family"] == "ipv6"
    # "state" is the default and not written: it is read back as state.
    assert blocks["256"].ident == {"number": "256", "entry": "251", "what": "state"}
    assert blocks["257"].ident["what"] == "reachability"
    assert blocks["258"].ident == {"number": "258", "kind": "and"}
    assert blocks["260"].scope == "weight" and blocks["261"].scope == "percentage"


def test_the_page_view() -> None:
    view = parse_track(STATE, CONFIG)
    (first,) = [i for i in view.of("interface") if i.ident["number"] == "250"]
    assert first.title == "Object 250: loopback250 line-protocol"
    assert first.values == {"delay": {"up": "180", "down": "4"}}
    facts = dict(first.facts)
    assert facts["State"] == "UP" and facts["Waits"] == "up 180 s, down 4 s"
    (route,) = [i for i in view.of("route") if i.ident["number"] == "253"]
    assert route.values["vrf"] == {"vrf": "management"}
    (weight,) = view.of("weight")
    assert weight.values["threshold"] == {"up": "30", "down": "5"}
    assert "object 252 weight 255 DOWN" in dict(weight.facts)["Objects"]
    (percentage,) = view.of("percentage")
    assert percentage.values["threshold"] == {"up": "60", "down": ""}
    (table,) = view.tables
    assert table.rows[0] == (
        "250", "Interface", "loopback250 line-protocol", "UP", "1", "00:00:34",
        "Track List 258, Track List 259, Track List 260, Track List 261",
    )  # fmt: skip
    unread = parse_track(STATE, None)
    assert unread.notes and not unread.instances and unread.tables[0].rows


def test_the_lines() -> None:
    def lines(scope: str, action: str, ident: dict[str, str], setting: str = "", **values: str):
        return build_track_change(scope, setting, action, ident, values).lines

    port = {"number": "10", "interface": "eth1/49", "what": "line-protocol"}
    assert lines("interface", "create", port) == ("track 10 interface Ethernet1/49 line-protocol",)
    assert lines("interface", "delete", port) == ("no track 10",)
    assert lines("interface", "set", port, "delay", up="5", down="") == (
        "track 10 interface Ethernet1/49 line-protocol",
        "delay up 5",
    )
    assert lines("interface", "remove", port, "delay")[-1] == "no delay"
    route = {"number": "11", "family": "ip", "prefix": "0.0.0.0/0"}
    assert lines("route", "create", route) == ("track 11 ip route 0.0.0.0/0 reachability",)
    assert lines("route", "set", route, "vrf", vrf="lab")[-1] == "vrf member lab"
    assert lines("route", "remove", route, "vrf", vrf="lab")[-1] == "no vrf member lab"
    sla = {"number": "12", "entry": "5", "what": "reachability"}
    assert lines("sla", "create", sla) == ("track 12 ip sla 5 reachability",)
    boolean = {"number": "13", "kind": "and"}
    assert lines("boolean", "set", boolean, "object", object="10", negate="yes") == (
        "track 13 list boolean and",
        "object 10 not",
    )
    assert lines("boolean", "remove", boolean, "object", object="10")[-1] == "no object 10"
    weight = {"number": "14"}
    assert lines("weight", "set", weight, "object", object="10", weight="20")[-1] == (
        "object 10 weight 20"
    )
    assert lines("weight", "set", weight, "threshold", up="20", down="5") == (
        "track 14 list threshold weight",
        "threshold weight up 20 down 5",
    )
    assert lines("percentage", "set", {"number": "15"}, "threshold", up="50", down="")[-1] == (
        "threshold percentage up 50"
    )
    assert lines("percentage", "remove", {"number": "15"}, "threshold")[-1] == (
        "no threshold percentage"
    )
    # Any interface, to read it only: VLAN interfaces above NXray's own range too.
    assert lines("interface", "create", {**port, "interface": "Vlan300"})[0] == (
        "track 10 interface Vlan300 line-protocol"
    )


@pytest.mark.parametrize(
    ("scope", "action", "setting", "ident", "values"),
    [
        ("interface", "create", "", {"number": "513", "interface": "loopback0",
                                     "what": "line-protocol"}, {}),
        ("interface", "create", "", {"number": "0", "interface": "loopback0",
                                     "what": "line-protocol"}, {}),
        ("interface", "create", "", {"number": "1", "interface": "bogus1",
                                     "what": "line-protocol"}, {}),
        ("route", "create", "", {"number": "1", "family": "ip", "prefix": "2001:db8::/32"}, {}),
        ("route", "create", "", {"number": "1", "family": "ipv6", "prefix": "10.0.0.0/8"}, {}),
        ("sla", "create", "", {"number": "1", "entry": "2147483648", "what": "state"}, {}),
        ("interface", "set", "delay", {"number": "1", "interface": "loopback0",
                                       "what": "line-protocol"}, {"up": "181"}),
        ("interface", "set", "delay", {"number": "1", "interface": "loopback0",
                                       "what": "line-protocol"}, {}),
        ("weight", "set", "threshold", {"number": "1"}, {"up": "10", "down": "20"}),
        ("weight", "set", "threshold", {"number": "1"}, {"up": "256"}),
        ("percentage", "set", "threshold", {"number": "1"}, {"up": "101"}),
        ("weight", "set", "object", {"number": "1"}, {"object": "2", "weight": "0"}),
    ],
)  # fmt: skip
def test_wrong_values_are_refused(
    scope: str, action: str, setting: str, ident: dict[str, str], values: dict[str, str]
) -> None:
    with pytest.raises(ValueError):
        build_track_change(scope, setting, action, ident, values)


def test_hsrp_points_at_this_page() -> None:
    group = next(s for s in HSRP.scopes if s.setting("track") is not None)
    (field,) = [f for f in group.setting("track").fields if f.name == "object"]
    assert field.hint == TRACK_HINT and field.maximum == TRACK_MAX


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
    fake.tracks.update(
        {
            1: ["interface Ethernet1/1 line-protocol", "delay up 10"],
            2: ["ip route 0.0.0.0/0 reachability"],
            3: ["list boolean and", "object 1", "object 2 not"],
        }
    )
    fake.track_up.add(1)
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
    return client.post("/track/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/track", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/track"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/track")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "Object 1: Ethernet1/1 line-protocol" in text
    assert "Object 3: boolean and" in text and "object 1 UP; object 2 DOWN" in text
    assert "Used by Track List 3" in text
    assert enabled.requests == [list(PAGE_COMMANDS), list(COMMANDS), ["show running-config"]]
    assert "/track/change" in page.text


def test_before_changes_are_on_only_the_state_shows(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    page = logged_in.get("/track")
    text = _text(page.text)
    assert "only their state is shown" in text and "Ethernet1/1 line-protocol" in text
    assert "/track/change" not in page.text  # changes are off


def test_with_no_objects_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.tracks.clear()
    text = _text(logged_in.get("/track").text)
    assert "No tracked objects yet." in text


def test_making_and_changing_an_object(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {"id_number": "20", "id_interface": "Ethernet1/2", "id_what": "ip routing"}
    asked = _change(logged_in, confirm=False, scope="interface", action="create", **fields)
    assert "track 20 interface Ethernet1/2 ip routing" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, scope="interface", action="create", **fields)
    assert done.status_code == 200, _text(done.text)
    waited = _change(
        logged_in, scope="interface", setting="delay", action="set", v_up="", v_down="7",
        **fields,
    )  # fmt: skip
    assert waited.status_code == 200, _text(waited.text)
    assert _config_requests(enabled) == [
        ["track 20 interface Ethernet1/2 ip routing"],
        ["track 20 interface Ethernet1/2 ip routing", "delay down 7"],
    ]
    assert enabled.tracks[20] == ["interface Ethernet1/2 ip routing", "delay down 7"]
    assert "Object 20: Ethernet1/2 ip routing" in _text(waited.text)


def test_an_interface_the_switch_lacks_is_refused(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    refused = _change(
        logged_in, scope="interface", action="create", id_number="21",
        id_interface="Ethernet1/99", id_what="line-protocol",
    )  # fmt: skip
    assert refused.status_code == 400 and "no interface Ethernet1/99" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_an_object_on_a_deleted_interface_can_still_be_deleted(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.tracks[30] = ["interface Vlan99 line-protocol"]
    gone = _change(
        logged_in, scope="interface", action="delete", id_number="30", id_interface="Vlan99",
        id_what="line-protocol",
    )  # fmt: skip
    assert gone.status_code == 200, _text(gone.text)
    assert 30 not in enabled.tracks


def test_the_switchs_refusals_are_shown(logged_in: TestClient, enabled: FakeSwitch) -> None:
    # An object a list uses cannot be deleted.
    used = _change(
        logged_in, scope="interface", action="delete", id_number="1", id_interface="Ethernet1/1",
        id_what="line-protocol",
    )  # fmt: skip
    assert used.status_code == 400 and "currently tracked" in _text(used.text)
    # A list cannot hold itself.
    itself = _change(
        logged_in, scope="boolean", setting="object", action="set", id_number="3",
        id_kind="and", v_object="3",
    )  # fmt: skip
    assert itself.status_code == 400 and "cannot contain itself" in _text(itself.text)
    # An object cannot change kind.
    kind = _change(
        logged_in, scope="route", action="create", id_number="1", id_family="ip",
        id_prefix="10.0.0.0/8",
    )  # fmt: skip
    assert kind.status_code == 400 and "Cannot modify already existing object" in _text(kind.text)


def test_lists(logged_in: TestClient, enabled: FakeSwitch) -> None:
    made = _change(logged_in, scope="weight", action="create", id_number="40")
    assert made.status_code == 200, _text(made.text)
    member = _change(
        logged_in, scope="weight", setting="object", action="set", id_number="40",
        v_object="1", v_weight="20",
    )  # fmt: skip
    assert member.status_code == 200, _text(member.text)
    threshold = _change(
        logged_in, scope="weight", setting="threshold", action="set", id_number="40",
        v_up="20", v_down="5",
    )  # fmt: skip
    assert threshold.status_code == 200, _text(threshold.text)
    assert enabled.tracks[40] == [
        "list threshold weight",
        "object 1 weight 20",
        "threshold weight up 20 down 5",
    ]
    # An AND list made again as or turns into an OR list.
    turned = _change(logged_in, scope="boolean", action="create", id_number="3", id_kind="or")
    assert turned.status_code == 200, _text(turned.text)
    assert enabled.tracks[3][0] == "list boolean or"


def test_with_the_admin_login_stored_the_change_is_sent_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "stored")
    done = _change(
        logged_in, scope="sla", action="create", id_number="50", id_entry="1", id_what="state"
    )
    assert done.status_code == 200, _text(done.text)
    assert "admin" in switch.signed_in
    assert switch.tracks[50] == ["ip sla 1"]  # state is the default, not written


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    refused = _change(logged_in, scope="weight", action="create", id_number="40")
    assert refused.status_code == 400 and "Tracked object changes are off" in _text(refused.text)
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
    page = vera.get("/track")
    assert page.status_code == 200 and "Object 1: Ethernet1/1" in _text(page.text)
    assert "/track/change" not in page.text
    assert "can look at tracked objects but not change them" in _text(page.text)


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "track"})
    assert saved.status_code == 200
    assert "Track an interface" in _text(saved.text) and enabled.saved
