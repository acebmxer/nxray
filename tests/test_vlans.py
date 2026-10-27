"""VLAN parsing, the VLAN list format, the guarded VLAN commands and the VLAN role rules."""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterable
from pathlib import Path

import httpx
import pytest

from app.db import _MIGRATIONS, init_db, migrate, open_db
from app.nxapi import (
    NxapiClient,
    SwitchTarget,
    format_vlan_list,
    parse_vlan_list,
    validate_vlan_id,
    validate_vlan_name,
)
from app.port_changes import (
    ROLE_RULES,
    ROLE_VERSION,
    VLAN_RULES,
    enable_port_changes,
    role_lines,
)
from app.switch_connection import (
    SwitchConnection,
    get_connection,
    save_connection,
    set_changes_enabled,
)
from app.vlans import (
    ALL_VLANS,
    PortVlans,
    Vlan,
    VlanView,
    describe_port_vlans,
    parse_switchports,
    parse_vlans,
    plan_port_vlans,
)
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

NXRAY_PASSWORD = "Nxray4Test9Pw"


# ---- parsing recorded switch output ---------------------------------------


def test_live_vlan_brief_has_the_default_vlan_only() -> None:
    # cisco-25gb as delivered: one VLAN, so the table holds one object, not a list.
    vlans = parse_vlans(load_fixture("show_vlan_brief"))
    assert [(v.id, v.name, v.state) for v in vlans] == [(1, "default", "active")]


def test_vlan_brief_with_several_vlans() -> None:
    # Recorded during the permission probe, with a test VLAN named by the probe.
    vlans = parse_vlans(load_fixture("show_vlan_brief_two"))
    assert [(v.id, v.name) for v in vlans] == [(1, "default"), (3900, "Ab.c_d-e/f+g")]


def test_vlan_shut_down_is_reported() -> None:
    body = {
        "TABLE_vlanbriefxbrief": {
            "ROW_vlanbriefxbrief": {
                "vlanshowbr-vlanid": "20",
                "vlanshowbr-vlanname": "lab",
                "vlanshowbr-vlanstate": "active",
                "vlanshowbr-shutstate": "shutdown",
            }
        }
    }
    assert parse_vlans(body)[0].state == "shutdown"


def test_live_switchports_are_access_ports_in_vlan_1() -> None:
    ports = parse_switchports(load_fixture("show_interface_switchport"))
    assert len(ports) == 54
    first = ports["Ethernet1/1"]
    assert (first.switchport, first.mode, first.access_vlan, first.native_vlan) == (
        True,
        "access",
        1,
        1,
    )
    assert first.allowed == ALL_VLANS and first.allowed_text == "1-4094"


def test_trunk_switchport_recorded_live() -> None:
    port = parse_switchports(load_fixture("show_interface_switchport_trunk"))["Ethernet1/54"]
    assert (port.mode, port.native_vlan) == ("trunk", 3900)
    assert port.allowed_text == "1,10-12,3900"
    # The access VLAN the probe set while it was an access port stays stored.
    assert port.access_vlan == 3950


# ---- the VLAN list format ---------------------------------------------------


@pytest.mark.parametrize(
    ("typed", "numbers"),
    [
        ("10", [10]),
        ("1,10-12,3900", [1, 10, 11, 12, 3900]),
        (" 20 , 10-11 ,10", [10, 11, 20]),
        ("none", []),
        ("", []),
        ("ALL", list(range(1, 4095))),
        ("1-4094", list(range(1, 4095))),
    ],
)
def test_vlan_lists_accepted(typed: str, numbers: list[int]) -> None:
    assert parse_vlan_list(typed) == numbers


@pytest.mark.parametrize(
    "typed", ["0", "4095", "10-5", "abc", "10;reload", "1,,2", "10 20", "-3", "1-2-3", "１０"]
)
def test_vlan_lists_refused(typed: str) -> None:
    with pytest.raises(ValueError):
        parse_vlan_list(typed)


@pytest.mark.parametrize(
    ("numbers", "text"),
    [([], "none"), ([5], "5"), ([1, 10, 11, 12, 3900], "1,10-12,3900"), ([3, 2, 1], "1-3")],
)
def test_vlan_lists_written_as_the_switch_writes_them(numbers: list[int], text: str) -> None:
    assert format_vlan_list(numbers) == text
    assert parse_vlan_list(text) == sorted(numbers)


def test_vlan_numbers_and_names() -> None:
    assert validate_vlan_id("42") == 42
    for bad in ("0", "4095", "x", "", "1e3", " 4 2"):
        with pytest.raises(ValueError):
            validate_vlan_id(bad)
    assert validate_vlan_name(" storage-10_a.b ") == "storage-10_a.b"
    assert validate_vlan_name("x" * 32) == "x" * 32
    # The switch accepts 33-128 characters but silently keeps the old name.
    for bad in ("x" * 33, "has space", "", "a;b", "why?", "café"):
        with pytest.raises(ValueError):
            validate_vlan_name(bad)


# ---- which ports use a VLAN -------------------------------------------------


def _port(
    name: str,
    mode: str,
    access: int = 1,
    native: int = 1,
    allowed: Iterable[int] = ALL_VLANS,
    switchport: bool = True,
) -> PortVlans:
    return PortVlans(name, switchport, mode, access, native, frozenset(allowed))


def test_ports_using_a_vlan() -> None:
    view = VlanView(
        [],
        {
            "Ethernet1/10": _port("Ethernet1/10", "access", access=20),
            "Ethernet1/2": _port("Ethernet1/2", "trunk", native=20),
            "Ethernet1/3": _port("Ethernet1/3", "trunk", allowed={1, 20, 30}),
            "Ethernet1/4": _port("Ethernet1/4", "trunk"),  # carries every VLAN
            "Ethernet1/5": _port("Ethernet1/5", "trunk", access=20),  # access VLAN unused
            "Ethernet1/6": _port("Ethernet1/6", "access", access=20, switchport=False),
        },
    )
    assert view.ports_using(20) == ["Ethernet1/2", "Ethernet1/3", "Ethernet1/10"]
    assert view.ports_using(30) == ["Ethernet1/3"]
    assert view.ports_using(40) == []


# ---- planning a port's VLAN change -----------------------------------------


def _view(*ids: int) -> VlanView:
    return VlanView([Vlan(i, f"v{i}", "active") for i in ids], {})


def test_plan_keeps_only_what_changes() -> None:
    access = _port("Ethernet1/3", "access", access=10)
    view = _view(1, 10, 20)
    same = plan_port_vlans(
        access, view, mode="access", access_vlan="10", native_vlan="1", allowed=""
    )
    assert same.empty
    move = plan_port_vlans(
        access, view, mode="access", access_vlan="20", native_vlan="1", allowed=""
    )
    assert (move.mode, move.access_vlan, move.native_vlan, move.allowed_vlans) == (
        None,
        20,
        None,
        None,
    )
    trunk = plan_port_vlans(
        access, view, mode="trunk", access_vlan="10", native_vlan="1", allowed="10,20"
    )
    assert (trunk.mode, trunk.native_vlan, trunk.allowed_vlans) == ("trunk", None, [10, 20])


def test_plan_refuses_what_the_switch_would_take_badly() -> None:
    access = _port("Ethernet1/3", "access")
    view = _view(1, 10)
    cases = [
        (dict(mode="access", access_vlan="30"), "does not exist"),
        (dict(mode="trunk", native_vlan="30"), "does not exist"),
        (dict(mode="trunk", native_vlan="1", allowed="1;reload"), "not a VLAN"),
        (dict(mode="routed"), "access or trunk"),
    ]
    for fields, message in cases:
        args = {"access_vlan": "1", "native_vlan": "1", "allowed": "all", **fields}
        with pytest.raises(ValueError, match=message):
            plan_port_vlans(access, view, **args)
    routed = _port("Ethernet1/4", "access", switchport=False)
    with pytest.raises(ValueError, match="routed port"):
        plan_port_vlans(routed, view, mode="access", access_vlan="10", native_vlan="1", allowed="")


def test_describe_warns_about_mode_changes_and_dropped_vlans() -> None:
    access = _port("Ethernet1/3", "access", access=10)
    view = _view(1, 10, 20)
    to_trunk = plan_port_vlans(
        access, view, mode="trunk", access_vlan="10", native_vlan="1", allowed="all"
    )
    lines, warnings = describe_port_vlans(access, to_trunk)
    assert lines == ["Mode: access → trunk."]
    assert any("may lose its connection for a moment" in w for w in warnings)

    trunk = _port("Ethernet1/3", "trunk", allowed={1, 10, 20})
    narrower = plan_port_vlans(
        trunk, view, mode="trunk", access_vlan="1", native_vlan="1", allowed="1,10"
    )
    lines, warnings = describe_port_vlans(trunk, narrower)
    assert lines == ["VLANs carried: 1,10,20 → 1,10."]
    assert warnings == ["VLANs 20 stop passing over this port at once."]

    moved = plan_port_vlans(
        access, view, mode="access", access_vlan="20", native_vlan="1", allowed=""
    )
    lines, warnings = describe_port_vlans(access, moved)
    assert lines == ["Access VLAN: 10 → 20."]
    assert "loses its connection to VLAN 10" in warnings[0]


# ---- the guarded commands ---------------------------------------------------


def _recording(seen: list[list[str]]) -> NxapiClient:
    def handler(request: httpx.Request) -> httpx.Response:
        entries = json.loads(request.content)
        seen.append([entry["params"]["cmd"] for entry in entries])
        replies = [{"jsonrpc": "2.0", "result": None, "id": e["id"]} for e in entries]
        return httpx.Response(200, json=replies[0] if len(replies) == 1 else replies)

    target = SwitchTarget("192.0.2.10", 443, "nxray", NXRAY_PASSWORD, 10)
    return NxapiClient(target, transport=httpx.MockTransport(handler))


def test_vlan_commands_are_built_from_checked_values() -> None:
    seen: list[list[str]] = []
    with _recording(seen) as client:
        client.configure_vlan(20)
        client.configure_vlan(20, "storage")
        client.delete_vlan(20)
        client.configure_port_vlans("Ethernet1/3", mode="trunk", allowed_vlans=[1, 10, 11, 20])
        client.configure_port_vlans("Ethernet1/3", native_vlan=10, allowed_vlans=[])
        client.configure_port_vlans("Ethernet1/3", mode="access", access_vlan=20)
    assert seen == [
        ["vlan 20"],
        ["vlan 20", "name storage"],
        ["no vlan 20"],
        [
            "interface Ethernet1/3",
            "switchport mode trunk",
            "switchport trunk allowed vlan 1,10-11,20",
        ],
        [
            "interface Ethernet1/3",
            "switchport trunk native vlan 10",
            "switchport trunk allowed vlan none",
        ],
        ["interface Ethernet1/3", "switchport mode access", "switchport access vlan 20"],
    ]


@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.configure_vlan(0),
        lambda c: c.configure_vlan(20, "two words"),
        lambda c: c.configure_vlan(20, "x ; reload"),
        lambda c: c.delete_vlan(1),
        lambda c: c.delete_vlan(5000),
        lambda c: c.configure_port_vlans("mgmt0", mode="access"),
        lambda c: c.configure_port_vlans("Ethernet1/3", mode="fex-fabric"),
        lambda c: c.configure_port_vlans("Ethernet1/3", access_vlan=4095),
        lambda c: c.configure_port_vlans("Ethernet1/3"),
    ],
)
def test_vlan_commands_refuse_before_sending(call) -> None:
    seen: list[list[str]] = []
    with _recording(seen) as client, pytest.raises(ValueError):
        call(client)
    assert seen == []


# ---- the role ---------------------------------------------------------------


def test_role_lines_carry_the_vlan_rules() -> None:
    lines = role_lines(["Ethernet1/1"], "nxray")
    assert all(rule in lines for rule in (*ROLE_RULES, *VLAN_RULES))
    # Rule numbers continue after the port rules and never repeat.
    numbers = [int(rule.split()[1]) for rule in (*ROLE_RULES, *VLAN_RULES)]
    assert numbers == list(range(1, len(numbers) + 1))
    # VLAN names only, never a bare "vlan *" (that would allow shutting VLANs down).
    assert "rule 6 permit command conf t ; vlan * ; name *" in VLAN_RULES
    assert not any(rule.endswith("; vlan *") for rule in VLAN_RULES)
    for rule in VLAN_RULES:
        assert rule.endswith(
            (
                "; vlan * ; name *",
                "; no vlan *",
                "; switchport mode *",
                "; switchport access vlan *",
                "; switchport trunk allowed vlan *",
                "; switchport trunk native vlan *",
            )
        )


def _enable(switch: FakeSwitch):
    return enable_port_changes(
        host="192.0.2.10",
        nxapi_port=443,
        ssh_port=22,
        admin_user="admin",
        admin_password=ADMIN_PASSWORD,
        account_name="nxray",
        transport=switch.transport(),
        ssh_opener=switch.ssh_opener(),
    )


def test_updating_a_role_the_account_has_needs_no_wait() -> None:
    switch = FakeSwitch()
    switch.users["nxray"] = (NXRAY_PASSWORD, "network-operator")
    first = _enable(switch)
    assert (first.had_role, first.pause_seconds) == (False, 660)
    again = _enable(switch)
    assert (again.had_role, again.pause_seconds) == (True, 0)
    assert again.config_saved


def test_after_enabling_the_account_can_change_vlans() -> None:
    switch = FakeSwitch()
    switch.users["nxray"] = (NXRAY_PASSWORD, "network-operator")
    target = SwitchTarget("192.0.2.10", 443, "nxray", NXRAY_PASSWORD, 10)
    with NxapiClient(target, transport=switch.transport()) as client:
        with pytest.raises(Exception, match="Permission denied"):
            client.configure_vlan(20, "lab")
        _enable(switch)
        client.configure_vlan(20, "lab")
        client.configure_port_vlans("Ethernet1/3", mode="access", access_vlan=20)
        client.delete_vlan(30)
    assert switch.vlans[20] == "lab"
    assert switch.port_state["Ethernet1/3"]["access"] == "20"


# ---- storing the role version -----------------------------------------------


def _connected(tmp_path: Path) -> Path:
    db = tmp_path / "nxray.db"
    init_db(db)
    with open_db(db) as conn:
        save_connection(
            conn,
            host="192.0.2.10",
            port=443,
            username="nxray",
            password=NXRAY_PASSWORD,
            switch_hostname="nexus-lab",
            config_saved=True,
            secret_key="k" * 32,
        )
    return db


def _stored(conn: sqlite3.Connection) -> SwitchConnection:
    connection = get_connection(conn)
    assert connection is not None
    return connection


def test_role_version_is_stored_and_a_running_pause_is_kept(tmp_path: Path) -> None:
    db = _connected(tmp_path)
    with open_db(db) as conn:
        assert _stored(conn).role_version == 0
        set_changes_enabled(conn, pause_seconds=660, role_version=1)
        first = _stored(conn)
        assert first.changes_enabled and not first.vlan_changes_enabled
        # The update needs no wait, but must not cut the first wait short.
        set_changes_enabled(conn, pause_seconds=0, role_version=ROLE_VERSION)
        second = _stored(conn)
        assert second.vlan_changes_enabled
        assert second.paused_until == first.paused_until
        conn.execute("UPDATE switch_connection SET paused_until = ?", (time.time() - 5,))
        set_changes_enabled(conn, pause_seconds=0, role_version=ROLE_VERSION)
        assert _stored(conn).paused_seconds() == 0


def test_installs_with_port_changes_on_get_role_version_1(tmp_path: Path) -> None:
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    # A database as stage 5 left it: schema 3, port changes on.
    conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    for index, script in enumerate(_MIGRATIONS[:3], start=1):
        conn.executescript(script)
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (index,))
    conn.execute(
        "INSERT INTO switch_connection (id, host, port, username, password_encrypted, "
        "switch_hostname, created_at, config_saved, changes_enabled_at) "
        "VALUES (1, 'h', 443, 'nxray', 'x', 'sw', 0, 1, 100)"
    )
    conn.commit()
    assert migrate(conn) == len(_MIGRATIONS)
    connection = get_connection(conn)
    conn.close()
    assert connection is not None
    assert (connection.role_version, connection.changes_enabled) == (1, True)
    assert not connection.vlan_changes_enabled
