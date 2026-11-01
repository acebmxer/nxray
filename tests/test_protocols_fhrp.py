"""Gateway backup (app/protocols_fhrp.py): HSRP, VRRP and VRRPv3 parsed from
output recorded on cisco-25gb (NX-OS 9.3(16)), and the exact lines every
setting sends."""

from __future__ import annotations

import pytest

from app.protocols import build_change
from app.protocols_fhrp import (
    HSRP,
    PROTOCOLS,
    VRRP,
    VRRPV3,
    parse_hsrp,
    parse_vrrp,
    parse_vrrpv3,
)
from tests.conftest import load_fixture

# ---- reading -----------------------------------------------------------------


def test_protocols_are_the_three_pages() -> None:
    assert [p.key for p in PROTOCOLS] == ["hsrp", "vrrp", "vrrpv3"]
    assert HSRP.features == ("hsrp_engine",)
    assert VRRP.features == ("vrrp",)
    assert VRRPV3.features == ("vrrpv3",)
    assert HSRP.commands == ("show hsrp",)
    assert VRRP.commands == ("show vrrp detail", "show vrrp")
    assert VRRPV3.commands == ("show vrrpv3 detail", "show vrrpv3")
    # The switch refuses vrrp and vrrpv3 on together; both pages say so.
    assert "same time" in VRRP.about and "same time" in VRRPV3.about


def test_hsrp_reads_interface_and_groups() -> None:
    view = parse_hsrp([load_fixture("show_hsrp")])
    (interface,) = view.of("interface")
    assert interface.ident == {"interface": "Ethernet1/54"}
    assert interface.values == {"version": {"version": "2"}}
    assert dict(interface.facts)["Groups"] == "10, 20"

    v4, v6 = view.of("group")
    assert v4.ident == {"interface": "Ethernet1/54", "group": "10", "ipv6": ""}
    assert v4.title == "Ethernet1/54 group 10 (IPv4)"
    assert v4.values == {
        "address": {"address": "192.0.2.254", "secondary": ""},
        "priority": {"priority": "110", "lower": "", "upper": ""},
        "preempt": {},
        "timers": {"hello": "1", "hold": "3"},
        "name": {"name": "nxprobe-hsrp"},
    }
    facts = dict(v4.facts)
    assert facts["Authentication"] == "MD5"
    assert facts["Active router"] == "none heard"
    assert facts["State"] == "Initial (Interface Down)"
    # The key chain name is not echoed as a fact or a value.
    assert "nxprobe-kc" not in str(v4.facts) + str(v4.values)

    assert v6.ident == {"interface": "Ethernet1/54", "group": "20", "ipv6": "ipv6"}
    # The default name and timers are not prefilled; neither is an address,
    # since the switch reports only the link-local one it made.
    assert v6.values == {
        "priority": {"priority": "105", "lower": "", "upper": ""},
        "preempt": {},
    }
    facts = dict(v6.facts)
    assert facts["Virtual address"] == "fe80::5:73ff:fea0:14"
    # The garbled IPv4 "secondary" the switch prints for an IPv6 group is dropped.
    assert "Extra addresses" not in facts
    assert facts["Authentication"] == "none set (plain text, the default)"
    assert view.notes and "link-local" in view.notes[0]


def test_hsrp_groups_table() -> None:
    (table,) = parse_hsrp([load_fixture("show_hsrp")]).tables
    assert table.columns[:5] == ("Interface", "Group", "Family", "State", "Virtual address")
    assert table.rows[0] == (
        "Ethernet1/54",
        "10",
        "IPv4",
        "Initial (Interface Down)",
        "192.0.2.254",
        "110",
        "yes",
        "-",
        "-",
        "0000.0c9f.f00a",
    )
    assert table.rows[1][2] == "IPv6"
    assert "184.13.1.32" not in table.rows[1][4]


def test_hsrp_active_and_standby_routers() -> None:
    # Shaped after Cisco's documented NX-API fields for show hsrp, not recorded:
    # nothing was plugged in when the probe ran, so no peer was ever seen live.
    body = {
        "TABLE_grp_detail": {
            "ROW_grp_detail": {
                "sh_if_index": "Vlan10",
                "sh_group_num": 1,
                "sh_group_type": "v4",
                "sh_group_version": "v1",
                "sh_group_state": "Standby",
                "sh_prio": 100,
                "sh_cfg_prio": 100,
                "sh_preempt": "disabled",
                "sh_cfg_hello": 250,
                "sh_cfg_hello_attr": "msec",
                "sh_cfg_hold": 750,
                "sh_vip": "192.0.2.1",
                "sh_active_router_addr": "192.0.2.3",
                "sh_standby_router_addr": "local",
                "sh_authentication_type": "text",
                "sh_authentication_data": "s3cret",
                "sh_vmac": "0200.0000.0001",
                "sh_vmac_attr": "Configured MAC",
                "sh_ip_redund_name_attr": "Default",
                "TABLE_grp_vip_sec": {"ROW_grp_vip_sec": [{"sh_vip_sec": "192.0.2.2"}]},
            }
        }
    }
    view = parse_hsrp([body])
    (group,) = view.of("group")
    assert group.values["timers_msec"] == {"hello_ms": "250", "hold_ms": "750"}
    assert group.values["mac"] == {"mac": "0200.0000.0001"}
    assert "preempt" not in group.values
    facts = dict(group.facts)
    assert facts["Active router"] == "192.0.2.3"
    assert facts["Extra addresses"] == "192.0.2.2"
    assert facts["Authentication"] == "plain-text password"
    assert "s3cret" not in str(view)
    assert view.tables[0].rows[0][4] == "192.0.2.1, 192.0.2.2"
    assert view.notes == ()


def test_parsers_take_empty_output() -> None:
    # "result": null (no groups) reaches the parser as an empty body.
    for parse, count in ((parse_hsrp, 1), (parse_vrrp, 2), (parse_vrrpv3, 2)):
        view = parse([{}] * count)
        assert view.instances == ()
        assert view.tables[0].rows == ()
        assert parse([]).instances == ()


def test_vrrp_reads_group_from_detail() -> None:
    view = parse_vrrp([load_fixture("show_vrrp_detail"), load_fixture("show_vrrp")])
    (group,) = view.of("group")
    assert group.ident == {"interface": "Ethernet1/54", "group": "30"}
    assert group.values == {
        "address": {"address": "192.0.2.253", "secondary": ""},
        "priority": {"priority": "120", "lower": "", "upper": ""},
        "preempt": {},
        "advertisement": {"seconds": "2"},
    }
    facts = dict(group.facts)
    assert facts["Master router"] == "none heard"
    assert facts["Virtual MAC"] == "0000.5e00.011e"
    (table,) = view.tables
    assert table.rows == (
        (
            "Ethernet1/54",
            "30",
            "Init",
            "192.0.2.253",
            "120",
            "yes",
            "2 s",
            "-",
            "0000.5e00.011e",
        ),
    )


def test_vrrp_falls_back_to_plain_show() -> None:
    view = parse_vrrp([{}, load_fixture("show_vrrp")])
    (group,) = view.of("group")
    assert group.values["priority"]["priority"] == "120"
    assert view.tables[0].rows[0][8] == "-"


def test_vrrpv3_reads_both_families() -> None:
    view = parse_vrrpv3([load_fixture("show_vrrpv3_detail"), load_fixture("show_vrrpv3")])
    v4, v6 = view.of("group")
    assert v4.ident == {"interface": "Ethernet1/54", "group": "40", "af": "ipv4"}
    assert v4.values == {
        "address": {"address": "192.0.2.252", "primary": "primary"},
        "priority": {"priority": "115"},
        "preempt": {"delay": ""},
        "timers": {"msec": "200"},
    }
    assert v6.ident == {"interface": "Ethernet1/54", "group": "41", "af": "ipv6"}
    assert v6.values["address6"] == {"address6": "fe80::41", "primary6": "primary"}
    assert dict(v6.facts)["Extra addresses"] == "2001:db8:1::fd"
    (table,) = view.tables
    assert table.rows[1] == (
        "Ethernet1/54",
        "41",
        "IPv6",
        "INIT",
        "fe80::41, 2001:db8:1::fd",
        "100",
        "yes",
        "1000 ms",
        "0000.5e00.0229",
    )
    # The plain show gives the same groups when the detail one is empty.
    assert len(parse_vrrpv3([{}, load_fixture("show_vrrpv3")]).of("group")) == 2


# ---- changes -----------------------------------------------------------------

_HSRP_IF = {"interface": "Ethernet1/54"}
_HSRP_V4 = {"interface": "Ethernet1/54", "group": "10"}
_HSRP_V6 = {"interface": "Vlan10", "group": "20", "ipv6": "yes"}
_VRRP = {"interface": "Ethernet1/54", "group": "30"}
_V3_4 = {"interface": "Ethernet1/54", "group": "40", "af": "ipv4"}
_V3_6 = {"interface": "port-channel5", "group": "41", "af": "ipv6"}

# (protocol, scope, setting, ident, values, set line, remove line: None for "no " + set line,
#  "" when it cannot be removed)
CASES = [
    # HSRP, interface-wide
    (HSRP, "interface", "version", _HSRP_IF, {"version": "2"}, "hsrp version 2", None),
    (HSRP, "interface", "bfd", _HSRP_IF, {}, "hsrp bfd", None),
    (
        HSRP,
        "interface",
        "mac_refresh",
        _HSRP_IF,
        {"seconds": "120"},
        "hsrp mac-refresh 120",
        None,
    ),
    (HSRP, "interface", "use_bia", _HSRP_IF, {"scope": "on"}, "hsrp use-bia scope interface", None),
    (
        HSRP,
        "interface",
        "delay_minimum",
        _HSRP_IF,
        {"seconds": "30"},
        "hsrp delay minimum 30",
        None,
    ),
    (HSRP, "interface", "delay_reload", _HSRP_IF, {"seconds": "60"}, "hsrp delay reload 60", None),
    # HSRP group
    (
        HSRP,
        "group",
        "address",
        _HSRP_V4,
        {"address": "192.0.2.254", "secondary": ""},
        "ip 192.0.2.254",
        None,
    ),
    (
        HSRP,
        "group",
        "address6",
        _HSRP_V6,
        {"address6": "2001:db8:1::fe"},
        "ip 2001:db8:1::fe",
        None,
    ),
    (HSRP, "group", "autoconfig", _HSRP_V6, {}, "ip autoconfig", None),
    (
        HSRP,
        "group",
        "priority",
        _HSRP_V4,
        {"priority": "110", "lower": "40", "upper": "50"},
        "priority 110 forwarding-threshold lower 40 upper 50",
        None,
    ),
    (HSRP, "group", "preempt", _HSRP_V4, {}, "preempt", None),
    (
        HSRP,
        "group",
        "preempt_delay",
        _HSRP_V4,
        {"minimum": "60", "reload": "120", "sync": "0"},
        "preempt delay minimum 60 reload 120 sync 0",
        "",
    ),
    (
        HSRP,
        "group",
        "track",
        _HSRP_V4,
        {"object": "1", "decrement": "20"},
        "track 1 decrement 20",
        None,
    ),
    (HSRP, "group", "timers", _HSRP_V4, {"hello": "1", "hold": "3"}, "timers 1 3", None),
    (
        HSRP,
        "group",
        "timers_msec",
        _HSRP_V4,
        {"hello_ms": "250", "hold_ms": "750"},
        "timers msec 250 msec 750",
        None,
    ),
    (
        HSRP,
        "group",
        "auth_text",
        _HSRP_V4,
        {"password": "pa55"},
        "authentication text pa55",
        "no authentication",
    ),
    (
        HSRP,
        "group",
        "auth_md5",
        _HSRP_V4,
        {"key": "k3y!", "timeout": "300"},
        "authentication md5 key-string 0 k3y! timeout 300",
        "no authentication",
    ),
    (
        HSRP,
        "group",
        "auth_keychain",
        _HSRP_V4,
        {"key_chain": "nxprobe-kc"},
        "authentication md5 key-chain nxprobe-kc",
        "no authentication",
    ),
    (HSRP, "group", "name", _HSRP_V4, {"name": "nxprobe-hsrp"}, "name nxprobe-hsrp", None),
    (HSRP, "group", "follow", _HSRP_V4, {"follow": "core-gw"}, "follow core-gw", None),
    (
        HSRP,
        "group",
        "mac",
        _HSRP_V4,
        {"mac": "0200.0000.0001"},
        "mac-address 0200.0000.0001",
        None,
    ),
    (HSRP, "group", "shutdown", _HSRP_V4, {}, "shutdown", None),
    # VRRP
    (VRRP, "group", "enabled", _VRRP, {}, "no shutdown", "shutdown"),
    (
        VRRP,
        "group",
        "address",
        _VRRP,
        {"address": "192.0.2.250", "secondary": "on"},
        "address 192.0.2.250 secondary",
        None,
    ),
    (
        VRRP,
        "group",
        "priority",
        _VRRP,
        {"priority": "120", "lower": "", "upper": ""},
        "priority 120",
        None,
    ),
    (VRRP, "group", "preempt", _VRRP, {}, "preempt", None),
    (
        VRRP,
        "group",
        "track_interface",
        _VRRP,
        {"track_interface": "Ethernet1/49", "track_priority": "90"},
        "track interface Ethernet1/49 priority 90",
        None,
    ),
    (
        VRRP,
        "group",
        "track",
        _VRRP,
        {"object": "2", "decrement": "30"},
        "track 2 decrement 30",
        None,
    ),
    (
        VRRP,
        "group",
        "advertisement",
        _VRRP,
        {"seconds": "2"},
        "advertisement-interval 2",
        None,
    ),
    (
        VRRP,
        "group",
        "auth_text",
        _VRRP,
        {"password": "vrrpKey1"},
        "authentication text vrrpKey1",
        None,
    ),
    # VRRPv3
    (
        VRRPV3,
        "group",
        "address",
        _V3_4,
        {"address": "192.0.2.252", "primary": "on"},
        "address 192.0.2.252 primary",
        None,
    ),
    (
        VRRPV3,
        "group",
        "address6",
        _V3_6,
        {"address6": "fe80::41", "primary6": "on"},
        "address fe80::41 primary",
        None,
    ),
    (VRRPV3, "group", "priority", _V3_4, {"priority": "115"}, "priority 115", None),
    (VRRPV3, "group", "preempt", _V3_4, {"delay": "30"}, "preempt delay minimum 30", None),
    (
        VRRPV3,
        "group",
        "track",
        _V3_4,
        {"object": "1", "decrement": "2"},
        "object-track 1 decrement 2",
        None,
    ),
    (VRRPV3, "group", "timers", _V3_4, {"msec": "200"}, "timers advertise 200", None),
    (VRRPV3, "group", "match_address", _V3_4, {}, "match-address", None),
    (VRRPV3, "group", "vrrp2", _V3_4, {}, "vrrp2", None),
    (
        VRRPV3,
        "group",
        "description",
        _V3_6,
        {"description": "gateway for lab"},
        "description gateway for lab",
        None,
    ),
    (VRRPV3, "group", "shutdown", _V3_4, {}, "shutdown", None),
]

_ENTER = {
    (HSRP.key, "interface", "Ethernet1/54"): ("interface Ethernet1/54",),
    (HSRP.key, "group", "10"): ("interface Ethernet1/54", "hsrp 10"),
    (HSRP.key, "group", "20"): ("interface Vlan10", "hsrp 20 ipv6"),
    (VRRP.key, "group", "30"): ("interface Ethernet1/54", "vrrp 30"),
    (VRRPV3.key, "group", "40"): ("interface Ethernet1/54", "vrrpv3 40 address-family ipv4"),
    (VRRPV3.key, "group", "41"): ("interface port-channel5", "vrrpv3 41 address-family ipv6"),
}


def _enter(protocol, scope: str, ident: dict[str, str]) -> tuple[str, ...]:
    return _ENTER[(protocol.key, scope, ident.get("group", ident["interface"]))]


def test_every_setting_has_a_case() -> None:
    covered = {(p.key, scope, setting) for p, scope, setting, *_ in CASES}
    every = {(p.key, s.key, t.key) for p in PROTOCOLS for s in p.scopes for t in s.settings}
    assert covered == every


@pytest.mark.parametrize(
    ("protocol", "scope", "setting", "ident", "values", "line", "no_line"),
    CASES,
    ids=[f"{c[0].key}-{c[1]}-{c[2]}" for c in CASES],
)
def test_setting_lines(protocol, scope, setting, ident, values, line, no_line) -> None:
    enter = _enter(protocol, scope, ident)
    change = build_change(protocol, scope, setting, "set", ident, values)
    assert change.lines == (*enter, line)
    if no_line == "":
        with pytest.raises(ValueError, match="cannot be removed"):
            build_change(protocol, scope, setting, "remove", ident, values)
        return
    removed = build_change(protocol, scope, setting, "remove", ident, values)
    assert removed.lines == (*enter, no_line or f"no {line}")


def test_secrets_are_masked() -> None:
    change = build_change(HSRP, "group", "auth_md5", "set", _HSRP_V4, {"key": "k3y!"})
    assert change.lines[-1] == "authentication md5 key-string 0 k3y!"
    assert change.labels[-1] == "authentication md5 key-string 0 ***"
    assert "k3y!" not in change.describe
    change = build_change(VRRP, "group", "auth_text", "remove", _VRRP, {"password": "vrrpKey1"})
    assert change.labels[-1] == "no authentication text ***"


def test_optional_parts_drop_out() -> None:
    change = build_change(HSRP, "group", "priority", "set", _HSRP_V4, {"priority": "90"})
    assert change.lines[-1] == "priority 90"
    change = build_change(HSRP, "group", "track", "set", _HSRP_V4, {"object": "3"})
    assert change.lines[-1] == "track 3"
    change = build_change(HSRP, "interface", "use_bia", "set", _HSRP_IF, {})
    assert change.lines[-1] == "hsrp use-bia"
    change = build_change(VRRPV3, "group", "preempt", "set", _V3_4, {})
    assert change.lines[-1] == "preempt"


def test_create_and_delete_groups() -> None:
    cases = [
        (HSRP, _HSRP_V4, ("interface Ethernet1/54", "hsrp 10"), "no hsrp 10"),
        (HSRP, _HSRP_V6, ("interface Vlan10", "hsrp 20 ipv6"), "no hsrp 20 ipv6"),
        (VRRP, _VRRP, ("interface Ethernet1/54", "vrrp 30"), "no vrrp 30"),
        (
            VRRPV3,
            _V3_4,
            ("interface Ethernet1/54", "vrrpv3 40 address-family ipv4"),
            "no vrrpv3 40 address-family ipv4",
        ),
        (
            VRRPV3,
            _V3_6,
            ("interface port-channel5", "vrrpv3 41 address-family ipv6"),
            "no vrrpv3 41 address-family ipv6",
        ),
    ]
    for protocol, ident, lines, no_line in cases:
        made = build_change(protocol, "group", "", "create", ident, {})
        assert made.lines == lines
        gone = build_change(protocol, "group", "", "delete", ident, {})
        assert gone.lines == (lines[0], no_line)
        assert gone.warning


def test_hsrp_interface_scope_is_not_made_or_deleted() -> None:
    with pytest.raises(ValueError, match="not made"):
        build_change(HSRP, "interface", "", "create", _HSRP_IF, {})
    with pytest.raises(ValueError, match="not deleted"):
        build_change(HSRP, "interface", "", "delete", _HSRP_IF, {})


@pytest.mark.parametrize(
    ("protocol", "scope", "setting", "ident", "values", "message"),
    [
        # wrong address family
        (HSRP, "group", "address", _HSRP_V4, {"address": "2001:db8::1"}, "IPv4"),
        (HSRP, "group", "address6", _HSRP_V6, {"address6": "192.0.2.1"}, "IPv6"),
        (VRRP, "group", "address", _VRRP, {"address": "2001:db8::1"}, "IPv4"),
        (VRRPV3, "group", "address6", _V3_6, {"address6": "192.0.2.1"}, "IPv6"),
        (VRRPV3, "group", "address", _V3_4, {"address": "fe80::1"}, "IPv4"),
        (HSRP, "group", "address", _HSRP_V4, {"address": "224.0.0.2"}, "not an address"),
        # out of range
        (HSRP, "group", "priority", _HSRP_V4, {"priority": "256"}, "0 to 255"),
        (VRRP, "group", "priority", _VRRP, {"priority": "255"}, "1 to 254"),
        (VRRP, "group", "advertisement", _VRRP, {"seconds": "0"}, "1 to 255"),
        (VRRPV3, "group", "timers", _V3_4, {"msec": "50"}, "100 to 40950"),
        (HSRP, "group", "timers", _HSRP_V4, {"hello": "1", "hold": "2"}, "3 to 255"),
        (HSRP, "group", "timers_msec", _HSRP_V4, {"hello_ms": "100", "hold_ms": "750"}, "250"),
        (HSRP, "group", "track", _HSRP_V4, {"object": "513"}, "1 to 512"),
        (HSRP, "group", "preempt_delay", _HSRP_V4, {"minimum": "3601"}, "0 to 3600"),
        (HSRP, "interface", "mac_refresh", _HSRP_IF, {"seconds": "x"}, "whole number"),
        # names and secrets
        (HSRP, "group", "name", _HSRP_V4, {"name": "a;b"}, "cannot contain"),
        (HSRP, "group", "auth_keychain", _HSRP_V4, {"key_chain": "kc;x"}, "cannot contain"),
        (HSRP, "group", "auth_text", _HSRP_V4, {"password": "a;b"}, "without spaces"),
        (VRRP, "group", "auth_text", _VRRP, {"password": "two words"}, "without spaces"),
        (VRRPV3, "group", "description", _V3_4, {"description": "a?b"}, "cannot contain"),
        (HSRP, "interface", "version", _HSRP_IF, {"version": "3"}, "one of 1, 2"),
        (VRRP, "group", "track_interface", _VRRP, {"track_interface": "mgmt0"}, "Interface"),
    ],
)
def test_bad_values_are_refused(protocol, scope, setting, ident, values, message) -> None:
    with pytest.raises(ValueError, match=message):
        build_change(protocol, scope, setting, "set", ident, values)


@pytest.mark.parametrize(
    ("protocol", "ident", "message"),
    [
        (HSRP, {"interface": "Ethernet1/54", "group": "4096"}, "0 to 4095"),
        (VRRP, {"interface": "Ethernet1/54", "group": "0"}, "1 to 255"),
        (VRRP, {"interface": "Ethernet1/54", "group": "256"}, "1 to 255"),
        (VRRPV3, {"interface": "Ethernet1/54", "group": "40", "af": "ip"}, "ipv4, ipv6"),
        # never the management port, and VLAN interfaces up to Vlan254 only
        (HSRP, {"interface": "mgmt0", "group": "1"}, "Interface"),
        (VRRP, {"interface": "Vlan300", "group": "1"}, "1 to 254"),
        (VRRPV3, {"interface": "Ethernet1/54;x", "group": "1", "af": "ipv4"}, "cannot contain"),
    ],
)
def test_bad_groups_are_refused(protocol, ident, message) -> None:
    with pytest.raises(ValueError, match=message):
        build_change(protocol, "group", "", "create", ident, {})
