"""ACLs and port security: their field checks, the lines they build, and reading
them from the running configuration."""

from __future__ import annotations

import pytest

from app.acls import build_acl_change, layer3_names, parse_acl_config, parse_acls
from app.port_security import (
    build_port_security_change,
    parse_port_security,
    parse_port_security_config,
)
from app.protocols import Field, check_value

CONFIG = """\
!Command: show running-config
!Time: Sun Nov  1 10:00:00 2026
hostname nexus-lab
ip access-list mgmt-in
  statistics per-entry
  5 remark Allow the NOC only
  10 permit tcp 192.0.2.0/24 any eq 22
  20 deny ip any any log
ipv6 access-list v6-in
  10 permit ipv6 2001:db8::/32 any
interface Vlan10
  ip access-group mgmt-in in
  ipv6 traffic-filter v6-in out
interface Ethernet1/3
  switchport
  ip port access-group mgmt-in in
  switchport port-security
  switchport port-security maximum 3
  switchport port-security violation restrict
  switchport port-security mac-address sticky
  switchport port-security mac-address 0200.0000.0001 vlan 10
  switchport port-security aging time 30
  switchport port-security aging type inactivity
interface Ethernet1/4
  switchport
"""


@pytest.mark.parametrize(
    ("raw", "sent"),
    [
        ("22", "eq 22"),
        ("eq 80", "eq 80"),
        ("1024-65535", "range 1024 65535"),
        ("range 10 20", "range 10 20"),
        (">1023", "gt 1023"),
        ("<1024", "lt 1024"),
        ("!=23", "neq 23"),
    ],
)
def test_port_matches(raw: str, sent: str) -> None:
    assert check_value(Field("p", "Port", "l4port"), raw) == sent


@pytest.mark.parametrize("raw", ["70000", "20-10", "5-5", "ssh", "eq", "1;2"])
def test_bad_port_matches(raw: str) -> None:
    with pytest.raises(ValueError):
        check_value(Field("p", "Port", "l4port"), raw)


def test_acl_addresses() -> None:
    four, six = Field("s", "Source", "aclnet4"), Field("s", "Source", "aclnet6")
    assert check_value(four, "any") == "any"
    assert check_value(four, "192.0.2.0/24") == "192.0.2.0/24"
    assert check_value(four, "192.0.2.9") == "192.0.2.9/32"
    assert check_value(six, "2001:db8::1") == "2001:db8::1/128"
    for bad in ("192.0.2.1/24", "2001:db8::/32", "host", "192.0.2.300"):
        with pytest.raises(ValueError):
            check_value(four, bad)
    with pytest.raises(ValueError):
        check_value(six, "192.0.2.0/24")


def test_entry_lines() -> None:
    change = build_acl_change(
        "ipv4_acl",
        "entry",
        "set",
        {"name": "mgmt-in"},
        {
            "seq": "10",
            "action": "permit",
            "protocol": "tcp",
            "source": "192.0.2.0/24",
            "destination": "any",
            "destination_port": "22",
            "log": "yes",
        },
    )
    assert change.lines == ("ip access-list mgmt-in", "10 permit tcp 192.0.2.0/24 any eq 22 log")
    removed = build_acl_change("ipv4_acl", "entry", "remove", {"name": "mgmt-in"}, {"seq": "10"})
    assert removed.lines == ("ip access-list mgmt-in", "no 10")


def test_ports_only_for_tcp_udp_sctp() -> None:
    with pytest.raises(ValueError, match="tcp, udp or sctp"):
        build_acl_change(
            "ipv4_acl",
            "entry",
            "set",
            {"name": "a"},
            {"seq": "10", "action": "permit", "protocol": "icmp", "source": "any",
             "destination": "any", "destination_port": "22"},
        )  # fmt: skip


def test_ipv6_protocols_and_free_text_refused() -> None:
    with pytest.raises(ValueError, match="Protocol"):
        build_acl_change(
            "ipv6_acl",
            "entry",
            "set",
            {"name": "v6"},
            {"seq": "10", "action": "permit", "protocol": "ip", "source": "any",
             "destination": "any"},
        )  # fmt: skip
    with pytest.raises(ValueError):
        build_acl_change("ipv4_acl", "", "create", {"name": "bad name ; shutdown"}, {})


def test_make_delete_and_apply() -> None:
    assert build_acl_change("ipv4_acl", "", "create", {"name": "web"}, {}).lines == (
        "ip access-list web",
    )
    assert build_acl_change("ipv6_acl", "", "delete", {"name": "web6"}, {}).lines == (
        "no ipv6 access-list web6",
    )
    applied = build_acl_change("routed", "ipv4_out", "set", {"interface": "Vlan10"}, {"acl": "web"})
    assert applied.lines == ("interface Vlan10", "ip access-group web out")
    assert applied.warning
    port = build_acl_change(
        "switched", "ipv6_in", "remove", {"port": "Ethernet1/3"}, {"acl": "web6"}
    )
    assert port.lines == ("interface Ethernet1/3", "no ipv6 port traffic-filter web6 in")


def test_parse_acl_config() -> None:
    config = parse_acl_config(CONFIG)
    assert config.ipv4["mgmt-in"] == [
        "5 remark Allow the NOC only",
        "10 permit tcp 192.0.2.0/24 any eq 22",
        "20 deny ip any any log",
    ]
    assert config.ipv6 == {"v6-in": ["10 permit ipv6 2001:db8::/32 any"]}
    assert ("ipv4", "mgmt-in") in config.statistics
    assert config.routed == {"Vlan10": {"ipv4_in": "mgmt-in", "ipv6_out": "v6-in"}}
    assert config.switched == {"Ethernet1/3": {"ipv4_in": "mgmt-in"}}


def test_acl_view() -> None:
    view = parse_acls([{}], CONFIG)
    acl = view.of("ipv4_acl")[0]
    facts = dict(acl.facts)
    assert facts["10"] == "permit tcp 192.0.2.0/24 any eq 22"
    assert facts["Applies on"] == "Vlan10 in, Ethernet1/3 in"
    assert acl.values == {"statistics": {"on": "yes"}}
    assert view.of("routed")[0].values["ipv6_out"] == {"acl": "v6-in"}
    assert view.tables[0].rows[1] == ("v6-in", "IPv6", "1", "Vlan10 out")
    assert "does not let it read" in parse_acls([{}], None).notes[0]


def test_layer3_names() -> None:
    brief = {
        "TABLE_interface": {
            "ROW_interface": [
                {"interface": "Vlan10"},
                {"interface": "Vlan300"},
                {"interface": "Ethernet1/5", "portmode": "routed"},
                {"interface": "Ethernet1/6", "portmode": "access"},
            ]
        }
    }
    assert layer3_names(brief) == ("Vlan10", "Ethernet1/5")


def test_port_security_lines() -> None:
    def change(setting: str, action: str = "set", **values: str):
        return build_port_security_change("port", setting, action, {"port": "Ethernet1/3"}, values)

    assert change("enable").lines == ("interface Ethernet1/3", "switchport port-security")
    assert change("enable", "remove").lines[-1] == "no switchport port-security"
    assert change("maximum", maximum="5").lines[-1] == "switchport port-security maximum 5"
    assert change("violation", mode="restrict").lines[-1] == (
        "switchport port-security violation restrict"
    )
    assert change("mac", mac="02:00:00:00:00:01", vlan="10").lines[-1] == (
        "switchport port-security mac-address 0200.0000.0001 vlan 10"
    )
    assert change("mac", mac="0200.0000.0001", vlan="").lines[-1] == (
        "switchport port-security mac-address 0200.0000.0001"
    )
    assert change("aging_time", minutes="30").lines[-1] == "switchport port-security aging time 30"
    with pytest.raises(ValueError):
        change("maximum", maximum="2000")
    with pytest.raises(ValueError):
        change("violation", mode="explode")


def test_parse_port_security() -> None:
    ports = parse_port_security_config(CONFIG)
    assert list(ports) == ["Ethernet1/3"]
    port = ports["Ethernet1/3"]
    assert port.enabled and port.sticky
    assert (port.maximum, port.violation) == ("3", "restrict")
    assert (port.aging_time, port.aging_type) == ("30", "inactivity")
    assert port.macs == [("0200.0000.0001", "10")]
    view = parse_port_security([{}, {}], CONFIG)
    instance = view.of("port")[0]
    assert dict(instance.facts)["Known addresses"] == "0200.0000.0001 (VLAN 10)"
    assert instance.values["maximum"] == {"maximum": "3"}
    assert view.tables[0].rows == (("Ethernet1/3", "on", "3", "restrict", "1"),)
