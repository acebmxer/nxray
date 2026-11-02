"""Role version 14: DHCP snooping and relay, ARP inspection, IP Source Guard, MAC
ACLs, object groups, VLAN access maps, TCAM regions and restarting the switch;
their field checks, the lines they build, and reading them back."""

from __future__ import annotations

import pytest

from app.acls import (
    build_acl_change,
    needs_v14,
    parse_acl_config,
    parse_acls,
    parse_tcam_regions,
)
from app.dhcp_security import (
    build_dhcp_change,
    parse_bindings,
    parse_dhcp,
    parse_dhcp_config,
)
from app.port_changes import LAYER2_RULES, ROLE_VERSION, missing_changes, role_lines
from app.protocols import Field, check_value
from app.switch_ssh import SshAuthError, SshCommandError, SshUnreachable, reload_switch
from tests.fake_switch import FIXTURES

ACL_CONFIG = """\
!Command: show running-config
hardware access-list tcam region ing-ifacl 256
object-group ip address web-servers
  10 192.0.2.10/32
  20 198.51.100.0/24
object-group ipv6 address v6-servers
  10 2001:db8::/32
object-group ip port web-ports
  10 eq 443
  20 range 8000 8080
ip access-list web-in
  10 permit tcp any addrgroup web-servers portgroup web-ports
mac access-list no-ipx
  statistics per-entry
  10 deny any any 0x8137
  20 permit any any
vlan access-map guard 10
  match ip address web-in
  action forward
  statistics per-entry
vlan access-map guard 20
  action drop
vlan filter guard vlan-list 10,20
interface Ethernet1/3
  switchport
  mac port access-group no-ipx
"""

TCAM_TEXT = """\
                                    NAT ACL[nat] size =    0
                        Ingress PACL [ing-ifacl] size =  256
                                     VACL [vacl] size =    0
                          Ingress RACL [ing-racl] size = 1536
"""

DHCP_CONFIG = """\
!Command: show running-config
feature dhcp
ip dhcp snooping
ip dhcp snooping vlan 10,20
ip dhcp snooping information option
no ip dhcp snooping verify mac-address
no ipv6 dhcp relay
ip dhcp relay information option vpn
ip arp inspection vlan 10
ip arp inspection validate src-mac ip
ip arp inspection filter fixed-hosts vlan 10
ip arp inspection log-buffer entries 64
ip source binding 192.0.2.20 0200.0000.0020 vlan 10 interface Ethernet1/3
arp access-list fixed-hosts
  10 permit ip host 192.0.2.20 mac host 0200.0000.0020
interface Vlan10
  ip dhcp relay address 192.0.2.53
  ip dhcp relay address 198.51.100.53 use-vrf lab
  ipv6 dhcp relay address 2001:db8::53
interface Ethernet1/3
  switchport
  ip dhcp snooping trust
  ip dhcp snooping limit rate 30
  ip arp inspection trust
interface Ethernet1/4
  switchport
  ip verify source dhcp-snooping-vlan
interface Ethernet1/5
  switchport
"""

# ---- field kinds ---------------------------------------------------------------------


def test_object_groups_in_acl_matches() -> None:
    four, six = Field("s", "Source", "aclnet4"), Field("s", "Source", "aclnet6")
    port = Field("p", "Port", "l4port")
    assert check_value(four, "addrgroup web-servers") == "addrgroup web-servers"
    assert check_value(six, "ADDRGROUP v6") == "addrgroup v6"
    assert check_value(port, "portgroup web-ports") == "portgroup web-ports"
    for bad in ("addrgroup", "addrgroup a b", "addrgroup -x"):
        with pytest.raises(ValueError):
            check_value(four, bad)
    with pytest.raises(ValueError):
        check_value(port, "portgroup")


def test_mac_matches_and_ethertypes() -> None:
    mac = Field("m", "Source", "aclmac")
    assert check_value(mac, "any") == "any"
    assert check_value(mac, "02:00:00:00:00:01") == "0200.0000.0001 0000.0000.0000"
    assert check_value(mac, "0100.5e00.0000 0000.00ff.ffff") == "0100.5e00.0000 0000.00ff.ffff"
    for bad in ("host", "0200.0000.0001 x", "a b c"):
        with pytest.raises(ValueError):
            check_value(mac, bad)
    kind = Field("e", "EtherType", "ethertype")
    assert check_value(kind, "0x8137") == "0x8137"
    assert check_value(kind, "806") == "0x0806"
    for bad in ("0x05ff", "0x10000", "ipx"):
        with pytest.raises(ValueError):
            check_value(kind, bad)


def test_arp_matches() -> None:
    ip, mac = Field("i", "Sender IPv4", "arpip"), Field("m", "Sender MAC", "arpmac")
    assert check_value(ip, "any") == "any"
    assert check_value(ip, "192.0.2.20") == "host 192.0.2.20"
    assert check_value(mac, "0200.0000.0020") == "host 0200.0000.0020"
    for bad in ("192.0.2.0/24", "2001:db8::1"):
        with pytest.raises(ValueError):
            check_value(ip, bad)


# ---- the ACLs page -------------------------------------------------------------------


def test_mac_acl_lines() -> None:
    change = build_acl_change(
        "mac_acl",
        "entry",
        "set",
        {"name": "no-ipx"},
        {
            "seq": "10",
            "action": "deny",
            "source": "any",
            "destination": "0200.0000.0001",
            "ethertype": "0x8137",
            "cos": "3",
            "vlan": "10",
        },
    )
    assert change.lines == (
        "mac access-list no-ipx",
        "10 deny any 0200.0000.0001 0000.0000.0000 0x8137 cos 3 vlan 10",
    )
    bare = build_acl_change(
        "mac_acl", "entry", "set", {"name": "a"},
        {"seq": "20", "action": "permit", "source": "any", "destination": "any"},
    )  # fmt: skip
    assert bare.lines[-1] == "20 permit any any"
    applied = build_acl_change("switched", "mac_in", "set", {"port": "eth1/3"}, {"acl": "no-ipx"})
    assert applied.lines == ("interface Ethernet1/3", "mac port access-group no-ipx")
    removed = build_acl_change("switched", "mac_in", "remove", {"port": "Ethernet1/3"},
                               {"acl": "no-ipx"})  # fmt: skip
    assert removed.lines[-1] == "no mac port access-group no-ipx"


def test_object_group_lines() -> None:
    made = build_acl_change("addr4_group", "", "create", {"name": "web-servers"}, {})
    assert made.lines == ("object-group ip address web-servers",)
    entry = build_acl_change("addr4_group", "entry", "set", {"name": "web-servers"},
                             {"seq": "10", "address": "192.0.2.10"})  # fmt: skip
    assert entry.lines[-1] == "10 192.0.2.10/32"
    with pytest.raises(ValueError, match="not any or a group"):
        build_acl_change("addr4_group", "entry", "set", {"name": "w"},
                         {"seq": "10", "address": "any"})  # fmt: skip
    six = build_acl_change("addr6_group", "", "delete", {"name": "v6"}, {})
    assert six.lines == ("no object-group ipv6 address v6",)
    ports = build_acl_change("port_group", "entry", "set", {"name": "web-ports"},
                             {"seq": "20", "port": "8000-8080"})  # fmt: skip
    assert ports.lines == ("object-group ip port web-ports", "20 range 8000 8080")
    with pytest.raises(ValueError, match="not another group"):
        build_acl_change("port_group", "entry", "set", {"name": "p"},
                         {"seq": "1", "port": "portgroup p"})  # fmt: skip
    using = build_acl_change(
        "ipv4_acl", "entry", "set", {"name": "web-in"},
        {"seq": "10", "action": "permit", "protocol": "tcp", "source": "any",
         "destination": "addrgroup web-servers", "destination_port": "portgroup web-ports"},
    )  # fmt: skip
    assert using.lines[-1] == "10 permit tcp any addrgroup web-servers portgroup web-ports"


def test_access_map_and_filter_lines() -> None:
    made = build_acl_change("access_map", "", "create", {"name": "guard", "seq": "10"}, {})
    assert made.lines == ("vlan access-map guard 10",)
    match = build_acl_change("access_map", "match_ip", "set", {"name": "guard", "seq": "10"},
                             {"acl": "web-in"})  # fmt: skip
    assert match.lines == ("vlan access-map guard 10", "match ip address web-in")
    action = build_acl_change("access_map", "action", "set", {"name": "guard", "seq": "20"},
                              {"action": "drop"})  # fmt: skip
    assert action.lines[-1] == "action drop"
    with pytest.raises(ValueError):
        build_acl_change("access_map", "action", "remove", {"name": "g", "seq": "1"}, {})
    applied = build_acl_change("vlan_filter", "vlans", "set", {"name": "guard"},
                               {"vlans": "10, 20-30"})  # fmt: skip
    assert applied.lines == ("vlan filter guard vlan-list 10,20-30",)
    assert "dropped at once" in applied.warning
    removed = build_acl_change("vlan_filter", "vlans", "remove", {"name": "guard"},
                               {"vlans": "10"})  # fmt: skip
    assert removed.lines == ("no vlan filter guard vlan-list 10",)


def test_tcam_lines() -> None:
    change = build_acl_change("tcam", "region", "set", {}, {"region": "ing-ifacl", "size": "512"})
    assert change.lines == ("hardware access-list tcam region ing-ifacl 512",)
    assert "restarts" in change.warning
    with pytest.raises(ValueError, match="multiple of 256"):
        build_acl_change("tcam", "region", "set", {}, {"region": "vacl", "size": "300"})
    with pytest.raises(ValueError):
        build_acl_change("tcam", "region", "remove", {}, {"region": "vacl"})


def test_what_needs_role_version_14() -> None:
    assert needs_v14("mac_acl", "entry") and needs_v14("tcam", "region")
    assert needs_v14("switched", "mac_in")
    assert not needs_v14("switched", "ipv4_in") and not needs_v14("ipv4_acl", "entry")


def test_reading_the_new_acl_parts() -> None:
    config = parse_acl_config(ACL_CONFIG)
    assert config.mac == {"no-ipx": ["10 deny any any 0x8137", "20 permit any any"]}
    assert ("mac", "no-ipx") in config.statistics
    assert config.groups["addr4_group"]["web-servers"] == ["10 192.0.2.10/32", "20 198.51.100.0/24"]
    assert config.groups["port_group"]["web-ports"] == ["10 eq 443", "20 range 8000 8080"]
    guard = config.access_maps[("guard", "10")]
    assert guard.matches == [("match_ip", "web-in")] and guard.action == "forward"
    assert guard.statistics
    assert config.access_maps[("guard", "20")].action == "drop"
    assert config.vlan_filters == {"guard": ["10,20"]}
    assert config.switched == {"Ethernet1/3": {"mac_in": "no-ipx"}}
    assert config.tcam == {"ing-ifacl": "256"}

    view = parse_acls([{}], ACL_CONFIG, TCAM_TEXT)
    mac = next(i for i in view.of("mac_acl"))
    assert ("Applies on", "Ethernet1/3 in") in mac.facts
    web = view.of("ipv4_acl")[0]
    assert ("Applies on", "access map guard 10") in web.facts
    group = view.of("addr4_group")[0]
    assert ("Used by", "web-in") in group.facts
    ports = view.of("port_group")[0]
    assert ("Used by", "web-in") in ports.facts
    maps = view.of("access_map")
    assert maps[0].values == {
        "match_ip": {"acl": "web-in"},
        "action": {"action": "forward"},
        "statistics": {"on": "yes"},
    }
    assert view.of("vlan_filter")[0].facts == (("VLANs", "10,20"),)
    tcam = view.tables[2]
    assert ("ing-ifacl", "Ingress PACL", "256", "256") in tcam.rows
    assert ("vacl", "VACL", "0", "—") in tcam.rows


def test_tcam_regions_waiting_for_a_restart() -> None:
    assert parse_tcam_regions(TCAM_TEXT)[1] == ("ing-ifacl", "Ingress PACL", "256")
    config = ACL_CONFIG.replace("ing-ifacl 256", "ing-ifacl 512")
    note = parse_acls([{}], config, TCAM_TEXT).tables[2].note
    assert note == "Waiting for a restart of the switch: ing-ifacl."
    unread = parse_acls([{}], ACL_CONFIG, None).tables[2]
    assert unread.rows == () and "did not answer" in unread.empty


# ---- the DHCP and ARP page -----------------------------------------------------------


def test_dhcp_switch_wide_lines() -> None:
    def line(setting: str, values: dict[str, str], action: str = "set") -> tuple[str, ...]:
        return build_dhcp_change("switch", setting, action, {}, values).lines

    assert line("snooping", {}) == ("ip dhcp snooping",)
    assert line("snooping_vlans", {"vlans": "10,20"}) == ("ip dhcp snooping vlan 10,20",)
    assert line("verify_mac", {}, "remove") == ("no ip dhcp snooping verify mac-address",)
    assert line("relay", {}, "remove") == ("no ip dhcp relay",)
    assert line("relay6", {}, "remove") == ("no ipv6 dhcp relay",)
    assert line("arp_vlans", {"vlans": "10"}) == ("ip arp inspection vlan 10",)
    assert line("arp_validate", {"checks": "src-mac ip"}) == (
        "ip arp inspection validate src-mac ip",
    )
    assert line("arp_filter", {"acl": "fixed-hosts", "vlans": "10"}) == (
        "ip arp inspection filter fixed-hosts vlan 10",
    )
    assert line(
        "binding",
        {"address": "192.0.2.20", "mac": "02-00-00-00-00-20", "vlan": "10", "port": "eth1/3"},
    ) == ("ip source binding 192.0.2.20 0200.0000.0020 vlan 10 interface Ethernet1/3",)
    with pytest.raises(ValueError):
        line("arp_validate", {"checks": "everything"})
    with pytest.raises(ValueError):
        line("arp_log_buffer", {"entries": "2000"})


def test_dhcp_port_relay_and_arp_acl_lines() -> None:
    trust = build_dhcp_change("port", "snooping_trust", "set", {"port": "Ethernet1/3"}, {})
    assert trust.lines == ("interface Ethernet1/3", "ip dhcp snooping trust")
    rate = build_dhcp_change("port", "snooping_rate", "set", {"port": "po43"}, {"rate": "30"})
    assert rate.lines == ("interface port-channel43", "ip dhcp snooping limit rate 30")
    guard = build_dhcp_change("port", "source_guard", "set", {"port": "Ethernet1/4"}, {})
    assert guard.lines[-1] == "ip verify source dhcp-snooping-vlan"
    assert "lose their traffic" in guard.warning
    relay = build_dhcp_change("relay", "server", "set", {"interface": "Vlan10"},
                              {"server": "192.0.2.53", "vrf": "default"})  # fmt: skip
    assert relay.lines == ("interface Vlan10", "ip dhcp relay address 192.0.2.53")
    other = build_dhcp_change("relay", "server", "remove", {"interface": "Vlan10"},
                              {"server": "198.51.100.53", "vrf": "lab"})  # fmt: skip
    assert other.lines[-1] == "no ip dhcp relay address 198.51.100.53 use-vrf lab"
    six = build_dhcp_change("relay", "server6", "set", {"interface": "Vlan10"},
                            {"server": "2001:db8::53"})  # fmt: skip
    assert six.lines[-1] == "ipv6 dhcp relay address 2001:db8::53"
    entry = build_dhcp_change(
        "arp_acl", "entry", "set", {"name": "fixed-hosts"},
        {"seq": "10", "action": "permit", "address": "192.0.2.20", "mac": "0200.0000.0020",
         "log": "on"},
    )  # fmt: skip
    assert entry.lines == (
        "arp access-list fixed-hosts",
        "10 permit ip host 192.0.2.20 mac host 0200.0000.0020 log",
    )
    assert build_dhcp_change("arp_acl", "", "delete", {"name": "fixed-hosts"}, {}).lines == (
        "no arp access-list fixed-hosts",
    )


def test_reading_dhcp_and_arp() -> None:
    config = parse_dhcp_config(DHCP_CONFIG)
    assert config.snooping and config.snooping_vlans == ["10,20"] and config.option82
    assert not config.verify_mac and config.relay and not config.relay6 and config.relay_vpn
    assert config.arp_vlans == ["10"] and config.arp_validate == "src-mac ip"
    assert config.arp_filters == [("fixed-hosts", "10")] and config.arp_log_buffer == "64"
    assert config.bindings == [("192.0.2.20", "0200.0000.0020", "10", "Ethernet1/3")]
    assert config.servers["Vlan10"] == [
        ("ipv4", "192.0.2.53", ""),
        ("ipv4", "198.51.100.53", "lab"),
        ("ipv6", "2001:db8::53", ""),
    ]
    three = config.ports["Ethernet1/3"]
    assert three.snooping_trust and three.rate == "30" and three.arp_trust
    assert config.ports["Ethernet1/4"].source_guard
    assert "Ethernet1/5" not in config.ports
    assert config.arp_acls == {
        "fixed-hosts": ["10 permit ip host 192.0.2.20 mac host 0200.0000.0020"]
    }


def test_dhcp_page_view() -> None:
    bindings = FIXTURES.joinpath("show_ip_dhcp_snooping_binding.txt").read_text()
    assert parse_bindings(bindings)[0] == (
        "02:00:00:00:00:21", "192.0.2.21", "6943", "dhcp-snoop", "10", "Ethernet1/3",
    )  # fmt: skip
    view = parse_dhcp([{}, {}], DHCP_CONFIG, bindings)
    switch = view.of("switch")[0]
    assert ("Snooping in VLANs", "10,20") in switch.facts
    assert ("MAC addresses checked", "off") in switch.facts
    assert ("DHCPv6 relay", "off") in switch.facts
    assert switch.values["arp_validate"] == {"checks": "src-mac ip"}
    assert "verify_mac" not in switch.values and "relay" in switch.values
    port = next(i for i in view.of("port") if i.title == "Ethernet1/3")
    assert port.values == {
        "snooping_trust": {"on": "yes"},
        "snooping_rate": {"rate": "30"},
        "arp_trust": {"on": "yes"},
    }
    relay = view.of("relay")[0]
    assert relay.facts == (("DHCP servers", "192.0.2.53, 198.51.100.53 (VRF lab), 2001:db8::53"),)
    acl = view.of("arp_acl")[0]
    assert ("For VLANs", "10") in acl.facts
    rows = view.tables[2].rows
    assert len(rows) == 3  # two learned, one fixed
    assert ("0200.0000.0020", "192.0.2.20", "—", "static", "10", "Ethernet1/3") in rows
    unread = parse_dhcp([{}, {}], DHCP_CONFIG, None).tables[2]
    assert "did not answer" in unread.note
    assert "does not let it read" in parse_dhcp([{}, {}], None).notes[0]


def test_dhcp_defaults_with_no_lines() -> None:
    switch = parse_dhcp([{}, {}], "hostname a\n").of("switch")[0]
    assert ("DHCP snooping", "off") in switch.facts
    assert ("DHCP relay", "on") in switch.facts and ("MAC addresses checked", "on") in switch.facts


# ---- the role ------------------------------------------------------------------------


def test_role_has_the_layer2_rules() -> None:
    lines = role_lines(["Ethernet1/1"], "nxray")
    for rule in LAYER2_RULES:
        assert rule in lines
    assert ROLE_VERSION == 15
    assert missing_changes(13) == "layer 2 security and traffic measuring changes"
    description = next(line for line in lines if line.startswith("description "))
    assert len(description.removeprefix("description ")) <= 128
    # Restarting is never in the role.
    assert not any("reload" in line for line in lines)


# ---- restarting ----------------------------------------------------------------------


class ReloadShell:
    def __init__(self, answers: dict[str, str] | None = None, drops: bool = True) -> None:
        self.answers = answers or {}
        self.drops = drops
        self.lines: list[str] = []
        self.closed = False

    def run(self, line: str) -> str:
        self.lines.append(line)
        if line == "reload" and self.drops:
            raise SshUnreachable("the switch closed the SSH session")
        return self.answers.get(line, "")

    def close(self) -> None:
        self.closed = True
        raise OSError("socket is closed")


def _reload(shell: ReloadShell) -> None:
    reload_switch(
        host="192.0.2.10",
        port=22,
        username="admin",
        password="pw",
        timeout=5.0,
        opener=lambda *args: shell,
    )


def test_reload_types_dont_ask_then_reload() -> None:
    shell = ReloadShell()
    _reload(shell)
    assert shell.lines == ["terminal dont-ask", "reload"]
    assert shell.closed


def test_reload_that_comes_back_to_a_prompt_is_refused() -> None:
    shell = ReloadShell({"reload": "% Permission denied for the role"}, drops=False)
    with pytest.raises(SshCommandError, match="Permission denied"):
        _reload(shell)
    quiet = ReloadShell(drops=False)
    with pytest.raises(SshCommandError, match="did not restart"):
        _reload(quiet)


def test_reload_stops_when_dont_ask_is_refused() -> None:
    shell = ReloadShell({"terminal dont-ask": "% Invalid command at '^' marker."})
    with pytest.raises(SshCommandError, match="dont-ask"):
        _reload(shell)
    assert shell.lines == ["terminal dont-ask"]


def test_reload_sign_in_errors_pass_through() -> None:
    def opener(*args):  # noqa: ANN002
        raise SshAuthError("the switch refused the SSH username or password")

    with pytest.raises(SshAuthError):
        reload_switch(host="h", port=22, username="u", password="p", timeout=1.0, opener=opener)
