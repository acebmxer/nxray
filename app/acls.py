"""ACLs: the switch's IPv4, IPv6 and MAC access lists, their entries, the object
groups and VLAN access maps that go with them, where they apply, the TCAM space
they live in, and every change the ACLs page makes.

The page is described with the same parts as the routing protocol pages
(``app/protocols.py``): one scope per kind of ACL (``ip access-list {name}``,
``ipv6 access-list {name}``), made and deleted from the page, with its entries
as settings; and two scopes for where an ACL applies: a layer 3 interface (a
VLAN interface, routed port or routed port-channel, ``ip access-group`` and
``ipv6 traffic-filter``, in or out) and a switched front port or port-channel
(``ip port access-group`` and ``ipv6 port traffic-filter``, in only, as NX-OS
allows). ``NxapiClient.configure_acl`` sends what ``build_acl_change`` builds.

An entry is one line inside the ACL, numbered: ``10 permit tcp 192.0.2.0/24
any eq 22``. Its source and destination are ``any``, a network, or one
address (sent as /32 or /128); TCP, UDP and SCTP entries may also match ports.
The switch refuses a number already in use, so changing an entry is removing
it and adding it again. Every ACL ends with an unwritten "deny everything
else".

From role version 14 the page also has MAC ACLs (``mac access-list {name}``,
applied to switched ports with ``mac port access-group``); object groups
(``object-group ip address``, ``ipv6 address``, ``ip port``), which an entry
names as ``addrgroup <name>`` or ``portgroup <name>`` in place of an address or
port; VLAN access maps (``vlan access-map {name} {seq}``: match an ACL, then
forward or drop) and the VLAN filters that apply them (``vlan filter {name}
vlan-list {vlans}``); and the TCAM regions' sizes (``hardware access-list tcam
region {region} {size}``), which on a Nexus 9000 decide whether port ACLs, VLAN
ACLs and DHCP snooping fit at all and change only when the switch restarts.
``V14_SCOPES`` names what needs that role.

Read: ``show interface brief`` for the interfaces, the running configuration as
text, the only place the ACLs show as typed (NXray's role allows that read from
role version 12), and ``show hardware access-list tcam region`` as text. The
lines follow Cisco's NX-OS 9.3 Security Configuration Guide; not yet tried on
a switch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.config_tools import RUNNING_COMMAND, config_sections
from app.nxapi import VLAN_INTERFACE_MAX, NxapiClient, NxapiCommandError
from app.protocols import (
    Field,
    Instance,
    Protocol,
    ProtocolChange,
    ProtocolView,
    Scope,
    Setting,
    Table,
    build_change,
    interface_field,
    port_field,
)
from app.routing import parse_brief
from app.spanning_tree import stp_vlan_numbers, switch_port_names

SEQ_MAX = 4294967295
REMARK_MAX = 100
IPV4_PROTOCOLS = ("ip", "tcp", "udp", "icmp", "igmp", "ospf", "pim", "gre", "esp", "ahp", "sctp")
IPV6_PROTOCOLS = ("ipv6", "tcp", "udp", "icmp", "sctp")
PORT_PROTOCOLS = ("tcp", "udp", "sctp")
COS_MAX = 7
# TCAM regions are sized in entries, a multiple of 256 on a Nexus 9000.
TCAM_STEP = 256
TCAM_MAX = 16384
TCAM_COMMAND = "show hardware access-list tcam region"


def _acl_name(name: str = "name", label: str = "ACL") -> Field:
    return Field(
        name,
        label,
        "name",
        maximum=64,
        hint="Letters, digits, '.', '_' or '-'",
        placeholder="mgmt-in",
    )


def _ports_only_for_l4(values: dict[str, str]) -> None:
    if (values["source_port"] or values["destination_port"]) and values[
        "protocol"
    ] not in PORT_PROTOCOLS:
        raise ValueError("ports can only be matched for tcp, udp or sctp")


def _entry_settings(family: str) -> tuple[Setting, ...]:
    v6 = family == "IPv6"
    kind = "aclnet6" if v6 else "aclnet4"
    example = "2001:db8::/32" if v6 else "192.0.2.0/24"

    def net(name: str, label: str) -> Field:
        return Field(
            name,
            label,
            kind,
            hint=f"any, a network such as {example}, one address, or addrgroup <name>",
            placeholder="any",
        )

    def port(name: str, label: str) -> Field:
        return Field(
            name,
            label,
            "l4port",
            optional=True,
            hint="tcp, udp or sctp only: 22, 1024-65535, >1023, <1024, !=23 or portgroup <name>",
        )

    return (
        Setting(
            "entry",
            "Entry",
            "{seq} {action} {protocol} {source}[ {source_port}] {destination}"
            "[ {destination_port}][ {log}]",
            (
                Field("seq", "Number", "int", 1, SEQ_MAX, placeholder="10"),
                Field("action", "Action", "choice", choices=("permit", "deny")),
                Field(
                    "protocol",
                    "Protocol",
                    "choice",
                    choices=IPV6_PROTOCOLS if v6 else IPV4_PROTOCOLS,
                    hint=f"{'ipv6' if v6 else 'ip'}: every protocol",
                ),
                net("source", "Source"),
                port("source_port", "Source port"),
                net("destination", "Destination"),
                port("destination_port", "Destination port"),
                Field("log", "Log matches", "flag", choices=("log",)),
            ),
            no_line="no {seq}",
            help="Entries are checked from the lowest number up; the first that matches "
            "decides. To change an entry, remove it (only its number is needed) and add it again",
            check=_ports_only_for_l4,
            group="Entries",
        ),
        Setting(
            "remark",
            "Remark",
            "{seq} remark {remark}",
            (
                Field("seq", "Number", "int", 1, SEQ_MAX, placeholder="5"),
                Field("remark", "Text", "text", maximum=REMARK_MAX),
            ),
            no_line="no {seq}",
            help="A note between the entries; it matches nothing",
            group="Entries",
        ),
        Setting(
            "statistics",
            "Count matches",
            "statistics per-entry",
            help="The switch counts the packets each entry matches",
            group="Options",
        ),
    )


IPV4_ACL = Scope(
    "ipv4_acl",
    "IPv4 ACLs",
    (_acl_name(),),
    ("ip access-list {name}",),
    _entry_settings("IPv4"),
    create=True,
    create_label="Make an IPv4 ACL",
    delete=("no ip access-list {name}",),
    delete_warning="Interfaces that use this ACL keep naming it; with the ACL gone the switch "
    "lets their traffic through unfiltered.",
    help="Named lists of IPv4 entries that permit or deny packets. A new ACL has no entries.",
)

IPV6_ACL = Scope(
    "ipv6_acl",
    "IPv6 ACLs",
    (_acl_name(),),
    ("ipv6 access-list {name}",),
    _entry_settings("IPv6"),
    create=True,
    create_label="Make an IPv6 ACL",
    delete=("no ipv6 access-list {name}",),
    delete_warning=IPV4_ACL.delete_warning,
    help="Named lists of IPv6 entries that permit or deny packets.",
)

_APPLY_WARNING = (
    "Traffic the ACL does not permit is dropped at once, the session you are using "
    "too if it crosses this interface."
)


def _apply(key: str, label: str, line: str, help_text: str = "") -> Setting:
    return Setting(
        key,
        label,
        line,
        (_acl_name("acl"),),
        help=help_text,
        warning=_APPLY_WARNING,
        group="ACLs",
    )


LAYER3 = Scope(
    "routed",
    "On layer 3 interfaces",
    (interface_field(),),
    ("interface {interface}",),
    (
        _apply("ipv4_in", "IPv4 ACL, in", "ip access-group {acl} in", "Packets coming in"),
        _apply("ipv4_out", "IPv4 ACL, out", "ip access-group {acl} out", "Packets going out"),
        _apply("ipv6_in", "IPv6 ACL, in", "ipv6 traffic-filter {acl} in"),
        _apply("ipv6_out", "IPv6 ACL, out", "ipv6 traffic-filter {acl} out"),
    ),
    help="ACLs on VLAN interfaces, routed ports and routed port-channels: they filter "
    "the traffic routed through them.",
)

SWITCHED = Scope(
    "switched",
    "On switched ports",
    (port_field(),),
    ("interface {port}",),
    (
        _apply(
            "ipv4_in", "IPv4 port ACL, in", "ip port access-group {acl} in", "Packets coming in"
        ),
        _apply("ipv6_in", "IPv6 port ACL, in", "ipv6 port traffic-filter {acl} in"),
        _apply(
            "mac_in",
            "MAC port ACL, in",
            "mac port access-group {acl}",
            "Checks the packets that are not IP by their MAC addresses (role version 14)",
        ),
    ),
    help="Port ACLs on front ports and port-channels carrying VLANs: they filter the "
    "packets coming in, switched or routed. NX-OS has them inbound only. On a Nexus 9000 "
    "they need TCAM space (the ing-ifacl region) first.",
)

# ---- role version 14: MAC ACLs, object groups, VLAN access maps, TCAM ---------------


MAC_ACL = Scope(
    "mac_acl",
    "MAC ACLs",
    (_acl_name(),),
    ("mac access-list {name}",),
    (
        Setting(
            "entry",
            "Entry",
            "{seq} {action} {source} {destination}[ {ethertype}][ cos {cos}][ vlan {vlan}]",
            (
                Field("seq", "Number", "int", 1, SEQ_MAX, placeholder="10"),
                Field("action", "Action", "choice", choices=("permit", "deny")),
                Field(
                    "source",
                    "Source",
                    "aclmac",
                    hint="any, one address (0200.0000.0001), or an address and a mask whose "
                    "1 bits are ignored (0200.0000.0000 0000.00ff.ffff)",
                    placeholder="any",
                ),
                Field("destination", "Destination", "aclmac", placeholder="any"),
                Field(
                    "ethertype",
                    "EtherType",
                    "ethertype",
                    optional=True,
                    hint="Only this kind of packet: 0x0806 is ARP, 0x8100 a tagged frame",
                ),
                Field("cos", "CoS", "int", 0, COS_MAX, optional=True, hint="802.1p priority"),
                Field("vlan", "VLAN", "vlan", optional=True),
            ),
            no_line="no {seq}",
            help="Entries are checked from the lowest number up; the first that matches "
            "decides. A MAC port ACL checks only packets that are not IP",
            group="Entries",
        ),
        Setting(
            "remark",
            "Remark",
            "{seq} remark {remark}",
            (
                Field("seq", "Number", "int", 1, SEQ_MAX, placeholder="5"),
                Field("remark", "Text", "text", maximum=REMARK_MAX),
            ),
            no_line="no {seq}",
            help="A note between the entries; it matches nothing",
            group="Entries",
        ),
        Setting(
            "statistics",
            "Count matches",
            "statistics per-entry",
            help="The switch counts the packets each entry matches",
            group="Options",
        ),
    ),
    create=True,
    create_label="Make a MAC ACL",
    delete=("no mac access-list {name}",),
    delete_warning=IPV4_ACL.delete_warning,
    help="Named lists that permit or deny packets by their MAC addresses, EtherType, CoS "
    "and VLAN. Role version 14.",
)


def _group_address(values: dict[str, str]) -> None:
    if values["address"] == "any" or values["address"].startswith("addrgroup "):
        raise ValueError("an address group holds networks and addresses, not any or a group")


def _group_port(values: dict[str, str]) -> None:
    if values["port"].startswith("portgroup "):
        raise ValueError("a port group holds ports and ranges, not another group")


def _address_group(key: str, family: str) -> Scope:
    v6 = family == "IPv6"
    word = "ipv6" if v6 else "ip"
    example = "2001:db8::/32" if v6 else "192.0.2.0/24"
    return Scope(
        key,
        f"{family} address groups",
        (_acl_name(label="Group"),),
        (f"object-group {word} address {{name}}",),
        (
            Setting(
                "entry",
                "Entry",
                "{seq} {address}",
                (
                    Field("seq", "Number", "int", 1, SEQ_MAX, placeholder="10"),
                    Field(
                        "address",
                        "Address",
                        "aclnet6" if v6 else "aclnet4",
                        hint=f"A network such as {example}, or one address",
                    ),
                ),
                no_line="no {seq}",
                check=_group_address,
                group="Entries",
            ),
        ),
        create=True,
        create_label=f"Make an {family} address group",
        delete=(f"no object-group {word} address {{name}}",),
        delete_warning="The switch refuses while an ACL entry names the group.",
        help=f"Named sets of {family} networks; an {family} ACL entry names one as "
        "addrgroup <name> in place of its source or destination. Role version 14.",
    )


ADDR4_GROUP = _address_group("addr4_group", "IPv4")
ADDR6_GROUP = _address_group("addr6_group", "IPv6")

PORT_GROUP = Scope(
    "port_group",
    "Port groups",
    (_acl_name(label="Group"),),
    ("object-group ip port {name}",),
    (
        Setting(
            "entry",
            "Entry",
            "{seq} {port}",
            (
                Field("seq", "Number", "int", 1, SEQ_MAX, placeholder="10"),
                Field(
                    "port",
                    "Port",
                    "l4port",
                    hint="22, 1024-65535, >1023, <1024 or !=23",
                ),
            ),
            no_line="no {seq}",
            check=_group_port,
            group="Entries",
        ),
    ),
    create=True,
    create_label="Make a port group",
    delete=("no object-group ip port {name}",),
    delete_warning=ADDR4_GROUP.delete_warning,
    help="Named sets of TCP, UDP or SCTP ports; an entry names one as portgroup <name> in "
    "place of a port. Role version 14.",
)

ACCESS_MAP = Scope(
    "access_map",
    "VLAN access maps",
    (
        _acl_name(label="Access map"),
        Field("seq", "Entry", "int", 1, SEQ_MAX, placeholder="10"),
    ),
    ("vlan access-map {name} {seq}",),
    (
        Setting(
            "match_ip",
            "Match an IPv4 ACL",
            "match ip address {acl}",
            (_acl_name("acl"),),
            help="Packets the ACL permits match this entry",
            group="Match",
        ),
        Setting(
            "match_ipv6",
            "Match an IPv6 ACL",
            "match ipv6 address {acl}",
            (_acl_name("acl"),),
            group="Match",
        ),
        Setting(
            "match_mac",
            "Match a MAC ACL",
            "match mac address {acl}",
            (_acl_name("acl"),),
            group="Match",
        ),
        Setting(
            "action",
            "Then",
            "action {action}",
            (Field("action", "Action", "choice", choices=("forward", "drop")),),
            removable=False,
            help="What happens to the packets that match",
            group="Action",
        ),
        Setting(
            "statistics",
            "Count matches",
            "statistics per-entry",
            group="Action",
        ),
    ),
    create=True,
    create_label="Make a VLAN access map entry",
    delete=("no vlan access-map {name} {seq}",),
    delete_warning="A VLAN filter that names the map keeps it; with no entry left the VLANs "
    "are no longer filtered by it.",
    help="VLAN ACLs: entries, checked from the lowest number up, that match an ACL and then "
    "forward or drop. A VLAN filter applies the map to VLANs. Role version 14.",
)

VLAN_FILTER = Scope(
    "vlan_filter",
    "VLAN filters",
    (_acl_name(label="Access map"),),
    (),
    (
        Setting(
            "vlans",
            "Filter VLANs",
            "vlan filter {name} vlan-list {vlans}",
            (Field("vlans", "VLANs", "vlans", placeholder="10,20-30"),),
            ident=("name",),
            help="Every packet in these VLANs, switched or routed, goes through the access "
            "map. Remove takes the same VLANs",
            warning="Packets the map does not forward are dropped at once, in every port of "
            "these VLANs; a map with no matching entry drops everything.",
            group="VLANs",
        ),
    ),
    help="Applies a VLAN access map to VLANs. On a Nexus 9000 it needs TCAM space (the "
    "vacl region) first. Role version 14.",
)


def _tcam_size(values: dict[str, str]) -> None:
    if int(values["size"]) % TCAM_STEP:
        raise ValueError(f"a TCAM region's size is a multiple of {TCAM_STEP}")


TCAM = Scope(
    "tcam",
    "TCAM space",
    (),
    (),
    (
        Setting(
            "region",
            "Region size",
            "hardware access-list tcam region {region} {size}",
            (
                Field(
                    "region",
                    "Region",
                    "name",
                    maximum=32,
                    hint="Its name in brackets in the table above: ing-ifacl (port ACLs), "
                    "vacl (VLAN ACLs), ing-racl (ACLs on layer 3 interfaces), ing-sup",
                    placeholder="ing-ifacl",
                ),
                Field(
                    "size",
                    "Entries",
                    "int",
                    0,
                    TCAM_MAX,
                    hint=f"A multiple of {TCAM_STEP}; 0 frees the region",
                    placeholder="256",
                ),
            ),
            removable=False,
            check=_tcam_size,
            help="The space must come from another region: shrink one first. The new sizes "
            "count only after Save config and a restart of the switch",
            warning="Nothing changes until the switch restarts (Config page). Save config "
            "first, or the restart loses this. A region shrunk below what it holds then drops "
            "those ACL entries.",
            group="Regions",
        ),
    ),
    help="The hardware space ACLs, port ACLs, VLAN ACLs, QoS and DHCP snooping are kept in. "
    "Role version 14.",
)

# What needs role version 14 on this page: scopes, and settings of older scopes.
V14_SCOPES = frozenset(
    ("mac_acl", "addr4_group", "addr6_group", "port_group", "access_map", "vlan_filter", "tcam")
)
V14_SETTINGS = frozenset((("switched", "mac_in"),))


def needs_v14(scope: str, setting: str) -> bool:
    """Whether a change on the ACLs page needs NXray's role version 14."""
    return scope in V14_SCOPES or (scope, setting) in V14_SETTINGS


# ---- reading ------------------------------------------------------------------------


@dataclass
class AccessMap:
    """One entry of a VLAN access map, as the running configuration has it."""

    matches: list[tuple[str, str]] = field(default_factory=list)  # (setting key, ACL)
    action: str = ""
    statistics: bool = False


@dataclass(frozen=True)
class AclConfig:
    """The ACLs and where they apply, as the running configuration has them."""

    ipv4: dict[str, list[str]]  # name -> entry lines, as typed
    ipv6: dict[str, list[str]]
    statistics: set[tuple[str, str]]  # (family, name) with statistics per-entry
    routed: dict[str, dict[str, str]]  # interface -> setting key -> ACL
    switched: dict[str, dict[str, str]]  # port -> setting key -> ACL
    mac: dict[str, list[str]] = field(default_factory=dict)
    groups: dict[str, dict[str, list[str]]] = field(default_factory=dict)  # scope -> name -> lines
    access_maps: dict[tuple[str, str], AccessMap] = field(default_factory=dict)  # (name, seq)
    vlan_filters: dict[str, list[str]] = field(default_factory=dict)  # map -> VLAN lists
    tcam: dict[str, str] = field(default_factory=dict)  # region -> size configured


_ROUTED_LINES = {
    ("ip", "access-group", "in"): "ipv4_in",
    ("ip", "access-group", "out"): "ipv4_out",
    ("ipv6", "traffic-filter", "in"): "ipv6_in",
    ("ipv6", "traffic-filter", "out"): "ipv6_out",
}
_PORT_LINES = {
    ("ip", "access-group", "in"): "ipv4_in",
    ("ipv6", "traffic-filter", "in"): "ipv6_in",
}
_LIST_HEADERS = {("ip",): "ipv4", ("ipv6",): "ipv6", ("mac",): "mac"}
_GROUP_HEADERS = {
    ("ip", "address"): "addr4_group",
    ("ipv6", "address"): "addr6_group",
    ("ip", "port"): "port_group",
}
_MATCH_LINES = {"ip": "match_ip", "ipv6": "match_ipv6", "mac": "match_mac"}


def _interface_lines(found: AclConfig, name: str, body: list[str]) -> None:
    for line in body:
        parts = line.split()
        if len(parts) == 4 and parts[:3] == ["mac", "port", "access-group"]:
            found.switched.setdefault(name, {})["mac_in"] = parts[3]
        elif len(parts) == 5 and parts[1] == "port":
            key = _PORT_LINES.get((parts[0], parts[2], parts[4]))
            if key:
                found.switched.setdefault(name, {})[key] = parts[3]
        elif len(parts) == 4:
            key = _ROUTED_LINES.get((parts[0], parts[1], parts[3]))
            if key:
                found.routed.setdefault(name, {})[key] = parts[2]


def parse_acl_config(config: str) -> AclConfig:
    """``show running-config`` as text: the ACLs, their entries, the object groups,
    VLAN access maps and filters, the TCAM sizes set, and the interfaces the ACLs
    apply on."""
    found = AclConfig({}, {}, set(), {}, {})
    for header, body in config_sections(config):
        words = header.split()
        if len(words) == 3 and words[1] == "access-list" and (words[0],) in _LIST_HEADERS:
            family = _LIST_HEADERS[(words[0],)]
            lists = {"ipv4": found.ipv4, "ipv6": found.ipv6, "mac": found.mac}[family]
            lines = lists.setdefault(words[2], [])
            for line in body:
                if line == "statistics per-entry":
                    found.statistics.add((family, words[2]))
                elif line.split()[0].isdigit():
                    lines.append(line)
        elif len(words) == 4 and words[0] == "object-group":
            scope = _GROUP_HEADERS.get((words[1], words[2]))
            if scope:
                entries = found.groups.setdefault(scope, {}).setdefault(words[3], [])
                entries += [line for line in body if line.split()[0].isdigit()]
        elif len(words) == 4 and words[:2] == ["vlan", "access-map"]:
            entry = found.access_maps.setdefault((words[2], words[3]), AccessMap())
            for line in body:
                parts = line.split()
                if len(parts) == 4 and parts[0] == "match" and parts[2] == "address":
                    key = _MATCH_LINES.get(parts[1])
                    if key:
                        entry.matches.append((key, parts[3]))
                elif len(parts) == 2 and parts[0] == "action":
                    entry.action = parts[1]
                elif line == "statistics per-entry":
                    entry.statistics = True
        elif len(words) == 5 and words[:2] == ["vlan", "filter"] and words[3] == "vlan-list":
            found.vlan_filters.setdefault(words[2], []).append(words[4])
        elif len(words) == 6 and words[:4] == ["hardware", "access-list", "tcam", "region"]:
            found.tcam[words[4]] = words[5]
        elif len(words) == 2 and words[0] == "interface":
            _interface_lines(found, words[1], body)
    return found


_TCAM_LINE = re.compile(r"^\s*(.*?)\s*\[([A-Za-z0-9_-]+)\]\s+size\s*=\s*(\d+)\s*$")


def parse_tcam_regions(text: str) -> list[tuple[str, str, str]]:
    """``show hardware access-list tcam region`` as text: (region, what it is
    for, size in entries), from lines such as ``Ingress PACL [ing-ifacl] size =
    256``."""
    found = []
    for line in text.splitlines():
        if match := _TCAM_LINE.match(line):
            found.append((match.group(2), match.group(1), match.group(3)))
    return found


def _uses(config: AclConfig, family: str, name: str) -> list[str]:
    """Where an ACL applies, as "Vlan10 in" (or "access map web 10")."""
    prefix = f"{family}_"
    found = []
    for place in (config.routed, config.switched):
        for interface, keys in place.items():
            for key, acl in keys.items():
                if acl == name and key.startswith(prefix):
                    found.append(f"{interface} {key.rsplit('_', 1)[1]}")
    match_key = {"ipv4": "match_ip", "ipv6": "match_ipv6", "mac": "match_mac"}[family]
    for (map_name, seq), entry in config.access_maps.items():
        if (match_key, name) in entry.matches:
            found.append(f"access map {map_name} {seq}")
    return found


_LABELS = {
    "ipv4_in": "IPv4 in",
    "ipv4_out": "IPv4 out",
    "ipv6_in": "IPv6 in",
    "ipv6_out": "IPv6 out",
    "mac_in": "MAC in",
}
_FAMILY_NAMES = {"ipv4": "IPv4", "ipv6": "IPv6", "mac": "MAC"}
_GROUP_NAMES = {
    "addr4_group": "IPv4 addresses",
    "addr6_group": "IPv6 addresses",
    "port_group": "ports",
}


def _entry_facts(entries: list[str]) -> list[tuple[str, str]]:
    return [(line.split(" ", 1)[0], line.split(" ", 1)[1]) for line in entries if " " in line]


def _group_uses(config: AclConfig, scope: str, name: str) -> list[str]:
    word = "portgroup" if scope == "port_group" else "addrgroup"
    lists = config.ipv6 if scope == "addr6_group" else config.ipv4
    return [
        acl
        for acl, entries in lists.items()
        if any(f" {word} {name} " in f" {line} " for line in entries)
    ]


def _list_instances(config: AclConfig) -> tuple[list[Instance], list[tuple[str, ...]]]:
    instances: list[Instance] = []
    rows: list[tuple[str, ...]] = []
    for family, scope, lists in (
        ("ipv4", "ipv4_acl", config.ipv4),
        ("ipv6", "ipv6_acl", config.ipv6),
        ("mac", "mac_acl", config.mac),
    ):
        for name, entries in lists.items():
            facts = _entry_facts(entries)
            if not facts:
                facts = [("Entries", "none yet: where it applies, it drops everything")]
            uses = _uses(config, family, name)
            facts.append(("Applies on", ", ".join(uses) if uses else "nothing yet"))
            counted = (family, name) in config.statistics
            if counted:
                facts.append(("Counts matches", "yes"))
            values = {"statistics": {"on": "yes"}} if counted else {}
            instances.append(Instance(scope, {"name": name}, name, tuple(facts), values))
            rows.append((name, _FAMILY_NAMES[family], str(len(entries)), ", ".join(uses) or "—"))
    return instances, rows


def _more_instances(config: AclConfig) -> tuple[list[Instance], list[tuple[str, ...]]]:
    """The object groups, VLAN access maps and VLAN filters, with the rows of their
    table."""
    instances: list[Instance] = []
    rows: list[tuple[str, ...]] = []
    for scope in ("addr4_group", "addr6_group", "port_group"):
        for name, entries in config.groups.get(scope, {}).items():
            uses = _group_uses(config, scope, name)
            facts = _entry_facts(entries) or [("Entries", "none yet")]
            facts.append(("Used by", ", ".join(uses) if uses else "no ACL yet"))
            instances.append(Instance(scope, {"name": name}, name, tuple(facts)))
            rows.append(
                (f"{_GROUP_NAMES[scope]} group", name, str(len(entries)), ", ".join(uses) or "—")
            )
    for (name, seq), entry in config.access_maps.items():
        facts = [(_MATCH_TITLES[key], acl) for key, acl in entry.matches]
        facts.append(("Then", entry.action or "not set: the switch forwards"))
        if entry.statistics:
            facts.append(("Counts matches", "yes"))
        values: dict[str, dict[str, str]] = {key: {"acl": acl} for key, acl in entry.matches}
        if entry.action:
            values["action"] = {"action": entry.action}
        if entry.statistics:
            values["statistics"] = {"on": "yes"}
        instances.append(
            Instance(
                "access_map", {"name": name, "seq": seq}, f"{name} {seq}", tuple(facts), values
            )
        )
        vlans = ", ".join(config.vlan_filters.get(name, []))
        matched = ", ".join(acl for _, acl in entry.matches) or "everything"
        rows.append(
            (
                "VLAN access map",
                f"{name} {seq}",
                f"{matched} → {entry.action or 'forward'}",
                vlans or "—",
            )
        )
    for name, vlan_lists in config.vlan_filters.items():
        instances.append(
            Instance(
                "vlan_filter",
                {"name": name},
                name,
                (("VLANs", ", ".join(vlan_lists)),),
            )
        )
    return instances, rows


_MATCH_TITLES = {
    "match_ip": "Matches IPv4 ACL",
    "match_ipv6": "Matches IPv6 ACL",
    "match_mac": "Matches MAC ACL",
}


def _tcam_table(text: str | None, config: AclConfig) -> Table:
    if text is None:
        return Table(
            "TCAM regions",
            ("Region", "For", "Entries now", "Set to"),
            empty="The switch did not answer show hardware access-list tcam region.",
        )
    regions = parse_tcam_regions(text)
    rows = tuple(
        (region, purpose, size, config.tcam.get(region, "—")) for region, purpose, size in regions
    )
    pending = [r for r, _, size in regions if r in config.tcam and config.tcam[r] != size]
    return Table(
        "TCAM regions",
        ("Region", "For", "Entries now", "Set to"),
        rows,
        empty="The switch listed no TCAM regions.",
        note=(
            f"Waiting for a restart of the switch: {', '.join(pending)}."
            if pending
            else "A region of 0 entries cannot hold any: port ACLs need ing-ifacl, VLAN ACLs vacl."
        ),
    )


def parse_acls(
    bodies: list[dict[str, Any]], config_text: str | None = None, tcam_text: str | None = None
) -> ProtocolView:
    """The ACLs page from the running configuration (None: NXray may not read it)
    and the TCAM regions (None: not read)."""
    if config_text is None:
        return ProtocolView(
            notes=(
                "NXray's role on the switch does not let it read the switch's configuration "
                "yet, the only place the ACLs show: an NXray admin turns on security and "
                "config changes on the Switch page.",
            )
        )
    config = parse_acl_config(config_text)
    instances, rows = _list_instances(config)
    more, more_rows = _more_instances(config)
    instances += more
    for scope, place in (("routed", config.routed), ("switched", config.switched)):
        ident_name = "interface" if scope == "routed" else "port"
        for interface, keys in place.items():
            instances.append(
                Instance(
                    scope,
                    {ident_name: interface},
                    interface,
                    tuple((_LABELS[key], acl) for key, acl in sorted(keys.items())),
                    {key: {"acl": acl} for key, acl in keys.items()},
                )
            )
    tables = [
        Table(
            "Every ACL",
            ("ACL", "Family", "Entries", "Applies on"),
            tuple(rows),
            empty="None: the switch filters no traffic with ACLs.",
        ),
        Table(
            "Object groups and VLAN access maps",
            ("Kind", "Name", "Holds", "Used by / VLANs"),
            tuple(more_rows),
            empty="None.",
        ),
        _tcam_table(tcam_text, config),
    ]
    return ProtocolView(tuple(instances), tuple(tables))


ACLS = Protocol(
    key="acls",
    name="ACLs",
    summary="Access lists: which packets the switch lets through, on which interfaces",
    features=(),
    commands=("show interface brief",),
    parse=parse_acls,
    scopes=(
        IPV4_ACL,
        IPV6_ACL,
        LAYER3,
        SWITCHED,
        MAC_ACL,
        ADDR4_GROUP,
        ADDR6_GROUP,
        PORT_GROUP,
        ACCESS_MAP,
        VLAN_FILTER,
        TCAM,
    ),
    about="Make an ACL, add its entries, then apply it to an interface, port or (with a VLAN "
    "access map) VLANs. Every ACL ends with an unwritten entry that drops everything else.",
)


@dataclass(frozen=True)
class AclPage:
    """Everything the ACLs page shows."""

    protocol: Protocol
    view: ProtocolView
    interfaces: tuple[str, ...]  # VLAN interfaces up to Vlan254, routed ports and channels
    ports: tuple[str, ...]  # switched front ports and port-channels
    vlans: tuple[str, ...] = ()  # for the VLAN field's list
    problem: str = ""
    missing: tuple[str, ...] = ()  # needs no feature; kept for the template


def layer3_names(brief: dict[str, Any]) -> tuple[str, ...]:
    """The VLAN interfaces (up to Vlan254) and routed ports and port-channels in
    ``show interface brief``."""
    svis, routed = parse_brief(brief)
    names = [n for n in svis if int(n[4:]) <= VLAN_INTERFACE_MAX]
    return tuple(names + [str(r.get("interface", "")).strip() for r in routed])


def load_acls_page(client: NxapiClient) -> AclPage:
    """One request for the interfaces and VLANs, one for the configuration text, one
    for the TCAM regions."""
    brief, vlan_body = client.show(*ACLS.commands, "show vlan brief")
    try:
        config: str | None = client.show_text(RUNNING_COMMAND)
    except NxapiCommandError:
        config = None
    try:
        tcam: str | None = client.show_text(TCAM_COMMAND)
    except NxapiCommandError:
        tcam = None
    view = parse_acls([brief], config, tcam)
    vlans = tuple(str(n) for n in stp_vlan_numbers(vlan_body))
    return AclPage(ACLS, view, layer3_names(brief), tuple(switch_port_names(brief)), vlans)


def build_acl_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the ACLs page."""
    return build_change(ACLS, scope, setting, action, ident, values)
