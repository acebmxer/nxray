"""ACLs: the switch's IPv4 and IPv6 access lists, their entries, and where they
apply, and every change the ACLs page makes.

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

Read: ``show interface brief`` for the interfaces, and the running
configuration as text, the only place the ACLs show as typed (NXray's role
allows that read from role version 12). The lines follow Cisco's NX-OS 9.3
Security Configuration Guide; not yet tried on a switch. MAC ACLs, object
groups and VLAN access maps are left out.
"""

from __future__ import annotations

from dataclasses import dataclass
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
from app.spanning_tree import switch_port_names

SEQ_MAX = 4294967295
REMARK_MAX = 100
IPV4_PROTOCOLS = ("ip", "tcp", "udp", "icmp", "igmp", "ospf", "pim", "gre", "esp", "ahp", "sctp")
IPV6_PROTOCOLS = ("ipv6", "tcp", "udp", "icmp", "sctp")
PORT_PROTOCOLS = ("tcp", "udp", "sctp")


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
            hint=f"any, a network such as {example}, or one address",
            placeholder="any",
        )

    def port(name: str, label: str) -> Field:
        return Field(
            name,
            label,
            "l4port",
            optional=True,
            hint="tcp, udp or sctp only: 22, 1024-65535, >1023, <1024 or !=23",
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
    ),
    help="Port ACLs on front ports and port-channels carrying VLANs: they filter the "
    "packets coming in, switched or routed. NX-OS has them inbound only.",
)

# ---- reading ------------------------------------------------------------------------


@dataclass(frozen=True)
class AclConfig:
    """The ACLs and where they apply, as the running configuration has them."""

    ipv4: dict[str, list[str]]  # name -> entry lines, as typed
    ipv6: dict[str, list[str]]
    statistics: set[tuple[str, str]]  # (family, name) with statistics per-entry
    routed: dict[str, dict[str, str]]  # interface -> setting key -> ACL
    switched: dict[str, dict[str, str]]  # port -> setting key -> ACL


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


def parse_acl_config(config: str) -> AclConfig:
    """``show running-config`` as text: the ACLs, their entries, and the interfaces
    they apply on."""
    found = AclConfig({}, {}, set(), {}, {})
    for header, body in config_sections(config):
        words = header.split()
        if len(words) == 3 and words[1] == "access-list" and words[0] in ("ip", "ipv6"):
            family = "ipv4" if words[0] == "ip" else "ipv6"
            entries = found.ipv4 if family == "ipv4" else found.ipv6
            lines = entries.setdefault(words[2], [])
            for line in body:
                if line == "statistics per-entry":
                    found.statistics.add((family, words[2]))
                elif line.split()[0].isdigit():
                    lines.append(line)
        elif len(words) == 2 and words[0] == "interface":
            for line in body:
                parts = line.split()
                if len(parts) == 5 and parts[1] == "port":
                    key = _PORT_LINES.get((parts[0], parts[2], parts[4]))
                    if key:
                        found.switched.setdefault(words[1], {})[key] = parts[3]
                elif len(parts) == 4:
                    key = _ROUTED_LINES.get((parts[0], parts[1], parts[3]))
                    if key:
                        found.routed.setdefault(words[1], {})[key] = parts[2]
    return found


def _uses(config: AclConfig, family: str, name: str) -> list[str]:
    """Where an ACL applies, as "Vlan10 in"."""
    prefix = "ipv4_" if family == "ipv4" else "ipv6_"
    found = []
    for place in (config.routed, config.switched):
        for interface, keys in place.items():
            for key, acl in keys.items():
                if acl == name and key.startswith(prefix):
                    found.append(f"{interface} {key.rsplit('_', 1)[1]}")
    return found


_LABELS = {
    "ipv4_in": "IPv4 in",
    "ipv4_out": "IPv4 out",
    "ipv6_in": "IPv6 in",
    "ipv6_out": "IPv6 out",
}


def parse_acls(bodies: list[dict[str, Any]], config_text: str | None = None) -> ProtocolView:
    """The ACLs page from the running configuration (None: NXray may not read it)."""
    if config_text is None:
        return ProtocolView(
            notes=(
                "NXray's role on the switch does not let it read the switch's configuration "
                "yet, the only place the ACLs show: an NXray admin turns on security and "
                "config changes on the Switch page.",
            )
        )
    config = parse_acl_config(config_text)
    instances: list[Instance] = []
    rows: list[tuple[str, ...]] = []
    for family, scope, lists in (
        ("ipv4", "ipv4_acl", config.ipv4),
        ("ipv6", "ipv6_acl", config.ipv6),
    ):
        for name, entries in lists.items():
            facts = [
                (line.split(" ", 1)[0], line.split(" ", 1)[1]) for line in entries if " " in line
            ]
            if not facts:
                facts = [("Entries", "none yet: where it applies, it drops everything")]
            uses = _uses(config, family, name)
            facts.append(("Applies on", ", ".join(uses) if uses else "nothing yet"))
            if (family, name) in config.statistics:
                facts.append(("Counts matches", "yes"))
            values = {"statistics": {"on": "yes"}} if (family, name) in config.statistics else {}
            instances.append(Instance(scope, {"name": name}, name, tuple(facts), values))
            rows.append(
                (
                    name,
                    "IPv4" if family == "ipv4" else "IPv6",
                    str(len(entries)),
                    ", ".join(uses) or "—",
                )
            )
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
    table = Table(
        "Every ACL",
        ("ACL", "Family", "Entries", "Applies on"),
        tuple(rows),
        empty="None: the switch filters no traffic with ACLs.",
    )
    return ProtocolView(tuple(instances), (table,))


ACLS = Protocol(
    key="acls",
    name="ACLs",
    summary="Access lists: which packets the switch lets through, on which interfaces",
    features=(),
    commands=("show interface brief",),
    parse=parse_acls,
    scopes=(IPV4_ACL, IPV6_ACL, LAYER3, SWITCHED),
    about="Make an ACL, add its entries, then apply it to an interface. Every ACL ends with an "
    "unwritten entry that drops everything else.",
)


@dataclass(frozen=True)
class AclPage:
    """Everything the ACLs page shows."""

    protocol: Protocol
    view: ProtocolView
    interfaces: tuple[str, ...]  # VLAN interfaces up to Vlan254, routed ports and channels
    ports: tuple[str, ...]  # switched front ports and port-channels
    problem: str = ""
    missing: tuple[str, ...] = ()  # needs no feature; kept for the template


def layer3_names(brief: dict[str, Any]) -> tuple[str, ...]:
    """The VLAN interfaces (up to Vlan254) and routed ports and port-channels in
    ``show interface brief``."""
    svis, routed = parse_brief(brief)
    names = [n for n in svis if int(n[4:]) <= VLAN_INTERFACE_MAX]
    return tuple(names + [str(r.get("interface", "")).strip() for r in routed])


def load_acls_page(client: NxapiClient) -> AclPage:
    """One request for the interfaces, one for the configuration text."""
    (brief,) = client.show(*ACLS.commands)
    try:
        config: str | None = client.show_text(RUNNING_COMMAND)
    except NxapiCommandError:
        config = None
    view = parse_acls([brief], config)
    return AclPage(ACLS, view, layer3_names(brief), tuple(switch_port_names(brief)))


def build_acl_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the ACLs page."""
    return build_change(ACLS, scope, setting, action, ident, values)
