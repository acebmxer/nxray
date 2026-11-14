"""Policy-based routing (PBR): route-maps that send chosen traffic to a next hop of their
own instead of the one the routing table gives, applied to the interfaces the traffic
comes in on.

A PBR route-map entry matches packets with an ACL (``match ip address <acl>``) and sets
where they go (``set ip next-hop <address> ...``, or drops them with ``set interface
null0``); ``ip policy route-map <name>`` on an interface applies it to the packets coming
in there. Packets no entry matches are routed as usual.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (a route-map entry, a route-map, an interface), each
setting the one configuration line it sends with checked values in its blanks, and
``build_change`` building the lines. ``NxapiClient.configure_pbr`` sends them.

Read from the switch: ``show feature``, ``show interface brief``, ``show vrf`` and ``show
vrf interface`` in one request (the interfaces a policy can go on); while ``feature pbr``
is on, ``show route-map``, ``show ip policy`` and ``show ipv6 policy`` in one, and ``show
route-map <name> pbr-statistics`` for each applied route-map.

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-11) with a throwaway route-map, ACL and VLAN
interface, all removed afterwards. What the switch showed and the page follows:

* ``match ip address <acl>`` takes one ACL per line; ``match ipv6 address <acl>`` too;
* ``set ip next-hop A [B ...] [load-share] [force-order] [drop-on-fail]`` is taken, and
  setting it again merges the options into the line already there. Its bare ``no`` form
  answers OK and removes nothing: the page sends the whole line;
* ``set ipv6 next-hop`` is taken; IPv4 and IPv6 set lines cannot share one route-map;
* ``set interface null0`` is taken once the route-map is applied;
* ``set ip default next-hop``, ``set vrf`` and ``set ip dscp`` are not commands on this
  switch, and ``set ip precedence`` and ``verify-availability`` gave "Internal error", so
  the page does not offer them. A route-map that once took a failed set line was refused
  by ``ip policy route-map`` until it was deleted and made again;
* ``ip policy route-map`` is refused on a loopback ("not supported on specified interface
  type"), so the page offers VLAN interfaces, routed ports and port-channels;
* ``route-map <name> pbr-statistics`` turns counting on; ``show route-map <name>
  pbr-statistics`` answers "Given route-map is not being used for PBR" until it is
  applied.

``show ip policy`` gives TABLE_pbr/ROW_pbr {interface, rmap, status, vrf_name} (nothing
when no policy is applied), ``show route-map`` TABLE_rmap/ROW_rmap with its match and set
clauses (``set_type`` and ``set_stmt``), and the statistics TABLE_rmap/ROW_rmap with
``dflt_rtg_pkt_count`` and TABLE_pbr/ROW_pbr {seq, action, pbr_pkt_count}.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.features import feature_states
from app.nxapi import NxapiClient, NxapiCommandError
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
    table_rows,
)
from app.routing import parse_vrf_members
from app.routing_protocols import layer3_interfaces
from app.switch import text

FEATURE = "pbr"
PAGE_COMMANDS = ("show feature", "show interface brief", "show vrf", "show vrf interface")
COMMANDS = ("show route-map", "show ip policy", "show ipv6 policy")
NEXT_HOPS_MAX = 16
_OPTIONS = ("load-share", "force-order", "drop-on-fail")


def _name(name: str = "name", label: str = "Route-map") -> Field:
    return Field(name, label, "name", hint="Letters, digits, - and _", placeholder="pbr-web")


def _acl(label: str) -> Field:
    return Field("acl", label, "name", hint="An ACL made on the Security page", placeholder="web")


def _hops(kind: str, placeholder: str) -> Field:
    return Field(
        "hops",
        "Next hops",
        kind,
        maximum=NEXT_HOPS_MAX,
        hint="One or more addresses, with spaces between: tried in order, or shared with "
        "load-share",
        placeholder=placeholder,
    )


def _options() -> tuple[Field, ...]:
    return (
        Field(
            "load_share",
            "Share the traffic over the next hops",
            "flag",
            choices=("load-share",),
        ),
        Field(
            "force_order",
            "Use the next hops in the order given",
            "flag",
            choices=("force-order",),
        ),
        Field(
            "drop_on_fail",
            "Drop the traffic when no next hop answers",
            "flag",
            choices=("drop-on-fail",),
        ),
    )


_NEXT_HOP_LINE = "{hops}[ {load_share}][ {force_order}][ {drop_on_fail}]"
_FAMILY_NOTE = "IPv4 and IPv6 set lines cannot share one route-map: use one for each."

_ENTRY = Scope(
    key="entry",
    label="Route-map entry",
    ident=(
        _name(),
        Field(
            "seq",
            "Entry number",
            "int",
            minimum=1,
            maximum=65535,
            hint="Entries are tried from the lowest number",
            placeholder="10",
        ),
        Field("action", "Action", "choice", choices=("permit", "deny")),
    ),
    enter=("route-map {name} {action} {seq}",),
    create=True,
    create_label="Add a route-map entry",
    delete=("no route-map {name} {action} {seq}",),
    delete_warning="Traffic this entry matched is routed by the routing table again.",
    help=(
        "One numbered entry: the traffic it matches (an ACL) and where it goes. permit sends "
        "matched traffic by the entry's set line; deny routes it as usual."
    ),
    settings=(
        Setting(
            key="description",
            label="Description",
            line="description {text}",
            no_line="no description",
            group="About",
            fields=(Field("text", "Description", "text", maximum=90),),
        ),
        Setting(
            key="match_ip",
            label="IPv4 traffic",
            line="match ip address {acl}",
            group="Match: which traffic",
            fields=(_acl("IPv4 ACL"),),
            help="The traffic an IPv4 ACL permits. One ACL per entry.",
        ),
        Setting(
            key="match_ipv6",
            label="IPv6 traffic",
            line="match ipv6 address {acl}",
            group="Match: which traffic",
            fields=(_acl("IPv6 ACL"),),
            help="The traffic an IPv6 ACL permits. One ACL per entry.",
        ),
        Setting(
            key="next_hop",
            label="IPv4 next hops",
            line="set ip next-hop " + _NEXT_HOP_LINE,
            group="Set: where it goes",
            fields=(_hops("ipv4list", "192.0.2.1 192.0.2.2"), *_options()),
            help="Send matched IPv4 traffic to these next hops. Setting it again adds the "
            "options to the line already there. " + _FAMILY_NOTE,
        ),
        Setting(
            key="next_hop6",
            label="IPv6 next hops",
            line="set ipv6 next-hop " + _NEXT_HOP_LINE,
            group="Set: where it goes",
            fields=(_hops("ipv6list", "2001:db8::1"), *_options()),
            help="Send matched IPv6 traffic to these next hops. " + _FAMILY_NOTE,
        ),
        Setting(
            key="null",
            label="Drop it",
            line="set interface null0",
            group="Set: where it goes",
            help="Throw matched traffic away. The switch takes this once the route-map is "
            "applied to an interface.",
        ),
    ),
)

_MAP = Scope(
    key="route_map",
    label="Route-map",
    ident=(_name(),),
    enter=(),
    delete=("no route-map {name}",),
    delete_warning=(
        "Every entry goes. An interface that applies this route-map then routes its traffic "
        "by the routing table."
    ),
    help="A whole route-map: its counters, or deleting it with all its entries.",
    settings=(
        Setting(
            key="statistics",
            label="Count the traffic",
            line="route-map {name} pbr-statistics",
            ident=("name",),
            group="Counters",
            help="Count the packets each entry sends; Remove stops counting.",
        ),
    ),
)

_INTERFACE = Scope(
    key="interface",
    label="Interface",
    ident=(Field("interface", "Interface", "interface"),),
    enter=("interface {interface}",),
    help=(
        "Apply a route-map to the traffic coming in on a VLAN interface, routed port or "
        "routed port-channel."
    ),
    settings=(
        Setting(
            key="policy",
            label="IPv4 policy",
            line="ip policy route-map {map}",
            group="Policy",
            fields=(_name("map"),),
            help="IPv4 traffic coming in here goes by this route-map.",
            warning="Traffic coming in on this interface follows the route-map at once.",
        ),
        Setting(
            key="policy6",
            label="IPv6 policy",
            line="ipv6 policy route-map {map}",
            group="Policy",
            fields=(_name("map"),),
            help="IPv6 traffic coming in here goes by this route-map.",
            warning="Traffic coming in on this interface follows the route-map at once.",
        ),
    ),
)


def _clauses(row: dict[str, Any], table: str) -> list[str]:
    """A route-map entry's match or set clauses, each as one line (type and statement)."""
    found = []
    for clause in table_rows(row, f"TABLE_rmap_{table}", f"ROW_rmap_{table}"):
        words = f"{text(clause.get(f'{table}_type'))} {text(clause.get(f'{table}_stmt'))}"
        line = " ".join(words.split())
        if line:
            found.append(line)
    return found


def _next_hop_values(line: str) -> dict[str, str] | None:
    """The fields of a ``ip next-hop`` / ``ipv6 next-hop`` set clause."""
    words = line.split()
    hops = [w for w in words if w not in _OPTIONS]
    if not hops:
        return None
    return {
        "hops": " ".join(hops),
        "load_share": "load-share" if "load-share" in words else "",
        "force_order": "force-order" if "force-order" in words else "",
        "drop_on_fail": "drop-on-fail" if "drop-on-fail" in words else "",
    }


def _entry_values(matches: list[str], sets: list[str], description: str) -> dict[str, Any]:
    values: dict[str, dict[str, str]] = {}
    if description:
        values["description"] = {"text": description}
    for line in matches:
        if match := re.fullmatch(r"ip address:? (\S+)", line):
            values["match_ip"] = {"acl": match.group(1)}
        elif match := re.fullmatch(r"ipv6 address:? (\S+)", line):
            values["match_ipv6"] = {"acl": match.group(1)}
    for line in sets:
        if match := re.fullmatch(r"ip next-hop:? (.+)", line):
            if found := _next_hop_values(match.group(1)):
                values["next_hop"] = found
        elif match := re.fullmatch(r"ipv6 next-hop:? (.+)", line):
            if found := _next_hop_values(match.group(1)):
                values["next_hop6"] = found
        elif re.fullmatch(r"interface:? null0", line, re.IGNORECASE):
            values["null"] = {"on": "yes"}
    return values


@dataclass(frozen=True)
class Policy:
    """One ``ip policy`` or ``ipv6 policy`` line, as ``show ip|ipv6 policy`` reports it."""

    interface: str
    route_map: str
    family: str  # "IPv4" or "IPv6"
    status: str
    vrf: str


def parse_policies(ip_body: Any, ipv6_body: Any) -> list[Policy]:
    """The route-maps applied to interfaces, IPv4 first."""
    found = []
    for family, body in (("IPv4", ip_body), ("IPv6", ipv6_body)):
        for row in table_rows(body or {}, "TABLE_pbr", "ROW_pbr"):
            interface, route_map = text(row.get("interface")), text(row.get("rmap"))
            if interface and route_map:
                found.append(
                    Policy(
                        interface,
                        route_map,
                        family,
                        text(row.get("status")),
                        text(row.get("vrf_name")) or "default",
                    )
                )
    return found


def parse_statistics(body: Any) -> list[tuple[str, str, str, str]]:
    """``show route-map <name> pbr-statistics``: (route-map, entry, action, packets) per
    entry, then the packets the routing table routed (entry "-")."""
    found = []
    for row in table_rows(body or {}, "TABLE_rmap", "ROW_rmap"):
        name = text(row.get("name"))
        for entry in table_rows(row, "TABLE_pbr", "ROW_pbr"):
            found.append(
                (
                    name,
                    text(entry.get("seq")),
                    text(entry.get("action")),
                    text(entry.get("pbr_pkt_count")) or "0",
                )
            )
        if "dflt_rtg_pkt_count" in row:
            found.append((name, "-", "routing table", text(row.get("dflt_rtg_pkt_count"))))
    return found


def parse_pbr(bodies: list[Any], statistics: dict[str, Any] | None = None) -> ProtocolView:
    """The page from ``show route-map``, ``show ip policy`` and ``show ipv6 policy``, and the
    statistics of each applied route-map that counts."""
    route_maps, ip_policy, ipv6_policy = (list(bodies) + [None] * 3)[:3]
    policies = parse_policies(ip_policy, ipv6_policy)
    applied: dict[str, list[str]] = {}
    for policy in policies:
        applied.setdefault(policy.route_map, []).append(policy.interface)
    entries: list[Instance] = []
    names: dict[str, int] = {}
    for row in table_rows(route_maps or {}, "TABLE_rmap", "ROW_rmap"):
        name, action, seq = text(row.get("name")), text(row.get("action")), text(row.get("seq"))
        if not name:
            continue
        names[name] = names.get(name, 0) + 1
        matches, sets = _clauses(row, "match"), _clauses(row, "set")
        description = text(row.get("descript"))
        entries.append(
            Instance(
                "entry",
                {"name": name, "seq": seq, "action": action},
                f"{name} {action} {seq}",
                (
                    ("Match", "; ".join(matches) or "everything"),
                    ("Set", "; ".join(sets) or "nothing"),
                    ("Description", description or "-"),
                ),
                _entry_values(matches, sets, description),
            )
        )
    counting = statistics or {}
    maps = [
        Instance(
            "route_map",
            {"name": name},
            name,
            (
                ("Entries", str(count)),
                ("Applied on", ", ".join(applied.get(name, [])) or "no interface"),
            ),
            {"statistics": {"on": "yes"}} if name in counting else {},
        )
        for name, count in names.items()
    ]
    interfaces: dict[str, dict[str, dict[str, str]]] = {}
    for policy in policies:
        key = "policy" if policy.family == "IPv4" else "policy6"
        interfaces.setdefault(policy.interface, {})[key] = {"map": policy.route_map}
    places = [
        Instance(
            "interface",
            {"interface": interface},
            interface,
            tuple(
                (("IPv4 policy" if key == "policy" else "IPv6 policy"), value["map"])
                for key, value in values.items()
            ),
            values,
        )
        for interface, values in interfaces.items()
    ]
    stat_rows = [row for body in counting.values() for row in parse_statistics(body)]
    tables = (
        Table(
            "Applied policies",
            ("Interface", "Family", "Route-map", "Status", "VRF"),
            tuple((p.interface, p.family, p.route_map, p.status, p.vrf) for p in policies),
            empty="No route-map is applied to an interface yet.",
        ),
        Table(
            "Counters",
            ("Route-map", "Entry", "Action", "Packets"),
            tuple(stat_rows),
            empty="No applied route-map counts its traffic. Turn on Count the traffic on a "
            "route-map below.",
            note="Read when the page loads.",
        ),
    )
    return ProtocolView((*maps, *entries, *places), tables)


PBR = Protocol(
    key="pbr",
    name="Policy-based routing",
    summary="Send chosen traffic to a next hop of its own instead of the routing table's",
    features=(FEATURE,),
    commands=COMMANDS,
    parse=parse_pbr,
    scopes=(_ENTRY, _MAP, _INTERFACE),
    about=(
        "Make an ACL for the traffic on the Security page, add a route-map entry that "
        "matches it and sets the next hop, then apply the route-map to the interface the "
        "traffic comes in on."
    ),
)


@dataclass(frozen=True)
class PbrPage:
    """Everything the Policy-based routing page shows."""

    protocol: Protocol
    view: ProtocolView
    interfaces: tuple[str, ...]  # VLAN interfaces, routed ports and port-channels
    route_maps: tuple[str, ...] = ()
    problem: str = ""
    missing: tuple[str, ...] = ()  # the pbr feature, when it is off


def load_pbr_page(client: NxapiClient) -> PbrPage:
    """One request for the features and interfaces; while pbr is on, one for the
    route-maps and policies, and one per applied route-map for its counters."""
    feature, brief, _vrf, vrf_members = client.show(*PAGE_COMMANDS)
    interfaces = layer3_interfaces(brief, parse_vrf_members(vrf_members))
    if not feature_states(feature).get(FEATURE, False):
        return PbrPage(PBR, ProtocolView(), interfaces, missing=(FEATURE,))
    bodies = client.show(*COMMANDS)
    statistics: dict[str, Any] = {}
    for name in dict.fromkeys(p.route_map for p in parse_policies(bodies[1], bodies[2])):
        try:
            (body,) = client.show(f"show route-map {name} pbr-statistics")
        except NxapiCommandError:
            continue  # not counting, or not used for PBR yet
        if body:
            statistics[name] = body
    view = parse_pbr(bodies, statistics)
    names = tuple(i.ident["name"] for i in view.of("route_map"))
    return PbrPage(PBR, view, interfaces, names)


def check_pbr_place(page: PbrPage, ident: dict[str, str]) -> None:
    """Refuse an interface a policy cannot go on."""
    interface = ident.get("interface", "").strip()
    if interface and interface not in page.interfaces:
        known = ", ".join(page.interfaces) or "none"
        raise ValueError(
            f"{interface} is not a VLAN interface (up to Vlan254), routed port or routed "
            f"port-channel on the switch; those are: {known}"
        )


def build_pbr_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Policy-based routing page."""
    return build_change(PBR, scope, setting, action, ident, values)
