"""Tracked objects: numbered objects that are up or down after something on the switch (an
interface, a route, an IP SLA entry, or a list of other objects), for HSRP, VRRP and EEM to
follow (``track <n> decrement``, ``event track``).

An **interface object** follows an interface's link (``line-protocol``) or whether it routes
IPv4 or IPv6. A **route object** is up while the routing table has a route, in the default
VRF or another. An **IP SLA object** follows an IP SLA entry's last result (``state``: it
succeeded within its threshold; ``reachability``: the target answered). A **list** combines
other objects: all of them up (``boolean and``), any of them (``boolean or``), or enough of
them by weight or by percentage, with an up and a down threshold. Any object can wait a
while before it changes state (``delay``).

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): a scope per kind of object, each setting the one line it sends with
checked values in its blanks, and ``build_change`` building the lines.
``NxapiClient.configure_track`` sends them. Tracked objects need no feature.

Read from the switch: ``show interface brief`` and ``show vrf`` in one request, ``show
track`` (each object's state, changes and the lists that use it), and ``show
running-config`` as text (the role's ``show running-config`` rule), where the objects are
read as set.

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-12) with throwaway objects 250 to 512, a VLAN
interface and a loopback, all removed afterwards. What the switch showed and the page
follows:

* objects are numbered 1 to 512;
* ``track <n> interface <interface> line-protocol|ip routing|ipv6 routing``, ``track <n>
  ip|ipv6 route <prefix> reachability``, ``track <n> ip sla <1-2147483647>
  [state|reachability]`` (``state`` is the default and not written in the configuration),
  ``track <n> list boolean and|or``, ``track <n> list threshold weight|percentage``;
* typing an object's line again enters it, so the page enters an object by its own line;
  an object cannot change kind ("Cannot modify already existing object"), except that
  ``list boolean or`` turns an AND list into an OR list;
* in a list: ``object <n>`` (with ``not`` in a boolean list, ``weight <1-255>`` in a weight
  list, 10 when not given), ``no object <n>``; a list cannot hold itself; ``threshold weight
  [up <0-255>] [down <0-255>]`` and ``threshold percentage [up <0-100>] [down <0-100>]``,
  up above down, ``no threshold weight|percentage``;
* ``delay [up <0-180>] [down <0-180>]`` (given separately they add up), ``no delay``;
* ``vrf member <vrf>`` only on route objects ("Object is not an ip route object"), ``no vrf
  member <vrf>``;
* an object a list uses cannot be deleted ("Object is currently tracked, cannot remove"),
  and an object stays when its interface is deleted.

``show track`` gives TABLE_track_detail/ROW_track_detail {st_obj_id, st_obj_type
(interface, route, v6route, sla, Booleanand, Booleanor, thresholdweight,
thresholdpercentage), st_obj_instance, st_obj_param, st_obj_state, st_obj_chg_cnt,
st_last_chg_time, st_vrf, st_track_list_info (the lists using it), st_track_list_obj (a
list's members with their state), st_threshold_info, st_obj_up_delay, st_obj_down_delay}.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from app.loopbacks import parse_loopbacks
from app.monitor import all_port_names
from app.nxapi import DEFAULT_VRF, NxapiClient, NxapiCommandError
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
from app.routing import parse_brief
from app.switch import text
from app.switch_admin import vrf_choices
from app.vxlan import parse_vxlan_config

PAGE_COMMANDS = ("show interface brief", "show vrf")
COMMANDS = ("show track",)
CONFIG_COMMAND = "show running-config"
# Tracked objects are numbered 1 to 512 (checked on the switch); HSRP, VRRP and EEM name
# them by these numbers.
TRACK_MAX = 512
DELAY_MAX = 180
# The hint of a field elsewhere (HSRP, VRRP, EEM) that names an object by its number.
TRACK_HINT = "Made on the Tracked objects page"
SLA_MAX = 2147483647


def _number() -> Field:
    return Field(
        "number",
        "Object number",
        "int",
        minimum=1,
        maximum=TRACK_MAX,
        hint=f"1 to {TRACK_MAX}: the number HSRP, VRRP and EEM name",
        placeholder="10",
    )


def _check_delay(values: dict[str, str]) -> None:
    if not values["up"] and not values["down"]:
        raise ValueError("give the wait going up, going down, or both")


_DELAY = Setting(
    key="delay",
    label="Wait before changing state",
    line="delay[ up {up}][ down {down}]",
    no_line="no delay",
    fields=(
        Field(
            "up",
            "Going up",
            "int",
            minimum=0,
            maximum=DELAY_MAX,
            optional=True,
            hint=f"Seconds, 0 to {DELAY_MAX}",
            placeholder="10",
        ),
        Field(
            "down",
            "Going down",
            "int",
            minimum=0,
            maximum=DELAY_MAX,
            optional=True,
            hint=f"Seconds, 0 to {DELAY_MAX}",
            placeholder="10",
        ),
    ),
    check=_check_delay,
    group="Timing",
    help="The object waits this long before it says it changed, so a short flap changes "
    "nothing. Setting one keeps the other.",
)

_DELETE_WARNING = (
    "HSRP, VRRP or an EEM applet that follows this object has nothing left to follow. The "
    "switch refuses to delete an object a list still uses: take it out of the list first."
)


def _member(weight: bool = False, negate: bool = False) -> Setting:
    fields = [
        Field(
            "object",
            "Object",
            "int",
            minimum=1,
            maximum=TRACK_MAX,
            hint="Another tracked object's number",
            placeholder="1",
        )
    ]
    line = "object {object}"
    if weight:
        fields.append(
            Field(
                "weight",
                "Weight",
                "int",
                minimum=1,
                maximum=255,
                optional=True,
                hint="1 to 255; 10 if empty",
                placeholder="10",
            )
        )
        line += "[ weight {weight}]"
    if negate:
        fields.append(Field("negate", "Count it as up while it is down", "flag", choices=("not",)))
        line += "[ {negate}]"
    return Setting(
        key="object",
        label="Object in the list",
        line=line,
        no_line="no object {object}",
        fields=tuple(fields),
        group="Objects",
        help="Add an object to the list, or change it; Remove takes it out.",
    )


def _threshold(word: str, highest: int) -> Setting:
    def check(values: dict[str, str]) -> None:
        if not values["up"] and not values["down"]:
            raise ValueError("give the up threshold, the down threshold, or both")
        if values["up"] and values["down"] and int(values["up"]) <= int(values["down"]):
            raise ValueError("the up threshold must be above the down threshold")

    unit = "a total weight" if word == "weight" else "a percentage"
    return Setting(
        key="threshold",
        label="Thresholds",
        line=f"threshold {word}[ up {{up}}][ down {{down}}]",
        no_line=f"no threshold {word}",
        fields=(
            Field(
                "up",
                "Up at",
                "int",
                minimum=0,
                maximum=highest,
                optional=True,
                hint=f"{unit} from 0 to {highest}",
            ),
            Field(
                "down",
                "Down at",
                "int",
                minimum=0,
                maximum=highest,
                optional=True,
                hint=f"{unit} from 0 to {highest}, below up",
            ),
        ),
        check=check,
        group="Thresholds",
        help="The list goes up once its up objects reach the up threshold, and down once they "
        "fall to the down threshold.",
    )


_INTERFACE = Scope(
    key="interface",
    label="Interface object",
    ident=(
        _number(),
        Field(
            "interface",
            "Interface",
            "ifname",
            hint="Any port, port-channel, VLAN interface or loopback: tracking only reads it",
        ),
        Field(
            "what",
            "Up while",
            "choice",
            choices=("line-protocol", "ip routing", "ipv6 routing"),
            hint="line-protocol: its link is up; ip routing or ipv6 routing: it is up and routes",
        ),
    ),
    enter=("track {number} interface {interface} {what}",),
    create=True,
    create_label="Track an interface",
    delete=("no track {number}",),
    delete_warning=_DELETE_WARNING,
    help="Up while an interface is up, or while it routes IPv4 or IPv6.",
    settings=(_DELAY,),
)

_ROUTE = Scope(
    key="route",
    label="Route object",
    ident=(
        _number(),
        Field("family", "Family", "choice", choices=("ip", "ipv6"), hint="ip: IPv4"),
        Field(
            "prefix", "Route", "prefix", hint="A network with its length", placeholder="0.0.0.0/0"
        ),
    ),
    enter=("track {number} {family} route {prefix} reachability",),
    create=True,
    create_label="Track a route",
    delete=("no track {number}",),
    delete_warning=_DELETE_WARNING,
    help="Up while the routing table has the route: in the default VRF, or the VRF set here.",
    settings=(
        Setting(
            key="vrf",
            label="VRF",
            line="vrf member {vrf}",
            fields=(Field("vrf", "VRF", "vrf", hint="The VRF whose routing table is looked at"),),
            group="Where",
            help="Look for the route in this VRF; Remove goes back to the default VRF.",
        ),
        _DELAY,
    ),
)

_SLA = Scope(
    key="sla",
    label="IP SLA object",
    ident=(
        _number(),
        Field(
            "entry",
            "IP SLA entry",
            "int",
            minimum=1,
            maximum=SLA_MAX,
            hint="An entry made on the IP SLA page",
            placeholder="1",
        ),
        Field(
            "what",
            "Up while",
            "choice",
            choices=("state", "reachability"),
            hint="state: its last measurement succeeded within its threshold; reachability: "
            "the target answered, even too slowly",
        ),
    ),
    enter=("track {number} ip sla {entry} {what}",),
    create=True,
    create_label="Track an IP SLA entry",
    delete=("no track {number}",),
    delete_warning=_DELETE_WARNING,
    help="Up while an IP SLA entry's measurements succeed.",
    settings=(_DELAY,),
)

_BOOLEAN = Scope(
    key="boolean",
    label="List: all or any",
    ident=(
        _number(),
        Field(
            "kind",
            "Up while",
            "choice",
            choices=("and", "or"),
            hint="and: every object in it is up; or: any one is. Making an AND list again as "
            "or turns it into an OR list",
        ),
    ),
    enter=("track {number} list boolean {kind}",),
    create=True,
    create_label="Make an all-or-any list",
    delete=("no track {number}",),
    delete_warning=_DELETE_WARNING,
    help="Combines other objects: up while all of them are up, or while any one is.",
    settings=(_member(negate=True), _DELAY),
)

_WEIGHT = Scope(
    key="weight",
    label="List: by weight",
    ident=(_number(),),
    enter=("track {number} list threshold weight",),
    create=True,
    create_label="Make a list by weight",
    delete=("no track {number}",),
    delete_warning=_DELETE_WARNING,
    help="Each object in it has a weight: the list is up while the up objects' weights add up "
    "to enough.",
    settings=(_member(weight=True), _threshold("weight", 255), _DELAY),
)

_PERCENTAGE = Scope(
    key="percentage",
    label="List: by percentage",
    ident=(_number(),),
    enter=("track {number} list threshold percentage",),
    create=True,
    create_label="Make a list by percentage",
    delete=("no track {number}",),
    delete_warning=_DELETE_WARNING,
    help="Up while enough of its objects, as a percentage, are up.",
    settings=(_member(), _threshold("percentage", 100), _DELAY),
)

SCOPES = (_INTERFACE, _ROUTE, _SLA, _BOOLEAN, _WEIGHT, _PERCENTAGE)


# ---- reading -----------------------------------------------------------------------------

_KIND_WORDS = {
    "interface": "Interface",
    "route": "IPv4 route",
    "v6route": "IPv6 route",
    "sla": "IP SLA",
    "booleanand": "List: all up",
    "booleanor": "List: any up",
    "thresholdweight": "List: by weight",
    "thresholdpercentage": "List: by percentage",
}
_PARAM_WORDS = {
    "line-protocol": "line-protocol",
    "ip-routing": "ip routing",
    "ipv6-routing": "ipv6 routing",
}


def _lines(value: Any) -> tuple[str, ...]:
    """A field the switch gives as one string or a list of them, each with its spaces
    tidied."""
    items = value if isinstance(value, list) else [value]
    return tuple(" ".join(text(item).split()) for item in items if text(item))


@dataclass(frozen=True)
class TrackState:
    """One object as ``show track`` reports it."""

    number: str
    kind: str  # in words: "Interface", "List: all up"
    follows: str  # "loopback0 line-protocol", "0.0.0.0/0", "entry 5"; "" for a list
    state: str  # UP or DOWN
    changes: str
    last_change: str
    vrf: str
    used_by: tuple[str, ...]  # "Track List 258"
    members: tuple[str, ...]  # a list's objects with their state: "object 250 UP"
    threshold: str
    delay_up: str
    delay_down: str


def parse_track_state(body: Any) -> list[TrackState]:
    """``show track``: every object, in number order."""
    found = []
    for row in table_rows(body or {}, "TABLE_track_detail", "ROW_track_detail"):
        number = text(row.get("st_obj_id"))
        if not number:
            continue
        kind = text(row.get("st_obj_type")).lower()
        instance = text(row.get("st_obj_instance"))
        if kind == "interface":
            param = text(row.get("st_obj_param")).lower()
            follows = f"{instance} {_PARAM_WORDS.get(param, param)}".strip()
        elif kind == "sla":
            follows = f"entry {instance}" if instance else ""
        else:
            follows = instance
        found.append(
            TrackState(
                number=number,
                kind=_KIND_WORDS.get(kind, text(row.get("st_obj_type"))),
                follows=follows,
                state=text(row.get("st_obj_state")),
                changes=text(row.get("st_obj_chg_cnt")),
                last_change=text(row.get("st_last_chg_time")),
                vrf=text(row.get("st_vrf")),
                used_by=_lines(row.get("st_track_list_info")),
                members=_lines(row.get("st_track_list_obj")),
                threshold=" ".join(text(row.get("st_threshold_info")).split()),
                delay_up=text(row.get("st_obj_up_delay")),
                delay_down=text(row.get("st_obj_down_delay")),
            )
        )
    return sorted(found, key=lambda s: int(s.number) if s.number.isdigit() else 0)


@dataclass(frozen=True)
class TrackConfig:
    """One ``track`` block of the running configuration."""

    scope: str
    ident: dict[str, str]
    follows: str
    lines: tuple[str, ...]  # the lines inside it


_DEFINITIONS = (
    (
        "interface",
        re.compile(r"track (\d+) interface (\S+) (line-protocol|ip routing|ipv6 routing)"),
    ),
    ("route", re.compile(r"track (\d+) (ip|ipv6) route (\S+) reachability")),
    ("sla", re.compile(r"track (\d+) ip sla (\d+)(?: (state|reachability))?")),
    ("boolean", re.compile(r"track (\d+) list boolean (and|or)")),
    ("weight", re.compile(r"track (\d+) list threshold weight")),
    ("percentage", re.compile(r"track (\d+) list threshold percentage")),
)


def _definition(line: str) -> tuple[str, dict[str, str], str] | None:
    """(scope, identity values, what it follows in words) of a ``track`` line."""
    for scope, pattern in _DEFINITIONS:
        match = pattern.fullmatch(line)
        if not match:
            continue
        groups = match.groups()
        if scope == "interface":
            return (
                scope,
                dict(zip(("number", "interface", "what"), groups, strict=True)),
                (f"{groups[1]} {groups[2]}"),
            )
        if scope == "route":
            return scope, dict(zip(("number", "family", "prefix"), groups, strict=True)), groups[2]
        if scope == "sla":
            what = groups[2] or "state"
            return (
                scope,
                {"number": groups[0], "entry": groups[1], "what": what},
                (f"IP SLA entry {groups[1]} {what}"),
            )
        if scope == "boolean":
            return scope, {"number": groups[0], "kind": groups[1]}, f"boolean {groups[1]}"
        return scope, {"number": groups[0]}, f"threshold {scope}"
    return None


def parse_track_config(config: str) -> list[TrackConfig]:
    """The ``track`` blocks of ``show running-config``."""
    tree = parse_vxlan_config(config)
    found = []
    for line in tree.children():
        if not line.startswith("track "):
            continue
        definition = _definition(line)
        if definition is None:
            continue
        scope, ident, follows = definition
        found.append(TrackConfig(scope, ident, follows, tuple(tree.children(line))))
    return found


def _values(lines: tuple[str, ...]) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    for line in lines:
        if match := re.fullmatch(r"delay(?: up (\d+))?(?: down (\d+))?", line):
            up, down = match.groups()
            if up or down:
                values["delay"] = {"up": up or "", "down": down or ""}
        elif match := re.fullmatch(r"vrf member (\S+)", line):
            values["vrf"] = {"vrf": match.group(1)}
        elif match := re.fullmatch(
            r"threshold (?:weight|percentage)(?: up (\d+))?(?: down (\d+))?", line
        ):
            up, down = match.groups()
            values["threshold"] = {"up": up or "", "down": down or ""}
    return values


def _members(lines: tuple[str, ...]) -> str:
    """A list's ``object`` lines in words: "250, 251 weight 20, 252 not"."""
    shown = [" ".join(line.split()[1:]) for line in lines if line.startswith("object ")]
    return ", ".join(shown)


def _facts(state: TrackState | None, block: TrackConfig) -> tuple[tuple[str, str], ...]:
    facts: list[tuple[str, str]] = []
    if state is not None:
        facts.append(("State", state.state or "-"))
        changes = state.changes or "0"
        facts.append(("Changes", f"{changes}, the last {state.last_change} ago"))
    values = _values(block.lines)
    if "vrf" in values:
        facts.append(("VRF", values["vrf"]["vrf"]))
    elif block.scope == "route":
        facts.append(("VRF", DEFAULT_VRF))
    if "delay" in values:
        delay = values["delay"]
        parts = [
            f"{word} {delay[key]} s" for key, word in (("up", "up"), ("down", "down")) if delay[key]
        ]
        facts.append(("Waits", ", ".join(parts)))
    if block.scope in ("boolean", "weight", "percentage"):
        if state is not None and state.members:
            facts.append(("Objects", "; ".join(state.members)))
        else:
            facts.append(("Objects", _members(block.lines) or "none yet"))
        if state is not None and state.threshold:
            facts.append(("Thresholds", state.threshold))
    if state is not None and state.used_by:
        facts.append(("Used by", ", ".join(state.used_by)))
    return tuple(facts)


def parse_track(body: Any, config: str | None) -> ProtocolView:
    """The page from ``show track`` and the configuration text (None when the switch did
    not show it)."""
    states = parse_track_state(body)
    by_number = {state.number: state for state in states}
    instances = []
    notes: tuple[str, ...] = ()
    if config is None:
        notes = (
            "The switch did not show the tracked objects' settings to NXray's account: only "
            "their state is shown.",
        )
    else:
        for block in parse_track_config(config):
            number = block.ident["number"]
            instances.append(
                Instance(
                    block.scope,
                    block.ident,
                    f"Object {number}: {block.follows}",
                    _facts(by_number.get(number), block),
                    _values(block.lines),
                )
            )
    table = Table(
        "State",
        ("Object", "Kind", "Follows", "State", "Changes", "Last change", "Used by"),
        tuple(
            (
                s.number,
                s.kind,
                s.follows or "-",
                s.state or "-",
                s.changes or "0",
                s.last_change or "-",
                ", ".join(s.used_by) or "-",
            )
            for s in states
        ),
        empty="No tracked objects yet.",
        note="Read when the page loads.",
    )
    return ProtocolView(tuple(instances), (table,), notes)


TRACK = Protocol(
    key="track",
    name="Tracked objects",
    summary="Objects that follow an interface, a route or an IP SLA entry, for HSRP, VRRP and EEM",
    features=(),
    commands=COMMANDS,
    parse=lambda bodies: parse_track(bodies[0] if bodies else None, None),
    scopes=SCOPES,
    about=(
        "Make an object that follows an interface, a route or an IP SLA entry, or a list of "
        "other objects, then name its number on the HSRP or VRRP page (a group's tracked "
        "object) or in an EEM applet."
    ),
)


@dataclass(frozen=True)
class TrackPage:
    """Everything the Tracked objects page shows."""

    protocol: Protocol
    view: ProtocolView
    interfaces: tuple[str, ...]  # every interface the switch has
    vrfs: tuple[str, ...]  # management and the VRFs made on the switch (not default)
    problem: str = ""
    missing: tuple[str, ...] = ()  # always empty: tracking needs no feature


def track_interfaces(brief: Any) -> tuple[str, ...]:
    """Every interface an object can follow: front ports and port-channels, VLAN
    interfaces, loopbacks."""
    svis, _routed = parse_brief(brief or {})
    loopbacks = [f"loopback{lo.number}" for lo in parse_loopbacks([brief])]
    return tuple(dict.fromkeys([*all_port_names(brief or {}), *svis, *loopbacks]))


def load_track_page(client: NxapiClient) -> TrackPage:
    """One request for the interfaces and VRFs, one for ``show track`` and one for the
    configuration text."""
    brief, vrf_body = client.show(*PAGE_COMMANDS)
    interfaces = track_interfaces(brief)
    vrfs = tuple(v for v in vrf_choices(vrf_body) if v != DEFAULT_VRF)
    problem = ""
    try:
        (body,) = client.show(*COMMANDS)
    except NxapiCommandError as exc:
        body, problem = None, f"The switch did not report the tracked objects: {exc}"
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = None
    return TrackPage(TRACK, parse_track(body, config), interfaces, vrfs, problem)


def check_track_place(page: TrackPage, ident: dict[str, str]) -> None:
    """Refuse an interface the switch does not have, unless an object on the page already
    follows it (an object stays when its interface is deleted)."""
    interface = ident.get("interface", "").strip()
    if not interface or interface in page.interfaces:
        return
    for instance in page.view.of("interface"):
        if instance.ident.get("interface") == interface:
            return
    raise ValueError(f"the switch has no interface {interface}")


def build_track_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Tracked objects page; a route object's network must be of
    its family."""
    change = build_change(TRACK, scope, setting, action, ident, values)
    if scope == "route":
        version = ipaddress.ip_network(ident["prefix"].strip(), strict=False).version
        if (version == 4) != (ident["family"].strip() == "ip"):
            raise ValueError("an ip route object follows an IPv4 network, ipv6 an IPv6 one")
    return change
