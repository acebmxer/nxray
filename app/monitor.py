"""Port mirroring: SPAN and ERSPAN monitor sessions.

A monitor session copies the traffic of some ports or VLANs (the sources) somewhere
else: to another port of the switch (SPAN) or, wrapped in GRE, to an address elsewhere
on the network (ERSPAN source). The Monitor sessions page is described with the same
parts as the routing protocol pages (``app/protocols.py``): scopes (a local session, an
ERSPAN source session, a destination port, the ERSPAN source address), each setting the
one configuration line it sends with checked values in its blanks, and ``build_change``
building the lines. ``NxapiClient.configure_monitor`` sends them.

Read from the switch: ``show interface brief`` (the ports), ``show feature`` (sFlow) and
``show monitor session all``, which NX-API answers in full as JSON; with no session it
answers with a note, not a table. The ERSPAN source address is not in that answer until
a session uses it, so it is read from ``show running-config monitor`` (text).

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-10) with throwaway sessions, all removed
afterwards: every line the page sends, and the JSON of ``show monitor session all``.
What the switch showed and the page works around:

* sessions are numbered 1 to 32;
* an ERSPAN session must be entered as ``monitor session N type erspan-source`` every
  time: entered plainly it is a local session and the lines inside are refused;
* while sFlow is on, the switch refuses ``tx`` and ``both`` on an interface source
  ("SFLOW and Egress SPAN at the same time"); ``rx`` works;
* a description is at most 32 characters;
* ``header-type`` was refused, so the page does not offer it;
* an ERSPAN destination session is refused while the nve (nv overlay) feature is on
  ("ERSPAN destination configuration is not allowed"), and nve was on, so those lines were
  not tried; they are written from Cisco's NX-OS 9.3 guide;
* a session did not leave "Session admin shut" on the test ports (the destination had
  no transceiver and the sources were down), so the page shows the state and reason the
  switch reports and cannot promise a session comes up.
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
    port_field,
    table_rows,
)
from app.spanning_tree import switch_port_names
from app.switch import text

SESSION_MAX = 32
PAGE_COMMANDS = ("show interface brief", "show feature")
SESSIONS_COMMAND = "show monitor session all"
CONFIG_COMMAND = "show running-config monitor"
DIRECTIONS = ("rx", "tx", "both")
TYPE_LOCAL = "local"
TYPE_ERSPAN = "erspan-source"
TYPE_ERSPAN_DST = "erspan-destination"

_ORIGIN = re.compile(r"monitor erspan origin ip-address (\S+) global")


def _session_field() -> Field:
    return Field(
        "session",
        "Session",
        "int",
        minimum=1,
        maximum=SESSION_MAX,
        hint=f"1 to {SESSION_MAX}",
    )


def _direction_field() -> Field:
    return Field(
        "direction",
        "Direction",
        "choice",
        choices=DIRECTIONS,
        hint="rx: traffic coming in; tx: going out; both. While sFlow is on the switch "
        "takes only rx on a port",
    )


def _settings(erspan: bool) -> tuple[Setting, ...]:
    """The settings of a session; ``erspan`` swaps the destination port for the ERSPAN
    destination address and adds its tunnel settings."""
    settings = [
        Setting(
            key="description",
            label="Description",
            line="description {text}",
            no_line="no description",
            group="Session",
            fields=(Field("text", "Description", "text", maximum=32, hint="Up to 32 characters"),),
            help="A name for what this session is for.",
        ),
        Setting(
            key="source_interface",
            label="Source port",
            line="source interface {port} {direction}",
            no_line="no source interface {port}",
            group="Sources",
            fields=(port_field(), _direction_field()),
            help="A port or port-channel whose traffic is copied. Set it again for another port.",
        ),
        Setting(
            key="source_vlan",
            label="Source VLANs",
            line="source vlan {vlans} {direction}",
            no_line="no source vlan {vlans}",
            group="Sources",
            fields=(
                Field(
                    "vlans",
                    "VLANs",
                    "vlans",
                    hint="VLAN numbers and ranges, such as 10,20-30",
                    placeholder="10,20-30",
                ),
                _direction_field(),
            ),
            help="Every port's traffic in these VLANs is copied.",
        ),
        Setting(
            key="filter_vlan",
            label="Only these VLANs",
            line="filter vlan {vlans}",
            no_line="no filter vlan {vlans}",
            group="Sources",
            fields=(
                Field(
                    "vlans",
                    "VLANs",
                    "vlans",
                    hint="VLAN numbers and ranges, such as 10,20-30",
                    placeholder="10,20-30",
                ),
            ),
            help="Copy only traffic of these VLANs from the source ports.",
        ),
    ]
    if erspan:
        settings += [
            Setting(
                key="destination_ip",
                label="Destination address",
                line="destination ip {address}",
                no_line="no destination ip {address}",
                group="Tunnel",
                fields=(Field("address", "Address", "ipv4", placeholder="192.0.2.50"),),
                help="Where the copied traffic is sent: the analyzer's IPv4 address.",
            ),
            Setting(
                key="erspan_id",
                label="ERSPAN ID",
                line="erspan-id {id}",
                no_line="no erspan-id",
                group="Tunnel",
                fields=(Field("id", "ID", "int", minimum=1, maximum=1023, hint="1 to 1023"),),
                help="Tells the analyzer which session a packet belongs to.",
            ),
            Setting(
                key="vrf",
                label="VRF",
                line="vrf {vrf_name}",
                no_line="no vrf {vrf_name}",
                group="Tunnel",
                fields=(
                    Field(
                        "vrf_name",
                        "VRF",
                        "name",
                        hint="default, or a VRF made on the Routing page",
                        placeholder="default",
                    ),
                ),
                help="The VRF the destination address is reached in.",
            ),
            Setting(
                key="ttl",
                label="Time to live",
                line="ip ttl {ttl}",
                no_line="no ip ttl",
                group="Tunnel",
                fields=(Field("ttl", "TTL", "int", minimum=1, maximum=255, hint="1 to 255"),),
                help="How many routers the copied traffic may pass.",
            ),
            Setting(
                key="dscp",
                label="DSCP",
                line="ip dscp {dscp}",
                no_line="no ip dscp",
                group="Tunnel",
                fields=(Field("dscp", "DSCP", "int", minimum=0, maximum=63, hint="0 to 63"),),
                help="The priority mark on the copied traffic.",
            ),
        ]
    else:
        settings.append(
            Setting(
                key="destination_interface",
                label="Destination port",
                line="destination interface {port}",
                no_line="no destination interface {port}",
                group="Destination",
                fields=(port_field(),),
                help="The port the copied traffic leaves by: where the analyzer is plugged "
                "in. Turn on Monitor destination below for that port first.",
            )
        )
    settings += [
        Setting(
            key="mtu",
            label="Largest packet copied",
            line="mtu {mtu}",
            no_line="no mtu",
            group="Session",
            fields=(Field("mtu", "Bytes", "int", minimum=64, maximum=1500, hint="64 to 1500"),),
            help="Longer packets are cut to this size.",
        ),
        Setting(
            key="admin_up",
            label="Turn on",
            line="no shut",
            group="State",
            removable=False,
            help="Start copying traffic.",
        ),
        Setting(
            key="admin_down",
            label="Turn off",
            line="shut",
            group="State",
            removable=False,
            help="Stop copying traffic. The session stays configured.",
        ),
    ]
    return tuple(settings)


_SPAN = Scope(
    key="span",
    label="Local session (SPAN)",
    ident=(_session_field(),),
    enter=("monitor session {session}",),
    create=True,
    create_label="Make a local session",
    delete=("no monitor session {session}",),
    delete_warning="The session stops copying traffic and is removed.",
    help="Copies traffic from ports or VLANs to another port of this switch.",
    settings=_settings(erspan=False),
)

_ERSPAN = Scope(
    key="erspan",
    label="ERSPAN source session",
    ident=(_session_field(),),
    enter=("monitor session {session} type erspan-source",),
    create=True,
    create_label="Make an ERSPAN source session",
    delete=("no monitor session {session}",),
    delete_warning="The session stops copying traffic and is removed.",
    help="Copies traffic from ports or VLANs to an analyzer elsewhere on the network, "
    "over GRE. Set the ERSPAN source address below first.",
    settings=_settings(erspan=True),
)

_ERSPAN_DST = Scope(
    key="erspan_dst",
    label="ERSPAN destination session",
    ident=(_session_field(),),
    enter=("monitor session {session} type erspan-destination",),
    create=True,
    create_label="Make an ERSPAN destination session",
    delete=("no monitor session {session}",),
    delete_warning="The session stops receiving traffic and is removed.",
    help=(
        "Receives ERSPAN traffic from another switch and sends it out of a port of this one. "
        "The switch refuses it while the nve feature (VXLAN) is on."
    ),
    settings=(
        Setting(
            key="description",
            label="Description",
            line="description {text}",
            no_line="no description",
            group="Session",
            fields=(Field("text", "Description", "text", maximum=32, hint="Up to 32 characters"),),
            help="A name for what this session is for.",
        ),
        Setting(
            key="source_ip",
            label="Source address",
            line="source ip {address}",
            no_line="no source ip {address}",
            group="Tunnel",
            fields=(Field("address", "Address", "ipv4", placeholder="192.0.2.1"),),
            help="The address the other switch sends the copied traffic from.",
        ),
        Setting(
            key="erspan_id",
            label="ERSPAN ID",
            line="erspan-id {id}",
            no_line="no erspan-id",
            group="Tunnel",
            fields=(Field("id", "ID", "int", minimum=1, maximum=1023, hint="1 to 1023"),),
            help="Only traffic with this ID is taken.",
        ),
        Setting(
            key="vrf",
            label="VRF",
            line="vrf {vrf_name}",
            no_line="no vrf {vrf_name}",
            group="Tunnel",
            fields=(
                Field(
                    "vrf_name",
                    "VRF",
                    "name",
                    hint="default, or a VRF made on the Routing page",
                    placeholder="default",
                ),
            ),
            help="The VRF the copied traffic arrives in.",
        ),
        Setting(
            key="destination_interface",
            label="Destination port",
            line="destination interface {port}",
            no_line="no destination interface {port}",
            group="Destination",
            fields=(port_field(),),
            help="The port the received traffic leaves by. Turn on Monitor destination below "
            "for that port first.",
        ),
        Setting(
            key="admin_up",
            label="Turn on",
            line="no shut",
            group="State",
            removable=False,
            help="Start receiving traffic.",
        ),
        Setting(
            key="admin_down",
            label="Turn off",
            line="shut",
            group="State",
            removable=False,
            help="Stop receiving traffic. The session stays configured.",
        ),
    ),
)

_PORT = Scope(
    key="dest_port",
    label="Monitor destination port",
    ident=(port_field(),),
    enter=("interface {port}",),
    help="A port must be marked as a monitor destination before a local session can send "
    "traffic to it. It stops being a normal port: it carries only the copies.",
    settings=(
        Setting(
            key="monitor",
            label="Monitor destination",
            line="switchport monitor",
            group="Settings",
            help="Use this port only as a destination for monitor sessions.",
            warning="The port stops forwarding normal traffic. Pick one with nothing else on it.",
        ),
    ),
)

_ORIGIN_SCOPE = Scope(
    key="origin",
    label="ERSPAN source address",
    ident=(),
    enter=(),
    help="The address the switch sends ERSPAN traffic from. One for the whole switch.",
    settings=(
        Setting(
            key="origin",
            label="Source address",
            line="monitor erspan origin ip-address {address} global",
            no_line="no monitor erspan origin ip-address {address} global",
            fields=(Field("address", "Address", "ipv4", placeholder="192.0.2.1"),),
            help="An IPv4 address of this switch, such as a loopback's.",
        ),
    ),
)


# ---- reading `show monitor session all` ---------------------------------------------------


def _first(row: dict[str, Any], *keys: str) -> str:
    """The first of ``keys`` the row has, as text ('' for none)."""
    for key in keys:
        if value := text(row.get(key)):
            return value
    return ""


def _sources(row: dict[str, Any]) -> list[str]:
    """The interface sources of a session as 'Ethernet1/54 (rx)'."""
    found = []
    for direction in DIRECTIONS:
        for source in table_rows(row, f"TABLE_sources_{direction}", f"ROW_sources_{direction}"):
            if name := text(source.get(f"sources_{direction}")):
                found.append(f"{name} ({direction})")
    return found


def _vlan_sources(row: dict[str, Any]) -> list[str]:
    return [
        f"{value} ({direction})"
        for direction in DIRECTIONS
        if (value := _first(row, f"source_vlans_{direction}"))
    ]


def _state(row: dict[str, Any]) -> str:
    state = _first(row, "state")
    reason = _first(row, "state_reason")
    return f"{state} ({reason})" if state and reason else state or "-"


def parse_origin(config: str) -> str:
    """The ERSPAN source address in ``show running-config monitor`` text ('' for none)."""
    for line in config.splitlines():
        if match := _ORIGIN.fullmatch(line.strip()):
            return match.group(1)
    return ""


def _values(row: dict[str, Any], kind: str) -> dict[str, dict[str, str]]:
    """The settings the session has, as field values, for the "set" marks."""
    values: dict[str, dict[str, str]] = {}
    if description := _first(row, "description"):
        values["description"] = {"text": description}
    if mtu := _first(row, "span_mtu"):
        values["mtu"] = {"mtu": mtu}
    if kind in (TYPE_ERSPAN, TYPE_ERSPAN_DST):
        for key, names, field in (
            ("destination_ip", ("dst_ip",), "address"),
            ("erspan_id", ("flow_id",), "id"),
            ("vrf", ("vrf_name",), "vrf_name"),
            ("ttl", ("erspan_ttl",), "ttl"),
            ("dscp", ("erspan_dscp",), "dscp"),
        ):
            if value := _first(row, *names):
                values[key] = {field: value}
    if kind == TYPE_ERSPAN_DST and (source := _first(row, "src_ip", "source_ip")):
        values["source_ip"] = {"address": source}
    return values


def parse_monitor(bodies: list[dict[str, Any]], origin: str = "") -> ProtocolView:
    """The sessions from ``show monitor session all`` (the one body) and the ERSPAN
    source address (``origin``, from the configuration text)."""
    rows = table_rows(bodies[0] if bodies else {}, "TABLE_session", "ROW_session")
    instances: list[Instance] = []
    table_lines: list[tuple[str, ...]] = []
    for row in rows:
        number = _first(row, "session_number")
        kind = _first(row, "type") or TYPE_LOCAL
        sources = [*_sources(row), *(f"VLAN {v}" for v in _vlan_sources(row))]
        destination = _first(row, "destinations") or _first(row, "dst_ip") or "-"
        table_lines.append((number, kind, _state(row), "; ".join(sources) or "-", destination))
        if kind not in (TYPE_LOCAL, TYPE_ERSPAN, TYPE_ERSPAN_DST) or not number.isdigit():
            continue  # a session type NXray has no form for: shown in the table only
        facts = [("Type", kind), ("State", _state(row))]
        if sources:
            facts.append(("Source ports", "; ".join(_sources(row)) or "none"))
        if vlans := _vlan_sources(row):
            facts.append(("Source VLANs", "; ".join(vlans)))
        if filtered := _first(row, "filter_vlans"):
            facts.append(("Only VLANs", filtered))
        if kind in (TYPE_LOCAL, TYPE_ERSPAN_DST):
            facts.append(("Destination port", _first(row, "destinations") or "none"))
            if kind == TYPE_ERSPAN_DST:
                if source := _first(row, "src_ip", "source_ip"):
                    facts.append(("Source address", source))
                if flow := _first(row, "flow_id"):
                    facts.append(("ERSPAN ID", flow))
        else:
            facts.append(("Destination address", _first(row, "dst_ip") or "none"))
            if flow := _first(row, "flow_id"):
                facts.append(("ERSPAN ID", flow))
            if vrf := _first(row, "vrf_name"):
                facts.append(("VRF", vrf))
        instances.append(
            Instance(
                {TYPE_ERSPAN: "erspan", TYPE_ERSPAN_DST: "erspan_dst"}.get(kind, "span"),
                {"session": number},
                f"Session {number}",
                tuple(facts),
                _values(row, kind),
            )
        )
    if origin:
        instances.append(
            Instance(
                "origin",
                {},
                "ERSPAN source address",
                (("Address", origin),),
                {"origin": {"address": origin}},
            )
        )
    tables = (
        Table(
            "Sessions",
            ("Session", "Type", "State", "Sources", "Destination"),
            tuple(table_lines),
            empty="No monitor sessions. Make one below.",
        ),
    )
    return ProtocolView(tuple(instances), tables)


MONITOR = Protocol(
    key="monitor",
    name="Monitor sessions",
    summary="Copy the traffic of ports or VLANs to a port or an analyzer (SPAN and ERSPAN)",
    features=(),
    commands=(SESSIONS_COMMAND,),
    parse=parse_monitor,
    scopes=(_SPAN, _ERSPAN, _ERSPAN_DST, _PORT, _ORIGIN_SCOPE),
    about=(
        "For a local session: mark the destination port, make the session, add its "
        "sources and its destination port, then turn it on. For ERSPAN: set the source "
        "address, make the session, add its sources, destination address and ERSPAN ID, "
        "then turn it on."
    ),
)


# ---- the page -----------------------------------------------------------------------------


@dataclass(frozen=True)
class MonitorPage:
    """Everything the Monitor sessions page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # the front ports and port-channels
    vlans: tuple[str, ...] = ()  # kept for the template; the VLAN lists are typed
    problem: str = ""
    missing: tuple[str, ...] = ()  # monitor sessions need no feature; kept for the template


def all_port_names(brief: dict[str, Any]) -> tuple[str, ...]:
    """Every front port and port-channel in ``show interface brief``: a routed port can be
    a source too, so the spanning tree page's switched-only list is not used as it is."""
    switched = switch_port_names(brief)
    routed = []
    for row in table_rows(brief, "TABLE_interface", "ROW_interface"):
        if text(row.get("portmode")).lower() == "routed":
            name = text(row.get("interface"))
            if re.fullmatch(r"Ethernet\d+/\d+", name):
                routed.append(name)
    return tuple(dict.fromkeys([*switched, *routed]))


def load_monitor_page(client: NxapiClient) -> MonitorPage:
    """One request for the ports and features, one for the sessions and one for the
    configuration text (the ERSPAN source address)."""
    brief, feature = client.show(*PAGE_COMMANDS)
    problem = ""
    try:
        (sessions,) = client.show(SESSIONS_COMMAND)
    except NxapiCommandError as exc:
        # With no session the switch prints a note, which NX-API cannot turn into JSON
        # ("CLI output cannot be parsed by the server", seen on cisco-25gb 2026-11-10).
        sessions = {}
        message = str(exc).lower()
        if "no sessions" not in message and "cannot be parsed" not in message:
            problem = f"The switch did not report its monitor sessions: {exc}"
    try:
        origin = parse_origin(client.show_text(CONFIG_COMMAND))
    except NxapiCommandError:
        origin = ""
    view = parse_monitor([sessions], origin)
    if feature_states(feature).get("sflow", False):
        view = ProtocolView(
            view.instances,
            view.tables,
            (
                "sFlow is on, so the switch takes only rx on a source port: tx and both are "
                "refused.",
                *view.notes,
            ),
        )
    return MonitorPage(MONITOR, view, all_port_names(brief), problem=problem)


def build_monitor_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Monitor sessions page."""
    return build_change(MONITOR, scope, setting, action, ident, values)
