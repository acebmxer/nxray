"""Tunnel interfaces: GRE and IP-in-IP tunnels to other routers, made, given their source,
destination, mode and addresses, turned off and deleted.

A tunnel interface wraps the IPv4 packets routed into it in another IPv4 header, from the
tunnel's source to its destination, so two routers reach each other's networks across a
network that does not route them (another site over the internet, say). Each end has an
address on the tunnel, and routing (a static route or a routing protocol) sends traffic
into it.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): one scope (a tunnel), each setting the one configuration line it
sends with checked values in its blanks, and ``build_change`` building the lines.
``NxapiClient.configure_tunnels`` sends them.

Read from the switch: ``show feature`` and ``show vrf`` in one request; while ``feature
tunnel`` is on, ``show interface brief`` (each tunnel's state, when the switch lists it)
and ``show running-config`` as text (each ``interface TunnelN`` block with its lines).
Reading the text needs the role's ``show running-config`` rule (rule 170), as the VXLAN
page does; without it the page shows the tunnels the brief lists, with no settings.

Built from Cisco's Nexus 9000 NX-OS Interfaces Configuration Guide, Release 9.3(x),
"Configuring IP Tunnels", and NOT tried on a switch: on cisco-25gb (NX-OS 9.3(16)) the
switch refused ``feature tunnel`` ("feature nv overlay already enabled. Please disable
that"), and the guide says the tunnel feature cannot be on with VXLAN (``feature nv
overlay``). What the page follows from the guide:

* ``feature tunnel`` first; ``interface tunnel N`` makes a tunnel, ``no interface tunnel
  N`` deletes it with its lines. The guide gives no number range; NXray takes 0 to 65535
  and the switch refuses a number it does not take;
* ``tunnel mode gre ip`` (the default), ``tunnel mode ipip ip`` and ``tunnel mode ipip
  decapsulate-any`` (ends IP-in-IP tunnels from any source, sends nothing);
* ``tunnel source`` an address or an interface, ``tunnel destination`` an address,
  ``tunnel use-vrf`` the VRF the destination is looked up in, ``tunnel ttl`` 1 to 255;
* ``tunnel path-mtu-discovery age-timer`` 10 to 30 minutes (default 10) and ``tunnel
  path-mtu-discovery min-mtu`` 64 to 9192 bytes (default 64);
* ``mtu`` 64 to 9192, ``description``, ``vrf member`` (then the address: the guide sets
  the address after the VRF), ``ip address`` (IPv4 only: NX-OS carries IPv4 in tunnels),
  ``shutdown``;
* at most 16 GRE and IP-in-IP tunnels (9.3(3) and later); two tunnels in one VRF may not
  share a source or destination address; no keepalives, ACLs, QoS policies, SPAN or BFD on
  tunnels.

The ``no`` forms of the tunnel lines are not printed in the guide; the page sends ``no``
and the line (``no tunnel source``, ``no tunnel destination`` ...), as for other
interface lines.

Changes need the stored admin login: NXray's broad role lists the interfaces it may change
(``interface policy deny``), and the switch refuses ``permit interface tunnelN`` while
tunnel is off ("Invalid interface format", seen on cisco-25gb), so the role cannot be
written to name them in advance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.features import feature_states
from app.nxapi import DEFAULT_VRF, NxapiClient, NxapiCommandError
from app.protocols import (
    Field,
    Instance,
    Protocol,
    ProtocolChange,
    ProtocolView,
    Scope,
    Setting,
    build_change,
    source_field,
)
from app.switch import rows, text
from app.switch_admin import vrf_choices

FEATURE = "tunnel"
VXLAN_FEATURE = "nve"  # show feature's name for `feature nv overlay`
TUNNEL_MAX = 65535
TUNNEL_LIMIT = 16  # GRE and IP-in-IP tunnels a Nexus 9200 or 9300 takes (9.3(3) and later)
MODES = ("gre ip", "ipip ip", "ipip decapsulate-any")
DEFAULT_MODE = "gre ip"
PAGE_COMMANDS = ("show feature", "show vrf")
COMMANDS = ("show interface brief",)
CONFIG_COMMAND = "show running-config"

VXLAN_ON = (
    "VXLAN (feature nv overlay) is on, and the switch turns on tunnel only while it is off: "
    "the two cannot be on together. Turn VXLAN off first if it is not used."
)

_NAME = re.compile(r"^tunnel\s*(\d+)$", re.IGNORECASE)
_BLOCK = re.compile(r"^interface\s+tunnel\s*(\d+)$", re.IGNORECASE)
_VRF_WARNING = (
    "The switch deletes the tunnel's address when its VRF changes: put it on again afterwards."
)


def _number_field() -> Field:
    return Field(
        "number",
        "Tunnel",
        "int",
        minimum=0,
        maximum=TUNNEL_MAX,
        hint="The number after tunnel: tunnel1",
        placeholder="1",
    )


def _address(name: str, label: str, hint: str, placeholder: str) -> Field:
    return Field(name, label, "ipv4", hint=hint, placeholder=placeholder)


_TUNNEL = Scope(
    key="tunnel",
    label="Tunnel",
    ident=(_number_field(),),
    enter=("interface tunnel {number}",),
    create=True,
    create_label="Make a tunnel",
    delete=("no interface tunnel {number}",),
    delete_warning=(
        "Its source, destination and address go with it, and traffic routed into it stops."
    ),
    help=(
        "A tunnel to another router: give it a source, a destination and an address, then "
        "route traffic into it. The router at the other end needs the same tunnel the other "
        "way round."
    ),
    settings=(
        Setting(
            key="mode",
            label="Mode",
            line="tunnel mode {mode}",
            no_line="no tunnel mode",
            group="Tunnel",
            fields=(
                Field(
                    "mode",
                    "Mode",
                    "choice",
                    choices=MODES,
                    hint="gre ip: GRE over IPv4 (the default). ipip ip: IP-in-IP. ipip "
                    "decapsulate-any: only receives, ending IP-in-IP tunnels from any source",
                ),
            ),
            help="How packets are wrapped; both ends use the same mode.",
            warning="The tunnel stops carrying traffic until the other end uses the same mode.",
        ),
        Setting(
            key="source_interface",
            label="Source interface",
            line="tunnel source {source}",
            no_line="no tunnel source",
            group="Tunnel",
            fields=(source_field(),),
            help="The interface whose address the tunnel's packets come from (a loopback is "
            "usual). Replaces a source address.",
        ),
        Setting(
            key="source_address",
            label="Source address",
            line="tunnel source {address}",
            no_line="no tunnel source",
            group="Tunnel",
            fields=(
                _address(
                    "address",
                    "Address",
                    "An address this switch has; the other end's destination",
                    "192.0.2.1",
                ),
            ),
            help="The address the tunnel's packets come from. Replaces a source interface.",
        ),
        Setting(
            key="destination",
            label="Destination",
            line="tunnel destination {address}",
            no_line="no tunnel destination",
            group="Tunnel",
            fields=(
                _address(
                    "address",
                    "Address",
                    "The other end's source address",
                    "198.51.100.1",
                ),
            ),
            help="Where the tunnel's packets go. Two tunnels in one VRF may not share a "
            "destination.",
        ),
        Setting(
            key="use_vrf",
            label="Transport VRF",
            line="tunnel use-vrf {vrf}",
            no_line="no tunnel use-vrf",
            group="Tunnel",
            fields=(
                Field(
                    "vrf",
                    "VRF",
                    "vrf",
                    hint="A VRF made on the Routing page; remove to look in default",
                ),
            ),
            help="The VRF the destination is reached in, when it is not the default VRF.",
        ),
        Setting(
            key="ttl",
            label="TTL",
            line="tunnel ttl {ttl}",
            no_line="no tunnel ttl",
            group="Tunnel",
            fields=(Field("ttl", "TTL", "int", minimum=1, maximum=255, placeholder="255"),),
            help="The time-to-live of the outer packets, 1 to 255.",
        ),
        Setting(
            key="ipv4",
            label="IPv4 address",
            line="ip address {address}",
            no_line="no ip address {address}",
            group="Address",
            fields=(
                Field(
                    "address",
                    "Address",
                    "ifaddr4",
                    hint="With its prefix length; the other end has another address in the "
                    "same network",
                    placeholder="203.0.113.1/30",
                ),
            ),
            help="The tunnel's own address, which routes point at. Set the VRF first: "
            "changing it deletes the address.",
        ),
        Setting(
            key="description",
            label="Description",
            line="description {text}",
            no_line="no description",
            group="Interface",
            fields=(Field("text", "Description", "text", hint="What the tunnel is for"),),
        ),
        Setting(
            key="mtu",
            label="MTU",
            line="mtu {mtu}",
            no_line="no mtu",
            group="Interface",
            fields=(Field("mtu", "MTU", "int", minimum=64, maximum=9192, placeholder="1400"),),
            help="The largest IP packet sent into the tunnel, 64 to 9192 bytes.",
        ),
        Setting(
            key="vrf",
            label="VRF",
            line="vrf member {vrf}",
            group="Interface",
            fields=(
                Field(
                    "vrf",
                    "VRF",
                    "vrf",
                    hint="A VRF made on the Routing page; remove to go back to default",
                ),
            ),
            help="Put the tunnel in a VRF; Remove takes it back to the default VRF. For "
            "IP-in-IP the transport VRF must be the same one.",
            warning=_VRF_WARNING,
        ),
        Setting(
            key="pmtud_age",
            label="Path MTU age timer",
            line="tunnel path-mtu-discovery age-timer {minutes}",
            group="Path MTU discovery",
            fields=(
                Field(
                    "minutes",
                    "Minutes",
                    "int",
                    minimum=10,
                    maximum=30,
                    hint="10 to 30; 10 when not set",
                    placeholder="10",
                ),
            ),
            help="Turns on path MTU discovery: how long a learned path MTU is kept. The "
            "tunnel's packets then carry the don't-fragment bit.",
        ),
        Setting(
            key="pmtud_min",
            label="Path MTU minimum",
            line="tunnel path-mtu-discovery min-mtu {bytes}",
            group="Path MTU discovery",
            fields=(
                Field(
                    "bytes",
                    "Bytes",
                    "int",
                    minimum=64,
                    maximum=9192,
                    hint="64 to 9192; 64 when not set",
                    placeholder="64",
                ),
            ),
            help="Turns on path MTU discovery: the smallest MTU it accepts.",
        ),
        Setting(
            key="admin_up",
            label="Turn on",
            line="no shutdown",
            group="State",
            removable=False,
            help="Bring the tunnel up.",
        ),
        Setting(
            key="admin_down",
            label="Turn off",
            line="shutdown",
            group="State",
            removable=False,
            help="Take the tunnel down: traffic routed into it stops.",
            warning="Traffic routed into this tunnel stops while it is off.",
        ),
    ),
)


@dataclass(frozen=True)
class Tunnel:
    """One tunnel interface, from its configuration lines and ``show interface brief``."""

    number: int
    state: str = ""  # as show interface brief has it ("up", "down"); "" when not listed
    shutdown: bool = False
    description: str = ""
    mode: str = ""  # "" when the line is not there: GRE, the default
    source: str = ""
    destination: str = ""
    use_vrf: str = ""
    vrf: str = DEFAULT_VRF
    ipv4: str = ""
    mtu: str = ""
    ttl: str = ""
    pmtud_age: str = ""
    pmtud_min: str = ""


def parse_tunnel_config(config: str) -> dict[int, list[str]]:
    """Each ``interface TunnelN`` block of ``show running-config`` with its lines."""
    blocks: dict[int, list[str]] = {}
    current: list[str] | None = None
    for raw in config.splitlines():
        line = raw.strip()
        if not raw[:1].isspace():
            match = _BLOCK.fullmatch(line)
            current = blocks.setdefault(int(match.group(1)), []) if match else None
            continue
        if current is not None and line and not line.startswith("!"):
            current.append(line)
    return blocks


def _from_lines(number: int, lines: list[str], state: str) -> Tunnel:
    found: dict[str, Any] = {"number": number, "state": state}
    for line in lines:
        if line == "shutdown":
            found["shutdown"] = True
        elif line == "no shutdown":
            found["shutdown"] = False
        elif match := re.fullmatch(r"description (.+)", line):
            found["description"] = match.group(1)
        elif match := re.fullmatch(r"tunnel mode (.+)", line):
            found["mode"] = match.group(1)
        elif match := re.fullmatch(r"tunnel source (.+)", line):
            found["source"] = match.group(1)
        elif match := re.fullmatch(r"tunnel destination (\S+)", line):
            found["destination"] = match.group(1)
        elif match := re.fullmatch(r"tunnel use-vrf (\S+)", line):
            found["use_vrf"] = match.group(1)
        elif match := re.fullmatch(r"vrf member (\S+)", line):
            found["vrf"] = match.group(1)
        elif match := re.fullmatch(r"ip address (\S+)", line):
            found["ipv4"] = match.group(1)
        elif match := re.fullmatch(r"mtu (\d+)", line):
            found["mtu"] = match.group(1)
        elif match := re.fullmatch(r"tunnel ttl (\d+)", line):
            found["ttl"] = match.group(1)
        elif match := re.fullmatch(r"tunnel path-mtu-discovery age-timer (\d+)", line):
            found["pmtud_age"] = match.group(1)
        elif match := re.fullmatch(r"tunnel path-mtu-discovery min-mtu (\d+)", line):
            found["pmtud_min"] = match.group(1)
        elif match := re.fullmatch(r"tunnel path-mtu-discovery (\d+) (\d+)", line):
            # The form the guide's example prints: age timer, then minimum MTU.
            found["pmtud_age"], found["pmtud_min"] = match.group(1), match.group(2)
    return Tunnel(**found)


def parse_tunnels(brief: Any, config: str | None) -> list[Tunnel]:
    """Every tunnel, in number order: those in the configuration text with their lines,
    and any other that ``show interface brief`` lists (with no lines, when the text could
    not be read)."""
    states: dict[int, str] = {}
    for row in rows(brief or {}, "TABLE_interface", "ROW_interface"):
        match = _NAME.fullmatch(text(row.get("interface")))
        if match:
            states[int(match.group(1))] = text(row.get("state")).lower()
    blocks = parse_tunnel_config(config or "")
    numbers = sorted(set(blocks) | set(states))
    return [_from_lines(n, blocks.get(n, []), states.get(n, "")) for n in numbers]


def _source_values(source: str) -> dict[str, dict[str, str]]:
    if re.fullmatch(r"[0-9.]+", source):
        return {"source_address": {"address": source}}
    return {"source_interface": {"source": source}} if source else {}


def parse_tunnel_view(brief: Any, config: str | None) -> ProtocolView:
    """The page: one place per tunnel, with its state, mode, ends and address."""
    instances = []
    for tunnel in parse_tunnels(brief, config):
        if tunnel.state:
            state = tunnel.state
        elif config is not None:
            state = "off" if tunnel.shutdown else "on"
        else:
            state = "-"
        facts = (
            ("State", state),
            ("Mode", tunnel.mode or f"{DEFAULT_MODE} (default)"),
            ("Source", tunnel.source or "not set"),
            ("Destination", tunnel.destination or "not set"),
            ("Transport VRF", tunnel.use_vrf or DEFAULT_VRF),
            ("VRF", tunnel.vrf),
            ("IPv4", tunnel.ipv4 or "none"),
            ("MTU", tunnel.mtu or "-"),
            ("Description", tunnel.description or "-"),
        )
        values: dict[str, dict[str, str]] = _source_values(tunnel.source)
        pairs = (
            ("mode", "mode", tunnel.mode),
            ("destination", "address", tunnel.destination),
            ("use_vrf", "vrf", tunnel.use_vrf),
            ("ttl", "ttl", tunnel.ttl),
            ("ipv4", "address", tunnel.ipv4),
            ("description", "text", tunnel.description),
            ("mtu", "mtu", tunnel.mtu),
            ("pmtud_age", "minutes", tunnel.pmtud_age),
            ("pmtud_min", "bytes", tunnel.pmtud_min),
        )
        values.update({key: {name: value} for key, name, value in pairs if value})
        if tunnel.vrf != DEFAULT_VRF:
            values["vrf"] = {"vrf": tunnel.vrf}
        instances.append(
            Instance(
                "tunnel", {"number": str(tunnel.number)}, f"tunnel{tunnel.number}", facts, values
            )
        )
    notes = ()
    if len(instances) >= TUNNEL_LIMIT:
        notes = (f"The switch takes at most {TUNNEL_LIMIT} GRE and IP-in-IP tunnels.",)
    return ProtocolView(tuple(instances), (), notes)


TUNNELS = Protocol(
    key="tunnels",
    name="Tunnels",
    summary="GRE and IP-in-IP tunnels to other routers",
    features=(FEATURE,),
    commands=COMMANDS,
    parse=lambda bodies: parse_tunnel_view(bodies[0] if bodies else None, None),
    scopes=(_TUNNEL,),
    about=(
        "Make a tunnel, give it a source, a destination and an address, and route traffic "
        "into it. The switch takes up to 16 tunnels, and none while VXLAN is on."
    ),
)


@dataclass(frozen=True)
class TunnelPage:
    """Everything the Tunnels page shows."""

    protocol: Protocol
    view: ProtocolView
    vrfs: tuple[str, ...]  # the VRFs made on the switch: never default or management
    numbers: tuple[int, ...] = ()  # the tunnels on the switch
    problem: str = ""
    missing: tuple[str, ...] = ()  # the tunnel feature, when it is off


def load_tunnel_page(client: NxapiClient) -> TunnelPage:
    """One request for the features and VRFs; while tunnel is on, one for the brief and
    the configuration text."""
    feature_body, vrf_body = client.show(*PAGE_COMMANDS)
    # The VRF forms offer only the VRFs made on the switch; Remove goes back to default.
    vrfs = tuple(v for v in vrf_choices(vrf_body) if v not in (DEFAULT_VRF, "management"))
    states = feature_states(feature_body)
    if not states.get(FEATURE, False):
        problem = VXLAN_ON if states.get(VXLAN_FEATURE, False) else ""
        return TunnelPage(TUNNELS, ProtocolView(), vrfs, problem=problem, missing=(FEATURE,))
    (brief,) = client.show(*COMMANDS)
    problem = ""
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError as exc:
        config = None
        problem = f"The switch did not show the tunnels' settings: {exc}"
    view = parse_tunnel_view(brief, config)
    numbers = tuple(int(i.ident["number"]) for i in view.of("tunnel"))
    return TunnelPage(TUNNELS, view, vrfs, numbers, problem)


def build_tunnel_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Tunnels page."""
    return build_change(TUNNELS, scope, setting, action, ident, values)
