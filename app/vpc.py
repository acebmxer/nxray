"""Virtual port-channel (vPC): two switches that act as one, so a server or another
switch can have a port-channel to both.

The vPC page is described with the same parts as the routing protocol pages
(``app/protocols.py``): scopes (the vPC domain, a port-channel), each setting
the one configuration line it sends with checked values in its blanks, and
``build_change`` building the lines. ``NxapiClient.configure_vpc`` sends them.

A vPC pair needs, in this order:

1. ``feature vpc`` (and ``feature lacp``), turned on on the Features page;
2. a vPC domain with the same number on both switches;
3. a peer keepalive: the address of the other switch, normally reached in the
   management VRF, which tells each switch the other is alive;
4. a peer-link: a port-channel of two or more ports between the switches
   (made on the Port-channels page, then marked ``vpc peer-link`` here);
5. a vPC on each port-channel that goes to a device attached to both switches:
   ``vpc <number>``, the same number on both switches.

Read from the switch: ``show feature``, ``show port-channel summary`` (the
port-channels the vPC lines may name) and ``show vrf`` in one request; then ``show vpc``
(the domain's state, the peer-link and every vPC with its consistency) while the
features are on. The settings that are configured come from ``show running-config vpc``, which
NX-API gives only as text (``NxapiClient.show_text``) and only once NXray's role
allows it (role version 19); without it the page still shows everything
``show vpc`` reports.

Not tried on a switch: vPC is off on cisco-25gb, which is in production, so
this page was written from Cisco's NX-OS 9.3 Interfaces and Layer 2 Switching
Configuration Guides and the field names Cisco documents for ``show vpc``
(``vpc-domain-id``, ``vpc-peer-status``, ``TABLE_peerlink``, ``TABLE_vpc``).
Every field is read tolerantly: one the switch words differently shows empty
rather than breaking the page.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.features import feature_states
from app.nxapi import NxapiClient, NxapiCommandError
from app.port_channels import parse_channels
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
    channel_field,
    table_rows,
)
from app.switch import text

DOMAIN_MAX = 1000
VPC_NUMBER_MAX = 4096
COMMANDS = ("show vpc",)
CONFIG_COMMAND = "show running-config vpc"
PAGE_COMMANDS = ("show feature", "show port-channel summary", "show vrf")


def _int(name: str, label: str, low: int, high: int, **kw: Any) -> Field:
    return Field(name, label, "int", minimum=low, maximum=high, **kw)


# ---- settings -------------------------------------------------------------------------

_DOMAIN = Scope(
    key="domain",
    label="vPC domain",
    ident=(
        _int(
            "domain",
            "Domain number",
            1,
            DOMAIN_MAX,
            hint="1 to 1000; the same number on both switches",
        ),
    ),
    enter=("vpc domain {domain}",),
    create=True,
    create_label="Make the vPC domain",
    delete=("no vpc domain {domain}",),
    delete_warning=(
        "Deleting the vPC domain takes down the peer-link and every vPC on this switch: "
        "devices connected through a vPC lose their link to it until they reach the other "
        "switch. A switch has one vPC domain."
    ),
    help="The pair's shared settings. A switch has one domain; give both switches the same number.",
    settings=(
        Setting(
            key="keepalive",
            label="Peer keepalive",
            line="peer-keepalive destination {destination}[ source {source}][ vrf {vrf}]",
            no_line="no peer-keepalive destination {destination}",
            group="Peer keepalive",
            fields=(
                Field(
                    "destination",
                    "The other switch's address",
                    "ipv4",
                    hint="Where the keepalive messages go: the other switch's management "
                    "address, or an address on a link of their own",
                ),
                Field(
                    "source",
                    "This switch's address",
                    "ipv4",
                    optional=True,
                    hint="Leave empty to use the address of the VRF's interface",
                ),
                Field(
                    "vrf",
                    "VRF",
                    "usevrf",
                    optional=True,
                    hint="Where the other switch is reached: management or another VRF. "
                    "Never the peer-link itself",
                ),
            ),
            help=(
                "How each switch tells the other it is alive. Send it over a path that does "
                "not use the peer-link, such as the management ports."
            ),
        ),
        Setting(
            key="role_priority",
            label="Role priority",
            line="role priority {priority}",
            group="Roles and priorities",
            fields=(_int("priority", "Priority", 1, 65535, hint="1 to 65535; default 32667"),),
            help="The switch with the lower number becomes the primary vPC switch.",
        ),
        Setting(
            key="system_priority",
            label="System priority",
            line="system-priority {priority}",
            group="Roles and priorities",
            fields=(_int("priority", "Priority", 1, 65535, hint="1 to 65535; default 32667"),),
            help=(
                "Used in LACP with the pair's shared system MAC address. Give both switches "
                "the same number."
            ),
        ),
        Setting(
            key="peer_switch",
            label="Peer switch",
            line="peer-switch",
            group="Behaviour",
            help=(
                "Both switches act as one spanning tree root, so a failure of the primary does "
                "not restart the tree. Set the same spanning tree priority on both."
            ),
            warning="Spanning tree restarts on both switches while the pair agrees on this.",
        ),
        Setting(
            key="peer_gateway",
            label="Peer gateway",
            line="peer-gateway",
            group="Behaviour",
            help=(
                "Each switch answers for the other's gateway MAC address, for devices that "
                "send traffic to the MAC address they learned instead of the shared one."
            ),
        ),
        Setting(
            key="layer3_peer_router",
            label="Layer 3 peer router",
            line="layer3 peer-router",
            group="Behaviour",
            help="Lets the pair route for routers that send routed traffic across the vPC.",
        ),
        Setting(
            key="arp_sync",
            label="Synchronize ARP",
            line="ip arp synchronize",
            group="Behaviour",
            help="Copy learned ARP entries to the peer so routing recovers faster.",
        ),
        Setting(
            key="nd_sync",
            label="Synchronize IPv6 neighbors",
            line="ipv6 nd synchronize",
            group="Behaviour",
            help="Copy learned IPv6 neighbor entries to the peer.",
        ),
        Setting(
            key="auto_recovery",
            label="Auto-recovery",
            line="auto-recovery[ reload-delay {delay}]",
            group="Recovery",
            fields=(
                _int(
                    "delay",
                    "Wait (seconds)",
                    240,
                    3600,
                    optional=True,
                    hint="240 to 3600; empty for the default (240)",
                ),
            ),
            help=(
                "After both switches restart and the peer does not come back, this one brings "
                "its vPCs up on its own after the wait."
            ),
        ),
        Setting(
            key="delay_restore",
            label="Delay restore",
            line="delay restore {seconds}",
            group="Recovery",
            fields=(_int("seconds", "Seconds", 1, 3600, hint="1 to 3600; default 30"),),
            help="How long a restarted switch waits before bringing its vPC ports up.",
        ),
        Setting(
            key="delay_restore_svi",
            label="Delay restore for VLAN interfaces",
            line="delay restore interface-vlan {seconds}",
            group="Recovery",
            fields=(_int("seconds", "Seconds", 1, 3600, hint="1 to 3600; default 10"),),
            help="How long a restarted switch waits before bringing its VLAN interfaces up.",
        ),
    ),
)

_CHANNEL = Scope(
    key="channel",
    label="vPC on a port-channel",
    ident=(channel_field(),),
    enter=("interface {channel}",),
    help=(
        "Mark the port-channel between the two switches as the peer-link, or give a "
        "port-channel that goes to a device on both switches a vPC number. Make the "
        "port-channel first on the Port-channels page."
    ),
    settings=(
        Setting(
            key="peer_link",
            label="Peer-link",
            line="vpc peer-link",
            help=(
                "The port-channel that joins the two switches. Use two or more ports, "
                "at 10G or faster, and make it a trunk."
            ),
            warning=(
                "The peer-link carries the pair's traffic between the switches. Marking or "
                "unmarking it makes the vPC pair restart its negotiation."
            ),
        ),
        Setting(
            key="number",
            label="vPC number",
            line="vpc {number}",
            fields=(
                _int(
                    "number",
                    "vPC number",
                    1,
                    VPC_NUMBER_MAX,
                    hint="1 to 4096; the same number on the port-channel of both switches",
                ),
            ),
            help="Joins this port-channel to the same-numbered one on the other switch.",
            warning=(
                "The port-channel flaps while the two switches agree on the vPC, so the "
                "device connected to it loses its link for a moment."
            ),
        ),
    ),
)


# ---- the configuration text ---------------------------------------------------------------


@dataclass(frozen=True)
class VpcConfig:
    """The vPC lines of the running configuration."""

    domain: str = ""  # the domain's number, "" when none is made
    lines: tuple[str, ...] = ()  # the lines inside ``vpc domain``
    channels: dict[str, tuple[str, ...]] | None = None  # port-channel -> its vpc lines

    def values(self) -> dict[str, dict[str, str]]:
        """The domain's settings in the configuration, by setting key."""
        return domain_values(self.lines)


def parse_vpc_config(config: str) -> VpcConfig:
    """The vPC domain and the ``vpc`` lines of port-channels from
    ``show running-config vpc``."""
    domain = ""
    lines: list[str] = []
    channels: dict[str, list[str]] = {}
    section = ""
    current = ""
    for raw in config.splitlines():
        line = raw.strip()
        if not line or line.startswith("!"):
            continue
        if not raw[0].isspace():
            match = re.fullmatch(r"vpc domain ([0-9]+)", line)
            if match:
                domain, section = match.group(1), "domain"
            elif line.startswith("interface "):
                section, current = "interface", line.split(None, 1)[1].lower()
            else:
                section = ""
            continue
        if section == "domain":
            lines.append(line)
        elif section == "interface" and (line == "vpc peer-link" or line.startswith("vpc ")):
            channels.setdefault(current, []).append(line)
    return VpcConfig(domain, tuple(lines), {k: tuple(v) for k, v in channels.items()})


def _keepalive(line: str) -> dict[str, str]:
    """``peer-keepalive destination 192.0.2.2 source 192.0.2.1 vrf management`` -> its
    destination, source and vrf; the words the switch adds (timers) are skipped."""
    words = line.split()
    found = {"destination": "", "source": "", "vrf": ""}
    for key, value in zip(words, words[1:], strict=False):
        if key in found:
            found[key] = value
    return found


def domain_values(lines: tuple[str, ...] | list[str]) -> dict[str, dict[str, str]]:
    """The settings the domain's lines show, by setting key, as field values."""
    values: dict[str, dict[str, str]] = {}
    for line in lines:
        if line.startswith("peer-keepalive destination "):
            found = _keepalive(line)
            found["vrf"] = found["vrf"] or "default"
            values["keepalive"] = found
        elif match := re.fullmatch(r"role priority ([0-9]+)", line):
            values["role_priority"] = {"priority": match.group(1)}
        elif match := re.fullmatch(r"system-priority ([0-9]+)", line):
            values["system_priority"] = {"priority": match.group(1)}
        elif match := re.fullmatch(r"delay restore ([0-9]+)", line):
            values["delay_restore"] = {"seconds": match.group(1)}
        elif match := re.fullmatch(r"delay restore interface-vlan ([0-9]+)", line):
            values["delay_restore_svi"] = {"seconds": match.group(1)}
        elif match := re.fullmatch(r"auto-recovery(?: reload-delay ([0-9]+))?", line):
            values["auto_recovery"] = {"delay": match.group(1) or ""}
    return values


# Lines with no value in them: shown under "Turned on", since a setting with no blanks
# has no value to mark it as set.
_FLAG_LINES = {
    "peer-switch": "Peer switch",
    "peer-gateway": "Peer gateway",
    "layer3 peer-router": "Layer 3 peer router",
    "ip arp synchronize": "Synchronize ARP",
    "ipv6 nd synchronize": "Synchronize IPv6 neighbors",
}


# ---- reading `show vpc` -------------------------------------------------------------------


def channel_name(value: str) -> str:
    """'Po20' (how ``show vpc`` writes a port-channel) -> 'port-channel20'; others unchanged."""
    match = re.fullmatch(r"(?i)po(?:rt-channel)?\s*([0-9]+)", value.strip())
    return f"port-channel{match.group(1)}" if match else value.strip()


def _up(value: Any) -> str:
    """'1' (how ``show vpc`` writes a port state) -> up; '0' -> down; words as they are."""
    found = text(value)
    return {"1": "up", "0": "down"}.get(found, found or "-")


def _joined(*parts: str) -> str:
    return " ".join(p for p in parts if p)


def _shown(value: Any) -> str:
    found = text(value)
    return "" if found in ("", "-", "--") else found


def parse_vpc(bodies: list[dict[str, Any]], config: VpcConfig | None = None) -> ProtocolView:
    """The vPC domain, peer-link and vPCs from ``show vpc`` (``bodies[0]``) and the
    configured settings from ``config`` (None: NXray's role cannot read them yet)."""
    body = bodies[0] if bodies else {}
    if not isinstance(body, dict):
        body = {}
    notes: list[str] = []
    instances: list[Instance] = []

    reported = text(body.get("vpc-domain-id"))
    domain = (config.domain if config is not None else "") or (
        reported if reported.isdigit() else ""
    )
    facts: list[tuple[str, str]] = []
    if body:
        for label, key in (
            ("This switch is", "vpc-role"),
            ("Peer keepalive", "vpc-peer-keepalive-status"),
            ("Configuration consistency", "vpc-peer-consistency"),
            ("Per-VLAN consistency", "vpc-per-vlan-peer-consistency"),
            ("Type 2 consistency", "vpc-type-2-consistency"),
            ("vPCs on the switch", "num-of-vpcs"),
            ("Peer gateway", "peer-gateway"),
            ("Auto-recovery", "vpc-auto-recovery-status"),
            ("Delay restore", "vpc-delay-restore-status"),
            ("Delay restore, VLAN interfaces", "vpc-delay-restore-svi-status"),
            ("Layer 3 peer router", "operational-l3-peer"),
            ("VLANs shut down on a split", "dual-active-excluded-vlans"),
        ):
            if value := _shown(body.get(key)):
                facts.append((label, value))
        peer = _joined(text(body.get("vpc-peer-status")), text(body.get("vpc-peer-status-reason")))
        if peer:
            facts.insert(0, ("Peer status", peer))
    values: dict[str, dict[str, str]] = config.values() if config is not None else {}
    if config is not None:
        turned_on = [name for line, name in _FLAG_LINES.items() if line in config.lines]
        facts.append(("Turned on", ", ".join(turned_on) or "none of the on/off settings"))
    if domain:
        instances.append(
            Instance("domain", {"domain": domain}, f"vPC domain {domain}", tuple(facts), values)
        )

    link_rows: list[tuple[str, ...]] = []
    vpc_rows: list[tuple[str, ...]] = []
    channels: dict[str, tuple[list[tuple[str, str]], dict[str, dict[str, str]]]] = {}
    for row in table_rows(body, "TABLE_peerlink", "ROW_peerlink"):
        name = channel_name(text(row.get("peerlink-ifindex")))
        if not name:
            continue
        status = _up(row.get("peer-link-port-state"))
        vlans = _shown(row.get("peer-up-vlan-bitset"))
        link_rows.append((name, status, vlans or "-"))
        channels[name] = ([("Role", "vPC peer-link"), ("State", status)], {})
    for row in table_rows(body, "TABLE_vpc", "ROW_vpc"):
        name = channel_name(text(row.get("vpc-ifindex")))
        number = text(row.get("vpc-id"))
        if not name:
            continue
        status = _up(row.get("vpc-port-state"))
        consistency = _joined(
            text(row.get("vpc-consistency")), _shown(row.get("vpc-consistency-status"))
        )
        vlans = _shown(row.get("up-vlan-bitset"))
        vpc_rows.append((number, name, status, consistency or "-", vlans or "-"))
        channels[name] = (
            [
                ("Role", f"vPC {number}"),
                ("State", status),
                ("Consistency", consistency or "-"),
            ],
            {"number": {"number": number}} if number else {},
        )
    # Port-channels the configuration marks that `show vpc` does not (yet) list, such
    # as a vPC while the peer is down.
    for name, lines in (config.channels or {}).items() if config is not None else ():
        shown_facts, shown_values = channels.setdefault(name, ([("Role", "not up yet")], {}))
        for line in lines:
            if match := re.fullmatch(r"vpc ([0-9]+)", line):
                shown_values.setdefault("number", {"number": match.group(1)})
    for name, (shown_facts, shown_values) in channels.items():
        instances.append(
            Instance("channel", {"channel": name}, name, tuple(shown_facts), shown_values)
        )

    if config is None:
        notes.append(
            "NXray's role on the switch does not let it read the vPC settings yet, so only "
            "what the switch reports about the pair is shown: an NXray admin turns on vPC "
            "changes on the Switch page."
        )
    tables = (
        Table(
            "Peer-link",
            ("Port-channel", "State", "VLANs allowed across it"),
            tuple(link_rows),
            empty="No peer-link. Make a port-channel of two or more ports between the "
            "switches, then mark it as the peer-link below.",
        ),
        Table(
            "vPCs",
            ("vPC", "Port-channel", "State", "Consistency", "VLANs up"),
            tuple(vpc_rows),
            empty="No vPC. Give a port-channel that goes to a device on both switches a vPC "
            "number below.",
        ),
    )
    return ProtocolView(tuple(instances), tables, tuple(notes))


VPC = Protocol(
    key="vpc",
    name="vPC",
    summary="Two switches act as one, so a server or switch can have a port-channel to both",
    features=("vpc", "lacp"),
    commands=COMMANDS,
    parse=parse_vpc,
    scopes=(_DOMAIN, _CHANNEL),
    about=(
        "Set up in this order: turn on the vpc and lacp features, make the vPC domain, set "
        "the peer keepalive, mark the port-channel between the switches as the peer-link, "
        "then give each port-channel that goes to a device on both switches a vPC number. "
        "Do the same on the other switch, with the same domain and vPC numbers."
    ),
)


# ---- the page -----------------------------------------------------------------------------


@dataclass(frozen=True)
class VpcPage:
    """Everything the vPC page shows."""

    protocol: Protocol
    view: ProtocolView
    channels: tuple[str, ...]  # the switched port-channels on the switch
    vrfs: tuple[str, ...]  # default, management and the VRFs made on the switch
    domain: str = ""  # the vPC domain the switch has, "" when none
    problem: str = ""
    missing: tuple[str, ...] = ()  # the features still off (show feature names)

    @property
    def on(self) -> bool:
        return not self.missing


def _vrf_names(body: dict[str, Any]) -> tuple[str, ...]:
    names = [text(r.get("vrf_name")) for r in table_rows(body, "TABLE_vrf", "ROW_vrf")]
    rest = sorted(n for n in names if n and n not in ("default", "management"))
    return ("default", "management", *rest)


def load_vpc_page(client: NxapiClient) -> VpcPage:
    """One request for the features, port-channels and VRFs; while the features are on,
    one for ``show vpc`` and one for the configuration text NXray may read."""
    feature, summary, vrf_body = client.show(*PAGE_COMMANDS)
    states = feature_states(feature)
    missing = tuple(name for name in VPC.features if not states.get(name, False))
    channels = tuple(c.name for c in parse_channels(summary, {}, {}, set()) if not c.routed)
    vrfs = _vrf_names(vrf_body)
    if missing:
        return VpcPage(VPC, ProtocolView(), channels, vrfs, missing=missing)
    problem = ""
    try:
        bodies = client.show(*COMMANDS)
    except NxapiCommandError as exc:
        # Before the domain is made the switch can refuse `show vpc`; the page still
        # offers the settings.
        bodies = [{}]
        problem = f"The switch did not report vPC's state: {exc}"
    try:
        config: VpcConfig | None = parse_vpc_config(client.show_text(CONFIG_COMMAND))
    except NxapiCommandError:
        config = None  # the role predates the rule that allows it
    view = parse_vpc(bodies, config)
    domain = next((i.ident["domain"] for i in view.of("domain")), "")
    return VpcPage(VPC, view, channels, vrfs, domain, problem)


def build_vpc_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the vPC page."""
    return build_change(VPC, scope, setting, action, ident, values)
