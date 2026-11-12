"""Static MPLS: turning MPLS on, the label range, MPLS on the interfaces, and static label
bindings that swap or pop a label towards a next hop.

MPLS forwards packets by a short label instead of the destination address. With static
MPLS each binding is typed by hand: packets arriving with a local label for a prefix are
sent to a next hop with another label (a swap), or with the label taken off (a pop, out
label ``implicit-null``), with a backup next hop if wanted.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (the switch-wide lines, an interface, a binding), each
setting the one configuration line it sends with checked values in its blanks, and
``build_change`` building the lines. ``NxapiClient.configure_mpls`` sends them.

Read from the switch: ``show feature``, ``show interface brief``, ``show vrf`` and ``show
vrf interface`` in one request, ``show feature-set`` as text (whether the MPLS feature set
is installed and on); while ``feature mpls static`` is on, ``show mpls switching`` (the
labels in use) and ``show running-config`` as text (the label range, the interfaces with
``mpls ip forwarding`` and the bindings, read with the role's ``show running-config``
rule).

Built from Cisco's Nexus 9000 NX-OS Label Switching Configuration Guide, Release 9.3(x)
("Configuring Static MPLS"). On cisco-25gb (NX-OS 9.3(16), 2026-11-11) ``install
feature-set mpls`` and ``feature-set mpls`` were taken (and undone), and ``feature mpls
static`` was refused while VXLAN's ``feature vn-segment-vlan-based`` was on ("Please
disable the vnseg_vlan / vn-segment-vlan-based feature first"); nothing past that was
tried. What the page follows from the guide:

* ``install feature-set mpls``, ``feature-set mpls``, then ``feature mpls static``, each
  with its ``no`` form; the Nexus 9200 needs no TCAM carving for static MPLS;
* ``mpls label range MIN MAX [static MIN MAX]``, labels 16 to 471804;
* ``mpls ip forwarding`` on each interface that carries labels (not on subinterfaces);
* ``mpls static configuration``, ``address-family ipv4|ipv6 unicast``, ``local-label L
  prefix P``, then ``next-hop auto-resolve out-label N`` (swap), ``next-hop A out-label
  implicit-null`` (pop) or ``next-hop backup INTERFACE A out-label N`` (the backup path);
* static MPLS takes up to 128 labels; no VRFs, vPC, FEX or VXLAN with it; label push is
  not supported, nor ECMP with a pop.

MPLS Layer 3 VPNs and LDP are not on this page: Cisco's 9.3 guide lists L3VPN only for
Nexus 3600-R and 9500 -R line cards, and LDP is not a command on the 92160YC-X.
"""

from __future__ import annotations

import ipaddress
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
)
from app.routing import parse_vrf_members
from app.routing_protocols import layer3_interfaces
from app.switch import text
from app.vxlan import parse_vxlan_config

FEATURE = "mpls_static"  # show feature's name for `feature mpls static`
VXLAN_FEATURES = ("nve", "vnseg_vlan")  # feature nv overlay, feature vn-segment-vlan-based
PAGE_COMMANDS = ("show feature", "show interface brief", "show vrf", "show vrf interface")
SET_COMMAND = "show feature-set"
COMMANDS = ("show mpls switching",)
CONFIG_COMMAND = "show running-config"
LABEL_MIN, LABEL_MAX = 16, 471804
OUT_LABEL_MAX = 1048575  # a label is 20 bits
BINDINGS_MAX = 128

VXLAN_ON = (
    "VXLAN (feature nv overlay or vn-segment-vlan-based) is on, and the switch turns on "
    "static MPLS only while both are off: the two cannot be on together."
)
STATIC_OFF = (
    "Static MPLS is off: turn on the MPLS feature set and static MPLS under Switch-wide first."
)


def _label(name: str, label: str, low: int = LABEL_MIN, high: int = LABEL_MAX) -> Field:
    return Field(name, label, "int", minimum=low, maximum=high, placeholder="2000")


_SWITCH = Scope(
    key="switch",
    label="Switch-wide",
    ident=(),
    enter=(),
    help="MPLS is turned on in three steps, in order: install the feature set, turn it on, "
    "then turn on static MPLS.",
    settings=(
        Setting(
            key="install",
            label="Install the MPLS feature set",
            line="install feature-set mpls",
            group="Turn MPLS on",
            help="Remove uninstalls it (after it is turned off).",
        ),
        Setting(
            key="feature_set",
            label="Turn on the MPLS feature set",
            line="feature-set mpls",
            group="Turn MPLS on",
            help="Remove turns it off (after static MPLS is off).",
        ),
        Setting(
            key="static",
            label="Turn on static MPLS",
            line="feature mpls static",
            group="Turn MPLS on",
            help="Not while VXLAN is on.",
            warning="Turning static MPLS off deletes every static binding.",
        ),
        Setting(
            key="label_range",
            label="Label range",
            line="mpls label range {low} {high}[ static {static_low} {static_high}]",
            group="Labels",
            fields=(
                _label("low", "Lowest label"),
                _label("high", "Highest label"),
                Field(
                    "static_low",
                    "Lowest static label",
                    "int",
                    minimum=LABEL_MIN,
                    maximum=LABEL_MAX,
                    optional=True,
                ),
                Field(
                    "static_high",
                    "Highest static label",
                    "int",
                    minimum=LABEL_MIN,
                    maximum=LABEL_MAX,
                    optional=True,
                ),
            ),
            help=f"Labels {LABEL_MIN} to {LABEL_MAX}. A binding's local label must be in "
            "the static range.",
        ),
    ),
)

_INTERFACE = Scope(
    key="interface",
    label="Interface",
    ident=(Field("interface", "Interface", "interface"),),
    enter=("interface {interface}",),
    help="MPLS is on only on the interfaces that carry labelled packets.",
    settings=(
        Setting(
            key="forwarding",
            label="MPLS forwarding",
            line="mpls ip forwarding",
            group="MPLS",
            help="Take labelled packets on this interface. Not on a subinterface.",
        ),
    ),
)

_BINDING = Scope(
    key="binding",
    label="Static binding",
    ident=(
        Field("family", "Family", "choice", choices=("ipv4", "ipv6")),
        _label("label", "Local label"),
        Field(
            "prefix",
            "Prefix",
            "prefix",
            hint="A route the switch has: 192.0.2.1/32",
            placeholder="192.0.2.1/32",
        ),
    ),
    enter=(
        "mpls static configuration",
        "address-family {family} unicast",
        "local-label {label} prefix {prefix}",
    ),
    create=True,
    create_label="Add a binding",
    delete=(
        "mpls static configuration",
        "address-family {family} unicast",
        "no local-label {label} prefix {prefix}",
    ),
    delete_warning="Packets arriving with this label are dropped.",
    help=(
        f"A local label for a prefix and where packets with it go. Up to {BINDINGS_MAX} "
        "labels; the prefix must match a route in the routing table."
    ),
    settings=(
        Setting(
            key="swap",
            label="Swap the label",
            line="next-hop auto-resolve out-label {out}",
            group="Next hop",
            fields=(_label("out", "Out label", 0, OUT_LABEL_MAX),),
            help="Send on with another label, to the next hop the routing table gives.",
        ),
        Setting(
            key="pop",
            label="Take the label off",
            line="next-hop {address} out-label implicit-null",
            group="Next hop",
            fields=(Field("address", "Next hop", "ip", placeholder="192.0.2.2"),),
            help="Send on without a label, to this next hop. Not with several paths.",
        ),
        Setting(
            key="backup",
            label="Backup path",
            line="next-hop backup {interface} {address} out-label {out}",
            group="Next hop",
            fields=(
                Field("interface", "Out interface", "interface"),
                Field("address", "Next hop", "ip", placeholder="192.0.2.6"),
                _label("out", "Out label", 0, OUT_LABEL_MAX),
            ),
            help="Used when the main path is down: a directly connected next hop, through "
            "a front port or port-channel.",
        ),
    ),
)


def parse_feature_set(output: str) -> str:
    """The MPLS feature set's state in ``show feature-set`` ("enabled", "disabled",
    "installed", "uninstalled"), or "" when the output does not list it."""
    for line in output.splitlines():
        match = re.match(r"\s*mpls\s+\d+\s+(\S+)", line)
        if match:
            return match.group(1).lower()
    return ""


def _prefix(prefix: str, mask: str = "") -> str:
    """``192.0.2.1/32`` from that or from ``192.0.2.1 255.255.255.255``."""
    try:
        return str(ipaddress.ip_network(f"{prefix}/{mask}" if mask else prefix, strict=False))
    except ValueError:
        return prefix


@dataclass(frozen=True)
class MplsConfig:
    """The MPLS lines of the running configuration."""

    label_range: str = ""
    interfaces: tuple[str, ...] = ()
    # (family, label, prefix, next-hop lines)
    bindings: tuple[tuple[str, str, str, tuple[str, ...]], ...] = ()


_LOCAL = re.compile(r"local-label (\d+) prefix (\S+)(?: (\d+\.\d+\.\d+\.\d+))?(?: (next-hop .+))?")


def parse_mpls_config(config: str) -> MplsConfig:
    """The label range, the interfaces with ``mpls ip forwarding`` and the static bindings
    in ``show running-config``."""
    tree = parse_vxlan_config(config)
    top = tree.children()
    label_range = next(
        (line[len("mpls label range ") :] for line in top if line.startswith("mpls label range ")),
        "",
    )
    interfaces = tuple(
        line.split(" ", 1)[1]
        for line in top
        if line.startswith("interface ") and "mpls ip forwarding" in tree.children(line)
    )
    bindings = []
    if "mpls static configuration" in top:
        for family_line in tree.children("mpls static configuration"):
            family = re.fullmatch(r"address-family (ipv4|ipv6) unicast", family_line)
            if not family:
                continue
            for local in tree.children("mpls static configuration", family_line):
                match = _LOCAL.fullmatch(local)
                if not match:
                    continue
                hops = [*tree.children("mpls static configuration", family_line, local)]
                if match.group(4):
                    hops.insert(0, match.group(4))
                bindings.append(
                    (
                        family.group(1),
                        match.group(1),
                        _prefix(match.group(2), match.group(3) or ""),
                        tuple(hops),
                    )
                )
    return MplsConfig(label_range, interfaces, tuple(bindings))


def _hop_values(hops: tuple[str, ...]) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    for hop in hops:
        if match := re.fullmatch(r"next-hop auto-resolve out-label (\d+)", hop):
            values["swap"] = {"out": match.group(1)}
        elif match := re.fullmatch(r"next-hop backup (\S+) (\S+) out-label (\d+)", hop):
            values["backup"] = {
                "interface": match.group(1),
                "address": match.group(2),
                "out": match.group(3),
            }
        elif match := re.fullmatch(r"next-hop (\S+) out-label implicit-null", hop):
            values["pop"] = {"address": match.group(1)}
    return values


def _switching_rows(body: Any) -> list[dict[str, Any]]:
    """Every row of ``show mpls switching`` that has an in-label, wherever the switch nests
    it (Cisco's guide names the keys, not the tables around them)."""
    found: list[dict[str, Any]] = []
    stack = [body]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if "in_label" in item:
                found.append(item)
            else:
                stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(reversed(item))
    return found


def parse_mpls(
    switching: Any, config: str | None, feature_set: str, static_on: bool
) -> ProtocolView:
    """The page from ``show mpls switching``, the configuration text (None when it could
    not be read), the feature set's state and whether static MPLS is on."""
    parsed = parse_mpls_config(config or "")
    switch_values: dict[str, dict[str, str]] = {}
    if feature_set in ("installed", "enabled", "disabled"):
        switch_values["install"] = {"on": "yes"}
    if feature_set == "enabled":
        switch_values["feature_set"] = {"on": "yes"}
    if static_on:
        switch_values["static"] = {"on": "yes"}
    if parsed.label_range:
        words = parsed.label_range.split()
        found = {"low": words[0], "high": words[1] if len(words) > 1 else ""}
        if len(words) >= 4 and words[2] == "static":
            found |= {"static_low": words[3], "static_high": words[4] if len(words) > 4 else ""}
        switch_values["label_range"] = found
    places = [
        Instance(
            "switch",
            {},
            "Switch-wide",
            (
                ("MPLS feature set", feature_set or "not listed"),
                ("Static MPLS", "on" if static_on else "off"),
                ("Label range", parsed.label_range or "the switch's default"),
            ),
            switch_values,
        ),
        *(
            Instance(
                "interface",
                {"interface": name},
                name,
                (("MPLS forwarding", "on"),),
                {"forwarding": {"on": "yes"}},
            )
            for name in parsed.interfaces
        ),
        *(
            Instance(
                "binding",
                {"family": family, "label": label, "prefix": prefix},
                f"Label {label} for {prefix}",
                (("Next hops", "; ".join(hops) or "none yet"),),
                _hop_values(hops),
            )
            for family, label, prefix, hops in parsed.bindings
        ),
    ]
    rows = tuple(
        (
            text(row.get("in_label")),
            text(row.get("out_label_stack") or row.get("out_label")),
            text(row.get("ipv4_prefix") or row.get("ipv6_prefix")),
            text(row.get("out_interface")),
            text(row.get("ipv4_next_hop") or row.get("ipv6_next_hop")),
        )
        for row in _switching_rows(switching)
    )
    tables = (
        Table(
            "Labels in use",
            ("In label", "Out label", "Prefix", "Out interface", "Next hop"),
            rows,
            empty="No label is in use." if static_on else "Static MPLS is off.",
            note="Read when the page loads.",
        ),
    )
    notes = ()
    if static_on and config is None:
        notes = ("The switch did not show the MPLS settings to NXray's account.",)
    return ProtocolView(tuple(places), tables, notes)


MPLS = Protocol(
    key="mpls",
    name="MPLS",
    summary="Static MPLS labels: swap or pop a label towards a next hop",
    features=(),
    commands=COMMANDS,
    parse=lambda bodies: parse_mpls(bodies[0] if bodies else None, None, "", False),
    scopes=(_SWITCH, _INTERFACE, _BINDING),
    about=(
        "Turn MPLS on under Switch-wide, set the label range, turn on MPLS forwarding on "
        "the interfaces that carry labels, then add a binding for each label."
    ),
)


@dataclass(frozen=True)
class MplsPage:
    """Everything the MPLS page shows."""

    protocol: Protocol
    view: ProtocolView
    interfaces: tuple[str, ...]  # VLAN interfaces, routed ports and port-channels
    static_on: bool = False
    problem: str = ""
    # Always empty: the page itself turns MPLS on, so it never shows only "feature off".
    missing: tuple[str, ...] = ()


def load_mpls_page(client: NxapiClient) -> MplsPage:
    """One request for the features and interfaces, the feature set's state as text;
    while static MPLS is on, the labels in use and the configuration text."""
    feature, brief, _vrf, vrf_members = client.show(*PAGE_COMMANDS)
    interfaces = layer3_interfaces(brief, parse_vrf_members(vrf_members))
    states = feature_states(feature)
    try:
        feature_set = parse_feature_set(client.show_text(SET_COMMAND))
    except NxapiCommandError:
        feature_set = ""
    static_on = states.get(FEATURE, False)
    problem = ""
    if not static_on and any(states.get(name, False) for name in VXLAN_FEATURES):
        problem = VXLAN_ON
    switching = config = None
    if static_on:
        try:
            (switching,) = client.show(*COMMANDS)
        except NxapiCommandError as exc:
            problem = f"The switch did not report the labels in use: {exc}"
        try:
            config = client.show_text(CONFIG_COMMAND)
        except NxapiCommandError:
            config = None
    view = parse_mpls(switching, config, feature_set, static_on)
    return MplsPage(MPLS, view, interfaces, static_on, problem)


def check_mpls_place(page: MplsPage, ident: dict[str, str]) -> None:
    """Refuse an interface a label cannot go out of, and interface and binding changes
    while static MPLS is off."""
    if ("label" in ident or "interface" in ident) and not page.static_on:
        raise ValueError(STATIC_OFF[0].lower() + STATIC_OFF[1:].rstrip("."))
    interface = ident.get("interface", "").strip()
    if interface and interface not in page.interfaces:
        known = ", ".join(page.interfaces) or "none"
        raise ValueError(
            f"{interface} is not a VLAN interface (up to Vlan254), routed port or routed "
            f"port-channel on the switch; those are: {known}"
        )


def build_mpls_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the MPLS page."""
    return build_change(MPLS, scope, setting, action, ident, values)
