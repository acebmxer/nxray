"""MPLS: turning MPLS on, the label range, MPLS on the interfaces, static label bindings
that swap or pop a label towards a next hop, and Layer 3 VPNs over segment routing.

MPLS forwards packets by a short label instead of the destination address. With static
MPLS each binding is typed by hand: packets arriving with a local label for a prefix are
sent to a next hop with another label (a swap), or with the label taken off (a pop, out
label ``implicit-null``), with a backup next hop if wanted. With segment routing the
labels are handed out from a block (the global block) and each prefix of this switch gets
one (a prefix SID); a Layer 3 VPN then carries each VRF's routes between switches through
BGP, kept apart by the VRF's route distinguisher and route-targets. The BGP side (the VPN
address families, labels for IPv4 routes, labelled-unicast and VPN neighbors) is on the
BGP page (``app/protocols_bgp.py``).

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (the switch-wide lines, an interface, a binding), each
setting the one configuration line it sends with checked values in its blanks, and
``build_change`` building the lines. ``NxapiClient.configure_mpls`` sends them.

Read from the switch: ``show feature``, ``show interface brief``, ``show vrf``, ``show
vrf interface`` and ``show license usage`` (whether the VPN Fabric licence is installed)
in one request, ``show feature-set`` as text (whether the MPLS feature set is installed
and on); while static MPLS or segment routing is on, ``show mpls switching`` (the labels
in use); while static MPLS, segment routing or Layer 3 VPNs are on, ``show
running-config`` as text (the label range, the interfaces with ``mpls ip forwarding``,
the bindings, the segment routing block, the prefix SIDs and each VRF's route
distinguisher and route-targets, read with the role's ``show running-config`` rule).

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

Layer 3 VPNs follow the same guide ("Configuring Segment Routing": "Layer 3 VPN over
Segment Routing is supported on Cisco Nexus 3100, 3200, 9200, 9300 ..."). On cisco-25gb
``feature mpls segment-routing`` and ``feature mpls l3vpn`` were refused while
``feature vn-segment-vlan-based`` was on, as static MPLS was, so nothing below was tried
on a switch:

* ``feature mpls segment-routing`` and ``feature mpls l3vpn`` (after ``feature bgp``),
  each with its ``no`` form; static MPLS and segment routing cannot be on together;
* ``segment-routing`` then ``mpls`` turns segment routing on with the default global
  block 16000 to 23999; ``global-block MIN MAX`` (16000 to 471804) changes it, which
  restarts BGP; ``no segment-routing`` removes it with the MPLS settings that hang on it;
* ``connected-prefix-sid-map``, ``address-family ipv4``, then ``PREFIX/LEN index N`` or
  ``PREFIX/LEN absolute LABEL``: this switch's own prefix and its label;
* ``vrf context NAME`` with ``rd VALUE`` and, in ``address-family ipv4|ipv6 unicast``,
  ``route-target import|export VALUE`` (without ``evpn``: those are the VXLAN page's);
* the guide asks for the VPN Fabric licence; ``show license usage`` on cisco-25gb lists
  ``VPN_FABRIC`` as not installed.

Layer 3 VPNs over LDP are not on this page: Cisco's 9.3 guide lists them only for Nexus
3600-R and 9500 -R line cards, and LDP is not a command on the 92160YC-X.
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
    table_rows,
    vrf_field,
)
from app.routing import parse_vrf_members, parse_vrfs
from app.routing_protocols import layer3_interfaces
from app.switch import text
from app.vxlan import check_target, parse_vxlan_config, target_field

FEATURE = "mpls_static"  # show feature's name for `feature mpls static`
SR_FEATURE = "segment-routing"  # `feature mpls segment-routing`
L3VPN_FEATURE = "l3vpn"  # `feature mpls l3vpn`
VXLAN_FEATURES = ("nve", "vnseg_vlan")  # feature nv overlay, feature vn-segment-vlan-based
PAGE_COMMANDS = (
    "show feature",
    "show interface brief",
    "show vrf",
    "show vrf interface",
    "show license usage",
)
SET_COMMAND = "show feature-set"
COMMANDS = ("show mpls switching",)
CONFIG_COMMAND = "show running-config"
LABEL_MIN, LABEL_MAX = 16, 471804
OUT_LABEL_MAX = 1048575  # a label is 20 bits
BINDINGS_MAX = 128
# Segment routing's global block: 16000 to 471804, 16000-23999 when not set (Cisco's guide).
BLOCK_MIN, BLOCK_MAX = 16000, 471804
INDEX_MAX = 471788  # the highest label index the guide gives (``set label-index``)
LICENCE = "VPN_FABRIC"  # the licence Cisco's guide asks for, as show license usage names it

VXLAN_ON = (
    "VXLAN (feature nv overlay or vn-segment-vlan-based) is on, and the switch turns on "
    "static MPLS, segment routing and Layer 3 VPNs only while both are off: they cannot be "
    "on together."
)
STATIC_OFF = (
    "Static MPLS is off: turn on the MPLS feature set and static MPLS under Switch-wide first."
)
LABELS_OFF = (
    "Static MPLS and segment routing are off: turn on the MPLS feature set and one of them "
    "under Switch-wide first."
)
SR_OFF = (
    "Segment routing is off: turn on the MPLS feature set and segment routing under "
    "Switch-wide first."
)
L3VPN_OFF = (
    "Layer 3 VPNs are off: turn on the MPLS feature set and Layer 3 VPNs under Switch-wide first."
)
NO_LICENCE = (
    "Cisco's guide says Layer 3 VPNs need the VPN Fabric licence, and the switch lists it "
    "as not installed."
)


def _label(name: str, label: str, low: int = LABEL_MIN, high: int = LABEL_MAX) -> Field:
    return Field(name, label, "int", minimum=low, maximum=high, placeholder="2000")


_SWITCH = Scope(
    key="switch",
    label="Switch-wide",
    ident=(),
    enter=(),
    help="MPLS is turned on in steps, in order: install the feature set, turn it on, then "
    "turn on static MPLS, or segment routing and Layer 3 VPNs (not both ways at once).",
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
            help="Not while VXLAN or segment routing is on.",
            warning="Turning static MPLS off deletes every static binding.",
        ),
        Setting(
            key="segment_routing",
            label="Turn on segment routing",
            line="feature mpls segment-routing",
            group="Turn MPLS on",
            help="Labels handed out from a block, for Layer 3 VPNs. Not while VXLAN or "
            "static MPLS is on.",
            warning="Turning segment routing off deletes its settings and prefix SIDs.",
        ),
        Setting(
            key="l3vpn",
            label="Turn on Layer 3 VPNs",
            line="feature mpls l3vpn",
            group="Turn MPLS on",
            help="After segment routing, with BGP on (Features page). Cisco's guide asks "
            "for the VPN Fabric licence.",
            warning="Turning Layer 3 VPNs off stops every VPN route between switches.",
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
            help="Take labelled packets on this interface. Not on a subinterface, nor on "
            "the interface a tunnel ends on.",
        ),
    ),
)


def _sid_field() -> Field:
    return Field(
        "sid",
        "Index or label",
        "int",
        minimum=0,
        maximum=BLOCK_MAX,
        hint=f"An index (0 to {INDEX_MAX}) counts from the start of the global block; an "
        f"absolute label is {BLOCK_MIN} to {BLOCK_MAX}",
        placeholder="10",
    )


def _check_block(values: dict[str, str]) -> None:
    if int(values["high"]) <= int(values["low"]):
        raise ValueError("the block's last label must be higher than its first")


_SEGMENT_ROUTING = Scope(
    key="sr",
    label="Segment routing",
    ident=(),
    enter=("segment-routing", "mpls"),
    create=True,
    create_label="Start segment routing",
    delete=("no segment-routing",),
    delete_warning="Every segment routing setting goes, with the MPLS settings that hang on "
    "it, and labelled traffic through this switch stops.",
    help="Turn on segment routing under Switch-wide first. Starting it takes the default "
    f"global block, {BLOCK_MIN} to 23999.",
    settings=(
        Setting(
            key="global_block",
            label="Global block",
            line="global-block {low} {high}",
            group="Labels",
            fields=(
                Field("low", "First label", "int", minimum=BLOCK_MIN, maximum=BLOCK_MAX),
                Field("high", "Last label", "int", minimum=BLOCK_MIN, maximum=BLOCK_MAX),
            ),
            check=_check_block,
            help="The labels segment routing hands out; the same block on every switch of "
            "the network. Removing it goes back to 16000 to 23999.",
            warning="Changing the global block restarts BGP: traffic stops for a few seconds.",
        ),
    ),
)

_PREFIX_SID = Scope(
    key="prefix_sid",
    label="Prefix SID",
    ident=(
        Field(
            "prefix",
            "Prefix",
            "prefix4",
            hint="An IPv4 prefix of this switch, usually a loopback's: 192.0.2.1/32",
            placeholder="192.0.2.1/32",
        ),
        Field("kind", "Given as", "choice", choices=("index", "absolute")),
        _sid_field(),
    ),
    enter=(
        "segment-routing",
        "mpls",
        "connected-prefix-sid-map",
        "address-family ipv4",
        "{prefix} {kind} {sid}",
    ),
    create=True,
    create_label="Add a prefix SID",
    delete=(
        "segment-routing",
        "mpls",
        "connected-prefix-sid-map",
        "address-family ipv4",
        "no {prefix} {kind} {sid}",
    ),
    delete_warning="Other switches stop reaching this prefix by its label.",
    help="The label other switches use to reach a prefix of this switch. A label outside "
    "the global block is not handed to the routing protocols.",
)

_VPN_VRF = Scope(
    key="vrf",
    label="VPN VRF",
    ident=(vrf_field(optional=False),),
    enter=("vrf context {vrf}",),
    help="A VRF whose routes a Layer 3 VPN carries. Make the VRF on the Routing page; "
    "add its address family to BGP on the BGP page.",
    settings=(
        Setting(
            key="rd",
            label="Route distinguisher",
            line="rd {target}",
            no_line="no rd {target}",
            group="Route distinguisher",
            fields=(target_field(),),
            check=check_target,
            help="Keeps this VRF's routes apart from other VRFs' in BGP. auto works it out "
            "from BGP's router ID and the VRF's number.",
            warning="Changing the route distinguisher withdraws the VRF's routes and sends "
            "them again.",
        ),
    ),
)


def _check_vpn_target(values: dict[str, str]) -> None:
    check_target(values)
    if values.get("target") == "auto":
        raise ValueError("auto is for EVPN route-targets; give ASN:number such as 65000:100")


def _vpn_target(key: str, way: str, help_text: str) -> Setting:
    return Setting(
        key=key,
        label=f"Route-target {way}ed",
        line=f"route-target {way} {{target}}",
        group="Route-targets",
        fields=(target_field(),),
        check=_check_vpn_target,
        help=help_text,
    )


_VPN_TARGETS = Scope(
    key="vrf_af",
    label="VPN route-targets",
    ident=(
        vrf_field(optional=False),
        Field("af", "Address family", "choice", choices=("ipv4", "ipv6")),
    ),
    enter=("vrf context {vrf}", "address-family {af} unicast"),
    help="Which VPN routes come into the VRF and which leave it. Use the same values on "
    "the switches at the other ends of the VPN. EVPN route-targets are on the VXLAN page.",
    settings=(
        _vpn_target(
            "rt_import", "import", "VPN routes carrying this route-target are taken into the VRF."
        ),
        _vpn_target("rt_export", "export", "Routes sent from the VRF carry this route-target."),
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
class VpnVrf:
    """A VRF's Layer 3 VPN lines: its route distinguisher and, per address family, the
    route-targets it imports and exports (the ``evpn`` ones are left to the VXLAN page)."""

    name: str
    rd: str = ""
    # (address family "ipv4" or "ipv6", imported, exported)
    targets: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = ()


@dataclass(frozen=True)
class MplsConfig:
    """The MPLS lines of the running configuration."""

    label_range: str = ""
    interfaces: tuple[str, ...] = ()
    # (family, label, prefix, next-hop lines)
    bindings: tuple[tuple[str, str, str, tuple[str, ...]], ...] = ()
    segment_routing: bool = False  # the segment-routing block, with its mpls part
    global_block: str = ""  # "16000 23999" when set
    # (prefix, "index" or "absolute", number)
    prefix_sids: tuple[tuple[str, str, str], ...] = ()
    vrfs: tuple[VpnVrf, ...] = ()


_LOCAL = re.compile(r"local-label (\d+) prefix (\S+)(?: (\d+\.\d+\.\d+\.\d+))?(?: (next-hop .+))?")
_SID = re.compile(r"(\S+?)(?: (\d+\.\d+\.\d+\.\d+))? (index|absolute) (\d+)")
_VPN_TARGET = re.compile(r"route-target (import|export) (\S+)")


def _bindings(tree: Any) -> tuple[tuple[str, str, str, tuple[str, ...]], ...]:
    bindings = []
    if "mpls static configuration" not in tree.children():
        return ()
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
    return tuple(bindings)


def _segment_routing(tree: Any) -> tuple[bool, str, tuple[tuple[str, str, str], ...]]:
    """Whether the segment-routing block has its mpls part, its global block and the
    prefix SIDs. NX-OS before 9.3(1) wrote the first two lines as one, ``segment-routing
    mpls``; both forms are read."""
    top = tree.children()
    if "segment-routing" in top and "mpls" in tree.children("segment-routing"):
        base: tuple[str, ...] = ("segment-routing", "mpls")
    elif "segment-routing mpls" in top:
        base = ("segment-routing mpls",)
    else:
        return False, "", ()
    block = next(
        (
            line.split(" ", 1)[1]
            for line in tree.children(*base)
            if line.startswith("global-block ")
        ),
        "",
    )
    sids = []
    for family in tree.children(*base, "connected-prefix-sid-map"):
        if family.split() != ["address-family", "ipv4"]:
            continue
        for line in tree.children(*base, "connected-prefix-sid-map", family):
            if match := _SID.fullmatch(line):
                sids.append(
                    (_prefix(match.group(1), match.group(2) or ""), match.group(3), match.group(4))
                )
    return True, block, tuple(sids)


def _vpn_vrfs(tree: Any) -> tuple[VpnVrf, ...]:
    found = []
    for line in dict.fromkeys(tree.children()):  # a VRF is listed once, however it is printed
        if not line.startswith("vrf context ") or line == "vrf context management":
            continue
        name = line.split(" ", 2)[2]
        rd = next(
            (child[3:] for child in tree.children(line) if child.startswith("rd ")),
            "",
        )
        targets = []
        for af_line in tree.children(line):
            af = re.fullmatch(r"address-family (ipv4|ipv6) unicast", af_line)
            if not af:
                continue
            ways: dict[str, list[str]] = {"import": [], "export": []}
            for child in tree.children(line, af_line):
                if match := _VPN_TARGET.fullmatch(child):
                    ways[match.group(1)].append(match.group(2))
            targets.append((af.group(1), tuple(ways["import"]), tuple(ways["export"])))
        found.append(VpnVrf(name, rd, tuple(targets)))
    return tuple(found)


def parse_mpls_config(config: str) -> MplsConfig:
    """The label range, the interfaces with ``mpls ip forwarding``, the static bindings,
    the segment routing block and its prefix SIDs, and each VRF's route distinguisher and
    route-targets in ``show running-config``."""
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
    segment_routing, block, sids = _segment_routing(tree)
    return MplsConfig(
        label_range, interfaces, _bindings(tree), segment_routing, block, sids, _vpn_vrfs(tree)
    )


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


def licence_installed(body: Any) -> bool | None:
    """Whether ``show license usage`` lists the VPN Fabric licence as installed; None when
    it does not list it."""
    for row in table_rows(body, "TABLE_show_lic_usage", "ROW_show_lic_usage"):
        if text(row.get("feature_name")) == LICENCE:
            return text(row.get("lic_installed")).lower() == "yes"
    return None


def _state(on: bool) -> str:
    return "on" if on else "off"


def _vpn_places(vrfs: tuple[VpnVrf, ...]) -> list[Instance]:
    places = []
    for vrf in vrfs:
        places.append(
            Instance(
                "vrf",
                {"vrf": vrf.name},
                f"VRF {vrf.name}",
                (("Route distinguisher", vrf.rd or "not set"),),
                {"rd": {"target": vrf.rd}} if vrf.rd else {},
            )
        )
        for af, imported, exported in vrf.targets:
            values = {}
            if imported:
                values["rt_import"] = {"target": imported[0]}
            if exported:
                values["rt_export"] = {"target": exported[0]}
            places.append(
                Instance(
                    "vrf_af",
                    {"vrf": vrf.name, "af": af},
                    f"VRF {vrf.name}, {af.replace('ipv', 'IPv')} unicast",
                    (
                        ("Imported", ", ".join(imported) or "none"),
                        ("Exported", ", ".join(exported) or "none"),
                    ),
                    values,
                )
            )
    return places


def parse_mpls(
    switching: Any,
    config: str | None,
    feature_set: str,
    static_on: bool,
    *,
    sr_on: bool = False,
    l3vpn_on: bool = False,
    licence: bool | None = None,
) -> ProtocolView:
    """The page from ``show mpls switching``, the configuration text (None when it could
    not be read), the feature set's state, whether static MPLS, segment routing and Layer 3
    VPNs are on, and whether the VPN Fabric licence is installed (None: not listed)."""
    parsed = parse_mpls_config(config or "")
    switch_values: dict[str, dict[str, str]] = {}
    if feature_set in ("installed", "enabled", "disabled"):
        switch_values["install"] = {"on": "yes"}
    if feature_set == "enabled":
        switch_values["feature_set"] = {"on": "yes"}
    for key, on in (("static", static_on), ("segment_routing", sr_on), ("l3vpn", l3vpn_on)):
        if on:
            switch_values[key] = {"on": "yes"}
    if parsed.label_range:
        words = parsed.label_range.split()
        found = {"low": words[0], "high": words[1] if len(words) > 1 else ""}
        if len(words) >= 4 and words[2] == "static":
            found |= {"static_low": words[3], "static_high": words[4] if len(words) > 4 else ""}
        switch_values["label_range"] = found
    switch_facts = [
        ("MPLS feature set", feature_set or "not listed"),
        ("Static MPLS", _state(static_on)),
        ("Segment routing", _state(sr_on)),
        ("Layer 3 VPNs", _state(l3vpn_on)),
        ("Label range", parsed.label_range or "the switch's default"),
    ]
    if licence is not None:
        switch_facts.append(("VPN Fabric licence", "installed" if licence else "not installed"))
    places = [
        Instance("switch", {}, "Switch-wide", tuple(switch_facts), switch_values),
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
    if parsed.segment_routing:
        block = parsed.global_block.split()
        places.append(
            Instance(
                "sr",
                {},
                "Segment routing",
                (
                    (
                        "Global block",
                        " to ".join(block) if block else f"{BLOCK_MIN} to 23999 (the default)",
                    ),
                    ("Prefix SIDs", str(len(parsed.prefix_sids))),
                ),
                {"global_block": {"low": block[0], "high": block[1]}} if len(block) == 2 else {},
            )
        )
    places += [
        Instance(
            "prefix_sid",
            {"prefix": prefix, "kind": kind, "sid": sid},
            f"{prefix}: {kind} {sid}",
        )
        for prefix, kind, sid in parsed.prefix_sids
    ]
    if l3vpn_on:
        places += _vpn_places(parsed.vrfs)
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
    labels_on = static_on or sr_on
    tables = (
        Table(
            "Labels in use",
            ("In label", "Out label", "Prefix", "Out interface", "Next hop"),
            rows,
            empty="No label is in use."
            if labels_on
            else "Static MPLS and segment routing are off.",
            note="Read when the page loads.",
        ),
    )
    notes: tuple[str, ...] = ()
    if (labels_on or l3vpn_on) and config is None:
        notes = ("The switch did not show the MPLS settings to NXray's account.",)
    if l3vpn_on and licence is False:
        notes = (*notes, NO_LICENCE)
    return ProtocolView(tuple(places), tables, notes)


MPLS = Protocol(
    key="mpls",
    name="MPLS",
    summary="MPLS labels: static bindings, or segment routing for Layer 3 VPNs",
    features=(),
    commands=COMMANDS,
    parse=lambda bodies: parse_mpls(bodies[0] if bodies else None, None, "", False),
    scopes=(
        _SWITCH,
        _INTERFACE,
        _BINDING,
        _SEGMENT_ROUTING,
        _PREFIX_SID,
        _VPN_VRF,
        _VPN_TARGETS,
    ),
    about=(
        "Turn MPLS on under Switch-wide, then go one of two ways. Static labels: set the "
        "label range, turn on MPLS forwarding on the interfaces that carry labels, then add "
        "a binding for each label. Layer 3 VPNs: turn on segment routing and Layer 3 VPNs, "
        "start segment routing and give this switch's loopback a prefix SID, turn on MPLS "
        "forwarding on the interfaces towards the other switches, set each VPN VRF's route "
        "distinguisher and route-targets, then on the BGP page add the VPN address family "
        "and the neighbors (labelled unicast for the labels, VPN for the routes, with "
        "extended communities sent) and the VRF's address family."
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
    sr_on: bool = False
    l3vpn_on: bool = False
    vrfs: tuple[str, ...] = ()  # the VRFs made on the switch, without default and management


def load_mpls_page(client: NxapiClient) -> MplsPage:
    """One request for the features, interfaces, VRFs and licences, the feature set's state
    as text; while static MPLS or segment routing is on, the labels in use; while either or
    Layer 3 VPNs are on, the configuration text."""
    feature, brief, vrf_body, vrf_members, licences = client.show(*PAGE_COMMANDS)
    members = parse_vrf_members(vrf_members)
    interfaces = layer3_interfaces(brief, members)
    vrfs = tuple(
        v.name for v in parse_vrfs(vrf_body, members) if v.name not in ("default", "management")
    )
    states = feature_states(feature)
    try:
        feature_set = parse_feature_set(client.show_text(SET_COMMAND))
    except NxapiCommandError:
        feature_set = ""
    static_on = states.get(FEATURE, False)
    sr_on = states.get(SR_FEATURE, False)
    l3vpn_on = states.get(L3VPN_FEATURE, False)
    problem = ""
    if not (static_on or sr_on) and any(states.get(name, False) for name in VXLAN_FEATURES):
        problem = VXLAN_ON
    switching = config = None
    if static_on or sr_on:
        try:
            (switching,) = client.show(*COMMANDS)
        except NxapiCommandError as exc:
            problem = f"The switch did not report the labels in use: {exc}"
    if static_on or sr_on or l3vpn_on:
        try:
            config = client.show_text(CONFIG_COMMAND)
        except NxapiCommandError:
            config = None
    view = parse_mpls(
        switching,
        config,
        feature_set,
        static_on,
        sr_on=sr_on,
        l3vpn_on=l3vpn_on,
        licence=licence_installed(licences),
    )
    return MplsPage(MPLS, view, interfaces, static_on, problem, (), sr_on, l3vpn_on, vrfs)


def check_mpls_place(page: MplsPage, ident: dict[str, str]) -> None:
    """Refuse bindings while static MPLS is off, interfaces while static MPLS and segment
    routing are off, prefix SIDs while segment routing is off, VPN VRFs while Layer 3 VPNs
    are off; and an interface or VRF the switch lacks, and a prefix SID out of range."""
    if "label" in ident and not page.static_on:
        raise ValueError(_refusal(STATIC_OFF))
    interface = ident.get("interface", "").strip()
    if interface and not (page.static_on or page.sr_on):
        raise ValueError(_refusal(LABELS_OFF))
    if "sid" in ident:
        if not page.sr_on:
            raise ValueError(_refusal(SR_OFF))
        sid = ident.get("sid", "").strip()
        if sid.isdigit() and ident.get("kind") == "index" and int(sid) > INDEX_MAX:
            raise ValueError(f"an index is 0 to {INDEX_MAX}")
        if sid.isdigit() and ident.get("kind") == "absolute" and int(sid) < BLOCK_MIN:
            raise ValueError(f"an absolute label is {BLOCK_MIN} to {BLOCK_MAX}")
    vrf = ident.get("vrf", "").strip()
    if vrf:
        if not page.l3vpn_on:
            raise ValueError(_refusal(L3VPN_OFF))
        if vrf not in page.vrfs:
            known = ", ".join(page.vrfs) or "none yet"
            raise ValueError(
                f"the switch has no VRF {vrf} for a VPN (made on the Routing page: {known})"
            )
    if interface and interface not in page.interfaces:
        known = ", ".join(page.interfaces) or "none"
        raise ValueError(
            f"{interface} is not a VLAN interface (up to Vlan254), routed port or routed "
            f"port-channel on the switch; those are: {known}"
        )


def _refusal(message: str) -> str:
    """'Static MPLS is off: ... first.' as the end of 'Not changed: ...'. A name with a
    number in it keeps its capital ("Layer 3 VPNs are off")."""
    first, _, rest = message.rstrip(".").partition(" ")
    return f"{first if rest[:1].isdigit() else first.lower()} {rest}"


def build_mpls_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the MPLS page."""
    return build_change(MPLS, scope, setting, action, ident, values)
