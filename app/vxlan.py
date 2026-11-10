"""VXLAN and EVPN: carry VLANs across a routed network between switches.

The VXLAN page is described with the same parts as the routing protocol pages
(``app/protocols.py``): scopes (the whole switch, a VLAN, the NVE interface, its member
VNIs, the EVPN settings of a VNI, a VRF), each setting the one configuration line it
sends with checked values in its blanks, and ``build_change`` building the lines.
``NxapiClient.configure_vxlan`` sends them.

A VXLAN switch needs, in this order:

1. the ``nve`` (``nv overlay``) and ``vnseg_vlan`` (``vn-segment-vlan-based``) features,
   turned on on the Features page;
2. for EVPN, ``nv overlay evpn`` on the switch (and BGP with the l2vpn evpn address
   family, on the Routing protocols page);
3. a VNI on each VLAN that crosses the fabric: ``vlan 10`` then ``vn-segment 10010``;
4. the NVE interface ``nve1``: ``source-interface loopback0`` (the address the other
   switches send VXLAN traffic to) and, for EVPN, ``host-reachability protocol bgp``;
5. each VNI as a member of ``nve1``: ``member vni 10010``, with ``suppress-arp``,
   ``mcast-group`` or ``ingress-replication`` for how it floods; a VNI that routes
   between VLANs (a layer 3 VNI) is ``member vni 50000 associate-vrf`` and the VRF
   names it: ``vrf context tenant`` then ``vni 50000``;
6. for EVPN, the VNI's route distinguisher and route-targets (``evpn`` then
   ``vni 10010 l2``), and ``route-target both auto evpn`` in the VRF's address families.

Read from the switch: ``show feature``, ``show vlan brief`` and ``show vrf`` in one
request; then, while the features are on, ``show nve interface``, ``show nve peers`` and
``show nve vni``. The settings that are configured come from ``show running-config``,
which NX-API gives only as text (``NxapiClient.show_text``) and only once NXray's role
allows it (it has since role version 12); without it the page still shows everything the
``show nve`` commands report. The whole configuration is read because NX-OS 9.3 splits
the VXLAN lines over filters (``show running-config nv overlay`` has the NVE interface,
``vlan`` the ``vn-segment`` lines, ``vrf`` the ``vni`` lines, only ``bgp`` or a pipe the
``evpn`` block, and ``nv overlay evpn`` is in none of them), and there is no
``show running-config vxlan``.

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-10) with throwaway objects, all removed
afterwards: every line the page sends, its ``no`` form, and the JSON of ``show nve
interface`` and ``show nve vni``. Not tried: ``show nve peers`` (no peer exists), the
role rules (the fake switch stands in), ``suppress-arp`` data-plane use (it needs a TCAM
carve and a reload), and EVPN with a real BGP neighbor. The ``evpn`` block and the VRF
route-targets need ``feature bgp`` first; the switch refuses them without it.
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
    source_field,
    table_rows,
    vrf_field,
)
from app.switch import text

VNI_MAX = 16777215  # a VNI is 24 bits
NVE_MAX = 1  # NX-OS 9.3 has one NVE interface, nve1
COMMANDS = ("show nve interface", "show nve peers", "show nve vni")
CONFIG_COMMAND = "show running-config"
PAGE_COMMANDS = ("show feature", "show vlan brief", "show vrf")
ADDRESS_FAMILIES = ("ipv4", "ipv6")

# A route distinguisher or route-target: auto, ASN:number or address:number.
_TARGET = re.compile(r"^(?:auto|[0-9]{1,10}:[0-9]{1,10}|(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5})$")


def _int(name: str, label: str, low: int, high: int, **kw: Any) -> Field:
    return Field(name, label, "int", minimum=low, maximum=high, **kw)


def _vni_field(label: str = "VNI", hint: str = "") -> Field:
    return _int(
        "vni",
        label,
        1,
        VNI_MAX,
        hint=hint or "1 to 16777215; the same number on every switch the segment reaches",
    )


def _nve_field() -> Field:
    return _int("nve", "NVE interface", 1, NVE_MAX, hint="nve1: the switch has one")


def _target_field(label: str = "Value") -> Field:
    return Field(
        "target",
        label,
        "text",
        maximum=31,
        hint="auto, or ASN:number such as 65000:10010, or address:number",
        placeholder="auto",
    )


def _check_target(values: dict[str, str]) -> None:
    value = values.get("target", "")
    if not _TARGET.fullmatch(value):
        raise ValueError("the value is auto, ASN:number (65000:10010) or address:number")


# ---- settings -------------------------------------------------------------------------

_SWITCH = Scope(
    key="switch",
    label="EVPN and anycast gateway",
    ident=(),
    enter=(),
    help="Switch-wide lines. Turn the nve and vnseg_vlan features on first (Features page).",
    settings=(
        Setting(
            key="evpn",
            label="EVPN control plane",
            line="nv overlay evpn",
            group="EVPN",
            help=(
                "Lets BGP carry the VXLAN hosts and networks (EVPN) instead of the switches "
                "learning them by flooding. Needs the nve feature."
            ),
            warning="Turning EVPN off removes every EVPN route this switch has learned.",
        ),
        Setting(
            key="anycast_mac",
            label="Anycast gateway MAC",
            line="fabric forwarding anycast-gateway-mac {mac}",
            no_line="no fabric forwarding anycast-gateway-mac {mac}",
            group="EVPN",
            fields=(
                Field(
                    "mac",
                    "MAC address",
                    "mac",
                    hint="One address for every switch of the fabric, such as 2020.0000.00aa",
                    placeholder="2020.0000.00aa",
                ),
            ),
            help=(
                "The MAC address every switch answers with for a gateway address that exists "
                "on all of them. Needs the fabric forwarding feature (Features page)."
            ),
        ),
    ),
)

_VLAN = Scope(
    key="vlan",
    label="VLAN to VNI",
    ident=(Field("vlan", "VLAN", "vlan", hint="A VLAN made on the VLANs page"),),
    enter=("vlan {vlan}",),
    help=(
        "Give a VLAN the VNI that carries it across the fabric. Make the VLAN on the VLANs "
        "page first."
    ),
    settings=(
        Setting(
            key="vni",
            label="VNI",
            line="vn-segment {vni}",
            no_line="no vn-segment {vni}",
            fields=(_vni_field(),),
            help="The VXLAN segment this VLAN is carried in.",
            warning="Changing a VLAN's VNI drops its VXLAN traffic until the other switches agree.",
        ),
    ),
)

_NVE = Scope(
    key="nve",
    label="NVE interface",
    ident=(_nve_field(),),
    enter=("interface nve{nve}",),
    create=True,
    create_label="Make the NVE interface",
    delete=("no interface nve{nve}",),
    delete_warning=(
        "Deleting the NVE interface ends every VXLAN tunnel this switch has: the VLANs "
        "carried in VNIs stop reaching the other switches."
    ),
    help="The tunnel end of this switch. A switch has one, nve1.",
    settings=(
        Setting(
            key="source_interface",
            label="Source interface",
            line="source-interface {source}",
            no_line="no source-interface {source}",
            group="Tunnel",
            fields=(
                source_field(
                    "source",
                    "Loopback or interface",
                ),
            ),
            help=(
                "Its address is where the other switches send VXLAN traffic to, so give it a "
                "loopback that the routing protocols advertise."
            ),
            warning="Changing the source interface ends the tunnels until the peers learn it.",
        ),
        Setting(
            key="host_reachability",
            label="Host reachability through BGP",
            line="host-reachability protocol bgp",
            group="Tunnel",
            help="Learn the hosts behind other switches from EVPN (BGP) instead of flooding.",
        ),
        Setting(
            key="advertise_vmac",
            label="Advertise the virtual MAC",
            line="advertise virtual-rmac",
            group="Tunnel",
            help="Advertise the virtual router MAC of a vPC pair, so the pair acts as one VTEP.",
        ),
        Setting(
            key="admin_up",
            label="Turn on",
            line="no shutdown",
            group="State",
            removable=False,
            help="Bring the NVE interface up.",
        ),
        Setting(
            key="admin_down",
            label="Turn off",
            line="shutdown",
            group="State",
            removable=False,
            help="Take the NVE interface down.",
            warning="Turning the NVE interface off ends every VXLAN tunnel this switch has.",
        ),
        Setting(
            key="global_suppress_arp",
            label="Suppress ARP for every VNI",
            line="global suppress-arp",
            group="For every VNI",
            help="Answer ARP requests from the switch's own table instead of flooding them.",
        ),
        Setting(
            key="global_ingress",
            label="Ingress replication through BGP for every VNI",
            line="global ingress-replication protocol bgp",
            group="For every VNI",
            help="Send flooded traffic to each peer in turn, as BGP lists the peers.",
        ),
        Setting(
            key="global_mcast",
            label="Multicast group for every VNI",
            line="global mcast-group {group} {layer}",
            no_line="no global mcast-group {layer}",
            group="For every VNI",
            fields=(
                Field("group", "Multicast group", "maddr4", placeholder="239.1.1.1"),
                Field("layer", "For", "choice", choices=("L2", "L3"), hint="L2 VNIs or L3 VNIs"),
            ),
            help="Send flooded traffic to this multicast group.",
        ),
    ),
)

_L2VNI = Scope(
    key="l2vni",
    label="L2 VNI of the NVE interface",
    ident=(_nve_field(), _vni_field()),
    enter=("interface nve{nve}", "member vni {vni}"),
    create=True,
    create_label="Add a layer 2 VNI",
    delete=("interface nve{nve}", "no member vni {vni}"),
    delete_warning="The VLAN of this VNI stops reaching the other switches.",
    help=(
        "A VNI that carries a VLAN, which a VLAN to VNI line above ties to the VLAN. Add "
        "it to the NVE interface here."
    ),
    settings=(
        Setting(
            key="suppress_arp",
            label="Suppress ARP",
            line="suppress-arp",
            group="Flooding",
            help="Answer ARP requests in this VNI from the switch's own table.",
        ),
        Setting(
            key="mcast_group",
            label="Multicast group",
            line="mcast-group {group}",
            no_line="no mcast-group {group}",
            group="Flooding",
            fields=(Field("group", "Multicast group", "maddr4", placeholder="239.1.1.1"),),
            help="Send this VNI's flooded traffic to the group.",
        ),
        Setting(
            key="ingress",
            label="Ingress replication through BGP",
            line="ingress-replication protocol bgp",
            group="Flooding",
            help="Send this VNI's flooded traffic to each peer BGP lists.",
        ),
    ),
)

_L3VNI = Scope(
    key="l3vni",
    label="L3 VNI of the NVE interface",
    ident=(_nve_field(), _vni_field()),
    enter=("interface nve{nve}", "member vni {vni} associate-vrf"),
    create=True,
    create_label="Add a layer 3 VNI",
    delete=("interface nve{nve}", "no member vni {vni} associate-vrf"),
    delete_warning="Routing between the VLANs of this VRF across the fabric stops.",
    help=(
        "A VNI that routes between the VLANs of one VRF. Name it in the VRF below and add it "
        "here with the same number. The switch needs host reachability through BGP on the "
        "NVE interface first."
    ),
)

_EVPN = Scope(
    key="evpn",
    label="EVPN settings of an L2 VNI",
    ident=(_vni_field(),),
    enter=("evpn", "vni {vni} l2"),
    create=True,
    create_label="Make the EVPN settings of a VNI",
    delete=("evpn", "no vni {vni} l2"),
    delete_warning="BGP stops advertising this VNI's hosts.",
    help=(
        "How EVPN names the VNI's routes. Use auto for both and the switches work the "
        "route distinguisher and route-targets out from the BGP AS number and the VNI. "
        "The switch takes these only while the bgp feature is on and EVPN is turned on above."
    ),
    settings=(
        Setting(
            key="rd",
            label="Route distinguisher",
            line="rd {target}",
            no_line="no rd {target}",
            group="Route distinguisher and route-targets",
            fields=(_target_field(),),
            check=_check_target,
            help="Marks this VNI's routes as its own. auto works it out.",
        ),
        Setting(
            key="rt_import",
            label="Route-target imported",
            line="route-target import {target}",
            no_line="no route-target import {target}",
            group="Route distinguisher and route-targets",
            fields=(_target_field(),),
            check=_check_target,
            help="Routes carrying this target are taken into the VNI.",
        ),
        Setting(
            key="rt_export",
            label="Route-target exported",
            line="route-target export {target}",
            no_line="no route-target export {target}",
            group="Route distinguisher and route-targets",
            fields=(_target_field(),),
            check=_check_target,
            help="Routes sent from this VNI carry this target.",
        ),
    ),
)

_VRF = Scope(
    key="vrf",
    label="VRF of an L3 VNI",
    ident=(vrf_field(optional=False),),
    enter=("vrf context {vrf}",),
    help="Name the layer 3 VNI that routes this VRF across the fabric. Make the VRF first.",
    settings=(
        Setting(
            key="vni",
            label="Layer 3 VNI",
            line="vni {vni}",
            no_line="no vni {vni}",
            fields=(_vni_field("Layer 3 VNI"),),
            help="The VNI that carries this VRF's routed traffic. Add it to the NVE interface too.",
            warning=(
                "Changing the VRF's VNI stops its routed traffic across the fabric for a moment."
            ),
        ),
    ),
)

_VRF_AF = Scope(
    key="vrf_af",
    label="EVPN route-targets of a VRF",
    ident=(
        vrf_field(optional=False),
        Field("af", "Address family", "choice", choices=ADDRESS_FAMILIES),
    ),
    enter=("vrf context {vrf}", "address-family {af} unicast"),
    help=(
        "Which routes of the VRF go into EVPN and which come out of it. The switch takes "
        "these only while the bgp feature is on and EVPN is turned on above."
    ),
    settings=(
        Setting(
            key="rt_both_auto",
            label="Import and export through EVPN (auto)",
            line="route-target both auto evpn",
            help="The route-targets are worked out from the BGP AS number and the layer 3 VNI.",
        ),
        Setting(
            key="rt_import",
            label="Route-target imported through EVPN",
            line="route-target import {target} evpn",
            no_line="no route-target import {target} evpn",
            fields=(_target_field(),),
            check=_check_target,
            help="Routes carrying this target are taken into the VRF.",
        ),
        Setting(
            key="rt_export",
            label="Route-target exported through EVPN",
            line="route-target export {target} evpn",
            no_line="no route-target export {target} evpn",
            fields=(_target_field(),),
            check=_check_target,
            help="Routes sent from the VRF carry this target.",
        ),
    ),
)


# ---- the configuration text ---------------------------------------------------------------


@dataclass(frozen=True)
class VxlanConfig:
    """The VXLAN lines of the running configuration, as a tree: each entry is the lines it
    sits under and its own line."""

    entries: tuple[tuple[tuple[str, ...], str], ...] = ()

    def children(self, *path: str) -> list[str]:
        """The lines directly under ``path`` (empty path: the top-level lines)."""
        return [line for parents, line in self.entries if parents == path]

    def has(self, *path: str) -> bool:
        return bool(path) and path[-1] in self.children(*path[:-1])


def parse_vxlan_config(config: str) -> VxlanConfig:
    """``show running-config vxlan`` text as a tree by its indentation."""
    entries: list[tuple[tuple[str, ...], str]] = []
    stack: list[tuple[int, str]] = []
    for raw in config.splitlines():
        line = raw.strip()
        if not line or line.startswith("!"):
            continue
        indent = len(raw) - len(raw.lstrip())
        while stack and stack[-1][0] >= indent:
            stack.pop()
        entries.append((tuple(item[1] for item in stack), line))
        stack.append((indent, line))
    return VxlanConfig(tuple(entries))


# Lines with no value in them: shown under "Turned on", since a setting with no blanks has
# no value to mark it as set.
_NVE_FLAGS = {
    "host-reachability protocol bgp": "Host reachability through BGP",
    "advertise virtual-rmac": "Advertise the virtual MAC",
    "global suppress-arp": "Suppress ARP for every VNI",
    "global ingress-replication protocol bgp": "Ingress replication for every VNI",
}
_MEMBER_FLAGS = {
    "suppress-arp": "Suppress ARP",
    "ingress-replication protocol bgp": "Ingress replication through BGP",
}


def _turned_on(lines: list[str], flags: dict[str, str]) -> str:
    return ", ".join(name for line, name in flags.items() if line in lines)


def _nve_values(lines: list[str]) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    for line in lines:
        if match := re.fullmatch(r"source-interface (\S+)(?: .*)?", line):
            values["source_interface"] = {"source": match.group(1)}
        elif match := re.fullmatch(r"global mcast-group (\S+)(?: (L[23]))?", line):
            values["global_mcast"] = {"group": match.group(1), "layer": match.group(2) or "L2"}
    return values


def _member_values(lines: list[str]) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    for line in lines:
        if match := re.fullmatch(r"mcast-group (\S+)", line):
            values["mcast_group"] = {"group": match.group(1)}
    return values


def _target_values(lines: list[str]) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    for line in lines:
        if match := re.fullmatch(r"rd (\S+)", line):
            values.setdefault("rd", {"target": match.group(1)})
        elif match := re.fullmatch(r"route-target import (\S+)(?: evpn)?", line):
            values.setdefault("rt_import", {"target": match.group(1)})
        elif match := re.fullmatch(r"route-target export (\S+)(?: evpn)?", line):
            values.setdefault("rt_export", {"target": match.group(1)})
    return values


# ---- reading `show nve` -------------------------------------------------------------------


def _first(row: dict[str, Any], *keys: str) -> str:
    """The first of ``keys`` the row has, as text ('' for none)."""
    for key in keys:
        if value := text(row.get(key)):
            return value
    return ""


def _number(name: str) -> str:
    """'nve1' -> '1' ('' when the name is not an NVE interface)."""
    match = re.fullmatch(r"(?i)nve\s*([0-9]+)", name.strip())
    return match.group(1) if match else ""


def _nve_rows(body: Any) -> list[dict[str, Any]]:
    """The rows of ``show nve interface``: its table when it has one, else the answer
    itself when it describes one interface."""
    if not isinstance(body, dict):
        return []
    for table, row in (("TABLE_nve_if", "ROW_nve_if"), ("TABLE_nve", "ROW_nve")):
        if found := table_rows(body, table, row):
            return found
    return [body] if _first(body, "interface", "if-name") else []


def _joined(*parts: str) -> str:
    return " ".join(p for p in parts if p)


def _l3(kind: str) -> bool:
    return kind.strip().upper().startswith("L3")


def parse_vxlan(bodies: list[dict[str, Any]], config: VxlanConfig | None = None) -> ProtocolView:
    """The NVE interface, its peers and VNIs from ``show nve interface``, ``show nve
    peers`` and ``show nve vni`` (``bodies``), and the configured settings from
    ``config`` (None: NXray's role cannot read them yet)."""
    padded = [*bodies, {}, {}, {}][:3]
    interface_rows = _nve_rows(padded[0])
    peer_rows = table_rows(padded[1], "TABLE_nve_peers", "ROW_nve_peers")
    vni_rows = table_rows(padded[2], "TABLE_nve_vni", "ROW_nve_vni")
    instances: list[Instance] = []
    configured = config if config is not None else VxlanConfig()

    # The NVE interfaces, from the configuration and the interfaces the switch reports.
    numbers = [
        n
        for line in configured.children()
        if (m := re.fullmatch(r"interface (nve[0-9]+)", line)) and (n := _number(m.group(1)))
    ]
    reported = {_number(_first(r, "interface", "if-name")): r for r in interface_rows}
    reported.pop("", None)
    for number in dict.fromkeys([*numbers, *reported]):
        row = reported.get(number, {})
        lines = configured.children(f"interface nve{number}")
        facts: list[tuple[str, str]] = []
        for label, keys in (
            ("State", ("state", "nve-state", "if-state")),
            ("Source interface", ("source-if", "source-interface")),
            ("Source address", ("primary-ip", "source-ip")),
            ("Source interface state", ("source-if-state",)),
            ("Encapsulation", ("encap-type", "encapsulation")),
            ("Host reachability", ("host-reach-mode",)),
            ("Advertise virtual MAC", ("adv-vmac",)),
            ("Virtual router MAC", ("vip-rmac", "virtual-router-mac")),
        ):
            if value := _first(row, *keys):
                facts.append((label, value))
        if config is not None:
            facts.append(("Admin state", "on" if "no shutdown" in lines else "off"))
            facts.append(("Turned on", _turned_on(lines, _NVE_FLAGS) or "none of the on/off lines"))
        instances.append(
            Instance(
                "nve",
                {"nve": number},
                f"nve{number}",
                tuple(facts),
                _nve_values(lines) if config is not None else {},
            )
        )

    # VLANs with a VNI, from the configuration.
    if config is not None:
        # The full configuration lists a VLAN once in the VLAN list and once with its lines.
        for line in dict.fromkeys(configured.children()):
            vlan = re.fullmatch(r"vlan ([0-9]+)", line)
            if not vlan:
                continue
            for child in configured.children(line):
                if segment := re.fullmatch(r"vn-segment ([0-9]+)", child):
                    instances.append(
                        Instance(
                            "vlan",
                            {"vlan": vlan.group(1)},
                            f"VLAN {vlan.group(1)}",
                            (("VNI", segment.group(1)),),
                            {"vni": {"vni": segment.group(1)}},
                        )
                    )

    # Member VNIs: the configuration's, then those only `show nve vni` lists.
    reported_vnis: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in vni_rows:
        vni = _first(row, "vni")
        number = _number(_first(row, "if-name", "interface")) or (numbers[0] if numbers else "1")
        kind = "l3vni" if _l3(_first(row, "type")) else "l2vni"
        if vni.isdigit():
            reported_vnis[(kind, number, vni)] = row
    members: dict[tuple[str, str, str], list[str]] = {}
    for number in numbers:
        for line in configured.children(f"interface nve{number}"):
            if member := re.fullmatch(r"member vni ([0-9]+)( associate-vrf)?", line):
                kind = "l3vni" if member.group(2) else "l2vni"
                members[(kind, number, member.group(1))] = configured.children(
                    f"interface nve{number}", line
                )
    for key in dict.fromkeys([*members, *reported_vnis]):
        kind, number, vni = key
        row = reported_vnis.get(key, {})
        lines = members.get(key, [])
        facts = []
        for label, keys in (
            ("State", ("vni-state",)),
            ("Mode", ("mode",)),
            ("Multicast group", ("mcast",)),
            ("VLAN or VRF", ("bd-vrf", "vlan")),
            ("Flags", ("flags",)),
        ):
            if value := _first(row, *keys):
                facts.append((label, value))
        if config is not None and kind == "l2vni":
            facts.append(
                ("Turned on", _turned_on(lines, _MEMBER_FLAGS) or "none of the on/off lines")
            )
        instances.append(
            Instance(
                kind,
                {"nve": number, "vni": vni},
                f"VNI {vni} on nve{number}",
                tuple(facts),
                _member_values(lines) if config is not None else {},
            )
        )

    if config is not None:
        # The EVPN block, the VRFs' VNIs and their route-targets.
        for line in configured.children("evpn"):
            if match := re.fullmatch(r"vni ([0-9]+) l2", line):
                lines = configured.children("evpn", line)
                instances.append(
                    Instance(
                        "evpn",
                        {"vni": match.group(1)},
                        f"VNI {match.group(1)}",
                        (),
                        _target_values(lines),
                    )
                )
        for line in configured.children():
            if not (vrf := re.fullmatch(r"vrf context (\S+)", line)):
                continue
            name = vrf.group(1)
            children = configured.children(line)
            if segment := next(
                (m for c in children if (m := re.fullmatch(r"vni ([0-9]+)", c))), None
            ):
                instances.append(
                    Instance(
                        "vrf",
                        {"vrf": name},
                        f"VRF {name}",
                        (("Layer 3 VNI", segment.group(1)),),
                        {"vni": {"vni": segment.group(1)}},
                    )
                )
            for child in children:
                if family := re.fullmatch(r"address-family (ipv[46]) unicast", child):
                    inside = configured.children(line, child)
                    if any(item.startswith("route-target ") for item in inside):
                        instances.append(
                            Instance(
                                "vrf_af",
                                {"vrf": name, "af": family.group(1)},
                                f"VRF {name}, {family.group(1)}",
                                (
                                    (
                                        "Route-targets",
                                        "; ".join(
                                            i for i in inside if i.startswith("route-target ")
                                        ),
                                    ),
                                ),
                                _target_values(inside),
                            )
                        )

    notes: list[str] = []
    if config is not None:
        notes.append(
            "The EVPN control plane is on."
            if configured.has("nv overlay evpn")
            else "The EVPN control plane is off."
        )
    if config is None:
        notes.append(
            "NXray's role on the switch does not let it read the VXLAN settings yet, so only "
            "what the switch reports about its tunnels is shown: an NXray admin turns on VXLAN "
            "changes on the Switch page."
        )
    peers = tuple(
        (
            _first(r, "if-name", "interface") or "-",
            _first(r, "peer-ip", "peer-ipv4") or "-",
            _first(r, "peer-state", "state") or "-",
            _first(r, "learn-type") or "-",
            _first(r, "uptime") or "-",
            _first(r, "router-mac") or "-",
        )
        for r in peer_rows
    )
    vnis = tuple(
        (
            _first(r, "if-name", "interface") or "-",
            _first(r, "vni") or "-",
            _first(r, "type") or "-",
            _first(r, "mode") or "-",
            _first(r, "vni-state") or "-",
            _first(r, "mcast") or "-",
            _first(r, "bd-vrf", "vlan") or "-",
        )
        for r in vni_rows
    )
    tables = (
        Table(
            "Peers",
            ("Interface", "Peer", "State", "Learned by", "Up for", "Router MAC"),
            peers,
            empty="No peers. Another switch shows here once its tunnel to this one is up.",
        ),
        Table(
            "VNIs",
            ("Interface", "VNI", "Type", "Mode", "State", "Multicast group", "VLAN or VRF"),
            vnis,
            empty="No VNI on the NVE interface. Add one below.",
        ),
    )
    return ProtocolView(tuple(instances), tables, tuple(notes))


VXLAN = Protocol(
    key="vxlan",
    name="VXLAN",
    summary="Carry VLANs across a routed network between switches, with EVPN (BGP) or by flooding",
    features=("nve", "vnseg_vlan"),
    commands=COMMANDS,
    parse=parse_vxlan,
    scopes=(_SWITCH, _VLAN, _NVE, _L2VNI, _L3VNI, _EVPN, _VRF, _VRF_AF),
    about=(
        "Set up in this order: turn on the nve and vnseg_vlan features, give each VLAN that "
        "crosses the fabric a VNI, make the NVE interface with its source loopback, add the "
        "VNIs to it, and for EVPN turn the EVPN control plane on and set the VNIs' route "
        "distinguishers and route-targets. Do the same on every switch of the fabric, with "
        "the same VNIs."
    ),
)


# ---- the page -----------------------------------------------------------------------------


@dataclass(frozen=True)
class VxlanPage:
    """Everything the VXLAN page shows."""

    protocol: Protocol
    view: ProtocolView
    vlans: tuple[str, ...]  # the VLANs on the switch, as text
    vrfs: tuple[str, ...]  # default, management and the VRFs made on the switch
    problem: str = ""
    missing: tuple[str, ...] = ()  # the features still off (show feature names)

    @property
    def on(self) -> bool:
        return not self.missing


def _vrf_names(body: dict[str, Any]) -> tuple[str, ...]:
    names = [text(r.get("vrf_name")) for r in table_rows(body, "TABLE_vrf", "ROW_vrf")]
    rest = sorted(n for n in names if n and n not in ("default", "management"))
    return ("default", "management", *rest)


def _vlan_numbers(body: dict[str, Any]) -> tuple[str, ...]:
    numbers = []
    for row in table_rows(body, "TABLE_vlanbriefxbrief", "ROW_vlanbriefxbrief"):
        value = text(row.get("vlanshowbr-vlanid"))
        if value.isdigit() and int(value) <= 3967:
            numbers.append(int(value))
    return tuple(str(n) for n in sorted(numbers))


def load_vxlan_page(client: NxapiClient) -> VxlanPage:
    """One request for the features, VLANs and VRFs; while the features are on, one for
    the ``show nve`` commands and one for the configuration text NXray may read."""
    feature, vlan_body, vrf_body = client.show(*PAGE_COMMANDS)
    states = feature_states(feature)
    missing = tuple(name for name in VXLAN.features if not states.get(name, False))
    vlans = _vlan_numbers(vlan_body)
    vrfs = _vrf_names(vrf_body)
    if missing:
        return VxlanPage(VXLAN, ProtocolView(), vlans, vrfs, missing=missing)
    problem = ""
    try:
        bodies = client.show(*COMMANDS)
    except NxapiCommandError as exc:
        # Before the NVE interface is made the switch can refuse `show nve`; the page
        # still offers the settings.
        bodies = [{}, {}, {}]
        problem = f"The switch did not report VXLAN's state: {exc}"
    try:
        config: VxlanConfig | None = parse_vxlan_config(client.show_text(CONFIG_COMMAND))
    except NxapiCommandError:
        config = None  # the role predates the rule that allows it
    return VxlanPage(VXLAN, parse_vxlan(bodies, config), vlans, vrfs, problem)


def build_vxlan_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the VXLAN page."""
    return build_change(VXLAN, scope, setting, action, ident, values)
