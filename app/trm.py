"""Multicast over VXLAN EVPN: tenant routed multicast (TRM), which routes the tenants'
multicast between the switches of a VXLAN EVPN fabric, with BGP carrying who wants which
group (the ``ngmvpn`` feature, next-generation multicast VPN).

On top of a working VXLAN EVPN fabric (the VXLAN page: the NVE interface with host
reachability through BGP, a layer 3 VNI per VRF), TRM needs, in the order of Cisco's
guide:

1. ``feature ngmvpn`` (Features page) and IGMP snooping in the VXLAN VLANs (``ip igmp
   snooping vxlan``, on the IGMP snooping page);
2. a multicast group for each layer 3 VNI (``member vni <n> associate-vrf`` then
   ``mcast-group <group>``) and, in each VRF, ``ip multicast multipath s-g-hash
   next-hop-based`` and the MVPN route-targets (``route-target both auto mvpn`` in its
   ``address-family ipv4 unicast``);
3. the ``ipv4 mvpn`` address family on the BGP neighbors, with extended communities sent
   (the BGP page, Protocols), and a rendezvous point in each VRF (the PIM page);
4. for the switch-wide choices: ``ip multicast overlay-spt-only`` (on by default),
   ``ip multicast overlay-distributed-dr`` and ``advertise evpn multicast`` for layer 2
   TRM and the mixed mode, ``ip pim evpn-border-leaf`` on an anycast border leaf, and
   ``advertise-pip`` in the BGP ``l2vpn evpn`` family for vPC border leafs.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes, each setting the one line it sends with checked values in
its blanks, and ``build_change`` building the lines. ``NxapiClient.configure_trm`` sends
them.

Read from the switch: ``show feature`` and ``show vrf`` in one request, and ``show
running-config`` as text, where the TRM lines, the NVE interface's layer 3 VNIs, the VRFs'
VNIs and route-targets and the BGP process are read.

Cisco's NX-OS 9.3 VXLAN guide lists the Nexus 9200 for layer 3 TRM and as an anchor DR
in the mixed mode. Tried on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-13), all
removed and the feature turned back off: ``feature ngmvpn`` was taken, and with it ``ip
multicast overlay-spt-only`` (on by default, not written), ``ip multicast
overlay-distributed-dr``, ``advertise evpn multicast``, in a VRF ``ip multicast multipath
s-g-hash next-hop-based``, and on the NVE interface ``mcast-routing override
source-interface <loopback>``. The switch refuses the MVPN route-targets without BGP and
EVPN, and a layer 3 VNI without host reachability through BGP ("Cannot configure associate
vrf for vni without host reachability protocol bgp"); those lines, ``mcast-group`` on a
layer 3 VNI, the BGP ``ipv4 mvpn`` and ``l2vpn evpn`` lines, ``advertise-pip`` and ``ip pim
evpn-border-leaf`` follow the guide and were not tried on a switch.
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
    vrf_field,
)
from app.switch_admin import vrf_choices
from app.vxlan import NVE_MAX, VNI_MAX, check_target, parse_vxlan_config, target_field

FEATURE = "ngmvpn"
VXLAN_FEATURE = "nve"
PAGE_COMMANDS = ("show feature", "show vrf")
CONFIG_COMMAND = "show running-config"
BGP_FAMILIES = ("ipv4 mvpn", "l2vpn evpn")
PATHS_MAX = 64

VXLAN_OFF = (
    "VXLAN (feature nv overlay) is off: multicast over VXLAN runs on a VXLAN EVPN fabric. "
    "Set VXLAN up on the VXLAN page first."
)


def _nve() -> Field:
    return Field(
        "nve", "NVE interface", "int", minimum=1, maximum=NVE_MAX, hint="nve1: the switch has one"
    )


def _vni() -> Field:
    return Field(
        "vni",
        "Layer 3 VNI",
        "int",
        minimum=1,
        maximum=VNI_MAX,
        hint="A layer 3 VNI of the NVE interface, made on the VXLAN page",
    )


_GLOBAL = Scope(
    key="global",
    label="Whole switch",
    ident=(),
    enter=(),
    help="Multicast over VXLAN for the whole switch.",
    settings=(
        Setting(
            "overlay_spt_only",
            "Shortest path only across the fabric",
            "ip multicast overlay-spt-only",
            group="Fabric",
            help="On by default once ngmvpn is on: sources' traffic takes the shortest path "
            "between the switches, not the RP's shared tree. Remove turns it off.",
        ),
        Setting(
            "overlay_distributed_dr",
            "Distributed designated router",
            "ip multicast overlay-distributed-dr",
            group="Fabric",
            help="For layer 2 and layer 3 TRM together (the mixed mode): every switch acts as "
            "designated router for its own hosts.",
            warning="Cisco: shut the NVE interface and turn it on again afterwards for it to "
            "count, which stops VXLAN traffic for a moment.",
        ),
        Setting(
            "advertise_evpn_multicast",
            "Advertise multicast in EVPN",
            "advertise evpn multicast",
            group="Fabric",
            help="For layer 2 TRM and the mixed mode: BGP tells the other switches which "
            "groups the hosts here joined.",
        ),
        Setting(
            "evpn_border_leaf",
            "Anycast border leaf",
            "ip pim evpn-border-leaf",
            group="Border",
            help="This switch is one of the border leafs sharing the fabric's rendezvous "
            "point address. Needs the pim feature.",
        ),
    ),
)

_NVE = Scope(
    key="nve",
    label="NVE interface",
    ident=(_nve(),),
    enter=("interface nve{nve}",),
    help="The NVE interface, made on the VXLAN page.",
    settings=(
        Setting(
            "mcast_override",
            "Multicast source interface",
            "mcast-routing override source-interface {source}",
            (source_field("source", "Loopback"),),
            group="Multicast",
            help="Send the tenants' multicast from this loopback's address instead of the NVE "
            "interface's own (Cisco's mixed mode, with an anchor DR).",
        ),
    ),
)

_L3VNI = Scope(
    key="l3vni",
    label="Layer 3 VNI",
    ident=(_nve(), _vni()),
    enter=("interface nve{nve}", "member vni {vni} associate-vrf"),
    help="A layer 3 VNI of the NVE interface: its VRF's multicast crosses the fabric in "
    "this group.",
    settings=(
        Setting(
            "mcast_group",
            "Multicast group",
            "mcast-group {group}",
            (Field("group", "Group", "maddr4", placeholder="239.3.3.3"),),
            no_line="no mcast-group {group}",
            group="Multicast",
            help="Cisco: a group of its own, not one an L2 VNI or another VRF uses.",
        ),
    ),
)

_VRF = Scope(
    key="vrf",
    label="VRF",
    ident=(vrf_field(optional=False),),
    enter=("vrf context {vrf}",),
    help="A tenant VRF with a layer 3 VNI. Its rendezvous point is set on the PIM page.",
    settings=(
        Setting(
            "s_g_hash",
            "Spread flows by source, group and next hop",
            "ip multicast multipath s-g-hash next-hop-based",
            group="Multicast",
            help="Cisco asks for it in every TRM VRF: equal paths are chosen per source, "
            "group and next hop.",
        ),
    ),
)

_VRF_AF = Scope(
    key="vrf_af",
    label="MVPN route-targets of a VRF",
    ident=(vrf_field(optional=False),),
    enter=("vrf context {vrf}", "address-family ipv4 unicast"),
    help="Which multicast routes of the VRF BGP carries (TRM is IPv4 only). The switch "
    "takes these only while BGP and EVPN are on.",
    settings=(
        Setting(
            "rt_both_auto",
            "Import and export through MVPN (auto)",
            "route-target both auto mvpn",
            group="Route-targets",
            help="Worked out from the BGP AS number and the layer 3 VNI.",
        ),
        Setting(
            "rt_import",
            "Route-target imported through MVPN",
            "route-target import {target} mvpn",
            (target_field(),),
            check=check_target,
            group="Route-targets",
        ),
        Setting(
            "rt_export",
            "Route-target exported through MVPN",
            "route-target export {target} mvpn",
            (target_field(),),
            check=check_target,
            group="Route-targets",
        ),
    ),
)

_BGP_AF = Scope(
    key="bgp_af",
    label="BGP overlay address family",
    ident=(
        Field("asn", "AS number", "asn", hint="The BGP process's AS number", placeholder="65001"),
        Field(
            "af",
            "Address family",
            "choice",
            choices=BGP_FAMILIES,
            hint="ipv4 mvpn: multicast routes; l2vpn evpn: the EVPN routes",
        ),
    ),
    enter=("router bgp {asn}", "address-family {af}"),
    create=True,
    create_label="Add an overlay address family to BGP",
    delete=("router bgp {asn}", "no address-family {af}"),
    delete_warning="BGP stops carrying these routes for the whole fabric.",
    help="The BGP process's own MVPN or EVPN family. Each neighbor's family is set on the BGP "
    "page (Protocols), with extended communities sent.",
    settings=(
        Setting(
            "advertise_pip",
            "Advertise the primary address",
            "advertise-pip",
            group="vPC",
            help="l2vpn evpn only: a vPC border leaf advertises its own address as well as "
            "the pair's, as Cisco asks for TRM with vPC border leafs (with Advertise the "
            "virtual MAC on the VXLAN page).",
        ),
        Setting(
            "retain_rt",
            "Keep every route-target",
            "retain route-target all",
            group="Spine",
            help="On a spine with no VRFs of its own: keep the routes for every route-target "
            "to pass on.",
        ),
        Setting(
            "maximum_paths",
            "Most paths",
            "maximum-paths {paths}",
            (
                Field(
                    "paths",
                    "Paths",
                    "int",
                    minimum=1,
                    maximum=PATHS_MAX,
                    hint=f"1 to {PATHS_MAX}",
                ),
            ),
            group="Spine",
            help="Cisco: with an eBGP underlay, on spines when the leafs share one AS.",
        ),
    ),
)

SCOPES = (_GLOBAL, _NVE, _L3VNI, _VRF, _VRF_AF, _BGP_AF)

# ---- reading ---------------------------------------------------------------------------------

_GLOBAL_LINES = {
    "ip multicast overlay-distributed-dr": "overlay_distributed_dr",
    "advertise evpn multicast": "advertise_evpn_multicast",
    "ip pim evpn-border-leaf": "evpn_border_leaf",
}


@dataclass(frozen=True)
class TrmConfig:
    """The TRM lines of the running configuration and what they sit on."""

    global_values: dict[str, dict[str, str]]
    nves: dict[str, dict[str, dict[str, str]]]  # NVE number -> values
    l3vnis: dict[tuple[str, str], str]  # (NVE number, VNI) -> its multicast group ("" none)
    vrfs: dict[str, dict[str, Any]]  # VRF -> {"vni", "values", "af_values"}
    asn: str  # the BGP process's AS number, "" without one
    bgp_afs: dict[str, dict[str, dict[str, str]]]  # family -> values


def parse_trm_config(config: str, ngmvpn_on: bool = True) -> TrmConfig:
    """The TRM lines of ``show running-config``. ``ngmvpn_on``: overlay-spt-only is on by
    default and written only as ``no ip multicast overlay-spt-only``."""
    tree = parse_vxlan_config(config)
    top = tree.children()
    global_values: dict[str, dict[str, str]] = {}
    if ngmvpn_on and "no ip multicast overlay-spt-only" not in top:
        global_values["overlay_spt_only"] = {}
    for line, key in _GLOBAL_LINES.items():
        if line in top:
            global_values[key] = {}
    nves: dict[str, dict[str, dict[str, str]]] = {}
    l3vnis: dict[tuple[str, str], str] = {}
    vrfs: dict[str, dict[str, Any]] = {}
    asn, bgp_afs = "", {}
    for line in top:
        if match := re.fullmatch(r"interface nve(\d+)", line):
            number = match.group(1)
            values: dict[str, dict[str, str]] = {}
            for inner in tree.children(line):
                if found := re.fullmatch(r"mcast-routing override source-interface (\S+)", inner):
                    values["mcast_override"] = {"source": found.group(1)}
                elif found := re.fullmatch(r"member vni (\d+) associate-vrf", inner):
                    groups = [
                        g.split()[1]
                        for g in tree.children(line, inner)
                        if g.startswith("mcast-group ")
                    ]
                    l3vnis[(number, found.group(1))] = groups[0] if groups else ""
            nves[number] = values
        elif match := re.fullmatch(r"vrf context (\S+)", line):
            entry = vrfs.setdefault(match.group(1), {"vni": "", "values": {}, "af_values": {}})
            for inner in tree.children(line):
                if found := re.fullmatch(r"vni (\d+)", inner):
                    entry["vni"] = found.group(1)
                elif inner == "ip multicast multipath s-g-hash next-hop-based":
                    entry["values"]["s_g_hash"] = {}
                elif inner == "address-family ipv4 unicast":
                    for rt in tree.children(line, inner):
                        if rt == "route-target both auto mvpn":
                            entry["af_values"]["rt_both_auto"] = {}
                        elif found := re.fullmatch(r"route-target (import|export) (\S+) mvpn", rt):
                            entry["af_values"].setdefault(
                                f"rt_{found.group(1)}", {"target": found.group(2)}
                            )
        elif match := re.fullmatch(r"router bgp (\S+)", line):
            asn = match.group(1)
            for inner in tree.children(line):
                if found := re.fullmatch(r"address-family (ipv4 mvpn|l2vpn evpn)", inner):
                    af_values: dict[str, dict[str, str]] = {}
                    for item in tree.children(line, inner):
                        if item == "advertise-pip":
                            af_values["advertise_pip"] = {}
                        elif item == "retain route-target all":
                            af_values["retain_rt"] = {}
                        elif paths := re.fullmatch(r"maximum-paths (\d+)", item):
                            af_values["maximum_paths"] = {"paths": paths.group(1)}
                    bgp_afs[found.group(1)] = af_values
    return TrmConfig(global_values, nves, l3vnis, vrfs, asn, bgp_afs)


def _on(values: dict[str, Any], key: str) -> str:
    return "on" if key in values else "off"


def parse_trm(config: str | None, ngmvpn_on: bool = True) -> ProtocolView:
    """The page from the configuration text (None when the switch did not show it)."""
    if config is None:
        return ProtocolView(
            (Instance("global", {}, "Whole switch"),),
            (),
            (
                "The switch did not show its configuration to NXray's account, where the "
                "multicast over VXLAN settings are read.",
            ),
        )
    found = parse_trm_config(config, ngmvpn_on)
    facts = tuple(
        (setting.label, _on(found.global_values, setting.key)) for setting in _GLOBAL.settings
    )
    instances = [Instance("global", {}, "Whole switch", facts, found.global_values)]
    for number, values in found.nves.items():
        instances.append(Instance("nve", {"nve": number}, f"nve{number}", (), values))
    by_vni = {entry["vni"]: name for name, entry in found.vrfs.items() if entry["vni"]}
    rows = []
    for (number, vni), group in found.l3vnis.items():
        vrf = by_vni.get(vni, "")
        values = {"mcast_group": {"group": group}} if group else {}
        instances.append(
            Instance(
                "l3vni",
                {"nve": number, "vni": vni},
                f"Layer 3 VNI {vni}",
                (("VRF", vrf or "none names it"), ("Multicast group", group or "none")),
                values,
            )
        )
        entry = found.vrfs.get(vrf, {"values": {}, "af_values": {}})
        targets = ", ".join(
            name
            for key, name in (
                ("rt_both_auto", "auto"),
                ("rt_import", "import"),
                ("rt_export", "export"),
            )
            if key in entry["af_values"]
        )
        rows.append(
            (
                vni,
                vrf or "-",
                group or "-",
                "yes" if "s_g_hash" in entry["values"] else "no",
                targets or "none",
            )
        )
    for name, entry in found.vrfs.items():
        if not entry["vni"]:
            continue
        instances.append(
            Instance(
                "vrf",
                {"vrf": name},
                f"VRF {name}",
                (("Layer 3 VNI", entry["vni"]),),
                entry["values"],
            )
        )
        instances.append(
            Instance(
                "vrf_af", {"vrf": name}, f"VRF {name}: MVPN route-targets", (), entry["af_values"]
            )
        )
    for af, values in found.bgp_afs.items():
        instances.append(
            Instance(
                "bgp_af", {"asn": found.asn, "af": af}, f"BGP AS {found.asn}: {af}", (), values
            )
        )
    table = Table(
        "Layer 3 VNIs",
        ("VNI", "VRF", "Multicast group", "Spread by source and group", "MVPN route-targets"),
        tuple(rows),
        empty="The NVE interface has no layer 3 VNI yet: add one on the VXLAN page.",
    )
    return ProtocolView(tuple(instances), (table,))


TRM = Protocol(
    key="trm",
    name="Multicast over VXLAN",
    summary="Tenant routed multicast across a VXLAN EVPN fabric",
    features=(FEATURE,),
    commands=(),
    parse=lambda bodies: parse_trm(None),
    scopes=SCOPES,
    about=(
        "Give each layer 3 VNI a multicast group, spread each VRF's flows and give it the "
        "MVPN route-targets, then add the ipv4 mvpn family to the BGP neighbors (BGP page) "
        "and a rendezvous point in each VRF (PIM page). IGMP snooping must be on in the "
        "VXLAN VLANs (IGMP snooping page)."
    ),
)


@dataclass(frozen=True)
class TrmPage:
    """Everything the Multicast over VXLAN page shows."""

    protocol: Protocol
    view: ProtocolView
    vrfs: tuple[str, ...]
    problem: str = ""
    missing: tuple[str, ...] = ()  # the ngmvpn feature, when it is off
    asn: str = ""  # the BGP process's AS number, "" without one (or unread)


def load_trm_page(client: NxapiClient) -> TrmPage:
    """One request for the features and VRFs; while ngmvpn is on, the configuration text."""
    feature, vrf_body = client.show(*PAGE_COMMANDS)
    states = feature_states(feature)
    vrfs = vrf_choices(vrf_body)
    problem = "" if states.get(VXLAN_FEATURE, False) else VXLAN_OFF
    if not states.get(FEATURE, False):
        return TrmPage(TRM, ProtocolView(), vrfs, problem, (FEATURE,))
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = None
    asn = parse_trm_config(config).asn if config is not None else ""
    return TrmPage(TRM, parse_trm(config), vrfs, problem, asn=asn)


def check_trm_place(page: TrmPage, ident: dict[str, str]) -> None:
    """Refuse a VRF the switch does not have, an NVE interface or layer 3 VNI the VXLAN page
    has not made (entering one would make it), and an AS number other than the BGP
    process's."""
    vrf = ident.get("vrf", "").strip()
    if vrf and vrf not in page.vrfs:
        raise ValueError(f"the switch has no VRF {vrf}; make it on the Routing page first")
    nve = ident.get("nve", "").strip()
    if nve and not page.view.of("nve"):
        raise ValueError("the switch has no NVE interface; make it on the VXLAN page first")
    vni = ident.get("vni", "").strip()
    if vni and not any(i.ident.get("vni") == vni for i in page.view.of("l3vni")):
        raise ValueError(f"nve1 has no layer 3 VNI {vni}; add it on the VXLAN page first")
    asn = ident.get("asn", "").strip()
    if asn:
        if not page.asn:
            raise ValueError("the switch has no BGP process; make it on the BGP page first")
        if asn != page.asn:
            raise ValueError(f"the switch's BGP process is AS {page.asn}, not {asn}")


def build_trm_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Multicast over VXLAN page; advertise-pip is for the l2vpn
    evpn family only."""
    if scope == "bgp_af" and setting == "advertise_pip" and ident.get("af") != "l2vpn evpn":
        raise ValueError("advertise-pip goes in the l2vpn evpn family")
    return build_change(TRM, scope, setting, action, ident, values)
