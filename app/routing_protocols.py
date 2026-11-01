"""The Routing protocols pages: which protocols NXray offers, reading one from the
switch, and the switch's whole route table.

Each protocol is described in its own module (``app/protocols_*.py``, built on
``app/protocols.py``); this module lists them in the order the pages show them
and reads what a page needs:

- the overview: ``show feature`` (which protocols are on), ``show ip route vrf
  all`` and ``show ipv6 route vrf all`` (every route the switch uses, from every
  source: connected networks, static routes and each protocol);
- one protocol's page: ``show feature``, ``show interface brief`` and ``show
  vrf`` (for the interface and VRF choices) in one request, then, when the
  protocol's features are on, the protocol's own show commands in a second.

A protocol whose feature is off is not read: the switch answers its show
commands with "% Invalid command" then. Its page says which feature to turn on
on the Features page.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.features import CATALOG, feature_states
from app.nxapi import VLAN_INTERFACE_MAX, NxapiClient, NxapiCommandError
from app.protocols import (
    Protocol,
    ProtocolChange,
    ProtocolView,
    build_change,
    route_age,
    table_rows,
    text,
)
from app.protocols_bgp import PROTOCOLS as _BGP
from app.protocols_fhrp import PROTOCOLS as _FHRP
from app.protocols_igp import PROTOCOLS as _IGP
from app.protocols_multicast import PROTOCOLS as _MULTICAST
from app.protocols_ospf import PROTOCOLS as _OSPF
from app.protocols_policy import PROTOCOLS as _POLICY
from app.routing import parse_brief, parse_vrf_members, parse_vrfs

ALL_PROTOCOLS: tuple[Protocol, ...] = (*_OSPF, *_BGP, *_IGP, *_FHRP, *_MULTICAST, *_POLICY)

OVERVIEW_COMMANDS = ("show feature", "show ip route vrf all", "show ipv6 route vrf all")
PAGE_COMMANDS = ("show feature", "show interface brief", "show vrf", "show vrf interface")


def protocol(key: str) -> Protocol | None:
    """The protocol a page key names (``ospf``, ``bgp``, ``policy``), or None."""
    return next((p for p in ALL_PROTOCOLS if p.key == key), None)


def build_protocol_change(
    key: str,
    scope: str,
    setting: str,
    action: str,
    ident: dict[str, str],
    values: dict[str, str],
) -> ProtocolChange:
    """The checked lines for one change on a protocol's page, or ValueError.

    ``NxapiClient.configure_protocol`` calls this itself, so the lines it sends
    can only come from the protocols' own descriptions.
    """
    found = protocol(key)
    if found is None:
        raise ValueError(f"NXray has no routing protocol page {key!r}")
    return build_change(found, scope, setting, action, ident, values)


def feature_command(name: str) -> str:
    """The word typed after ``feature`` for a ``show feature`` name (hsrp_engine -> hsrp)."""
    info = CATALOG.get(name)
    return info.command if info is not None and info.command else name


# ---- the route table -------------------------------------------------------------


@dataclass(frozen=True)
class Route:
    """One route the switch uses, with every path (next hop) it has for it."""

    vrf: str
    prefix: str
    source: str  # "direct", "local", "static", "ospf-core", "bgp-65001", ...
    next_hops: tuple[str, ...]
    distance: str
    metric: str
    age: str

    @property
    def ipv6(self) -> bool:
        return ":" in self.prefix


def parse_routes(body: dict[str, Any]) -> list[Route]:
    """Every route in ``show ip route vrf all`` or ``show ipv6 route vrf all``.

    One row per destination; its paths are the next hops (an address, an
    interface, or both). The best path's distance, metric and age are shown.
    """
    found = []
    for vrf_row in table_rows(body, "TABLE_vrf", "ROW_vrf"):
        vrf = text(vrf_row.get("vrf-name-out")) or "default"
        for family in table_rows(vrf_row, "TABLE_addrf", "ROW_addrf"):
            for row in table_rows(family, "TABLE_prefix", "ROW_prefix"):
                prefix = text(row.get("ipprefix"))
                paths = table_rows(row, "TABLE_path", "ROW_path")
                if not prefix or not paths:
                    continue
                hops = []
                for path in paths:
                    via = text(path.get("ipnexthop"))
                    interface = text(path.get("ifname"))
                    hops.append(" on ".join(x for x in (via, interface) if x) or "—")
                best = next((p for p in paths if text(p.get("ubest")) == "true"), paths[0])
                found.append(
                    Route(
                        vrf=vrf,
                        prefix=prefix,
                        source=text(best.get("clientname")),
                        next_hops=tuple(hops),
                        distance=text(best.get("pref")),
                        metric=text(best.get("metric")),
                        age=route_age(text(best.get("uptime"))),
                    )
                )
    return found


# ---- the overview ----------------------------------------------------------------


@dataclass(frozen=True)
class ProtocolState:
    protocol: Protocol
    missing: tuple[str, ...]  # the features still off (show feature names)

    @property
    def on(self) -> bool:
        return not self.missing


@dataclass(frozen=True)
class ProtocolsOverview:
    states: list[ProtocolState] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)

    @property
    def vrfs(self) -> list[str]:
        """The VRFs that have routes, default first."""
        return sorted({r.vrf for r in self.routes}, key=lambda v: (v != "default", v))


def _missing(proto: Protocol, states: dict[str, bool]) -> tuple[str, ...]:
    return tuple(name for name in proto.features if not states.get(name, False))


def load_overview(client: NxapiClient) -> ProtocolsOverview:
    """Which protocols are on, and the route table: one request."""
    feature, ip4, ip6 = client.show(*OVERVIEW_COMMANDS)
    states = feature_states(feature)
    return ProtocolsOverview(
        states=[ProtocolState(p, _missing(p, states)) for p in ALL_PROTOCOLS],
        routes=[*parse_routes(ip4), *parse_routes(ip6)],
    )


# ---- one protocol's page -----------------------------------------------------------


@dataclass(frozen=True)
class ProtocolPage:
    protocol: Protocol
    missing: tuple[str, ...] = ()
    view: ProtocolView | None = None
    interfaces: tuple[str, ...] = ()  # the layer 3 interfaces NXray may set protocols on
    vrfs: tuple[str, ...] = ("default",)  # default and the VRFs made on the switch
    problem: str = ""  # why the protocol's own output could not be read

    @property
    def on(self) -> bool:
        return not self.missing


def _layer3_interfaces(brief: dict[str, Any], members: dict[str, str]) -> tuple[str, ...]:
    """VLAN interfaces up to Vlan254 and routed front ports and port-channels,
    never one in the management VRF."""
    svis, routed = parse_brief(brief)
    names = [n for n in svis if int(n[4:]) <= VLAN_INTERFACE_MAX] + [
        text(r.get("interface")) for r in routed
    ]
    return tuple(n for n in names if members.get(n, "default") != "management")


def load_protocol_page(client: NxapiClient, proto: Protocol) -> ProtocolPage:
    """Everything one protocol's page shows: one request, and one more when it is on."""
    feature, brief, vrf_body, vrf_members = client.show(*PAGE_COMMANDS)
    missing = _missing(proto, feature_states(feature))
    members = parse_vrf_members(vrf_members)
    vrfs = tuple(v.name for v in parse_vrfs(vrf_body, members) if v.name != "management")
    interfaces = _layer3_interfaces(brief, members)
    if missing or not proto.commands:
        view = None if missing else proto.parse([])
        return ProtocolPage(proto, missing, view, interfaces, vrfs)
    try:
        bodies = client.show(*proto.commands)
    except NxapiCommandError as exc:
        # A feature turned on a moment ago can refuse its show commands for a
        # few seconds; the page still offers its settings.
        problem = f"The switch did not report {proto.name}'s state: {exc}"
        return ProtocolPage(proto, missing, ProtocolView(), interfaces, vrfs, problem)
    return ProtocolPage(proto, missing, proto.parse(bodies), interfaces, vrfs)
