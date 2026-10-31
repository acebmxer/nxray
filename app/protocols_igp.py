"""EIGRP, RIP and IS-IS: the three interior routing protocols other than OSPF.

What is read: for EIGRP ``show ip eigrp vrf all``, its ``interfaces`` and
``neighbors`` and the IPv6 ``show ipv6 eigrp`` pair; for RIP ``show ip rip vrf
all``, its ``interface`` and ``neighbor`` and the IPv6 pair; for IS-IS ``show
isis vrf all``, ``show isis interface vrf all`` and ``show isis adjacency vrf
all``. Each page lists the processes (per VRF and address family), the
interfaces that run the protocol, and the neighbors it has found.

What can be changed: a process is made and deleted (``router eigrp|rip|isis
TAG``), with its VRF parts and address families; every process line an
operator uses on a Nexus 9300 with NX-OS 9.3 (router ID, redistribution through
a route-map, default route, distance, equal-cost paths, timers, authentication
by key chain, graceful restart, BFD, logging, IS-IS levels and overload bit,
EIGRP stub and metric weights); and each protocol's interface lines (``ip router
eigrp TAG``, ``ip rip ...``, ``isis ...``). Redistribution always goes through
a route-map, which NX-OS requires; route-maps and key chains are made on the
Routing policy page, so here they are only names.

What was tried on the switch (cisco-25gb, NX-OS 9.3(16), as NXray's restricted
account, 2026-10-31): making and deleting all three processes; EIGRP
``autonomous-system``, ``router-id``, ``redistribute static route-map``,
``maximum-paths``, ``address-family ipv6 unicast``; EIGRP interface ``router``,
``passive-interface``, ``hello-interval``, ``hold-time``, ``authentication mode
... md5``, ``authentication key-chain`` and ``summary-address`` lines and their
``no`` forms; RIP ``address-family ipv4|ipv6 unicast`` with ``redistribute``,
``default-information originate``, ``maximum-paths`` and ``timers basic``; RIP
interface ``router``, ``passive-interface``, ``authentication mode md5``,
``authentication key-chain`` and ``metric-offset``; IS-IS ``net``, ``is-type``,
``log-adjacency-changes``, ``authentication-type`` and ``authentication
key-chain`` per level, ``redistribute`` and ``default-information originate
always`` per address family; IS-IS interface ``router``, ``circuit-type``,
``metric``, ``passive-interface``, ``hello-interval``, ``priority`` and
``network point-to-point``. Every other line here follows Cisco's NX-OS 9.3
Unicast Routing Configuration Guide and Configuration Command Reference.
Nothing was plugged into the probe port, so no neighbor was ever seen live:
neighbor (and EIGRP interface) rows are read by the field names Cisco documents
for these commands.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.neighbors import readable_duration
from app.protocols import (
    Field,
    Instance,
    Protocol,
    ProtocolView,
    Scope,
    Setting,
    Table,
    interface_field,
    table_rows,
    text,
    vrf_field,
)
from app.routing import long_name

# ---- fields shared by the three protocols ---------------------------------------

_LEVELS = ("level-1", "level-2")
_LEVELS_BOTH = ("level-1", "level-2", "level-1-2")
_FAMILIES = ("ipv4", "ipv6")
_REDISTRIBUTE_SOURCES = ("static", "direct")
_REDISTRIBUTE_PROTOCOLS = ("bgp", "eigrp", "isis", "ospf", "ospfv3", "rip")


def _tag(label: str = "Process") -> Field:
    return Field(
        "tag",
        label,
        "name",
        maximum=20,
        hint="The process name given when it was made (up to 20 letters and digits)",
        placeholder="core",
    )


def _number(
    name: str,
    label: str,
    low: int,
    high: int,
    optional: bool = False,
    hint: str = "",
    placeholder: str = "",
) -> Field:
    return Field(
        name,
        label,
        "int",
        minimum=low,
        maximum=high,
        optional=optional,
        hint=hint or f"{low} to {high}",
        placeholder=placeholder,
    )


def _choice(
    name: str, label: str, choices: tuple[str, ...], optional: bool = False, hint: str = ""
) -> Field:
    return Field(name, label, "choice", choices=choices, optional=optional, hint=hint)


def _level(optional: bool = False, both: bool = False, name: str = "level") -> Field:
    return _choice(
        name,
        "Level",
        _LEVELS_BOTH if both else _LEVELS,
        optional=optional,
        hint="Leave empty for both levels" if optional else "",
    )


def _route_map(optional: bool = False, name: str = "route_map") -> Field:
    return Field(
        name,
        "Route-map",
        "name",
        optional=optional,
        hint="A route-map made on the Routing policy page",
        placeholder="redistribute-static",
    )


def _key_chain() -> Field:
    return Field(
        "key_chain",
        "Key chain",
        "name",
        hint="A key chain made on the Routing policy page",
        placeholder="routing-keys",
    )


def _list_fields() -> tuple[Field, ...]:
    return (
        _choice("list_kind", "Filter by", ("route-map", "prefix-list")),
        Field("list_name", "Its name", "name", hint="Made on the Routing policy page"),
        _choice("direction", "Direction", ("in", "out"), hint="in: routes heard; out: sent"),
    )


def _redistribution(group: str = "Routes from elsewhere") -> tuple[Setting, ...]:
    """The two redistribute lines; NX-OS takes neither without a route-map."""
    return (
        Setting(
            "redistribute",
            "Redistribute static or connected routes",
            "redistribute {source} route-map {route_map}",
            (
                _choice(
                    "source",
                    "Routes",
                    _REDISTRIBUTE_SOURCES,
                    hint="static: static routes; direct: the switch's own subnets",
                ),
                _route_map(),
            ),
            help="Advertise these routes too, as far as the route-map lets them through.",
            group=group,
        ),
        Setting(
            "redistribute_protocol",
            "Redistribute another protocol",
            "redistribute {protocol} {source_tag} route-map {route_map}",
            (
                _choice(
                    "protocol",
                    "Protocol",
                    _REDISTRIBUTE_PROTOCOLS,
                    hint="ospf for IPv4, ospfv3 for IPv6",
                ),
                Field(
                    "source_tag",
                    "Its process or AS",
                    "name",
                    hint="The other protocol's process name, or the BGP AS number",
                ),
                _route_map(),
            ),
            help="Advertise routes another routing protocol learned.",
            group=group,
        ),
    )


def _redistribute_limit(group: str = "Routes from elsewhere") -> Setting:
    return Setting(
        "redistribute_limit",
        "Limit redistributed routes",
        "redistribute maximum-prefix {maximum} [{threshold}] [{limit_action}]",
        (
            _number("maximum", "Most routes", 1, 65535),
            _number("threshold", "Warn at percent", 1, 100, optional=True, hint="Default 75"),
            _choice(
                "limit_action",
                "When reached",
                ("warning-only", "withdraw"),
                optional=True,
                hint="Empty: refuse more routes",
            ),
        ),
        help="Caps how many routes other protocols can put in.",
        group=group,
    )


def _distance_one(group: str = "Routes") -> Setting:
    return Setting(
        "distance",
        "Administrative distance",
        "distance {distance}",
        (_number("distance", "Distance", 1, 255),),
        help="How much the switch trusts these routes against other protocols' (lower wins).",
        group=group,
    )


def _maximum_paths(high: int, group: str = "Routes") -> Setting:
    return Setting(
        "maximum_paths",
        "Equal-cost paths",
        "maximum-paths {paths}",
        (_number("paths", "Paths", 1, high),),
        help="How many equally good routes to one network are used at once.",
        group=group,
    )


def _default_information(group: str = "Routes") -> Setting:
    return Setting(
        "default_information",
        "Send a default route",
        "default-information originate [{always}] [route-map {route_map}]",
        (
            Field(
                "always",
                "Even without one",
                "flag",
                choices=("always",),
                hint="Send it even when this switch has no default route itself",
            ),
            _route_map(optional=True),
        ),
        help="Tell the neighbors to send everything they have no route for to this switch.",
        group=group,
    )


def _simple(
    key: str,
    label: str,
    line: str,
    help: str = "",
    group: str = "Settings",
    warning: str = "",
) -> Setting:
    return Setting(key, label, line, help=help, group=group, warning=warning)


def _per_family(
    key: str,
    label: str,
    line: str,
    fields: Iterable[Field] = (),
    help: str = "",
    group: str = "Settings",
    families: tuple[str, ...] = ("ip", "ipv6"),
) -> tuple[Setting, ...]:
    """The IPv4 line (``line`` starts with ``ip ``) and its ``ipv6`` twin.

    The IPv4 one keeps ``key``; the IPv6 one gets ``key`` + "6".
    """
    found = []
    for family in families:
        found.append(
            Setting(
                key if family == "ip" else key + "6",
                f"{label} ({'IPv4' if family == 'ip' else 'IPv6'})",
                line if family == "ip" else "ipv6 " + line[3:],
                tuple(fields),
                help=help,
                group=group,
            )
        )
    return tuple(found)


def _router_scopes(
    command: str,
    name: str,
    process_settings: tuple[Setting, ...],
    vrf_settings: tuple[Setting, ...],
    af_settings: tuple[Setting, ...],
    delete_warning: str,
) -> tuple[Scope, Scope, Scope]:
    """A process, its part in a VRF, and an address family of either."""
    process = Scope(
        "process",
        f"{name} process",
        (_tag(),),
        (f"router {command} {{tag}}",),
        process_settings,
        create=True,
        create_label=f"Make an {name} process",
        delete=(f"no router {command} {{tag}}",),
        delete_warning=delete_warning,
        help="Settings for the default VRF.",
    )
    vrf = Scope(
        "vrf",
        f"{name} in a VRF",
        (_tag(), vrf_field(optional=False)),
        (f"router {command} {{tag}}", "[vrf {vrf}]"),
        vrf_settings,
        create=True,
        create_label=f"Run an {name} process in a VRF",
        delete=(f"router {command} {{tag}}", "[no vrf {vrf}]"),
        delete_warning=f"Removes everything this {name} process has in the VRF.",
        help="The same process, routing for another VRF.",
    )
    af = Scope(
        "af",
        f"{name} address family",
        (_tag(), vrf_field(), _choice("af", "Address family", _FAMILIES)),
        (f"router {command} {{tag}}", "[vrf {vrf}]", "address-family {af} unicast"),
        af_settings,
        create=True,
        create_label="Add an address family",
        delete=(f"router {command} {{tag}}", "[vrf {vrf}]", "no address-family {af} unicast"),
        delete_warning="Removes the address family and everything set in it.",
        help="Settings for IPv4 or IPv6 routes only.",
    )
    return process, vrf, af


def _interface_scope(settings: tuple[Setting, ...], help: str) -> Scope:
    return Scope(
        "interface",
        "Interface",
        (interface_field(),),
        ("interface {interface}",),
        settings,
        help=help,
    )


# ---- EIGRP ------------------------------------------------------------------------

_EIGRP_ROUTER = (
    Setting(
        "autonomous_system",
        "Autonomous system",
        "autonomous-system {asn}",
        (_number("asn", "AS number", 1, 65535),),
        help="Neighbors only talk EIGRP inside the same AS number. Needed when the "
        "process name is not a number, and for IPv6.",
        group="Identity",
    ),
    Setting(
        "router_id",
        "Router ID",
        "router-id {router_id}",
        (Field("router_id", "Router ID", "ipv4", placeholder="192.0.2.1"),),
        help="The address this switch calls itself in EIGRP.",
        group="Identity",
    ),
    *_redistribution(),
    _redistribute_limit(),
    _default_information(),
    Setting(
        "default_metric",
        "Metric for redistributed routes",
        "default-metric {bandwidth} {delay} {reliability} {load} {mtu}",
        (
            _number("bandwidth", "Bandwidth (kbit/s)", 1, 2560000000, placeholder="100000"),
            _number("delay", "Delay (tens of microseconds)", 1, 16777215, placeholder="100"),
            _number("reliability", "Reliability (255 = 100%)", 0, 255, placeholder="255"),
            _number("load", "Load (255 = full)", 1, 255, placeholder="1"),
            _number("mtu", "MTU", 1, 65535, placeholder="1492"),
        ),
        help="Routes from other protocols need a metric; this one is used when the "
        "route-map sets none.",
        group="Routes from elsewhere",
    ),
    Setting(
        "distance",
        "Administrative distance",
        "distance {internal} {external}",
        (
            _number("internal", "Internal", 1, 255, hint="Default 90"),
            _number("external", "External", 1, 255, hint="Default 170"),
        ),
        help="How much the switch trusts EIGRP routes (lower wins). External routes are "
        "ones EIGRP redistributed from elsewhere.",
        group="Routes",
    ),
    _maximum_paths(32),
    Setting(
        "metric_weights",
        "Metric weights (K values)",
        "metric weights 0 {k1} {k2} {k3} {k4} {k5} [{k6}]",
        (
            _number("k1", "K1 (bandwidth)", 0, 255, hint="Default 1"),
            _number("k2", "K2 (load)", 0, 255, hint="Default 0"),
            _number("k3", "K3 (delay)", 0, 255, hint="Default 1"),
            _number("k4", "K4 (reliability)", 0, 255, hint="Default 0"),
            _number("k5", "K5 (reliability)", 0, 255, hint="Default 0"),
            _number("k6", "K6 (extended)", 0, 255, optional=True, hint="Default 0"),
        ),
        help="How EIGRP weighs a link. Every neighbor must use the same values.",
        warning="Neighbors with different K values drop their EIGRP sessions.",
        group="Metric",
    ),
    Setting(
        "metric_max_hops",
        "Most hops",
        "metric maximum-hops {hops}",
        (_number("hops", "Hops", 1, 255, hint="Default 100"),),
        help="Routes further away than this are treated as unreachable.",
        group="Metric",
    ),
    _simple(
        "metric_version",
        "Wide (64-bit) metrics",
        "metric version 64bit",
        help="Lets EIGRP tell fast links apart above 1 Gbit/s.",
        group="Metric",
    ),
    Setting(
        "metric_rib_scale",
        "Wide metric scale",
        "metric rib-scale {scale}",
        (_number("scale", "Scale", 1, 255, hint="Default 128"),),
        help="Divides 64-bit metrics down to fit the routing table.",
        group="Metric",
    ),
    Setting(
        "stub",
        "Stub router",
        "stub [{stub_routes}] [leak-map {leak_map}]",
        (
            _choice(
                "stub_routes",
                "Advertise",
                (
                    "connected",
                    "summary",
                    "connected summary",
                    "static",
                    "redistributed",
                    "connected redistributed",
                    "receive-only",
                ),
                optional=True,
                hint="Empty: connected and summary routes",
            ),
            _route_map(optional=True, name="leak_map"),
        ),
        help="This switch is an edge: neighbors never send it queries for other routes.",
        group="Stub",
    ),
    Setting(
        "timers_active",
        "Stuck-in-active time",
        "timers active-time {minutes}",
        (_number("minutes", "Minutes", 1, 65535, hint="Default 3"),),
        help="How long to wait for answers about a lost route before resetting the neighbor.",
        group="Timers",
    ),
    _simple(
        "timers_active_disabled",
        "No stuck-in-active limit",
        "timers active-time disabled",
        help="Wait for answers about a lost route for ever.",
        group="Timers",
    ),
    Setting(
        "nsf_converge",
        "Graceful restart: time to converge",
        "timers nsf converge {seconds}",
        (_number("seconds", "Seconds", 60, 180, hint="Default 120"),),
        group="Timers",
    ),
    Setting(
        "nsf_route_hold",
        "Graceful restart: keep a restarting neighbor's routes",
        "timers nsf route-hold {seconds}",
        (_number("seconds", "Seconds", 20, 300, hint="Default 240"),),
        group="Timers",
    ),
    Setting(
        "nsf_signal",
        "Graceful restart: time to signal a restart",
        "timers nsf signal {seconds}",
        (_number("seconds", "Seconds", 10, 30, hint="Default 20"),),
        group="Timers",
    ),
    Setting(
        "authentication_key_chain",
        "Authentication key chain",
        "authentication key-chain {key_chain}",
        (_key_chain(),),
        help="Neighbors must prove they know a key from this chain. An interface's own "
        "setting overrides this one.",
        group="Authentication",
    ),
    _simple(
        "authentication_mode",
        "MD5 authentication",
        "authentication mode md5",
        help="Sign EIGRP packets with MD5, using the key chain.",
        group="Authentication",
    ),
    _simple(
        "graceful_restart",
        "Graceful restart",
        "graceful-restart",
        help="On by default: keep forwarding while EIGRP restarts.",
        group="Resilience",
    ),
    _simple(
        "nsf_await",
        "Wait for redistributed protocols after a restart",
        "nsf await-redist-proto-convergence",
        group="Resilience",
    ),
    _simple(
        "bfd",
        "BFD on every interface",
        "bfd",
        help="Notice a dead neighbor in under a second (BFD must be on).",
        group="Resilience",
    ),
    _simple(
        "log_neighbor_changes",
        "Log neighbor changes",
        "log-neighbor-changes",
        help="On by default: log a line whenever a neighbor comes or goes.",
        group="Logging",
    ),
    Setting(
        "log_neighbor_warnings",
        "Log neighbor warnings",
        "log-neighbor-warnings [{seconds}]",
        (_number("seconds", "Every (seconds)", 1, 65535, optional=True, hint="Default 10"),),
        group="Logging",
    ),
    _simple(
        "shutdown",
        "Shut down",
        "shutdown",
        help="Stop EIGRP here but keep its settings.",
        warning="All EIGRP neighbors here go down and their routes are withdrawn.",
        group="State",
    ),
)

_EIGRP_TAG = _tag()

_EIGRP_INTERFACE = (
    *_per_family(
        "ip_router",
        "Run EIGRP",
        "ip router eigrp {tag}",
        (_EIGRP_TAG,),
        help="Send and listen for EIGRP on this interface.",
        group="EIGRP on this interface",
    ),
    *_per_family(
        "passive",
        "Passive",
        "ip passive-interface eigrp {tag}",
        (_EIGRP_TAG,),
        help="Advertise this interface's subnet but never talk EIGRP on it.",
        group="EIGRP on this interface",
    ),
    *_per_family(
        "hello_interval",
        "Hello interval",
        "ip hello-interval eigrp {tag} {seconds}",
        (_EIGRP_TAG, _number("seconds", "Seconds", 1, 65535, hint="Default 5")),
        group="Timers",
    ),
    *_per_family(
        "hold_time",
        "Hold time",
        "ip hold-time eigrp {tag} {seconds}",
        (_EIGRP_TAG, _number("seconds", "Seconds", 1, 65535, hint="Default 15")),
        help="How long neighbors wait without a hello before giving up on this switch.",
        group="Timers",
    ),
    *_per_family(
        "authentication_mode",
        "MD5 authentication",
        "ip authentication mode eigrp {tag} md5",
        (_EIGRP_TAG,),
        group="Authentication",
    ),
    *_per_family(
        "authentication_key_chain",
        "Authentication key chain",
        "ip authentication key-chain eigrp {tag} {key_chain}",
        (_EIGRP_TAG, _key_chain()),
        group="Authentication",
    ),
    Setting(
        "summary",
        "Summary route (IPv4)",
        "ip summary-address eigrp {tag} {prefix} [{distance}]",
        (
            _EIGRP_TAG,
            Field("prefix", "Network", "prefix4", placeholder="192.0.2.0/23"),
            _number("distance", "Distance", 1, 255, optional=True, hint="Default 5"),
        ),
        help="Send one route for this whole network out of this interface instead of its parts.",
        group="Routes",
    ),
    Setting(
        "summary6",
        "Summary route (IPv6)",
        "ipv6 summary-address eigrp {tag} {prefix} [{distance}]",
        (
            _EIGRP_TAG,
            Field("prefix", "Network", "prefix6", placeholder="2001:db8::/48"),
            _number("distance", "Distance", 1, 255, optional=True, hint="Default 5"),
        ),
        help="Send one route for this whole network out of this interface instead of its parts.",
        group="Routes",
    ),
    *_per_family(
        "distribute_list",
        "Filter routes",
        "ip distribute-list eigrp {tag} {list_kind} {list_name} {direction}",
        (_EIGRP_TAG, *_list_fields()),
        group="Routes",
    ),
    *_per_family(
        "bandwidth",
        "Bandwidth for the metric",
        "ip bandwidth eigrp {tag} {kbps}",
        (_EIGRP_TAG, _number("kbps", "kbit/s", 1, 2560000000)),
        group="Metric",
    ),
    *_per_family(
        "delay",
        "Delay for the metric",
        "ip delay eigrp {tag} {delay}",
        (_EIGRP_TAG, _number("delay", "Tens of microseconds", 1, 16777215)),
        group="Metric",
    ),
    *_per_family(
        "bandwidth_percent",
        "Most bandwidth EIGRP may use",
        "ip bandwidth-percent eigrp {tag} {percent}",
        (_EIGRP_TAG, _number("percent", "Percent", 0, 100, hint="Default 50")),
        group="Metric",
    ),
    *_per_family(
        "split_horizon",
        "Split horizon",
        "ip split-horizon eigrp {tag}",
        (_EIGRP_TAG,),
        help="On by default: never send a route back out of the interface it came in on.",
        group="Advanced",
    ),
    *_per_family(
        "next_hop_self",
        "Next hop self",
        "ip next-hop-self eigrp {tag}",
        (_EIGRP_TAG,),
        help="On by default: tell neighbors to send traffic to this switch, not to the "
        "router it learned the route from.",
        group="Advanced",
    ),
)

_EIGRP_PROCESS, _EIGRP_VRF, _EIGRP_AF = _router_scopes(
    "eigrp",
    "EIGRP",
    _EIGRP_ROUTER,
    _EIGRP_ROUTER,
    _EIGRP_ROUTER,
    "Removes the process and every setting in it. Interfaces keep their own "
    "EIGRP lines until they are removed too.",
)


def _true(value: Any) -> bool:
    return text(value).lower() == "true"


def _vrf_ident(vrf: str) -> str:
    """The VRF as a scope's identity value: "" for the default VRF."""
    return "" if vrf in ("", "default") else vrf


def _where_title(name: str, tag: str, vrf: str, family: str = "") -> str:
    parts = [f"{name} {tag}"]
    if family:
        parts.append("IPv6" if family == "ipv6" else "IPv4")
    if vrf not in ("", "default"):
        parts.append(f"VRF {vrf}")
    return ", ".join(parts)


def _on(value: bool) -> str:
    return "on" if value else "off"


def _eigrp_redistribution(row: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        (text(r.get("redist_srcproto")), text(r.get("redist_routemap")))
        for r in table_rows(row, "TABLE_redist", "ROW_redist")
        if text(r.get("redist_srcproto"))
    ]


def _redistribution_values(found: list[tuple[str, str]], values: dict[str, dict[str, str]]) -> None:
    """Prefill the first static/direct and the first other redistribution.

    Other protocols show as "ospf-core" or similar; only that shape is
    prefilled (the probe redistributed static routes only).
    """
    for source, route_map in found:
        if source in _REDISTRIBUTE_SOURCES and "redistribute" not in values:
            values["redistribute"] = {"source": source, "route_map": route_map}
        protocol, _, tag = source.partition("-")
        if protocol in _REDISTRIBUTE_PROTOCOLS and tag and "redistribute_protocol" not in values:
            values["redistribute_protocol"] = {
                "protocol": protocol,
                "source_tag": tag,
                "route_map": route_map,
            }


def _redistribution_fact(found: list[tuple[str, str]]) -> str:
    return (
        "; ".join(f"{source} (route-map {route_map or 'none'})" for source, route_map in found)
        or "nothing"
    )


def _eigrp_process(
    asn: str, router_id: str, row: dict[str, Any]
) -> tuple[tuple[tuple[str, str], ...], dict[str, dict[str, str]]]:
    """Facts and current values of one EIGRP process in one VRF."""
    values: dict[str, dict[str, str]] = {}
    if asn not in ("", "0"):
        values["autonomous_system"] = {"asn": asn}
    if router_id:
        values["router_id"] = {"router_id": router_id}
    paths = text(row.get("max_paths"))
    if paths:
        values["maximum_paths"] = {"paths": paths}
    internal, external = text(row.get("int_distance")), text(row.get("ext_distance"))
    if internal and external:
        values["distance"] = {"internal": internal, "external": external}
    weights = {f"k{n}": text(row.get(f"metric_weight_k{n}")) for n in range(1, 6)}
    if all(weights.values()):
        values["metric_weights"] = {**weights, "k6": ""}
    if text(row.get("metric_version")) == "64bit":
        values["metric_version"] = {}
    if text(row.get("active_interval")):
        values["timers_active"] = {"minutes": text(row.get("active_interval"))}
    for key, field_name in (
        ("nsf_converge", "nsf_converge_time"),
        ("nsf_route_hold", "nsf_route_hold_time"),
        ("nsf_signal", "nsf_signal_time"),
    ):
        if text(row.get(field_name)):
            values[key] = {"seconds": text(row.get(field_name))}
    for key, field_name in (
        ("graceful_restart", "graceful_restart"),
        ("bfd", "bfd_enabled"),
        ("authentication_mode", "authen_md5"),
        ("nsf_await", "await_redist_proto_converge"),
    ):
        if _true(row.get(field_name)):
            values[key] = {}
    key_chain = text(row.get("authen_keychain"))
    if key_chain and key_chain != "none":
        values["authentication_key_chain"] = {"key_chain": key_chain}
    redistribution = _eigrp_redistribution(row)
    _redistribution_values(redistribution, values)
    facts = (
        ("AS", asn if asn not in ("", "0") else "not set"),
        ("Router ID", router_id or "none"),
        ("VRF", text(row.get("vrf")) or "default"),
        ("Distance", f"{internal or '?'} internal, {external or '?'} external"),
        ("Equal-cost paths", paths),
        ("Interfaces", text(row.get("num_interfaces"))),
        ("Passive interfaces", text(row.get("num_pass_interfaces"))),
        ("Neighbors", text(row.get("num_peers"))),
        ("Redistributes", _redistribution_fact(redistribution)),
        ("Graceful restart", _on(_true(row.get("graceful_restart")))),
        ("Stub", "yes" if _true(row.get("stub_configured")) else "no"),
        ("BFD", _on(_true(row.get("bfd_enabled")))),
        ("Authentication", f"key chain {key_chain}" if key_chain not in ("", "none") else "none"),
    )
    return facts, values


def _body(bodies: list[dict[str, Any]], index: int) -> Any:
    return bodies[index] if index < len(bodies) else None


def _interface_instances(
    found: dict[str, tuple[list[tuple[str, str]], dict[str, dict[str, str]]]],
) -> list[Instance]:
    return [
        Instance("interface", {"interface": name}, name, tuple(facts), values)
        for name, (facts, values) in found.items()
    ]


def parse_eigrp(bodies: list[dict[str, Any]]) -> ProtocolView:
    """EIGRP processes, interfaces and neighbors from the five EIGRP reads."""
    instances: list[Instance] = []
    processes: dict[str, bool] = {}  # tag -> has a default-VRF row
    tags: dict[tuple[str, str, str], str] = {}  # (family, asn, vrf) -> tag
    for family, body in (("ipv4", _body(bodies, 0)), ("ipv6", _body(bodies, 3))):
        for asn_row in table_rows(body, "TABLE_asn", "ROW_asn"):
            asn, router_id = text(asn_row.get("asn")), text(asn_row.get("router_id"))
            for row in table_rows(asn_row, "TABLE_vrf", "ROW_vrf"):
                tag, vrf = text(row.get("eigrp_ptag")), text(row.get("vrf")) or "default"
                if not tag:
                    continue
                tags[(family, asn, vrf)] = tag
                facts, values = _eigrp_process(asn, router_id, row)
                processes.setdefault(tag, False)
                if family == "ipv6":
                    ident = {"tag": tag, "vrf": _vrf_ident(vrf), "af": "ipv6"}
                    title = _where_title("EIGRP", tag, vrf, family)
                    instances.append(Instance("af", ident, title, facts, values))
                elif vrf == "default":
                    processes[tag] = True
                    instances.append(
                        Instance("process", {"tag": tag}, f"EIGRP {tag}", facts, values)
                    )
                else:
                    ident = {"tag": tag, "vrf": vrf}
                    title = _where_title("EIGRP", tag, vrf)
                    instances.append(Instance("vrf", ident, title, facts, values))
    for tag, seen in processes.items():
        if not seen:
            instances.append(Instance("process", {"tag": tag}, f"EIGRP {tag}"))

    found: dict[str, tuple[list[tuple[str, str]], dict[str, dict[str, str]]]] = {}
    interface_rows = []
    for family, body in (("ipv4", _body(bodies, 1)), ("ipv6", _body(bodies, 4))):
        for asn_row in table_rows(body, "TABLE_asn", "ROW_asn"):
            asn = text(asn_row.get("asn"))
            for vrf_row in table_rows(asn_row, "TABLE_vrf", "ROW_vrf"):
                vrf = text(vrf_row.get("vrf")) or "default"
                tag = tags.get((family, asn, vrf), "")
                for row in table_rows(vrf_row, "TABLE_if", "ROW_if"):
                    name = long_name(text(row.get("ifname")))
                    if not name:
                        continue
                    interface_rows.append(
                        (
                            "IPv4" if family == "ipv4" else "IPv6",
                            tag or f"AS {asn}",
                            vrf,
                            name,
                            text(row.get("peer_count")),
                            text(row.get("mean_srtt")),
                            text(row.get("pending_routes")),
                        )
                    )
                    facts, values = found.setdefault(name, ([], {}))
                    if tag:
                        key = "ip_router" if family == "ipv4" else "ip_router6"
                        values.setdefault(key, {"tag": tag})
                    peers = text(row.get("peer_count")) or "0"
                    facts.append((f"EIGRP {tag or asn} ({family})", f"{peers} neighbors"))
    instances.extend(_interface_instances(found))

    # Rows with neighbors were never seen live (nothing was plugged in during the
    # probe): the field names are the ones Cisco documents for this command.
    neighbor_rows = []
    for asn_row in table_rows(_body(bodies, 2), "TABLE_asn", "ROW_asn"):
        asn = text(asn_row.get("asn"))
        for vrf_row in table_rows(asn_row, "TABLE_vrf", "ROW_vrf"):
            vrf = text(vrf_row.get("vrf")) or "default"
            tag = tags.get(("ipv4", asn, vrf), f"AS {asn}")
            for row in table_rows(vrf_row, "TABLE_peer", "ROW_peer"):
                neighbor_rows.append(
                    (
                        tag,
                        vrf,
                        text(row.get("peer_ipaddr")),
                        long_name(text(row.get("peer_ifname"))),
                        text(row.get("peer_holdtime")),
                        readable_duration(row.get("peer_uptime")),
                        text(row.get("peer_srtt")),
                        text(row.get("peer_xmitq_count")),
                    )
                )
    tables = (
        Table(
            "Neighbors (IPv4)",
            ("Process", "VRF", "Address", "Interface", "Hold (s)", "Up for", "SRTT (ms)", "Queue"),
            tuple(neighbor_rows),
            empty="No EIGRP neighbors.",
        ),
        Table(
            "Interfaces",
            ("Family", "Process", "VRF", "Interface", "Neighbors", "SRTT (ms)", "Routes waiting"),
            tuple(interface_rows),
            empty="No interface is talking EIGRP.",
            note="An interface shows here only while it is up.",
        ),
    )
    return ProtocolView(tuple(instances), tables)


EIGRP = Protocol(
    key="eigrp",
    name="EIGRP",
    summary="Cisco's own routing protocol: switches tell each other which networks "
    "they reach and how fast.",
    features=("eigrp",),
    commands=(
        "show ip eigrp vrf all",
        "show ip eigrp interfaces vrf all",
        "show ip eigrp neighbors vrf all",
        "show ipv6 eigrp vrf all",
        "show ipv6 eigrp interfaces vrf all",
    ),
    parse=parse_eigrp,
    scopes=(
        _EIGRP_PROCESS,
        _EIGRP_VRF,
        _EIGRP_AF,
        _interface_scope(_EIGRP_INTERFACE, "EIGRP lines on one interface."),
    ),
    about="Make a process, give it an AS number, then turn EIGRP on for each "
    "interface. IPv6 needs the IPv6 address family and its own AS number.",
)

# ---- RIP ----------------------------------------------------------------------------

_RIP_SHUTDOWN = _simple(
    "shutdown",
    "Shut down",
    "shutdown",
    help="Stop RIP here but keep its settings.",
    warning="RIP routes from this process are withdrawn.",
    group="State",
)

_RIP_PROCESS = (
    _simple(
        "metric_direct_zero",
        "Connected routes cost 0",
        "metric direct 0",
        help="Count the switch's own subnets as cost 0, as Cisco IOS routers do.",
        group="Routes",
    ),
    _RIP_SHUTDOWN,
)

_RIP_AF = (
    *_redistribution(),
    _default_information(group="Routes from elsewhere"),
    Setting(
        "default_metric",
        "Metric for redistributed routes",
        "default-metric {metric}",
        (_number("metric", "Hops", 1, 15, hint="Default 1"),),
        group="Routes from elsewhere",
    ),
    _distance_one(),
    _maximum_paths(64),
    Setting(
        "timers",
        "Timers",
        "timers basic {update} {invalid} {holddown} {garbage}",
        (
            _number("update", "Update every (s)", 5, 4294967295, hint="Default 30"),
            _number("invalid", "Invalid after (s)", 1, 4294967295, hint="Default 180"),
            _number("holddown", "Hold down (s)", 0, 4294967295, hint="Default 180"),
            _number("garbage", "Flush after (s)", 1, 4294967295, hint="Default 120"),
        ),
        help="Every RIP router on the network must use the same timers.",
        group="Timers",
    ),
)

_RIP_TAG = _tag()

_RIP_INTERFACE = (
    *_per_family(
        "ip_router",
        "Run RIP",
        "ip router rip {tag}",
        (_RIP_TAG,),
        help="Send and listen for RIP on this interface.",
        group="RIP on this interface",
    ),
    *_per_family(
        "passive",
        "Passive",
        "ip rip passive-interface",
        help="Listen for routes but never send any.",
        group="RIP on this interface",
    ),
    Setting(
        "auth_mode",
        "Authentication",
        "ip rip authentication mode {mode}",
        (_choice("mode", "Mode", ("md5", "text"), hint="md5 signs; text sends the key"),),
        group="Authentication",
    ),
    Setting(
        "auth_key_chain",
        "Authentication key chain",
        "ip rip authentication key-chain {key_chain}",
        (_key_chain(),),
        group="Authentication",
    ),
    *_per_family(
        "metric_offset",
        "Metric offset",
        "ip rip metric-offset {offset}",
        (_number("offset", "Add", 1, 15, hint="Default 1"),),
        help="Add this to the metric of every route heard here, to make the path less liked.",
        group="Routes",
    ),
    *_per_family(
        "poison_reverse",
        "Poison reverse",
        "ip rip poison-reverse",
        help="Send routes back out as unreachable, instead of not at all.",
        group="Routes",
    ),
    Setting(
        "summary",
        "Summary route (IPv4)",
        "ip rip summary-address {prefix}",
        (Field("prefix", "Network", "prefix4", placeholder="192.0.2.0/23"),),
        group="Routes",
    ),
    Setting(
        "summary6",
        "Summary route (IPv6)",
        "ipv6 rip summary-address {prefix}",
        (Field("prefix", "Network", "prefix6", placeholder="2001:db8::/48"),),
        group="Routes",
    ),
    *_per_family(
        "route_filter",
        "Filter routes",
        "ip rip route-filter {list_kind} {list_name} {direction}",
        _list_fields(),
        group="Routes",
    ),
)

_RIP_PROCESS_SCOPE, _RIP_VRF, _RIP_AF_SCOPE = _router_scopes(
    "rip",
    "RIP",
    _RIP_PROCESS,
    (_RIP_SHUTDOWN,),
    _RIP_AF,
    "Removes the process and every setting in it. Interfaces keep their own "
    "RIP lines until they are removed too.",
)


def _rip_tag(name: str) -> str:
    """RIP shows process "core" as "rip-core"."""
    return name[4:] if name.startswith("rip-") else name


def _rip_family_rows(row: dict[str, Any], family: str) -> list[dict[str, Any]]:
    return [r for r in table_rows(row, "TABLE_afi", "ROW_afi") if text(r.get("af")) == family]


def _rip_af(row: dict[str, Any], family: str) -> tuple[tuple[tuple[str, str], ...], dict]:
    values: dict[str, dict[str, str]] = {}
    for key, field_name, output in (
        ("distance", "distance", "admin-dist"),
        ("maximum_paths", "paths", "max-paths"),
        ("default_metric", "metric", "def-metric"),
    ):
        if text(row.get(output)):
            values[key] = {field_name: text(row.get(output))}
    if _true(row.get("def-rt-distrib")):
        values["default_information"] = {
            "always": "always" if _true(row.get("def-distrib-always")) else "",
            "route_map": "",
        }
    redistribution: list[tuple[str, str]] = []
    interfaces: list[str] = []
    for afi in _rip_family_rows(row, family):
        for redist in table_rows(afi, "TABLE_redistrib", "ROW_redistrib"):
            for client in table_rows(redist, "TABLE_clients", "ROW_clients"):
                redistribution.append((text(client.get("pibname")), text(client.get("policy"))))
        interfaces.extend(
            long_name(text(r.get("if-name")))
            for r in table_rows(afi, "TABLE_interface", "ROW_interface")
        )
    _redistribution_values(redistribution, values)
    timers = (
        f"update {text(row.get('update-tmr'))} s, invalid {text(row.get('expire-tmr'))} s, "
        f"flush {text(row.get('garbage-tmr'))} s"
    )
    facts = (
        ("VRF", text(row.get("vrf")) or "default"),
        ("Distance", text(row.get("admin-dist"))),
        ("Equal-cost paths", text(row.get("max-paths"))),
        ("Default metric", text(row.get("def-metric"))),
        ("Timers", timers),
        (
            "Default route",
            ("sent always" if _true(row.get("def-distrib-always")) else "sent")
            if _true(row.get("def-rt-distrib"))
            else "not sent",
        ),
        ("Redistributes", _redistribution_fact(redistribution)),
        ("Interfaces", ", ".join(interfaces) or "none"),
        ("Shut down", "yes" if _true(row.get("rip-shut-globally-in-this-vrf")) else "no"),
    )
    return facts, values


def parse_rip(bodies: list[dict[str, Any]]) -> ProtocolView:
    """RIP processes, interfaces and neighbors from the five RIP reads."""
    instances: list[Instance] = []
    processes: list[str] = []
    vrfs: list[tuple[str, str]] = []
    for family, body in (("ipv4", _body(bodies, 0)), ("ipv6", _body(bodies, 3))):
        for mode in table_rows(body, "TABLE_mode", "ROW_mode"):
            for inst in table_rows(mode, "TABLE_inst", "ROW_inst"):
                tag = _rip_tag(text(inst.get("inst-name")))
                if not tag:
                    continue
                if tag not in processes:
                    processes.append(tag)
                for row in table_rows(inst, "TABLE_vrf", "ROW_vrf"):
                    vrf = text(row.get("vrf")) or "default"
                    if vrf != "default" and (tag, vrf) not in vrfs:
                        vrfs.append((tag, vrf))
                    facts, values = _rip_af(row, family)
                    ident = {"tag": tag, "vrf": _vrf_ident(vrf), "af": family}
                    title = _where_title("RIP", tag, vrf, family)
                    instances.append(Instance("af", ident, title, facts, values))
    instances[:0] = [
        *(Instance("process", {"tag": tag}, f"RIP {tag}") for tag in processes),
        *(
            Instance("vrf", {"tag": tag, "vrf": vrf}, _where_title("RIP", tag, vrf))
            for tag, vrf in vrfs
        ),
    ]

    found: dict[str, tuple[list[tuple[str, str]], dict[str, dict[str, str]]]] = {}
    interface_rows = []
    for family, body in (("ipv4", _body(bodies, 1)), ("ipv6", _body(bodies, 4))):
        suffix = "" if family == "ipv4" else "6"
        for inst in table_rows(body, "TABLE_inst", "ROW_inst"):
            tag = _rip_tag(text(inst.get("inst-name")))
            for vrf_row in table_rows(inst, "TABLE_vrf", "ROW_vrf"):
                vrf = text(vrf_row.get("vrf")) or "default"
                for row in table_rows(vrf_row, "TABLE_inter", "ROW_inter"):
                    name = long_name(text(row.get("if-name")))
                    if not name:
                        continue
                    facts, values = found.setdefault(name, ([], {}))
                    values["ip_router" + suffix] = {"tag": tag}
                    if _true(row.get("if-passive")):
                        values["passive" + suffix] = {}
                    if text(row.get("if-metric")):
                        values["metric_offset" + suffix] = {"offset": text(row.get("if-metric"))}
                    if _true(row.get("poison-reverse")):
                        values["poison_reverse" + suffix] = {}
                    auth = "none"
                    for auth_row in table_rows(row, "TABLE_auth", "ROW_auth"):
                        if not _true(auth_row.get("auth-ena")):
                            continue
                        mode, chain = (
                            text(auth_row.get("auth-type")),
                            text(auth_row.get("auth-keychain")),
                        )
                        auth = f"{mode}, key chain {chain}" if chain else mode
                        if family == "ipv4" and mode:
                            values["auth_mode"] = {"mode": mode}
                        if family == "ipv4" and chain:
                            values["auth_key_chain"] = {"key_chain": chain}
                    facts.append((f"RIP {tag} ({family})", text(row.get("if-status"))))
                    interface_rows.append(
                        (
                            "IPv4" if family == "ipv4" else "IPv6",
                            tag,
                            vrf,
                            name,
                            text(row.get("if-status")),
                            "yes" if _true(row.get("if-passive")) else "no",
                            text(row.get("if-metric")),
                            "yes" if _true(row.get("poison-reverse")) else "no",
                            auth,
                        )
                    )
    instances.extend(_interface_instances(found))

    # Rows with neighbors were never seen live (nothing was plugged in during the
    # probe): the field names are the ones Cisco documents for this command.
    neighbor_rows = []
    for inst in table_rows(_body(bodies, 2), "TABLE_inst", "ROW_inst"):
        tag = _rip_tag(text(inst.get("inst-name")))
        for vrf_row in table_rows(inst, "TABLE_vrf", "ROW_vrf"):
            vrf = text(vrf_row.get("vrf")) or "default"
            for row in table_rows(vrf_row, "TABLE_adj", "ROW_adj"):
                neighbor_rows.append(
                    (
                        tag,
                        vrf,
                        text(row.get("adj-addr")),
                        long_name(text(row.get("if-name"))),
                        text(row.get("in-bad-packets")),
                        text(row.get("in-bad-routes")),
                    )
                )
    tables = (
        Table(
            "Neighbors (IPv4)",
            ("Process", "VRF", "Address", "Interface", "Bad packets", "Bad routes"),
            tuple(neighbor_rows),
            empty="No RIP neighbors.",
        ),
        Table(
            "Interfaces",
            (
                "Family",
                "Process",
                "VRF",
                "Interface",
                "State",
                "Passive",
                "Metric offset",
                "Poison reverse",
                "Authentication",
            ),
            tuple(interface_rows),
            empty="No interface runs RIP.",
        ),
    )
    return ProtocolView(tuple(instances), tables)


RIP = Protocol(
    key="rip",
    name="RIP",
    summary="The oldest, simplest routing protocol: routers share their routes every "
    "30 seconds and count hops.",
    features=("rip",),
    commands=(
        "show ip rip vrf all",
        "show ip rip interface vrf all",
        "show ip rip neighbor vrf all",
        "show ipv6 rip vrf all",
        "show ipv6 rip interface vrf all",
    ),
    parse=parse_rip,
    scopes=(
        _RIP_PROCESS_SCOPE,
        _RIP_VRF,
        _RIP_AF_SCOPE,
        _interface_scope(_RIP_INTERFACE, "RIP lines on one interface."),
    ),
    about="Make a process, add the IPv4 (or IPv6) address family, then turn RIP on "
    "for each interface. RIP suits small, simple networks; it counts at most 15 hops.",
)

# ---- IS-IS ----------------------------------------------------------------------------


def _isis_per_level(
    key: str,
    label: str,
    line: str,
    fields: tuple[Field, ...] = (),
    help: str = "",
    group: str = "Settings",
) -> tuple[Setting, ...]:
    """One setting per IS-IS level; ``line`` holds ``LEVEL`` where it goes."""
    return tuple(
        Setting(
            f"{key}_l{number}",
            f"{label} (level {number})",
            line.replace("LEVEL", f"level-{number}"),
            fields,
            help=help,
            group=group,
        )
        for number in (1, 2)
    )


def _isis_auth_type() -> Field:
    return _choice("auth_type", "Type", ("md5", "cleartext"), hint="md5 signs; cleartext sends")


def _isis_wait_fields() -> tuple[Field, ...]:
    return (
        _level(),
        _number("max_wait", "Longest wait (ms)", 500, 65535),
        _number("initial_wait", "First wait (ms)", 50, 65535, optional=True),
        _number("second_wait", "Second wait (ms)", 50, 65535, optional=True),
    )


_ISIS_ROUTER = (
    Setting(
        "net",
        "NET (area and system ID)",
        "net {net}",
        (Field("net", "NET", "net", placeholder="49.0001.1920.0000.2001.00"),),
        help="The switch's IS-IS address: area, then a system ID unique in the network, then 00.",
        group="Identity",
    ),
    Setting(
        "is_type",
        "Level",
        "is-type {is_type}",
        (_choice("is_type", "Level", _LEVELS_BOTH, hint="Default level-1-2"),),
        help="level-1 routes inside the area, level-2 between areas.",
        group="Identity",
    ),
    _simple(
        "hostname_dynamic",
        "Share host names",
        "hostname dynamic",
        help="Neighbors show this switch's name instead of its system ID.",
        group="Identity",
    ),
    *_isis_per_level(
        "auth_type",
        "Authentication type",
        "authentication-type {auth_type} LEVEL",
        (_isis_auth_type(),),
        group="Authentication",
    ),
    *_isis_per_level(
        "auth_key_chain",
        "Authentication key chain",
        "authentication key-chain {key_chain} LEVEL",
        (_key_chain(),),
        group="Authentication",
    ),
    *_isis_per_level(
        "auth_check",
        "Check authentication",
        "authentication-check LEVEL",
        help="On by default: drop packets that fail the check.",
        group="Authentication",
    ),
    _distance_one(),
    _maximum_paths(64),
    _default_information(),
    *_redistribution(),
    _redistribute_limit(),
    Setting(
        "reference_bandwidth",
        "Reference bandwidth",
        "reference-bandwidth {bandwidth} {unit}",
        (
            _number("bandwidth", "Bandwidth", 1, 4000000, hint="Default 40 Gbps"),
            _choice("unit", "Unit", ("Gbps", "Mbps")),
        ),
        help="The speed that costs 1; slower links cost more.",
        group="Routes",
    ),
    Setting(
        "overload_always",
        "Overload bit",
        "set-overload-bit always [suppress {suppress}]",
        (
            _choice(
                "suppress",
                "Also hide",
                ("interlevel", "external", "interlevel external"),
                optional=True,
            ),
        ),
        help="Ask other routers not to send traffic through this switch.",
        warning="Traffic that passes through this switch moves to other paths.",
        group="Overload",
    ),
    Setting(
        "overload_startup",
        "Overload bit after a restart",
        "set-overload-bit on-startup {seconds} [suppress {suppress}]",
        (
            _number("seconds", "Seconds", 5, 86400),
            _choice(
                "suppress",
                "Also hide",
                ("interlevel", "external", "interlevel external"),
                optional=True,
            ),
        ),
        help="Keep traffic away for this long after the switch starts.",
        group="Overload",
    ),
    Setting(
        "overload_bgp",
        "Overload bit until BGP is ready",
        "set-overload-bit on-startup wait-for bgp {asn}",
        (Field("asn", "BGP AS", "asn", placeholder="65001"),),
        group="Overload",
    ),
    _simple(
        "attached_bit",
        "Set the attached bit",
        "set-attached-bit",
        help="On by default: level-1 routers may use this switch to leave the area.",
        group="Overload",
    ),
    Setting(
        "lsp_gen_interval",
        "LSP generation throttle",
        "lsp-gen-interval {level} {max_wait} [{initial_wait} {second_wait}]",
        _isis_wait_fields(),
        group="Timers",
    ),
    Setting(
        "spf_interval",
        "Route calculation throttle",
        "spf-interval {level} {max_wait} [{initial_wait} {second_wait}]",
        _isis_wait_fields(),
        group="Timers",
    ),
    Setting(
        "lsp_mtu",
        "LSP size",
        "lsp-mtu {mtu}",
        (_number("mtu", "Bytes", 128, 4352, hint="Default 1492"),),
        group="Timers",
    ),
    Setting(
        "max_lsp_lifetime",
        "LSP lifetime",
        "max-lsp-lifetime {seconds}",
        (_number("seconds", "Seconds", 1, 65535, hint="Default 1200"),),
        group="Timers",
    ),
    _simple(
        "graceful_restart",
        "Graceful restart",
        "graceful-restart",
        help="On by default: keep forwarding while IS-IS restarts.",
        group="Resilience",
    ),
    Setting(
        "graceful_restart_t3",
        "Graceful restart wait (T3)",
        "graceful-restart t3 manual {seconds}",
        (_number("seconds", "Seconds", 30, 65535, hint="Default 60"),),
        group="Resilience",
    ),
    _simple(
        "bfd",
        "BFD on every interface",
        "bfd",
        help="Notice a dead neighbor in under a second (BFD must be on).",
        group="Resilience",
    ),
    _simple(
        "log_adjacency_changes",
        "Log neighbor changes",
        "log-adjacency-changes",
        group="Logging",
    ),
    _simple(
        "shutdown",
        "Shut down",
        "shutdown",
        help="Stop IS-IS here but keep its settings.",
        warning="All IS-IS neighbors here go down and their routes are withdrawn.",
        group="State",
    ),
)

_ISIS_AF = (
    *_redistribution(),
    _redistribute_limit(),
    _default_information(),
    Setting(
        "summary",
        "Summary route",
        "summary-address {prefix} {level}",
        (Field("prefix", "Network", "prefix", placeholder="192.0.2.0/23"), _level(both=True)),
        help="Advertise one route for this whole network instead of its parts.",
        group="Routes",
    ),
    Setting(
        "distribute_all",
        "Leak all routes between levels",
        "distribute {from_level} into {to_level} all",
        (_level(name="from_level"), _level(name="to_level")),
        group="Routes",
    ),
    Setting(
        "distribute_route_map",
        "Leak routes between levels",
        "distribute {from_level} into {to_level} route-map {route_map}",
        (_level(name="from_level"), _level(name="to_level"), _route_map()),
        group="Routes",
    ),
    _distance_one(),
    _maximum_paths(64),
    _simple(
        "adjacency_check",
        "Same address families only",
        "adjacency-check",
        help="On by default: only become neighbors with routers running this family too.",
        group="Advanced",
    ),
    _simple(
        "bfd",
        "BFD for this family",
        "bfd",
        help="Notice a dead neighbor in under a second (BFD must be on).",
        group="Advanced",
    ),
)

_ISIS_TAG = _tag()

_ISIS_INTERFACE = (
    Setting(
        "ip_router",
        "Run IS-IS (IPv4)",
        "ip router isis {tag}",
        (_ISIS_TAG,),
        group="IS-IS on this interface",
    ),
    Setting(
        "ip_router6",
        "Run IS-IS (IPv6)",
        "ipv6 router isis {tag}",
        (_ISIS_TAG,),
        group="IS-IS on this interface",
    ),
    Setting(
        "circuit_type",
        "Level",
        "isis circuit-type {circuit_type}",
        (_choice("circuit_type", "Level", _LEVELS_BOTH),),
        help="Which levels this interface forms neighbors at.",
        group="IS-IS on this interface",
    ),
    Setting(
        "passive",
        "Passive",
        "isis passive-interface {level}",
        (_level(both=True),),
        help="Advertise this interface's subnet but never talk IS-IS on it.",
        group="IS-IS on this interface",
    ),
    _simple(
        "network_p2p",
        "Point-to-point",
        "isis network point-to-point",
        help="Only one neighbor on this link: skips electing a designated router.",
        group="IS-IS on this interface",
    ),
    *_isis_per_level(
        "metric",
        "Cost",
        "isis metric {metric} LEVEL",
        (_number("metric", "Cost", 1, 16777214, hint="Default 10"),),
        group="Cost",
    ),
    *_isis_per_level(
        "metric6",
        "IPv6 cost",
        "isis ipv6 metric {metric} LEVEL",
        (_number("metric", "Cost", 1, 16777214, hint="Default 10"),),
        group="Cost",
    ),
    Setting(
        "priority",
        "Priority",
        "isis priority {priority} {level}",
        (_number("priority", "Priority", 0, 127, hint="Default 64"), _level()),
        help="The highest becomes the designated router on a shared link.",
        group="Cost",
    ),
    Setting(
        "hello_interval",
        "Hello interval",
        "isis hello-interval {seconds} [{level}]",
        (_number("seconds", "Seconds", 1, 65535, hint="Default 10"), _level(optional=True)),
        group="Timers",
    ),
    Setting(
        "hello_multiplier",
        "Hellos missed before giving up",
        "isis hello-multiplier {multiplier} [{level}]",
        (_number("multiplier", "Hellos", 3, 1000, hint="Default 3"), _level(optional=True)),
        group="Timers",
    ),
    Setting(
        "csnp_interval",
        "CSNP interval",
        "isis csnp-interval {seconds} {level}",
        (_number("seconds", "Seconds", 1, 65535, hint="Default 10"), _level()),
        group="Timers",
    ),
    Setting(
        "lsp_interval",
        "LSP interval",
        "isis lsp-interval {ms}",
        (_number("ms", "Milliseconds", 10, 65535, hint="Default 33"),),
        group="Timers",
    ),
    Setting(
        "retransmit_interval",
        "LSP resend interval",
        "isis retransmit-interval {seconds}",
        (_number("seconds", "Seconds", 1, 65535, hint="Default 5"),),
        group="Timers",
    ),
    _simple(
        "hello_padding",
        "Pad hellos",
        "isis hello-padding",
        help="On by default: pad hellos to the full MTU, to catch MTU mismatches.",
        group="Timers",
    ),
    Setting(
        "auth_type",
        "Authentication type",
        "isis authentication-type {auth_type} [{level}]",
        (_isis_auth_type(), _level(optional=True)),
        group="Authentication",
    ),
    Setting(
        "auth_key_chain",
        "Authentication key chain",
        "isis authentication key-chain {key_chain} [{level}]",
        (_key_chain(), _level(optional=True)),
        group="Authentication",
    ),
    Setting(
        "auth_check",
        "Check authentication",
        "isis authentication-check [{level}]",
        (_level(optional=True),),
        group="Authentication",
    ),
    Setting(
        "mesh_group",
        "Mesh group",
        "isis mesh-group {mesh_id}",
        (_number("mesh_id", "Group", 1, 4294967295),),
        help="Do not flood updates to other interfaces of the same group.",
        group="Advanced",
    ),
    _simple(
        "mesh_blocked",
        "Block flooding",
        "isis mesh-group blocked",
        help="Never flood updates out of this interface.",
        group="Advanced",
    ),
    _simple("bfd", "BFD (IPv4)", "isis bfd", group="Advanced"),
    _simple("bfd6", "BFD (IPv6)", "isis ipv6 bfd", group="Advanced"),
    _simple(
        "shutdown",
        "Shut down IS-IS here",
        "isis shutdown",
        help="Stop IS-IS on this interface but keep its settings.",
        warning="IS-IS neighbors on this interface go down.",
        group="Advanced",
    ),
)

_ISIS_PROCESS, _ISIS_VRF, _ISIS_AF_SCOPE = _router_scopes(
    "isis",
    "IS-IS",
    _ISIS_ROUTER,
    _ISIS_ROUTER,
    _ISIS_AF,
    "Removes the process and every setting in it. Interfaces keep their own "
    "IS-IS lines until they are removed too.",
)

_IS_TYPES = {"L1": "level-1", "L2": "level-2"}


def _is_type(value: str) -> str:
    """ "L2" -> "level-2"; any value naming both levels -> "level-1-2"."""
    if value in _IS_TYPES:
        return _IS_TYPES[value]
    return "level-1-2" if "1" in value and "2" in value else ""


def _isis_process(row: dict[str, Any]) -> tuple[tuple[tuple[str, str], ...], dict]:
    values: dict[str, dict[str, str]] = {}
    system_id = text(row.get("system-id-out"))
    areas = [
        text(r.get("area-addr-nsap"))
        for r in table_rows(row, "TABLE_area_addr", "ROW_area_addr")
        if text(r.get("area-addr-nsap"))
    ]
    nets = [f"{area}.{system_id}.00".lower() for area in areas if system_id]
    if nets:
        values["net"] = {"net": nets[0]}
    level = _is_type(text(row.get("is-type-out")))
    if level:
        values["is_type"] = {"is_type": level}
    if text(row.get("mtu-out")):
        values["lsp_mtu"] = {"mtu": text(row.get("mtu-out"))}
    restart = text(row.get("gr-status-out")).lower()
    if "enabled" in restart:
        values["graceful_restart"] = {}
    auth_facts = []
    for auth in table_rows(row, "TABLE_auth", "ROW_auth"):
        number = text(auth.get("auth-lvl-out"))
        if number not in ("1", "2"):
            continue
        kind = ""
        if auth.get("auth-type-md5"):
            kind = "md5"
        elif auth.get("auth-type-cleartext"):
            kind = "cleartext"
        chain = text(auth.get("auth-type-key-chain"))
        if kind:
            values[f"auth_type_l{number}"] = {"auth_type": kind}
        if chain:
            values[f"auth_key_chain_l{number}"] = {"key_chain": chain}
        if auth.get("auth-check") is not None and auth.get("auth-no-check") is None:
            values[f"auth_check_l{number}"] = {}
        described = f"{kind}, key chain {chain}" if kind and chain else kind or "none"
        auth_facts.append(f"level {number}: {described}")
    interfaces = [
        long_name(text(r.get("intf-name-out")))
        for r in table_rows(row, "TABLE_iib_list_yeild", "ROW_iib_list_yeild")
    ]
    facts = (
        ("VRF", text(row.get("vrf-name-out")) or "default"),
        ("System ID", system_id),
        ("Areas", ", ".join(areas) or "none"),
        ("NET", ", ".join(nets) or "not set"),
        ("Level", level or text(row.get("is-type-out"))),
        ("Graceful restart", "on" if values.get("graceful_restart") is not None else "off"),
        ("Authentication", "; ".join(auth_facts) or "none"),
        ("Metrics accepted", text(row.get("accept-metric"))),
        ("Interfaces", ", ".join(interfaces) or "none"),
    )
    return facts, values


def _isis_interface(row: dict[str, Any]) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    """Current values of one IS-IS interface, and its metric per level.

    Metrics come from the point-to-point rows (the only kind the probe
    produced); broadcast links show their cost in the table only when the
    switch reports it the same way.
    """
    values: dict[str, dict[str, str]] = {}
    level = _is_type(text(row.get("intf-ckt-type-out")))
    if level:
        values["circuit_type"] = {"circuit_type": level}
    if _true(row.get("intf-passive-mask-out")):
        values["passive"] = {"level": text(row.get("intf-passive-mask-lvl-out"))}
    if _true(row.get("intf-p2p-type-out")):
        values["network_p2p"] = {}
    metrics: dict[str, str] = {}
    for p2p in table_rows(row, "TABLE_p2p", "ROW_p2p"):
        number, metric = text(p2p.get("intf-p2p-lvl-out")), text(p2p.get("intf-p2p-metric-lvl-out"))
        if number in ("1", "2") and metric:
            metrics[number] = metric
            values[f"metric_l{number}"] = {"metric": metric}
    for key, field_name, output in (
        ("hello_interval", "seconds", "intf-p2p-hello-intv-out"),
        ("hello_multiplier", "multiplier", "intf-p2p-hello-multi-out"),
    ):
        if text(row.get(output)):
            values[key] = {field_name: text(row.get(output)), "level": ""}
    if text(row.get("intf-lsp-intv-out")):
        values["lsp_interval"] = {"ms": text(row.get("intf-lsp-intv-out"))}
    if text(row.get("intf-retx-intv-out")):
        values["retransmit_interval"] = {"seconds": text(row.get("intf-retx-intv-out"))}
    for bfd in table_rows(row, "TABLE_bfd", "ROW_bfd"):
        if _true(bfd.get("intf-bfd-ipv4-state-out")):
            values["bfd"] = {}
        if _true(bfd.get("intf-bfd-ipv6-state-out")):
            values["bfd6"] = {}
    return values, metrics


def parse_isis(bodies: list[dict[str, Any]]) -> ProtocolView:
    """IS-IS processes, interfaces and adjacencies from the three IS-IS reads."""
    instances: list[Instance] = []
    processes: dict[str, bool] = {}
    for row in table_rows(_body(bodies, 0), "TABLE_process_tag", "ROW_process_tag"):
        tag, vrf = text(row.get("process-tag-out")), text(row.get("vrf-name-out")) or "default"
        if not tag:
            continue
        facts, values = _isis_process(row)
        processes.setdefault(tag, False)
        if vrf == "default":
            processes[tag] = True
            instances.append(Instance("process", {"tag": tag}, f"IS-IS {tag}", facts, values))
        else:
            ident = {"tag": tag, "vrf": vrf}
            instances.append(Instance("vrf", ident, _where_title("IS-IS", tag, vrf), facts, values))
        for af in table_rows(row, "TABLE_afi_safi", "ROW_afi_safi"):
            family = text(af.get("af-ix")).lower()
            if family not in _FAMILIES:
                continue
            bfd = text(af.get("af-bfd-config")) == "enabled"
            instances.append(
                Instance(
                    "af",
                    {"tag": tag, "vrf": _vrf_ident(vrf), "af": family},
                    _where_title("IS-IS", tag, vrf, family),
                    (("BFD", _on(bfd)),),
                    {"bfd": {}} if bfd else {},
                )
            )
    for tag, seen in processes.items():
        if not seen:
            instances.append(Instance("process", {"tag": tag}, f"IS-IS {tag}"))

    interface_rows = []
    seen_interfaces: list[str] = []
    for proc in table_rows(_body(bodies, 1), "TABLE_process_tag", "ROW_process_tag"):
        tag = text(proc.get("process-tag-out"))
        for vrf_row in table_rows(proc, "TABLE_vrf", "ROW_vrf"):
            vrf = text(vrf_row.get("vrf-name-out")) or "default"
            for row in table_rows(vrf_row, "TABLE_interface", "ROW_interface"):
                name = long_name(text(row.get("intf-name-out")))
                if not name:
                    continue
                values, metrics = _isis_interface(row)
                passive = values.get("passive", {}).get("level", "")
                interface_rows.append(
                    (
                        tag,
                        vrf,
                        name,
                        text(row.get("intf-state-out")),
                        values.get("circuit_type", {}).get("circuit_type", ""),
                        "point-to-point" if "network_p2p" in values else "broadcast",
                        passive or "no",
                        metrics.get("1", ""),
                        metrics.get("2", ""),
                    )
                )
                if name in seen_interfaces:
                    continue
                seen_interfaces.append(name)
                facts = (
                    ("Process", tag),
                    ("VRF", vrf),
                    ("State", text(row.get("intf-status-out"))),
                )
                instances.append(Instance("interface", {"interface": name}, name, facts, values))

    # Rows with adjacencies were never seen live (nothing was plugged in during
    # the probe): the field names are the ones Cisco documents for this command.
    adjacency_rows = []
    for proc in table_rows(_body(bodies, 2), "TABLE_process_tag", "ROW_process_tag"):
        tag = text(proc.get("process-tag-out"))
        for vrf_row in table_rows(proc, "TABLE_vrf", "ROW_vrf"):
            vrf = text(vrf_row.get("vrf-name-out")) or "default"
            for row in table_rows(vrf_row, "TABLE_process_adj", "ROW_process_adj"):
                adjacency_rows.append(
                    (
                        tag,
                        vrf,
                        text(row.get("adj-sys-name-out")),
                        text(row.get("adj-sys-id-out")),
                        long_name(text(row.get("adj-intf-name-out"))),
                        text(row.get("adj-usage-out")),
                        text(row.get("adj-state-out")),
                        text(row.get("adj-hold-time-out")),
                    )
                )
    tables = (
        Table(
            "Adjacencies",
            ("Process", "VRF", "Neighbor", "System ID", "Interface", "Level", "State", "Hold time"),
            tuple(adjacency_rows),
            empty="No IS-IS neighbors.",
        ),
        Table(
            "Interfaces",
            (
                "Process",
                "VRF",
                "Interface",
                "State",
                "Level",
                "Network",
                "Passive",
                "Cost level 1",
                "Cost level 2",
            ),
            tuple(interface_rows),
            empty="No interface runs IS-IS.",
        ),
    )
    return ProtocolView(tuple(instances), tables)


ISIS = Protocol(
    key="isis",
    name="IS-IS",
    summary="A link-state routing protocol like OSPF, common in large and service "
    "provider networks.",
    features=("isis",),
    commands=(
        "show isis vrf all",
        "show isis interface vrf all",
        "show isis adjacency vrf all",
    ),
    parse=parse_isis,
    scopes=(
        _ISIS_PROCESS,
        _ISIS_VRF,
        _ISIS_AF_SCOPE,
        _interface_scope(_ISIS_INTERFACE, "IS-IS lines on one interface."),
    ),
    about="Make a process, give it a NET, then turn IS-IS on for each interface "
    "(IPv4 and IPv6 separately).",
)

PROTOCOLS: tuple[Protocol, ...] = (EIGRP, RIP, ISIS)
