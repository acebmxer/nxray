"""OSPF and OSPFv3: the two link-state routing protocols, as protocol pages.

What is read (one request per page, while the feature is on):

- OSPF: ``show ip ospf vrf all`` (each process in each VRF: router ID, areas,
  reference bandwidth, timers), ``show ip ospf interface vrf all``, ``show ip
  ospf neighbors vrf all`` and ``show ip ospf summary-address vrf all``.
- OSPFv3: ``show ospfv3 vrf all``, ``show ospfv3 interface vrf all`` and
  ``show ospfv3 neighbors vrf all``.

What can be changed: processes (made and deleted), a process's part in each
VRF, everything inside them (router ID, areas and their types, ranges,
authentication, virtual links, redistribution through a route-map, the
default route, summaries, distance, paths, reference bandwidth, timers,
graceful restart, BFD, stub-router advertising, logging, shutdown), OSPFv3's
IPv6 address family, and each interface's OSPF settings (process and area,
cost, priority, timers, network type, passive, authentication, BFD).

Tried on the switch (cisco-25gb, NX-OS 9.3(16), as NXray's restricted
account): ``router ospf`` with router-id, log-adjacency-changes detail,
auto-cost reference-bandwidth 100 Gbps, timers throttle spf, passive-interface
default, area stub / nssa / range / authentication message-digest,
summary-address, redistribute static and direct with a route-map,
default-information originate always, distance, maximum-paths; the nested
``vrf`` part with router-id and an area; ``router ospfv3`` with router-id, an
area and the IPv6 address family (redistribute, default-information,
maximum-paths, area range); on an interface ``ip router ospf ... area``, ip
ospf cost / passive-interface / hello-interval / dead-interval / network
point-to-point / priority / authentication key-chain / mtu-ignore, and the
OSPFv3 equivalents; several ``no`` forms and ``no router ospf|ospfv3``. Every
other line follows Cisco's NX-OS 9.3 configuration guide and command
reference.

The probe had nothing plugged in, so the neighbor tables were empty: neighbor
rows are read with the field names in Cisco's NX-API reference for the same
commands, and were never seen live.
"""

from __future__ import annotations

import re
from typing import Any

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

# ---- fields ---------------------------------------------------------------------


def _tag_field() -> Field:
    return Field(
        "tag",
        "Process",
        "name",
        hint="The OSPF process's name on this switch, such as 1 or core",
        placeholder="1",
    )


def _area(name: str = "area") -> Field:
    return Field(
        name,
        "Area",
        "area",
        hint="A number such as 0, or written like 0.0.0.1; area 0 is the backbone",
        placeholder="0",
    )


def _number(name: str, label: str, low: int, high: int, hint: str = "") -> Field:
    return Field(name, label, "int", minimum=low, maximum=high, hint=hint)


def _route_map(name: str = "route_map", optional: bool = False) -> Field:
    return Field(
        name,
        "Route-map",
        "name",
        optional=optional,
        hint="A route-map made on the Routing policy page",
    )


def _flag(name: str, label: str, word: str, hint: str = "") -> Field:
    return Field(name, label, "flag", choices=(word,), hint=hint)


# ---- settings shared by OSPF and OSPFv3 -----------------------------------------


def _router_id() -> Setting:
    return Setting(
        "router_id",
        "Router ID",
        "router-id {router_id}",
        (
            Field(
                "router_id",
                "Router ID",
                "ipv4",
                hint="The address this switch calls itself in OSPF; usually a loopback address",
            ),
        ),
        help="The address this switch calls itself in OSPF",
        warning="Changing the router ID restarts every OSPF neighbor of this process.",
        group="Basics",
    )


def _auto_cost() -> Setting:
    return Setting(
        "auto_cost",
        "Reference bandwidth",
        "auto-cost reference-bandwidth {bandwidth} [{unit}]",
        (
            _number("bandwidth", "Bandwidth", 1, 4000000, "1 to 4000 Gbps or 1 to 4000000 Mbps"),
            Field("unit", "Unit", "choice", choices=("Gbps", "Mbps"), optional=True),
        ),
        no_line="no auto-cost reference-bandwidth",
        help="The speed that gets cost 1; slower links cost more (default 40 Gbps)",
        group="Basics",
    )


def _basics() -> tuple[Setting, ...]:
    return (
        Setting(
            "passive_default",
            "Passive on every interface",
            "passive-interface default",
            help="Interfaces in OSPF advertise their networks but talk to no neighbor, "
            "unless an interface is made active",
            group="Basics",
        ),
        Setting(
            "log_adjacency",
            "Log neighbor changes",
            "log-adjacency-changes [{detail}]",
            (_flag("detail", "Every step", "detail", "Log every state, not only up and down"),),
            no_line="no log-adjacency-changes",
            help="Write a log message when a neighbor comes up or goes down",
            group="Basics",
        ),
        Setting(
            "bfd",
            "BFD on every interface",
            "bfd",
            help="Use BFD to notice a dead neighbor in under a second (BFD must be on)",
            group="Basics",
        ),
        Setting(
            "name_lookup",
            "Show router names",
            "name-lookup",
            help="Show router IDs by their DNS names in show commands",
            group="Basics",
        ),
        Setting(
            "shutdown",
            "Stop this process",
            "shutdown",
            help="Stop OSPF here without losing its settings",
            warning="Stopping the process drops every neighbor and every route it learned.",
            group="Basics",
        ),
    )


def _area_settings(with_routes: bool) -> tuple[Setting, ...]:
    """Area types and virtual links (both protocols, router level)."""
    found = [
        Setting(
            "area_stub",
            "Stub area",
            "area {area} stub [{no_summary}]",
            (
                _area(),
                _flag(
                    "no_summary",
                    "Totally stubby",
                    "no-summary",
                    "Also keep routes from other areas out, sending only a default route",
                ),
            ),
            no_line="no area {area} stub",
            help="An area that gets a default route instead of routes from outside OSPF",
            group="Areas",
        ),
        Setting(
            "area_nssa",
            "NSSA area",
            "area {area} nssa [{no_summary}] [{no_redistribution}] [{originate}]",
            (
                _area(),
                _flag("no_summary", "No routes from other areas", "no-summary"),
                _flag(
                    "no_redistribution",
                    "No redistributed routes",
                    "no-redistribution",
                    "Keep routes this switch redistributes out of this area",
                ),
                _flag(
                    "originate",
                    "Send a default route",
                    "default-information-originate",
                ),
            ),
            no_line="no area {area} nssa",
            help="A stub area that may still take routes redistributed into it",
            group="Areas",
        ),
        Setting(
            "area_nssa_translate",
            "NSSA translation",
            "area {area} nssa translate type7 {translate}",
            (
                _area(),
                Field(
                    "translate",
                    "Translate",
                    "choice",
                    choices=("always", "never"),
                    hint="Whether this border router turns the NSSA's routes into normal ones",
                ),
            ),
            no_line="no area {area} nssa translate type7",
            group="Areas",
        ),
        Setting(
            "area_virtual_link",
            "Virtual link",
            "area {area} virtual-link {peer}",
            (
                _area(),
                Field(
                    "peer",
                    "Far router ID",
                    "ipv4",
                    hint="The router ID of the border router at the other end",
                ),
            ),
            help="Join an area that does not touch area 0 to the backbone through this area",
            group="Areas",
        ),
    ]
    if not with_routes:
        return tuple(found)
    return (*found, *_area_route_settings(4))


def _area_route_settings(version: int) -> tuple[Setting, ...]:
    """Area ranges, default cost and filters (OSPF router level, OSPFv3 address family)."""
    prefix = "prefix4" if version == 4 else "prefix6"
    example = "192.0.2.0/24" if version == 4 else "2001:db8:1::/48"
    return (
        Setting(
            "area_range",
            "Area range",
            "area {area} range {prefix} [{not_advertise}] [cost {range_cost}]",
            (
                _area(),
                Field("prefix", "Network", prefix, placeholder=example),
                _flag(
                    "not_advertise",
                    "Hide it",
                    "not-advertise",
                    "Advertise neither it nor its parts",
                ),
                Field(
                    "range_cost",
                    "Cost",
                    "int",
                    minimum=0,
                    maximum=16777215,
                    optional=True,
                ),
            ),
            no_line="no area {area} range {prefix}",
            help="On an area border router, advertise one summary for an area's networks",
            group="Areas",
        ),
        Setting(
            "area_default_cost",
            "Default route cost",
            "area {area} default-cost {cost}",
            (_area(), _number("cost", "Cost", 0, 16777215)),
            no_line="no area {area} default-cost",
            help="The cost of the default route sent into a stub area",
            group="Areas",
        ),
        Setting(
            "area_filter",
            "Area filter",
            "area {area} filter-list route-map {route_map} {direction}",
            (
                _area(),
                _route_map(),
                Field("direction", "Direction", "choice", choices=("in", "out")),
            ),
            help="On an area border router, filter the routes going into or out of an area",
            group="Areas",
        ),
    )


def _authentication() -> Setting:
    return Setting(
        "area_authentication",
        "Area authentication",
        "area {area} authentication [{message_digest}]",
        (
            _area(),
            _flag("message_digest", "MD5", "message-digest", "Unticked: a plain password"),
        ),
        no_line="no area {area} authentication",
        help="Every interface in the area must then have a key (set on the interface)",
        group="Areas",
    )


_SOURCES_V4 = ("bgp", "direct", "eigrp", "isis", "ospf", "rip", "static")
_SOURCES_V6 = ("bgp", "direct", "eigrp", "isis", "ospfv3", "rip", "static")
_SOURCE_WORDS = {
    "bgp": "BGP",
    "direct": "connected networks",
    "eigrp": "EIGRP",
    "isis": "IS-IS",
    "ospf": "another OSPF process",
    "ospfv3": "another OSPFv3 process",
    "rip": "RIP",
    "static": "static routes",
}


def _redistribute(source: str) -> Setting:
    if source == "bgp":
        line = "redistribute bgp {asn} route-map {route_map}"
        fields: tuple[Field, ...] = (
            Field("asn", "BGP AS", "asn", hint="This switch's BGP AS number"),
            _route_map(),
        )
    elif source in ("direct", "static"):
        line = f"redistribute {source} route-map {{route_map}}"
        fields = (_route_map(),)
    else:
        line = f"redistribute {source} {{source_tag}} route-map {{route_map}}"
        fields = (
            Field("source_tag", "Its process", "name", hint="The other process's name"),
            _route_map(),
        )
    return Setting(
        f"redistribute_{source}",
        f"Redistribute {_SOURCE_WORDS[source]}",
        line,
        fields,
        help=f"Advertise {_SOURCE_WORDS[source]} in OSPF, as the route-map allows",
        group="Redistribution",
    )


def _route_settings(version: int) -> tuple[Setting, ...]:
    """Redistribution, default route, summaries, distance, paths, SPF timers.

    OSPF has them at the router level, OSPFv3 in its IPv6 address family.
    """
    prefix = "prefix4" if version == 4 else "prefix6"
    sources = _SOURCES_V4 if version == 4 else _SOURCES_V6
    maximum_no = None if version == 4 else "no redistribute maximum-prefix"
    return (
        *(_redistribute(source) for source in sources),
        Setting(
            "redistribute_maximum",
            "Redistribution limit",
            "redistribute maximum-prefix {maximum} [{threshold}] [{limit_action}]",
            (
                _number("maximum", "Most routes", 1, 65536),
                Field(
                    "threshold",
                    "Warn at percent",
                    "int",
                    minimum=1,
                    maximum=100,
                    optional=True,
                ),
                Field(
                    "limit_action",
                    "When over",
                    "choice",
                    choices=("warning-only", "withdraw"),
                    optional=True,
                    hint="warning-only: only log; withdraw: drop the redistributed routes",
                ),
            ),
            no_line=maximum_no,
            help="Cap how many redistributed routes OSPF takes",
            group="Redistribution",
        ),
        Setting(
            "default_information",
            "Send a default route",
            "default-information originate [{always}] [route-map {route_map}]",
            (
                _flag(
                    "always",
                    "Even without one",
                    "always",
                    "Send it even when this switch has no default route",
                ),
                _route_map(optional=True),
            ),
            no_line="no default-information originate",
            help="Advertise a default route to the rest of OSPF",
            group="Redistribution",
        ),
        Setting(
            "default_metric",
            "Cost of redistributed routes",
            "default-metric {metric}",
            (_number("metric", "Cost", 1, 16777214),),
            group="Redistribution",
        ),
        Setting(
            "summary_address",
            "Summary address",
            "summary-address {prefix} [tag {summary_tag}]",
            (
                Field("prefix", "Network", prefix),
                Field(
                    "summary_tag",
                    "Tag",
                    "int",
                    minimum=0,
                    maximum=4294967295,
                    optional=True,
                    hint="A number route-maps can match",
                ),
            ),
            no_line="no summary-address {prefix}",
            help="Advertise one summary for the redistributed networks inside it",
            group="Summaries",
        ),
        Setting(
            "summary_hidden",
            "Hidden summary",
            "summary-address {prefix} not-advertise",
            (Field("prefix", "Network", prefix),),
            no_line="no summary-address {prefix}",
            help="Advertise neither the summary nor the redistributed networks inside it",
            group="Summaries",
        ),
        Setting(
            "distance",
            "Distance",
            "distance {distance}",
            (
                _number(
                    "distance", "Distance", 1, 255, "Lower wins over other protocols; default 110"
                ),
            ),
            group="Routes",
        ),
        Setting(
            "maximum_paths",
            "Equal paths",
            "maximum-paths {paths}",
            (_number("paths", "Paths", 1, 16, "Default 8"),),
            help="How many equal-cost paths to one network OSPF uses at once",
            group="Routes",
        ),
        Setting(
            "table_map",
            "Route filter to the route table",
            "table-map {route_map} [{filter}]",
            (
                _route_map(),
                _flag("filter", "Drop denied routes", "filter", "Unticked: only change them"),
            ),
            help="Change or drop OSPF routes on their way into the switch's route table",
            group="Routes",
        ),
        _spf_timers(),
    )


def _spf_timers() -> Setting:
    return Setting(
        "timers_spf",
        "Route calculation timers",
        "timers throttle spf {spf_start} {spf_hold} {spf_max}",
        (
            _number("spf_start", "First wait (ms)", 1, 600000, "Default 200"),
            _number("spf_hold", "Hold (ms)", 1, 600000, "Default 1000"),
            _number("spf_max", "Longest wait (ms)", 1, 600000, "Default 5000"),
        ),
        help="How long OSPF waits before working out routes again after a change",
        group="Timers",
    )


def _timer_settings() -> tuple[Setting, ...]:
    return (
        Setting(
            "timers_lsa",
            "Update sending timers",
            "timers throttle lsa {lsa_start} {lsa_hold} {lsa_max}",
            (
                _number("lsa_start", "First wait (ms)", 0, 5000, "Default 0"),
                _number("lsa_hold", "Hold (ms)", 50, 30000, "Default 5000"),
                _number("lsa_max", "Longest wait (ms)", 50, 30000, "Default 5000"),
            ),
            help="How fast this switch sends updates about its own links",
            group="Timers",
        ),
        Setting(
            "lsa_arrival",
            "Update arrival time",
            "timers lsa-arrival {arrival}",
            (_number("arrival", "Milliseconds", 10, 600000, "Default 1000"),),
            help="The shortest time between two copies of one update this switch accepts",
            group="Timers",
        ),
        Setting(
            "lsa_pacing",
            "Update refresh grouping",
            "timers lsa-group-pacing {pacing}",
            (_number("pacing", "Seconds", 1, 1800, "Default 240"),),
            group="Timers",
        ),
    )


def _restart_settings() -> tuple[Setting, ...]:
    return (
        Setting(
            "graceful_restart",
            "Graceful restart",
            "graceful-restart [{planned_only}]",
            (_flag("planned_only", "Planned restarts only", "planned-only"),),
            no_line="no graceful-restart",
            help="On by default: neighbors keep forwarding while OSPF restarts; "
            "removing it turns graceful restart off",
            group="Graceful restart",
        ),
        Setting(
            "grace_period",
            "Grace period",
            "graceful-restart grace-period {grace}",
            (_number("grace", "Seconds", 5, 1800, "Default 60"),),
            group="Graceful restart",
        ),
        Setting(
            "helper_disable",
            "Do not help neighbors restart",
            "graceful-restart helper-disable",
            group="Graceful restart",
        ),
    )


def _max_lsa() -> Setting:
    return Setting(
        "max_lsa",
        "Update limit",
        "max-lsa {max_lsa} [{lsa_threshold}] [{lsa_warning}]",
        (
            _number("max_lsa", "Most updates", 1, 4294967295),
            Field("lsa_threshold", "Warn at percent", "int", minimum=1, maximum=100, optional=True),
            _flag("lsa_warning", "Only warn", "warning-only"),
        ),
        help="Cap how many updates from other routers this process keeps",
        group="Stub router",
    )


def _max_metric(version: int) -> Setting:
    if version == 4:
        line = (
            "max-metric router-lsa [{external}] [{include_stub}] [on-startup {startup}] [{summary}]"
        )
        fields = (
            _flag("external", "Also external routes", "external-lsa"),
            _flag("include_stub", "Also stub networks", "include-stub"),
            Field(
                "startup", "Only after start (s)", "int", minimum=5, maximum=86400, optional=True
            ),
            _flag("summary", "Also summaries", "summary-lsa"),
        )
    else:
        line = (
            "max-metric router-lsa [{external}] [{stub_prefix}] [on-startup {startup}] "
            "[{inter_area}]"
        )
        fields = (
            _flag("external", "Also external routes", "external-lsa"),
            _flag("stub_prefix", "Also stub networks", "stub-prefix-lsa"),
            Field(
                "startup", "Only after start (s)", "int", minimum=5, maximum=86400, optional=True
            ),
            _flag("inter_area", "Also summaries", "inter-area-prefix-lsa"),
        )
    return Setting(
        "max_metric",
        "Stub router",
        line,
        fields,
        no_line="no max-metric router-lsa",
        help="Advertise this switch's links at the highest cost so traffic goes around it "
        "(for maintenance)",
        group="Stub router",
    )


def _ospf_router_settings() -> tuple[Setting, ...]:
    return (
        _router_id(),
        _auto_cost(),
        *_basics(),
        Setting(
            "rfc1583",
            "RFC 1583 compatibility",
            "rfc1583compatibility",
            help="Choose routes the way old OSPF routers do",
            group="Basics",
        ),
        *_area_settings(with_routes=True),
        _authentication(),
        *_route_settings(4),
        *_timer_settings(),
        *_restart_settings(),
        _max_metric(4),
        _max_lsa(),
    )


def _ospfv3_router_settings() -> tuple[Setting, ...]:
    return (
        _router_id(),
        _auto_cost(),
        *_basics(),
        *_area_settings(with_routes=False),
        *_timer_settings(),
        *_restart_settings(),
        _max_metric(6),
        _max_lsa(),
    )


def _ospfv3_af_settings() -> tuple[Setting, ...]:
    return (*_route_settings(6), *_area_route_settings(6))


# ---- interface settings -----------------------------------------------------------


def _interface_settings(version: int) -> tuple[Setting, ...]:
    word = "ip ospf" if version == 4 else "ospfv3"
    join = "ip router ospf" if version == 4 else "ipv6 router ospfv3"
    process = Field("process", "Process", "name", hint="The OSPF process's name", placeholder="1")
    found = [
        Setting(
            "router",
            "Process and area",
            f"{join} {{process}} area {{area}} [{{secondaries}}]",
            (
                process,
                _area(),
                _flag(
                    "secondaries",
                    "Leave out secondary addresses",
                    "secondaries none",
                ),
            ),
            no_line=f"no {join} {{process}} area {{area}}",
            help="Run OSPF on this interface, in this area",
            group="OSPF on this interface",
        ),
        Setting(
            "multi_area",
            "Extra area",
            f"{join} {{process}} multi-area {{area}}",
            (process, _area()),
            help="Also put this interface in a second area",
            group="OSPF on this interface",
        ),
        Setting(
            "cost",
            "Cost",
            f"{word} cost {{cost}}",
            (_number("cost", "Cost", 1, 65535, "Lower is preferred"),),
            help="What a path through this interface costs; by default worked out from its speed",
            group="OSPF on this interface",
        ),
        Setting(
            "priority",
            "Priority",
            f"{word} priority {{priority}}",
            (_number("priority", "Priority", 0, 255, "0 never becomes designated router"),),
            help="Who wins the designated router election on a shared network (default 1)",
            group="OSPF on this interface",
        ),
        Setting(
            "network",
            "Network type",
            f"{word} network {{network}}",
            (Field("network", "Type", "choice", choices=("point-to-point", "broadcast")),),
            no_line=f"no {word} network",
            help="point-to-point for a link to one other router: no designated router, "
            "faster to come up",
            group="OSPF on this interface",
        ),
        Setting(
            "passive",
            "Passive",
            f"{word} passive-interface",
            help="Advertise this interface's network but talk to no neighbor on it; removing "
            "it makes the interface active even when the process is passive by default",
            group="OSPF on this interface",
        ),
        Setting(
            "mtu_ignore",
            "Ignore MTU mismatch",
            f"{word} mtu-ignore",
            help="Become neighbors even when the two ends have a different MTU",
            group="OSPF on this interface",
        ),
        Setting(
            "hello",
            "Hello interval",
            f"{word} hello-interval {{hello}}",
            (_number("hello", "Seconds", 1, 65535, "Default 10; both ends must match"),),
            group="Timers",
        ),
        Setting(
            "dead",
            "Dead interval",
            f"{word} dead-interval {{dead}}",
            (
                _number(
                    "dead",
                    "Seconds",
                    1,
                    65535,
                    "Default four hellos; both ends must match",
                ),
            ),
            help="How long without a hello before the neighbor counts as gone",
            group="Timers",
        ),
        Setting(
            "retransmit",
            "Retransmit interval",
            f"{word} retransmit-interval {{retransmit}}",
            (_number("retransmit", "Seconds", 1, 65535, "Default 5"),),
            group="Timers",
        ),
        Setting(
            "transmit_delay",
            "Transmit delay",
            f"{word} transmit-delay {{delay}}",
            (_number("delay", "Seconds", 1, 450, "Default 1"),),
            group="Timers",
        ),
        Setting(
            "bfd",
            "BFD",
            f"{word} bfd",
            help="Use BFD to notice a dead neighbor on this interface in under a second",
            group="BFD",
        ),
        Setting(
            "bfd_disable",
            "No BFD here",
            f"{word} bfd disable",
            help="Leave this interface out when BFD is on for the whole process",
            group="BFD",
        ),
        Setting(
            "shutdown",
            "Stop OSPF here",
            f"{word} shutdown",
            warning="Stopping OSPF on the interface drops its neighbors.",
            group="OSPF on this interface",
        ),
    ]
    if version == 6:
        found.append(
            Setting(
                "instance",
                "Instance ID",
                "ospfv3 instance {instance}",
                (_number("instance", "Instance", 0, 255, "Default 0; both ends must match"),),
                group="OSPF on this interface",
            )
        )
        return tuple(found)
    found += [
        Setting(
            "authentication",
            "Authentication",
            "ip ospf authentication [{auth_mode}]",
            (
                Field(
                    "auth_mode",
                    "Kind",
                    "choice",
                    choices=("message-digest", "null"),
                    optional=True,
                    hint="Empty: a plain password; message-digest: MD5; null: none, even "
                    "when the area asks for it",
                ),
            ),
            no_line="no ip ospf authentication",
            group="Authentication",
        ),
        Setting(
            "key_chain",
            "Key chain",
            "ip ospf authentication key-chain {key_chain}",
            (
                Field(
                    "key_chain",
                    "Key chain",
                    "name",
                    hint="A key chain made on the Routing policy page",
                ),
            ),
            help="Take the keys from a key chain",
            group="Authentication",
        ),
        Setting(
            "password",
            "Plain password",
            "ip ospf authentication-key {password}",
            (Field("password", "Password", "secret"),),
            no_line="no ip ospf authentication-key",
            group="Authentication",
        ),
        Setting(
            "md5_key",
            "MD5 key",
            "ip ospf message-digest-key {key_id} md5 {md5_key}",
            (
                _number("key_id", "Key number", 1, 255, "Both ends must use the same number"),
                Field("md5_key", "Key", "secret"),
            ),
            no_line="no ip ospf message-digest-key {key_id}",
            group="Authentication",
        ),
    ]
    return tuple(found)


# ---- reading ------------------------------------------------------------------------

_DURATION = re.compile(
    r"^P(?:(?P<d>\d+)D)?(?:T(?:(?P<h>\d+)H)?(?:(?P<m>\d+)M)?(?:(?P<s>\d+(?:\.\d+)?)S)?)?$"
)
_STATE = {
    "DOWN": "down",
    "LOOPBACK": "loopback",
    "WAITING": "waiting",
    "P2P": "point-to-point",
    "DR": "designated router",
    "BDR": "backup designated router",
    "DROTHER": "other router",
}
_NETWORK = {"P2P": "point-to-point", "BCAST": "broadcast", "BROADCAST": "broadcast"}
_AUTH = {"none": "none", "md": "MD5", "simple": "plain password"}


def _body(bodies: list[dict[str, Any]], index: int) -> dict[str, Any]:
    return bodies[index] if index < len(bodies) and isinstance(bodies[index], dict) else {}


def _yes(value: Any) -> bool:
    return text(value).lower() == "true"


def _seconds(value: Any) -> float | None:
    match = _DURATION.match(text(value))
    if not match or not any(match.groupdict().values()):
        return None
    parts = {k: float(v) if v else 0.0 for k, v in match.groupdict().items()}
    return parts["d"] * 86400 + parts["h"] * 3600 + parts["m"] * 60 + parts["s"]


def _duration(value: Any) -> str:
    """ "P7DT11H59M45S" -> "7d 11h 59m 45s"; anything else as it is."""
    raw = text(value)
    match = _DURATION.match(raw)
    if not match or not any(match.groupdict().values()):
        return raw
    shown = [f"{v}{k}" for k, v in match.groupdict().items() if v and float(v)]
    return " ".join(shown) or "0s"


def _area_type(row: dict[str, Any]) -> str:
    if _yes(row.get("stub")):
        return "stub, no summaries" if _yes(row.get("no_summary")) else "stub"
    if _yes(row.get("nssa")):
        words = ["NSSA"]
        if _yes(row.get("no_summary")):
            words.append("no summaries")
        if _yes(row.get("no_redist")):
            words.append("no redistribution")
        return ", ".join(words)
    return "backbone" if text(row.get("aname")) == "0.0.0.0" else "normal"


def _ranges(row: dict[str, Any]) -> str:
    found = []
    for item in table_rows(row, "TABLE_range", "ROW_range"):
        prefix = f"{text(item.get('addr'))}/{text(item.get('masklen'))}"
        if text(item.get("advertise")) not in ("", "advertise"):
            prefix += " (hidden)"
        found.append(prefix)
    return ", ".join(found)


def _process_values(row: dict[str, Any], version: int) -> dict[str, dict[str, str]]:
    """The router-level settings the output tells, as field values."""
    values: dict[str, dict[str, str]] = {}
    if rid := text(row.get("rid")):
        values["router_id"] = {"router_id": rid}
    bandwidth = text(row.get("ref_bw"))
    if bandwidth.isdigit():
        mbps = int(bandwidth)
        values["auto_cost"] = (
            {"bandwidth": str(mbps // 1000), "unit": "Gbps"}
            if mbps % 1000 == 0
            else {"bandwidth": str(mbps), "unit": "Mbps"}
        )
    if _yes(row.get("passive_dflt")):
        values["passive_default"] = {}
    if _yes(row.get("gr_ha")):
        planned = "planned-only" if _yes(row.get("gr_planned_only")) else ""
        values["graceful_restart"] = {"planned_only": planned}
        grace = _seconds(row.get("gr_grace_period"))
        if grace is not None:
            values["grace_period"] = {"grace": str(int(grace))}
    if version == 4:
        values.update(_route_values(row))
    return values


def _route_values(row: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Distance and paths: router level in OSPF, the address family in OSPFv3."""
    values: dict[str, dict[str, str]] = {}
    if distance := text(row.get("admin_dist")):
        values["distance"] = {"distance": distance}
    if paths := text(row.get("spf_max_paths")):
        values["maximum_paths"] = {"paths": paths}
    return values


def _process_facts(row: dict[str, Any], areas: list[dict[str, Any]]) -> tuple[tuple[str, str], ...]:
    facts = [
        ("Router ID", text(row.get("rid")) or "none yet"),
        ("VRF", text(row.get("cname")) or "default"),
        (
            "State",
            f"{text(row.get('act_area_total')) or '0'} of "
            f"{text(row.get('area_total')) or '0'} areas active",
        ),
    ]
    roles = []
    if _yes(row.get("is_abr")):
        roles.append("area border router")
    if _yes(row.get("is_asbr")):
        roles.append("AS boundary router (brings in outside routes)")
    if roles:
        facts.append(("Role", ", ".join(roles)))
    if areas:
        facts.append(
            ("Areas", ", ".join(f"{text(a.get('aname'))} ({_area_type(a)})" for a in areas))
        )
    if bandwidth := text(row.get("ref_bw")):
        facts.append(("Reference bandwidth", f"{bandwidth} Mbps"))
    facts.append(
        (
            "SPF timers",
            f"start {_duration(row.get('spf_start_time'))}, hold "
            f"{_duration(row.get('spf_hold_time'))}, max {_duration(row.get('spf_max_time'))}",
        )
    )
    if distance := text(row.get("admin_dist")):
        facts.append(("Distance", distance))
    if paths := text(row.get("spf_max_paths")):
        facts.append(("Equal paths", paths))
    redistributed = [text(r.get("proto")) for r in table_rows(row, "TABLE_redist", "ROW_redist")]
    if redistributed:
        facts.append(("Redistributes", ", ".join(p for p in redistributed if p)))
    if _yes(row.get("passive_dflt")):
        facts.append(("Interfaces", "passive unless made active"))
    if _yes(row.get("gr_ha")):
        planned = " (planned restarts only)" if _yes(row.get("gr_planned_only")) else ""
        facts.append(
            (
                "Graceful restart",
                f"on{planned}, grace period {_duration(row.get('gr_grace_period'))}",
            )
        )
    else:
        facts.append(("Graceful restart", "off"))
    if _yes(row.get("max_metric_adver")):
        facts.append(("Stub router", "advertising the highest cost"))
    return tuple(facts)


def _processes(
    body: dict[str, Any], version: int, area_rows: list[tuple[str, ...]]
) -> list[Instance]:
    """Process, VRF-part and (OSPFv3) address-family instances; fills ``area_rows``."""
    found: list[Instance] = []
    for row in table_rows(body, "TABLE_ctx", "ROW_ctx"):
        tag = text(row.get("ptag"))
        if not tag:
            continue
        vrf = text(row.get("cname")) or "default"
        areas = table_rows(row, "TABLE_area", "ROW_area")
        for area in areas:
            area_rows.append(
                (
                    tag,
                    vrf,
                    text(area.get("aname")),
                    _area_type(area),
                    _AUTH.get(text(area.get("auth_type")), text(area.get("auth_type")) or "-"),
                    text(area.get("total_intf")) or "0",
                    _ranges(area) or "-",
                )
            )
        facts = _process_facts(row, areas)
        values = _process_values(row, version)
        if vrf == "default":
            found.append(Instance("process", {"tag": tag}, tag, facts, values))
        else:
            found.append(
                Instance("vrf", {"tag": tag, "vrf": vrf}, f"{tag}, VRF {vrf}", facts, values)
            )
        if version == 6:
            title = f"{tag} IPv6" if vrf == "default" else f"{tag}, VRF {vrf}, IPv6"
            found.append(Instance("af", {"tag": tag, "vrf": vrf}, title, values=_route_values(row)))
    return found


def _interfaces(body: dict[str, Any]) -> tuple[list[Instance], list[tuple[str, ...]]]:
    instances: dict[str, Instance] = {}
    rows: list[tuple[str, ...]] = []
    for ctx in table_rows(body, "TABLE_ctx", "ROW_ctx"):
        tag = text(ctx.get("ptag"))
        vrf = text(ctx.get("cname")) or "default"
        for row in table_rows(ctx, "TABLE_intf", "ROW_intf"):
            name = long_name(text(row.get("ifname")))
            if not name:
                continue
            area = text(row.get("area"))
            cost = text(row.get("cost"))
            kind = text(row.get("type_str")).upper()
            network = _NETWORK.get(kind, "")
            passive = _yes(row.get("passive"))
            state = text(row.get("state_str"))
            rows.append(
                (
                    name,
                    tag,
                    vrf,
                    area,
                    cost,
                    _STATE.get(state.upper(), state.lower()),
                    network or kind.lower(),
                    "yes" if passive else "no",
                )
            )
            if name in instances:
                continue
            values: dict[str, dict[str, str]] = {}
            if tag and area:
                values["router"] = {"process": tag, "area": area, "secondaries": ""}
            if cost:
                values["cost"] = {"cost": cost}
            if network:
                values["network"] = {"network": network}
            if passive:
                values["passive"] = {}
            facts = (("Process", tag), ("VRF", vrf), ("Area", area), ("State", rows[-1][5]))
            instances[name] = Instance("interface", {"interface": name}, name, facts, values)
    return list(instances.values()), rows


def _neighbors(body: dict[str, Any]) -> list[tuple[str, ...]]:
    # Shaped after Cisco's NX-API reference for these commands; rows with
    # neighbors were never seen live (the probe switch had nothing plugged in).
    rows = []
    for ctx in table_rows(body, "TABLE_ctx", "ROW_ctx"):
        tag = text(ctx.get("ptag"))
        vrf = text(ctx.get("cname")) or "default"
        for row in table_rows(ctx, "TABLE_nbr", "ROW_nbr"):
            state = text(row.get("state"))
            role = text(row.get("drstate")).strip(" -")
            rows.append(
                (
                    text(row.get("rid")),
                    text(row.get("addr")),
                    long_name(text(row.get("intf"))),
                    f"{state}/{role}" if role else state,
                    _duration(row.get("uptime")),
                    vrf,
                    tag,
                )
            )
    return rows


def _summaries(body: dict[str, Any]) -> list[tuple[str, ...]]:
    rows = []
    for ctx in table_rows(body, "TABLE_ctx", "ROW_ctx"):
        tag = text(ctx.get("ptag"))
        vrf = text(ctx.get("cname")) or "default"
        for row in table_rows(ctx, "TABLE_sum", "ROW_sum"):
            prefix = f"{text(row.get('addr'))}/{text(row.get('masklen'))}"
            status = "waiting for routes" if _yes(row.get("pending")) else "advertised"
            rows.append((tag, vrf, prefix, status))
    return rows


_NEIGHBOR_COLUMNS = ("Neighbor ID", "Address", "Interface", "State", "Up for", "VRF", "Process")
_INTERFACE_COLUMNS = (
    "Interface",
    "Process",
    "VRF",
    "Area",
    "Cost",
    "State",
    "Network type",
    "Passive",
)
_AREA_COLUMNS = ("Process", "VRF", "Area", "Type", "Authentication", "Interfaces", "Ranges")


def _view(
    processes: list[Instance],
    interfaces: list[Instance],
    tables: list[Table],
    name: str,
) -> ProtocolView:
    notes = () if processes else (f"No {name} process yet. Make one below.",)
    return ProtocolView(tuple(processes + interfaces), tuple(tables), notes)


def parse_ospf(bodies: list[dict[str, Any]]) -> ProtocolView:
    """The OSPF page from ``show ip ospf vrf all``, its interfaces, neighbors and
    summary addresses (in ``OSPF.commands`` order)."""
    area_rows: list[tuple[str, ...]] = []
    processes = _processes(_body(bodies, 0), 4, area_rows)
    interfaces, interface_rows = _interfaces(_body(bodies, 1))
    tables = [
        Table("Neighbors", _NEIGHBOR_COLUMNS, tuple(_neighbors(_body(bodies, 2))), "No neighbors."),
        Table("Interfaces", _INTERFACE_COLUMNS, tuple(interface_rows), "No interface runs OSPF."),
        Table("Areas", _AREA_COLUMNS, tuple(area_rows), "No areas."),
        Table(
            "Summary addresses",
            ("Process", "VRF", "Summary", "Status"),
            tuple(_summaries(_body(bodies, 3))),
            "No summary addresses.",
        ),
    ]
    return _view(processes, interfaces, tables, "OSPF")


def parse_ospfv3(bodies: list[dict[str, Any]]) -> ProtocolView:
    """The OSPFv3 page from ``show ospfv3 vrf all``, its interfaces and neighbors
    (in ``OSPFV3.commands`` order)."""
    area_rows: list[tuple[str, ...]] = []
    processes = _processes(_body(bodies, 0), 6, area_rows)
    interfaces, interface_rows = _interfaces(_body(bodies, 1))
    tables = [
        Table("Neighbors", _NEIGHBOR_COLUMNS, tuple(_neighbors(_body(bodies, 2))), "No neighbors."),
        Table("Interfaces", _INTERFACE_COLUMNS, tuple(interface_rows), "No interface runs OSPFv3."),
        Table("Areas", _AREA_COLUMNS, tuple(area_rows), "No areas."),
    ]
    return _view(processes, interfaces, tables, "OSPFv3")


# ---- the two protocols ----------------------------------------------------------------

_DELETE_WARNING = (
    "Deleting the process drops all its neighbors and routes. The interfaces keep their "
    "OSPF lines; remove those on each interface."
)

OSPF = Protocol(
    key="ospf",
    name="OSPF",
    summary="Link-state routing for IPv4 inside your network",
    features=("ospf",),
    commands=(
        "show ip ospf vrf all",
        "show ip ospf interface vrf all",
        "show ip ospf neighbors vrf all",
        "show ip ospf summary-address vrf all",
    ),
    parse=parse_ospf,
    scopes=(
        Scope(
            "process",
            "OSPF process",
            (_tag_field(),),
            ("router ospf {tag}",),
            _ospf_router_settings(),
            create=True,
            create_label="Make an OSPF process",
            delete=("no router ospf {tag}",),
            delete_warning=_DELETE_WARNING,
            help="A process's settings here apply to the default VRF",
        ),
        Scope(
            "vrf",
            "OSPF in a VRF",
            (_tag_field(), vrf_field(optional=False)),
            ("router ospf {tag}", "vrf {vrf}"),
            _ospf_router_settings(),
            create=True,
            create_label="Run a process in a VRF",
            delete=("router ospf {tag}", "no vrf {vrf}"),
            delete_warning="Deleting a process's VRF part drops its neighbors and routes there.",
            help="The same process, in another VRF, with its own router ID and areas",
        ),
        Scope(
            "interface",
            "Interface",
            (interface_field(),),
            ("interface {interface}",),
            _interface_settings(4),
            help="OSPF on one VLAN interface, routed port or routed port-channel",
        ),
    ),
    about="OSPF finds routes by having every router share a map of its links. Put an "
    "interface in a process and area to run it there.",
)

OSPFV3 = Protocol(
    key="ospfv3",
    name="OSPFv3",
    summary="Link-state routing for IPv6 inside your network",
    features=("ospfv3",),
    commands=(
        "show ospfv3 vrf all",
        "show ospfv3 interface vrf all",
        "show ospfv3 neighbors vrf all",
    ),
    parse=parse_ospfv3,
    scopes=(
        Scope(
            "process",
            "OSPFv3 process",
            (_tag_field(),),
            ("router ospfv3 {tag}",),
            _ospfv3_router_settings(),
            create=True,
            create_label="Make an OSPFv3 process",
            delete=("no router ospfv3 {tag}",),
            delete_warning=_DELETE_WARNING,
            help="A process's settings here apply to the default VRF",
        ),
        Scope(
            "vrf",
            "OSPFv3 in a VRF",
            (_tag_field(), vrf_field(optional=False)),
            ("router ospfv3 {tag}", "vrf {vrf}"),
            _ospfv3_router_settings(),
            create=True,
            create_label="Run a process in a VRF",
            delete=("router ospfv3 {tag}", "no vrf {vrf}"),
            delete_warning="Deleting a process's VRF part drops its neighbors and routes there.",
        ),
        Scope(
            "af",
            "IPv6 routes",
            (_tag_field(), vrf_field()),
            ("router ospfv3 {tag}", "[vrf {vrf}]", "address-family ipv6 unicast"),
            _ospfv3_af_settings(),
            help="Redistribution, the default route, summaries, distance and paths of a "
            "process (in the default VRF or another)",
        ),
        Scope(
            "interface",
            "Interface",
            (interface_field(),),
            ("interface {interface}",),
            _interface_settings(6),
            help="OSPFv3 on one VLAN interface, routed port or routed port-channel",
        ),
    ),
    about="OSPFv3 is OSPF for IPv6. Put an interface in a process and area to run it there.",
)

PROTOCOLS: tuple[Protocol, ...] = (OSPF, OSPFV3)
