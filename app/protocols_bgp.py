"""BGP: the switch's one BGP process, its VRF parts, address families and
neighbors, described for the Routing protocols pages (see ``app/protocols.py``).

Read, in one request, while the bgp feature is on:

- ``show bgp process``: the AS number, whether BGP runs, and per VRF the
  router ID (the one set by hand, too), the cluster ID, the confederation,
  the neighbor counts and the address families with their redistribution;
- ``show bgp all summary vrf all``: every neighbor per VRF and address
  family, with its state, how long it has been in it and the prefixes it sent;
- ``show bgp vrf all all neighbors``: each neighbor's settings (remote AS,
  description, update source, BFD, passive) and per address family its
  policies (route-maps, prefix-lists, filter-lists in and out) and options;
- ``show bgp sessions vrf all``: the TCP sessions, with their ports and drops;
- ``show bgp ipv6 unicast vrf all``: the IPv6 BGP table. ``show ip bgp vrf
  all`` is not read: NX-OS 9.3 refuses it as JSON ("does not support XML
  output"); the IPv4 routes BGP put in use are in the route table on the
  overview.

A switch has one BGP process, for one AS. What can be changed: making and
deleting the process; its router ID, neighbor logging, best-path choices,
timers, graceful restart, confederation, route reflector cluster ID and
safety checks; the VRF parts (each VRF's own router ID, timers, local AS);
the address families of the process and of each VRF (networks, aggregates,
redistribution through a route-map, maximum paths, distance, default route,
dampening, additional paths, next-hop and table maps); neighbors (remote AS,
description, update source, multihop, timers, password, BFD, shutdown, local
AS, private AS removal and the session options) and each neighbor's address
families (route-maps, prefix-lists, filter-lists, soft reconfiguration,
next-hop-self, communities, route reflector client, maximum prefixes,
allowas-in, default route, weight, AS override, unsuppress-map).
Route-maps, prefix-lists and AS-path lists are made on the Routing policy
page; here they are named.

Tried on cisco-25gb (NX-OS 9.3(16)) as NXray's restricted account, all
accepted: ``router bgp 65001`` with ``router-id``, ``log-neighbor-changes``,
``bestpath as-path multipath-relax``; in ``address-family ipv4 unicast``
``network``, ``redistribute static route-map``, ``maximum-paths`` and
``aggregate-address ... summary-only``; ``address-family ipv6 unicast`` with
``network``; a neighbor with ``remote-as``, ``description``,
``update-source``, ``timers``, ``password 0``, ``bfd`` and, in its
``address-family ipv4 unicast``, ``route-map ... in``,
``soft-reconfiguration inbound``, ``next-hop-self``, ``send-community``; an
IPv6 neighbor with its address family; ``vrf`` with ``router-id`` and a
network; ``no neighbor``, ``no description`` and ``no router bgp``. Every
other line follows Cisco's NX-OS 9.3 Unicast Routing guide and command
reference. The neighbors on the probe switch never came up (nothing was
plugged in), so rows of an established neighbor were never seen live: their
handling follows the field names the switch used for idle neighbors and
Cisco's documented output.
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
    route_age,
    source_field,
    table_rows,
    text,
    vrf_field,
)
from app.routing import long_name

# ---- fields ----------------------------------------------------------------------

ADDRESS_FAMILIES = ("ipv4 unicast", "ipv6 unicast", "ipv4 multicast", "ipv6 multicast")


def _asn_field() -> Field:
    return Field(
        "asn",
        "AS number",
        "asn",
        hint="The AS number of this switch's BGP process: 1 to 4294967295, or like 1.10",
        placeholder="65001",
    )


def _af_field() -> Field:
    return Field(
        "af",
        "Address family",
        "choice",
        choices=ADDRESS_FAMILIES,
        hint="Which kind of routes: IPv4 or IPv6, unicast (normal) or multicast",
    )


def _neighbor_field() -> Field:
    return Field(
        "address",
        "Neighbor address",
        "ip",
        hint="The IPv4 or IPv6 address of the other router",
        placeholder="192.0.2.2",
    )


def _route_map(name: str = "route_map", optional: bool = False) -> Field:
    return Field(
        name,
        "Route-map",
        "name",
        optional=optional,
        hint="A route-map made on the Routing policy page",
    )


def _seconds(name: str, label: str, low: int, high: int, hint: str = "") -> Field:
    return Field(name, label, "int", minimum=low, maximum=high, hint=hint)


# ---- settings shared by the process and its VRF parts --------------------------------

_BESTPATH = (
    ("bestpath_multipath_relax", "as-path multipath-relax", "Share load over different AS paths",
     "Use paths of equal length through different AS numbers together"),
    ("bestpath_as_path_ignore", "as-path ignore", "Ignore AS path length",
     "Leave the AS path length out of choosing the best path"),
    ("bestpath_compare_routerid", "compare-routerid", "Compare router IDs",
     "Between equal paths from other ASes, prefer the lowest router ID"),
    ("bestpath_compare_neighborid", "compare-neighborid", "Compare neighbor addresses",
     "Between equal paths, prefer the neighbor with the lowest address"),
    ("bestpath_always_compare_med", "always-compare-med", "Always compare MED",
     "Compare MED between paths from different ASes too"),
    ("bestpath_med_missing_as_worst", "med missing-as-worst", "Missing MED is worst",
     "Treat a path without a MED as the worst"),
    ("bestpath_med_confed", "med confed", "MED inside the confederation",
     "Compare MED only between paths from inside the confederation"),
    ("bestpath_med_non_deterministic", "med non-deterministic", "Non-deterministic MED",
     "Do not always pick the best-MED path among those from the same AS"),
    ("bestpath_cost_community_ignore", "cost-community ignore", "Ignore cost community",
     "Leave the cost community out of choosing the best path"),
    ("bestpath_igp_metric_ignore", "igp-metric ignore", "Ignore IGP metric",
     "Leave the IGP metric to the next hop out of choosing the best path"),
)  # fmt: skip


def _common_settings() -> tuple[Setting, ...]:
    """The lines the process and each of its VRF parts both take."""
    bestpath = tuple(
        Setting(key, label, f"bestpath {words}", help=help_text, group="Best path")
        for key, words, label, help_text in _BESTPATH
    )
    return (
        Setting(
            "router_id",
            "Router ID",
            "router-id {router_id}",
            (Field("router_id", "Router ID", "ipv4", placeholder="192.0.2.1"),),
            help="The address this switch calls itself in BGP; by default the highest "
            "loopback or interface address",
            warning="Changing the router ID restarts every BGP session here.",
            group="Identity",
        ),
        Setting(
            "log_neighbor_changes",
            "Log neighbor changes",
            "log-neighbor-changes",
            help="Write a log message when a neighbor comes up or goes down",
            group="Identity",
        ),
        *bestpath,
        Setting(
            "timers",
            "Keepalive and hold timers",
            "timers bgp {keepalive} {hold}",
            (
                _seconds("keepalive", "Keepalive (seconds)", 0, 3600, "60 by default"),
                _seconds("hold", "Hold time (seconds)", 0, 3600, "180 by default"),
            ),
            help="How often neighbors say hello, and how long without one before a "
            "neighbor counts as gone",
            warning="New timers apply when sessions start again.",
            group="Timers",
        ),
        Setting(
            "graceful_restart",
            "Graceful restart",
            "graceful-restart",
            help="On by default: keep forwarding while BGP restarts, and help neighbors "
            "that restart. Removing it turns it off.",
            warning="Turning graceful restart on or off resets the BGP sessions.",
            group="Graceful restart",
        ),
        Setting(
            "graceful_restart_time",
            "Restart time",
            "graceful-restart restart-time {restart_time}",
            (_seconds("restart_time", "Restart time (seconds)", 1, 3600, "120 by default"),),
            help="How long neighbors wait for this switch to come back after a restart",
            group="Graceful restart",
        ),
        Setting(
            "graceful_restart_stalepath",
            "Stale path time",
            "graceful-restart stalepath-time {stalepath_time}",
            (_seconds("stalepath_time", "Stale path time (seconds)", 1, 3600, "300 by default"),),
            help="How long routes from a restarting neighbor are kept",
            group="Graceful restart",
        ),
        Setting(
            "graceful_restart_helper",
            "Graceful restart helper only",
            "graceful-restart-helper",
            help="Help restarting neighbors without restarting gracefully itself",
            group="Graceful restart",
        ),
        Setting(
            "cluster_id",
            "Route reflector cluster ID",
            "cluster-id {cluster_id}",
            (Field("cluster_id", "Cluster ID", "ipv4", placeholder="192.0.2.1"),),
            help="Shared by the route reflectors of one cluster; the router ID by default",
            warning="Changing the cluster ID refreshes every BGP session here.",
            group="Route reflection and confederation",
        ),
        Setting(
            "maxas_limit",
            "Longest AS path accepted",
            "maxas-limit {as_limit}",
            (Field("as_limit", "AS numbers", "int", minimum=1, maximum=512),),
            help="Drop routes from other ASes whose AS path is longer than this",
            group="Safety",
        ),
    )


_PROCESS_SETTINGS = (
    *_common_settings(),
    Setting(
        "confederation_id",
        "Confederation identifier",
        "confederation identifier {confed_id}",
        (Field("confed_id", "Confederation AS", "asn"),),
        help="The AS number a confederation of ASes shows to the outside",
        warning="This resets every BGP session.",
        group="Route reflection and confederation",
    ),
    Setting(
        "confederation_peers",
        "Confederation peers",
        "confederation peers {peer1} [{peer2}] [{peer3}] [{peer4}]",
        (
            Field("peer1", "Member AS", "asn"),
            Field("peer2", "Member AS", "asn", optional=True),
            Field("peer3", "Member AS", "asn", optional=True),
            Field("peer4", "Member AS", "asn", optional=True),
        ),
        help="The other member ASes of the confederation",
        warning="This resets every BGP session.",
        group="Route reflection and confederation",
    ),
    Setting(
        "enforce_first_as",
        "Enforce first AS",
        "enforce-first-as",
        help="Refuse routes from an outside neighbor whose AS path does not start with "
        "that neighbor's AS. Removing it turns the check off.",
        group="Safety",
    ),
    Setting(
        "fast_external_fallover",
        "Fast external fallover",
        "fast-external-fallover",
        help="On by default: drop a session to a directly connected outside neighbor as "
        "soon as the link goes down. Removing it turns this off.",
        group="Safety",
    ),
    Setting(
        "shutdown",
        "Shut BGP down",
        "shutdown",
        help="Stop BGP without deleting its settings; removing it starts BGP again",
        warning="Every BGP session on the switch goes down and its routes are withdrawn.",
        group="On or off",
    ),
)

_VRF_SETTINGS = (
    *_common_settings(),
    Setting(
        "local_as",
        "Local AS for this VRF",
        "local-as {local_as}",
        (Field("local_as", "Local AS", "asn"),),
        help="The AS number this VRF uses instead of the process's own",
        warning="This resets the sessions in this VRF.",
        group="Identity",
    ),
)

# ---- address family settings -----------------------------------------------------------

_REDISTRIBUTED = ("direct", "static")
_PROTOCOLS = ("ospf", "ospfv3", "eigrp", "rip", "isis")

_AF_SETTINGS = (
    Setting(
        "network",
        "Network",
        "network {prefix} [route-map {route_map}]",
        (
            Field("prefix", "Network", "prefix", placeholder="192.0.2.0/24"),
            _route_map(optional=True),
        ),
        help="Announce this network; it must be in the routing table exactly",
        group="What is announced",
    ),
    Setting(
        "aggregate",
        "Aggregate (summary)",
        "aggregate-address {prefix} [{as_set}] [{summary_only}] "
        "[advertise-map {advertise_map}] [attribute-map {attribute_map}] "
        "[suppress-map {suppress_map}]",
        (
            Field("prefix", "Summary network", "prefix", placeholder="192.0.2.0/23"),
            Field(
                "as_set", "Keep the AS numbers of the parts (as-set)", "flag", choices=("as-set",)
            ),
            Field("summary_only", "Announce only the summary", "flag", choices=("summary-only",)),
            _route_map("advertise_map", optional=True),
            _route_map("attribute_map", optional=True),
            _route_map("suppress_map", optional=True),
        ),
        help="Announce one network in place of the smaller ones inside it",
        group="What is announced",
    ),
    Setting(
        "redistribute",
        "Redistribute connected or static",
        "redistribute {source} route-map {route_map}",
        (
            Field(
                "source",
                "Routes",
                "choice",
                choices=_REDISTRIBUTED,
                hint="direct: connected networks; static: static routes",
            ),
            _route_map(),
        ),
        help="Announce connected networks or static routes, through a route-map",
        group="What is announced",
    ),
    Setting(
        "redistribute_protocol",
        "Redistribute a routing protocol",
        "redistribute {protocol} {tag} route-map {route_map}",
        (
            Field(
                "protocol",
                "Protocol",
                "choice",
                choices=_PROTOCOLS,
                hint="ospf for IPv4, ospfv3 for IPv6",
            ),
            Field("tag", "Process tag", "name", hint="The process's tag, such as core"),
            _route_map(),
        ),
        help="Announce the routes another routing protocol learned, through a route-map",
        group="What is announced",
    ),
    Setting(
        "default_information",
        "Default route",
        "default-information originate",
        help="Let a redistributed default route (0.0.0.0/0, ::/0) be announced",
        group="What is announced",
    ),
    Setting(
        "maximum_paths",
        "Equal paths used (outside)",
        "maximum-paths {paths}",
        (Field("paths", "Paths", "int", minimum=1, maximum=64, hint="1 by default"),),
        help="How many equal routes learned from other ASes are used together",
        group="Paths",
    ),
    Setting(
        "maximum_paths_ibgp",
        "Equal paths used (inside)",
        "maximum-paths ibgp {paths}",
        (Field("paths", "Paths", "int", minimum=1, maximum=64, hint="1 by default"),),
        help="How many equal routes learned inside this AS are used together",
        group="Paths",
    ),
    Setting(
        "distance",
        "Distance",
        "distance {external} {internal} {local}",
        (
            Field(
                "external", "From other ASes", "int", minimum=1, maximum=255, hint="20 by default"
            ),
            Field(
                "internal",
                "From inside this AS",
                "int",
                minimum=1,
                maximum=255,
                hint="200 by default",
            ),
            Field(
                "local", "Local (aggregates)", "int", minimum=1, maximum=255, hint="220 by default"
            ),
        ),
        help="How trusted BGP routes are next to other sources; lower wins",
        group="Paths",
    ),
    Setting(
        "dampening",
        "Dampening",
        "dampening [{half_life} {reuse} {suppress} {max_suppress}]",
        (
            Field(
                "half_life",
                "Half-life (minutes)",
                "int",
                minimum=1,
                maximum=45,
                optional=True,
                hint="Leave all four empty for the defaults",
            ),
            Field("reuse", "Reuse limit", "int", minimum=1, maximum=20000, optional=True),
            Field("suppress", "Suppress limit", "int", minimum=1, maximum=20000, optional=True),
            Field(
                "max_suppress",
                "Longest suppression (minutes)",
                "int",
                minimum=1,
                maximum=255,
                optional=True,
            ),
        ),
        help="Hold back routes that keep coming and going",
        group="Stability",
    ),
    Setting(
        "dampening_route_map",
        "Dampening by route-map",
        "dampening route-map {route_map}",
        (_route_map(),),
        help="Dampening with the values a route-map sets",
        group="Stability",
    ),
    Setting(
        "additional_paths_send",
        "Send additional paths",
        "additional-paths send",
        help="Offer neighbors more than the best path",
        group="Additional paths",
    ),
    Setting(
        "additional_paths_receive",
        "Receive additional paths",
        "additional-paths receive",
        help="Accept more than the best path from neighbors",
        group="Additional paths",
    ),
    Setting(
        "additional_paths_selection",
        "Additional paths chosen by",
        "additional-paths selection route-map {route_map}",
        (_route_map(),),
        help="The route-map that picks which extra paths are sent",
        group="Additional paths",
    ),
    Setting(
        "nexthop_route_map",
        "Next hops allowed by",
        "nexthop route-map {route_map}",
        (_route_map(),),
        help="Only next hops this route-map allows are used",
        group="Maps",
    ),
    Setting(
        "table_map",
        "Table map",
        "table-map {route_map} [{filter}]",
        (
            _route_map(),
            Field("filter", "Keep out routes the map denies", "flag", choices=("filter",)),
        ),
        help="A route-map applied to BGP routes on their way into the routing table",
        group="Maps",
    ),
)

# ---- neighbor settings -----------------------------------------------------------

_NEIGHBOR_SETTINGS = (
    Setting(
        "remote_as",
        "Remote AS",
        "remote-as {remote_as}",
        (
            Field(
                "remote_as",
                "Remote AS",
                "asn",
                placeholder="65002",
                hint="The neighbor's AS number; this switch's own for a neighbor inside",
            ),
        ),
        removable=False,
        help="Set this first: a neighbor does nothing until it has its AS",
        group="Neighbor",
    ),
    Setting(
        "description",
        "Description",
        "description {description}",
        (Field("description", "Description", "text", maximum=80),),
        help="A note for people: who this neighbor is",
        group="Neighbor",
    ),
    Setting(
        "update_source",
        "Update source",
        "update-source {source}",
        (source_field("source", "Interface"),),
        help="Talk to the neighbor from this interface's address (a loopback for inside neighbors)",
        warning="The session to this neighbor restarts.",
        group="Neighbor",
    ),
    Setting(
        "ebgp_multihop",
        "Hops away (eBGP multihop)",
        "ebgp-multihop {ttl}",
        (Field("ttl", "Hops", "int", minimum=2, maximum=255),),
        help="For an outside neighbor that is not directly connected",
        warning="The session to this neighbor restarts.",
        group="Neighbor",
    ),
    Setting(
        "ttl_security",
        "TTL security",
        "ttl-security hops {hops}",
        (Field("hops", "Hops", "int", minimum=1, maximum=254),),
        help="Accept the neighbor's packets only from at most this many hops away",
        group="Neighbor",
    ),
    Setting(
        "timers",
        "Keepalive and hold timers",
        "timers {keepalive} {hold}",
        (
            _seconds("keepalive", "Keepalive (seconds)", 0, 3600, "60 by default"),
            _seconds("hold", "Hold time (seconds)", 0, 3600, "180 by default"),
        ),
        help="This neighbor's own timers, in place of the process's",
        group="Session",
    ),
    Setting(
        "password",
        "Password",
        "password 0 {password}",
        (Field("password", "Password", "secret"),),
        no_line="no password",
        help="An MD5 password both sides must share",
        warning="The session to this neighbor restarts and stays down until both sides "
        "have the same password.",
        group="Session",
    ),
    Setting(
        "bfd",
        "BFD",
        "bfd",
        help="Notice a failed link within a second (BFD must be on, on the BFD page)",
        group="Session",
    ),
    Setting(
        "shutdown",
        "Shut this neighbor down",
        "shutdown",
        help="Stop the session without deleting the neighbor; removing it starts it again",
        warning="The session to this neighbor goes down and its routes are withdrawn.",
        group="Session",
    ),
    Setting(
        "transport_passive",
        "Wait for the neighbor to connect",
        "transport connection-mode passive",
        help="Never start the connection; only accept it",
        group="Session",
    ),
    Setting(
        "local_as",
        "Local AS for this neighbor",
        "local-as {local_as} [{mode}]",
        (
            Field("local_as", "Local AS", "asn"),
            Field(
                "mode",
                "How",
                "choice",
                optional=True,
                choices=("no-prepend", "no-prepend replace-as", "no-prepend replace-as dual-as"),
            ),
        ),
        help="Show this neighbor another AS number than the process's own",
        group="Session",
    ),
    Setting(
        "remove_private_as",
        "Remove private AS numbers",
        "remove-private-as [{mode}]",
        (Field("mode", "Which", "choice", optional=True, choices=("all", "replace-as")),),
        help="Strip private AS numbers (64512 and up) from routes sent to this neighbor",
        group="Session",
    ),
    Setting(
        "disable_connected_check",
        "Skip the connected check",
        "disable-connected-check",
        help="Allow a one-hop outside session between loopbacks",
        group="Session",
    ),
    Setting(
        "dynamic_capability",
        "Dynamic capability",
        "dynamic-capability",
        help="Change capabilities without restarting the session",
        group="Session",
    ),
    Setting(
        "suppress_4byte_as",
        "Hide 4-byte AS support",
        "capability suppress 4-byte-as",
        help="For old neighbors that do not understand 4-byte AS numbers",
        group="Session",
    ),
)

_NEIGHBOR_AF_SETTINGS = (
    *(
        Setting(
            f"route_map_{way}",
            f"Route-map {way}",
            f"route-map {{route_map}} {way}",
            (_route_map(),),
            help=f"Filter or change the routes {'from' if way == 'in' else 'to'} this neighbor",
            group="Filters",
        )
        for way in ("in", "out")
    ),
    *(
        Setting(
            f"prefix_list_{way}",
            f"Prefix-list {way}",
            f"prefix-list {{prefix_list}} {way}",
            (
                Field(
                    "prefix_list",
                    "Prefix-list",
                    "name",
                    hint="A prefix-list made on the Routing policy page",
                ),
            ),
            help=f"Only the networks this list allows {'come in' if way == 'in' else 'go out'}",
            group="Filters",
        )
        for way in ("in", "out")
    ),
    *(
        Setting(
            f"filter_list_{way}",
            f"AS-path filter {way}",
            f"filter-list {{filter_list}} {way}",
            (Field("filter_list", "AS-path list", "name"),),
            help="Only routes whose AS path this list allows",
            group="Filters",
        )
        for way in ("in", "out")
    ),
    Setting(
        "unsuppress_map",
        "Unsuppress map",
        "unsuppress-map {route_map}",
        (_route_map(),),
        help="Still send this neighbor the parts of a summary the route-map allows",
        group="Filters",
    ),
    Setting(
        "soft_reconfiguration",
        "Soft reconfiguration",
        "soft-reconfiguration inbound [{always}]",
        (Field("always", "Even if the neighbor can refresh", "flag", choices=("always",)),),
        no_line="no soft-reconfiguration inbound",
        help="Keep a copy of what the neighbor sent, so a policy change applies without "
        "resetting the session",
        group="Routes",
    ),
    Setting(
        "next_hop_self",
        "Next hop self",
        "next-hop-self [{all}]",
        (Field("all", "Reflected routes too", "flag", choices=("all",)),),
        help="Send routes to this neighbor with this switch as the next hop",
        group="Routes",
    ),
    Setting(
        "send_community",
        "Send communities",
        "send-community",
        help="Pass the community tags of routes on to this neighbor",
        group="Routes",
    ),
    Setting(
        "send_community_extended",
        "Send extended communities",
        "send-community extended",
        help="Pass the extended community tags on to this neighbor",
        group="Routes",
    ),
    Setting(
        "route_reflector_client",
        "Route reflector client",
        "route-reflector-client",
        help="Pass routes from other neighbors inside this AS on to this one",
        group="Routes",
    ),
    Setting(
        "default_originate",
        "Send a default route",
        "default-originate [route-map {route_map}]",
        (_route_map(optional=True),),
        help="Send this neighbor a default route",
        group="Routes",
    ),
    Setting(
        "weight",
        "Weight",
        "weight {weight}",
        (Field("weight", "Weight", "int", minimum=0, maximum=65535),),
        help="Prefer routes from this neighbor: higher wins, on this switch only",
        group="Routes",
    ),
    Setting(
        "maximum_prefix",
        "Most prefixes accepted",
        "maximum-prefix {limit} [{threshold}] [{warning_only}]",
        (
            Field("limit", "Prefixes", "int", minimum=1, maximum=300000),
            Field(
                "threshold",
                "Warn at (percent)",
                "int",
                minimum=1,
                maximum=100,
                optional=True,
                hint="75 by default",
            ),
            Field("warning_only", "Only warn, keep the session", "flag", choices=("warning-only",)),
        ),
        help="Close the session when the neighbor sends more prefixes than this",
        group="Limits",
    ),
    Setting(
        "maximum_prefix_restart",
        "Most prefixes, then restart",
        "maximum-prefix {limit} [{threshold}] restart {restart}",
        (
            Field("limit", "Prefixes", "int", minimum=1, maximum=300000),
            Field("threshold", "Warn at (percent)", "int", minimum=1, maximum=100, optional=True),
            Field("restart", "Restart after (minutes)", "int", minimum=1, maximum=65535),
        ),
        help="As above, and start the session again after a while",
        group="Limits",
    ),
    Setting(
        "allowas_in",
        "Allow own AS",
        "allowas-in [{count}]",
        (
            Field(
                "count", "Times", "int", minimum=1, maximum=10, optional=True, hint="3 by default"
            ),
        ),
        help="Accept routes that already have this switch's AS in their path",
        group="Loops",
    ),
    Setting(
        "as_override",
        "AS override",
        "as-override",
        help="Replace the neighbor's AS with this switch's in routes sent to it",
        group="Loops",
    ),
    Setting(
        "disable_peer_as_check",
        "Skip the peer AS check",
        "disable-peer-as-check",
        help="Send routes even when their path already holds the neighbor's AS",
        group="Loops",
    ),
    Setting(
        "suppress_inactive",
        "Only active routes",
        "suppress-inactive",
        help="Send this neighbor only the routes in use",
        group="Routes",
    ),
)

# ---- scopes ----------------------------------------------------------------------

_ENTER = "router bgp {asn}"
_IN_VRF = "[vrf {vrf}]"

PROCESS = Scope(
    "process",
    "BGP process",
    (_asn_field(),),
    (_ENTER,),
    _PROCESS_SETTINGS,
    create=True,
    create_label="Start BGP",
    delete=("no router bgp {asn}",),
    delete_warning="Deleting the BGP process removes every BGP setting on the switch: all "
    "neighbors, VRF parts and address families. Every BGP session goes down and every BGP "
    "route is withdrawn.",
    help="The switch has one BGP process, for its one AS number",
)

VRF = Scope(
    "vrf",
    "BGP in a VRF",
    (_asn_field(), vrf_field(optional=False)),
    (_ENTER, _IN_VRF),
    _VRF_SETTINGS,
    create=True,
    create_label="Add a VRF to BGP",
    delete=(_ENTER, "[no vrf {vrf}]"),
    delete_warning="Deleting the VRF part removes its neighbors and address families; "
    "their sessions go down.",
    help="BGP's own settings inside one VRF",
)

ADDRESS_FAMILY = Scope(
    "af",
    "Address family",
    (_asn_field(), vrf_field(), _af_field()),
    (_ENTER, _IN_VRF, "address-family {af}"),
    _AF_SETTINGS,
    create=True,
    create_label="Add an address family",
    delete=(_ENTER, _IN_VRF, "no address-family {af}"),
    delete_warning="Every network, aggregate and redistribution in it goes, and its routes "
    "are withdrawn.",
    help="What BGP announces for IPv4 or IPv6, in the default VRF or one VRF",
)

NEIGHBOR = Scope(
    "neighbor",
    "Neighbor",
    (_asn_field(), vrf_field(), _neighbor_field()),
    (_ENTER, _IN_VRF, "neighbor {address}"),
    _NEIGHBOR_SETTINGS,
    create=True,
    create_label="Add a neighbor",
    delete=(_ENTER, _IN_VRF, "no neighbor {address}"),
    delete_warning="The session to this neighbor goes down and every route from it is withdrawn.",
    help="Another router BGP talks to. Set its remote AS first, then add an address "
    "family to it, or no routes are exchanged.",
)

NEIGHBOR_AF = Scope(
    "neighbor_af",
    "Neighbor address family",
    (_asn_field(), vrf_field(), _neighbor_field(), _af_field()),
    (_ENTER, _IN_VRF, "neighbor {address}", "address-family {af}"),
    _NEIGHBOR_AF_SETTINGS,
    create=True,
    create_label="Exchange this address family with the neighbor",
    delete=(_ENTER, _IN_VRF, "neighbor {address}", "no address-family {af}"),
    delete_warning="Routes of this address family from this neighbor are withdrawn.",
    help="Which routes go to and come from one neighbor, and how",
)

# ---- parsing ---------------------------------------------------------------------


def _true(value: Any) -> bool:
    return text(value).lower() in ("true", "yes", "enabled")


def _af_name(value: Any) -> str:
    """'IPv4 Unicast' -> 'ipv4 unicast' (the words the address-family line takes)."""
    name = " ".join(text(value).lower().split())
    return name if name in ADDRESS_FAMILIES else ""


def _af_label(af: str) -> str:
    """'ipv4 unicast' -> 'IPv4 unicast', for titles."""
    return af.replace("ipv", "IPv")


def _set_id(value: Any) -> str:
    """An ID the switch reports, or "" for its 'not set' forms (0.0.0.0, 0)."""
    found = text(value)
    return "" if found in ("", "0", "0.0.0.0") else found


def _vrf_name(row: dict[str, Any]) -> str:
    return text(row.get("vrf-name-out")) or "default"


def _redistribution(row: dict[str, Any]) -> tuple[str, dict[str, str]] | None:
    """One TABLE_redist row as (setting key, values), or None for one NXray does not offer.

    Only ``static`` was seen live; protocol rows are read as ``ospf-core`` or
    ``ospf`` with a ``tag``, as Cisco's other outputs write them.
    """
    protocol = text(row.get("protocol")).lower()
    route_map = text(row.get("route-map"))
    if protocol in _REDISTRIBUTED:
        return "redistribute", {"source": protocol, "route_map": route_map}
    match = re.fullmatch(r"(ospfv3|ospf|eigrp|rip|isis)[- ]?(\S*)", protocol)
    if match:
        tag = match.group(2) or text(row.get("tag"))
        return "redistribute_protocol", {
            "protocol": match.group(1),
            "tag": tag,
            "route_map": route_map,
        }
    return None


def _process(body: dict[str, Any]) -> tuple[list[Instance], list[str]]:
    """The process, its VRF parts and address families from ``show bgp process``."""
    asn = text(body.get("protocoltag"))
    if not asn:
        return [], []
    instances: list[Instance] = []
    vrf_rows = table_rows(body, "TABLE_vrf", "ROW_vrf")
    default = next((r for r in vrf_rows if _vrf_name(r) == "default"), {})
    values: dict[str, dict[str, str]] = {}
    if router_id := _set_id(default.get("vrf-cfgd-id")):
        values["router_id"] = {"router_id": router_id}
    if cluster := _set_id(default.get("vrf-cluster-id")):
        values["cluster_id"] = {"cluster_id": cluster}
    if confed := _set_id(default.get("vrf-confed-id")):
        values["confederation_id"] = {"confed_id": confed}
    peers = sum(int(text(r.get("vrf-peers")) or 0) for r in vrf_rows)
    established = sum(int(text(r.get("vrf-est-peers")) or 0) for r in vrf_rows)
    state = text(body.get("protocolstate"))
    if text(body.get("isolatemode")).lower() == "yes":
        state += " (isolated)"
    instances.append(
        Instance(
            "process",
            {"asn": asn},
            f"BGP AS {asn}",
            (
                ("AS number", asn),
                ("Router ID", text(default.get("vrf-router-id"))),
                ("State", state),
                ("Neighbors", f"{established} of {peers} established"),
            ),
            values,
        )
    )
    vrfs = []
    for row in vrf_rows:
        vrf = _vrf_name(row)
        vrfs.append(vrf)
        if vrf != "default":
            vrf_values = {}
            if router_id := _set_id(row.get("vrf-cfgd-id")):
                vrf_values["router_id"] = {"router_id": router_id}
            if cluster := _set_id(row.get("vrf-cluster-id")):
                vrf_values["cluster_id"] = {"cluster_id": cluster}
            instances.append(
                Instance(
                    "vrf",
                    {"asn": asn, "vrf": vrf},
                    f"VRF {vrf}",
                    (
                        ("Router ID", text(row.get("vrf-router-id"))),
                        ("State", text(row.get("vrf-state"))),
                        (
                            "Neighbors",
                            f"{text(row.get('vrf-est-peers')) or '0'} of "
                            f"{text(row.get('vrf-peers')) or '0'} established",
                        ),
                    ),
                    vrf_values,
                )
            )
        for af_row in table_rows(row, "TABLE_af", "ROW_af"):
            af = _af_name(af_row.get("af-name"))
            if not af:
                continue
            af_values: dict[str, dict[str, str]] = {}
            redistributed = []
            for redist in table_rows(af_row, "TABLE_redist", "ROW_redist"):
                found = _redistribution(redist)
                route_map = text(redist.get("route-map"))
                redistributed.append(
                    f"{text(redist.get('protocol'))} (route-map {route_map})"
                    if route_map
                    else text(redist.get("protocol"))
                )
                if found and found[0] not in af_values:
                    af_values[found[0]] = found[1]
            if _true(af_row.get("default-information-enabled")):
                af_values["default_information"] = {}
            instances.append(
                Instance(
                    "af",
                    {"asn": asn, "vrf": vrf, "af": af},
                    f"{_af_label(af)} in VRF {vrf}",
                    (
                        ("Networks", text(af_row.get("af-peer-networks")) or "0"),
                        ("Aggregates", text(af_row.get("af-peer-aggregates")) or "0"),
                        ("Routes", text(af_row.get("af-peer-routes")) or "0"),
                        ("Neighbors", text(af_row.get("af-num-peers")) or "0"),
                        ("Redistributes", ", ".join(redistributed) or "nothing"),
                    ),
                    af_values,
                )
            )
    return instances, vrfs


def _summary_vrfs(summary: dict[str, Any], sessions: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Every VRF BGP has, from the summary and sessions: router ID, local AS, neighbor counts."""
    found: dict[str, dict[str, str]] = {}
    for row in table_rows(summary, "TABLE_vrf", "ROW_vrf"):
        found.setdefault(_vrf_name(row), {}).update(
            {"router_id": text(row.get("vrf-router-id")), "asn": text(row.get("vrf-local-as"))}
        )
    for row in table_rows(sessions, "TABLE_vrf", "ROW_vrf"):
        entry = found.setdefault(_vrf_name(row), {})
        entry.setdefault("router_id", text(row.get("router-id")))
        entry.setdefault("asn", text(row.get("local-as")))
        entry["peers"] = text(row.get("vrfpeers")) or "0"
        entry["established"] = text(row.get("vrfestablishedpeers")) or "0"
    return found


def _summary_afs(summary: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    """(VRF, address family, row) for every family the summary gives details of.

    The switch lists IPv4 and IPv6 unicast for every VRF, configured or not;
    only a family it gives a table version for is one that is set up.
    """
    found = []
    for row in table_rows(summary, "TABLE_vrf", "ROW_vrf"):
        for af_row in table_rows(row, "TABLE_af", "ROW_af"):
            for saf in table_rows(af_row, "TABLE_saf", "ROW_saf"):
                af = _af_name(saf.get("af-name"))
                if af:
                    found.append((_vrf_name(row), af, saf))
    return found


def _policies(saf: dict[str, Any], way: str) -> dict[str, dict[str, str]]:
    """The route-map, prefix-list and filter-list a neighbor's family has, one way.

    ``TABLE_inpolicy`` was seen live; ``TABLE_outpolicy`` follows the same
    shape (Cisco's documented field names).
    """
    fields = {"route-map": "route_map", "prefix-list": "prefix_list", "filter-list": "filter_list"}
    values: dict[str, dict[str, str]] = {}
    for row in table_rows(saf, f"TABLE_{way}policy", f"ROW_{way}policy"):
        kind = text(row.get(f"{way}policytype"))
        name = text(row.get(f"{way}policyname"))
        if kind in fields and name:
            values[f"{fields[kind]}_{way}"] = {fields[kind]: name}
    return values


def _neighbor_af_values(saf: dict[str, Any]) -> dict[str, dict[str, str]]:
    values = {**_policies(saf, "in"), **_policies(saf, "out")}
    if _true(saf.get("insoftreconfigallowed")):
        always = "always" if _true(saf.get("insoftreconfigallowedalways")) else ""
        values["soft_reconfiguration"] = {"always": always}
    for key, setting in (
        ("sendcommunity", "send_community"),
        ("sendextcommunity", "send_community_extended"),
        ("asoverride", "as_override"),
        ("peerascheckdisabled", "disable_peer_as_check"),
        ("rrconfigured", "route_reflector_client"),
    ):
        if _true(saf.get(key)):
            values[setting] = {}
    if _true(saf.get("defaultoriginate")):
        values["default_originate"] = {"route_map": text(saf.get("defaultoriginatermap"))}
    return values


def _neighbors(body: dict[str, Any], asn: str) -> list[Instance]:
    """Neighbors and their address families from ``show bgp vrf all all neighbors``.

    The probe's neighbors were idle (nothing plugged in); established rows
    were never seen live and are read with the same field names.
    """
    instances = []
    for row in table_rows(body, "TABLE_neighbor", "ROW_neighbor"):
        address = text(row.get("neighbor")) or text(row.get("ipv6neighbor"))
        if not address:
            continue
        vrf = text(row.get("vrf")) or "default"
        remote_as = text(row.get("remoteas"))
        values: dict[str, dict[str, str]] = {}
        if remote_as:
            values["remote_as"] = {"remote_as": remote_as}
        if description := text(row.get("description")):
            values["description"] = {"description": description}
        if source := text(row.get("sourceif")):
            values["update_source"] = {"source": long_name(source)}
        if _true(row.get("bfd")):
            values["bfd"] = {}
        if _true(row.get("passiveonly")):
            values["transport_passive"] = {}
        if _true(row.get("remove-privateas")):
            values["remove_private_as"] = {"mode": ""}
        state = text(row.get("state"))
        since = route_age(text(row.get("elapsedtime")))
        link = text(row.get("link"))
        facts = [
            ("Remote AS", remote_as),
            ("Kind", {"ebgp": "outside (eBGP)", "ibgp": "inside (iBGP)"}.get(link, link)),
            ("State", f"{state} for {since}" if since else state),
            ("Neighbor's router ID", _set_id(row.get("remote-id")) or "not known yet"),
        ]
        if description:
            facts.append(("Description", description))
        if source:
            facts.append(("Update source", long_name(source)))
        facts.append(
            (
                "Messages",
                f"{text(row.get('msgsent')) or '0'} sent, "
                f"{text(row.get('msgrecvd')) or '0'} received",
            )
        )
        reset = text(row.get("resetreason"))
        if reset and reset != "No error":
            facts.append(("Last reset", reset))
        ident = {"asn": asn, "vrf": vrf, "address": address}
        where = f" in VRF {vrf}" if vrf != "default" else ""
        instances.append(
            Instance("neighbor", ident, f"Neighbor {address}{where}", tuple(facts), values)
        )
        for peraf in table_rows(row, "TABLE_peraf", "ROW_peraf"):
            for saf in table_rows(peraf, "TABLE_persaf", "ROW_persaf"):
                af = _af_name(saf.get("per-af-name"))
                if not af:
                    continue
                instances.append(
                    Instance(
                        "neighbor_af",
                        {**ident, "af": af},
                        f"Neighbor {address}{where}, {_af_label(af)}",
                        (
                            ("Prefixes received", text(saf.get("pfxrecvd")) or "0"),
                            ("Prefixes sent", text(saf.get("pfxsent")) or "0"),
                        ),
                        _neighbor_af_values(saf),
                    )
                )
    return instances


def _neighbor_table(summary: dict[str, Any]) -> Table:
    rows = []
    for vrf, af, saf in _summary_afs(summary):
        for row in table_rows(saf, "TABLE_neighbor", "ROW_neighbor"):
            state = text(row.get("state"))
            rows.append(
                (
                    text(row.get("neighborid")),
                    vrf,
                    af,
                    text(row.get("neighboras")),
                    state,
                    route_age(text(row.get("time"))),
                    text(row.get("prefixreceived")) if state == "Established" else "",
                )
            )
    return Table(
        "Neighbors",
        ("Address", "VRF", "Address family", "Remote AS", "State", "For", "Prefixes received"),
        tuple(rows),
        empty="No neighbors yet.",
    )


def _session_table(sessions: dict[str, Any]) -> Table:
    rows = []
    for vrf_row in table_rows(sessions, "TABLE_vrf", "ROW_vrf"):
        vrf = _vrf_name(vrf_row)
        for row in table_rows(vrf_row, "TABLE_neighbor", "ROW_neighbor"):
            ports = [text(row.get("localport")), text(row.get("remoteport"))]
            rows.append(
                (
                    text(row.get("neighbor-id")),
                    vrf,
                    text(row.get("remoteas")),
                    text(row.get("state")),
                    route_age(text(row.get("lastflap"))),
                    "" if ports == ["0", "0"] else " / ".join(ports),
                    text(row.get("connectionsdropped")) or "0",
                    f"{text(row.get('notificationssent')) or '0'} / "
                    f"{text(row.get('notificationsreceived')) or '0'}",
                )
            )
    return Table(
        "Sessions",
        (
            "Neighbor",
            "VRF",
            "Remote AS",
            "State",
            "Last change",
            "Ports (here / there)",
            "Drops",
            "Notifications (sent / received)",
        ),
        tuple(rows),
        empty="No sessions.",
    )


def _ipv6_table(body: dict[str, Any]) -> Table:
    rows = []
    for vrf_row in table_rows(body, "TABLE_vrf", "ROW_vrf"):
        vrf = _vrf_name(vrf_row)
        for afi in table_rows(vrf_row, "TABLE_afi", "ROW_afi"):
            for safi in table_rows(afi, "TABLE_safi", "ROW_safi"):
                prefixes = table_rows(safi, "TABLE_prefix", "ROW_prefix")
                for rd in table_rows(safi, "TABLE_rd", "ROW_rd"):
                    prefixes += table_rows(rd, "TABLE_prefix", "ROW_prefix")
                for prefix in prefixes:
                    for path in table_rows(prefix, "TABLE_path", "ROW_path"):
                        best = text(path.get("best")).lower()
                        hop = text(path.get("ipv6nexthop"))
                        rows.append(
                            (
                                vrf,
                                text(prefix.get("ipv6prefix")),
                                "this switch" if hop in ("0::", "::") else hop,
                                "yes" if best not in ("", "none", "false") else "",
                                text(path.get("status")),
                                text(path.get("localpref")),
                                text(path.get("weight")),
                                text(path.get("aspath")),
                                text(path.get("origin")),
                            )
                        )
    return Table(
        "IPv6 BGP table",
        (
            "VRF",
            "Network",
            "Next hop",
            "Best",
            "Status",
            "Local preference",
            "Weight",
            "AS path",
            "Origin",
        ),
        tuple(rows),
        empty="No IPv6 BGP routes.",
        note="The switch does not give its IPv4 BGP table as data; the IPv4 routes BGP "
        "uses are in the route table on the Routing protocols page.",
    )


def parse_bgp(bodies: list[dict[str, Any]]) -> ProtocolView:
    """The BGP page from the bodies of ``BGP.commands``, in that order.

    Instances: the process (with its AS, router ID, state and neighbor
    count), each VRF part, each address family, each neighbor and each
    neighbor's address families, with the settings the output tells.
    Tables: neighbors, sessions and the IPv6 BGP table.
    """
    process, summary, neighbors, sessions, ipv6 = ([*bodies, {}, {}, {}, {}, {}])[:5]
    tables = (_neighbor_table(summary), _session_table(sessions), _ipv6_table(ipv6))
    instances, process_vrfs = _process(process)
    if not instances:
        return ProtocolView(
            tables=tables,
            notes=(
                "BGP is on, but there is no BGP process yet: start one with this "
                "switch's AS number.",
            ),
        )
    asn = instances[0].ident["asn"]
    seen_vrfs = set(process_vrfs)
    vrf_info = _summary_vrfs(summary, sessions)
    for vrf, info in vrf_info.items():
        if vrf in seen_vrfs:
            continue
        seen_vrfs.add(vrf)
        if vrf == "default":
            continue
        instances.append(
            Instance(
                "vrf",
                {"asn": asn, "vrf": vrf},
                f"VRF {vrf}",
                (
                    ("Router ID", info.get("router_id", "")),
                    (
                        "Neighbors",
                        f"{info.get('established', '0')} of {info.get('peers', '0')} established",
                    ),
                ),
            )
        )
    seen_afs = {(i.ident["vrf"], i.ident["af"]) for i in instances if i.scope == "af"}
    for vrf, af, saf in _summary_afs(summary):
        if (vrf, af) in seen_afs or not text(saf.get("tableversion")):
            continue
        seen_afs.add((vrf, af))
        instances.append(
            Instance(
                "af",
                {"asn": asn, "vrf": vrf, "af": af},
                f"{_af_label(af)} in VRF {vrf}",
                (
                    ("Networks", text(saf.get("totalnetworks")) or "0"),
                    ("Neighbors", text(saf.get("configuredpeers")) or "0"),
                ),
            )
        )
    instances.extend(_neighbors(neighbors, asn))
    others = sorted(v for v in seen_vrfs if v != "default")
    notes = []
    vrfs_without_af = [v for v in others if not any(vrf == v for vrf, _ in seen_afs)]
    if vrfs_without_af:
        notes.append(
            "The switch does not say which address families "
            + ", ".join(f"VRF {v}" for v in vrfs_without_af)
            + " has until one of them has a neighbor; adding one that is already there "
            "changes nothing."
        )
    facts = (*instances[0].facts, ("VRFs", ", ".join(["default", *others])))
    instances[0] = Instance(
        "process", instances[0].ident, instances[0].title, facts, instances[0].values
    )
    return ProtocolView(tuple(instances), tables, tuple(notes))


BGP = Protocol(
    key="bgp",
    name="BGP",
    summary="Exchange routes with other networks and data centres, by AS number",
    features=("bgp",),
    commands=(
        "show bgp process",
        "show bgp all summary vrf all",
        "show bgp vrf all all neighbors",
        "show bgp sessions vrf all",
        "show bgp ipv6 unicast vrf all",
    ),
    parse=parse_bgp,
    scopes=(PROCESS, VRF, ADDRESS_FAMILY, NEIGHBOR, NEIGHBOR_AF),
    about="BGP exchanges routes between autonomous systems (AS): each network has an AS "
    "number, and BGP tells neighbors which networks it can reach. A neighbor in another "
    "AS is outside (eBGP), one in the same AS inside (iBGP). The switch runs one BGP "
    "process, for one AS number. Routes are only exchanged in the address families both "
    "the process and the neighbor have.",
)

PROTOCOLS: tuple[Protocol, ...] = (BGP,)
