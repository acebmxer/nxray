"""Routing policy: route-maps, prefix lists and key chains, the pieces the
routing protocol pages refer to by name.

A **route-map** is a list of numbered entries; each entry permits or denies
the routes it matches and can change them (``set metric 100``). NX-OS needs
one for every redistribution (``redistribute static route-map NAME``) and
BGP uses them to filter and change routes per neighbor. A **prefix list**
names networks (``192.0.2.0/24 le 32``) for a route-map to match. A **key
chain** holds the keys that OSPF, EIGRP, RIP, IS-IS, BGP and HSRP sign
their messages with.

Read in one request, always (these need no feature turned on):

- ``show route-map``: each entry with its match and set clauses;
- ``show ip prefix-list`` and ``show ipv6 prefix-list``: each entry;
- ``show key chain``: each chain and key, and whether the key is used now
  for receiving and sending. The key itself is never shown.

Each output is empty (``{}`` or no body at all) when there is none.

What can be changed: a route-map entry (made, deleted, and every match and
set clause an operator uses on a Nexus 9300), a whole route-map (deleted),
prefix list entries and descriptions, whole prefix lists (deleted), key
chains and their keys (made, deleted, key string, accept and send
lifetimes, cryptographic algorithm).

Tried on cisco-25gb (NX-OS 9.3(16)) as NXray's restricted account:
``ip prefix-list NAME seq 5 permit 192.0.2.0/24 le 32``, the IPv6 form,
``route-map NAME permit 10`` with ``match ip address prefix-list`` and
``set metric``, ``key chain``/``key 1``/``key-string 0 ...``, and the
``no route-map``, ``no ip prefix-list``, ``no ipv6 prefix-list`` and ``no key
chain`` deletes. Every other line follows Cisco's NX-OS 9.3 command reference.
Only the two route-map clauses above were seen in ``show route-map`` output;
the others are read from the same text the switch prints (``metric 100``,
``ip address prefix-lists nxprobe-pl``), wherever NX-API splits it.
"""

from __future__ import annotations

import ipaddress
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
    table_rows,
    text,
)
from app.routing import long_name

POLICY_COMMANDS = (
    "show route-map",
    "show ip prefix-list",
    "show ipv6 prefix-list",
    "show key chain",
)

_UINT32 = 4294967295
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_HOURS = tuple(f"{n:02d}" for n in range(24))
_SIXTY = tuple(f"{n:02d}" for n in range(60))
# Years a key lifetime can start or end in.
_YEAR_MIN = 2000
_YEAR_MAX = 2035
# The longest key lifetime the switch takes, in seconds (about 68 years).
_DURATION_MAX = 2147483646

# ---- fields --------------------------------------------------------------------


def _name(name: str, label: str, hint: str = "", placeholder: str = "") -> Field:
    return Field(name, label, "name", hint=hint, placeholder=placeholder)


def _prefix_list_name(name: str, label: str = "Prefix list") -> Field:
    return _name(name, label, "A prefix list's name, made below", "allow-lab")


# ---- route-map entries ---------------------------------------------------------

_ROUTE_TYPES = (
    "external",
    "internal",
    "local",
    "inter-area",
    "intra-area",
    "nssa-external",
    "type-1",
    "type-2",
    "level-1",
    "level-2",
)


def _setting(
    key: str,
    label: str,
    line: str,
    fields: tuple[Field, ...],
    group: str,
    explain: str = "",
    no_line: str | None = None,
) -> Setting:
    return Setting(key, label, line, fields, no_line=no_line, help=explain, group=group)


_MATCH = "Match: which routes this entry is about"
_SET = "Set: what it changes on them"

_ENTRY_SETTINGS = (
    Setting(
        "description",
        "Description",
        "description {description}",
        (Field("description", "Description", "text", maximum=90),),
        no_line="no description",
        help="A note for people: what this entry is for",
        group="About",
    ),
    _setting(
        "match_ip_prefix",
        "IPv4 networks",
        "match ip address prefix-list {ip_prefix_list}",
        (_prefix_list_name("ip_prefix_list", "IPv4 prefix list"),),
        _MATCH,
        "Routes to the networks an IPv4 prefix list names",
    ),
    _setting(
        "match_ipv6_prefix",
        "IPv6 networks",
        "match ipv6 address prefix-list {ipv6_prefix_list}",
        (_prefix_list_name("ipv6_prefix_list", "IPv6 prefix list"),),
        _MATCH,
        "Routes to the networks an IPv6 prefix list names",
    ),
    _setting(
        "match_ip_next_hop",
        "IPv4 next hop",
        "match ip next-hop prefix-list {ip_next_hop_list}",
        (_prefix_list_name("ip_next_hop_list", "IPv4 prefix list"),),
        _MATCH,
        "Routes whose next hop is in an IPv4 prefix list",
    ),
    _setting(
        "match_ipv6_next_hop",
        "IPv6 next hop",
        "match ipv6 next-hop prefix-list {ipv6_next_hop_list}",
        (_prefix_list_name("ipv6_next_hop_list", "IPv6 prefix list"),),
        _MATCH,
        "Routes whose next hop is in an IPv6 prefix list",
    ),
    _setting(
        "match_interface",
        "Out of interface",
        "match interface {match_interface}",
        (
            Field(
                "match_interface",
                "Interface",
                "interface",
                hint="A VLAN interface (Vlan1 to Vlan254), routed port or routed port-channel",
                placeholder="Vlan10",
            ),
        ),
        _MATCH,
        "Routes that leave through this interface (not for BGP)",
    ),
    _setting(
        "match_tag",
        "Tag",
        "match tag {match_tag}",
        (Field("match_tag", "Tag", "int", 0, _UINT32),),
        _MATCH,
        "Routes carrying this tag number",
    ),
    _setting(
        "match_metric",
        "Metric",
        "match metric {match_metric}[ +- {match_deviation}]",
        (
            Field("match_metric", "Metric", "int", 0, _UINT32),
            Field(
                "match_deviation",
                "Give or take",
                "int",
                0,
                _UINT32,
                optional=True,
                hint="Also match metrics this much above or below",
            ),
        ),
        _MATCH,
        "Routes with this metric (cost)",
    ),
    _setting(
        "match_route_type",
        "Route type",
        "match route-type {route_type}",
        (Field("route_type", "Route type", "choice", choices=_ROUTE_TYPES),),
        _MATCH,
        "Routes of one kind: external, internal, local, OSPF area or external types, IS-IS levels",
    ),
    _setting(
        "match_as_path",
        "AS path list",
        "match as-path {as_path_list}",
        (_name("as_path_list", "AS path list", "An ip as-path access-list name"),),
        _MATCH,
        "BGP routes whose AS path an AS path list allows",
    ),
    _setting(
        "match_community",
        "Community list",
        "match community {community_list}[ {exact_match}]",
        (
            _name("community_list", "Community list", "An ip community-list name"),
            Field(
                "exact_match",
                "Exactly these communities",
                "flag",
                choices=("exact-match",),
                hint="Only routes with exactly the list's communities, no others",
            ),
        ),
        _MATCH,
        "BGP routes carrying the communities a community list names",
    ),
    _setting(
        "set_metric",
        "Metric",
        "set metric {metric}[ {delay} {reliability} {load} {mtu}]",
        (
            Field("metric", "Metric", "int", 0, _UINT32, hint="For EIGRP: bandwidth in kb/s"),
            Field("delay", "EIGRP delay", "int", 0, _UINT32, optional=True, hint="In 10 µs"),
            Field("reliability", "EIGRP reliability", "int", 0, 255, optional=True),
            Field("load", "EIGRP load", "int", 1, 200, optional=True),
            Field("mtu", "EIGRP MTU", "int", 1, _UINT32, optional=True),
        ),
        _SET,
        "The metric (cost) the routes get; for EIGRP fill all five or only the first",
    ),
    _setting(
        "set_metric_type",
        "Metric type",
        "set metric-type {metric_type}",
        (
            Field(
                "metric_type",
                "Metric type",
                "choice",
                choices=("type-1", "type-2", "internal", "external"),
                hint="type-1/type-2: OSPF external types; internal: BGP MED from the IGP "
                "metric; external: IS-IS external metric",
            ),
        ),
        _SET,
    ),
    _setting(
        "set_tag",
        "Tag",
        "set tag {tag}",
        (Field("tag", "Tag", "int", 0, _UINT32),),
        _SET,
        "A number stuck on the routes, for later route-maps to match",
    ),
    _setting(
        "set_local_preference",
        "BGP local preference",
        "set local-preference {local_preference}",
        (Field("local_preference", "Local preference", "int", 0, _UINT32),),
        _SET,
        "Higher wins: which way out of this AS BGP prefers",
    ),
    _setting(
        "set_weight",
        "BGP weight",
        "set weight {weight}",
        (Field("weight", "Weight", "int", 0, 65535),),
        _SET,
        "Higher wins, on this switch only",
    ),
    _setting(
        "set_origin",
        "BGP origin",
        "set origin {origin}",
        (Field("origin", "Origin", "choice", choices=("igp", "egp", "incomplete")),),
        _SET,
    ),
    _setting(
        "set_as_path_prepend",
        "BGP AS path prepend",
        "set as-path prepend {prepend_1}[ {prepend_2}][ {prepend_3}][ {prepend_4}]",
        (
            Field("prepend_1", "AS number", "asn"),
            Field("prepend_2", "Then", "asn", optional=True),
            Field("prepend_3", "Then", "asn", optional=True),
            Field("prepend_4", "Then", "asn", optional=True),
        ),
        _SET,
        "AS numbers added in front of the path, to make it look longer",
        no_line="no set as-path prepend",
    ),
    _setting(
        "set_as_path_prepend_last_as",
        "BGP AS path prepend last AS",
        "set as-path prepend last-as {last_as}",
        (Field("last_as", "Times", "int", 1, 10),),
        _SET,
        "Repeat the path's last AS number this many times",
        no_line="no set as-path prepend last-as",
    ),
    _setting(
        "set_community",
        "BGP community",
        "set community {community_as}:{community_value}[ {additive}]",
        (
            Field("community_as", "Community (first half)", "int", 0, 65535, placeholder="65001"),
            Field("community_value", "Community (second half)", "int", 0, 65535),
            Field(
                "additive",
                "Keep the communities routes have",
                "flag",
                choices=("additive",),
            ),
        ),
        _SET,
        "A community written aa:nn, such as 65001:100",
        no_line="no set community",
    ),
    _setting(
        "set_community_well_known",
        "BGP well-known community",
        "set community {well_known}[ {additive}]",
        (
            Field(
                "well_known",
                "Community",
                "choice",
                choices=("no-export", "no-advertise", "local-AS", "internet", "graceful-shutdown"),
            ),
            Field(
                "additive",
                "Keep the communities routes have",
                "flag",
                choices=("additive",),
            ),
        ),
        _SET,
        "no-export: not out of this AS; no-advertise: to no BGP neighbor; local-AS: not "
        "out of this confederation member",
        no_line="no set community",
    ),
    _setting(
        "set_community_none",
        "BGP no communities",
        "set community none",
        (),
        _SET,
        "Strip every community from the routes",
        no_line="no set community",
    ),
    _setting(
        "set_ip_next_hop",
        "IPv4 next hop",
        "set ip next-hop {ip_next_hop}",
        (Field("ip_next_hop", "Next hop", "ipv4"),),
        _SET,
    ),
    _setting(
        "set_ipv6_next_hop",
        "IPv6 next hop",
        "set ipv6 next-hop {ipv6_next_hop}",
        (Field("ipv6_next_hop", "Next hop", "ipv6"),),
        _SET,
    ),
    _setting(
        "set_distance",
        "Distance",
        "set distance {distance}",
        (Field("distance", "Distance", "int", 1, 255),),
        _SET,
        "How much the switch trusts these routes; lower wins (OSPF, EIGRP, IS-IS table-map)",
        no_line="no set distance",
    ),
    _setting(
        "set_distance_bgp",
        "BGP distances",
        "set distance {distance_external} {distance_internal} {distance_local}",
        (
            Field("distance_external", "External (eBGP)", "int", 1, 255),
            Field("distance_internal", "Internal (iBGP)", "int", 1, 255),
            Field("distance_local", "Local", "int", 1, 255),
        ),
        _SET,
        "For a BGP table-map: distances of external, internal and local routes",
        no_line="no set distance",
    ),
    _setting(
        "set_level",
        "IS-IS level",
        "set level {level}",
        (Field("level", "Level", "choice", choices=("level-1", "level-2", "level-1-2")),),
        _SET,
        "Which IS-IS level redistributed routes go into",
    ),
    Setting(
        "continue",
        "Continue at entry",
        "continue {continue_seq}",
        (Field("continue_seq", "Entry number", "int", 1, 65535),),
        no_line="no continue",
        help="After this entry matches, go on to this later entry instead of stopping",
        group="Next",
    ),
)

ROUTE_MAP_ENTRY = Scope(
    "route_map_entry",
    "Route-map entry",
    (
        _name("name", "Route-map", placeholder="lab-redistribute"),
        Field(
            "seq",
            "Entry number",
            "int",
            1,
            65535,
            hint="Entries are tried from the lowest number",
            placeholder="10",
        ),
        Field("action", "Action", "choice", choices=("permit", "deny")),
    ),
    ("route-map {name} {action} {seq}",),
    _ENTRY_SETTINGS,
    create=True,
    create_label="Add a route-map entry",
    delete=("no route-map {name} {action} {seq}",),
    delete_warning="Protocols that use this route-map treat its routes differently at once.",
    help="One numbered entry: permit or deny the routes it matches, and change them",
)

ROUTE_MAP = Scope(
    "route_map",
    "Route-map",
    (_name("name", "Route-map"),),
    (),
    delete=("no route-map {name}",),
    delete_warning=(
        "Every entry goes. A redistribution or neighbor that names this route-map then "
        "passes no routes."
    ),
    help="A whole route-map with all its entries",
)

# ---- prefix lists --------------------------------------------------------------


def _check_entry(values: dict[str, str]) -> None:
    check_prefix_entry(values["prefix"], values["ge"], values["le"])


def _prefix_list_settings(family: str, word: str, kind: str, longest: int) -> tuple[Setting, ...]:
    example = "192.0.2.0/24" if family == "IPv4" else "2001:db8::/32"
    return (
        Setting(
            "entry",
            f"{family} prefix list entry",
            f"{word} prefix-list {{list}} seq {{seq}} {{action}} {{prefix}}"
            "[ ge {ge}][ le {le}]",
            (
                _name("list", "Prefix list", placeholder="allow-lab"),
                Field("seq", "Entry number", "int", 1, 4294967294, placeholder="5"),
                Field("action", "Action", "choice", choices=("permit", "deny")),
                Field("prefix", "Network", kind, placeholder=example),
                Field(
                    "ge",
                    "From length",
                    "int",
                    1,
                    longest,
                    optional=True,
                    hint="Also match longer networks inside it, from this length",
                ),
                Field(
                    "le",
                    "Up to length",
                    "int",
                    1,
                    longest,
                    optional=True,
                    hint=f"Also match longer networks inside it, up to this length ({longest} "
                    "for all)",
                ),
            ),
            help="Adding an entry makes the list when it is new",
            check=_check_entry,
        ),
        Setting(
            "description",
            f"{family} prefix list description",
            f"{word} prefix-list {{list}} description {{description}}",
            (
                _name("list", "Prefix list"),
                Field("description", "Description", "text", maximum=90),
            ),
            no_line=f"no {word} prefix-list {{list}} description",
        ),
    )


IPV4_PREFIX_LISTS = Scope(
    "ipv4_prefix_lists",
    "IPv4 prefix lists",
    (),
    (),
    _prefix_list_settings("IPv4", "ip", "prefix4", 32),
    help="Named lists of IPv4 networks, for route-maps to match",
)

IPV6_PREFIX_LISTS = Scope(
    "ipv6_prefix_lists",
    "IPv6 prefix lists",
    (),
    (),
    _prefix_list_settings("IPv6", "ipv6", "prefix6", 128),
    help="Named lists of IPv6 networks, for route-maps to match",
)

IPV4_PREFIX_LIST = Scope(
    "ipv4_prefix_list",
    "IPv4 prefix list",
    (_name("name", "Prefix list"),),
    (),
    delete=("no ip prefix-list {name}",),
    delete_warning="A route-map entry that matches this list then matches nothing.",
)

IPV6_PREFIX_LIST = Scope(
    "ipv6_prefix_list",
    "IPv6 prefix list",
    (_name("name", "Prefix list"),),
    (),
    delete=("no ipv6 prefix-list {name}",),
    delete_warning="A route-map entry that matches this list then matches nothing.",
)


def check_prefix_entry(prefix: str, ge: str = "", le: str = "") -> tuple[str, str, str]:
    """A prefix list entry's network and lengths, checked against each other.

    NX-OS takes ``ge`` and ``le`` only when the network's length < ``ge`` <=
    ``le`` <= 32 (128 for IPv6); either may be left out (""). Returns them as
    the switch should get them; raises ValueError saying what is wrong.
    """
    try:
        network = ipaddress.ip_network(prefix.strip())
    except ValueError as exc:
        raise ValueError(f"{prefix!r} is not a network such as 192.0.2.0/24") from exc
    longest = network.max_prefixlen
    lengths = []
    for word, raw in (("ge", ge), ("le", le)):
        value = raw.strip()
        if value and (not value.isascii() or not value.isdigit()):
            raise ValueError(f"{word} is a whole number")
        lengths.append(int(value) if value else None)
    low, high = lengths
    for word, number in (("ge", low), ("le", high)):
        if number is not None and not network.prefixlen < number <= longest:
            raise ValueError(
                f"{word} is a length from {network.prefixlen + 1} to {longest} "
                f"for {network}, longer than its own /{network.prefixlen}"
            )
    if low is not None and high is not None and low > high:
        raise ValueError(f"ge ({low}) cannot be more than le ({high})")
    return (
        str(network),
        "" if low is None else str(low),
        "" if high is None else str(high),
    )


# ---- key chains ----------------------------------------------------------------

KEY_CHAIN = Scope(
    "key_chain",
    "Key chain",
    (_name("chain", "Key chain", placeholder="ospf-keys"),),
    ("key chain {chain}",),
    create=True,
    create_label="Make a key chain",
    delete=("no key chain {chain}",),
    delete_warning="Neighbors that sign their messages with this key chain stop talking.",
    help="Keys the routing protocols sign their messages with",
)


def _moment(prefix: str, label: str) -> tuple[Field, ...]:
    return (
        Field(f"{prefix}_hour", f"{label} hour", "choice", choices=_HOURS),
        Field(f"{prefix}_minute", f"{label} minute", "choice", choices=_SIXTY),
        Field(f"{prefix}_second", f"{label} second", "choice", choices=_SIXTY),
        Field(f"{prefix}_month", f"{label} month", "choice", choices=_MONTHS),
        Field(f"{prefix}_day", f"{label} day", "int", 1, 31),
        Field(f"{prefix}_year", f"{label} year", "int", _YEAR_MIN, _YEAR_MAX),
    )


def _at(prefix: str) -> str:
    return (
        f"{{{prefix}_hour}}:{{{prefix}_minute}}:{{{prefix}_second}} "
        f"{{{prefix}_month}} {{{prefix}_day}} {{{prefix}_year}}"
    )


_LOCAL = Field(
    "local",
    "Switch's local time",
    "flag",
    choices=("local",),
    hint="Unticked: the times are UTC",
)


def _lifetimes(word: str, label: str, what: str) -> tuple[Setting, ...]:
    """The three ways to set a key's accept or send lifetime, and one way to remove it.

    The three share one line on the switch, so they are only set from here;
    ``{word}_lifetime`` removes whichever is there without asking for its times.
    """
    start = f"{word}-lifetime[ {{local}}] {_at('start')}"
    group = f"{label} lifetime"
    return (
        Setting(
            f"{word}_lifetime_infinite",
            f"{label} from, for ever",
            f"{start} infinite",
            (_LOCAL, *_moment("start", "From")),
            removable=False,
            help=f"The key is {what} from this moment on",
            group=group,
        ),
        Setting(
            f"{word}_lifetime_until",
            f"{label} from, until",
            f"{start} {_at('end')}",
            (_LOCAL, *_moment("start", "From"), *_moment("end", "Until")),
            removable=False,
            help=f"The key is {what} between these two moments",
            group=group,
        ),
        Setting(
            f"{word}_lifetime_duration",
            f"{label} from, for a time",
            f"{start} duration {{duration}}",
            (
                _LOCAL,
                *_moment("start", "From"),
                Field("duration", "For seconds", "int", 1, _DURATION_MAX),
            ),
            removable=False,
            help=f"The key is {what} for this many seconds from the start",
            group=group,
        ),
        Setting(
            f"{word}_lifetime",
            f"{label} lifetime",
            f"{word}-lifetime",
            no_line=f"no {word}-lifetime",
            settable=False,
            help=f"Removing it makes the key {what} at any time again",
            group=group,
        ),
    )


KEY = Scope(
    "key",
    "Key",
    (
        _name("chain", "Key chain"),
        Field("key", "Key number", "int", 0, 65535, hint="OSPF takes keys 0 to 255 only"),
    ),
    ("key chain {chain}", "key {key}"),
    (
        Setting(
            "key_string",
            "Key",
            "key-string 0 {key_string}",
            (Field("key_string", "Key", "secret", hint="Both ends need the same key"),),
            removable=False,
            help="The shared secret; NXray never shows it back",
            group="Key",
        ),
        Setting(
            "remove_key_string",
            "Key",
            "key-string",
            no_line="no key-string",
            settable=False,
            help="Removing the key leaves this key number unable to sign anything",
            group="Key",
        ),
        Setting(
            "cryptographic_algorithm",
            "Algorithm",
            "cryptographic-algorithm {algorithm}",
            (
                Field(
                    "algorithm",
                    "Algorithm",
                    "choice",
                    choices=("HMAC-SHA-1", "HMAC-SHA-256", "HMAC-SHA-384", "HMAC-SHA-512", "MD5"),
                ),
            ),
            help="For OSPF cryptographic authentication: how messages are signed",
            group="Key",
        ),
        *_lifetimes("accept", "Accept", "accepted from neighbors"),
        *_lifetimes("send", "Send", "used to sign what this switch sends"),
    ),
    create=True,
    create_label="Add a key",
    delete=("key chain {chain}", "no key {key}"),
    delete_warning="Neighbors still using this key stop talking.",
    help="One key in a key chain, with when it is used",
)

# ---- reading -------------------------------------------------------------------


def _clauses(row: dict[str, Any], table: str, kind: str) -> list[str]:
    """A route-map entry's match or set clauses, each as one line of text.

    The switch prints a clause as ``metric 100`` or ``ip address
    prefix-lists: nxprobe-pl``; NX-API splits that into ``*_type`` and
    ``*_stmt``. Joining them back gives the same text whatever the split.
    """
    found = []
    for clause in table_rows(row, f"TABLE_rmap_{table}", f"ROW_rmap_{table}"):
        words = f"{text(clause.get(f'{kind}_type'))} {text(clause.get(f'{kind}_stmt'))}"
        line = " ".join(words.split())
        if line:
            found.append(line)
    return found


# Match clauses, as the switch prints them, and the setting each fills.
# Recorded live: "ip address prefix-lists"; the others follow the same text.
_MATCH_READ: tuple[tuple[re.Pattern[str], str, tuple[str, ...]], ...] = (
    (
        re.compile(r"ip address prefix-lists?:? (\S+).*"),
        "match_ip_prefix",
        ("ip_prefix_list",),
    ),
    (
        re.compile(r"ipv6 address prefix-lists?:? (\S+).*"),
        "match_ipv6_prefix",
        ("ipv6_prefix_list",),
    ),
    (
        re.compile(r"ip next-hop prefix-lists?:? (\S+).*"),
        "match_ip_next_hop",
        ("ip_next_hop_list",),
    ),
    (
        re.compile(r"ipv6 next-hop prefix-lists?:? (\S+).*"),
        "match_ipv6_next_hop",
        ("ipv6_next_hop_list",),
    ),
    (re.compile(r"interface:? (\S+).*"), "match_interface", ("match_interface",)),
    (re.compile(r"tag:? (\d+).*"), "match_tag", ("match_tag",)),
    (
        re.compile(r"metric:? (\d+)(?: ?\+- ?(\d+))?.*"),
        "match_metric",
        ("match_metric", "match_deviation"),
    ),
    (re.compile(r"route-type:? (\S+).*"), "match_route_type", ("route_type",)),
    (
        re.compile(r"as-path(?: \(as-path filter\))?:? (\S+).*"),
        "match_as_path",
        ("as_path_list",),
    ),
    (
        re.compile(r"community(?: \(community-list filter\))?:? (\S+)( exact-match)?.*"),
        "match_community",
        ("community_list", "exact_match"),
    ),
)

# Set clauses. Recorded live: "metric 100".
_SET_READ: tuple[tuple[re.Pattern[str], str, tuple[str, ...]], ...] = (
    (
        re.compile(r"metric:? (\d+)(?: (\d+) (\d+) (\d+) (\d+))?"),
        "set_metric",
        ("metric", "delay", "reliability", "load", "mtu"),
    ),
    (re.compile(r"metric-type:? (\S+)"), "set_metric_type", ("metric_type",)),
    (re.compile(r"tag:? (\d+)"), "set_tag", ("tag",)),
    (re.compile(r"local-preference:? (\d+)"), "set_local_preference", ("local_preference",)),
    (re.compile(r"weight:? (\d+)"), "set_weight", ("weight",)),
    (re.compile(r"origin:? (igp|egp|incomplete)\b.*"), "set_origin", ("origin",)),
    (
        re.compile(r"as-path:? prepend:? last-as:? (\d+)"),
        "set_as_path_prepend_last_as",
        ("last_as",),
    ),
    (
        re.compile(r"as-path:? prepend:? (\S+)(?: (\S+))?(?: (\S+))?(?: (\S+))?"),
        "set_as_path_prepend",
        ("prepend_1", "prepend_2", "prepend_3", "prepend_4"),
    ),
    (
        re.compile(r"community:? (\d+):(\d+)( additive)?"),
        "set_community",
        ("community_as", "community_value", "additive"),
    ),
    (
        re.compile(
            r"community:? (no-export|no-advertise|local-AS|internet|graceful-shutdown)"
            r"( additive)?"
        ),
        "set_community_well_known",
        ("well_known", "additive"),
    ),
    (re.compile(r"community:? none"), "set_community_none", ()),
    (re.compile(r"ip next-hop:? (\S+)"), "set_ip_next_hop", ("ip_next_hop",)),
    (re.compile(r"ipv6 next-hop:? (\S+)"), "set_ipv6_next_hop", ("ipv6_next_hop",)),
    (
        re.compile(r"distance:? (\d+) (\d+) (\d+)"),
        "set_distance_bgp",
        ("distance_external", "distance_internal", "distance_local"),
    ),
    (re.compile(r"distance:? (\d+)"), "set_distance", ("distance",)),
    (re.compile(r"level:? (level-1-2|level-1|level-2)"), "set_level", ("level",)),
)


def _read(
    lines: list[str], patterns: tuple[tuple[re.Pattern[str], str, tuple[str, ...]], ...]
) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    for line in lines:
        for pattern, key, names in patterns:
            match = pattern.fullmatch(line)
            if match is None:
                continue
            found = {
                name: (value or "").strip()
                for name, value in zip(names, match.groups(), strict=True)
            }
            if "match_interface" in found:
                found["match_interface"] = long_name(found["match_interface"])
            values.setdefault(key, found)
            break
    return values


def _route_maps(body: Any) -> tuple[list[Instance], Table]:
    entries: list[Instance] = []
    names: dict[str, int] = {}
    rows = []
    for row in table_rows(body, "TABLE_rmap", "ROW_rmap"):
        name, action, seq = text(row.get("name")), text(row.get("action")), text(row.get("seq"))
        if not name:
            continue
        matches = _clauses(row, "match", "match")
        sets = _clauses(row, "set", "set")
        values = {**_read(matches, _MATCH_READ), **_read(sets, _SET_READ)}
        names[name] = names.get(name, 0) + 1
        entries.append(
            Instance(
                "route_map_entry",
                {"name": name, "seq": seq, "action": action},
                f"{name} {action} {seq}",
                (
                    ("Match", "; ".join(matches) or "every route"),
                    ("Set", "; ".join(sets) or "nothing"),
                ),
                values,
            )
        )
        rows.append((name, seq, action, "; ".join(matches), "; ".join(sets)))
    whole = [
        Instance(
            "route_map",
            {"name": name},
            name,
            (("Entries", str(count)),),
        )
        for name, count in names.items()
    ]
    table = Table(
        "Route-maps",
        ("Route-map", "Entry", "Action", "Match", "Set"),
        tuple(rows),
        empty="No route-maps yet.",
    )
    return [*whole, *entries], table


def _prefix_lists(body: Any, version: int) -> tuple[list[Instance], list[tuple[str, ...]]]:
    word = "ip" if version == 4 else "ipv6"
    family = f"IPv{version}"
    scope = f"ipv{version}_prefix_list"
    seen: dict[str, None] = {}
    rows = []
    for row in table_rows(body, f"TABLE_{word}_pfl", f"ROW_{word}_pfl"):
        name = text(row.get("name"))
        if not name:
            continue
        seen.setdefault(name, None)
        rows.append(
            (family, name, text(row.get("seq")), text(row.get("action")), text(row.get("rule")))
        )
    instances = [
        Instance(f"ipv{version}_prefix_lists", {}, f"{family} prefix lists"),
        *(Instance(scope, {"name": name}, name) for name in seen),
    ]
    return instances, rows


def _key_chains(body: Any) -> tuple[list[Instance], Table]:
    instances = []
    rows = []
    for chain_row in table_rows(body, "TABLE_keychain", "ROW_keychain"):
        chain = text(chain_row.get("chain_name"))
        if not chain:
            continue
        keys = table_rows(chain_row, "TABLE_key", "ROW_key")
        instances.append(
            Instance("key_chain", {"chain": chain}, chain, (("Keys", str(len(keys))),))
        )
        if not keys:
            rows.append((chain, "", "", ""))
        for key_row in keys:
            key = text(key_row.get("key_id"))
            accept = "yes" if text(key_row.get("accept_valid")) == "true" else "no"
            send = "yes" if text(key_row.get("send_valid")) == "true" else "no"
            # The key string is in this output (encrypted); it is never kept.
            instances.append(
                Instance(
                    "key",
                    {"chain": chain, "key": key},
                    f"{chain} key {key}",
                    (("Accepted now", accept), ("Sent now", send)),
                )
            )
            rows.append((chain, key, accept, send))
    table = Table(
        "Key chains",
        ("Key chain", "Key", "Accepted now", "Sent now"),
        tuple(rows),
        empty="No key chains yet.",
    )
    return instances, table


def parse_policy(bodies: list[dict[str, Any]]) -> ProtocolView:
    """The Routing policy page from the bodies of ``POLICY_COMMANDS``, in order.

    A missing or empty body means there is nothing of that kind.
    """
    padded = [*bodies, *([{}] * len(POLICY_COMMANDS))][: len(POLICY_COMMANDS)]
    route_map_body, ipv4_body, ipv6_body, key_body = padded
    route_maps, route_map_table = _route_maps(route_map_body)
    ipv4, ipv4_rows = _prefix_lists(ipv4_body, 4)
    ipv6, ipv6_rows = _prefix_lists(ipv6_body, 6)
    keys, key_table = _key_chains(key_body)
    prefix_table = Table(
        "Prefix lists",
        ("Family", "Prefix list", "Entry", "Action", "Network"),
        (*ipv4_rows, *ipv6_rows),
        empty="No prefix lists yet.",
    )
    return ProtocolView(
        (*route_maps, *ipv4, *ipv6, *keys),
        (route_map_table, prefix_table, key_table),
        (
            "A prefix list entry's lengths: the network's own length < from <= up to "
            "<= 32 (128 for IPv6).",
            "Route-maps, prefix lists and key chains are used by name on the protocol pages; "
            "make them here first.",
        ),
    )


POLICY = Protocol(
    "policy",
    "Routing policy",
    "Route-maps, prefix lists and key chains the routing protocols use",
    (),
    POLICY_COMMANDS,
    parse_policy,
    (
        ROUTE_MAP_ENTRY,
        ROUTE_MAP,
        IPV4_PREFIX_LISTS,
        IPV4_PREFIX_LIST,
        IPV6_PREFIX_LISTS,
        IPV6_PREFIX_LIST,
        KEY_CHAIN,
        KEY,
    ),
    about=(
        "NX-OS redistributes routes only through a route-map, and route-maps usually "
        "match prefix lists. Key chains hold the keys OSPF, EIGRP, RIP, IS-IS and HSRP "
        "sign their messages with."
    ),
)

PROTOCOLS: tuple[Protocol, ...] = (POLICY,)
