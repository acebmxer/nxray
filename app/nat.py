"""NAT: the switch rewriting the IP addresses of traffic that passes between its inside and
outside interfaces.

An interface is on the **inside** (the addresses NAT hides) or the **outside**. A **static
translation** always rewrites one address (or one TCP or UDP port) to another. A **dynamic
translation** rewrites the traffic an ACL permits to an address from a **pool**, or to an
interface's own address, sharing it between many hosts by port (overload, also called PAT).
The **timeouts** say how long an unused dynamic translation stays, and the **limits** how
many there may be.

On a Nexus 9000 NAT needs TCAM space of its own (the ``nat`` region, set with ``hardware
access-list tcam region nat <size>`` on the ACLs page, which counts only after a restart of
the switch). The page reads the regions and says plainly when the region has no space.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (an interface, a static translation, a pool, a dynamic
translation, the timeouts and limits, clearing), each setting the one line it sends with
checked values in its blanks, and ``build_change`` building the lines.
``NxapiClient.configure_nat`` sends them.

Read from the switch: ``show feature``, ``show interface brief``, ``show vrf`` and ``show
vrf interface`` in one request, ``show hardware access-list tcam region`` as text (as the
ACLs page reads it); while ``feature nat`` is on, ``show ip nat translations verbose``,
``show ip nat statistics`` and ``show ip nat max`` in one request, and ``show
running-config`` as text (the role's ``show running-config`` rule), where the NAT lines are
read.

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-12, NAT region 0) with throwaway translations,
pools, ACLs, a VLAN interface and a loopback, all removed afterwards and ``feature nat``
turned back off. What the switch showed and the page follows:

* ``ip nat inside`` and ``ip nat outside`` on an interface are refused while the region has
  no space ("Error: Nat tcam not carved."); every line below was taken all the same;
* ``ip nat inside source static [tcp|udp] <local> [<port>] <global> [<port>] [vrf <vrf>
  [match-in-vrf]] [add-route]`` and ``ip nat outside source static <global> <local>
  [add-route]``; a static in a VRF the switch does not have is taken silently and
  translates nothing, so the page refuses one; removing needs both addresses (and the
  VRF), not ``add-route`` or ``match-in-vrf``;
* ``ip nat pool <name> <first> <last> prefix-length <n>`` (or ``netmask``); a pool is
  removed even while a dynamic translation still names it;
* ``ip nat inside source list <acl> pool <pool> [vrf <vrf>] [overload]``, ``ip nat inside
  source list <acl> interface <interface> overload`` and ``ip nat outside source list <acl>
  pool <pool> [add-route]``; one ACL goes with one pool ("already mapped"); removing needs
  the whole line;
* ``ip nat translation timeout|tcp-timeout|udp-timeout|icmp-timeout <60-172800>``; the
  ``no`` forms of the last three need a number (any); ``syn-timeout`` and
  ``finrst-timeout`` are refused while the ``tcp-nat`` region has no space;
  ``creation-timeout``, ``inactivity-timeout``, ``sampling-timeout`` and ``ip nat log`` are
  not commands on this switch;
* ``ip nat translation max-entries <1-1023>`` and ``max-entries all-host <1-1023>``, each on
  its own line;
* ``clear ip nat translation all``, ``clear ip nat translation inside <global> <local>``,
  ``clear ip nat translation outside <local> <global>`` and ``clear ip nat statistics``,
  typed outside configuration mode.

The clearing commands are typed outside configuration mode, which NXray's broad role allows
from version ``BROAD_NAT_VERSION`` (rules 28 and 29); a broad role written before needs
Update the port list first.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from app.acls import TCAM_COMMAND, parse_tcam_regions
from app.features import feature_states
from app.loopbacks import parse_loopbacks
from app.nxapi import DEFAULT_VRF, NxapiClient, NxapiCommandError
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
    interface_field,
    table_rows,
)
from app.routing import parse_vrf_members
from app.routing_protocols import layer3_interfaces
from app.switch import text
from app.switch_admin import vrf_choices
from app.vxlan import parse_vxlan_config

FEATURE = "nat"
PAGE_COMMANDS = ("show feature", "show interface brief", "show vrf", "show vrf interface")
COMMANDS = ("show ip nat translations verbose", "show ip nat statistics", "show ip nat max")
CONFIG_COMMAND = "show running-config"
# The TCAM regions NAT uses: translations, TCP's SYN and FIN/RST timers, multicast.
NAT_REGIONS = ("nat", "tcp-nat", "mcast-nat")
TIMEOUT_MIN = 60
TIMEOUT_MAX = 172800
ENTRIES_MAX = 1023

NO_TCAM = (
    "The switch has no TCAM space for NAT: its nat region is 0 entries. Until it has some, "
    "the switch refuses ip nat inside and ip nat outside on interfaces, so nothing is "
    "translated. To give NAT space, size the nat region on the ACLs page (TCAM space; the "
    "entries come from another region), save the configuration and restart the switch."
)


def _address(name: str, label: str, hint: str) -> Field:
    return Field(name, label, "ipv4", hint=hint, placeholder="192.0.2.10")


def _port(name: str, label: str) -> Field:
    return Field(
        name,
        label,
        "int",
        minimum=1,
        maximum=65535,
        optional=True,
        hint="Only with TCP or UDP picked",
        placeholder="80",
    )


def _acl() -> Field:
    return Field(
        "acl",
        "ACL",
        "name",
        hint="The traffic to translate: the ACL's permit lines, made on the Security page",
        placeholder="nat-inside",
    )


def _vrf() -> Field:
    return Field(
        "vrf",
        "VRF",
        "vrf",
        optional=True,
        hint="default, or the VRF the inside hosts are in",
        placeholder="default",
    )


_INTERFACE = Scope(
    key="interface",
    label="Interface",
    ident=(interface_field(),),
    enter=("interface {interface}",),
    help=(
        "Which side of NAT an interface is on. Traffic is translated as it goes from an "
        "inside interface to an outside one, and back."
    ),
    settings=(
        Setting(
            key="inside",
            label="Inside",
            line="ip nat inside",
            group="Side",
            help="The hosts behind this interface get translated addresses.",
            warning="Traffic through this interface is translated at once.",
        ),
        Setting(
            key="outside",
            label="Outside",
            line="ip nat outside",
            group="Side",
            help="The network on this side sees the translated addresses.",
            warning="Traffic through this interface is translated at once.",
        ),
    ),
)

_STATIC_PART = (
    "ip nat {side} source static[ {protocol}] {real}[ {real_port}] {translated}"
    "[ {translated_port}][ vrf {vrf}]"
)

_STATIC = Scope(
    key="static",
    label="Static translation",
    ident=(
        Field(
            "side",
            "Side",
            "choice",
            choices=("inside", "outside"),
            hint="inside: an inside host as the outside sees it; outside: an outside host "
            "as the inside sees it",
        ),
        Field(
            "protocol",
            "Protocol",
            "choice",
            choices=("tcp", "udp"),
            optional=True,
            hint="Empty: the whole address. tcp or udp: one port only",
        ),
        _address("real", "Real address", "The host's own address"),
        _port("real_port", "Real port"),
        _address("translated", "Translated to", "The address the other side uses for it"),
        _port("translated_port", "Translated port"),
        _vrf(),
        Field(
            "match_in_vrf",
            "Only for traffic in that VRF",
            "flag",
            choices=("match-in-vrf",),
        ),
        Field(
            "add_route",
            "Add a route to the translated address",
            "flag",
            choices=("add-route",),
        ),
    ),
    enter=(_STATIC_PART + "[ {match_in_vrf}][ {add_route}]",),
    create=True,
    create_label="Add a static translation",
    delete=("no " + _STATIC_PART,),
    delete_warning="Traffic to and from these addresses is no longer translated.",
    help="One address, or one TCP or UDP port, always translated to another.",
)

_POOL = Scope(
    key="pool",
    label="Address pool",
    ident=(
        Field("name", "Name", "name", hint="Letters, digits, - and _", placeholder="nat-pool"),
        _address("first", "First address", "The pool's lowest address"),
        _address("last", "Last address", "The pool's highest address"),
        Field(
            "length",
            "Prefix length",
            "int",
            minimum=1,
            maximum=32,
            hint="Of the network the addresses are in, such as 24",
            placeholder="24",
        ),
    ),
    enter=("ip nat pool {name} {first} {last} prefix-length {length}",),
    create=True,
    create_label="Make an address pool",
    delete=("no ip nat pool {name}",),
    delete_warning=(
        "The switch deletes a pool even while a dynamic translation names it: that "
        "translation then has no addresses to give out. Delete the translation first."
    ),
    help="Addresses a dynamic translation hands out.",
)

_DYNAMIC_LINE = "ip nat {side} source list {acl} pool {pool}[ vrf {vrf}][ {overload}][ {add_route}]"

_DYNAMIC = Scope(
    key="dynamic",
    label="Dynamic translation",
    ident=(
        Field(
            "side",
            "Side",
            "choice",
            choices=("inside", "outside"),
            hint="inside: translate inside hosts' addresses; outside: outside hosts'",
        ),
        _acl(),
        Field(
            "pool", "Pool", "name", hint="An address pool made on this page", placeholder="nat-pool"
        ),
        _vrf(),
        Field(
            "overload",
            "Share the pool's addresses by port (PAT, inside only)",
            "flag",
            choices=("overload",),
        ),
        Field(
            "add_route",
            "Add a route to each translated address (outside only)",
            "flag",
            choices=("add-route",),
        ),
    ),
    enter=(_DYNAMIC_LINE,),
    create=True,
    create_label="Add a dynamic translation",
    delete=("no " + _DYNAMIC_LINE,),
    delete_warning="The traffic this ACL permits is no longer translated.",
    help=(
        "The traffic an ACL permits gets an address from a pool while it is used. One ACL "
        "goes with one pool."
    ),
)

_OVERLOAD_LINE = "ip nat inside source list {acl} interface {interface} overload"

_OVERLOAD = Scope(
    key="overload",
    label="Translation to an interface's address",
    ident=(
        _acl(),
        Field(
            "interface",
            "Interface",
            "source",
            hint="Its address is shared by the traffic, usually the outside interface: a "
            "VLAN interface, routed port, routed port-channel or loopback",
            placeholder="Vlan10",
        ),
    ),
    enter=(_OVERLOAD_LINE,),
    create=True,
    create_label="Add a translation to an interface's address",
    delete=("no " + _OVERLOAD_LINE,),
    delete_warning="The traffic this ACL permits is no longer translated.",
    help=(
        "The inside traffic an ACL permits all shares one interface's address, told apart by "
        "port (PAT). The address follows the interface's."
    ),
)


def _seconds(label: str = "Seconds") -> Field:
    return Field(
        "seconds",
        label,
        "int",
        minimum=TIMEOUT_MIN,
        maximum=TIMEOUT_MAX,
        hint=f"{TIMEOUT_MIN} to {TIMEOUT_MAX} (two days)",
        placeholder="3600",
    )


def _timeout(key: str, label: str, word: str, help_text: str, bare_no: bool = False) -> Setting:
    return Setting(
        key=key,
        label=label,
        line=f"ip nat translation {word} {{seconds}}",
        no_line=f"no ip nat translation {word}" + ("" if bare_no else " {seconds}"),
        fields=(_seconds(),),
        group="Timeouts",
        help=help_text,
    )


def _entries() -> Field:
    return Field(
        "count",
        "Translations",
        "int",
        minimum=1,
        maximum=ENTRIES_MAX,
        hint=f"1 to {ENTRIES_MAX}",
        placeholder="1000",
    )


_TCP_NAT_NOTE = (
    " The switch takes it only once its tcp-nat TCAM region has space (sized on the ACLs page)."
)

_LIMITS = Scope(
    key="limits",
    label="Timeouts and limits",
    ident=(),
    enter=(),
    help="How long an unused dynamic translation stays, and how many there may be. Empty: "
    "the switch's own default.",
    settings=(
        _timeout(
            "timeout",
            "Any traffic",
            "timeout",
            "How long a dynamic translation stays unused before it goes.",
            bare_no=True,
        ),
        _timeout("tcp", "TCP", "tcp-timeout", "The same, for TCP translations."),
        _timeout("udp", "UDP", "udp-timeout", "The same, for UDP translations."),
        _timeout("icmp", "ICMP", "icmp-timeout", "The same, for ICMP (ping) translations."),
        _timeout(
            "syn",
            "TCP connections being opened",
            "syn-timeout",
            "How long a TCP translation waits for its connection to open." + _TCP_NAT_NOTE,
        ),
        _timeout(
            "finrst",
            "TCP connections being closed",
            "finrst-timeout",
            "How long a TCP translation stays once its connection closes." + _TCP_NAT_NOTE,
        ),
        Setting(
            key="max_entries",
            label="Most dynamic translations",
            line="ip nat translation max-entries {count}",
            no_line="no ip nat translation max-entries",
            fields=(_entries(),),
            group="Limits",
            help="New traffic past this many is not translated.",
        ),
        Setting(
            key="all_host",
            label="Most dynamic translations per host",
            line="ip nat translation max-entries all-host {count}",
            no_line="no ip nat translation max-entries all-host",
            fields=(_entries(),),
            group="Limits",
            help="So one host cannot take them all.",
        ),
    ),
)

_CLEAR = Scope(
    key="clear",
    label="Clear translations and counters",
    ident=(),
    enter=(),
    help="Dynamic translations are made again by the next packet; static ones stay.",
    settings=(
        Setting(
            key="all",
            label="Clear every dynamic translation",
            line="clear ip nat translation all",
            removable=False,
            config=False,
            group="Clear",
            warning="Every connection through a dynamic translation has to start again.",
        ),
        Setting(
            key="inside",
            label="Clear one inside translation",
            line="clear ip nat translation inside {inside_global} {inside_local}",
            fields=(
                _address("inside_global", "Inside global", "The address the outside sees"),
                _address("inside_local", "Inside local", "The inside host's own address"),
            ),
            removable=False,
            config=False,
            group="Clear",
        ),
        Setting(
            key="outside",
            label="Clear one outside translation",
            line="clear ip nat translation outside {outside_local} {outside_global}",
            fields=(
                _address("outside_local", "Outside local", "The address the inside sees"),
                _address("outside_global", "Outside global", "The outside host's own address"),
            ),
            removable=False,
            config=False,
            group="Clear",
        ),
        Setting(
            key="statistics",
            label="Clear the counters",
            line="clear ip nat statistics",
            removable=False,
            config=False,
            group="Clear",
        ),
    ),
)

SCOPES = (_INTERFACE, _STATIC, _POOL, _DYNAMIC, _OVERLOAD, _LIMITS, _CLEAR)


# ---- reading -----------------------------------------------------------------------------


def _prefix_length(value: str) -> str:
    """'24' as it is; a netmask such as '255.255.255.0' as its length."""
    if value.isdigit():
        return value
    try:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{value}").prefixlen)
    except ValueError:
        return value


@dataclass(frozen=True)
class NatConfig:
    """The NAT lines of the running configuration, as the page's places."""

    sides: dict[str, set[str]]  # interface -> {"inside", "outside"}
    statics: list[dict[str, str]]  # the static scope's identity values
    pools: list[dict[str, str]]
    dynamics: list[dict[str, str]]
    overloads: list[dict[str, str]]
    limits: dict[str, str]  # setting key -> value


_STATIC_LINE = re.compile(
    r"ip nat (inside|outside) source static(?: (tcp|udp))? (\S+)(?: (\d+))? (\S+)(?: (\d+))?"
    r"((?: \S+)*)"
)
_LIST_LINE = re.compile(
    r"ip nat (inside|outside) source list (\S+) (pool|interface) (\S+)((?: \S+)*)"
)
_POOL_LINE = re.compile(r"ip nat pool (\S+) (\S+) (\S+) (?:prefix-length|netmask) (\S+)")
_TIMEOUT_LINE = re.compile(
    r"ip nat translation (timeout|tcp-timeout|udp-timeout|icmp-timeout|syn-timeout"
    r"|finrst-timeout) (\d+)"
)
_TIMEOUT_KEYS = {
    "timeout": "timeout",
    "tcp-timeout": "tcp",
    "udp-timeout": "udp",
    "icmp-timeout": "icmp",
    "syn-timeout": "syn",
    "finrst-timeout": "finrst",
}


def _options(words: str) -> tuple[str, set[str]]:
    """The VRF and the single-word options after a translation's addresses."""
    parts = words.split()
    vrf = ""
    if "vrf" in parts and parts.index("vrf") + 1 < len(parts):
        vrf = parts[parts.index("vrf") + 1]
    return vrf, set(parts)


def parse_nat_config(config: str) -> NatConfig:
    """The ``ip nat`` lines of ``show running-config``, and each interface's side."""
    tree = parse_vxlan_config(config)
    sides: dict[str, set[str]] = {}
    statics, pools, dynamics, overloads = [], [], [], []
    limits: dict[str, str] = {}
    for line in tree.children():
        if line.startswith("interface "):
            inner = tree.children(line)
            found = {side for side in ("inside", "outside") if f"ip nat {side}" in inner}
            if found:
                sides[line.split(" ", 1)[1]] = found
            continue
        if match := _STATIC_LINE.fullmatch(line):
            side, protocol, real, real_port, translated, translated_port, rest = match.groups()
            vrf, words = _options(rest)
            statics.append(
                {
                    "side": side,
                    "protocol": protocol or "",
                    "real": real,
                    "real_port": real_port or "",
                    "translated": translated,
                    "translated_port": translated_port or "",
                    "vrf": vrf,
                    "match_in_vrf": "match-in-vrf" if "match-in-vrf" in words else "",
                    "add_route": "add-route" if "add-route" in words else "",
                }
            )
        elif match := _LIST_LINE.fullmatch(line):
            side, acl, kind, target, rest = match.groups()
            vrf, words = _options(rest)
            if kind == "interface":
                overloads.append({"acl": acl, "interface": target})
            else:
                dynamics.append(
                    {
                        "side": side,
                        "acl": acl,
                        "pool": target,
                        "vrf": vrf,
                        "overload": "overload" if "overload" in words else "",
                        "add_route": "add-route" if "add-route" in words else "",
                    }
                )
        elif match := _POOL_LINE.fullmatch(line):
            name, first, last, length = match.groups()
            pools.append(
                {"name": name, "first": first, "last": last, "length": _prefix_length(length)}
            )
        elif match := _TIMEOUT_LINE.fullmatch(line):
            limits[_TIMEOUT_KEYS[match.group(1)]] = match.group(2)
        elif match := re.fullmatch(r"ip nat translation max-entries all-host (\d+)", line):
            limits["all_host"] = match.group(1)
        elif match := re.fullmatch(r"ip nat translation max-entries (\d+)", line):
            limits["max_entries"] = match.group(1)
    return NatConfig(sides, statics, pools, dynamics, overloads, limits)


def nat_regions(tcam_text: str | None) -> list[tuple[str, str, str]]:
    """The NAT regions of ``show hardware access-list tcam region``: (region, what it is
    for, entries)."""
    if not tcam_text:
        return []
    return [row for row in parse_tcam_regions(tcam_text) if row[0] in NAT_REGIONS]


def _with_port(address: Any, port: Any) -> str:
    shown = text(address)
    if not shown or shown == "---":
        return "-"
    return f"{shown}:{text(port)}" if text(port) else shown


def _time_left(value: str) -> str:
    """'0:0:-1' (a static translation) -> 'never'; others as the switch writes them."""
    return "never" if value.endswith("-1") else value or "-"


def parse_translations(body: Any) -> list[tuple[str, ...]]:
    """``show ip nat translations verbose``: one row per translation."""
    found = []
    for row in table_rows(body or {}, "TABLE_nat_translation", "ROW_nat_translation"):
        found.append(
            (
                text(row.get("Protocol")) or "any",
                _with_port(row.get("Inside_local_IP_V4_Address"), row.get("Inside_local_port")),
                _with_port(row.get("Inside_global_IP_V4_Address"), row.get("Inside_global_port")),
                _with_port(row.get("Outside_local_IP_V4_Address"), row.get("Outside_local_port")),
                _with_port(row.get("Outside_global_IP_V4_Address"), row.get("Outside_global_port")),
                text(row.get("VRF")) or DEFAULT_VRF,
                text(row.get("In_stats_count")) or "0",
                text(row.get("Out_stats_count")) or "0",
                _time_left(text(row.get("Time_left"))),
            )
        )
    return found


_STATISTICS = (
    ("total_active_translations", "Active translations"),
    ("static_translations", "Static"),
    ("dynamic_translations", "Dynamic"),
    ("icmp_translations", "Dynamic ICMP"),
    ("total_exp_translations", "Expired"),
    ("total_hits", "Hits"),
    ("total_misses", "Misses"),
    ("total_sw_translated", "Translated by the switch's processor"),
    ("total_sw_dropped", "Dropped by the switch's processor"),
    ("addr_alloc_fail_drop", "Dropped: no pool address left"),
    ("port_alloc_fail_drop", "Dropped: no port left"),
    ("dyn_trans_maxlimit_drop", "Dropped: at the most dynamic translations"),
    ("icmp_maxlimit_drop", "Dropped: at the most ICMP translations"),
    ("allhost_maxlimit_drop", "Dropped: at the most per host"),
    ("total_tcp_session_created", "TCP connections opened"),
    ("total_tcp_session_closed", "TCP connections closed"),
)
_MAXIMA = (
    ("max_dyn_translations", "Most dynamic translations"),
    ("max_all_host", "Most dynamic translations per host"),
)


def parse_statistics(statistics: Any, maxima: Any) -> list[tuple[str, str]]:
    """``show ip nat statistics`` and ``show ip nat max`` as (what, value) rows."""
    found = []
    body = statistics if isinstance(statistics, dict) else {}
    since = text(body.get("last_clear_time"))
    if since:
        found.append(("Counted since", since))
    found += [(label, text(body.get(key))) for key, label in _STATISTICS if key in body]
    most = maxima if isinstance(maxima, dict) else {}
    found += [(label, text(most.get(key))) for key, label in _MAXIMA if key in most]
    return found


def parse_lists_in_use(statistics: Any) -> list[tuple[str, ...]]:
    """The dynamic translations ``show ip nat statistics`` reports, with each pool's use."""
    found = []
    for side, prefix, table in (
        ("inside", "in", "TABLE_NAT_inside_source_list"),
        ("outside", "out", "TABLE_NAT_outside_source_list"),
    ):
        for row in table_rows(statistics or {}, table, table.replace("TABLE", "ROW")):
            pool = text(row.get(f"nat_{prefix}_pool_name"))
            interface = text(row.get("interface_name"))
            target = (
                f"pool {pool}" if pool else f"{interface} ({text(row.get('interface_ip_addr'))})"
            )
            shared = "yes" if text(row.get("nat_pool_overload")) or interface else "no"
            found.append(
                (
                    side,
                    text(row.get(f"nat_{prefix}_acl_name")),
                    target,
                    shared,
                    text(row.get(f"{prefix}_pool_total_address")) or "-",
                    text(row.get(f"{prefix}_pool_allocated")) or "-",
                    text(row.get(f"{prefix}_pool_missed")) or "-",
                )
            )
    return found


def _static_title(values: dict[str, str]) -> str:
    real = values["real"] + (f":{values['real_port']}" if values["real_port"] else "")
    translated = values["translated"] + (
        f":{values['translated_port']}" if values["translated_port"] else ""
    )
    protocol = f" {values['protocol'].upper()}" if values["protocol"] else ""
    return f"{values['side'].capitalize()}{protocol} {real} to {translated}"


def _limit_facts(limits: dict[str, str]) -> tuple[tuple[str, str], ...]:
    names = [(s.key, s.label) for s in _LIMITS.settings]
    facts = []
    for key, label in names:
        value = limits.get(key)
        if value is None:
            continue
        unit = " seconds" if key not in ("max_entries", "all_host") else ""
        facts.append((label, value + unit))
    return tuple(facts) or (("Set", "nothing: the switch's defaults"),)


def parse_nat(
    bodies: list[Any], config: str | None, regions: list[tuple[str, str, str]] | None = None
) -> ProtocolView:
    """The page from the translations, statistics and maxima, the configuration text (None
    when the switch did not show it) and the NAT TCAM regions."""
    translations, statistics, maxima = (list(bodies) + [None] * 3)[:3]
    instances: list[Instance] = []
    notes: tuple[str, ...] = ()
    if config is None:
        notes = (
            "The switch did not show NAT's settings to NXray's account: only the translations "
            "and counters are shown.",
        )
    else:
        found = parse_nat_config(config)
        for interface, sides in found.sides.items():
            instances.append(
                Instance(
                    "interface",
                    {"interface": interface},
                    interface,
                    (("Side", " and ".join(sorted(sides))),),
                    {side: {"on": "yes"} for side in sides},
                )
            )
        for values in found.statics:
            facts = [("VRF", values["vrf"] or DEFAULT_VRF)]
            if values["match_in_vrf"]:
                facts.append(("Only for traffic in the VRF", "yes"))
            if values["add_route"]:
                facts.append(("Adds a route", "yes"))
            instances.append(Instance("static", values, _static_title(values), tuple(facts)))
        for values in found.pools:
            instances.append(
                Instance(
                    "pool",
                    values,
                    values["name"],
                    (("Addresses", f"{values['first']} to {values['last']}/{values['length']}"),),
                )
            )
        for values in found.dynamics:
            facts = [("Pool", values["pool"])]
            if values["vrf"]:
                facts.append(("VRF", values["vrf"]))
            facts.append(("Shares addresses by port", "yes" if values["overload"] else "no"))
            if values["add_route"]:
                facts.append(("Adds routes", "yes"))
            instances.append(
                Instance(
                    "dynamic",
                    values,
                    f"{values['side'].capitalize()} traffic of ACL {values['acl']}",
                    tuple(facts),
                )
            )
        for values in found.overloads:
            instances.append(
                Instance(
                    "overload",
                    values,
                    f"ACL {values['acl']} to {values['interface']}'s address",
                    (("Shares the address by port", "yes"),),
                )
            )
        instances.append(
            Instance(
                "limits",
                {},
                "Timeouts and limits",
                _limit_facts(found.limits),
                {
                    key: {"count" if key in ("max_entries", "all_host") else "seconds": value}
                    for key, value in found.limits.items()
                },
            )
        )
    instances.append(Instance("clear", {}, "Clear"))
    tables = (
        Table(
            "TCAM space for NAT",
            ("Region", "For", "Entries"),
            tuple(regions or ()),
            empty="The switch did not show its TCAM regions.",
            note="Sized on the ACLs page; a new size counts after a restart of the switch.",
        ),
        Table(
            "Translations",
            (
                "Protocol",
                "Inside local",
                "Inside global",
                "Outside local",
                "Outside global",
                "VRF",
                "Packets in",
                "Packets out",
                "Time left",
            ),
            tuple(parse_translations(translations)),
            empty="No translations.",
            note="Inside local: an inside host's own address; inside global: that host as "
            "the outside sees it. Outside global: an outside host's own address; outside "
            "local: that host as the inside sees it. Read when the page loads.",
        ),
        Table(
            "Dynamic translations in use",
            ("Side", "ACL", "Translated to", "Shares by port", "Addresses", "In use", "Missed"),
            tuple(parse_lists_in_use(statistics)),
            empty="No dynamic translation is set up.",
        ),
        Table(
            "Counters",
            ("Counter", "Value"),
            tuple(parse_statistics(statistics, maxima)),
            empty="The switch reported no counters.",
        ),
    )
    return ProtocolView(tuple(instances), tables, notes)


NAT = Protocol(
    key="nat",
    name="NAT",
    summary="Translate the IP addresses of traffic between inside and outside interfaces",
    features=(FEATURE,),
    commands=COMMANDS,
    parse=lambda bodies: parse_nat(bodies, None),
    scopes=SCOPES,
    about=(
        "Mark the interfaces inside and outside, then add static translations, or an ACL "
        "for the traffic with a pool or an interface's address for dynamic ones."
    ),
)


@dataclass(frozen=True)
class NatPage:
    """Everything the NAT page shows."""

    protocol: Protocol
    view: ProtocolView
    interfaces: tuple[str, ...]  # VLAN interfaces, routed ports and port-channels
    vrfs: tuple[str, ...]  # default, management, then the others
    loopbacks: tuple[str, ...] = ()
    problem: str = ""
    missing: tuple[str, ...] = ()  # the nat feature, when it is off
    tcam_ready: bool | None = None  # None: the regions could not be read


def load_nat_page(client: NxapiClient) -> NatPage:
    """One request for the feature, interfaces and VRFs, the TCAM regions as text; while
    nat is on, one for the translations and counters and the configuration text."""
    feature, brief, vrf_body, vrf_members = client.show(*PAGE_COMMANDS)
    interfaces = layer3_interfaces(brief, parse_vrf_members(vrf_members))
    loopbacks = tuple(f"loopback{lo.number}" for lo in parse_loopbacks([brief]))
    vrfs = vrf_choices(vrf_body)
    try:
        regions = nat_regions(client.show_text(TCAM_COMMAND))
    except NxapiCommandError:
        regions = []
    sizes = {region: size for region, _, size in regions}
    ready = None if "nat" not in sizes else sizes["nat"] != "0"
    problem = NO_TCAM if ready is False else ""
    if not feature_states(feature).get(FEATURE, False):
        return NatPage(
            NAT,
            ProtocolView(),
            interfaces,
            vrfs,
            loopbacks,
            problem,
            missing=(FEATURE,),
            tcam_ready=ready,
        )
    try:
        bodies = client.show(*COMMANDS)
    except NxapiCommandError as exc:
        bodies = []
        problem = " ".join(p for p in (problem, f"The switch did not report NAT: {exc}") if p)
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = None
    view = parse_nat(bodies, config, regions)
    return NatPage(NAT, view, interfaces, vrfs, loopbacks, problem, tcam_ready=ready)


def check_nat_place(page: NatPage, ident: dict[str, str]) -> None:
    """Refuse an interface or VRF the switch does not have."""
    interface = ident.get("interface", "").strip()
    if interface and interface not in (*page.interfaces, *page.loopbacks):
        known = ", ".join((*page.interfaces, *page.loopbacks)) or "none"
        raise ValueError(
            f"{interface} is not a VLAN interface (up to Vlan254), routed port, routed "
            f"port-channel or loopback on the switch; those are: {known}"
        )
    vrf = ident.get("vrf", "").strip()
    if vrf and vrf != DEFAULT_VRF and vrf not in page.vrfs:
        raise ValueError(f"the switch has no VRF {vrf}; make it on the Routing page first")


def _given(ident: dict[str, str], name: str) -> bool:
    return bool(ident.get(name, "").strip())


def _check_combination(scope: str, ident: dict[str, str]) -> None:
    """Refuse the combinations a field on its own cannot: ports without a protocol, a VRF
    option without a VRF, an option on the side that does not take it, a pool backwards."""
    vrf = ident.get("vrf", "").strip()
    in_vrf = bool(vrf) and vrf != DEFAULT_VRF
    if scope == "static":
        ports = _given(ident, "real_port"), _given(ident, "translated_port")
        if _given(ident, "protocol") and not all(ports):
            raise ValueError("a TCP or UDP translation needs both ports")
        if not _given(ident, "protocol") and any(ports):
            raise ValueError("ports need tcp or udp picked as the protocol")
        if _given(ident, "match_in_vrf") and not in_vrf:
            raise ValueError("only for traffic in that VRF needs a VRF other than default")
    if scope == "dynamic":
        inside = ident.get("side", "").strip() == "inside"
        if not inside and (in_vrf or _given(ident, "overload")):
            raise ValueError("a VRF and sharing by port are for inside translations only")
        if inside and _given(ident, "add_route"):
            raise ValueError("adding routes is for outside translations only")
    if scope == "pool":
        try:
            first = ipaddress.IPv4Address(ident.get("first", "").strip())
            last = ipaddress.IPv4Address(ident.get("last", "").strip())
        except ValueError:
            return  # build_change names the field
        if last < first:
            raise ValueError("the pool's last address comes before its first")


def build_nat_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the NAT page, with the combinations checked when a translation
    or pool is made."""
    change = build_change(NAT, scope, setting, action, ident, values)
    if action == "create":
        _check_combination(scope, ident)
    return change
