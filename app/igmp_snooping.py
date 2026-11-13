"""IGMP snooping: the switch listening to the IGMP reports hosts send, so that it sends a
multicast group only out of the ports that asked for it instead of to every port of the
VLAN.

Snooping is on by default, switch-wide and in every VLAN, with no feature to turn on. In a
VLAN with no multicast router, a **querier** (the switch itself, from an address given
here) asks the hosts which groups they want; **router ports** (mrouter) are where the
multicast routers are, and get every group; a **static group** sends a group out of a port
even with no host asking. **Fast leave** stops a group on a port at once when its host
leaves (one host per port), **explicit tracking** follows each IGMPv3 host, and **report
suppression** sends the routers one report per group instead of every host's.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (the whole switch, a VLAN, and a VLAN's router ports, static
groups, report flooding ports and report filters), each setting the one line it sends with
checked values in its blanks, and ``build_change`` building the lines.
``NxapiClient.configure_igmp_snooping`` sends them.

Read from the switch: ``show interface brief``, ``show ip igmp snooping``, ``show ip igmp
snooping groups detail``, ``show ip igmp snooping querier`` and ``show ip igmp snooping
statistics`` in one request, ``show ip
igmp snooping mrouter`` as text (it prints nothing as JSON with no router port), and ``show
running-config`` as text (the role's ``show running-config`` rule), where the VLANs'
``vlan configuration <n>`` lines are read.

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-13) inside ``vlan configuration 250`` of a
throwaway VLAN, all removed afterwards. Every per-VLAN line below was taken, with these
ranges and quirks:

* ``[no] ip igmp snooping``, ``explicit-tracking`` and ``report-suppression`` are on by
  default and written only as their ``no`` forms; ``link-local-groups-suppression`` the
  same; ``version 3`` is the default and not written;
* ``group-timeout 1-10080`` (minutes) or ``never``, whose ``no`` form needs a value;
  ``last-member-query-interval 1-25``, ``proxy general-queries [mrt 1-25]``, ``querier
  <address>``, ``querier-timeout 1-65535``, ``query-interval 1-18000``,
  ``query-max-response-time 1-25``, ``startup-query-count 1-10``,
  ``startup-query-interval 1-18000``, ``robustness-variable 1-7``, ``version 2|3``,
  ``fast-leave``, ``v3-report-suppression``, ``report-flood all``, ``proxy-leave
  use-group-address``; their bare ``no`` forms remove them;
* ``mrouter interface <port>``, ``static-group <group> [source <address>] interface
  <port>`` (224.0.0.x is refused: "Reserved multicast address not allowed") and
  ``report-flood interface <port>`` take any port, even one the switch does not have, so
  the page refuses those; ``report-policy`` and ``access-group`` (a route-map or
  prefix-list) share one filter per port, the last one typed replacing it;
* a switch-wide-only line typed inside ``vlan configuration`` is taken as a switch-wide
  line (``max-gq-miss`` changed the whole switch), so the VLAN scope offers only the lines
  above.

The switch-wide lines (``ip igmp snooping``, ``report-suppression``,
``v3-report-suppression``, ``link-local-groups-suppression``, ``group-timeout``, ``proxy
general-queries``, ``event-history``, and for VXLAN ``vxlan`` and
``disable-nve-static-router-port``) follow Cisco's NX-OS 9.3 Multicast Routing and VXLAN
guides and were not tried: they are settings the switch already has. Their spelling
matches what ``show running-config igmp all`` printed there. Optimised multicast flood
(OMF) is shown but not offered: the 9.3 guide gives no command for it on a Nexus 9000, and
``no ip igmp snooping optimise-multicast-flood`` is "% Invalid command" in a VLAN. Router
ports, static groups on a port that is up and learned groups with sources were not seen on
the probe switch (nothing was plugged in): the router port list is read from the text
layout the switch printed with none.

Clearing is typed outside configuration mode, one VLAN at a time, which NXray's broad role
allows from version ``BROAD_SNOOPING_CLEAR_VERSION`` (rules 31 to 33). Tried on cisco-25gb
(2026-11-13) in a throwaway VLAN: ``clear ip igmp snooping groups * vlan <n>``, ``... groups
<group> [<source>] vlan <n>``, ``clear ip igmp snooping statistics vlan <n>`` and ``clear ip
igmp snooping explicit-tracking vlan <n>``; the switch refuses ``statistics vlan all``,
``statistics`` with no VLAN, a reserved group (224.0.0.x) and a VLAN it does not have.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.monitor import all_port_names
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
    check_value,
    port_field,
    table_rows,
)
from app.routing import long_name
from app.switch import text
from app.vxlan import parse_vxlan_config

COMMANDS = (
    "show interface brief",
    "show ip igmp snooping",
    "show ip igmp snooping groups detail",
    "show ip igmp snooping querier",
    "show ip igmp snooping statistics",
)
MROUTER_COMMAND = "show ip igmp snooping mrouter"
CONFIG_COMMAND = "show running-config"
PREFIX = "ip igmp snooping"
GROUP_TIMEOUT_MAX = 10080  # minutes (one week), as the switch said
# The switch's event-history buffers for snooping, as show running-config igmp all lists them.
EVENT_BUFFERS = (
    "vlan",
    "vlan-events",
    "igmp-snoop-internal",
    "mfdm",
    "mfdm-sum",
    "vpc",
    "rib",
)
EVENT_SIZES = ("small", "medium", "large")


def _int(name: str, label: str, low: int, high: int, hint: str = "") -> Field:
    return Field(name, label, "int", minimum=low, maximum=high, hint=hint)


def _toggle(
    key: str, label: str, word: str, help_text: str, group: str, default_on: bool
) -> Setting:
    """A line that is on or off. ``default_on``: the switch has it until it is removed,
    and Remove sends the ``no`` form that turns it off."""
    removing = "Remove turns it off." if default_on else ""
    return Setting(
        key,
        label,
        f"{PREFIX} {word}",
        group=group,
        help=" ".join(p for p in (help_text, removing) if p),
    )


def _timers() -> tuple[Setting, ...]:
    """The querier's timers of a VLAN."""
    rows = (
        ("query_interval", "Query interval", "query-interval", 1, 18000, "Default 125"),
        (
            "query_max_response_time",
            "Query response time",
            "query-max-response-time",
            1,
            25,
            "Default 10; less than the query interval",
        ),
        ("querier_timeout", "Querier timeout", "querier-timeout", 1, 65535, "Default 255"),
        (
            "startup_query_interval",
            "Start-up query interval",
            "startup-query-interval",
            1,
            18000,
            "Default 31",
        ),
        ("startup_query_count", "Start-up query count", "startup-query-count", 1, 10, "Default 2"),
        ("robustness_variable", "Robustness", "robustness-variable", 1, 7, "Default 2"),
        (
            "last_member_query_interval",
            "Last member query interval",
            "last-member-query-interval",
            1,
            25,
            "Default 1",
        ),
    )
    unit = {"startup_query_count": "count", "robustness_variable": "count"}
    return tuple(
        Setting(
            key,
            label,
            f"{PREFIX} {word} {{{unit.get(key, 'seconds')}}}",
            (
                _int(
                    unit.get(key, "seconds"),
                    "Value" if key in unit else "Seconds",
                    low,
                    high,
                    hint,
                ),
            ),
            no_line=f"no {PREFIX} {word}",
            group="Querier",
        )
        for key, label, word, low, high, hint in rows
    )


def _group_timeout(scope_words: str) -> tuple[Setting, ...]:
    return (
        Setting(
            "group_timeout",
            "Group timeout",
            f"{PREFIX} group-timeout {{minutes}}",
            (
                _int(
                    "minutes",
                    "Minutes",
                    1,
                    GROUP_TIMEOUT_MAX,
                    f"1 to {GROUP_TIMEOUT_MAX} (a week)",
                ),
            ),
            group="Groups",
            help=f"A group with no report for this long is dropped {scope_words}.",
        ),
        Setting(
            "group_timeout_never",
            "Groups never time out",
            f"{PREFIX} group-timeout never",
            group="Groups",
            help="Keep groups until a host leaves them; Cisco asks for this (or a long "
            "timeout) with the general query proxy.",
        ),
    )


def _proxy_queries() -> Setting:
    return Setting(
        "proxy_queries",
        "Answer general queries for the hosts",
        f"{PREFIX} proxy general-queries[ mrt {{mrt}}]",
        (
            Field(
                "mrt",
                "Response time (seconds)",
                "int",
                minimum=1,
                maximum=25,
                optional=True,
                hint="Default 5",
            ),
        ),
        no_line=f"no {PREFIX} proxy general-queries",
        group="Reports",
        help="The switch answers a router's general queries itself from the groups it knows.",
    )


# ---- the whole switch --------------------------------------------------------------------

_GLOBAL = Scope(
    key="global",
    label="Whole switch",
    ident=(),
    enter=(),
    help="IGMP snooping for every VLAN; a VLAN's own settings win.",
    settings=(
        Setting(
            "snooping_on",
            "Turn snooping on",
            PREFIX,
            removable=False,
            group="Snooping",
            help="On by default.",
        ),
        Setting(
            "snooping_off",
            "Turn snooping off",
            f"no {PREFIX}",
            removable=False,
            group="Snooping",
            help="Turns it off in every VLAN.",
            warning="Every VLAN then floods multicast to all its ports.",
        ),
        _toggle(
            "report_suppression",
            "Report suppression",
            "report-suppression",
            "Send the routers one IGMPv1 and v2 report per group, not every host's.",
            "Reports",
            default_on=True,
        ),
        _toggle(
            "v3_report_suppression",
            "IGMPv3 report suppression",
            "v3-report-suppression",
            "The same for IGMPv3 reports, with the switch reporting for its hosts.",
            "Reports",
            default_on=False,
        ),
        _toggle(
            "link_local_suppression",
            "Link-local groups suppression",
            "link-local-groups-suppression",
            "Do not snoop groups in 224.0.0.0/24; they go to every port.",
            "Reports",
            default_on=True,
        ),
        _proxy_queries(),
        *_group_timeout("in every VLAN"),
        Setting(
            "event_history",
            "Event history size",
            f"{PREFIX} event-history {{buffer}} size {{size}}",
            (
                Field("buffer", "Buffer", "choice", choices=EVENT_BUFFERS),
                Field("size", "Size", "choice", choices=EVENT_SIZES),
            ),
            removable=False,
            group="Event history",
            help="How much of snooping's own log the switch keeps, per buffer, for "
            "troubleshooting.",
        ),
        _toggle(
            "vxlan",
            "Snooping in VXLAN VLANs",
            "vxlan",
            "Snoop the VLANs carried in VXLAN too (needed for multicast over VXLAN).",
            "VXLAN",
            default_on=False,
        ),
        _toggle(
            "disable_nve_router_port",
            "No static router port on the NVE interface",
            "disable-nve-static-router-port",
            "Send a VXLAN VLAN's groups across the fabric only to switches that asked for "
            "them, instead of to every one.",
            "VXLAN",
            default_on=False,
        ),
    ),
)

# ---- a VLAN --------------------------------------------------------------------------------


def _vlan_field() -> Field:
    return Field("vlan", "VLAN", "vlan", hint="A VLAN the switch has", placeholder="10")


_VLAN_ENTER = "vlan configuration {vlan}"

_VLAN = Scope(
    key="vlan",
    label="VLAN",
    ident=(_vlan_field(),),
    enter=(_VLAN_ENTER,),
    help="IGMP snooping in one VLAN.",
    settings=(
        Setting(
            "snooping_on",
            "Turn snooping on here",
            PREFIX,
            removable=False,
            group="Snooping",
            help="On by default.",
        ),
        Setting(
            "snooping_off",
            "Turn snooping off here",
            f"no {PREFIX}",
            removable=False,
            group="Snooping",
            warning="This VLAN then floods multicast to all its ports.",
        ),
        Setting(
            "querier",
            "Querier",
            f"{PREFIX} querier {{address}}",
            (
                Field(
                    "address",
                    "Address",
                    "ipv4",
                    hint="The address its queries come from",
                    placeholder="192.0.2.1",
                ),
            ),
            no_line=f"no {PREFIX} querier",
            group="Querier",
            help="The switch asks the hosts which groups they want, for a VLAN with no "
            "multicast router.",
        ),
        *_timers(),
        Setting(
            "version",
            "IGMP version",
            f"{PREFIX} version {{version}}",
            (Field("version", "Version", "choice", choices=("2", "3"), hint="Default 3"),),
            no_line=f"no {PREFIX} version",
            group="Querier",
        ),
        _toggle(
            "fast_leave",
            "Fast leave",
            "fast-leave",
            "Stop a group on a port as soon as its host leaves: for one host per port.",
            "Groups",
            default_on=False,
        ),
        _toggle(
            "explicit_tracking",
            "Explicit tracking",
            "explicit-tracking",
            "Follow each IGMPv3 host on each port.",
            "Groups",
            default_on=True,
        ),
        *_group_timeout("in this VLAN"),
        _toggle(
            "report_suppression",
            "Report suppression",
            "report-suppression",
            "Send the routers one IGMPv1 and v2 report per group.",
            "Reports",
            default_on=True,
        ),
        _toggle(
            "v3_report_suppression",
            "IGMPv3 report suppression",
            "v3-report-suppression",
            "The same for IGMPv3 reports.",
            "Reports",
            default_on=False,
        ),
        _toggle(
            "link_local_suppression",
            "Link-local groups suppression",
            "link-local-groups-suppression",
            "Do not snoop groups in 224.0.0.0/24.",
            "Reports",
            default_on=True,
        ),
        _toggle(
            "report_flood_all",
            "Flood reports to every port",
            "report-flood all",
            "Send the hosts' reports out of every port of the VLAN, not only the router ports.",
            "Reports",
            default_on=False,
        ),
        _toggle(
            "proxy_leave",
            "Group address in proxy leaves",
            "proxy-leave use-group-address",
            "Send the leave the switch sends for its hosts to the group's address.",
            "Reports",
            default_on=False,
        ),
        _proxy_queries(),
    ),
)


def _place(
    key: str, label: str, line: str, fields: tuple[Field, ...], create_label: str, help_text: str
) -> Scope:
    """A line of a VLAN that names a port (and a group or filter): made and deleted, with
    no settings of its own."""
    return Scope(
        key=key,
        label=label,
        ident=(_vlan_field(), *fields),
        enter=(_VLAN_ENTER, f"{PREFIX} {line}"),
        create=True,
        create_label=create_label,
        delete=(_VLAN_ENTER, f"no {PREFIX} {line}"),
        help=help_text,
    )


_MROUTER = _place(
    "mrouter",
    "Router port",
    "mrouter interface {port}",
    (port_field(),),
    "Add a router port",
    "A port with a multicast router behind it: it gets every group of the VLAN.",
)

_STATIC = _place(
    "static",
    "Static group",
    "static-group {group}[ source {source}] interface {port}",
    (
        Field("group", "Group", "maddr4", placeholder="239.1.1.1"),
        Field(
            "source",
            "Only from sender",
            "ipv4",
            optional=True,
            hint="Empty for any sender",
            placeholder="192.0.2.10",
        ),
        port_field(),
    ),
    "Add a static group",
    "Send a group out of a port even when no host there asks for it.",
)

_FLOOD = _place(
    "flood",
    "Report flooding port",
    "report-flood interface {port}",
    (port_field(),),
    "Flood reports to a port",
    "Send the hosts' reports out of this port too.",
)

_FILTER = _place(
    "filter",
    "Report filter",
    "{command} {kind} {name} interface {port}",
    (
        Field(
            "command",
            "Command",
            "choice",
            choices=("report-policy", "access-group"),
            hint="The same filter; the switch keeps one per port, the last one given",
        ),
        Field("kind", "List", "choice", choices=("route-map", "prefix-list")),
        Field("name", "Name", "name", hint="Made on the Routing policy page"),
        port_field(),
    ),
    "Filter a port's reports",
    "Accept reports on a port only for the groups a route-map or prefix-list permits.",
)


def _clear(
    key: str, label: str, line: str, fields: tuple[Field, ...] = (), **extra: str
) -> Setting:
    return Setting(
        key,
        label,
        f"clear {PREFIX} {line} vlan {{vlan}}",
        fields,
        removable=False,
        config=False,
        group="Clear",
        ident=("vlan",),
        **extra,
    )


_CLEAR = Scope(
    key="clear",
    label="Clear a VLAN's groups or counters",
    ident=(_vlan_field(),),
    enter=(),
    help="The hosts report their groups again at the next query; nothing here is saved.",
    settings=(
        _clear(
            "groups",
            "Clear every learned group",
            "groups *",
            warning="Multicast to this VLAN's hosts may stop until they report again.",
        ),
        _clear(
            "group",
            "Clear one learned group",
            "groups {group}[ {source}]",
            (
                Field("group", "Group", "maddr4", placeholder="239.1.1.1"),
                Field(
                    "source",
                    "Only from sender",
                    "ipv4",
                    optional=True,
                    hint="Empty for every sender",
                    placeholder="192.0.2.10",
                ),
            ),
        ),
        _clear("statistics", "Clear the counters", "statistics"),
        _clear(
            "explicit_tracking",
            "Clear the IGMPv3 hosts tracked",
            "explicit-tracking",
            help="Forgets which IGMPv3 host joined what; they are learned again from reports.",
        ),
    ),
)

SCOPES = (_GLOBAL, _VLAN, _MROUTER, _STATIC, _FLOOD, _FILTER, _CLEAR)

# ---- reading ---------------------------------------------------------------------------------

# A VLAN's lines and the setting each one is (the default-on ones by their no forms).
_ON_LINES = {
    "fast-leave": "fast_leave",
    "v3-report-suppression": "v3_report_suppression",
    "report-flood all": "report_flood_all",
    "proxy-leave use-group-address": "proxy_leave",
}
_DEFAULT_ON = {
    "explicit-tracking": "explicit_tracking",
    "report-suppression": "report_suppression",
    "link-local-groups-suppression": "link_local_suppression",
}
_NUMBERS = {
    "query-interval": ("query_interval", "seconds"),
    "query-max-response-time": ("query_max_response_time", "seconds"),
    "querier-timeout": ("querier_timeout", "seconds"),
    "startup-query-interval": ("startup_query_interval", "seconds"),
    "startup-query-count": ("startup_query_count", "count"),
    "robustness-variable": ("robustness_variable", "count"),
    "last-member-query-interval": ("last_member_query_interval", "seconds"),
    "version": ("version", "version"),
}
_PLACES = (
    ("mrouter", re.compile(r"mrouter interface (\S+)"), ("port",)),
    (
        "static",
        re.compile(r"static-group (\S+)(?: source (\S+))? interface (\S+)"),
        ("group", "source", "port"),
    ),
    ("flood", re.compile(r"report-flood interface (\S+)"), ("port",)),
    (
        "filter",
        re.compile(r"(report-policy|access-group) (route-map|prefix-list) (\S+) interface (\S+)"),
        ("command", "kind", "name", "port"),
    ),
)


@dataclass(frozen=True)
class VlanConfig:
    """One ``vlan configuration <n>`` block: its settings and its places."""

    vlan: str
    values: dict[str, dict[str, str]]
    snooping: bool  # False when the block turns snooping off
    places: tuple[tuple[str, dict[str, str]], ...]  # (scope, identity values)


def _vlan_values(
    lines: list[str],
) -> tuple[dict[str, dict[str, str]], bool, list[tuple[str, dict[str, str]]]]:
    values: dict[str, dict[str, str]] = {key: {} for key in _DEFAULT_ON.values()}
    snooping = True
    places: list[tuple[str, dict[str, str]]] = []
    for line in lines:
        negated = line.startswith("no ")
        words = line.removeprefix("no ")
        if words == PREFIX:
            snooping = not negated
            continue
        if not words.startswith(PREFIX + " "):
            continue
        rest = words[len(PREFIX) + 1 :]
        if negated:
            if rest in _DEFAULT_ON:
                values.pop(_DEFAULT_ON[rest], None)
            continue
        if rest in _ON_LINES:
            values[_ON_LINES[rest]] = {}
        elif match := re.fullmatch(r"group-timeout (\d+|never)", rest):
            if match.group(1) == "never":
                values["group_timeout_never"] = {}
            else:
                values["group_timeout"] = {"minutes": match.group(1)}
        elif match := re.fullmatch(r"proxy general-queries(?: mrt (\d+))?", rest):
            values["proxy_queries"] = {"mrt": match.group(1) or ""}
        elif match := re.fullmatch(r"querier (\S+)", rest):
            values["querier"] = {"address": match.group(1)}
        elif (match := re.fullmatch(r"(\S+) (\d+)", rest)) and match.group(1) in _NUMBERS:
            key, name = _NUMBERS[match.group(1)]
            values[key] = {name: match.group(2)}
        else:
            for scope, pattern, names in _PLACES:
                if found := pattern.fullmatch(rest):
                    ident = {n: v or "" for n, v in zip(names, found.groups(), strict=True)}
                    places.append((scope, ident))
                    break
    return values, snooping, places


def parse_snooping_config(config: str) -> list[VlanConfig]:
    """The ``vlan configuration <n>`` blocks of ``show running-config``, with their IGMP
    snooping lines."""
    tree = parse_vxlan_config(config)
    found = []
    for line in tree.children():
        match = re.fullmatch(r"vlan configuration (\d+)", line)
        if not match:
            continue
        values, snooping, places = _vlan_values(tree.children(line))
        found.append(VlanConfig(match.group(1), values, snooping, tuple(places)))
    return found


def _yes(value: Any) -> str:
    """The switch's many ways of saying on or off, as yes or no."""
    found = text(value).lower()
    if found in ("yes", "true", "enabled"):
        return "yes"
    if found in ("no", "false", "disabled"):
        return "no"
    return text(value)


def _active_ports(row: dict[str, Any]) -> str:
    ports = [
        text(p.get("ActivePorts"))
        for p in table_rows(row, "TABLE_active_ports", "ROW_active_ports")
    ]
    return ", ".join(p for p in ports if p) or "none"


def parse_mrouter(output: str | None) -> list[tuple[str, ...]]:
    """``show ip igmp snooping mrouter`` as text: (VLAN, port, how it was learned, up for,
    expires), from rows under the ``Vlan  Router-port  Type  Uptime  Expires`` heading.
    The type letters are the switch's legend: S static, D dynamic, V vPC peer link, I
    internal, U set by hand and the others."""
    rows = []
    for line in (output or "").splitlines():
        match = re.match(r"^\s*(\d{1,4})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$", line)
        if match:
            vlan, port, kind, up, expires = match.groups()
            rows.append((vlan, long_name(port), kind, up, expires))
    return rows


def _groups(body: Any) -> list[tuple[str, ...]]:
    rows = []
    for vlan in table_rows(body, "TABLE_vlan", "ROW_vlan"):
        number = text(vlan.get("vlan-id"))
        for group in table_rows(vlan, "TABLE_group", "ROW_group"):
            ports = []
            for port in table_rows(group, "TABLE_star_g_ports", "ROW_star_g_ports"):
                name = long_name(text(port.get("star-g-if-name")))
                expires = text(port.get("expires"))
                if expires in ("0.000000", ""):
                    ports.append(name)
                else:
                    ports.append(f"{name} ({expires})")
            how = [w for w, k in (("static", "static"), ("learned", "dynamic")) if _on(group, k)]
            rows.append(
                (
                    number,
                    text(group.get("addr")),
                    text(group.get("GroupVersion")),
                    " and ".join(how) or "-",
                    text(group.get("ReporterAddress")) or "-",
                    ", ".join(p for p in ports if p) or "-",
                )
            )
    return rows


def parse_snooping_counters(body: Any) -> list[tuple[str, ...]]:
    """Each VLAN's IGMP counters from ``show ip igmp snooping statistics``: reports, queries
    and leaves received, reports sent on and invalid packets, and since when."""
    rows = []
    for row in table_rows(body, "TABLE_vlan", "ROW_vlan"):

        def count(*keys: str, row: dict[str, Any] = row) -> str:
            return "/".join(text(row.get(k)) or "0" for k in keys)

        since = text(row.get("Uptime"))
        rows.append(
            (
                text(row.get("vlan-id")),
                count("V1ReportRcvd", "V2ReportRcvd", "V3ReportRcvd"),
                count("V1QueryRcvd", "V2QueryRcvd", "V3QueryRcvd"),
                count("V2LeaveRcvd"),
                count("ReportFwded"),
                count("InvReportRcvd", "InvQueryRcvd"),
                "never cleared" if since in ("", "never") else since,
            )
        )
    return rows


def _on(row: dict[str, Any], key: str) -> bool:
    return text(row.get(key)).lower() == "true"


def _queriers(body: Any) -> list[tuple[str, ...]]:
    rows = []
    for row in table_rows(body, "TABLE_vlan", "ROW_vlan"):
        where = text(row.get("QuerierInterface"))
        name = text(row.get("QuerierName"))
        rows.append(
            (
                text(row.get("vlan-id")),
                text(row.get("QuerierAddress")),
                text(row.get("QuerierVersion")),
                text(row.get("QuerierExpires")),
                name if where in ("", "none") else long_name(where),
            )
        )
    return rows


_GLOBAL_FACTS = (
    ("Snooping", "GlobalSnoopEnabled"),
    ("Optimised multicast flood", "GlobalOMF"),
    ("Report suppression", "GlobalReportSupression"),
    ("IGMPv3 report suppression", "GlobalV3ReportSupression"),
    ("Link-local groups suppression", "GlobalLinkLocalGroupSupression"),
)
_VLAN_FACTS = (
    ("Snooping", "snoop-on"),
    ("Switch querier", "SwitchQuerier"),
    ("Explicit tracking", "ExplicitTracking"),
    ("Fast leave", "FastLeave"),
    ("Report suppression", "ReportSupression"),
    ("IGMPv3 report suppression", "V3ReportSupression"),
    ("Link-local groups suppression", "LinkLocalGroupSupression"),
    ("Reports flooded", "EnableReportFlooding"),
    ("Router ports", "RouterPortCount"),
    ("Groups", "GroupCount"),
)


def _global_values(state: dict[str, Any]) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    for key, source in (
        ("report_suppression", "GlobalReportSupression"),
        ("v3_report_suppression", "GlobalV3ReportSupression"),
        ("link_local_suppression", "GlobalLinkLocalGroupSupression"),
    ):
        if _yes(state.get(source)) == "yes":
            values[key] = {}
    return values


def parse_snooping(
    bodies: list[Any], config: str | None, mrouter: str | None = None
) -> ProtocolView:
    """The page from ``show ip igmp snooping``, its groups and queriers (``bodies``, in
    ``COMMANDS`` order without the interface list), the configuration text (None: not
    shown) and the router port text (None: not shown)."""
    state, groups, queriers, counters = (
        (bodies[i] if i < len(bodies) and isinstance(bodies[i], dict) else {}) for i in range(4)
    )
    facts = tuple((label, _yes(state.get(key)) or "-") for label, key in _GLOBAL_FACTS)
    instances = [Instance("global", {}, "Whole switch", facts, _global_values(state))]
    configs = {block.vlan: block for block in parse_snooping_config(config or "")}
    rows: list[tuple[str, ...]] = []
    places: list[Instance] = []
    clears: list[Instance] = []
    for row in table_rows(state, "TABLE_vlan", "ROW_vlan"):
        vlan = text(row.get("vlan-id"))
        if not vlan:
            continue
        querier = text(row.get("QuerierAddress"))
        vlan_facts = [(label, _yes(row.get(key)) or "-") for label, key in _VLAN_FACTS]
        vlan_facts.insert(1, ("Querier", querier or "none"))
        vlan_facts.append(("Active ports", _active_ports(row)))
        block = configs.get(vlan)
        values = dict(block.values) if block else {}
        if block is None and config is not None:
            values = {key: {} for key in _DEFAULT_ON.values()}
        instances.append(
            Instance("vlan", {"vlan": vlan}, f"VLAN {vlan}", tuple(vlan_facts), values)
        )
        clears.append(Instance("clear", {"vlan": vlan}, f"VLAN {vlan}"))
        if block is not None:
            for scope, ident in block.places:
                places.append(_place_instance(vlan, scope, ident))
        rows.append(
            (
                vlan,
                _yes(row.get("snoop-on")),
                querier or "-",
                _yes(row.get("FastLeave")),
                _yes(row.get("ExplicitTracking")),
                _yes(row.get("ReportSupression")),
                text(row.get("RouterPortCount")) or "0",
                text(row.get("GroupCount")) or "0",
                _active_ports(row),
            )
        )
    notes = []
    if config is None:
        notes.append(
            "The switch did not show its configuration to NXray's account: the VLANs' "
            "router ports, static groups and filters are not listed, and a VLAN's current "
            "values are not filled in."
        )
    tables = (
        Table(
            "VLANs",
            (
                "VLAN",
                "Snooping",
                "Querier",
                "Fast leave",
                "Explicit tracking",
                "Report suppression",
                "Router ports",
                "Groups",
                "Active ports",
            ),
            tuple(rows),
            empty="The switch reported no VLAN.",
            wrap_column=8,
        ),
        Table(
            "Groups",
            ("VLAN", "Group", "Version", "How", "Last reported by", "Ports (expires)"),
            tuple(_groups(groups)),
            empty="No host has joined a group.",
            wrap_column=5,
        ),
        Table(
            "Queriers",
            ("VLAN", "Address", "Version", "Next query in", "Where"),
            tuple(_queriers(queriers)),
            empty="No VLAN has a querier: a multicast router or this switch's querier asks "
            "the hosts.",
        ),
        Table(
            "Router ports",
            ("VLAN", "Port", "Type", "Up for", "Expires"),
            tuple(parse_mrouter(mrouter)),
            empty="No router port is up.",
            note="Type: S static, D learned, V vPC peer link, I internal, U set by hand.",
        ),
        Table(
            "Counters",
            (
                "VLAN",
                "Reports received (v1/v2/v3)",
                "Queries received (v1/v2/v3)",
                "Leaves received",
                "Reports forwarded",
                "Invalid reports/queries",
                "Counting since",
            ),
            tuple(parse_snooping_counters(counters)),
            empty="The switch reported no counters.",
        ),
    )
    return ProtocolView((*instances, *places, *clears), tables, tuple(notes))


def _place_instance(vlan: str, scope: str, ident: dict[str, str]) -> Instance:
    full = {"vlan": vlan, **ident}
    if scope == "mrouter":
        title = f"VLAN {vlan}: router port {ident['port']}"
    elif scope == "static":
        sender = f" from {ident['source']}" if ident["source"] else ""
        title = f"VLAN {vlan}: {ident['group']}{sender} on {ident['port']}"
    elif scope == "flood":
        title = f"VLAN {vlan}: reports flooded to {ident['port']}"
    else:
        title = f"VLAN {vlan}: {ident['port']} filtered by {ident['kind']} {ident['name']}"
    return Instance(scope, full, title)


IGMP_SNOOPING = Protocol(
    key="igmp-snooping",
    name="IGMP snooping",
    summary="Multicast sent only to the ports whose hosts asked for it, per VLAN",
    features=(),
    commands=COMMANDS[1:],
    parse=lambda bodies: parse_snooping(bodies, None),
    scopes=SCOPES,
    about=(
        "Snooping is on in every VLAN by default. Give a VLAN with no multicast router a "
        "querier, so its hosts keep reporting the groups they want; add router ports and "
        "static groups where the switch cannot learn them. Cisco's guide says snooping "
        "does not work in private VLANs."
    ),
)


@dataclass(frozen=True)
class SnoopingPage:
    """Everything the IGMP snooping page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # the front ports and port-channels
    vlans: tuple[str, ...]  # the VLANs the switch reported
    problem: str = ""
    missing: tuple[str, ...] = ()  # always empty: snooping needs no feature


def load_snooping_page(client: NxapiClient) -> SnoopingPage:
    """One request for the ports and snooping's state, groups and queriers; one for the
    router ports as text and one for the configuration text."""
    problem = ""
    try:
        brief, *bodies = client.show(*COMMANDS)
    except NxapiCommandError as exc:
        (brief,) = client.show(COMMANDS[0])
        bodies, problem = [], f"The switch did not report IGMP snooping: {exc}"
    try:
        mrouter: str | None = client.show_text(MROUTER_COMMAND)
    except NxapiCommandError:
        mrouter = None
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = None
    view = parse_snooping(bodies, config, mrouter)
    vlans = tuple(i.ident["vlan"] for i in view.of("vlan"))
    return SnoopingPage(IGMP_SNOOPING, view, all_port_names(brief or {}), vlans, problem)


def check_snooping_place(page: SnoopingPage, ident: dict[str, str]) -> None:
    """Refuse a VLAN or port the switch does not have (it takes them silently), unless a
    line on the page already names it, so it can still be removed."""
    try:
        vlan = check_value(_vlan_field(), ident.get("vlan", "")) if ident.get("vlan") else ""
        port = check_value(port_field(), ident.get("port", "")) if ident.get("port") else ""
    except ValueError:
        return  # build_change names the field
    if vlan and vlan not in page.vlans:
        raise ValueError(f"the switch has no VLAN {vlan}; make it on the VLANs page first")
    if not port or port in page.ports:
        return
    if any(i.ident.get("port") == port for i in page.view.instances):
        return
    raise ValueError(f"the switch has no port {port}")


def build_snooping_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the IGMP snooping page."""
    return build_change(IGMP_SNOOPING, scope, setting, action, ident, values)
