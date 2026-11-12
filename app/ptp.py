"""PTP (Precision Time Protocol, IEEE 1588): the switch's PTP clock, the ports that run
PTP, and the settings of both.

PTP gives devices time to well under a microsecond. A grandmaster clock (usually with a
GPS receiver) sends the time; this switch runs as a boundary clock: it takes the time
from the best master it hears on one port and passes it on to the devices on its other
PTP ports.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): two scopes (the whole switch, one port), each setting the one
configuration line it sends with checked values in its blanks, and ``build_change``
building the lines. ``NxapiClient.configure_ptp`` sends them.

Read from the switch: ``show feature``, ``show interface brief`` and ``show vrf`` in one
request; while ``feature ptp`` is on, ``show ptp clock``, ``show ptp parent``, ``show ptp
time-property``, ``show ptp brief`` and ``show ptp counters all`` in one request (JSON),
and ``show running-config`` as text for what is set (the role's ``show running-config``
rule, rule 170, as the Tunnels page uses). Without the text the page shows the clock and
the ports, with empty forms.

Tried on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-12) with throwaway values on
an empty port, all removed afterwards:

* switch-wide: ``ptp source <IPv4>[ vrf <vrf>]`` (IPv4 only; the switch does not print the
  VRF back; it cannot be removed while a port runs PTP, and a port's ``ptp`` is refused
  until a source is set), ``ptp domain`` 0-127, ``ptp priority1`` and ``priority2``
  0-255, ``ptp correction-range`` and ``ptp mean-path-delay`` 10-1000000000 ns, ``ptp
  correction-range logging``, ``ptp management`` (on from the start), ``ptp notification
  type parent-change|gm-change``, ``... high-correction interval <1-300>|immediate`` and
  ``... port-state-change [category all|master-slave-only] interval <1-300>|immediate``;
  every ``no`` form takes the value (``no ptp domain 5``). Only the boundary clock is
  offered: ``ptp device-type generalized-ptp`` is "not supported on this platform", and
  ``ptp cost`` too;
* on a port: ``ptp`` (``no ptp`` takes every PTP line off), ``ptp announce interval``
  0-4, ``ptp announce timeout`` 2-4, ``ptp sync interval`` -3 to 1 (-2 when not set),
  ``ptp delay-request minimum interval`` -1 to 6, ``ptp vlan`` (not the switch's own
  VLANs), ``ptp role master|slave|dynamic`` (slave only with unicast: "PTP slave-only role
  is not supported with PTP multicast transmission"), ``ptp transmission
  multicast|unicast``, ``ptp ucast-source``, ``ptp master <IPv4>`` and ``ptp slave
  <IPv4>`` (unicast peers, several of each); every ``no`` form takes the value.

``show ptp port interface`` gives a negative sync interval as a huge number (2 to the
64th), so the port's settings are read from the configuration text instead.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.features import feature_states
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
)
from app.switch import rows, text
from app.switch_admin import vrf_choices

FEATURE = "ptp"
PAGE_COMMANDS = ("show feature", "show interface brief", "show vrf")
COMMANDS = (
    "show ptp clock",
    "show ptp parent",
    "show ptp time-property",
    "show ptp brief",
    "show ptp counters all",
)
CONFIG_COMMAND = "show running-config"
NS_MAX = 1_000_000_000
NOTIFY_MAX = 300
CATEGORIES = ("all", "master-slave-only")
TRANSMISSIONS = ("multicast", "unicast")
ROLES = ("master", "slave", "dynamic")
ANNOUNCE_INTERVALS = tuple(str(n) for n in range(0, 5))
ANNOUNCE_TIMEOUTS = ("2", "3", "4")
SYNC_INTERVALS = tuple(str(n) for n in range(-3, 2))
DELAY_INTERVALS = tuple(str(n) for n in range(-1, 7))
PTP_VLAN_MAX = 3967  # the switch keeps the VLANs above for itself
DEVICE_TYPES = {"bc": "boundary clock"}

_LOG_HINT = "Written as a power of 2 in seconds: -1 is twice a second, 0 once a second, 1 every 2 s"


def _notify(key: str, label: str, kind: str, timed: bool, category: bool = False) -> Setting:
    """A notification line: sent at once (``interval immediate``) or at most every N s."""
    fields: tuple[Field, ...] = ()
    if category:
        fields += (
            Field(
                "category",
                "Which changes",
                "choice",
                choices=CATEGORIES,
                optional=True,
                hint="master-slave-only: only a port becoming master or slave",
            ),
        )
    if timed:
        fields += (
            Field(
                "seconds",
                "At most every (seconds)",
                "int",
                minimum=1,
                maximum=NOTIFY_MAX,
                hint=f"1 to {NOTIFY_MAX}",
            ),
        )
    when = "interval {seconds}" if timed else "interval immediate"
    return Setting(
        key=key,
        label=label,
        line=f"ptp notification type {kind}"
        + ("[ category {category}]" if category else "")
        + f" {when}",
        no_line=f"no ptp notification type {kind}",
        group="Notifications",
        fields=fields,
        help="The switch sends a notification (to a telemetry collector) when it happens. "
        "Setting the other timing for the same notification replaces this one.",
    )


def _ns(key: str, label: str, line: str, hint: str, help_text: str) -> Setting:
    return Setting(
        key=key,
        label=label,
        line=f"{line} {{ns}}",
        no_line=f"no {line} {{ns}}",
        group="Limits",
        fields=(Field("ns", "Nanoseconds", "int", minimum=10, maximum=NS_MAX, hint=hint),),
        help=help_text,
    )


_SWITCH = Scope(
    key="ptp_switch",
    label="PTP clock",
    ident=(),
    enter=(),
    help="The switch's own PTP clock: the address its PTP messages come from, its domain "
    "and priorities. Set the source address before turning PTP on on any port.",
    settings=(
        Setting(
            key="source",
            label="Source address",
            line="ptp source {address}[ vrf {vrf}]",
            no_line="no ptp source {address}",
            group="Clock",
            fields=(
                Field(
                    "address",
                    "Address",
                    "ipv4",
                    hint="An IPv4 address of this switch, such as a loopback's",
                    placeholder="192.0.2.1",
                ),
                Field("vrf", "VRF", "usevrf", optional=True, hint="Where the address is"),
            ),
            help="Needed before a port runs PTP. It cannot be removed while a port still runs PTP.",
        ),
        Setting(
            key="domain",
            label="Domain",
            line="ptp domain {domain}",
            no_line="no ptp domain {domain}",
            group="Clock",
            fields=(
                Field(
                    "domain",
                    "Domain",
                    "int",
                    minimum=0,
                    maximum=127,
                    hint="0 to 127; 0 when not set",
                ),
            ),
            help="Clocks only take the time from clocks in the same domain.",
            warning="Ports stop taking the time from clocks in the old domain.",
        ),
        Setting(
            key="priority1",
            label="Priority 1",
            line="ptp priority1 {priority}",
            no_line="no ptp priority1 {priority}",
            group="Clock",
            fields=(
                Field(
                    "priority",
                    "Priority",
                    "int",
                    minimum=0,
                    maximum=255,
                    hint="0 to 255, lower wins; 255 when not set",
                ),
            ),
            help="Compared first when clocks pick the grandmaster. Keep 255 unless this "
            "switch should be the one others take the time from.",
        ),
        Setting(
            key="priority2",
            label="Priority 2",
            line="ptp priority2 {priority}",
            no_line="no ptp priority2 {priority}",
            group="Clock",
            fields=(
                Field(
                    "priority",
                    "Priority",
                    "int",
                    minimum=0,
                    maximum=255,
                    hint="0 to 255, lower wins; 255 when not set",
                ),
            ),
            help="Breaks a tie between clocks that are otherwise equal.",
        ),
        Setting(
            key="management",
            label="Answer PTP management messages",
            line="ptp management",
            group="Clock",
            help="On from the start. Remove makes the switch ignore PTP management messages.",
        ),
        _ns(
            "correction_range",
            "Correction range",
            "ptp correction-range",
            "10 to 1000000000; 100000 when not set",
            "A correction larger than this counts as high (for the notification and the log).",
        ),
        Setting(
            key="correction_logging",
            label="Log high corrections",
            line="ptp correction-range logging",
            group="Limits",
            help="Writes a log message for every correction above the correction range.",
        ),
        _ns(
            "mean_path_delay",
            "Mean path delay limit",
            "ptp mean-path-delay",
            "10 to 1000000000; 1000000000 when not set",
            "A mean path delay above this counts as too high.",
        ),
        Setting(
            key="notify_parent",
            label="Notify: parent clock changes",
            line="ptp notification type parent-change",
            group="Notifications",
        ),
        Setting(
            key="notify_gm",
            label="Notify: grandmaster changes",
            line="ptp notification type gm-change",
            group="Notifications",
        ),
        _notify(
            "notify_correction_now", "Notify: high correction, at once", "high-correction", False
        ),
        _notify(
            "notify_correction_every",
            "Notify: high correction, at most every few seconds",
            "high-correction",
            True,
        ),
        _notify(
            "notify_port_now",
            "Notify: port state changes, at once",
            "port-state-change",
            False,
            category=True,
        ),
        _notify(
            "notify_port_every",
            "Notify: port state changes, at most every few seconds",
            "port-state-change",
            True,
            category=True,
        ),
    ),
)

_PORT = Scope(
    key="ptp_port",
    label="Port",
    ident=(
        Field(
            "port",
            "Port",
            "port",
            hint="A front port such as Ethernet1/3",
            placeholder="Ethernet1/3",
        ),
    ),
    enter=("interface {port}",),
    help="PTP on one front port: toward the grandmaster, or toward devices that take the "
    "time from this switch. Set PTP on this port first, then its other settings.",
    settings=(
        Setting(
            key="ptp",
            label="PTP on this port",
            line="ptp",
            group="PTP",
            help="Set starts PTP on the port (the clock's source address must be set). "
            "Remove takes every PTP line off the port.",
        ),
        Setting(
            key="transmission",
            label="Transmission",
            line="ptp transmission {mode}",
            no_line="no ptp transmission {mode}",
            group="PTP",
            fields=(
                Field(
                    "mode",
                    "Mode",
                    "choice",
                    choices=TRANSMISSIONS,
                    hint="multicast (the default): PTP finds its peers itself; unicast: to "
                    "the masters and slaves listed below",
                ),
            ),
        ),
        Setting(
            key="role",
            label="Role",
            line="ptp role {role}",
            no_line="no ptp role {role}",
            group="PTP",
            fields=(
                Field(
                    "role",
                    "Role",
                    "choice",
                    choices=ROLES,
                    hint="master: only gives the time; slave: only takes it (unicast "
                    "only); dynamic: PTP decides",
                ),
            ),
        ),
        Setting(
            key="vlan",
            label="PTP VLAN",
            line="ptp vlan {vlan}",
            no_line="no ptp vlan {vlan}",
            group="PTP",
            fields=(
                Field(
                    "vlan",
                    "VLAN",
                    "int",
                    minimum=1,
                    maximum=PTP_VLAN_MAX,
                    hint=f"1 to {PTP_VLAN_MAX}; on a trunk port, the VLAN PTP runs in",
                ),
            ),
        ),
        Setting(
            key="announce_interval",
            label="Announce interval",
            line="ptp announce interval {log}",
            no_line="no ptp announce interval {log}",
            group="Message timing",
            fields=(
                Field("log", "Interval", "choice", choices=ANNOUNCE_INTERVALS, hint=_LOG_HINT),
            ),
            help="How often the port sends announce messages; 0 to 4.",
        ),
        Setting(
            key="announce_timeout",
            label="Announce timeout",
            line="ptp announce timeout {count}",
            no_line="no ptp announce timeout {count}",
            group="Message timing",
            fields=(Field("count", "Intervals", "choice", choices=ANNOUNCE_TIMEOUTS),),
            help="How many announce intervals may pass without one before the master "
            "counts as gone.",
        ),
        Setting(
            key="sync_interval",
            label="Sync interval",
            line="ptp sync interval {log}",
            no_line="no ptp sync interval {log}",
            group="Message timing",
            fields=(
                Field(
                    "log",
                    "Interval",
                    "choice",
                    choices=SYNC_INTERVALS,
                    hint="-3 is 8 a second, -2 (the default) 4 a second, 1 every 2 s",
                ),
            ),
        ),
        Setting(
            key="delay_request",
            label="Delay request interval",
            line="ptp delay-request minimum interval {log}",
            no_line="no ptp delay-request minimum interval {log}",
            group="Message timing",
            fields=(Field("log", "Interval", "choice", choices=DELAY_INTERVALS, hint=_LOG_HINT),),
            help="The shortest time between delay requests; -1 to 6.",
        ),
        Setting(
            key="ucast_source",
            label="Unicast source address",
            line="ptp ucast-source {address}",
            no_line="no ptp ucast-source {address}",
            group="Unicast",
            fields=(Field("address", "Address", "ipv4", placeholder="192.0.2.1"),),
            help="The address this port's unicast PTP messages come from.",
        ),
        Setting(
            key="master",
            label="Unicast master",
            line="ptp master {address}",
            group="Unicast",
            fields=(Field("address", "Address", "ipv4", placeholder="192.0.2.10"),),
            help="A master this port takes the time from. Set adds one; a port can have "
            "several. Remove takes that one away.",
        ),
        Setting(
            key="slave",
            label="Unicast slave",
            line="ptp slave {address}",
            group="Unicast",
            fields=(Field("address", "Address", "ipv4", placeholder="192.0.2.20"),),
            help="A device this port gives the time to. Set adds one; Remove takes it away.",
        ),
    ),
)


# ---- reading the switch ------------------------------------------------------------------


_INTERFACE = re.compile(r"^interface\s+(\S+)$", re.IGNORECASE)


@dataclass
class PtpConfig:
    """The PTP lines of ``show running-config``: the switch-wide ones and each port's."""

    switch: list[str] = field(default_factory=list)
    ports: dict[str, list[str]] = field(default_factory=dict)


def parse_ptp_config(config: str) -> PtpConfig:
    """The ``ptp ...`` lines at the top of ``show running-config``, and the ``ptp`` lines
    inside each ``interface`` block (ports without one are left out)."""
    found = PtpConfig()
    current: str | None = None
    for raw in config.splitlines():
        line = raw.strip()
        if not raw[:1].isspace():
            match = _INTERFACE.fullmatch(line)
            current = match.group(1) if match else None
            if line.startswith(("ptp ", "no ptp ")):
                found.switch.append(line)
            continue
        if current and (line == "ptp" or line.startswith("ptp ")):
            found.ports.setdefault(current, []).append(line)
    return found


def _after(lines: list[str], start: str) -> str:
    return next((line[len(start) :].strip() for line in lines if line.startswith(start)), "")


def _switch_values(lines: list[str]) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    if source := _after(lines, "ptp source "):
        address, _, vrf = source.partition(" vrf ")
        values["source"] = {"address": address.strip(), "vrf": vrf.strip()}
    for key, start, name in (
        ("domain", "ptp domain ", "domain"),
        ("priority1", "ptp priority1 ", "priority"),
        ("priority2", "ptp priority2 ", "priority"),
        ("mean_path_delay", "ptp mean-path-delay ", "ns"),
    ):
        if (found := _after(lines, start)).isdigit():
            values[key] = {name: found}
    for line in lines:
        if match := re.fullmatch(r"ptp correction-range (\d+)", line):
            values["correction_range"] = {"ns": match.group(1)}
    if "ptp correction-range logging" in lines:
        values["correction_logging"] = {}
    if "no ptp management" not in lines:
        values["management"] = {}
    if "ptp notification type parent-change" in lines:
        values["notify_parent"] = {}
    if "ptp notification type gm-change" in lines:
        values["notify_gm"] = {}
    for kind, now, every in (
        ("high-correction", "notify_correction_now", "notify_correction_every"),
        ("port-state-change", "notify_port_now", "notify_port_every"),
    ):
        rest = _after(lines, f"ptp notification type {kind}")
        category = re.search(r"category (\S+)", rest)
        chosen = {"category": category.group(1)} if category else {}
        interval = re.search(r"interval (\S+)", rest)
        if interval and interval.group(1).isdigit():
            values[every] = {**chosen, "seconds": interval.group(1)}
        elif any(line.startswith(f"ptp notification type {kind}") for line in lines):
            values[now] = chosen
    return values


def _port_values(lines: list[str]) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {"ptp": {}} if "ptp" in lines else {}
    for key, start, name in (
        ("transmission", "ptp transmission ", "mode"),
        ("role", "ptp role ", "role"),
        ("vlan", "ptp vlan ", "vlan"),
        ("announce_interval", "ptp announce interval ", "log"),
        ("announce_timeout", "ptp announce timeout ", "count"),
        ("sync_interval", "ptp sync interval ", "log"),
        ("delay_request", "ptp delay-request minimum interval ", "log"),
        ("ucast_source", "ptp ucast-source ", "address"),
    ):
        if found := _after(lines, start):
            values[key] = {name: found}
    return values


def _addresses(lines: list[str], start: str) -> str:
    return ", ".join(line[len(start) :] for line in lines if line.startswith(start)) or "none"


def _state_rows(brief: Any) -> dict[str, str]:
    """``show ptp brief`` as port -> state ("Eth1/5 (unicast)" -> Ethernet1/5)."""
    states: dict[str, str] = {}
    for row in rows(brief or {}, "TABLE_ptp", "ROW_ptp"):
        name = text(row.get("ptp-ifindex")).split(" ")[0]
        states[_long_name(name)] = text(row.get("state")).lower()
    return states


def _long_name(name: str) -> str:
    """``Eth1/5`` -> ``Ethernet1/5``; other names as they are."""
    match = re.fullmatch(r"(?i)eth(?:ernet)?(\d+/\d+(?:/\d+)?)", name)
    return f"Ethernet{match.group(1)}" if match else name


_COUNTERS = (
    ("Announce", "announce"),
    ("Sync", "sync"),
    ("Follow-up", "follow-up"),
    ("Delay request", "delay-req"),
    ("Delay response", "delay-resp"),
)


def _counter_rows(counters: Any) -> dict[str, dict[str, Any]]:
    return {
        _long_name(text(row.get("interface_name"))): row
        for row in rows(counters or {}, "TABLE_ptp", "ROW_ptp")
    }


def _clock_facts(clock: dict[str, Any], parent: dict[str, Any], prop: dict[str, Any]):
    own = text(clock.get("clock-id"))
    grandmaster = text(parent.get("gm-id"))
    device = text(clock.get("device-type"))
    facts = [
        ("State", text(clock.get("clock-state")) or "-"),
        ("Device type", DEVICE_TYPES.get(device, device or "-")),
        ("Domain", text(clock.get("domain-id")) or "-"),
        ("Source address", text(clock.get("src-ip")) or "-"),
        (
            "Priority 1 / 2",
            f"{text(clock.get('priority1')) or '-'} / {text(clock.get('priority2')) or '-'}",
        ),
        ("Clock ID", own or "-"),
        (
            "Grandmaster",
            "this switch" if grandmaster and grandmaster == own else grandmaster or "-",
        ),
        ("Grandmaster class", text(parent.get("gm-class")) or "-"),
        ("Offset from master (ns)", text(clock.get("offset-from-master")) or "-"),
        ("Mean path delay (ns)", text(clock.get("mean-path-delay-to-master")) or "-"),
        ("Steps removed", text(clock.get("steps-removed")) or "-"),
        ("PTP ports", text(clock.get("num-ports")) or "-"),
        ("Time source", text(prop.get("time-source")) or "-"),
        ("UTC offset (s)", text(prop.get("current-utc-offset")) or "-"),
    ]
    return tuple(facts)


def parse_ptp_view(
    clock: Any,
    parent: Any,
    prop: Any,
    brief: Any,
    counters: Any,
    config: str | None,
) -> ProtocolView:
    """The page: the clock with its state and settings, one place per PTP port, and a
    table of every PTP port's state and message counters."""
    lines = parse_ptp_config(config or "")
    instances: list[Instance] = [
        Instance(
            "ptp_switch",
            {},
            "PTP clock",
            _clock_facts(clock or {}, parent or {}, prop or {}),
            _switch_values(lines.switch),
        )
    ]
    states = _state_rows(brief)
    counted = _counter_rows(counters)
    ports = list(dict.fromkeys([*lines.ports, *states]))
    table_rows: list[tuple[str, ...]] = []
    for port in ports:
        port_lines = lines.ports.get(port, [])
        state = states.get(port, "")
        facts = (
            ("State", state or "-"),
            ("Transmission", _after(port_lines, "ptp transmission ") or "multicast"),
            ("Role", _after(port_lines, "ptp role ") or "-"),
            ("VLAN", _after(port_lines, "ptp vlan ") or "-"),
            ("Unicast masters", _addresses(port_lines, "ptp master ")),
            ("Unicast slaves", _addresses(port_lines, "ptp slave ")),
        )
        values = _port_values(port_lines)
        if not port_lines and state:
            values["ptp"] = {}
        instances.append(Instance("ptp_port", {"port": port}, port, facts, values))
        row = counted.get(port, {})
        table_rows.append(
            (
                port,
                state or "-",
                *(
                    f"{text(row.get(f'tx-{name}-pkts')) or '-'} / "
                    f"{text(row.get(f'rx-{name}-pkts')) or '-'}"
                    for _, name in _COUNTERS
                ),
            )
        )
    tables = (
        Table(
            "PTP ports",
            ("Port", "State", *(f"{label} sent / received" for label, _ in _COUNTERS)),
            tuple(table_rows),
            empty="No port runs PTP.",
            note="A port taking the time from a master shows slave; one giving it, master.",
        ),
    )
    return ProtocolView(tuple(instances), tables)


PTP = Protocol(
    key="ptp",
    name="PTP",
    summary="Very precise time from a grandmaster clock, passed on to the devices behind "
    "this switch (PTP)",
    features=(FEATURE,),
    commands=COMMANDS,
    parse=lambda bodies: parse_ptp_view(*(bodies + [None] * 5)[:5], None),
    scopes=(_SWITCH, _PORT),
    about=(
        "The switch runs as a PTP boundary clock: it takes the time from the best master "
        "it hears and gives it to the devices on its other PTP ports. Set the clock's "
        "source address first, then turn PTP on on the ports."
    ),
)


@dataclass(frozen=True)
class PtpPage:
    """Everything the PTP page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # the front ports
    vrfs: tuple[str, ...]  # default, management, then the others
    problem: str = ""
    missing: tuple[str, ...] = ()  # the ptp feature, when it is off


def load_ptp_page(client: NxapiClient) -> PtpPage:
    """One request for the feature, the ports and the VRFs; while ptp is on, one for the
    clock and ports and one for the configuration text."""
    feature, brief, vrf_body = client.show(*PAGE_COMMANDS)
    ports = tuple(p for p in all_port_names(brief) if p.startswith("Ethernet"))
    vrfs = vrf_choices(vrf_body)
    if not feature_states(feature).get(FEATURE, False):
        return PtpPage(PTP, ProtocolView(), ports, vrfs, missing=(FEATURE,))
    try:
        bodies = client.show(*COMMANDS)
    except NxapiCommandError as exc:
        return PtpPage(PTP, ProtocolView(), ports, vrfs, f"The switch did not report PTP: {exc}")
    problem = ""
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError as exc:
        config = None
        problem = f"The switch did not show the PTP settings, so the forms start empty: {exc}"
    return PtpPage(PTP, parse_ptp_view(*bodies, config), ports, vrfs, problem)


def build_ptp_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the PTP page."""
    return build_change(PTP, scope, setting, action, ident, values)
