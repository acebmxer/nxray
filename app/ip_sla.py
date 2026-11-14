"""IP SLA: entries that measure the network from the switch (ping, UDP echo and jitter,
TCP connect, DNS, HTTP), their schedules, the reactions to their results, and the results.

An entry is numbered and measures one thing; once made, what it measures stays (the
switch takes the measuring line only once per entry). It runs only while it has a
schedule, and while it runs it cannot be changed: the schedule is removed first. A
reaction watches one event of an entry's results (a round-trip time over a threshold, a
timeout, packet loss) and can start another entry (a reaction trigger).

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (an entry, its schedule, its reactions), each setting the
one configuration line it sends with checked values in its blanks, and ``build_change``
building the lines. ``NxapiClient.configure_ip_sla`` sends them.

Read from the switch: ``show feature`` and ``show vrf`` in one request; while ``feature
sla sender`` is on (the commands do not exist before), ``show ip sla configuration`` and
``show ip sla statistics details`` in one, and ``show running-config sla sender`` as text
for what is set (the schedules, reactions and triggers, and each entry's own lines).
With no entry the switch answers the JSON commands with nothing.

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-11) with throwaway entries, all removed
afterwards: every line below and its ``no`` form, and the show commands. What the switch
does, as seen there:

* entering an entry that measures something goes straight into its settings; the
  measuring line typed again is refused, so is a different one;
* while an entry is scheduled every change to it is refused ("Entry already running and
  cannot be modified"); ``no ip sla schedule`` lets it be changed again;
* ``timeout`` is refused when it is below the threshold (5000 ms unless set);
* ``tag`` takes one word; ``vrf`` refuses a VRF the switch does not have;
* a reaction event set again replaces the one before; ``no ip sla reaction-configuration
  <n>`` alone is refused, so each event is removed by name; which events an entry takes
  depends on what it measures (connection loss and the jitter and packet events: UDP
  jitter; verify error: ping); ``mos`` takes thresholds from 100 to 500;
* ``recurring`` needs a start time of day, a life under a day, and life plus ageout over
  a day;
* ``show ip sla reaction-configuration`` gives lists that do not line up, so the
  reactions are read from the configuration text instead.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.features import feature_states
from app.nxapi import NxapiClient, NxapiCommandError
from app.protocols import (
    SLA_SECONDS_MAX,
    Field,
    Instance,
    Protocol,
    ProtocolChange,
    ProtocolView,
    Scope,
    Setting,
    Table,
    build_change,
    table_rows,
)
from app.switch import text
from app.switch_admin import vrf_choices

PAGE_COMMANDS = ("show feature", "show vrf")
COMMANDS = ("show ip sla configuration", "show ip sla statistics details")
CONFIG_COMMAND = "show running-config sla sender"
FEATURE = "sla_sender"
ENTRY_MAX = 2147483647
CODECS = ("g711alaw", "g711ulaw", "g729a")
EVENTS = (
    "rtt",
    "timeout",
    "connectionLoss",
    "verifyError",
    "jitterAvg",
    "jitterDSAvg",
    "jitterSDAvg",
    "maxOfPositiveSD",
    "maxOfNegativeSD",
    "maxOfPositiveDS",
    "maxOfNegativeDS",
    "packetLossSD",
    "packetLossDS",
    "packetLateArrival",
    "packetOutOfSequence",
    "icpif",
    "mos",
)
THRESHOLD_TYPES = ("immediate", "consecutive", "xofy", "average", "never")
ACTIONS = ("none", "trapOnly", "triggerOnly", "trapAndTrigger")
HISTORY_FILTERS = ("all", "overThreshold", "failures", "none")

# What ``latest-return-code`` means (the RTTMON MIB's RttResponseSense; 1 and 4 seen on
# cisco-25gb, written there as "OK" and "Timeout").
RETURN_CODES = {
    0: "Other",
    1: "OK",
    2: "Disconnected",
    3: "Over threshold",
    4: "Timeout",
    5: "Busy",
    6: "Not connected",
    7: "Dropped",
    8: "Sequence error",
    9: "Verify error",
    10: "Application specific",
    11: "DNS server timeout",
    12: "TCP connect timeout",
    13: "HTTP transaction timeout",
    14: "DNS query error",
    15: "HTTP error",
    16: "Error",
}

_ONCE = (
    "The switch takes this once, when the entry is made: to measure something else, delete "
    "the entry and make it again."
)
_SOURCE = Field(
    "source",
    "Source address",
    "ipv4",
    optional=True,
    hint="An address of the switch to send from; empty: the switch picks one",
)


def _target(hint: str = "The address to measure to") -> Field:
    return Field("target", "Target address", "ipv4", hint=hint, placeholder="192.0.2.1")


def _port(name: str = "port", label: str = "Target port", optional: bool = False) -> Field:
    return Field(name, label, "int", 1, 65535, optional=optional)


def _ms(name: str, label: str, hint: str) -> Field:
    return Field(name, label, "int", 0, SLA_SECONDS_MAX, hint=hint)


def _check_vrf(values: dict[str, str]) -> None:
    if not values.get("vrf"):
        raise ValueError(
            "the entry runs in the default VRF unless one is set; Remove goes back to it"
        )


def _measure(key: str, label: str, line: str, fields: tuple[Field, ...], hint: str) -> Setting:
    return Setting(
        key=key,
        label=label,
        line=line,
        removable=False,
        group="What it measures (once per entry)",
        fields=fields,
        help=f"{hint} {_ONCE}",
    )


_ENTRY = Scope(
    key="entry",
    label="IP SLA entry",
    ident=(
        Field(
            "entry",
            "Entry",
            "int",
            1,
            ENTRY_MAX,
            hint="A number of your own, 1 to 2147483647",
            placeholder="10",
        ),
    ),
    enter=("ip sla {entry}",),
    delete=("no ip sla {entry}",),
    delete_warning="Its schedule, results and reactions go with it.",
    help=(
        "To make an entry, pick a new number and set what it measures, then its other "
        "settings, then give it a schedule. A scheduled entry cannot be changed: remove "
        "its schedule first."
    ),
    settings=(
        _measure(
            "icmp_echo",
            "Ping (ICMP echo)",
            "icmp-echo {target}[ source-ip {source}]",
            (_target(), _SOURCE),
            "The round-trip time of a ping.",
        ),
        _measure(
            "udp_echo",
            "UDP echo",
            "udp-echo {target} {port}[ source-ip {source}]",
            (_target(), _port(), _SOURCE),
            "The round-trip time of a UDP packet echoed back by the target.",
        ),
        _measure(
            "udp_jitter",
            "UDP jitter",
            "udp-jitter {target} {port}[ codec {codec}][ source-ip {source}]"
            "[ source-port {source_port}][ num-packets {packets}][ interval {interval}]",
            (
                _target("A device that answers IP SLA (an IP SLA responder)"),
                _port(),
                Field(
                    "codec",
                    "Voice codec",
                    "choice",
                    choices=CODECS,
                    optional=True,
                    hint="Send like a voice call with this codec (gives a MOS score)",
                ),
                _SOURCE,
                _port("source_port", "Source port", optional=True),
                Field("packets", "Packets", "int", 1, 60000, optional=True, hint="Default 10"),
                Field(
                    "interval",
                    "Interval (ms)",
                    "int",
                    1,
                    60000,
                    optional=True,
                    hint="Between the packets; default 20",
                ),
            ),
            "Delay, jitter and packet loss to an IP SLA responder.",
        ),
        _measure(
            "tcp_connect",
            "TCP connect",
            "tcp-connect {target} {port}[ source-ip {source}]",
            (_target(), _port(), _SOURCE),
            "How long a TCP connection to the target takes to open.",
        ),
        _measure(
            "dns",
            "DNS lookup",
            "dns {name} name-server {server}",
            (
                Field(
                    "name",
                    "Name to look up",
                    "domain",
                    hint="Such as www.example.net",
                ),
                Field("server", "DNS server", "ipv4"),
            ),
            "How long a DNS server takes to answer.",
        ),
        _measure(
            "http",
            "HTTP get",
            "http get {url}",
            (
                Field(
                    "url",
                    "Web address",
                    "url",
                    hint="Starting http://; a ? cannot be sent",
                    placeholder="http://192.0.2.1/",
                ),
            ),
            "How long a web page takes to load.",
        ),
        Setting(
            key="frequency",
            label="How often",
            line="frequency {seconds}",
            no_line="no frequency",
            group="Timing",
            fields=(Field("seconds", "Every (seconds)", "int", 1, 604800, hint="Default 60"),),
        ),
        Setting(
            key="threshold",
            label="Threshold",
            line="threshold {ms}",
            no_line="no threshold",
            group="Timing",
            fields=(
                _ms(
                    "ms", "Milliseconds", "Slower than this counts as over threshold; default 5000"
                ),
            ),
        ),
        Setting(
            key="timeout",
            label="Timeout",
            line="timeout {ms}",
            no_line="no timeout",
            group="Timing",
            fields=(_ms("ms", "Milliseconds", "At least the threshold; default 5000"),),
        ),
        Setting(
            key="vrf",
            label="VRF",
            line="vrf {vrf}",
            no_line="no vrf",
            group="Packets",
            fields=(Field("vrf", "VRF", "usevrf", hint="The VRF the packets are sent in"),),
            check=_check_vrf,
            help="Remove goes back to the default VRF.",
        ),
        Setting(
            key="tos",
            label="Type of service",
            line="tos {tos}",
            no_line="no tos",
            group="Packets",
            fields=(
                Field(
                    "tos", "ToS byte", "int", 0, 255, hint="46 is the byte for DSCP 11, 184 for EF"
                ),
            ),
        ),
        Setting(
            key="request_data_size",
            label="Packet data size",
            line="request-data-size {bytes}",
            no_line="no request-data-size",
            group="Packets",
            fields=(Field("bytes", "Bytes", "int", 0, 16384),),
        ),
        Setting(
            key="verify_data",
            label="Check the data that comes back",
            line="verify-data",
            group="Packets",
        ),
        Setting(
            key="tag",
            label="Tag",
            line="tag {tag}",
            no_line="no tag",
            group="Labels",
            fields=(Field("tag", "Tag", "name", hint="One word"),),
        ),
        Setting(
            key="owner",
            label="Owner",
            line="owner {owner}",
            no_line="no owner",
            group="Labels",
            fields=(Field("owner", "Owner", "name", hint="One word"),),
        ),
        Setting(
            key="buckets_kept",
            label="History buckets kept",
            line="history buckets-kept {count}",
            no_line="no history buckets-kept",
            group="History",
            fields=(Field("count", "Buckets", "int", 1, 60),),
        ),
        Setting(
            key="lives_kept",
            label="History lives kept",
            line="history lives-kept {count}",
            no_line="no history lives-kept",
            group="History",
            fields=(Field("count", "Lives", "int", 0, 2),),
        ),
        Setting(
            key="filter",
            label="What history keeps",
            line="history filter {filter}",
            no_line="no history filter",
            group="History",
            fields=(Field("filter", "Keep", "choice", choices=HISTORY_FILTERS),),
        ),
        Setting(
            key="hours_kept",
            label="Hours of statistics kept",
            line="history hours-of-statistics-kept {hours}",
            no_line="no history hours-of-statistics-kept",
            group="History",
            fields=(Field("hours", "Hours", "int", 0, 25, hint="Default 2"),),
        ),
        Setting(
            key="distributions_kept",
            label="Statistics distributions kept",
            line="history distributions-of-statistics-kept {count}",
            no_line="no history distributions-of-statistics-kept",
            group="History",
            fields=(Field("count", "Distributions", "int", 1, 20, hint="Default 1"),),
        ),
        Setting(
            key="distribution_interval",
            label="Statistics distribution interval",
            line="history statistics-distribution-interval {ms}",
            no_line="no history statistics-distribution-interval",
            group="History",
            fields=(Field("ms", "Milliseconds", "int", 1, 100, hint="Default 20"),),
        ),
        Setting(
            key="enhanced",
            label="Enhanced history",
            line="history enhanced interval {interval} buckets {buckets}",
            group="History",
            fields=(
                Field("interval", "Interval (seconds)", "int", 1, 3600),
                Field("buckets", "Buckets", "int", 1, 100),
            ),
        ),
    ),
)


def _made() -> Field:
    """The entry a schedule or reaction is for: one already on the switch (its own name, so
    the page can refuse a number the switch does not have)."""
    return Field("sla", "Entry", "int", 1, ENTRY_MAX, hint="An entry made above")


# How long an entry runs when its schedule names no life.
DEFAULT_LIFE = 3600


def _check_schedule(values: dict[str, str]) -> None:
    if not values.get("recurring"):
        return
    start = values.get("start", "")
    if not re.match(r"[0-9]", start):
        raise ValueError("a recurring entry starts at a time of day, such as 02:00")
    life = values.get("life") or str(DEFAULT_LIFE)
    if not life.isdigit() or int(life) >= 86400:
        raise ValueError("a recurring entry runs for less than a day (86400 seconds)")
    if int(life) + int(values.get("ageout") or 0) <= 86400:
        raise ValueError("for a recurring entry, life plus ageout must be more than a day")


_SCHEDULE = Scope(
    key="schedule",
    label="Schedule",
    ident=(_made(),),
    enter=(),
    help=(
        "An entry runs only while it has a schedule. To change a schedule, remove it, "
        "then set the new one."
    ),
    settings=(
        Setting(
            key="schedule",
            label="Schedule",
            line="ip sla schedule {sla}[ life {life}][ start-time {start}][ ageout {ageout}]"
            "[ {recurring}]",
            no_line="no ip sla schedule {sla}",
            ident=("sla",),
            check=_check_schedule,
            group="Schedule",
            fields=(
                Field(
                    "start",
                    "Start",
                    "slastart",
                    optional=True,
                    hint="now, pending (started by a reaction), after 00:10:00, or a time "
                    "such as 14:30 or 14:30:00 Nov 12; empty: pending",
                    placeholder="now",
                ),
                Field(
                    "life",
                    "Runs for",
                    "slalife",
                    optional=True,
                    hint="Seconds, or forever; default 3600",
                    placeholder="forever",
                ),
                Field(
                    "ageout",
                    "Kept after it stops (seconds)",
                    "int",
                    0,
                    2073600,
                    optional=True,
                    hint="Empty: kept for good",
                ),
                Field(
                    "recurring",
                    "Every day",
                    "flag",
                    choices=("recurring",),
                    hint="Start again at the same time each day",
                ),
            ),
            help="Remove stops the entry; its settings stay.",
        ),
    ),
)


def _check_reaction(values: dict[str, str]) -> None:
    when, count, of = values.get("when"), values.get("count"), values.get("of")
    if when in ("consecutive", "average") and (not count or of):
        raise ValueError(f"{when} takes how many times (only)")
    if when == "xofy":
        if not (count and of):
            raise ValueError("xofy takes how many times (x) and out of how many (y)")
        if int(count) > int(of):
            raise ValueError("x cannot be more than y")
    if when in ("immediate", "never") and (count or of):
        raise ValueError(f"{when} takes no count")
    upper, lower = values.get("upper"), values.get("lower")
    if upper and lower and int(lower) > int(upper):
        raise ValueError("the falling threshold cannot be above the rising one")


_REACTION = Scope(
    key="reaction",
    label="Reactions",
    ident=(_made(),),
    enter=(),
    help=(
        "What to do when an entry's results cross a line: send an SNMP trap, start "
        "another entry, or both. One reaction per event: setting an event again replaces "
        "it."
    ),
    settings=(
        Setting(
            key="reaction",
            label="Reaction",
            line="ip sla reaction-configuration {sla} react {event}"
            "[ threshold-value {upper} {lower}] threshold-type {when}[ {count}][ {of}]"
            "[ action-type {action}]",
            no_line="no ip sla reaction-configuration {sla} react {event}",
            ident=("sla",),
            check=_check_reaction,
            group="Reaction",
            fields=(
                Field(
                    "event",
                    "Event",
                    "choice",
                    choices=EVENTS,
                    hint="rtt and timeout: every entry; verifyError: ping; connectionLoss, "
                    "jitter, packet and voice (icpif, mos) events: UDP jitter",
                ),
                Field(
                    "upper",
                    "Rising threshold",
                    "int",
                    0,
                    SLA_SECONDS_MAX,
                    optional=True,
                    hint="Milliseconds (packets for packet events; 100-500 for mos); "
                    "give both or neither",
                ),
                Field("lower", "Falling threshold", "int", 0, SLA_SECONDS_MAX, optional=True),
                Field(
                    "when",
                    "React",
                    "choice",
                    choices=THRESHOLD_TYPES,
                    hint="immediate: the first time; consecutive: N times in a row; xofy: x "
                    "of the last y; average: the average of N; never: only record it",
                ),
                Field("count", "Times (N or x)", "int", 1, 16, optional=True),
                Field("of", "Out of (y)", "int", 1, 16, optional=True),
                Field(
                    "action",
                    "Action",
                    "choice",
                    choices=ACTIONS,
                    optional=True,
                    hint="Default none",
                ),
            ),
            help="Remove needs only the event.",
        ),
        Setting(
            key="trigger",
            label="Start another entry",
            line="ip sla reaction-trigger {sla} {target}",
            ident=("sla",),
            group="Trigger",
            fields=(
                Field(
                    "target",
                    "Entry to start",
                    "int",
                    1,
                    ENTRY_MAX,
                    hint="Scheduled with start pending; a reaction with a trigger action starts it",
                ),
            ),
        ),
    ),
)


# ---- reading the switch ------------------------------------------------------------------


@dataclass
class SlaConfig:
    """What ``show running-config sla sender`` holds for one entry."""

    measure: str = ""  # the measuring line, as the switch prints it
    lines: list[str] | None = None  # the entry's other lines
    schedule: str = ""  # what follows "ip sla schedule <n>"
    reactions: list[tuple[str, str]] | None = None  # (event, the rest of the line)
    triggers: list[str] | None = None  # the entries a reaction starts


_TOP = re.compile(r"ip sla (\d+)$")
_SCHEDULE_LINE = re.compile(r"ip sla schedule (\d+)\s*(.*)$")
_REACTION_LINE = re.compile(r"ip sla reaction-configuration (\d+) react (\S+)\s*(.*)$")
_TRIGGER_LINE = re.compile(r"ip sla reaction-trigger (\d+) (\d+)$")


def parse_sla_config(config: str) -> dict[int, SlaConfig]:
    """The entries in ``show running-config sla sender`` text, by number."""
    found: dict[int, SlaConfig] = {}

    def entry(number: str) -> SlaConfig:
        return found.setdefault(int(number), SlaConfig(lines=[], reactions=[], triggers=[]))

    current: SlaConfig | None = None
    for raw in config.splitlines():
        if not raw.strip() or raw.lstrip().startswith("!"):
            continue
        line = raw.strip()
        if not raw.startswith(" "):
            current = None
            if match := _TOP.fullmatch(line):
                current = entry(match.group(1))
            elif match := _SCHEDULE_LINE.fullmatch(line):
                entry(match.group(1)).schedule = match.group(2)
            elif match := _REACTION_LINE.fullmatch(line):
                entry(match.group(1)).reactions.append((match.group(2), match.group(3)))  # type: ignore[union-attr]
            elif match := _TRIGGER_LINE.fullmatch(line):
                entry(match.group(1)).triggers.append(match.group(2))  # type: ignore[union-attr]
            continue
        if current is None:
            continue
        if not current.measure:
            current.measure = line
        else:
            current.lines.append(line)  # type: ignore[union-attr]
    return found


_MEASURES = (
    ("icmp_echo", re.compile(r"icmp-echo (?P<target>\S+)(?: source-ip (?P<source>\S+))?")),
    (
        "udp_echo",
        re.compile(r"udp-echo (?P<target>\S+) (?P<port>\d+)(?: source-ip (?P<source>\S+))?"),
    ),
    (
        "udp_jitter",
        re.compile(
            r"udp-jitter (?P<target>\S+) (?P<port>\d+)(?: codec (?P<codec>\S+))?"
            r"(?: source-ip (?P<source>\S+))?(?: source-port (?P<source_port>\d+))?"
            r"(?: num-packets (?P<packets>\d+))?(?: interval (?P<interval>\d+))?"
        ),
    ),
    (
        "tcp_connect",
        re.compile(r"tcp-connect (?P<target>\S+) (?P<port>\d+)(?: source-ip (?P<source>\S+))?"),
    ),
    ("dns", re.compile(r"dns (?P<name>\S+) name-server (?P<server>\S+)")),
    ("http", re.compile(r"http get (?P<url>\S+)")),
)

# An entry line -> (setting key, {field: value}) for the "set" marks.
_ENTRY_LINES = (
    (re.compile(r"frequency (\d+)"), "frequency", ("seconds",)),
    (re.compile(r"threshold (\d+)"), "threshold", ("ms",)),
    (re.compile(r"timeout (\d+)"), "timeout", ("ms",)),
    (re.compile(r"vrf (\S+)"), "vrf", ("vrf",)),
    (re.compile(r"tos (\d+)"), "tos", ("tos",)),
    (re.compile(r"request-data-size (\d+)"), "request_data_size", ("bytes",)),
    (re.compile(r"verify-data"), "verify_data", ()),
    (re.compile(r"tag (\S+)"), "tag", ("tag",)),
    (re.compile(r"owner (\S+)"), "owner", ("owner",)),
    (re.compile(r"history buckets-kept (\d+)"), "buckets_kept", ("count",)),
    (re.compile(r"history lives-kept (\d+)"), "lives_kept", ("count",)),
    (re.compile(r"history filter (\S+)"), "filter", ("filter",)),
    (re.compile(r"history hours-of-statistics-kept (\d+)"), "hours_kept", ("hours",)),
    (
        re.compile(r"history distributions-of-statistics-kept (\d+)"),
        "distributions_kept",
        ("count",),
    ),
    (
        re.compile(r"history statistics-distribution-interval (\d+)"),
        "distribution_interval",
        ("ms",),
    ),
    (
        re.compile(r"history enhanced interval (\d+) buckets (\d+)"),
        "enhanced",
        ("interval", "buckets"),
    ),
)


def entry_values(config: SlaConfig) -> dict[str, dict[str, str]]:
    """The settings an entry has, as field values, from its configuration lines."""
    values: dict[str, dict[str, str]] = {}
    for key, pattern in _MEASURES:
        if match := pattern.fullmatch(config.measure):
            values[key] = {k: v for k, v in match.groupdict().items() if v}
            break
    for line in config.lines or []:
        for pattern, key, names in _ENTRY_LINES:
            if match := pattern.fullmatch(line):
                values[key] = (
                    dict(zip(names, match.groups(), strict=True)) if names else {"on": "yes"}
                )
                break
    return values


_SCHEDULE_PARTS = re.compile(
    r"(?:life (?P<life>\S+)\s*)?(?:start-time (?P<start>.+?)\s*)?(?:ageout (?P<ageout>\d+)\s*)?"
    r"(?P<recurring>recurring)?"
)


def schedule_values(schedule: str) -> dict[str, str]:
    """'life 300 start-time now' -> {"life": "300", "start": "now"}."""
    match = _SCHEDULE_PARTS.fullmatch(schedule.strip())
    return {k: v for k, v in match.groupdict().items() if v} if match else {}


def _number(value: Any) -> int | None:
    found = text(value)
    return int(found) if found.isdigit() else None


def _count(value: Any) -> str:
    """'Number of successes: 3' -> '3'; 'Unknown' -> '-'."""
    found = text(value).rsplit(":", 1)[-1].strip()
    return found if found.isdigit() else "-"


def _measures(row: dict[str, Any]) -> str:
    kind = text(row.get("oper-type"))
    if kind == "http":
        return f"http get {text(row.get('url'))}"
    if kind == "dns":
        return f"dns {text(row.get('dest-ip'))} via {text(row.get('dns-name-server'))}"
    target = text(row.get("dest-ip"))
    port = _number(row.get("dest-port"))
    return f"{kind} {target}" + (f" port {port}" if port else "")


def _latest(stats: dict[str, Any]) -> str:
    code = _number(stats.get("latest-return-code"))
    if code is None:
        return "-"
    shown = RETURN_CODES.get(code, f"code {code}")
    rtt = _number(stats.get("latest-RTT"))
    return f"{shown}, {rtt} ms" if code == 1 and rtt is not None else shown


def _seconds(milliseconds: Any) -> str:
    found = _number(milliseconds)
    return f"{found // 1000} s" if found is not None else ""


def parse_ip_sla(bodies: list[dict[str, Any]], config: str | None = None) -> ProtocolView:
    """The page from ``show ip sla configuration`` and ``show ip sla statistics details``
    (``bodies``, in that order) and ``show running-config sla sender`` (``config``; None
    when it could not be read)."""
    config_body, stats_body = (list(bodies) + [{}, {}])[:2]
    configs = parse_sla_config(config or "")
    stats: dict[int, dict[str, Any]] = {}
    for row in table_rows(stats_body, "TABLE_stats", "ROW_stats"):
        number = _number(row.get("index"))
        if number is None:
            continue
        details = table_rows(row, "TABLE_detail", "ROW_detail")
        stats[number] = {**row, **(details[0] if details else {})}

    rows: list[tuple[str, ...]] = []
    instances: list[Instance] = []
    schedules: list[Instance] = []
    reactions: list[Instance] = []
    for row in table_rows(config_body, "TABLE_configuration", "ROW_configuration"):
        number = _number(row.get("index"))
        if number is None:
            continue
        result = stats.get(number, {})
        held = configs.get(number, SlaConfig(lines=[], reactions=[], triggers=[]))
        vrf = text(row.get("vrf-name") or row.get("http-vrf-name")) or "default"
        frequency = _number(row.get("frequency"))
        state = text(result.get("oper-state")) or text(row.get("status-of-entry")) or "-"
        rows.append(
            (
                str(number),
                _measures(row),
                vrf,
                f"{frequency} s" if frequency is not None else "-",
                state,
                _latest(result),
                f"{_count(result.get('outstring1'))} / {_count(result.get('outstring2'))}",
                text(result.get("latest-start-time")) or "-",
            )
        )
        facts = [("Measures", _measures(row)), ("VRF", vrf), ("State", state)]
        source = text(row.get("source-ip"))
        if source and source != "0.0.0.0":
            facts.append(("Source address", source))
        for label, key in (("Tag", "tag"), ("Owner", "owner")):
            if value := text(row.get(key) or row.get(f"http-{key}")):
                facts.append((label, value))
        timeout = _number(row.get("timeout") or row.get("http-timeout"))
        threshold = _number(row.get("threshold"))
        if timeout is not None and threshold is not None:
            facts.append(("Threshold / timeout", f"{threshold} ms / {timeout} ms"))
        instances.append(
            Instance(
                "entry",
                {"entry": str(number)},
                f"Entry {number}",
                tuple(facts),
                entry_values(held),
            )
        )
        if held.schedule:
            values = schedule_values(held.schedule)
            facts = [("Schedule", held.schedule)]
            if left := _seconds(result.get("life-left")):
                facts.append(("Time left", left))
            schedules.append(
                Instance(
                    "schedule",
                    {"sla": str(number)},
                    f"Entry {number}",
                    tuple(facts),
                    {"schedule": values},
                )
            )
        if held.reactions or held.triggers:
            facts = [(event, rest or "(defaults)") for event, rest in held.reactions or []]
            facts += [("Starts entry", target) for target in held.triggers or []]
            values = {"trigger": {"target": held.triggers[-1]}} if held.triggers else {}
            reactions.append(
                Instance("reaction", {"sla": str(number)}, f"Entry {number}", tuple(facts), values)
            )

    notes = ()
    if config is None:
        notes = (
            "The switch did not show its IP SLA configuration, so schedules and reactions "
            "are not listed.",
        )
    tables = (
        Table(
            "Entries",
            (
                "Entry",
                "Measures",
                "VRF",
                "Every",
                "State",
                "Latest result",
                "OK / failed",
                "Last run",
            ),
            tuple(rows),
            empty="No IP SLA entry yet. Make one below.",
            note="Results are read when the page loads.",
            wrap_column=1,
        ),
    )
    return ProtocolView((*instances, *schedules, *reactions), tables, notes)


IP_SLA = Protocol(
    key="ip-sla",
    name="IP SLA",
    summary="Measure delay, jitter and loss from the switch to other devices",
    features=(FEATURE,),
    commands=COMMANDS,
    parse=parse_ip_sla,
    scopes=(_ENTRY, _SCHEDULE, _REACTION),
    about=(
        "Make an entry (what it measures, then its timing and packets), give it a "
        "schedule to start it, and add reactions if something should happen when its "
        "results cross a threshold."
    ),
)


# ---- the page ------------------------------------------------------------------------------


@dataclass(frozen=True)
class IpSlaPage:
    """Everything the IP SLA page shows."""

    protocol: Protocol
    view: ProtocolView
    vrfs: tuple[str, ...]  # default, management, then the others
    entries: tuple[str, ...] = ()  # the entry numbers on the switch
    problem: str = ""
    missing: tuple[str, ...] = ()  # the features still off (show feature names)


def load_ip_sla_page(client: NxapiClient) -> IpSlaPage:
    """One request for the features and VRFs; while sla sender is on, one for the entries
    and their results, and the configuration text for the schedules and reactions."""
    feature, vrf_body = client.show(*PAGE_COMMANDS)
    vrfs = vrf_choices(vrf_body)
    if not feature_states(feature).get(FEATURE, False):
        return IpSlaPage(IP_SLA, ProtocolView(), vrfs, missing=(FEATURE,))
    bodies = client.show(*COMMANDS)
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = None
    view = parse_ip_sla(bodies, config)
    entries = tuple(i.ident["entry"] for i in view.of("entry"))
    return IpSlaPage(IP_SLA, view, vrfs, entries)


def build_ip_sla_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the IP SLA page."""
    return build_change(IP_SLA, scope, setting, action, ident, values)
