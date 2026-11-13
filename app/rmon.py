"""RMON: the events and alarms the switch watches for, with the changes its forms make.

An **event** says what the switch does when an alarm fires: write to the log, send an SNMP
trap to a community, or both. An **alarm** watches one SNMP object every few seconds and fires
a rising or falling event when its value crosses a threshold; a high-capacity alarm (hcalarm)
does the same for 64-bit counters and says which crossing counts at start-up.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): one scope per kind, each made by its whole line and deleted by its
``no`` form. ``NxapiClient.configure_rmon`` sends them. RMON has no feature to turn on.

Read from the switch as text: ``show rmon events``, ``show rmon alarms``, ``show rmon
hcalarms`` and ``show rmon info``.

Tried on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-13), everything removed again,
nothing saved:

- ``rmon event <1-65535> [log] [trap <community>] [description <word>] [owner <word>]``.
  The description and owner are one word each. Entering an event again replaces what it does
  (log and trap: left out means off) but keeps its description and owner, so these can be
  changed but not emptied; only ``no rmon event <n>`` empties them. The switch had events 1
  to 5 (owner PMON@FATAL and so on) before; they are shown like any other.
- ``rmon alarm <1-65535> <object> <1-700000 seconds> absolute|delta rising-threshold <v>
  [<event>] falling-threshold <v> [<event>] [owner <word>]``. The object is the numeric dotted
  form and must exist (ifIndex 1 does not on this switch: "No such entry"; the object for
  Ethernet1/53's received bytes is 1.3.6.1.2.1.2.2.1.10.436234240). The falling threshold must
  be below the rising one. An event left out is event 1; an event number need not exist.
  Entering an alarm again replaces it whole.
- ``rmon hcalarm <n> <object> <seconds> absolute|delta startupalarm 1|2|3 rising-threshold <v>
  <event> falling-threshold <v> <event> owner <word>`` (all parts needed); the start-up
  alarm 1 is "rising", 2 "falling" and 3 "rising or falling".
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.nxapi import NxapiClient, NxapiCommandError
from app.protocols import (
    Field,
    Instance,
    Protocol,
    ProtocolChange,
    ProtocolView,
    Scope,
    Table,
    build_change,
)

EVENTS_COMMAND = "show rmon events"
ALARMS_COMMAND = "show rmon alarms"
HCALARMS_COMMAND = "show rmon hcalarms"
INFO_COMMAND = "show rmon info"

NUMBER_MAX = 65535
INTERVAL_MAX = 700000
THRESHOLD_MAX = 2147483647


def _id(label: str) -> Field:
    return Field("id", label, "int", 1, NUMBER_MAX)


def _owner() -> Field:
    return Field(
        "owner",
        "Owner",
        "name",
        optional=True,
        hint="One word naming who made it; left empty it keeps the owner it had",
    )


def _event_field(name: str, label: str) -> Field:
    return Field(
        name,
        label,
        "int",
        1,
        NUMBER_MAX,
        optional=True,
        hint="An event number; left empty the switch uses event 1",
    )


_EVENT_LINE = "rmon event {id}[ {log}][ trap {trap}][ description {description}][ owner {owner}]"

_EVENT = Scope(
    key="event",
    label="Event",
    ident=(
        _id("Number"),
        Field("log", "Write to the log", "flag", choices=("log",)),
        Field(
            "trap",
            "Send a trap to community",
            "name",
            maximum=32,
            optional=True,
            hint="The SNMP community, such as public",
        ),
        Field(
            "description",
            "Description",
            "name",
            optional=True,
            hint="One word; left empty it keeps the description it had",
        ),
        _owner(),
    ),
    enter=(_EVENT_LINE,),
    create=True,
    create_label="Make or change an event",
    delete=("no rmon event {id}",),
    delete_warning="An alarm that names this event then fires nothing for it.",
    help=(
        "What the switch does when an alarm fires. Entering an event again changes what it "
        "does; its description and owner can be changed but only emptied by deleting it."
    ),
)

_ALARM_FIELDS = (
    _id("Number"),
    Field(
        "oid",
        "SNMP object",
        "oid",
        hint="The object's number, dotted, such as 1.3.6.1.2.1.2.2.1.10.436234240 (a port's "
        "received bytes; the last number is the port's SNMP index)",
    ),
    Field("interval", "Check every (seconds)", "int", 1, INTERVAL_MAX),
    Field("sample", "Compare", "choice", choices=("absolute", "delta")),
    Field(
        "rising",
        "Rising threshold",
        "int",
        0,
        THRESHOLD_MAX,
        hint="Fires the rising event when the value goes up to it",
    ),
    _event_field("rising_event", "Rising event"),
    Field(
        "falling",
        "Falling threshold",
        "int",
        0,
        THRESHOLD_MAX,
        hint="Below the rising threshold; fires the falling event when the value goes down to it",
    ),
    _event_field("falling_event", "Falling event"),
    _owner(),
)

_ALARM_LINE = (
    "rmon alarm {id} {oid} {interval} {sample} rising-threshold {rising}[ {rising_event}]"
    " falling-threshold {falling}[ {falling_event}][ owner {owner}]"
)

_ALARM = Scope(
    key="alarm",
    label="Alarm",
    ident=_ALARM_FIELDS,
    enter=(_ALARM_LINE,),
    create=True,
    create_label="Make or change an alarm",
    delete=("no rmon alarm {id}",),
    help=(
        "Watches one SNMP object (32-bit). Entering an alarm again replaces it. The value is "
        "compared as it is (absolute) or as its change since the last check (delta)."
    ),
)

_HCALARM_LINE = (
    "rmon hcalarm {id} {oid} {interval} {sample} startupalarm {startup} "
    "rising-threshold {rising} {rising_event} falling-threshold {falling} {falling_event} "
    "owner {owner}"
)

_HCALARM = Scope(
    key="hcalarm",
    label="High-capacity alarm",
    ident=(
        *_ALARM_FIELDS[:5],
        Field("rising_event", "Rising event", "int", 1, NUMBER_MAX),
        _ALARM_FIELDS[6],
        Field("falling_event", "Falling event", "int", 1, NUMBER_MAX),
        Field("owner", "Owner", "name", hint="One word naming who made it"),
        Field(
            "startup",
            "At start-up",
            "choice",
            choices=("1", "2", "3"),
            hint="1: the rising alarm may fire, 2: the falling alarm, 3: either",
        ),
    ),
    enter=(_HCALARM_LINE,),
    create=True,
    create_label="Make or change a high-capacity alarm",
    delete=("no rmon hcalarm {id}",),
    help="Like an alarm, for 64-bit counters. Every part is needed.",
)

SCOPES = (_EVENT, _ALARM, _HCALARM)


def _check_thresholds(scope: str, ident: dict[str, str]) -> None:
    if scope not in ("alarm", "hcalarm"):
        return
    try:
        rising, falling = int(ident.get("rising", "")), int(ident.get("falling", ""))
    except ValueError:
        return  # build_change names the field
    if falling >= rising:
        raise ValueError("the falling threshold is below the rising threshold")


# ---- reading ---------------------------------------------------------------------

_EVENT_HEAD = re.compile(r"^Event (\d+) is active, owned by(?: (\S*))?\s*$")
_DESCRIPTION = re.compile(r"^Description is(?: (\S.*?))?\s*$")
_CAUSE = re.compile(r"Event firing causes (.+?), last fired (.+?)\s*$")
_ALARM_HEAD = re.compile(r"^(High Capacity )?Alarm (\d+) is active, owned by(?: (\S*))?\s*$")
_MONITORS = re.compile(r"^\s*Monitors (\S+) every (\d+) second\(s\)")
_SAMPLES = re.compile(r"^\s*Taking (\w+) samples, last value was (\S+)")
_THRESHOLD = re.compile(r"^\s*(Rising|Falling) threshold is (-?\d+), assigned to event (\d+)")
_STARTUP = re.compile(r"^\s*On startup enable (.+?)\s*$")


@dataclass(frozen=True)
class RmonEvent:
    number: str
    log: bool
    trap: str
    description: str
    owner: str
    last_fired: str


@dataclass(frozen=True)
class RmonAlarm:
    number: str
    high_capacity: bool
    owner: str
    oid: str
    interval: str
    sample: str
    value: str
    rising: str
    rising_event: str
    falling: str
    falling_event: str
    startup: str


def parse_events(output: str | None) -> list[RmonEvent]:
    """The events of ``show rmon events``: each starts with its ``Event N is active`` line,
    then the description, then what firing causes."""
    events: list[RmonEvent] = []
    fields: dict[str, str] = {}

    def close() -> None:
        if fields:
            cause = fields.get("cause", "")
            trap = re.search(r"trap to community (\S+)", cause)
            events.append(
                RmonEvent(
                    fields["number"],
                    cause == "log" or cause.startswith("log and"),
                    trap.group(1) if trap else "",
                    fields.get("description", ""),
                    fields.get("owner", ""),
                    fields.get("last", ""),
                )
            )

    for line in (output or "").splitlines():
        if match := _EVENT_HEAD.match(line):
            close()
            fields = {"number": match.group(1), "owner": match.group(2) or ""}
        elif fields and (match := _DESCRIPTION.match(line)):
            fields["description"] = match.group(1) or ""
        elif fields and (match := _CAUSE.search(line)):
            fields["cause"], fields["last"] = match.group(1), match.group(2)
    close()
    return events


def parse_alarms(output: str | None) -> list[RmonAlarm]:
    """The alarms of ``show rmon alarms`` or ``show rmon hcalarms``."""
    found: list[RmonAlarm] = []
    block: dict[str, str] | None = None

    def close() -> None:
        if block is not None:
            found.append(RmonAlarm(**block))  # type: ignore[arg-type]

    for line in (output or "").splitlines():
        if match := _ALARM_HEAD.match(line):
            close()
            block = dict.fromkeys(RmonAlarm.__dataclass_fields__, "")
            block["number"] = match.group(2)
            block["high_capacity"] = bool(match.group(1))  # type: ignore[assignment]
            block["owner"] = match.group(3) or ""
        elif block is None:
            continue
        elif match := _MONITORS.match(line):
            block["oid"], block["interval"] = match.group(1), match.group(2)
        elif match := _SAMPLES.match(line):
            block["sample"], block["value"] = match.group(1), match.group(2)
        elif match := _THRESHOLD.match(line):
            word = match.group(1).lower()
            block[word], block[f"{word}_event"] = match.group(2), match.group(3)
        elif match := _STARTUP.match(line):
            block["startup"] = match.group(1)
    close()
    return found


_STARTUP_CODES = {"rising alarm": "1", "falling alarm": "2", "rising or falling alarm": "3"}


def _event_instance(event: RmonEvent) -> Instance:
    cause = " and ".join(
        part
        for part in ("log" if event.log else "", f"trap to {event.trap}" if event.trap else "")
        if part
    )
    return Instance(
        "event",
        {
            "id": event.number,
            "log": "log" if event.log else "",
            "trap": event.trap,
            "description": event.description,
            "owner": event.owner,
        },
        f"Event {event.number}",
        (
            ("When it fires", cause or "nothing"),
            ("Description", event.description or "none"),
            ("Owner", event.owner or "none"),
            ("Last fired", event.last_fired),
        ),
    )


def _alarm_instance(alarm: RmonAlarm) -> Instance:
    scope = "hcalarm" if alarm.high_capacity else "alarm"
    ident = {
        "id": alarm.number,
        "oid": alarm.oid,
        "interval": alarm.interval,
        "sample": alarm.sample,
        "rising": alarm.rising,
        "rising_event": alarm.rising_event,
        "falling": alarm.falling,
        "falling_event": alarm.falling_event,
        "owner": alarm.owner,
    }
    facts = [
        ("Watches", f"{alarm.oid} every {alarm.interval} s ({alarm.sample})"),
        ("Last value", alarm.value),
        ("Rising", f"{alarm.rising}, event {alarm.rising_event}"),
        ("Falling", f"{alarm.falling}, event {alarm.falling_event}"),
        ("Owner", alarm.owner or "none"),
    ]
    if alarm.high_capacity:
        ident["startup"] = _STARTUP_CODES.get(alarm.startup, "3")
        facts.append(("At start-up", alarm.startup))
    return Instance(scope, ident, f"Alarm {alarm.number}", tuple(facts))


def parse_rmon(
    events: str | None, alarms: str | None, hcalarms: str | None, info: str | None
) -> ProtocolView:
    """The page from the four texts (None: not read)."""
    instances = [_event_instance(e) for e in parse_events(events)]
    instances += [_alarm_instance(a) for a in parse_alarms(alarms)]
    instances += [_alarm_instance(a) for a in parse_alarms(hcalarms)]
    rows = tuple(
        (name.strip(), value.strip())
        for name, _, value in (line.partition(":") for line in (info or "").splitlines())
        if value.strip()
    )
    tables = (Table("Alarms in use", ("What", "Value"), rows, empty="Not read."),) if rows else ()
    notes = []
    unread = [
        name
        for name, text in (
            ("events", events),
            ("alarms", alarms),
            ("high-capacity alarms", hcalarms),
        )
        if text is None
    ]
    if unread:
        notes.append(f"The switch did not show its {', '.join(unread)} to NXray's account.")
    return ProtocolView(tuple(instances), tables, tuple(notes))


RMON = Protocol(
    key="rmon",
    name="RMON",
    summary="Events and alarms that watch SNMP objects",
    features=(),
    commands=(),
    parse=lambda bodies: parse_rmon(None, None, None, None),
    scopes=SCOPES,
    about=(
        "An alarm checks one SNMP object every few seconds and fires an event when its value "
        "crosses a threshold; the event writes to the log, sends an SNMP trap, or both."
    ),
)


@dataclass(frozen=True)
class RmonPage:
    """Everything the RMON page shows."""

    protocol: Protocol
    view: ProtocolView
    problem: str = ""
    missing: tuple[str, ...] = ()  # always empty: RMON has no feature


def _text(client: NxapiClient, command: str) -> str | None:
    try:
        return client.show_text(command)
    except NxapiCommandError:
        return None


def load_rmon_page(client: NxapiClient) -> RmonPage:
    """The four RMON reads, as text."""
    view = parse_rmon(
        _text(client, EVENTS_COMMAND),
        _text(client, ALARMS_COMMAND),
        _text(client, HCALARMS_COMMAND),
        _text(client, INFO_COMMAND),
    )
    return RmonPage(RMON, view)


def check_rmon_place(page: RmonPage, ident: dict[str, str]) -> None:
    """Every scope is the whole switch: nothing to check."""


def build_rmon_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the RMON page, with an alarm's thresholds checked against each
    other when it is made."""
    change = build_change(RMON, scope, setting, action, ident, values)
    if action == "create":
        _check_thresholds(scope, ident)
    return change
