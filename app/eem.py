"""EEM (the Embedded Event Manager): applets that watch for an event on the switch (a
syslog message, a command typed, a fan or temperature alarm, a timer...) and then act
(log a message, send an SNMP trap, run commands), the switch's own system policies, and
the environment variables applets use.

An applet's ``action ... cli`` commands run as the switch's admin, whoever made the
applet (seen on cisco-25gb, NX-OS 9.3(16)). So NXray's broad role denies EEM, and this
page changes EEM only with the stored admin login. The commands an applet may run come
from the fixed menu of ``app/command_menu.py``, never typed: each becomes one ``action
<label> cli <command>`` line (a command of several lines gets labels <n>.1, <n>.2, ...).

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (an applet, an environment variable), each setting the line
it sends with checked values in its blanks, and ``build_change`` building the lines;
``build_eem_change`` turns a picked menu entry into its action lines.
``NxapiClient.configure_eem`` sends them.

Read from the switch: ``show interface brief``, ``show event manager system-policy`` and
``show event manager history events`` in one request, and ``show running-config eem`` as
text (the applets and environment variables as they are set).

Tried on cisco-25gb (2026-11-11) with throwaway applets, removed afterwards: an applet
with ``description``, ``event cli match "<pattern>"``, ``action <n> syslog priority
notifications msg <text>``, ``action <n>.0 cli <command>`` and ``action <n> event-default``;
``no event manager applet <name>``; ``event manager environment <name> "<value>"`` (the
value must be quoted). The other event and action lines are from Cisco's NX-OS 9.3
System Management Configuration Guide and were not tried.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from typing import Any

from app.command_menu import MENU, SHOW_COMMANDS, menu_lines, port_and_channel_names
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
    table_rows,
)
from app.switch import text
from app.track import TRACK_HINT

PAGE_COMMANDS = (
    "show interface brief",
    "show event manager system-policy",
    "show event manager history events",
)
CONFIG_COMMAND = "show running-config eem"
NAME_MAX = 29  # applet and environment variable names
PRIORITIES = (
    "emergencies",
    "alerts",
    "critical",
    "errors",
    "warnings",
    "notifications",
    "informational",
    "debugging",
)
OPS = ("eq", "ge", "gt", "le", "lt", "ne")
HISTORY_ROWS = 10


def _label() -> Field:
    return Field(
        "label",
        "Label",
        "eemlabel",
        hint="Actions run in label order: 1, 2, ... or 1.0, 1.1, ...",
        placeholder="1",
    )


def _event(
    key: str, label: str, line: str, fields: tuple[Field, ...] = (), hint: str = ""
) -> Setting:
    return Setting(
        key=key,
        label=label,
        line=line,
        group="Events",
        fields=fields,
        help=hint,
    )


def _action(
    key: str, label: str, line: str, fields: tuple[Field, ...] = (), **extra: Any
) -> Setting:
    return Setting(
        key=key,
        label=label,
        line=line,
        no_line="no action {label}",
        group="Actions",
        fields=(_label(), *fields),
        **extra,
    )


_SECONDS = Field("seconds", "Seconds", "int", 1, 4294967295)
_TAG = Field(
    "tag",
    "Tag",
    "name",
    maximum=29,
    optional=True,
    hint="Needed when the applet has more than one event",
)

_APPLET = Scope(
    key="applet",
    label="Applets",
    ident=(
        Field("applet", "Applet", "name", maximum=NAME_MAX, hint="A name of your own, up to 29"),
        Field(
            "policy",
            "Overrides system policy",
            "syspolicy",
            optional=True,
            hint="Only to replace one of the switch's system policies (listed below)",
        ),
    ),
    enter=("event manager applet {applet}[ override {policy}]",),
    create=True,
    create_label="Make an applet",
    delete=("no event manager applet {applet}[ override {policy}]",),
    help=(
        "An applet waits for its event, then runs its actions in label order. Its commands "
        "run as the switch's admin. Events that need evmed (Features page): timers and none."
    ),
    settings=(
        Setting(
            key="description",
            label="Description",
            line='description "{text}"',
            no_line="no description",
            group="About",
            fields=(Field("text", "Description", "quoted", maximum=80),),
        ),
        _event(
            "cli",
            "A command is typed",
            'event cli[ tag {tag}] match "{pattern}"[ count {count}][ time {window}]',
            (
                _TAG,
                Field("pattern", "Command (a pattern)", "quoted", maximum=80),
                Field("count", "Times", "int", 1, 65000, optional=True),
                Field("window", "Within (seconds)", "int", 0, 4294967295, optional=True),
            ),
            "Add the default action (Run the command typed) or the switch does not run it.",
        ),
        _event(
            "syslog",
            "A log message",
            'event syslog[ occurs {count}] pattern "{pattern}"',
            (
                Field("count", "Times", "int", 1, 65000, optional=True),
                Field("pattern", "Message (a pattern)", "quoted", maximum=80),
            ),
        ),
        _event(
            "timer",
            "A timer",
            "event timer {kind} time {seconds} name {name}",
            (
                Field("kind", "Kind", "choice", choices=("countdown", "watchdog")),
                _SECONDS,
                Field("name", "Timer name", "name", maximum=29),
            ),
            "countdown: once; watchdog: again and again. Needs evmed.",
        ),
        _event(
            "oir",
            "A part is put in or taken out",
            "event oir {part} {how}",
            (
                Field("part", "Part", "choice", choices=("fan", "module", "powersupply")),
                Field("how", "When", "choice", choices=("anyoir", "insert", "remove")),
            ),
        ),
        _event(
            "temperature",
            "A temperature alarm",
            "event temperature threshold {level}",
            (Field("level", "Alarm", "choice", choices=("any", "major", "minor")),),
        ),
        _event(
            "fan",
            "A fan fails or is missing",
            "event {fault} time {seconds}",
            (
                Field("fault", "Fault", "choice", choices=("fanbad", "fanabsent")),
                Field("seconds", "For (seconds)", "int", 10, 64000),
            ),
        ),
        _event(
            "memory",
            "Memory runs low",
            "event memory {level}",
            (Field("level", "Level", "choice", choices=("minor", "severe", "critical")),),
        ),
        _event(
            "module",
            "A module comes or goes",
            "event module status {status} module all",
            (Field("status", "Status", "choice", choices=("online", "offline", "any")),),
        ),
        _event(
            "track",
            "A tracked object changes",
            "event track {track} state {state}",
            (
                Field("track", "Track object", "int", 1, 500, hint=TRACK_HINT),
                Field("state", "State", "choice", choices=("up", "down", "any")),
            ),
        ),
        _event(
            "counter",
            "A counter crosses a value",
            "event counter name {counter} entry-val {entry} entry-op {op}"
            "[ exit-val {exit} exit-op {exit_op}]",
            (
                Field("counter", "Counter", "name", maximum=28),
                Field("entry", "Value", "int", 0, 2147483647),
                Field("op", "Compared", "choice", choices=OPS),
                Field("exit", "Ends at", "int", 0, 2147483647, optional=True),
                Field("exit_op", "Compared", "choice", choices=OPS, optional=True),
            ),
        ),
        _event("storm", "Storm control acts", "event storm-control"),
        _event(
            "policy_default",
            "The overridden policy's event",
            "event policy-default count {count}[ time {window}]",
            (
                Field("count", "Times", "int", 1, 65000),
                Field("window", "Within (seconds)", "int", 0, 4294967295, optional=True),
            ),
            "For an applet that overrides a system policy.",
        ),
        _event("none", "No event (run by hand)", "event none", (), "Needs evmed."),
        _action(
            "log",
            "Log a message",
            "action {label} syslog[ priority {priority}] msg {msg}",
            (
                Field("priority", "Priority", "choice", choices=PRIORITIES, optional=True),
                Field("msg", "Message", "text", maximum=80),
            ),
        ),
        _action(
            "trap",
            "Send an SNMP trap",
            'action {label} snmp-trap strdata "{data}"',
            (Field("data", "Text", "quoted", maximum=80),),
        ),
        _action(
            "run",
            "Run a command",
            "action {label} cli {command}",
            (
                Field("command", "Command", "choice", choices=MENU),
                Field("port", "Port", "port", optional=True, hint="For a port's commands"),
                Field(
                    "file",
                    "Bootflash file",
                    "flashfile",
                    optional=True,
                    hint="For the copy",
                    placeholder="backup.cfg",
                ),
                Field("show", "Show command", "choice", choices=SHOW_COMMANDS, optional=True),
            ),
            help="A whole-number label: a command of several lines takes <label>.1, .2 and "
            ".3. Remove takes one label away.",
        ),
        _action("default", "Run the command typed", "action {label} event-default"),
        _action(
            "policy_default", "Do what the system policy does", "action {label} policy-default"
        ),
        _action(
            "count",
            "Change a counter",
            "action {label} counter name {counter} value {value} op {op}",
            (
                Field("counter", "Counter", "name", maximum=28),
                Field("value", "Value", "int", 0, 2147483647),
                Field("op", "How", "choice", choices=("inc", "dec", "set", "nop")),
            ),
        ),
        _action(
            "reload",
            "Restart the switch",
            "action {label} reload",
            warning="When the event happens the switch restarts, and every port goes down "
            "for a few minutes.",
        ),
    ),
)

_ENVIRONMENT = Scope(
    key="environment",
    label="Environment variables",
    ident=(Field("name", "Name", "name", maximum=NAME_MAX, hint="Applets use it as $name"),),
    enter=(),
    help="Values applets can use, such as an address to send to.",
    settings=(
        Setting(
            key="value",
            label="Value",
            line='event manager environment {name} "{value}"',
            no_line="no event manager environment {name}",
            ident=("name",),
            group="Value",
            fields=(Field("value", "Value", "quoted", maximum=39),),
        ),
    ),
)


# ---- reading the switch ------------------------------------------------------------------


@dataclass
class Applet:
    """One applet as ``show running-config eem`` prints it."""

    name: str
    policy: str = ""
    lines: list[str] = field(default_factory=list)


_APPLET_HEAD = re.compile(r"^event manager applet (\S+)(?: override (\S+))?\s*$")
_ENV = re.compile(r'^event manager environment (\S+) "(.*)"\s*$')


def parse_eem_config(config: str) -> tuple[list[Applet], list[tuple[str, str]]]:
    """The applets (with their lines) and the environment variables in ``show
    running-config eem``."""
    applets: list[Applet] = []
    variables: list[tuple[str, str]] = []
    current: Applet | None = None
    for raw in config.splitlines():
        if not raw.strip() or raw.startswith("!"):
            continue
        if raw.startswith(" ") and current is not None:
            current.lines.append(raw.strip())
            continue
        current = None
        if head := _APPLET_HEAD.match(raw):
            current = Applet(head.group(1), head.group(2) or "")
            applets.append(current)
        elif env := _ENV.match(raw):
            variables.append((env.group(1), env.group(2)))
    return applets, variables


def parse_history(history: str) -> list[tuple[str, ...]]:
    """The rows of ``show event manager history events`` (ID, date, time, type, slot,
    policies), newest first, the last ``HISTORY_ROWS``."""
    rows = []
    for line in history.splitlines():
        words = line.split()
        if len(words) >= 6 and words[0].isdigit() and re.fullmatch(r"\d\d/\d\d/\d{4}", words[1]):
            rows.append((f"{words[1]} {words[2]}", words[3], " ".join(words[5:])))
    return list(reversed(rows))[:HISTORY_ROWS]


def parse_eem(bodies: list[Any], config: str) -> ProtocolView:
    """The page from ``show event manager system-policy`` and ``... history events`` (the
    second and third bodies of the page's request) and the configuration text."""
    policies = table_rows(bodies[1] if len(bodies) > 1 else None, "TABLE_eem", "ROW_eem")
    history_body = bodies[2] if len(bodies) > 2 else None
    history = text(history_body.get("history-events")) if isinstance(history_body, dict) else ""
    applets, variables = parse_eem_config(config)
    instances: list[Instance] = []
    for applet in applets:
        described = next(
            (
                re.sub(r'^description "?(.*?)"?$', r"\1", line)
                for line in applet.lines
                if line.startswith("description ")
            ),
            "",
        )
        events = [line for line in applet.lines if line.startswith(("event ", "tag "))]
        actions = [line for line in applet.lines if line.startswith("action ")]
        facts = (
            ("Overrides", applet.policy or "-"),
            ("Description", described or "-"),
            ("Event", "; ".join(events) or "none: the applet never runs"),
            ("Actions", "; ".join(actions) or "none"),
        )
        instances.append(
            Instance(
                "applet",
                {"applet": applet.name, "policy": applet.policy},
                applet.name + (f" (overrides {applet.policy})" if applet.policy else ""),
                facts,
                {"description": {"text": described}} if described else {},
            )
        )
    for name, value in variables:
        instances.append(
            Instance(
                "environment",
                {"name": name},
                name,
                (("Value", value),),
                {"value": {"value": value}},
            )
        )
    tables = (
        Table(
            "Recent EEM events",
            ("When", "Type", "Policies"),
            tuple(parse_history(history)),
            empty="The switch lists no EEM events.",
            note=f"The newest {HISTORY_ROWS}; the switch's clock.",
        ),
        Table(
            "System policies",
            ("Name", "What it does", "Can be overridden"),
            tuple(
                (
                    text(row.get("event_name")),
                    text(row.get("event_description")),
                    text(row.get("event_overridable")),
                )
                for row in policies
            ),
            empty="The switch listed no system policies.",
            wrap_column=1,
        ),
    )
    return ProtocolView(tuple(instances), tables)


EEM = Protocol(
    key="eem",
    name="EEM",
    summary="Applets that act when something happens on the switch",
    features=(),
    commands=(),
    parse=lambda bodies: ProtocolView(),
    scopes=(_APPLET, _ENVIRONMENT),
    about=(
        "The Embedded Event Manager watches the switch for an event (a log message, a "
        "command typed, a fan or temperature alarm, a timer) and runs the applet's actions. "
        "Changes need the stored admin login."
    ),
)


@dataclass(frozen=True)
class EemPage:
    """Everything the EEM page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # the front ports and port-channels
    policies: tuple[str, ...]  # the system policies' names
    problem: str = ""
    missing: tuple[str, ...] = ()  # always empty: EEM needs no feature (evmed for some events)


def load_eem_page(client: NxapiClient) -> EemPage:
    """One request for the ports, the system policies and the event history; the
    configuration as text."""
    bodies = client.show(*PAGE_COMMANDS)
    ports = tuple(port_and_channel_names(bodies[0]))
    policies = tuple(
        text(row.get("event_name"))
        for row in table_rows(bodies[1], "TABLE_eem", "ROW_eem")
        if row.get("event_name")
    )
    try:
        config = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError as exc:
        return EemPage(
            EEM,
            parse_eem(bodies, ""),
            ports,
            policies,
            f"The switch did not show its EEM configuration: {exc}",
        )
    return EemPage(EEM, parse_eem(bodies, config), ports, policies)


def build_eem_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the EEM page; a picked command becomes its action lines."""
    change = build_change(EEM, scope, setting, action, ident, values)
    if (scope, setting, action) != ("applet", "run", "set"):
        return change
    run = _APPLET.setting("run")
    if run is None:  # pragma: no cover - defined above
        raise ValueError("the command form is missing")
    checked = {f.name: check_value(f, values.get(f.name, "")) for f in run.fields}
    commands = menu_lines(checked["command"], checked["port"], checked["file"], checked["show"])
    label = checked["label"]
    if len(commands) > 1 and "." in label:
        raise ValueError(
            f"{checked['command']} takes {len(commands)} lines: give a whole-number label, "
            "such as 5, and it uses 5.1 to "
            f"5.{len(commands)}"
        )
    labels = (
        [label] if len(commands) == 1 else [f"{label}.{n}" for n in range(1, len(commands) + 1)]
    )
    lines = tuple(
        f"action {name} cli {command}" for name, command in zip(labels, commands, strict=True)
    )
    enter = change.lines[:-1]
    where = change.describe.split(": set ")[0]
    return dataclasses.replace(
        change,
        lines=(*enter, *lines),
        labels=(*enter, *lines),
        describe=f"{where}: {checked['command']}, as action {', '.join(labels)}.",
    )
