"""The TWAMP server: the switch answering Two-Way Active Measurement Protocol tests.

TWAMP (RFC 5357) lets another device measure delay, jitter and loss to this switch. The
switch is the server and reflector; it starts only while ``feature sla twamp-server`` is on
(the Features page). The page shows the server's state and the lines set, and changes them
with the same parts as the Monitor sessions page (``app/protocols.py``), sent by
``NxapiClient.configure_twamp``.

Read from the switch: ``show feature``; then, while the feature is on, ``show ip sla twamp
session`` (text), ``show ip sla twamp standards`` (text) and ``show running-config | section
twamp`` (text, for the lines set).

Tried on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-13), the feature already on,
everything put back, nothing saved:

- ``ip sla server twamp`` opens the server's settings and, by being typed alone, is stored in
  the configuration. Inside it: ``port <1-65535>`` (862, the standard port, is the default
  and is not stored) and ``timer inactivity <1-6000>`` (seconds before an idle connection is
  closed). ``no port`` and ``no timer inactivity`` put them back, with or without a value.
- ``ip sla responder twamp`` is taken and stored; its ``no`` form removes it. The switch
  printed "IP SLAs Responder TWAMP is: Disabled" for ``show ip sla twamp session`` whether it
  was typed or not, so the page shows that text as the switch prints it.
- ``show ip sla twamp connection`` and ``show ip sla twamp-server`` are "% Invalid command".
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.features import feature_states
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

FEATURE = "sla_twamp"  # as show feature names it; the command is feature sla twamp-server
SESSION_COMMAND = "show ip sla twamp session"
STANDARDS_COMMAND = "show ip sla twamp standards"
CONFIG_COMMAND = "show running-config | section twamp"

_SERVER = Scope(
    key="server",
    label="TWAMP server",
    ident=(),
    enter=("ip sla server twamp",),
    help="Remove puts a setting back to its default.",
    settings=(
        Setting(
            "port",
            "Port",
            "port {port}",
            (Field("port", "Port", "int", 1, 65535, hint="Default 862"),),
            no_line="no port",
            group="Server",
        ),
        Setting(
            "inactivity",
            "Idle time",
            "timer inactivity {seconds}",
            (Field("seconds", "Seconds", "int", 1, 6000, hint="Until an idle connection closes"),),
            no_line="no timer inactivity",
            group="Server",
        ),
    ),
)

_RESPONDER = Scope(
    key="responder",
    label="TWAMP responder",
    ident=(),
    enter=(),
    help="The line that turns the responder on. Remove takes it out of the configuration.",
    settings=(
        Setting(
            "enabled",
            "Responder",
            "ip sla responder twamp",
            group="Responder",
            help="Set puts the line in the configuration, Remove takes it out.",
        ),
    ),
)

SCOPES = (_SERVER, _RESPONDER)


def parse_twamp_config(config: str) -> dict[str, dict[str, dict[str, str]]]:
    """``ip sla server twamp`` with its lines and ``ip sla responder twamp``, as setting
    values by scope; ``responder`` is {"enabled": {}} while its line is there."""
    values: dict[str, dict[str, dict[str, str]]] = {"server": {}, "responder": {}}
    inside = False
    for raw in config.splitlines():
        line = raw.strip()
        if not raw[:1].isspace():
            inside = line == "ip sla server twamp"
            if line == "ip sla responder twamp":
                values["responder"]["enabled"] = {}
            continue
        if not inside:
            continue
        if match := re.fullmatch(r"port (\d+)", line):
            values["server"]["port"] = {"port": match.group(1)}
        elif match := re.fullmatch(r"timer inactivity (\d+)", line):
            values["server"]["inactivity"] = {"seconds": match.group(1)}
    return values


def parse_standards(output: str | None) -> tuple[tuple[str, ...], ...]:
    """The rows of ``show ip sla twamp standards``: feature, organization, standard."""
    rows = []
    for line in (output or "").splitlines():
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) == 3 and parts[0] != "Feature" and not set(parts[0]) <= {"-", "="}:
            rows.append(tuple(parts))
    return tuple(rows)


def parse_twamp(
    config: str | None, session: str | None = None, standards: str | None = None
) -> ProtocolView:
    """The page from the text of each read (None: not read, as when the account may not)."""
    values = parse_twamp_config(config or "")
    status = " ".join((session or "").split())
    server_facts = (("State", status),) if status else ()
    responder_facts = (
        ("Responder line", "in the configuration" if values["responder"] else "not set"),
    )
    instances = (
        Instance("server", {}, "TWAMP server", server_facts, values["server"]),
        Instance("responder", {}, "TWAMP responder", responder_facts, values["responder"]),
    )
    notes = []
    if config is None:
        notes.append(
            "The switch did not show its configuration to NXray's account: the values set "
            "are not shown."
        )
    rows = parse_standards(standards)
    tables = (Table("Standards", ("Feature", "Organization", "Standard"), rows),) if rows else ()
    return ProtocolView(instances, tables, tuple(notes))


TWAMP = Protocol(
    key="twamp",
    name="TWAMP server",
    summary="Answer Two-Way Active Measurement Protocol tests from other devices",
    features=(FEATURE,),
    commands=(),
    parse=lambda bodies: parse_twamp(None),
    scopes=SCOPES,
    about=(
        "TWAMP measures delay, jitter and loss between two devices. The switch answers the "
        "tests another device starts; to measure from the switch, use IP SLA."
    ),
)


@dataclass(frozen=True)
class TwampPage:
    """Everything the TWAMP server page shows."""

    protocol: Protocol
    view: ProtocolView
    problem: str = ""
    missing: tuple[str, ...] = ()  # the feature, when it is off


def _text(client: NxapiClient, command: str) -> str | None:
    try:
        return client.show_text(command)
    except NxapiCommandError:
        return None


def load_twamp_page(client: NxapiClient) -> TwampPage:
    """``show feature``; while the feature is on, the three text reads."""
    (feature,) = client.show("show feature")
    if not feature_states(feature).get(FEATURE, False):
        return TwampPage(TWAMP, ProtocolView(), missing=(FEATURE,))
    view = parse_twamp(
        _text(client, CONFIG_COMMAND),
        _text(client, SESSION_COMMAND),
        _text(client, STANDARDS_COMMAND),
    )
    return TwampPage(TWAMP, view)


def check_twamp_place(page: TwampPage, ident: dict[str, str]) -> None:
    """Every scope is the whole switch: nothing to check."""


def build_twamp_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the TWAMP server page."""
    return build_change(TWAMP, scope, setting, action, ident, values)
