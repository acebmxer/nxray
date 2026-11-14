"""The switch's programming interfaces: gRPC, NETCONF, RESTCONF, NX-SDK, Container Tracker and
OpenFlow. What each is doing, and the few settings the switch has for them.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): one scope per interface, each setting the one line it sends with
checked values in its blanks. ``NxapiClient.configure_programmability`` sends them. A
feature is turned on and off on the Features page; an interface whose feature is off shows
only a note saying so.

Read from the switch: ``show feature`` first; then, for the features that are on, ``show
running-config`` (text, for the values set), ``show grpc gnmi service statistics`` (gRPC),
``show nxsdk internal service`` (NX-SDK) and ``show openflow switch 1`` (OpenFlow).

Tried on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-13), each feature turned on and
off again, nothing saved:

- gRPC: ``grpc port <1024-65535>``, ``grpc gnmi max-concurrent-calls <1-16>`` and ``grpc
  certificate <name>``, each with a ``no`` form that names the value (a bare ``no grpc
  port`` is "% Incomplete command"). ``grpc use-vrf`` is "% Invalid command", so no VRF
  setting is offered. The certificate need not exist when typed. ``show grpc gnmi service
  statistics`` prints the endpoint (VRF, address, certificate dates, call counts).
- NETCONF: ``netconf sessions <1-10>`` and ``netconf idle-timeout <0-1440>`` (minutes) with
  their ``no`` forms. ``netconf ssh port`` is "% Invalid command", and no ``show netconf``
  command exists, so the page shows only the lines set.
- RESTCONF: ``feature restconf`` only; ``restconf port`` and ``restconf idle-timeout`` are
  "% Invalid command", and ``show restconf`` is "% Incomplete command".
- NX-SDK: ``feature nxsdk`` (``show feature`` calls it nxsdk_mgr); ``nxsdk service-name
  <name>`` (at most 20 characters) is refused with "Service <name> not found" unless an
  application of that name is installed, which NXray cannot do. ``show nxsdk internal
  service`` prints how many services run and the application path.
- Container Tracker: ``feature container-tracker`` turns on, but the switch has no
  ``container-tracker`` command and no ``show container-tracker``: the page shows the
  feature's state only.
- OpenFlow: ``feature openflow`` turns on, and ``openflow`` is accepted, but ``switch 1
  pipeline 201`` is refused ("OpenFlow Switch submode configuration command failed") because
  the 92160YC-X has no OpenFlow TCAM region, which needs a TCAM carve and a restart. NXray
  shows the state only; it does not carve TCAM.
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

GRPC = "grpc"
NETCONF = "netconf"
RESTCONF = "restconf"
NXSDK = "nxsdk_mgr"  # as show feature names it; the command is feature nxsdk
CONTAINER_TRACKER = "container-tracker"
OPENFLOW = "openflow"

CONFIG_COMMAND = "show running-config"
GRPC_COMMAND = "show grpc gnmi service statistics"
NXSDK_COMMAND = "show nxsdk internal service"
OPENFLOW_COMMAND = "show openflow switch 1"

NXSDK_NAME_MAX = 20

# Each interface: its scope key, its feature as show feature names it, what to call it.
INTERFACES = (
    ("grpc", GRPC, "gRPC"),
    ("netconf", NETCONF, "NETCONF"),
    ("restconf", RESTCONF, "RESTCONF"),
    ("nxsdk", NXSDK, "NX-SDK"),
    ("container_tracker", CONTAINER_TRACKER, "Container Tracker"),
    ("openflow", OPENFLOW, "OpenFlow"),
)


def _service_name(values: dict[str, str]) -> None:
    if len(values.get("name", "")) > NXSDK_NAME_MAX:
        raise ValueError(f"the service name is at most {NXSDK_NAME_MAX} characters")


_GRPC = Scope(
    key="grpc",
    label="gRPC",
    ident=(),
    enter=(),
    help="The gRPC server (gNMI): the port it listens on and its certificate. Remove puts a "
    "setting back to its default.",
    settings=(
        Setting(
            "port",
            "Port",
            "grpc port {port}",
            (Field("port", "Port", "int", 1024, 65535, hint="Default 50051"),),
            group="Server",
        ),
        Setting(
            "max_calls",
            "Calls at once",
            "grpc gnmi max-concurrent-calls {calls}",
            (Field("calls", "Calls", "int", 1, 16, hint="Default 8"),),
            group="Server",
            help="How many gNMI calls the server answers at once.",
        ),
        Setting(
            "certificate",
            "Certificate",
            "grpc certificate {name}",
            (
                Field(
                    "name",
                    "Trustpoint",
                    "name",
                    hint="A trustpoint made on the SSH and certificates page",
                ),
            ),
            group="Server",
            help="Without one the switch makes its own short-lived certificate.",
        ),
    ),
)

_NETCONF = Scope(
    key="netconf",
    label="NETCONF",
    ident=(),
    enter=(),
    help="The NETCONF server. Remove puts a setting back to its default.",
    settings=(
        Setting(
            "sessions",
            "Sessions at once",
            "netconf sessions {sessions}",
            (Field("sessions", "Sessions", "int", 1, 10),),
            group="Server",
        ),
        Setting(
            "idle_timeout",
            "Idle time",
            "netconf idle-timeout {minutes}",
            (Field("minutes", "Minutes", "int", 0, 1440, hint="0: never closes an idle session"),),
            group="Server",
        ),
    ),
)

_RESTCONF = Scope(
    key="restconf",
    label="RESTCONF",
    ident=(),
    enter=(),
    help="RESTCONF has no setting of its own on this switch: it answers on NX-API's web server.",
)

_NXSDK = Scope(
    key="nxsdk",
    label="NX-SDK",
    ident=(),
    enter=(),
    help="NX-SDK runs applications you wrote on the switch.",
    settings=(
        Setting(
            "service",
            "Application service",
            "nxsdk service-name {name}",
            (
                Field(
                    "name",
                    "Service name",
                    "name",
                    hint=f"At most {NXSDK_NAME_MAX} characters; the application must be installed",
                ),
            ),
            group="Applications",
            check=_service_name,
            help="Starts an application the switch has installed. NXray cannot install one.",
        ),
    ),
)

_CONTAINER_TRACKER = Scope(
    key="container_tracker",
    label="Container Tracker",
    ident=(),
    enter=(),
    help="Container Tracker has no command of its own on this switch beyond its feature.",
)

_OPENFLOW = Scope(
    key="openflow",
    label="OpenFlow",
    ident=(),
    enter=(),
    help="The OpenFlow agent. NXray shows its state; it does not set it up.",
)

SCOPES = (_GRPC, _NETCONF, _RESTCONF, _NXSDK, _CONTAINER_TRACKER, _OPENFLOW)

_ON_ONLY = {
    "restconf": "On. It uses NX-API's web server and has no setting of its own.",
    "container_tracker": "On. The switch has no setting or status command for it.",
}


def parse_facts(output: str | None) -> tuple[tuple[str, str], ...]:
    """The ``Name : value`` lines of a command's text as (name, value) pairs; lines of
    another shape are left out."""
    facts = []
    for line in (output or "").splitlines():
        if match := re.fullmatch(r"\s*([^:=\s][^:]*?)\s*:\s*(\S.*?)\s*", line):
            facts.append((match.group(1), match.group(2)))
    return tuple(facts)


def parse_programmability_config(config: str) -> dict[str, dict[str, dict[str, str]]]:
    """The top-level ``grpc``, ``netconf`` and ``nxsdk`` lines of ``show running-config``, as
    setting values by scope."""
    values: dict[str, dict[str, dict[str, str]]] = {"grpc": {}, "netconf": {}, "nxsdk": {}}
    for raw in config.splitlines():
        if raw[:1].isspace():
            continue
        line = raw.strip()
        if match := re.fullmatch(r"grpc port (\d+)", line):
            values["grpc"]["port"] = {"port": match.group(1)}
        elif match := re.fullmatch(r"grpc gnmi max-concurrent-calls (\d+)", line):
            values["grpc"]["max_calls"] = {"calls": match.group(1)}
        elif match := re.fullmatch(r"grpc certificate (\S+)", line):
            values["grpc"]["certificate"] = {"name": match.group(1)}
        elif match := re.fullmatch(r"netconf sessions (\d+)", line):
            values["netconf"]["sessions"] = {"sessions": match.group(1)}
        elif match := re.fullmatch(r"netconf idle-timeout (\d+)", line):
            values["netconf"]["idle_timeout"] = {"minutes": match.group(1)}
        elif match := re.fullmatch(r"nxsdk service-name (\S+)", line):
            values["nxsdk"]["service"] = {"name": match.group(1)}
    return values


def parse_programmability(
    states: dict[str, bool],
    config: str | None = None,
    grpc: str | None = None,
    nxsdk: str | None = None,
    openflow: str | None = None,
) -> ProtocolView:
    """The page from the feature states and the text of each read (None: not read, as
    while its feature is off or the account may not read it)."""
    values = parse_programmability_config(config or "")
    facts_of = {
        "grpc": parse_facts(grpc),
        "nxsdk": parse_facts(nxsdk),
        "openflow": (
            (("State", openflow.strip().splitlines()[0]),) if (openflow or "").strip() else ()
        ),
    }
    instances = []
    off = []
    for scope, feature, label in INTERFACES:
        if not states.get(feature, False):
            off.append(label)
            continue
        facts = facts_of.get(scope) or (("State", _ON_ONLY.get(scope, "On")),)
        instances.append(Instance(scope, {}, label, facts, values.get(scope, {})))
    notes = []
    if off:
        notes.append(
            f"Off on the switch: {', '.join(off)}. An NXray admin turns a feature on on the "
            "Features page; its settings then appear here."
        )
    if config is None and any(states.get(f, False) for f in (GRPC, NETCONF, NXSDK)):
        notes.append(
            "The switch did not show its configuration to NXray's account: the values set "
            "are not shown."
        )
    tables = (
        Table(
            "Interfaces",
            ("Interface", "State"),
            tuple(
                (label, "on" if states.get(feature, False) else "off")
                for _, feature, label in INTERFACES
            ),
        ),
    )
    return ProtocolView(tuple(instances), tables, tuple(notes))


PROGRAMMABILITY = Protocol(
    key="programmability",
    name="Programmability",
    summary="gRPC, NETCONF, RESTCONF, NX-SDK, Container Tracker and OpenFlow",
    features=(),
    commands=(),
    parse=lambda bodies: parse_programmability({}),
    scopes=SCOPES,
    about=(
        "The ways a program can talk to the switch besides NX-API. Turning a feature on opens "
        "another way in, so each is off until an NXray admin turns it on on the Features page."
    ),
)


@dataclass(frozen=True)
class ProgrammabilityPage:
    """Everything the Programmability page shows."""

    protocol: Protocol
    view: ProtocolView
    problem: str = ""
    missing: tuple[str, ...] = ()  # always empty: each interface is shown or noted on its own
    # The scopes whose card is shown: those whose feature is on. The switch refuses an
    # interface's lines while its feature is off, so no form is offered for it.
    shown_scopes: tuple[Scope, ...] = ()


def _text(client: NxapiClient, command: str) -> str | None:
    try:
        return client.show_text(command)
    except NxapiCommandError:
        return None


def load_programmability_page(client: NxapiClient) -> ProgrammabilityPage:
    """``show feature``; for each feature that is on, its text reads."""
    (feature,) = client.show("show feature")
    states = feature_states(feature)
    on = {name for _, name, _ in INTERFACES if states.get(name, False)}
    config = _text(client, CONFIG_COMMAND) if on & {GRPC, NETCONF, NXSDK} else None
    view = parse_programmability(
        states,
        config,
        _text(client, GRPC_COMMAND) if GRPC in on else None,
        _text(client, NXSDK_COMMAND) if NXSDK in on else None,
        _text(client, OPENFLOW_COMMAND) if OPENFLOW in on else None,
    )
    shown = tuple(
        scope
        for scope in SCOPES
        if any(key == scope.key and states.get(feature, False) for key, feature, _ in INTERFACES)
    )
    return ProgrammabilityPage(PROGRAMMABILITY, view, shown_scopes=shown)


def check_programmability_place(page: ProgrammabilityPage, ident: dict[str, str]) -> None:
    """Every scope is the whole switch: nothing to check."""


def build_programmability_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Programmability page."""
    return build_change(PROGRAMMABILITY, scope, setting, action, ident, values)
