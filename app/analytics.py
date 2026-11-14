"""Flow analytics: the switch's flow telemetry objects (exporters, records, monitors, profiles,
filters and events) and the system settings that tie them together.

``feature analytics`` lets the switch watch flows in hardware. A **record** says what to
match and count in a flow, an **exporter** where the results go, a **monitor** joins a record
to an exporter, a **profile** sets how often the hardware reports, a **filter** limits it to
the traffic an ACL permits, and an **event** names what to report (drops, latency). The
**system** settings name the exporter ID and put a profile, filter or event to work.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``), sent by ``NxapiClient.configure_analytics``. The objects are read
from ``show running-config analytics all`` (text), so an account that may not read the
configuration sees none.

Tried on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-13), the feature already on,
everything removed again, nothing saved. This model is not one the objects do their work on:
a monitor cannot be put on a port (``ip flow monitor`` is "% Invalid command", and the
switch's ingress NetFlow TCAM region is 0), a record keeps only the IPv4 5-tuple, the type of
service, the byte count and the first and last time (the other ``match`` and ``collect`` lines
are taken and not kept), and a monitor's ``exporter`` and the system's ``monitor`` and
``event`` lines were refused. The page still builds and reads the objects, as the switch takes
them:

- ``flow exporter <name>``: ``description``, ``destination <address> [use-vrf <vrf>]``,
  ``dscp <0-63>`` and ``transport udp <1-65535>``.
- ``flow record <name>``: ``description`` and the ``match`` and ``collect`` lines below.
- ``flow monitor <name>``: ``description``, ``record <name>`` and ``exporter-bucket-id <id>
  <low> <high>``.
- ``flow profile <name>``: ``collect interval 100|1000|2000`` (milliseconds) and ``source
  port <1-65535>``.
- ``flow filter <name>``: ``ipv4`` or ``ipv6`` with the name of an ACL that already exists.
- ``flow event <name>``: ``description`` and ``group drop-events`` or ``group
  latency-events``.
- ``flow system config``: ``exporter-id <0-4095>``, and ``profile``, ``filter`` and ``event``
  by name. The ``no`` form of the exporter ID needs the value that is set.
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
    build_change,
)
from app.switch_admin import vrf_choices

FEATURE = "analytics"
PAGE_COMMANDS = ("show feature", "show vrf")
CONFIG_COMMAND = "show running-config analytics all"


def _name(label: str = "Name") -> Field:
    return Field("name", label, "name", hint="Letters, digits, - and _")


def _description() -> Setting:
    return Setting(
        "description",
        "Description",
        "description {text}",
        (Field("text", "Description", "text", maximum=100),),
        no_line="no description",
        group="Description",
    )


def _objects(key: str, label: str, noun: str, settings: tuple[Setting, ...], help_text: str):
    return Scope(
        key=key,
        label=label,
        ident=(_name(),),
        enter=(f"flow {noun} {{name}}",),
        create=True,
        create_label=f"Make {label[0].lower()}{label[1:]}",
        delete=(f"no flow {noun} {{name}}",),
        settings=settings,
        help=help_text,
    )


_EXPORTER = _objects(
    "exporter",
    "Exporter",
    "exporter",
    (
        _description(),
        Setting(
            "destination",
            "Destination",
            "destination {address}[ use-vrf {vrf}]",
            (
                Field("address", "Collector address", "ip"),
                Field("vrf", "VRF", "usevrf", hint="The VRF the collector is reached in"),
            ),
            no_line="no destination",
            group="Collector",
        ),
        Setting(
            "dscp",
            "DSCP",
            "dscp {dscp}",
            (Field("dscp", "DSCP", "int", 0, 63),),
            no_line="no dscp",
            group="Collector",
        ),
        Setting(
            "transport",
            "UDP port",
            "transport udp {port}",
            (Field("port", "Port", "int", 1, 65535),),
            no_line="no transport udp",
            group="Collector",
        ),
    ),
    "Where flow results are sent: a collector's address and UDP port.",
)

# The record lines: (setting key, label, line). The switch takes every one of these and keeps
# only the IPv4 ones (see the module's note).
_RECORD_LINES = (
    ("match_src", "Match source address", "match ip source address"),
    ("match_dst", "Match destination address", "match ip destination address"),
    ("match_proto", "Match protocol", "match ip protocol"),
    ("match_tos", "Match type of service", "match ip tos"),
    ("match_sport", "Match source port", "match transport source-port"),
    ("match_dport", "Match destination port", "match transport destination-port"),
    ("count_bytes", "Count bytes", "collect counter bytes"),
    ("time_first", "Note the time of the first packet", "collect timestamp sys-uptime first"),
    ("time_last", "Note the time of the last packet", "collect timestamp sys-uptime last"),
)

_RECORD = _objects(
    "record",
    "Record",
    "record",
    (
        _description(),
        *(
            Setting(key, label, line, group="Match" if line.startswith("match") else "Collect")
            for key, label, line in _RECORD_LINES
        ),
    ),
    "What the switch matches in a flow and counts. Set puts a line in the record, Remove takes "
    "it out.",
)

_MONITOR = _objects(
    "monitor",
    "Monitor",
    "monitor",
    (
        _description(),
        Setting(
            "record",
            "Record",
            "record {record}",
            (Field("record", "Record", "name", hint="A record made on this page"),),
            group="Parts",
        ),
        Setting(
            "bucket",
            "Exporter bucket",
            "exporter-bucket-id {bucket} {low} {high}",
            (
                Field("bucket", "Bucket ID", "int", 0, 65535),
                Field("low", "Hash from", "int", 0, 65535),
                Field("high", "Hash to", "int", 0, 65535),
            ),
            group="Parts",
        ),
    ),
    "Joins a record to an exporter. A monitor works on a port only where the switch supports it.",
)

_PROFILE = _objects(
    "profile",
    "Profile",
    "profile",
    (
        Setting(
            "interval",
            "Report every",
            "collect interval {interval}",
            (Field("interval", "Milliseconds", "choice", choices=("100", "1000", "2000")),),
            group="Reporting",
        ),
        Setting(
            "port",
            "Source UDP port",
            "source port {port}",
            (Field("port", "Port", "int", 1, 65535),),
            group="Reporting",
        ),
    ),
    "How often the hardware reports, and from which UDP port.",
)

_FILTER = _objects(
    "filter",
    "Filter",
    "filter",
    (
        Setting(
            "ipv4",
            "IPv4 ACL",
            "ipv4 {acl}",
            (Field("acl", "ACL", "name", hint="An ACL that exists on the switch"),),
            group="Traffic",
        ),
        Setting(
            "ipv6",
            "IPv6 ACL",
            "ipv6 {acl}",
            (Field("acl", "ACL", "name", hint="An ACL that exists on the switch"),),
            group="Traffic",
        ),
    ),
    "Limits flow telemetry to the traffic an ACL permits.",
)

_EVENT = _objects(
    "event",
    "Event",
    "event",
    (
        _description(),
        Setting("drops", "Report drops", "group drop-events", group="Events"),
        Setting("latency", "Report latency", "group latency-events", group="Events"),
    ),
    "What the hardware reports on: dropped packets, latency.",
)

_SYSTEM = Scope(
    key="system",
    label="System",
    ident=(),
    enter=("flow system config",),
    help="Ties the objects together for the whole switch. Remove takes a setting out.",
    settings=(
        Setting(
            "exporter_id",
            "Exporter ID",
            "exporter-id {id}",
            (Field("id", "ID", "int", 0, 4095, hint="Remove needs the ID that is set"),),
            group="System",
        ),
        Setting(
            "profile",
            "Profile in use",
            "profile {name}",
            (Field("name", "Profile", "name"),),
            group="In use",
        ),
        Setting(
            "filter",
            "Filter in use",
            "filter {name}",
            (Field("name", "Filter", "name"),),
            group="In use",
        ),
        Setting(
            "event",
            "Event in use",
            "event {name}",
            (Field("name", "Event", "name"),),
            group="In use",
        ),
    ),
)

SCOPES = (_EXPORTER, _RECORD, _MONITOR, _PROFILE, _FILTER, _EVENT, _SYSTEM)

# ---- reading ---------------------------------------------------------------------

_HEADS = {
    "exporter": re.compile(r"flow exporter (\S+)"),
    "record": re.compile(r"flow record (\S+)"),
    "monitor": re.compile(r"flow monitor (\S+)"),
    "profile": re.compile(r"flow profile (\S+)"),
    "filter": re.compile(r"flow filter (\S+)"),
    "event": re.compile(r"flow event (\S+)"),
}
_SYSTEM_HEAD = "flow system config"
_LINES = {
    "exporter": (
        (re.compile(r"description (.*)"), "description", ("text",)),
        (re.compile(r"destination (\S+)(?: use-vrf (\S+))?"), "destination", ("address", "vrf")),
        (re.compile(r"dscp (\d+)"), "dscp", ("dscp",)),
        (re.compile(r"transport udp (\d+)"), "transport", ("port",)),
    ),
    "record": (
        (re.compile(r"description (.*)"), "description", ("text",)),
        *((re.compile(re.escape(line)), key, ()) for key, _, line in _RECORD_LINES),
    ),
    "monitor": (
        (re.compile(r"description (.*)"), "description", ("text",)),
        (re.compile(r"record (\S+)"), "record", ("record",)),
        (
            re.compile(r"exporter-bucket-id (\d+) (\d+) (\d+)"),
            "bucket",
            ("bucket", "low", "high"),
        ),
    ),
    "profile": (
        (re.compile(r"collect interval (\d+)"), "interval", ("interval",)),
        (re.compile(r"source port (\d+)"), "port", ("port",)),
    ),
    "filter": (
        (re.compile(r"ipv4 (\S+)"), "ipv4", ("acl",)),
        (re.compile(r"ipv6 (\S+)"), "ipv6", ("acl",)),
    ),
    "event": (
        (re.compile(r"description (.*)"), "description", ("text",)),
        (re.compile(r"group drop-events"), "drops", ()),
        (re.compile(r"group latency-events"), "latency", ()),
    ),
    "system": (
        (re.compile(r"exporter-id (\d+)"), "exporter_id", ("id",)),
        (re.compile(r"profile (\S+)"), "profile", ("name",)),
        (re.compile(r"filter (\S+)"), "filter", ("name",)),
        (re.compile(r"event (\S+)"), "event", ("name",)),
    ),
}


def parse_analytics_config(config: str) -> dict[str, list[tuple[str, dict[str, dict[str, str]]]]]:
    """The flow objects of ``show running-config analytics all``: for each scope, its objects
    as (name, setting values by setting key). ``system`` has the one object, named "".

    A setting with no fields (a record's ``match ip tos``) has an empty values dict: the
    line is there.
    """
    found: dict[str, list[tuple[str, dict[str, dict[str, str]]]]] = {k: [] for k in _LINES}
    scope = ""
    values: dict[str, dict[str, str]] = {}
    for raw in config.splitlines():
        line = raw.strip()
        if not line or line.startswith("!"):
            continue
        if not raw[:1].isspace():
            scope = ""
            if line == _SYSTEM_HEAD:
                scope, values = "system", {}
                found["system"].append(("", values))
                continue
            for key, head in _HEADS.items():
                if match := head.fullmatch(line):
                    scope, values = key, {}
                    found[key].append((match.group(1), values))
                    break
            continue
        if not scope:
            continue
        for pattern, setting, names in _LINES[scope]:
            if match := pattern.fullmatch(line):
                values[setting] = {
                    name: group or "" for name, group in zip(names, match.groups(), strict=False)
                }
                break
    return found


def parse_analytics(config: str | None) -> ProtocolView:
    """The page from ``show running-config analytics all`` (None: not read)."""
    if config is None:
        return ProtocolView(
            (),
            (),
            (
                "The switch did not show its configuration to NXray's account: the flow "
                "objects are not shown.",
            ),
        )
    found = parse_analytics_config(config)
    instances = []
    for scope in SCOPES:
        for name, values in found[scope.key]:
            instances.append(
                Instance(
                    scope.key,
                    {"name": name} if scope.ident else {},
                    f"{scope.label} {name}" if name else scope.label,
                    (),
                    values,
                )
            )
    return ProtocolView(tuple(instances))


ANALYTICS = Protocol(
    key="analytics",
    name="Flow analytics",
    summary="Flow telemetry objects: exporters, records, monitors, profiles, filters, events",
    features=(FEATURE,),
    commands=(),
    parse=lambda bodies: parse_analytics(None),
    scopes=SCOPES,
    about=(
        "The switch's hardware can watch flows and report them to a collector. Make a record "
        "of what to count, an exporter for where to send it, and a monitor that joins them."
    ),
)


@dataclass(frozen=True)
class AnalyticsPage:
    """Everything the Flow analytics page shows."""

    protocol: Protocol
    view: ProtocolView
    vrfs: tuple[str, ...]  # default, management, then the others
    problem: str = ""
    missing: tuple[str, ...] = ()  # the feature, when it is off


def load_analytics_page(client: NxapiClient) -> AnalyticsPage:
    """``show feature`` and ``show vrf``; while the feature is on, the configuration text."""
    feature, vrf_body = client.show(*PAGE_COMMANDS)
    vrfs = vrf_choices(vrf_body)
    if not feature_states(feature).get(FEATURE, False):
        return AnalyticsPage(ANALYTICS, ProtocolView(), vrfs, missing=(FEATURE,))
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = None
    return AnalyticsPage(ANALYTICS, parse_analytics(config), vrfs)


def check_analytics_place(page: AnalyticsPage, ident: dict[str, str]) -> None:
    """Every identity is a name the user makes: nothing to check."""


def build_analytics_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Flow analytics page."""
    return build_change(ANALYTICS, scope, setting, action, ident, values)
