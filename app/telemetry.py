"""Streaming telemetry: the switch pushes its own data (interface counters, BGP state, the
output of show commands) to a collector on a timer or when something changes.

Three kinds of group make it up, all typed inside ``telemetry``: a destination group (the
collectors' addresses, ports, protocol and encoding), a sensor group (what to send: paths
into the switch's data, with a data source) and a subscription (which sensor groups go to
which destination groups, and how often). The destination profile holds settings for
every collector (the VRF, compression, the source interface).

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): one scope per kind, each setting the one configuration line it
sends with checked values in its blanks, and ``build_change`` building the lines.
``NxapiClient.configure_telemetry`` sends them.

Read from the switch: ``show feature`` and ``show vrf`` in one request; while ``feature
telemetry`` is on, ``show telemetry transport``, ``show telemetry control database
sensor-groups`` and ``show telemetry data collector brief`` in one request (JSON), and
``show running-config`` as text for every group and its lines (the role's ``show
running-config`` rule, rule 170, as the Tunnels page uses; the destination profile has no
show command of its own). Without the text the page shows the collectors and sensor groups
from the JSON, with empty forms.

Tried on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-12) with throwaway groups and
documentation addresses, all removed and the feature turned back off afterwards:

* ``destination-profile`` with ``use-vrf``, ``use-compression gzip``, ``source-interface``,
  ``use-retry size`` 10-1500 and ``use-nodeid``, with their ``no`` forms;
* ``destination-group N`` with ``ip address A port P protocol gRPC|HTTP|UDP encoding
  GPB|JSON`` (gRPC takes GPB only, HTTP JSON only: the switch refuses the others),
  ``ipv6 address ...`` and ``use-vrf``; ``no ip address A port P`` removes one;
* ``sensor-group N`` with ``data-source DME|NX-API|YANG|NATIVE`` (refused when it does not
  fit the paths already there) and ``path P [depth 0-32|unbounded] [query-condition Q]
  [filter-condition F]``; an NX-API path is a show command in double quotes; ``no path
  P`` removes one;
* ``subscription N`` with ``dst-grp N`` and ``snsr-grp N sample-interval MS`` (0 sends on
  change, otherwise 1000 to 604800000 ms), with their ``no`` forms;
* ``no destination-group N``, ``no sensor-group N``, ``no subscription N``.

A collector's TLS certificate (``certificate``) is not offered: it needs a file on the
switch's bootflash.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

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
from app.switch import rows, text
from app.switch_admin import vrf_choices

FEATURE = "telemetry"
PAGE_COMMANDS = ("show feature", "show vrf")
COMMANDS = (
    "show telemetry transport",
    "show telemetry control database sensor-groups",
    "show telemetry data collector brief",
)
CONFIG_COMMAND = "show running-config"
GROUP_MAX = 4294967295
PROTOCOLS = ("gRPC", "HTTP", "UDP")
ENCODINGS = ("GPB", "JSON")
# What each protocol may carry, as the switch answered: "Telemetry transport protocol
# HTTP does not support GPB encoding" and "... gRPC does not support JSON encoding".
ENCODINGS_FOR = {"gRPC": ("GPB",), "HTTP": ("JSON",), "UDP": ("GPB", "JSON")}
DATA_SOURCES = ("DME", "NX-API", "YANG", "NATIVE")
DEPTHS = (*(str(n) for n in range(0, 33)), "unbounded")
SAMPLE_MIN, SAMPLE_MAX = 1000, 604_800_000
RETRY_MIN, RETRY_MAX = 10, 1500
# Characters that would turn a show command into something else: a pipe into another
# command, or a redirect into a file.
_SHOW_FORBIDDEN = re.compile(r"[|<>]")


def _group_field(name: str, label: str) -> Field:
    return Field(
        name,
        label,
        "int",
        minimum=1,
        maximum=GROUP_MAX,
        hint=f"A number of your own, 1 to {GROUP_MAX}",
        placeholder="1",
    )


def _check_vrf(values: dict[str, str]) -> None:
    if not values.get("vrf"):
        raise ValueError("The default VRF is used when none is set: use Remove instead")


def _check_encoding(values: dict[str, str]) -> None:
    protocol, encoding = values.get("protocol", ""), values.get("encoding", "")
    allowed = ENCODINGS_FOR.get(protocol, ENCODINGS)
    if encoding not in allowed:
        raise ValueError(f"{protocol} carries {' or '.join(allowed)} only")


def _check_sample(values: dict[str, str]) -> None:
    sample = int(values.get("ms", "0"))
    if 0 < sample < SAMPLE_MIN:
        raise ValueError(
            f"The interval is 0 (send on every change) or {SAMPLE_MIN} to {SAMPLE_MAX} ms"
        )


def _check_show(values: dict[str, str]) -> None:
    command = values.get("command", "")
    if not command.startswith("show ") or _SHOW_FORBIDDEN.search(command):
        raise ValueError(
            'The command is one show command, such as "show version", without |, < or >'
        )


def _destination(key: str, label: str, word: str, kind: str, example: str) -> Setting:
    return Setting(
        key=key,
        label=label,
        line=f"{word} {{address}} port {{port}} protocol {{protocol}} encoding {{encoding}}",
        no_line=f"no {word} {{address}} port {{port}}",
        group="Collectors",
        fields=(
            Field("address", "Address", kind, placeholder=example),
            Field("port", "Port", "int", minimum=1, maximum=65535, placeholder="50051"),
            Field(
                "protocol",
                "Protocol",
                "choice",
                choices=PROTOCOLS,
                hint="gRPC carries GPB, HTTP carries JSON, UDP either",
            ),
            Field("encoding", "Encoding", "choice", choices=ENCODINGS),
        ),
        check=_check_encoding,
        help="Set adds a collector; a group can have several. Remove needs the address and port.",
    )


_PROFILE = Scope(
    key="profile",
    label="Destination profile",
    ident=(),
    enter=("telemetry", "destination-profile"),
    help="Settings for every collector the switch sends to.",
    settings=(
        Setting(
            key="use_vrf",
            label="VRF",
            line="use-vrf {vrf}",
            no_line="no use-vrf {vrf}",
            group="Profile",
            fields=(Field("vrf", "VRF", "usevrf", hint="Where the collectors are reached"),),
            check=_check_vrf,
            help="Without it the default VRF is used. A destination group's own VRF wins.",
        ),
        Setting(
            key="compression",
            label="Compress with gzip",
            line="use-compression gzip",
            group="Profile",
            help="For gRPC collectors that accept compressed data.",
        ),
        Setting(
            key="source_interface",
            label="Source interface",
            line="source-interface {source}",
            no_line="no source-interface {source}",
            group="Profile",
            fields=(
                Field(
                    "source",
                    "Interface",
                    "source",
                    hint="The interface whose address the data comes from, such as loopback0",
                    placeholder="loopback0",
                ),
            ),
        ),
        Setting(
            key="retry",
            label="Retry buffer",
            line="use-retry size {mb}",
            no_line="no use-retry",
            group="Profile",
            fields=(
                Field(
                    "mb",
                    "Megabytes",
                    "int",
                    minimum=RETRY_MIN,
                    maximum=RETRY_MAX,
                    hint=f"{RETRY_MIN} to {RETRY_MAX}",
                ),
            ),
            help="Keeps data a collector could not take and sends it again later.",
        ),
        Setting(
            key="nodeid",
            label="Node ID",
            line="use-nodeid {name}",
            no_line="no use-nodeid {name}",
            group="Profile",
            fields=(Field("name", "Name", "name", hint="Sent instead of the switch's hostname"),),
        ),
    ),
)

_DESTINATION = Scope(
    key="destination",
    label="Destination group",
    ident=(_group_field("group", "Group"),),
    enter=("telemetry", "destination-group {group}"),
    create=True,
    create_label="Make a destination group",
    delete=("telemetry", "no destination-group {group}"),
    delete_warning="Its collectors go with it; subscriptions that use it stop sending there.",
    help="The collectors the data goes to, each with its address, port, protocol and encoding.",
    settings=(
        _destination("ipv4", "IPv4 collector", "ip address", "ipv4", "192.0.2.50"),
        _destination("ipv6", "IPv6 collector", "ipv6 address", "ipv6", "2001:db8::50"),
        Setting(
            key="use_vrf",
            label="VRF",
            line="use-vrf {vrf}",
            no_line="no use-vrf {vrf}",
            group="Group",
            fields=(Field("vrf", "VRF", "usevrf"),),
            check=_check_vrf,
            help="Where this group's collectors are reached; the profile's VRF when not set.",
        ),
    ),
)

_SENSOR = Scope(
    key="sensor",
    label="Sensor group",
    ident=(_group_field("group", "Group"),),
    enter=("telemetry", "sensor-group {group}"),
    create=True,
    create_label="Make a sensor group",
    delete=("telemetry", "no sensor-group {group}"),
    delete_warning="Subscriptions that use it stop sending its data.",
    help="What to send: a data source and paths into it. DME paths look like sys/intf, "
    "YANG paths like /Cisco-NX-OS-device:System/bgp-items, NX-API paths are show commands.",
    settings=(
        Setting(
            key="data_source",
            label="Data source",
            line="data-source {source}",
            removable=False,
            group="Group",
            fields=(
                Field(
                    "source",
                    "Source",
                    "choice",
                    choices=DATA_SOURCES,
                    hint="DME: the switch's data model; NX-API: show commands; YANG: "
                    "OpenConfig and Cisco models; NATIVE: changes as they happen",
                ),
            ),
            help="Set it before the paths: the switch refuses a source that does not fit "
            "the paths already there.",
        ),
        Setting(
            key="path",
            label="Path",
            line="path {path}[ depth {depth}][ query-condition {query}][ filter-condition "
            "{filter}]",
            no_line="no path {path}",
            group="Paths",
            fields=(
                Field(
                    "path",
                    "Path",
                    "telpath",
                    hint="A DME or YANG path, without spaces",
                    placeholder="sys/intf",
                ),
                Field(
                    "depth",
                    "Depth",
                    "choice",
                    choices=DEPTHS,
                    optional=True,
                    hint="How far below the path to send; unbounded is everything",
                ),
                Field(
                    "query",
                    "Query condition",
                    "telpath",
                    optional=True,
                    hint="As the DME takes it, without spaces",
                ),
                Field(
                    "filter",
                    "Filter condition",
                    "telpath",
                    optional=True,
                    hint='Send only on a match, such as eq(ethpmPhysIf.operSt,"down")',
                ),
            ),
            help="Set adds a path; Remove needs only the path.",
        ),
        Setting(
            key="show_path",
            label="Show command (NX-API)",
            line='path "{command}"',
            no_line='no path "{command}"',
            group="Paths",
            fields=(
                Field(
                    "command",
                    "Command",
                    "quoted",
                    maximum=255,
                    hint="One show command; needs the NX-API data source",
                    placeholder="show version",
                ),
            ),
            check=_check_show,
            help="The switch runs the command and sends its output.",
        ),
    ),
)

_SUBSCRIPTION = Scope(
    key="subscription",
    label="Subscription",
    ident=(_group_field("subscription", "Subscription"),),
    enter=("telemetry", "subscription {subscription}"),
    create=True,
    create_label="Make a subscription",
    delete=("telemetry", "no subscription {subscription}"),
    delete_warning="The switch stops sending its sensor groups' data.",
    help="Which sensor groups go to which destination groups, and how often. Make the "
    "groups first.",
    settings=(
        Setting(
            key="dst_grp",
            label="Destination group",
            line="dst-grp {group}",
            group="Subscription",
            fields=(_group_field("group", "Destination group"),),
            help="Set adds one; a subscription can send to several.",
        ),
        Setting(
            key="snsr_grp",
            label="Sensor group",
            line="snsr-grp {group} sample-interval {ms}",
            no_line="no snsr-grp {group}",
            group="Subscription",
            fields=(
                _group_field("group", "Sensor group"),
                Field(
                    "ms",
                    "Every (milliseconds)",
                    "int",
                    minimum=0,
                    maximum=SAMPLE_MAX,
                    hint=f"0: on every change; or {SAMPLE_MIN} to {SAMPLE_MAX}",
                    placeholder="30000",
                ),
            ),
            check=_check_sample,
            help="Set adds one, or changes its interval. Remove needs only the group.",
        ),
    ),
)


# ---- reading the switch ------------------------------------------------------------------


@dataclass
class TelemetryConfig:
    """The ``telemetry`` block of ``show running-config``: the destination profile's lines
    and each group's, by kind and number."""

    found: bool = False
    profile: list[str] = field(default_factory=list)
    destinations: dict[str, list[str]] = field(default_factory=dict)
    sensors: dict[str, list[str]] = field(default_factory=dict)
    subscriptions: dict[str, list[str]] = field(default_factory=dict)


_PART = re.compile(
    r"^(destination-profile|destination-group|sensor-group|subscription)(?:\s+(\S+))?$"
)


def parse_telemetry_config(config: str) -> TelemetryConfig:
    """The ``telemetry`` block: each part (``destination-group 1``) with its lines."""
    found = TelemetryConfig()
    inside = False
    current: list[str] | None = None
    for raw in config.splitlines():
        line = raw.strip()
        if not raw[:1].isspace():
            inside = line == "telemetry"
            found.found = found.found or inside
            current = None
            continue
        if not inside or not line:
            continue
        if match := _PART.fullmatch(line):
            kind, number = match.group(1), match.group(2) or ""
            if kind == "destination-profile":
                current = found.profile
            else:
                target = {
                    "destination-group": found.destinations,
                    "sensor-group": found.sensors,
                    "subscription": found.subscriptions,
                }[kind]
                current = target.setdefault(number, [])
        elif current is not None:
            current.append(line)
    return found


_COLLECTOR = re.compile(
    r"^(ip|ipv6) address (\S+) port (\d+) protocol (\S+) encoding (\S+)$", re.IGNORECASE
)


def _after(lines: list[str], start: str) -> str:
    return next((line[len(start) :].strip() for line in lines if line.startswith(start)), "")


def _profile_instance(lines: list[str]) -> Instance:
    values: dict[str, dict[str, str]] = {}
    for key, start, name in (
        ("use_vrf", "use-vrf ", "vrf"),
        ("source_interface", "source-interface ", "source"),
        ("nodeid", "use-nodeid ", "name"),
    ):
        if found := _after(lines, start):
            values[key] = {name: found}
    if retry := re.search(r"\d+", _after(lines, "use-retry")):
        values["retry"] = {"mb": retry.group(0)}
    if "use-compression gzip" in lines:
        values["compression"] = {}
    facts = (
        ("VRF", _after(lines, "use-vrf ") or "default"),
        ("Compression", "gzip" if "compression" in values else "none"),
        ("Source interface", _after(lines, "source-interface ") or "not set"),
        ("Node ID", _after(lines, "use-nodeid ") or "the hostname"),
    )
    return Instance("profile", {}, "Destination profile", facts, values)


def _status_by_collector(transport: Any) -> dict[tuple[str, str], str]:
    return {
        (text(row.get("ip_address")), text(row.get("port"))): text(row.get("transport_status"))
        for row in rows(transport or {}, "TABLE_transport_info", "ROW_transport_info")
    }


def parse_telemetry_view(
    transport: Any, sensor_groups: Any, collectors: Any, config: str | None
) -> ProtocolView:
    """The page: the destination profile, a place per destination group, sensor group and
    subscription (from the configuration text), and tables of the collectors with their
    state, the sensor groups as the switch runs them, and the data collectors' counts."""
    parsed = parse_telemetry_config(config or "")
    statuses = _status_by_collector(transport)
    instances: list[Instance] = []
    if config is not None:
        instances.append(_profile_instance(parsed.profile))
    collector_rows: list[tuple[str, ...]] = []
    for number, lines in parsed.destinations.items():
        values: dict[str, dict[str, str]] = {}
        shown: list[str] = []
        for line in lines:
            if match := _COLLECTOR.fullmatch(line):
                family, address, port, protocol, encoding = match.groups()
                key = "ipv4" if family.lower() == "ip" else "ipv6"
                values.setdefault(
                    key,
                    {"address": address, "port": port, "protocol": protocol, "encoding": encoding},
                )
                status = statuses.get((address, port), "")
                shown.append(f"{address} port {port}")
                collector_rows.append((number, address, port, protocol, encoding, status or "-"))
        if vrf := _after(lines, "use-vrf "):
            values["use_vrf"] = {"vrf": vrf}
        facts = (
            ("Collectors", ", ".join(shown) or "none"),
            ("VRF", vrf or "the profile's"),
        )
        instances.append(
            Instance("destination", {"group": number}, f"Destination group {number}", facts, values)
        )
    for number, lines in parsed.sensors.items():
        source = _after(lines, "data-source ")
        paths = [line[len("path ") :] for line in lines if line.startswith("path ")]
        sensor_values: dict[str, dict[str, str]] = {}
        if source in DATA_SOURCES:
            sensor_values["data_source"] = {"source": source}
        facts = (
            ("Data source", source or "-"),
            ("Paths", "; ".join(paths) or "none"),
        )
        instances.append(
            Instance("sensor", {"group": number}, f"Sensor group {number}", facts, sensor_values)
        )
    for number, lines in parsed.subscriptions.items():
        sends = [line.split()[1] for line in lines if line.startswith("dst-grp ")]
        takes = [
            f"{parts[1]} every {parts[3]} ms" if parts[3] != "0" else f"{parts[1]} on change"
            for parts in (line.split() for line in lines if line.startswith("snsr-grp "))
            if len(parts) >= 4
        ]
        facts = (
            ("Destination groups", ", ".join(sends) or "none"),
            ("Sensor groups", ", ".join(takes) or "none"),
        )
        instances.append(
            Instance("subscription", {"subscription": number}, f"Subscription {number}", facts)
        )
    if config is None:
        # Without the text, the collectors come from the transport list alone.
        collector_rows = [
            (
                "-",
                text(row.get("ip_address")),
                text(row.get("port")),
                text(row.get("transport_type")),
                text(row.get("encoding_type")),
                text(row.get("transport_status")) or "-",
            )
            for row in rows(transport or {}, "TABLE_transport_info", "ROW_transport_info")
        ]
    sensor_rows = tuple(
        (
            text(row.get("snsr_grp_id")),
            text(row.get("snsr_grp_collector_type")) or "-",
            text(row.get("snsr_grp_type")) or "-",
            text(row.get("snsr_grp_timer_interval")) or "-",
            text(row.get("snsr_grp_timer_status")) or "-",
            text(row.get("snsr_grp_sub_count")) or "0",
        )
        for row in rows(sensor_groups or {}, "TABLE_sensor_grp", "ROW_sensor_grp")
    )
    collector_counts = tuple(
        (
            text(row.get("dcb_collector_type")),
            text(row.get("dcb_success_count")) or "0",
            text(row.get("dcb_fail_count")) or "0",
            text(row.get("dcb_skip_count")) or "0",
        )
        for row in rows(collectors or {}, "TABLE_data_collector_brief", "ROW_data_collector_brief")
    )
    tables = (
        Table(
            "Collectors",
            ("Group", "Address", "Port", "Protocol", "Encoding", "State"),
            tuple(collector_rows),
            empty="No collector is set.",
            note="State is the switch's connection to the collector: Idle until a "
            "subscription sends to it.",
        ),
        Table(
            "Sensor groups running",
            ("Group", "Data source", "Kind", "Interval (ms)", "Timer", "Subscriptions"),
            sensor_rows,
            empty="No sensor group is in a subscription.",
        ),
        Table(
            "Data collected",
            ("Data source", "Read", "Failed", "Skipped"),
            collector_counts,
            empty="Nothing collected yet.",
        ),
    )
    return ProtocolView(tuple(instances), tables)


TELEMETRY = Protocol(
    key="telemetry",
    name="Telemetry",
    summary="Stream the switch's data to a collector (model-driven telemetry)",
    features=(FEATURE,),
    commands=COMMANDS,
    parse=lambda bodies: parse_telemetry_view(*(bodies + [None] * 3)[:3], None),
    scopes=(_PROFILE, _DESTINATION, _SENSOR, _SUBSCRIPTION),
    about=(
        "Make a destination group (where the data goes) and a sensor group (what is sent), "
        "then a subscription that joins them with an interval."
    ),
)


@dataclass(frozen=True)
class TelemetryPage:
    """Everything the Telemetry page shows."""

    protocol: Protocol
    view: ProtocolView
    vrfs: tuple[str, ...]  # default, management, then the others
    problem: str = ""
    missing: tuple[str, ...] = ()  # the telemetry feature, when it is off


def load_telemetry_page(client: NxapiClient) -> TelemetryPage:
    """One request for the feature and the VRFs; while telemetry is on, one for the
    collectors, sensor groups and data collectors, and one for the configuration text."""
    feature, vrf_body = client.show(*PAGE_COMMANDS)
    vrfs = vrf_choices(vrf_body)
    if not feature_states(feature).get(FEATURE, False):
        return TelemetryPage(TELEMETRY, ProtocolView(), vrfs, missing=(FEATURE,))
    try:
        bodies = client.show(*COMMANDS)
    except NxapiCommandError as exc:
        return TelemetryPage(
            TELEMETRY, ProtocolView(), vrfs, f"The switch did not report telemetry: {exc}"
        )
    problem = ""
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError as exc:
        config = None
        problem = (
            f"The switch did not show the telemetry settings, so only the collectors and "
            f"running sensor groups are listed: {exc}"
        )
    return TelemetryPage(TELEMETRY, parse_telemetry_view(*bodies, config), vrfs, problem)


def build_telemetry_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Telemetry page."""
    return build_change(TELEMETRY, scope, setting, action, ident, values)
