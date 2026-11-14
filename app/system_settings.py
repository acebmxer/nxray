"""Switch-wide settings: the logging source, the TCP, DNS and HTTP client settings, the XML
server limits and the ACL log level.

These are single configuration lines that belong to no feature and to no other NXray page.
The page reads ``show running-config`` (text) for the lines set and changes them with the
same parts as the Monitor sessions page (``app/protocols.py``), sent by
``NxapiClient.configure_system_settings``.

Tried on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-13), every line put back and
nothing saved:

- ``logging source-interface IF``, ``ip dns source-interface IF`` and ``ip http
  source-interface IF`` are taken and stored; ``no logging source-interface`` needs no
  value, but ``no ip dns source-interface`` and ``no ip http source-interface`` are a syntax
  error without the interface, so those two send it back.
- ``ip tcp path-mtu-discovery``, ``ip tcp mss N`` and ``ip tcp synwait-time N`` are taken,
  the switch answers with a sentence ("Setting TCP MSS to 1400 bytes"), and each ``no`` form
  needs no value and goes back to the default (536 bytes, 30 seconds).
- ``xml server max-session N``, ``xml server validate all`` and ``acllog match-log-level N``
  are taken; ``no xml server max-session`` and ``no acllog match-log-level`` are a syntax
  error without the value, so they send it back.
- ``rate-limit cpu direction input pps 1000 action log`` is taken and stored; its ``no`` form
  must repeat the whole line (``no rate-limit cpu direction input`` is a syntax error).
- ``time-range NAME`` is made by being entered; ``periodic weekdays 08:00 to 17:00`` and
  ``absolute start 08:00 1 January 2027 end 17:00 31 December 2027`` are stored as numbered
  entries (10, 20); ``no time-range NAME`` deletes it. ``snmp ifmib ifalias long`` is taken.
- ``ip icmp-errors source-interface`` is listed by ``show cli list`` but refused ("Syntax
  error"), so it is not here.

Not tried on a switch, built from the lines ``show cli list`` gives (the switch is in
production, so nothing that changes forwarding, queues or needs a restart was tried):
``system default switchport[ shutdown]``, ``system routing max-mode``, ``system urpf disable``,
``system vlan long-name``, ``mac-learn disable``, ``router-guard``, ``l2protocol tunnel cos``,
``as-format asdot``, ``ip load-sharing``, ``switching-mode``, the ``hardware`` lines,
``hw-module logging onboard``, ``congestion-control random-detect forward-nonecn``,
``link-level-flow-control watch-dog-interval``, ``sockets local-port-range``,
``ttag-marker-interval`` and ``fips mode enable``. Each carries a warning where it can cut
traffic or needs a restart.
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
    Setting,
    build_change,
)

CONFIG_COMMAND = "show running-config"

_SOURCE = Field("interface", "Interface", "ifname", hint="Its address is the one used")

_SYSTEM = Scope(
    key="system",
    label="Switch-wide settings",
    ident=(),
    enter=(),
    help="Remove puts a setting back to its default.",
    settings=(
        Setting(
            "log_source",
            "Logging source interface",
            "logging source-interface {interface}",
            (_SOURCE,),
            no_line="no logging source-interface",
            group="Logging",
            help="The interface whose address the switch's log messages come from.",
        ),
        Setting(
            "dns_source",
            "DNS source interface",
            "ip dns source-interface {interface}",
            (_SOURCE,),
            no_line="no ip dns source-interface {interface}",
            group="Client settings",
            help="The interface whose address name lookups come from. Remove needs the same "
            "interface.",
        ),
        Setting(
            "http_source",
            "HTTP source interface",
            "ip http source-interface {interface}",
            (_SOURCE,),
            no_line="no ip http source-interface {interface}",
            group="Client settings",
            help="The interface whose address the switch's web requests come from. Remove needs "
            "the same interface.",
        ),
        Setting(
            "tcp_pmtud",
            "TCP path MTU discovery",
            "ip tcp path-mtu-discovery",
            group="TCP",
            help="Set turns it on, Remove turns it off.",
        ),
        Setting(
            "tcp_mss",
            "TCP maximum segment size",
            "ip tcp mss {bytes}",
            (Field("bytes", "Bytes", "int", 88, 10000, hint="Default 536"),),
            no_line="no ip tcp mss",
            group="TCP",
        ),
        Setting(
            "tcp_syn",
            "TCP connection wait",
            "ip tcp synwait-time {seconds}",
            (Field("seconds", "Seconds", "int", 5, 300, hint="Default 30"),),
            no_line="no ip tcp synwait-time",
            group="TCP",
        ),
        Setting(
            "xml_sessions",
            "XML server sessions",
            "xml server max-session {sessions}",
            (Field("sessions", "Sessions", "int", 1, 8),),
            no_line="no xml server max-session {sessions}",
            group="XML server",
            help="How many XML sessions the switch accepts at once. Remove needs the same number.",
        ),
        Setting(
            "xml_validate",
            "XML schema validation",
            "xml server validate all",
            group="XML server",
            help="Set checks every XML request against its schema.",
        ),
        Setting(
            "acllog_level",
            "ACL log level",
            "acllog match-log-level {level}",
            (Field("level", "Level", "int", 0, 7, hint="Syslog level, 0 to 7"),),
            no_line="no acllog match-log-level {level}",
            group="ACL logging",
            help="The syslog level of the messages ACL entries with log write. Remove needs the "
            "same level.",
        ),
        Setting(
            "ifalias_long",
            "Long interface descriptions in SNMP",
            "snmp ifmib ifalias long",
            group="SNMP",
            help="Set lets ifAlias carry the whole description, not the first 64 characters.",
        ),
        Setting(
            "cpu_rate_limit",
            "CPU rate limit (log only)",
            "rate-limit cpu direction {direction} pps {pps} action log",
            (
                Field("direction", "Direction", "choice", choices=("input", "output", "both")),
                Field("pps", "Packets per second", "int", 0, 100000),
            ),
            no_line="no rate-limit cpu direction {direction} pps {pps} action log",
            group="CPU and logging",
            help="Logs when traffic to or from the CPU passes this rate. Remove needs the same "
            "direction and rate.",
        ),
        Setting(
            "onboard_logging",
            "Onboard failure logging",
            "hw-module logging onboard[ {kind}]",
            (
                Field(
                    "kind",
                    "Kind",
                    "choice",
                    choices=(
                        "counter-stats",
                        "cpuhog",
                        "environmental-history",
                        "error-stats",
                        "interrupt-stats",
                        "obfl-logs",
                    ),
                    optional=True,
                    hint="Empty: all of them",
                ),
            ),
            no_line="no hw-module logging onboard[ {kind}]",
            group="CPU and logging",
            help="What the switch writes to its onboard failure log.",
        ),
        Setting(
            "sockets_range",
            "Local port range for sockets",
            "sockets local-port-range {low} {high}",
            (
                Field("low", "Lowest port", "int", 15001, 58000),
                Field("high", "Highest port", "int", 22001, 65535),
            ),
            no_line="no sockets local-port-range",
            group="CPU and logging",
            help="The range the switch's own connections use.",
        ),
        Setting(
            "ttag_interval",
            "Timing tag marker interval",
            "ttag-marker-interval {seconds}",
            (Field("seconds", "Seconds", "int", 1, 4),),
            no_line="no ttag-marker-interval",
            group="CPU and logging",
        ),
        Setting(
            "as_format",
            "BGP AS numbers as asdot",
            "as-format asdot",
            group="Routing",
            help="Set shows 4-byte AS numbers as 1.10, not 65546.",
        ),
        Setting(
            "load_sharing",
            "ECMP load sharing",
            "ip load-sharing address source-destination port source-destination[ rotate {rotate}]",
            (Field("rotate", "Rotate", "int", 1, 63, optional=True, hint="Hash rotation"),),
            no_line="no ip load-sharing address source-destination port source-destination",
            group="Routing",
            warning="Changing how traffic is spread over equal-cost paths can move flows "
            "to other paths.",
        ),
        Setting(
            "urpf_disable",
            "Unicast RPF off",
            "system urpf disable",
            group="Routing",
            warning="Turns unicast reverse-path checking off for the whole switch.",
        ),
        Setting(
            "routing_mode",
            "Routing table mode",
            "system routing max-mode {mode}",
            (Field("mode", "Mode", "choice", choices=("l3", "host", "l2", "l2-l3")),),
            no_line="no system routing max-mode {mode}",
            group="Routing",
            warning="The switch must be restarted before this takes effect, and the routing "
            "table is carved up differently.",
        ),
        Setting(
            "default_switchport",
            "Ports are layer 2 by default",
            "system default switchport",
            group="Defaults for ports",
            warning="Every port without its own switchport or no switchport line changes "
            "mode, which can cut traffic. Remove makes ports layer 3 by default.",
        ),
        Setting(
            "default_switchport_shutdown",
            "Layer 2 ports start shut down",
            "system default switchport shutdown",
            group="Defaults for ports",
            warning="Every layer 2 port without its own shutdown line goes down.",
        ),
        Setting(
            "vlan_long_name",
            "Long VLAN names",
            "system vlan long-name",
            group="Defaults for ports",
            help="Set lets VLAN names be up to 128 characters.",
        ),
        Setting(
            "mac_learn_off",
            "MAC learning off",
            "mac-learn disable",
            group="Layer 2",
            warning="The switch stops learning MAC addresses, so it floods traffic.",
        ),
        Setting(
            "router_guard4",
            "Router guard (IPv4 multicast)",
            "router-guard ip multicast switchports",
            group="Layer 2",
        ),
        Setting(
            "router_guard6",
            "Router guard (IPv6 multicast)",
            "router-guard ipv6 multicast switchports",
            group="Layer 2",
        ),
        Setting(
            "l2pt_cos",
            "Layer 2 tunnel CoS",
            "l2protocol tunnel cos {cos}",
            (Field("cos", "CoS", "int", 0, 7),),
            no_line="no l2protocol tunnel cos",
            group="Layer 2",
        ),
        Setting(
            "switching_mode",
            "Switching mode",
            "switching-mode {mode}",
            (
                Field(
                    "mode",
                    "Mode",
                    "choice",
                    choices=("store-forward", "fast-to-slow-speed-cut-through"),
                ),
            ),
            no_line="no switching-mode {mode}",
            group="Hardware and queues",
            warning="Changes how the switch forwards frames between ports of different speeds.",
        ),
        Setting(
            "afd_profile",
            "AFD queue profile",
            "hardware qos afd profile {profile}",
            (Field("profile", "Profile", "choice", choices=("mesh", "burst", "ultra-burst")),),
            no_line="no hardware qos afd profile",
            group="Hardware and queues",
            warning="Changes how the switch sets its queue thresholds.",
        ),
        Setting(
            "buffer_poll",
            "Buffer statistics interval",
            "hardware profile buffer info poll-interval timer {milliseconds}",
            (Field("milliseconds", "Milliseconds", "int", 500, 60000),),
            no_line="no hardware profile buffer info poll-interval timer",
            group="Hardware and queues",
        ),
        Setting(
            "buffer_threshold",
            "Buffer threshold per port",
            "hardware profile buffer info port-threshold threshold {percent}",
            (Field("percent", "Percent", "int", 1, 95),),
            no_line="no hardware profile buffer info port-threshold threshold",
            group="Hardware and queues",
        ),
        Setting(
            "ejector",
            "Hardware ejector",
            "hardware ejector enable",
            group="Hardware and queues",
        ),
        Setting(
            "tx_span",
            "Global transmit SPAN for multicast",
            "hardware multicast global-tx-span",
            group="Hardware and queues",
        ),
        Setting(
            "forward_nonecn",
            "Forward non-ECN traffic with WRED",
            "congestion-control random-detect forward-nonecn",
            group="Hardware and queues",
        ),
        Setting(
            "llfc_watchdog",
            "Link-level flow control watchdog",
            "link-level-flow-control watch-dog-interval {state}",
            (Field("state", "State", "choice", choices=("on", "off")),),
            no_line="no link-level-flow-control watch-dog-interval {state}",
            group="Hardware and queues",
        ),
        Setting(
            "fips",
            "FIPS mode",
            "fips mode enable",
            group="Security",
            warning="The switch must be restarted to enter FIPS mode, and some algorithms "
            "stop working.",
        ),
    ),
)

_TIME_RANGE = Scope(
    key="time_range",
    label="Time range",
    ident=(Field("name", "Name", "name"),),
    enter=("time-range {name}",),
    create=True,
    create_label="Make a time range",
    delete=("no time-range {name}",),
    delete_warning="ACL entries that use the time range stop matching it.",
    help="A time range an ACL entry can name. Remove takes one entry out.",
    settings=(
        Setting(
            "periodic",
            "Repeating entry",
            "periodic {days} {start} to {end}",
            (
                Field(
                    "days",
                    "Days",
                    "choice",
                    choices=(
                        "daily",
                        "weekdays",
                        "weekend",
                        "monday",
                        "tuesday",
                        "wednesday",
                        "thursday",
                        "friday",
                        "saturday",
                        "sunday",
                    ),
                ),
                Field("start", "From", "hhmm"),
                Field("end", "To", "hhmm"),
            ),
            no_line="no periodic {days} {start} to {end}",
            group="Entries",
            help="Remove needs the same days and times.",
        ),
    ),
)

SCOPES = (_SYSTEM, _TIME_RANGE)

# (setting key, the line as show running-config prints it, the field names in order)
_LINES = (
    ("log_source", r"logging source-interface (\S+)", ("interface",)),
    ("dns_source", r"ip dns source-interface (\S+)", ("interface",)),
    ("http_source", r"ip http source-interface (\S+)", ("interface",)),
    ("tcp_pmtud", r"ip tcp path-mtu-discovery", ()),
    ("tcp_mss", r"ip tcp mss (\d+)", ("bytes",)),
    ("tcp_syn", r"ip tcp synwait-time (\d+)", ("seconds",)),
    ("xml_sessions", r"xml server max-session (\d+)", ("sessions",)),
    ("xml_validate", r"xml server validate all", ()),
    ("acllog_level", r"acllog match-log-level (\d+)", ("level",)),
    ("ifalias_long", r"snmp ifmib ifalias long", ()),
    (
        "cpu_rate_limit",
        r"rate-limit cpu direction (input|output|both) pps (\d+) action log",
        ("direction", "pps"),
    ),
    ("sockets_range", r"sockets local-port-range (\d+) (\d+)", ("low", "high")),
    ("ttag_interval", r"ttag-marker-interval (\d+)", ("seconds",)),
    ("as_format", r"as-format asdot", ()),
    (
        "load_sharing",
        r"ip load-sharing address source-destination port source-destination"
        r"(?: rotate (\d+))?",
        ("rotate",),
    ),
    ("urpf_disable", r"system urpf disable", ()),
    ("routing_mode", r"system routing max-mode (\S+)", ("mode",)),
    ("default_switchport", r"system default switchport", ()),
    ("default_switchport_shutdown", r"system default switchport shutdown", ()),
    ("vlan_long_name", r"system vlan long-name", ()),
    ("mac_learn_off", r"mac-learn disable", ()),
    ("router_guard4", r"router-guard ip multicast switchports", ()),
    ("router_guard6", r"router-guard ipv6 multicast switchports", ()),
    ("l2pt_cos", r"l2protocol tunnel cos (\d+)", ("cos",)),
    ("switching_mode", r"switching-mode (\S+)", ("mode",)),
    ("afd_profile", r"hardware qos afd profile (\S+)", ("profile",)),
    (
        "buffer_poll",
        r"hardware profile buffer info poll-interval timer (\d+)",
        ("milliseconds",),
    ),
    (
        "buffer_threshold",
        r"hardware profile buffer info port-threshold threshold (\d+)",
        ("percent",),
    ),
    ("ejector", r"hardware ejector enable", ()),
    ("tx_span", r"hardware multicast global-tx-span", ()),
    ("forward_nonecn", r"congestion-control random-detect forward-nonecn", ()),
    ("llfc_watchdog", r"link-level-flow-control watch-dog-interval (on|off)", ("state",)),
    ("fips", r"fips mode enable", ()),
    ("onboard_logging", r"hw-module logging onboard(?: (\S+))?", ("kind",)),
)


def parse_system_config(config: str) -> dict[str, dict[str, str]]:
    """The settings of this page that ``show running-config`` shows, as setting values."""
    values: dict[str, dict[str, str]] = {}
    for raw in config.splitlines():
        if raw[:1].isspace():
            continue
        line = raw.strip()
        for key, pattern, names in _LINES:
            if match := re.fullmatch(pattern, line):
                found = zip(names, match.groups(), strict=True)
                values[key] = {name: value for name, value in found if value}
    return values


def parse_time_ranges(config: str) -> list[tuple[str, list[str], dict[str, str]]]:
    """Each ``time-range NAME`` of the configuration: its name, its entries as written
    ("periodic weekdays 08:00:00 to 17:00:00") and the first repeating entry as setting
    values."""
    found: list[tuple[str, list[str], dict[str, str]]] = []
    for raw in config.splitlines():
        line = raw.strip()
        if not raw[:1].isspace():
            if match := re.fullmatch(r"time-range (\S+)", line):
                found.append((match.group(1), [], {}))
            else:
                found.append(("", [], {}))  # something else: closes the block
            continue
        if not found or not found[-1][0]:
            continue
        entry = re.sub(r"^\d+ ", "", line)
        found[-1][1].append(entry)
        match = re.fullmatch(
            r"periodic (\S+) (\d\d:\d\d)(?::\d\d)? to (\d\d:\d\d)(?::\d\d)?", entry
        )
        if match and not found[-1][2]:
            found[-1][2].update(zip(("days", "start", "end"), match.groups(), strict=True))
    return [item for item in found if item[0]]


def parse_system_settings(config: str | None) -> ProtocolView:
    """The page from the text of ``show running-config`` (None: not read, as when the
    account may not)."""
    values = parse_system_config(config or "")
    notes = ()
    if config is None:
        notes = (
            "The switch did not show its configuration to NXray's account: the values set "
            "are not shown.",
        )
    instance = Instance("system", {}, "Switch-wide settings", (), values)
    ranges = tuple(
        Instance(
            "time_range",
            {"name": name},
            f"Time range {name}",
            (("Entries", "; ".join(entries) or "none"),),
            {"periodic": periodic} if periodic else {},
        )
        for name, entries, periodic in parse_time_ranges(config or "")
    )
    return ProtocolView((instance, *ranges), (), notes)


SYSTEM_SETTINGS = Protocol(
    key="system-settings",
    name="Switch-wide settings",
    summary="Logging source, TCP, DNS, HTTP and XML server settings, ACL log level",
    features=(),
    commands=(),
    parse=lambda bodies: parse_system_settings(None),
    scopes=SCOPES,
    about=(
        "Single settings for the whole switch that belong to no feature. Each shows its "
        "current value when the switch has one set; a setting at its default is not stored "
        "in the configuration."
    ),
)


@dataclass(frozen=True)
class SystemSettingsPage:
    """Everything the Switch-wide settings page shows."""

    protocol: Protocol
    view: ProtocolView
    problem: str = ""
    missing: tuple[str, ...] = ()


def load_system_settings_page(client: NxapiClient) -> SystemSettingsPage:
    """``show running-config`` as text."""
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = None
    return SystemSettingsPage(SYSTEM_SETTINGS, parse_system_settings(config))


def check_system_settings_place(page: SystemSettingsPage, ident: dict[str, str]) -> None:
    """The one scope is the whole switch: nothing to check."""


def build_system_settings_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Switch-wide settings page."""
    return build_change(SYSTEM_SETTINGS, scope, setting, action, ident, values)
