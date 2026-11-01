"""Switch admin: the switch's name, clock and NTP, DNS, logging, SNMP and banner,
and every setting the Switch admin page changes.

The page is described with the same parts as the routing protocol and
spanning tree pages (``app/protocols.py``): scopes (the whole switch, one NTP
server, one DNS server, one logging server, one SNMP trap receiver), each
setting the one configuration line it sends with checked values in its
blanks, and ``build_change`` building the lines.
``NxapiClient.configure_switch_admin`` sends them.

Read in one request: ``show hostname``, ``show clock`` and ``show vrf``. Then
``show ntp peer-status`` on its own (a switch without NTP servers may refuse
it), and ``show running-config`` as text (``NxapiClient.show_text``), the only
place most of these settings show; NXray's role allows that read from role
version 12. Without it the page shows the name, the time and the NTP servers
the switch is talking to.

Changes left out on purpose, so NXray's role need not allow them: SNMP users
and read-write communities (each is a way in to the whole switch), and AAA,
accounts and passwords. NXray only makes read-only (``network-operator``)
SNMP communities, and its role allows no other kind.

The lines follow Cisco's NX-OS 9.3 Fundamentals and System Management
Configuration Guides. The structured answers of ``show clock`` and ``show ntp
peer-status`` are shaped after Cisco's NX-API reference, not recorded on a
switch; the parsers take what they find and show the rest as unknown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.nxapi import DEFAULT_VRF, NxapiClient, NxapiCommandError, validate_show_command
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
    table_rows,
    text,
)
from app.routing import parse_vrfs

# ---- fields ---------------------------------------------------------------------

LEVELS = tuple(str(n) for n in range(8))  # syslog severities, 0 (emergencies) to 7 (debugging)
LEVEL_HINT = (
    "0 emergencies, 1 alerts, 2 critical, 3 errors, 4 warnings, 5 notifications, "
    "6 informational, 7 debugging: messages of this level and more urgent ones"
)
DAYS = ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")
MONTHS = (
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
)
# The banner's delimiter: the text may not contain it.
BANNER_DELIMITER = "#"
BANNER_MAX = 200
HOSTNAME_MAX = 63
COMMUNITY_MAX = 32
# What NX-OS keeps in its log file by default, in bytes, and the range it takes.
LOGFILE_SIZE_MIN = 4096
LOGFILE_SIZE_MAX = 4194304
# How many lines the log viewer may ask for.
LOG_LINES = (50, 200, 1000)


def _vrf_field(name: str = "vrf") -> Field:
    return Field(
        name,
        "VRF",
        "usevrf",
        hint="The VRF the switch reaches it in: management for the mgmt0 port",
    )


def _level(name: str = "level", label: str = "Level", optional: bool = False) -> Field:
    return Field(name, label, "choice", choices=LEVELS, optional=optional, hint=LEVEL_HINT)


def _banner_check(values: dict[str, str]) -> None:
    if BANNER_DELIMITER in values["text"]:
        raise ValueError(f'the banner cannot contain "{BANNER_DELIMITER}"')


def _vrf_needed(values: dict[str, str]) -> None:
    if not values["vrf"]:
        raise ValueError("pick the VRF it is reached in; the default VRF needs no line")


def _summer_fields() -> tuple[Field, ...]:
    def week(name: str, label: str) -> Field:
        return Field(name, label, "int", 1, 5, hint="1 to 5: which week of the month")

    return (
        Field("zone", "Summer zone name", "name", maximum=8, placeholder="EDT"),
        week("start_week", "Starts: week"),
        Field("start_day", "Starts: day", "choice", choices=DAYS),
        Field("start_month", "Starts: month", "choice", choices=MONTHS),
        Field("start_time", "Starts: time", "hhmm", placeholder="02:00"),
        week("end_week", "Ends: week"),
        Field("end_day", "Ends: day", "choice", choices=DAYS),
        Field("end_month", "Ends: month", "choice", choices=MONTHS),
        Field("end_time", "Ends: time", "hhmm", placeholder="02:00"),
        Field("offset", "Clock moves by", "int", 1, 1440, hint="Minutes; usually 60"),
    )


# ---- the whole switch -------------------------------------------------------------

SYSTEM = Scope(
    "system",
    "Whole switch",
    (),
    (),
    (
        Setting(
            "hostname",
            "Hostname",
            "hostname {name}",
            (
                Field(
                    "name",
                    "Hostname",
                    "name",
                    maximum=HOSTNAME_MAX,
                    hint="Letters, digits, '.', '_' or '-'",
                    placeholder="core-1",
                ),
            ),
            removable=False,
            help="The switch's name: its prompt, and what its neighbors see over CDP and LLDP",
            warning="Other devices see the new name at once: CDP and LLDP neighbors, and "
            "anything that reads the switch's name over SNMP.",
            group="Name and banner",
        ),
        Setting(
            "banner",
            "Login banner",
            "banner motd " + BANNER_DELIMITER + "{text}" + BANNER_DELIMITER,
            (
                Field(
                    "text",
                    "Text",
                    "text",
                    maximum=BANNER_MAX,
                    hint=f'One line, up to {BANNER_MAX} characters, without "{BANNER_DELIMITER}"',
                    placeholder="Authorized access only",
                ),
            ),
            no_line="no banner motd",
            help="Shown before every login. Remove puts back the switch's own",
            check=_banner_check,
            group="Name and banner",
        ),
        Setting(
            "timezone",
            "Time zone",
            "clock timezone {zone} {hours} {minutes}",
            (
                Field("zone", "Zone name", "name", maximum=8, placeholder="EST"),
                Field(
                    "hours",
                    "Hours from UTC",
                    "choice",
                    choices=tuple(str(n) for n in range(-23, 24)),
                ),
                Field("minutes", "And minutes", "int", 0, 59, placeholder="0"),
            ),
            no_line="no clock timezone",
            help="How far the switch's clock is from UTC. Remove: UTC",
            group="Clock",
        ),
        Setting(
            "summer_time",
            "Summer time",
            "clock summer-time {zone} {start_week} {start_day} {start_month} {start_time} "
            "{end_week} {end_day} {end_month} {end_time} {offset}",
            _summer_fields(),
            no_line="no clock summer-time",
            help="When the clock moves forward and back each year (US: week 2 Sunday March "
            "02:00 to week 1 Sunday November 02:00, 60)",
            group="Clock",
        ),
        Setting(
            "clock_set",
            "Set the time now",
            "clock set {time} {day} {month} {year}",
            (
                Field("time", "Time", "hhmmss", placeholder="14:30:00"),
                Field("day", "Day", "int", 1, 31),
                Field("month", "Month", "choice", choices=MONTHS),
                Field("year", "Year", "int", 2000, 2037),
            ),
            removable=False,
            help="In the switch's own time zone. Changes no configuration, so there is "
            "nothing to save",
            warning="With NTP servers set, NTP moves the clock back to their time.",
            group="Clock",
            config=False,
        ),
        Setting(
            "domain",
            "Domain name",
            "ip domain-name {domain}[ use-vrf {vrf}]",
            (
                Field("domain", "Domain", "domain", placeholder="example.net"),
                _vrf_field(),
            ),
            help="Added to names that have no domain",
            group="DNS",
        ),
        Setting(
            "lookup",
            "DNS lookups",
            "ip domain-lookup",
            help="Set: the switch asks its DNS servers for names. Remove: it does not. On by "
            "default",
            group="DNS",
        ),
        Setting(
            "logfile",
            "Log file",
            "logging logfile messages {level}[ size {size}]",
            (
                _level(),
                Field(
                    "size",
                    "Size",
                    "int",
                    LOGFILE_SIZE_MIN,
                    LOGFILE_SIZE_MAX,
                    optional=True,
                    hint=f"Bytes, {LOGFILE_SIZE_MIN} to {LOGFILE_SIZE_MAX}; empty: the "
                    "switch's default",
                ),
            ),
            removable=False,
            help="What the switch keeps in its own log (the Switch log page shows it). "
            "Default level 5",
            group="Logging",
        ),
        Setting(
            "console",
            "Console logging",
            "logging console {level}",
            (_level(),),
            no_line="no logging console",
            help="Messages printed on the serial console. Default level 2. Remove: none",
            group="Logging",
        ),
        Setting(
            "monitor",
            "Terminal logging",
            "logging monitor {level}",
            (_level(),),
            no_line="no logging monitor",
            help="Messages printed in SSH sessions that ask for them (terminal monitor). "
            "Default level 5. Remove: none",
            group="Logging",
        ),
        Setting(
            "timestamp",
            "Timestamps",
            "logging timestamp {unit}",
            (
                Field(
                    "unit",
                    "Unit",
                    "choice",
                    choices=("seconds", "milliseconds", "microseconds"),
                    hint="Default seconds",
                ),
            ),
            removable=False,
            group="Logging",
        ),
        Setting(
            "contact",
            "SNMP contact",
            "snmp-server contact {text}",
            (Field("text", "Contact", "text", maximum=128, placeholder="noc@example.net"),),
            no_line="no snmp-server contact",
            help="Who looks after the switch, as SNMP reports it",
            group="SNMP",
        ),
        Setting(
            "location",
            "SNMP location",
            "snmp-server location {text}",
            (Field("text", "Location", "text", maximum=128, placeholder="Rack 4, room 2"),),
            no_line="no snmp-server location",
            help="Where the switch is, as SNMP reports it",
            group="SNMP",
        ),
        Setting(
            "community",
            "SNMP community (read-only)",
            "snmp-server community {community} group network-operator",
            (
                Field(
                    "community",
                    "Community",
                    "secret",
                    maximum=COMMUNITY_MAX,
                    hint="Works like a password for SNMP v2c; type it again to remove it. "
                    "NXray only makes read-only ones",
                ),
            ),
            no_line="no snmp-server community {community}",
            help="Lets SNMP v2c managers read the switch",
            group="SNMP",
        ),
    ),
    help="Settings for the whole switch, by group.",
)

# ---- servers ----------------------------------------------------------------------

NTP_SERVER = Scope(
    "ntp",
    "NTP servers",
    (Field("address", "Server", "host", placeholder="192.0.2.123"),),
    (),
    (
        Setting(
            "server",
            "Add or change",
            "ntp server {address}[ {prefer}][ use-vrf {vrf}]",
            (
                Field("prefer", "Preferred", "flag", choices=("prefer",)),
                _vrf_field(),
            ),
            removable=False,
            ident=("address",),
        ),
    ),
    delete=("no ntp server {address}",),
    help="The servers the switch sets its clock from. To add one, open the form "
    "below and type its address.",
)

NAME_SERVER = Scope(
    "dns",
    "DNS servers",
    (
        Field("address", "Server", "ip", placeholder="192.0.2.53"),
        _vrf_field(),
    ),
    (),
    (
        Setting(
            "server",
            "Add",
            "ip name-server {address}[ use-vrf {vrf}]",
            removable=False,
            ident=("address", "vrf"),
        ),
    ),
    delete=("no ip name-server {address}[ use-vrf {vrf}]",),
    help="The servers the switch asks for names, when DNS lookups are on.",
)

# Name servers typed inside a VRF's configuration (vrf context management ;
# ip name-server ...), which some switches have instead: listed so they can be
# removed; new ones are added with use-vrf above.
CONTEXT_NAME_SERVER = Scope(
    "dns_context",
    "DNS servers set inside a VRF",
    (
        Field("address", "Server", "ip"),
        Field("context", "VRF", "usevrf"),
    ),
    ("vrf context {context}",),
    delete=("vrf context {context}", "no ip name-server {address}"),
    help="Typed inside a VRF's own configuration; they work like the ones above.",
)

LOG_SERVER = Scope(
    "logging",
    "Logging servers",
    (Field("address", "Server", "host", placeholder="192.0.2.50"),),
    (),
    (
        Setting(
            "server",
            "Add or change",
            "logging server {address}[ {level}][ use-vrf {vrf}]",
            (_level(optional=True), _vrf_field()),
            removable=False,
            ident=("address",),
        ),
    ),
    delete=("no logging server {address}",),
    help="Syslog servers the switch sends its messages to. Level empty: the switch's default (5).",
)

SNMP_HOST = Scope(
    "snmp_host",
    "SNMP trap receivers",
    (Field("address", "Receiver", "ip", placeholder="192.0.2.162"),),
    (),
    (
        Setting(
            "traps",
            "Send traps (SNMP v2c)",
            "snmp-server host {address} traps version 2c {community}",
            (
                Field(
                    "community",
                    "Community",
                    "secret",
                    maximum=COMMUNITY_MAX,
                    hint="The community the traps carry; type it again to remove them",
                ),
            ),
            no_line="no snmp-server host {address} traps version 2c {community}",
            ident=("address",),
        ),
        Setting(
            "vrf",
            "VRF",
            "snmp-server host {address} use-vrf {vrf}",
            (_vrf_field(),),
            no_line="no snmp-server host {address} use-vrf {vrf}",
            help="The VRF the traps leave in, when it is not the default one",
            check=_vrf_needed,
            ident=("address",),
        ),
    ),
    help="Where the switch sends SNMP traps.",
)

# ---- reading ------------------------------------------------------------------------

COMMANDS = ("show hostname", "show clock", "show vrf")
NTP_COMMAND = "show ntp peer-status"
CONFIG_COMMAND = "show running-config"


@dataclass
class AdminConfig:
    """The lines of the running configuration the Switch admin page shows."""

    hostname: str = ""
    banner: str | None = None  # None: the switch's own
    timezone: tuple[str, str, str] | None = None  # zone, hours, minutes
    summer_time: list[str] | None = None  # the ten words after clock summer-time
    domain: tuple[str, str] | None = None  # name, VRF ("" for default)
    lookup: bool = True
    name_servers: list[tuple[str, str]] = field(default_factory=list)  # address, VRF
    context_name_servers: list[tuple[str, str]] = field(default_factory=list)  # address, VRF
    ntp_servers: list[dict[str, str]] = field(default_factory=list)
    logfile: tuple[str, str] | None = None  # level, size
    console: str | None = None  # level, "off", or None for the default
    monitor: str | None = None
    timestamp: str = ""
    log_servers: list[dict[str, str]] = field(default_factory=list)
    contact: str = ""
    location: str = ""
    communities: list[tuple[str, str]] = field(default_factory=list)  # name, group
    trap_hosts: dict[str, dict[str, str]] = field(default_factory=dict)  # address -> details


def _vrf_after(words: list[str]) -> str:
    """The VRF named by ``use-vrf <name>`` in ``words``; "" for none or default."""
    if "use-vrf" in words:
        index = words.index("use-vrf")
        if index + 1 < len(words):
            name = words[index + 1]
            return "" if name == DEFAULT_VRF else name
    return ""


def _banner(lines: list[str], start: int) -> tuple[str, int]:
    """The banner text starting at ``lines[start]`` (``banner motd #text#``, the
    text possibly over several lines) and the index of its last line."""
    rest = lines[start].strip()[len("banner motd") :].strip()
    if not rest:
        return "", start
    delimiter, body = rest[0], rest[1:]
    if delimiter in body:
        return body[: body.index(delimiter)], start
    parts = [body]
    index = start
    while index + 1 < len(lines):
        index += 1
        line = lines[index]
        if delimiter in line:
            parts.append(line[: line.index(delimiter)])
            break
        parts.append(line)
    return "\n".join(parts).strip("\n"), index


def parse_admin_config(config: str) -> AdminConfig:
    """``show running-config`` as typed text: the lines this page shows."""
    found = AdminConfig()
    lines = config.splitlines()
    context: str | None = None  # the VRF while inside "vrf context <name>"
    index = -1
    while index + 1 < len(lines):
        index += 1
        raw = lines[index].rstrip()
        if not raw.strip() or raw.lstrip().startswith("!"):
            continue
        indented = raw.startswith(" ")
        line = raw.strip()
        words = line.split()
        if not indented:
            context = words[2] if line.startswith("vrf context ") and len(words) > 2 else None
        elif context is not None:
            if line.startswith("ip name-server "):
                for address in words[2:]:
                    if address == "use-vrf":
                        break
                    found.context_name_servers.append((address, context))
            continue
        else:
            continue
        if words[0] in ("hostname", "switchname") and len(words) == 2:
            found.hostname = words[1]
        elif line.startswith("banner motd"):
            found.banner, index = _banner(lines, index)
        elif line.startswith("clock timezone ") and len(words) >= 5:
            found.timezone = (words[2], words[3], words[4])
        elif line.startswith("clock summer-time ") and len(words) >= 12:
            found.summer_time = words[2:12]
        elif line.startswith("ip domain-name ") and len(words) >= 3:
            found.domain = (words[2], _vrf_after(words))
        elif line == "no ip domain-lookup":
            found.lookup = False
        elif line.startswith("ip name-server "):
            vrf = _vrf_after(words)
            for address in words[2:]:
                if address == "use-vrf":
                    break
                found.name_servers.append((address, vrf))
        elif line.startswith("ntp server ") and len(words) >= 3:
            found.ntp_servers.append(
                {
                    "address": words[2],
                    "prefer": "prefer" if "prefer" in words else "",
                    "vrf": _vrf_after(words),
                }
            )
        elif line.startswith("logging logfile ") and len(words) >= 4:
            size = words[words.index("size") + 1] if "size" in words[:-1] else ""
            found.logfile = (words[3], size)
        elif line == "no logging console":
            found.console = "off"
        elif line.startswith("logging console"):
            found.console = words[2] if len(words) > 2 else "2"
        elif line == "no logging monitor":
            found.monitor = "off"
        elif line.startswith("logging monitor"):
            found.monitor = words[2] if len(words) > 2 else "5"
        elif line.startswith("logging timestamp ") and len(words) == 3:
            found.timestamp = words[2]
        elif line.startswith("logging server ") and len(words) >= 3:
            level = words[3] if len(words) > 3 and words[3] in LEVELS else ""
            found.log_servers.append(
                {"address": words[2], "level": level, "vrf": _vrf_after(words)}
            )
        elif line.startswith("snmp-server contact "):
            found.contact = line[len("snmp-server contact ") :]
        elif line.startswith("snmp-server location "):
            found.location = line[len("snmp-server location ") :]
        elif line.startswith("snmp-server community ") and len(words) >= 3:
            group = words[words.index("group") + 1] if "group" in words[:-1] else ""
            if not group and len(words) > 3:
                group = {"ro": "network-operator", "rw": "network-admin"}.get(words[3], "")
            found.communities.append((words[2], group))
        elif line.startswith("snmp-server host ") and len(words) >= 4:
            host = found.trap_hosts.setdefault(words[2], {"kind": "", "vrf": ""})
            if words[3] == "use-vrf" and len(words) > 4:
                host["vrf"] = words[4]
            elif words[3] in ("traps", "informs"):
                version = words[words.index("version") + 1] if "version" in words[:-1] else "1"
                host["kind"] = f"{words[3]}, version {version}"
    return found


@dataclass(frozen=True)
class NtpPeer:
    """One NTP server or peer, as ``show ntp peer-status`` reports it."""

    address: str
    vrf: str
    synced: bool
    stratum: str
    reach: str
    poll: str
    delay: str


def parse_ntp_status(body: dict[str, Any]) -> list[NtpPeer]:
    """``show ntp peer-status``: each server, and whether the clock follows it
    (``*``)."""
    found = []
    for row in table_rows(body, "TABLE_peersstatus", "ROW_peersstatus"):
        address = text(row.get("remote"))
        if not address:
            continue
        vrf = text(row.get("vrf"))
        found.append(
            NtpPeer(
                address=address,
                vrf="" if vrf == DEFAULT_VRF else vrf,
                synced=text(row.get("syncmode")) == "*",
                stratum=text(row.get("st")),
                reach=text(row.get("reach")),
                poll=text(row.get("poll")),
                delay=text(row.get("delay")),
            )
        )
    return found


def clock_text(body: dict[str, Any]) -> tuple[str, str]:
    """``show clock``: (the time as the switch writes it, where it gets it from)."""
    time = text(body.get("simple_time")) or text(body.get("time"))
    if not time:
        time = next((text(v) for v in body.values() if isinstance(v, str) and ":" in v), "")
    return time or "unknown", text(body.get("time_source"))


def _level_words(level: str | None, default: str) -> str:
    if level is None:
        return f"level {default} (default)"
    return "off" if level == "off" else f"level {level}"


def _system_values(config: AdminConfig) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    if config.hostname:
        values["hostname"] = {"name": config.hostname}
    if config.banner is not None and "\n" not in config.banner:
        values["banner"] = {"text": config.banner}
    if config.timezone:
        zone, hours, minutes = config.timezone
        values["timezone"] = {"zone": zone, "hours": hours, "minutes": minutes}
    if config.summer_time:
        names = [f.name for f in _summer_fields()]
        values["summer_time"] = dict(zip(names, config.summer_time, strict=False))
    if config.domain:
        values["domain"] = {"domain": config.domain[0], "vrf": config.domain[1]}
    if config.lookup:
        values["lookup"] = {"on": "yes"}
    if config.logfile:
        values["logfile"] = {"level": config.logfile[0], "size": config.logfile[1]}
    for key, level in (("console", config.console), ("monitor", config.monitor)):
        if level is not None and level != "off":
            values[key] = {"level": level}
    if config.timestamp:
        values["timestamp"] = {"unit": config.timestamp}
    if config.contact:
        values["contact"] = {"text": config.contact}
    if config.location:
        values["location"] = {"text": config.location}
    if config.communities:
        values["community"] = {"count": str(len(config.communities))}
    return values


def parse_switch_admin(
    bodies: list[dict[str, Any]],
    ntp_body: dict[str, Any] | None = None,
    config_text: str | None = None,
) -> ProtocolView:
    """The Switch admin page from the reads in ``COMMANDS``, ``show ntp peer-status``
    (None when the switch refused it) and, when NXray may read it, ``show
    running-config`` as text (None when it may not)."""
    hostname_body, clock_body = (list(bodies) + [{}, {}])[:2]
    config = parse_admin_config(config_text) if config_text is not None else None
    peers = parse_ntp_status(ntp_body or {})
    time, source = clock_text(clock_body)
    hostname = text(hostname_body.get("hostname")) or (config.hostname if config else "")
    notes: list[str] = []

    facts: list[tuple[str, str]] = [
        ("Hostname", hostname or "unknown"),
        ("Time", time + (f" (from {source})" if source else "")),
    ]
    if config is not None:
        facts += [
            ("Time zone", _zone_words(config.timezone)),
            ("Summer time", " ".join(config.summer_time) if config.summer_time else "none"),
            (
                "Domain name",
                (config.domain[0] + (f" (VRF {config.domain[1]})" if config.domain[1] else ""))
                if config.domain
                else "none",
            ),
            ("DNS lookups", "on" if config.lookup else "off"),
            (
                "Log file",
                f"level {config.logfile[0]}"
                + (f", {config.logfile[1]} bytes" if config.logfile[1] else "")
                if config.logfile
                else "level 5 (default)",
            ),
            ("Console logging", _level_words(config.console, "2")),
            ("Terminal logging", _level_words(config.monitor, "5")),
            ("Timestamps", config.timestamp or "seconds (default)"),
            ("SNMP contact", config.contact or "none"),
            ("SNMP location", config.location or "none"),
            (
                "Login banner",
                config.banner if config.banner is not None else "the switch's own",
            ),
        ]
    instances = [
        Instance(
            "system",
            {},
            "This switch",
            tuple(facts),
            _system_values(config) if config is not None else {},
        )
    ]

    by_address = {p.address: p for p in peers}
    servers = config.ntp_servers if config is not None else []
    listed = {s["address"] for s in servers}
    for server in servers:
        peer = by_address.get(server["address"])
        instances.append(
            Instance(
                "ntp",
                {"address": server["address"]},
                server["address"],
                (
                    ("VRF", server["vrf"] or DEFAULT_VRF),
                    ("Preferred", "yes" if server["prefer"] else "no"),
                    ("Status", _peer_status(peer)),
                ),
                {"server": {"prefer": server["prefer"], "vrf": server["vrf"] or DEFAULT_VRF}},
            )
        )
    for peer in peers:
        if peer.address in listed or config is not None:
            continue
        instances.append(
            Instance(
                "ntp",
                {"address": peer.address},
                peer.address,
                (("VRF", peer.vrf or DEFAULT_VRF), ("Status", _peer_status(peer))),
                {"server": {"vrf": peer.vrf or DEFAULT_VRF}},
            )
        )

    tables: list[Table] = []
    if config is not None:
        for address, vrf in config.name_servers:
            instances.append(
                Instance(
                    "dns",
                    {"address": address, "vrf": vrf or DEFAULT_VRF},
                    address + (f" (VRF {vrf})" if vrf else ""),
                    (("VRF", vrf or DEFAULT_VRF),),
                )
            )
        for address, vrf in config.context_name_servers:
            instances.append(
                Instance(
                    "dns_context",
                    {"address": address, "context": vrf},
                    f"{address} (VRF {vrf})",
                    (("Set in", f"vrf context {vrf}"),),
                )
            )
        for server in config.log_servers:
            instances.append(
                Instance(
                    "logging",
                    {"address": server["address"]},
                    server["address"],
                    (
                        ("Level", server["level"] or "5 (default)"),
                        ("VRF", server["vrf"] or DEFAULT_VRF),
                    ),
                    {"server": {"level": server["level"], "vrf": server["vrf"] or DEFAULT_VRF}},
                )
            )
        for address, host in config.trap_hosts.items():
            values: dict[str, dict[str, str]] = {}
            if host["vrf"]:
                values["vrf"] = {"vrf": host["vrf"]}
            if host["kind"]:
                values["traps"] = {"kind": host["kind"]}
            instances.append(
                Instance(
                    "snmp_host",
                    {"address": address},
                    address,
                    (("Sends", host["kind"] or "nothing yet"), ("VRF", host["vrf"] or "default")),
                    values,
                )
            )
        tables.append(
            Table(
                "SNMP communities",
                ("Community", "Access"),
                tuple(("*** (hidden)", _access(group)) for _, group in config.communities),
                empty="None: SNMP v2c managers cannot read the switch.",
                note="Communities work like passwords, so NXray never shows them. To remove "
                "one, type it under Whole switch, SNMP.",
            )
        )
    else:
        notes.append(
            "NXray's role on the switch does not let it read the switch's configuration yet, "
            "so only the name, the time and the NTP servers in use are shown: an NXray admin "
            "turns on switch admin changes on the Switch page."
        )
    if ntp_body is None:
        notes.append("The switch did not report its NTP servers' state.")
    return ProtocolView(tuple(instances), tuple(tables), tuple(notes))


def _zone_words(zone: tuple[str, str, str] | None) -> str:
    """('EST', '-5', '0') -> 'EST, UTC -5:00'."""
    if zone is None:
        return "UTC"
    name, hours, minutes = zone
    if not hours.lstrip("+-").isdigit() or not minutes.isdigit():
        return " ".join(zone)
    return f"{name}, UTC {int(hours):+d}:{int(minutes):02d}"


def _access(group: str) -> str:
    if group == "network-operator":
        return "read-only (network-operator)"
    if group == "network-admin":
        return "read-write (network-admin)"
    return group or "unknown"


def _peer_status(peer: NtpPeer | None) -> str:
    if peer is None:
        return "not reported"
    words = (
        "the clock follows it"
        if peer.synced
        else "reachable"
        if peer.reach
        not in (
            "",
            "0",
        )
        else "not reached yet"
    )
    details = ", ".join(
        part
        for part in (
            f"stratum {peer.stratum}" if peer.stratum else "",
            f"reach {peer.reach}" if peer.reach else "",
            f"delay {peer.delay}" if peer.delay else "",
        )
        if part
    )
    return f"{words} ({details})" if details else words


SWITCH_ADMIN = Protocol(
    key="switch-admin",
    name="Switch admin",
    summary="The switch's name, clock and NTP, DNS, logging, SNMP and login banner",
    features=(),
    commands=COMMANDS,
    parse=parse_switch_admin,
    scopes=(SYSTEM, NTP_SERVER, NAME_SERVER, CONTEXT_NAME_SERVER, LOG_SERVER, SNMP_HOST),
    about="Settings for the whole switch come first, then its NTP, DNS and logging servers "
    "and SNMP trap receivers. The switch's own log is on the Switch log page.",
)


@dataclass(frozen=True)
class SwitchAdminPage:
    """Everything the Switch admin page shows."""

    protocol: Protocol
    view: ProtocolView
    vrfs: tuple[str, ...]  # default, management, then the others
    problem: str = ""
    missing: tuple[str, ...] = ()  # needs no feature; kept for the template


def vrf_choices(vrf_body: dict[str, Any]) -> tuple[str, ...]:
    """The VRFs in ``show vrf`` (``routing.parse_vrfs``: default, management, then the
    others), with default and management always there."""
    names = [v.name for v in parse_vrfs(vrf_body, {})]
    extra = [n for n in (DEFAULT_VRF, "management") if n not in names]
    return (*extra, *names) if extra else tuple(names)


def load_switch_admin_page(client: NxapiClient) -> SwitchAdminPage:
    """One request for the reads, one for NTP, one for the configuration text."""
    bodies = client.show(*COMMANDS)
    try:
        (ntp_body,) = client.show(NTP_COMMAND)
    except NxapiCommandError:
        ntp_body = None
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = None  # the role predates the rule that allows it
    view = parse_switch_admin(bodies, ntp_body, config)
    return SwitchAdminPage(SWITCH_ADMIN, view, vrf_choices(bodies[2]))


def build_admin_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Switch admin page."""
    return build_change(SWITCH_ADMIN, scope, setting, action, ident, values)


# ---- the switch's log ---------------------------------------------------------------


def log_command(lines: int) -> str:
    """``show logging last <n>`` for one of ``LOG_LINES``."""
    if lines not in LOG_LINES:
        raise ValueError(f"the log shows {', '.join(map(str, LOG_LINES))} lines")
    return validate_show_command(f"show logging last {lines}")


_SEVERITY = re.compile(r"%[A-Z0-9_]+-(\d)-[A-Z0-9_]+:")


@dataclass(frozen=True)
class LogLine:
    """One line of the switch's log, newest first on the page."""

    text: str
    severity: int | None  # 0-7 from "%FACILITY-5-MNEMONIC:", None when it has none


def parse_log(output: str, search: str = "", worst: int | None = None) -> list[LogLine]:
    """The log's lines, newest first: those containing ``search`` (any case) and, when
    ``worst`` is given, of that severity or more urgent."""
    needle = search.strip().lower()
    found = []
    for raw in output.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        match = _SEVERITY.search(line)
        severity = int(match.group(1)) if match else None
        if needle and needle not in line.lower():
            continue
        if worst is not None and (severity is None or severity > worst):
            continue
        found.append(LogLine(line, severity))
    found.reverse()
    return found


def load_switch_log(client: NxapiClient, lines: int) -> str:
    """The last ``lines`` lines of the switch's log file, as the switch prints them."""
    return client.show_text(log_command(lines))
