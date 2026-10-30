"""Port-channels and LACP: reading them, and the checked changes the pages offer.

A port-channel bundles several ports into one link that both ends treat as
one. With LACP (``mode active`` or ``passive``) the two ends agree on it and
leave out a port that is cabled wrong; a static one (``mode on``) just
bundles. Read from show output recorded on cisco-25gb:

- ``show port-channel summary``: every port-channel, LACP or not, up or
  down, and each member's state letter (P up in the channel, D down, I on
  its own, s suspended, H hot standby, ...);
- ``show port-channel database``: each member's mode (active, passive, on);
- ``show interface description``: the port-channels' descriptions;
- ``show interface brief``: the front ports, and which are turned off;
- while the lacp feature is on (every ``show lacp`` command is "% Invalid
  command" while it is off, so these go in a second request):
  ``show lacp system-identifier`` (the switch's LACP priority), ``show lacp
  interface`` (each port's LACP rate and port priority) and ``show lacp
  neighbor`` (the device at the other end of each member).

A port-channel's LACP minimum links is shown nowhere NXray's account can
read (only ``show running-config``, which its role may not run), so the
form for it has no current value.

The commands themselves are built by ``NxapiClient`` (``join_port_channel``,
``leave_port_channel``, ``delete_port_channel``, ``configure_port_channel``,
``set_port_lacp``, ``set_lacp_system_priority``) from checked values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.neighbors import feature_enabled
from app.nxapi import (
    CHANNEL_MODES,
    LACP_RATES,
    NxapiClient,
    validate_channel_number,
    validate_description,
    validate_lacp_priority,
    validate_min_links,
    validate_port_name,
)
from app.oui import format_mac, mac_maker
from app.ports import port_sort_key
from app.switch import rows

CHANNEL_COMMANDS = (
    "show feature",
    "show port-channel summary",
    "show port-channel database",
    "show interface description",
    "show interface brief",
)
LACP_COMMANDS = ("show lacp system-identifier", "show lacp interface", "show lacp neighbor")

# The switch's LACP priority when nobody set one.
DEFAULT_SYSTEM_PRIORITY = 32768
DEFAULT_PORT_PRIORITY = 32768

# The member state letters of ``show port-channel summary``, in words.
MEMBER_STATES = {
    "P": "up in the port-channel",
    "D": "down",
    "I": "on its own (not bundled)",
    "H": "standby",
    "s": "suspended",
    "r": "module removed",
    "p": "up, waiting for LACP",
}

MODE_WORDS = {
    "active": "LACP, active",
    "passive": "LACP, passive",
    "on": "static (no LACP)",
}

_CHANNEL_NAME = re.compile(r"^port-channel(\d+)$")

CONFIG_MUST_MATCH = (
    "Ports in one port-channel must have the same settings (access or trunk, VLANs, speed, "
    "MTU, flow control); the switch refuses a port that differs. The first port's settings "
    "become the port-channel's."
)


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _priority(value: Any) -> int | None:
    """``0x8000`` or ``32768`` -> 32768; None when there is no number."""
    text = _text(value)
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


@dataclass(frozen=True)
class Partner:
    """The device at the other end of a member port, as LACP reports it."""

    mac: str  # aa:bb:cc:dd:ee:ff
    system_priority: int | None
    port_number: str  # its own number for the port, "0x2"
    flags: str  # "FA": F fast or S slow, A active or P passive

    @property
    def maker(self) -> str:
        return mac_maker(self.mac)

    @property
    def words(self) -> str:
        parts = []
        if "A" in self.flags:
            parts.append("active")
        elif "P" in self.flags:
            parts.append("passive")
        if "F" in self.flags:
            parts.append("fast rate")
        elif "S" in self.flags:
            parts.append("normal rate")
        return ", ".join(parts)


@dataclass(frozen=True)
class Member:
    port: str  # "Ethernet1/43"
    state: str  # the summary's letter: P, D, I, ...
    mode: str  # active, passive or on; "" when the switch did not say
    rate: str | None = None  # normal or fast, while LACP is on
    port_priority: int | None = None
    partner: Partner | None = None

    @property
    def state_words(self) -> str:
        return MEMBER_STATES.get(self.state, self.state or "unknown")

    @property
    def bundled(self) -> bool:
        return self.state == "P"


@dataclass(frozen=True)
class Channel:
    number: int
    protocol: str  # "LACP" or "NONE"
    up: bool
    routed: bool
    description: str
    members: tuple[Member, ...]

    @property
    def name(self) -> str:
        return f"port-channel{self.number}"

    @property
    def mode(self) -> str:
        """The mode its members joined with (the switch keeps them alike); "" when empty."""
        return next((m.mode for m in self.members if m.mode), "")

    @property
    def lacp(self) -> bool:
        return self.protocol.upper() == "LACP" or self.mode in ("active", "passive")

    @property
    def member_names(self) -> list[str]:
        return [m.port for m in self.members]

    def member(self, port: str) -> Member | None:
        return next((m for m in self.members if m.port == port), None)


@dataclass(frozen=True)
class ChannelView:
    channels: list[Channel] = field(default_factory=list)
    lacp_enabled: bool = False
    system_priority: int | None = None
    system_mac: str = ""
    front_ports: list[str] = field(default_factory=list)
    turned_off: frozenset[str] = frozenset()
    up_ports: frozenset[str] = frozenset()

    def channel(self, number: int) -> Channel | None:
        return next((c for c in self.channels if c.number == number), None)

    def channel_of(self, port: str) -> Channel | None:
        return next((c for c in self.channels if port in c.member_names), None)

    @property
    def free_ports(self) -> list[str]:
        """Front ports in no port-channel, which can join one."""
        taken = {port for c in self.channels for port in c.member_names}
        return [port for port in self.front_ports if port not in taken]


# ---- reading ----------------------------------------------------------------


def _channel_number(name: str, group: Any = None) -> int | None:
    match = _CHANNEL_NAME.match(_text(name))
    if match:
        return int(match.group(1))
    text = _text(group)
    return int(text) if text.isdigit() else None


def parse_modes(database_body: dict[str, Any]) -> dict[str, str]:
    """Port -> how it joined (active, passive, on), from ``show port-channel database``."""
    modes = {}
    for channel in rows(database_body, "TABLE_interface", "ROW_interface"):
        for member in rows(channel, "TABLE_member", "ROW_member"):
            modes[_text(member.get("port"))] = _text(member.get("mode")).lower()
    return modes


def parse_descriptions(description_body: dict[str, Any]) -> dict[str, str]:
    """Interface -> description, from ``show interface description``."""
    return {
        _text(row.get("interface")): _text(row.get("desc"))
        for row in rows(description_body, "TABLE_interface", "ROW_interface")
        if _text(row.get("desc"))
    }


def parse_brief(
    brief_body: dict[str, Any],
) -> tuple[list[str], frozenset[str], frozenset[str], set[str]]:
    """(front ports in panel order, those turned off, those up, routed port-channels)
    from ``show interface brief``."""
    ports = []
    off = set()
    up = set()
    routed = set()
    for row in rows(brief_body, "TABLE_interface", "ROW_interface"):
        name = _text(row.get("interface"))
        if name.startswith("port-channel") and _text(row.get("portmode")).lower() == "routed":
            routed.add(name)
        try:
            validate_port_name(name)
        except ValueError:
            continue
        ports.append(name)
        if "administratively down" in _text(row.get("state_rsn_desc")).lower():
            off.add(name)
        if _text(row.get("state")).lower() == "up":
            up.add(name)
    return sorted(ports, key=port_sort_key), frozenset(off), frozenset(up), routed


def parse_lacp_ports(lacp_interface_body: dict[str, Any]) -> dict[str, tuple[str, int | None]]:
    """Port -> (LACP rate, port priority), from ``show lacp interface``.

    The switch writes the rate as the timeout it gives the other end: "Long"
    for normal (every 30 seconds), "Short" for fast (every second).
    """
    found = {}
    for row in rows(lacp_interface_body, "TABLE_lacp_intf", "ROW_lacp_intf"):
        local = row.get("localport") if isinstance(row.get("localport"), dict) else {}
        timeout = _text(local.get("local-timeout")).lower()
        rate = "fast" if timeout == "short" else "normal"
        found[_text(row.get("interface"))] = (rate, _priority(local.get("local-port-priority")))
    return found


def parse_partners(lacp_neighbor_body: dict[str, Any]) -> dict[str, Partner]:
    """Port -> the device at its other end, from ``show lacp neighbor``.

    ``partner-system-id`` is written "<priority>,<mac>" ("65535,b8-59-9f-00-00-0e").
    """
    found = {}
    for channel in rows(lacp_neighbor_body, "TABLE_interface", "ROW_interface"):
        for member in rows(channel, "TABLE_member", "ROW_member"):
            priority, _, mac = _text(member.get("partner-system-id")).partition(",")
            if not mac or set(mac) <= set("0-"):
                continue
            found[_text(member.get("port"))] = Partner(
                mac=format_mac(mac),
                system_priority=_priority(priority),
                port_number=_text(member.get("partner-port-num")),
                flags=_text(member.get("partner-flags")),
            )
    return found


def parse_channels(
    summary_body: dict[str, Any],
    modes: dict[str, str],
    descriptions: dict[str, str],
    routed: set[str],
    lacp_ports: dict[str, tuple[str, int | None]] | None = None,
    partners: dict[str, Partner] | None = None,
) -> list[Channel]:
    """The port-channels in ``show port-channel summary``, with what the other
    commands add, in number order."""
    found = []
    for row in rows(summary_body, "TABLE_channel", "ROW_channel"):
        number = _channel_number(row.get("port-channel"), row.get("group"))
        if number is None:
            continue
        members = []
        for member in rows(row, "TABLE_member", "ROW_member"):
            port = _text(member.get("port"))
            if not port:
                continue
            rate, priority = (lacp_ports or {}).get(port, (None, None))
            mode = modes.get(port, "")
            if mode == "on":
                rate, priority = None, None
            members.append(
                Member(
                    port=port,
                    state=_text(member.get("port-status")),
                    mode=mode,
                    rate=rate,
                    port_priority=priority,
                    partner=(partners or {}).get(port),
                )
            )
        name = f"port-channel{number}"
        found.append(
            Channel(
                number=number,
                protocol=_text(row.get("prtcl")).upper() or "NONE",
                up=_text(row.get("status")).upper().startswith("U"),
                routed=name in routed or _text(row.get("layer")).upper() == "R",
                description=descriptions.get(name, ""),
                members=tuple(sorted(members, key=lambda m: port_sort_key(m.port))),
            )
        )
    return sorted(found, key=lambda c: c.number)


def load_channels(client: NxapiClient) -> ChannelView:
    """Everything the Port-channels page shows: one request, plus one for LACP while it is on."""
    feature, summary, database, descriptions, brief = client.show(*CHANNEL_COMMANDS)
    lacp_on = feature_enabled(feature, "lacp")
    ports, off, up, routed = parse_brief(brief)
    lacp_ports: dict[str, tuple[str, int | None]] = {}
    partners: dict[str, Partner] = {}
    system_priority = None
    system_mac = ""
    if lacp_on:
        identifier, interfaces, neighbors = client.show(*LACP_COMMANDS)
        system_priority = _priority(identifier.get("system-priority"))
        system_mac = format_mac(_text(identifier.get("system-mac")))
        lacp_ports = parse_lacp_ports(interfaces)
        partners = parse_partners(neighbors)
    channels = parse_channels(
        summary, parse_modes(database), parse_descriptions(descriptions), routed, lacp_ports,
        partners,
    )  # fmt: skip
    return ChannelView(
        channels=channels,
        lacp_enabled=lacp_on,
        system_priority=system_priority,
        system_mac=system_mac,
        front_ports=ports,
        turned_off=off,
        up_ports=up,
    )


# ---- changes ------------------------------------------------------------------


def _number(text: str) -> int:
    cleaned = text.strip()
    if cleaned.lower().startswith("port-channel"):
        cleaned = cleaned[len("port-channel") :]
    elif cleaned.lower().startswith("po"):
        cleaned = cleaned[2:]
    return validate_channel_number(cleaned)


def _existing(view: ChannelView, text: str) -> Channel:
    number = _number(text)
    channel = view.channel(number)
    if channel is None:
        raise ValueError(f"the switch has no port-channel{number}")
    return channel


def _check_mode(view: ChannelView, mode: str) -> None:
    if mode not in CHANNEL_MODES:
        raise ValueError("choose LACP active, LACP passive or static")
    if mode != "on" and not view.lacp_enabled:
        raise ValueError(
            "LACP is off on the switch, so only a static port-channel can be made; an NXray "
            "admin turns LACP on on the Features page"
        )


def _check_free_ports(view: ChannelView, ports: list[str]) -> list[str]:
    if not ports:
        raise ValueError("choose at least one port")
    chosen = []
    for port in ports:
        if port not in view.front_ports:
            raise ValueError(f"{port!r} is not one of the switch's front ports")
        channel = view.channel_of(port)
        if channel is not None:
            raise ValueError(f"{port} is already in {channel.name}; take it out there first")
        if port not in chosen:
            chosen.append(port)
    return sorted(chosen, key=port_sort_key)


@dataclass(frozen=True)
class Join:
    """Ports joining a port-channel (a new one, or one that exists)."""

    number: int
    ports: tuple[str, ...]
    mode: str
    fast_rate: bool = False
    description: str | None = None


def _join_warnings(ports: list[str], mode: str, up: list[str]) -> list[str]:
    warnings = [CONFIG_MUST_MATCH]
    if up:
        warnings.append(
            f"{', '.join(up)} {'is' if len(up) == 1 else 'are'} up now: the link drops for a "
            "moment while it joins, and stays out of the bundle until the device on the "
            "other end bundles its ports too."
        )
    if mode == "on":
        warnings.append(
            "A static port-channel does not check the other end: if the device there has "
            "not bundled the same ports, traffic can be lost or loop."
        )
    return warnings


def plan_create(
    view: ChannelView,
    *,
    number: str,
    ports: list[str],
    mode: str,
    fast_rate: bool,
    description: str,
) -> tuple[Join, list[str], list[str]]:
    """A new port-channel from free ports."""
    channel_number = _number(number)
    if view.channel(channel_number) is not None:
        raise ValueError(f"port-channel{channel_number} exists already; add ports to it instead")
    _check_mode(view, mode)
    if fast_rate and mode == "on":
        raise ValueError("a static port-channel sends no LACP, so it has no LACP rate")
    chosen = _check_free_ports(view, ports)
    text = validate_description(description)
    join = Join(channel_number, tuple(chosen), mode, fast_rate, text or None)
    lines = [
        f"Make port-channel{channel_number} ({MODE_WORDS[mode]}) from {', '.join(chosen)}.",
    ]
    if fast_rate:
        lines.append("The ports send LACP messages every second (fast rate) instead of every 30.")
    if text:
        lines.append(f'Describe port-channel{channel_number} as "{text}".')
    up = [port for port in chosen if port in view.up_ports]
    return join, lines, _join_warnings(chosen, mode, up)


def plan_add(
    view: ChannelView,
    *,
    number: str,
    port: str,
    mode: str,
    fast_rate: bool,
) -> tuple[Join, list[str], list[str]]:
    """One free port joining an existing port-channel, with the mode its ports use."""
    channel = _existing(view, number)
    if channel.mode and mode != channel.mode:
        raise ValueError(
            f"the ports of {channel.name} joined as {MODE_WORDS[channel.mode]}; a new port "
            "must join the same way"
        )
    _check_mode(view, mode)
    if fast_rate and mode == "on":
        raise ValueError("a static port-channel sends no LACP, so it has no LACP rate")
    (chosen,) = _check_free_ports(view, [port])
    join = Join(channel.number, (chosen,), mode, fast_rate)
    lines = [f"Add {chosen} to {channel.name} ({MODE_WORDS[mode]})."]
    if fast_rate:
        lines.append(f"{chosen} sends LACP messages every second (fast rate).")
    up = [chosen] if chosen in view.up_ports else []
    return join, lines, _join_warnings([chosen], mode, up)


def plan_remove(view: ChannelView, *, port: str) -> tuple[str, list[str], list[str]]:
    """Taking a port out of its port-channel; (port, lines, warnings)."""
    name = port.strip()
    channel = view.channel_of(name)
    if channel is None:
        raise ValueError(f"{name or 'that port'} is in no port-channel")
    lines = [
        f"Take {name} out of {channel.name}.",
        f"{name} keeps its own settings and works as a separate port again.",
    ]
    warnings = []
    member = channel.member(name)
    if member is not None and member.bundled:
        warnings.append(
            f"{name} carries traffic for {channel.name} now: that traffic moves to its other "
            "ports, and the device on the other end may still treat this link as part of its "
            "bundle until it is changed there too."
        )
    if len(channel.members) == 1:
        warnings.append(
            f"It is the last port of {channel.name}: the port-channel stays, empty and down, "
            "until it is deleted."
        )
    return name, lines, warnings


def plan_delete(view: ChannelView, *, number: str) -> tuple[int, list[str], list[str]]:
    """Deleting a port-channel; refused while it has ports (NXray's rule, not the switch's)."""
    channel = _existing(view, number)
    if channel.members:
        raise ValueError(
            f"{channel.name} still has {', '.join(channel.member_names)}; take "
            f"{'it' if len(channel.members) == 1 else 'them'} out first"
        )
    return channel.number, [f"Delete {channel.name}."], []


@dataclass(frozen=True)
class ChannelSettings:
    number: int
    description: str | None = None  # "" removes it
    min_links: int | None = None


def plan_channel_settings(
    view: ChannelView, *, number: str, description: str, min_links: str
) -> tuple[ChannelSettings, list[str], list[str]]:
    """A port-channel's description and LACP minimum links; an empty minimum keeps it."""
    channel = _existing(view, number)
    text = validate_description(description)
    new_description = text if text != channel.description else None
    links = None
    if min_links.strip():
        if not channel.lacp:
            raise ValueError("a minimum number of links needs LACP; this port-channel is static")
        links = validate_min_links(min_links)
    if new_description is None and links is None:
        raise ValueError("nothing to change")
    lines = []
    warnings = []
    if new_description is not None:
        before = channel.description or "none"
        lines.append(
            f'Change the description of {channel.name} from "{before}" to "{text or "none"}".'
        )
    if links is not None:
        lines.append(f"Keep {channel.name} up only while at least {links} of its ports are up.")
        bundled = sum(1 for m in channel.members if m.bundled)
        if links > bundled:
            warnings.append(
                f"Only {bundled} of its ports {'is' if bundled == 1 else 'are'} up in it now, so "
                f"{channel.name} goes down until {links} are."
            )
    return ChannelSettings(channel.number, new_description, links), lines, warnings


@dataclass(frozen=True)
class PortLacp:
    port: str
    rate: str | None = None
    priority: int | None = None


def plan_port_lacp(
    view: ChannelView, *, port: str, rate: str, priority: str
) -> tuple[PortLacp, list[str], list[str]]:
    """A member's LACP rate and port priority; only what differs is sent.

    The switch changes the rate of a port in a port-channel only while the
    port is turned off (found by trying it), so NXray says so first.
    """
    name = port.strip()
    channel = view.channel_of(name)
    member = channel.member(name) if channel else None
    if channel is None or member is None:
        raise ValueError(f"{name or 'that port'} is in no port-channel")
    if not view.lacp_enabled or member.mode == "on":
        raise ValueError(f"{name} does not use LACP, so it has no LACP settings")
    if rate not in LACP_RATES:
        raise ValueError("choose a normal or fast LACP rate")
    new_rate = rate if rate != (member.rate or "normal") else None
    new_priority = None
    if priority.strip():
        value = validate_lacp_priority(priority)
        current = (
            member.port_priority if member.port_priority is not None else DEFAULT_PORT_PRIORITY
        )
        new_priority = value if value != current else None
    if new_rate is None and new_priority is None:
        raise ValueError("nothing to change")
    if new_rate is not None and name not in view.turned_off:
        raise ValueError(
            f"the switch changes the LACP rate of a port in a port-channel only while the port "
            f"is off: turn {name} off on its page, change the rate, then turn it on again"
        )
    lines = []
    if new_rate is not None:
        every = "every second" if new_rate == "fast" else "every 30 seconds"
        lines.append(f"{name} sends LACP messages {every} ({new_rate} rate).")
    if new_priority is not None:
        lines.append(
            f"Set the LACP port priority of {name} to {new_priority} (lower wins: when "
            f"{channel.name} has more ports than it can use, the lower ones are used first)."
        )
    return PortLacp(name, new_rate, new_priority), lines, []


def plan_system_priority(view: ChannelView, text: str) -> tuple[int, list[str], list[str]]:
    """The switch's LACP priority, for every port-channel at once."""
    if not view.lacp_enabled:
        raise ValueError(
            "LACP is off on the switch; an NXray admin turns it on on the Features page"
        )
    value = validate_lacp_priority(text)
    current = view.system_priority if view.system_priority is not None else DEFAULT_SYSTEM_PRIORITY
    if value == current:
        raise ValueError(f"the switch's LACP priority is {current} already")
    lines = [
        f"Set the switch's LACP priority to {value} (now {current}; lower wins). With it, the "
        "end with the lower priority decides which ports of a bundle are used.",
        "This is for the whole switch, every LACP port-channel.",
    ]
    lacp_channels = [c.name for c in view.channels if c.lacp and c.members]
    warnings = []
    if lacp_channels:
        warnings.append(
            f"Every LACP port-channel ({', '.join(lacp_channels)}) agrees on its ports again with "
            "the device at the other end: its traffic can stop for a moment."
        )
    return value, lines, warnings
