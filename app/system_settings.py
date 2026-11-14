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
- ``ip icmp-errors source-interface`` is listed by ``show cli list`` but refused ("Syntax
  error"), so it is not here.
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
    ),
)

SCOPES = (_SYSTEM,)

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
                values[key] = dict(zip(names, match.groups(), strict=True))
    return values


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
    return ProtocolView((instance,), (), notes)


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
