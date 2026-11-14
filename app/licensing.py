"""Smart Licensing: what the switch's licences are and whether it is registered with Cisco.

The page shows ``show license usage`` (the table of licence features, which the switch
prints with or without Smart Licensing) and, while Smart Licensing is on, ``show license
summary`` (whether the switch is registered, what it may export and how licences are
authorised) and ``show license udi`` (the model and serial number Cisco knows it by).

The one setting is ``license smart reservation``, in the same description as the Monitor
sessions page (``app/protocols.py``), sent by ``NxapiClient.configure_licensing``. Smart
Licensing itself is turned on and off on the Features page (``feature license smart``).

Tried on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-13), turned on and off again,
nothing saved: ``license smart enable`` turns on ``feature license smart`` and, as a side
effect the switch does itself, writes a Call Home section (``email-contact
sch-smart-licensing@cisco.com``, the CiscoTAC-1 profile over http and ``transport http
use-vrf management``) that ``no license smart enable`` leaves behind: it has to be removed
line by line. ``license smart reservation`` is taken and refused to be removed while ``no
license smart enable`` is typed first. ``feature license-smart`` and every other ``license
smart`` line (``transport``, ``url``, ``proxy``, ``priority``, ``conversion``) are "%
Invalid command"; only ``license smart enable`` and ``license smart reservation`` exist
in configuration mode. ``show license summary`` and ``status`` are "% Invalid command" until
it is on. Registering with a token, renewing and deregistering are commands typed outside
configuration mode and need a Cisco account to try: none is offered.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.features import feature_states
from app.nxapi import NxapiClient, NxapiCommandError
from app.protocols import (
    Instance,
    Protocol,
    ProtocolChange,
    ProtocolView,
    Scope,
    Setting,
    Table,
    build_change,
)

FEATURE = "license-smart"  # as show feature names it; the command is license smart enable
USAGE_COMMAND = "show license usage"
SUMMARY_COMMAND = "show license summary"
UDI_COMMAND = "show license udi"
CONFIG_COMMAND = "show running-config | section license"

_SMART = Scope(
    key="smart",
    label="Smart Licensing",
    ident=(),
    enter=(),
    help="Remove puts a setting back to its default.",
    settings=(
        Setting(
            "reservation",
            "Licence reservation",
            "license smart reservation",
            group="Settings",
            help="Reserves licences for a switch that never talks to Cisco. Remove it before "
            "turning Smart Licensing off.",
        ),
    ),
)
SCOPES = (_SMART,)

SUMMARY_LABELS = (
    ("Smart Licensing", r"Smart Licensing is (\S+)"),
    ("Registration", r"Registration:\s*\n\s*Status:\s*(.+)"),
    ("Export-controlled features", r"Export-Controlled Functionality:\s*(.+)"),
    ("Licence authorization", r"License Authorization:\s*\n?\s*Status:\s*(.+)"),
)


def parse_summary(output: str | None) -> tuple[tuple[str, str], ...]:
    """``show license summary`` as (label, value) pairs; what it does not say is left out."""
    facts = []
    for label, pattern in SUMMARY_LABELS:
        if match := re.search(pattern, output or "", re.IGNORECASE):
            facts.append((label, match.group(1).strip()))
    return tuple(facts)


def parse_udi(output: str | None) -> str:
    """``show license udi`` as the text after ``UDI:`` (``PID:..., SN:...``), or ""."""
    match = re.search(r"UDI:\s*(.+)", output or "")
    return match.group(1).strip() if match else ""


def parse_usage(output: str | None) -> tuple[tuple[str, ...], ...]:
    """The rows of ``show license usage`` as (feature, installed, count, status, expiry and
    comments)."""
    rows = []
    for line in (output or "").splitlines():
        if match := re.fullmatch(r"(\S+)\s+(Yes|No)\s+(\S+)\s+(\S+)\s*(.*?)\s*", line):
            rows.append(tuple(cell or "-" for cell in match.groups()))
    return tuple(rows)


def parse_licensing(
    on: bool, usage: str | None, summary: str | None = None, udi: str | None = None,
    config: str | None = None,
) -> ProtocolView:  # fmt: skip
    """The page from the feature state and the text of each read (None: not read)."""
    rows = parse_usage(usage)
    tables = (
        Table(
            "Licence features",
            ("Feature", "Installed", "Count", "Status", "Expiry and comments"),
            rows,
            empty="The switch did not report its licences."
            if usage is None
            else "No licence feature.",
        ),
    )
    if not on:
        note = (
            "Smart Licensing is off on the switch. An NXray admin turns it on on the Features "
            "page (feature license smart). The switch then sets up Call Home to Cisco "
            "itself, as Cisco's guide says it must."
        )
        return ProtocolView((), tables, (note,))
    facts = list(parse_summary(summary))
    if identity := parse_udi(udi):
        facts.append(("Identity (UDI)", identity))
    values = (
        {"reservation": {}} if re.search(r"^license smart reservation$", config or "", re.M) else {}
    )
    instance = Instance("smart", {}, "Smart Licensing", tuple(facts), values)
    notes = []
    if config is None:
        notes.append(
            "The switch did not show its configuration to NXray's account: whether licences "
            "are reserved is not known."
        )
    return ProtocolView((instance,), tables, tuple(notes))


SMART_LICENSING = Protocol(
    key="licensing",
    name="Smart Licensing",
    summary="Licence use, and whether the switch is registered with Cisco",
    features=(),
    commands=(),
    parse=lambda bodies: parse_licensing(False, None),
    scopes=SCOPES,
    about=(
        "Smart Licensing reports the licences the switch uses to Cisco. Registering with a "
        "token, renewing and deregistering are done on the switch itself."
    ),
)


@dataclass(frozen=True)
class LicensingPage:
    """Everything the Smart Licensing page shows."""

    protocol: Protocol
    view: ProtocolView
    problem: str = ""
    missing: tuple[str, ...] = ()  # always empty: the usage table needs no feature
    # The scopes whose card is shown: none while Smart Licensing is off, as the switch
    # refuses its line then.
    shown_scopes: tuple[Scope, ...] = SCOPES


def _text(client: NxapiClient, command: str) -> str | None:
    try:
        return client.show_text(command)
    except NxapiCommandError:
        return None


def load_licensing_page(client: NxapiClient) -> LicensingPage:
    """``show feature`` and ``show license usage``; while Smart Licensing is on, its summary,
    UDI and the licence lines of the configuration."""
    (feature,) = client.show("show feature")
    on = feature_states(feature).get(FEATURE, False)
    usage = _text(client, USAGE_COMMAND)
    if not on:
        return LicensingPage(SMART_LICENSING, parse_licensing(False, usage), shown_scopes=())
    view = parse_licensing(
        True,
        usage,
        _text(client, SUMMARY_COMMAND),
        _text(client, UDI_COMMAND),
        _text(client, CONFIG_COMMAND),
    )
    return LicensingPage(SMART_LICENSING, view)


def check_licensing_place(page: LicensingPage, ident: dict[str, str]) -> None:
    """The page's one scope is the whole switch: nothing to check."""


def build_licensing_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Smart Licensing page."""
    return build_change(SMART_LICENSING, scope, setting, action, ident, values)
