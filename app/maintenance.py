"""Maintenance mode (graceful insertion and removal, GIR): the switch's mode, how maintenance
mode behaves, and snapshots of the switch's state to compare before and after.

Maintenance mode takes the switch out of the network so it can be worked on: its routing
protocols stop advertising it and its ports are shut. **NXray never puts the switch into or
out of maintenance mode** (``system mode maintenance``): that takes the switch off the
network, and the page says so. It shows the mode, the settings the mode runs by, the profiles
and the snapshots, and changes the settings and snapshots with the same parts as the Monitor
sessions page (``app/protocols.py``), sent by ``NxapiClient.configure_maintenance``.

Read from the switch (text): ``show system mode``, ``show maintenance timeout``, ``show
maintenance maint-delay``, ``show maintenance snapshot-delay``, ``show maintenance on-reload
reset-reasons``, ``show maintenance profile`` and ``show snapshots``.

Tried on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-13), everything put back, nothing
saved, maintenance mode never entered:

- ``system mode maintenance timeout <5-65535>`` (minutes; 0 means no timeout and is the
  default), ``snapshot-delay <0-65535>`` and ``maint-delay <0-65535>`` (seconds; 120 is the
  default for both), ``always-use-custom-profile`` and ``on-reload reset-reason <reason>``
  (HW_ERROR, SVC_FAILURE, KERN_FAILURE, WDOG_TIMEOUT, FATAL_ERROR, LC_FAILURE, MANUAL_RELOAD,
  MAINTENANCE): after a restart for that reason the switch starts in maintenance mode. The
  ``no`` forms of the three numbers need the value (a bare one is "% Incomplete command").
- ``snapshot create <name> <description>`` (name up to 64 characters, description up to 254)
  takes about six seconds, and ``snapshot delete <name>`` removes it. A created snapshot
  leaves a ``.snapshots`` folder on bootflash even after it is deleted. ``show snapshots
  compare <a> <b> summary`` prints a table of counts (interfaces, VLANs, routes) with a
  changed column. The full compare is some 300 lines; ``ipv4routes`` and ``ipv6routes`` need
  a snapshot section for routes, which NXray does not add.
- ``configure maintenance profile maintenance-mode`` does not open a profile over NX-API (the
  lines that follow go to the global configuration), so profiles are shown, not changed.
"""

from __future__ import annotations

import dataclasses
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
    Table,
    build_change,
)

MODE_COMMAND = "show system mode"
TIMEOUT_COMMAND = "show maintenance timeout"
MAINT_DELAY_COMMAND = "show maintenance maint-delay"
SNAPSHOT_DELAY_COMMAND = "show maintenance snapshot-delay"
REASONS_COMMAND = "show maintenance on-reload reset-reasons"
PROFILE_COMMAND = "show maintenance profile"
SNAPSHOTS_COMMAND = "show snapshots"

REASONS = (
    "HW_ERROR",
    "SVC_FAILURE",
    "KERN_FAILURE",
    "WDOG_TIMEOUT",
    "FATAL_ERROR",
    "LC_FAILURE",
    "MANUAL_RELOAD",
    "MAINTENANCE",
)
SNAPSHOT_NAME_MAX = 64
SNAPSHOT_DESCRIPTION_MAX = 254
# ``snapshot create`` took about six seconds on cisco-25gb; the wait leaves room.
SNAPSHOT_WAIT = 60.0

# The scopes whose commands are typed outside configuration mode (SNAPSHOT_RULES).
EXEC_SCOPES = ("snapshot", "compare")

_ENTER = "system mode maintenance"

_MODE = Scope(
    key="mode",
    label="How maintenance mode behaves",
    ident=(),
    enter=(),
    help=(
        "Remove puts a setting back to its default. These change how maintenance mode runs "
        "once someone starts it at the switch; NXray does not start it."
    ),
    settings=(
        Setting(
            "timeout",
            "Time limit",
            f"{_ENTER} timeout {{minutes}}",
            (Field("minutes", "Minutes", "int", 5, 65535, hint="5 to 65535; none is the default"),),
            group="Timing",
            help="The switch leaves maintenance mode by itself after this long.",
        ),
        Setting(
            "maint_delay",
            "Wait before the command line is back",
            f"{_ENTER} maint-delay {{seconds}}",
            (Field("seconds", "Seconds", "int", 0, 65535, hint="Default 120"),),
            group="Timing",
            help="How long the switch holds the command line after entering maintenance mode.",
        ),
        Setting(
            "snapshot_delay",
            "Wait before the after-snapshot",
            f"{_ENTER} snapshot-delay {{seconds}}",
            (Field("seconds", "Seconds", "int", 0, 65535, hint="Default 120"),),
            group="Timing",
            help="How long the switch waits after leaving maintenance mode before it takes "
            "its after-maintenance snapshot.",
        ),
        Setting(
            "custom_profile",
            "Always use the custom profile",
            f"{_ENTER} always-use-custom-profile",
            group="Profile",
            help="Use the maintenance profile as written, not one the switch generates.",
        ),
        Setting(
            "reload_reason",
            "Start in maintenance mode after a restart for",
            f"{_ENTER} on-reload reset-reason {{reason}}",
            (Field("reason", "Reason", "choice", choices=REASONS),),
            group="After a restart",
            warning=(
                "After a restart for this reason the switch starts in maintenance mode: off "
                "the network until someone ends it at the switch."
            ),
            help="A restart for this reason leaves the switch in maintenance mode.",
        ),
    ),
)

_SNAPSHOT = Scope(
    key="snapshot",
    label="Snapshots",
    ident=(
        Field("name", "Name", "name", maximum=SNAPSHOT_NAME_MAX, hint="Letters, digits, . _ and -"),
        Field(
            "description",
            "Description",
            "text",
            maximum=SNAPSHOT_DESCRIPTION_MAX,
            hint="Up to 254 characters",
        ),
    ),
    enter=("snapshot create {name} {description}",),
    create=True,
    create_label="Take a snapshot",
    delete=("snapshot delete {name}",),
    delete_warning="The snapshot is gone from the switch's bootflash.",
    help=(
        "A snapshot keeps the switch's interfaces, VLANs and routes as they are now, to "
        "compare with another later. Taking one takes a few seconds."
    ),
)

_COMPARE = Scope(
    key="compare",
    label="Compare two snapshots",
    ident=(),
    enter=(),
    help="Counts of interfaces, VLANs and routes in each snapshot, with what changed.",
    settings=(
        Setting(
            "summary",
            "Compare",
            "show snapshots compare {first} {second} summary",
            (
                Field("first", "Snapshot taken first", "name", maximum=SNAPSHOT_NAME_MAX),
                Field("second", "Snapshot taken second", "name", maximum=SNAPSHOT_NAME_MAX),
            ),
            removable=False,
            config=False,
            button="Compare",
            group="Compare",
        ),
    ),
)

SCOPES = (_MODE, _SNAPSHOT, _COMPARE)


# ---- reading ---------------------------------------------------------------------

_MODE_LINE = re.compile(r"System Mode:\s*(\S+)")
_TIMEOUT = re.compile(r"timeout value:\s*(\d+) minutes?")
_DELAY = re.compile(r"delay (default )?value:\s*(\d+) seconds?")
_SNAPSHOT_LINE = re.compile(r"^(\S+)\s+((?:\w{3}\s+){2}\d+\s+\d\d:\d\d:\d\d\s+\d{4})\s*(.*?)\s*$")
_PROFILE_HEAD = re.compile(r"^\[(.+)\]\s*$")


def parse_mode(output: str | None) -> str:
    """The switch's mode: ``Normal``, ``Maintenance`` ... or "" when not read."""
    match = _MODE_LINE.search(output or "")
    return match.group(1) if match else ""


def parse_reasons(output: str | None) -> list[str]:
    """The reset reasons that start the switch in maintenance mode, from ``show maintenance
    on-reload reset-reasons``."""
    return [line.strip() for line in (output or "").splitlines() if line.strip() in REASONS]


def parse_profiles(output: str | None) -> list[tuple[str, str]]:
    """The profiles of ``show maintenance profile``: (name, its lines) in the order shown."""
    found: list[tuple[str, list[str]]] = []
    for line in (output or "").splitlines():
        if match := _PROFILE_HEAD.match(line):
            found.append((match.group(1), []))
        elif found and line.strip():
            found[-1][1].append(line.strip())
    return [(name, "; ".join(lines)) for name, lines in found]


def parse_snapshots(output: str | None) -> list[tuple[str, str, str]]:
    """The rows of ``show snapshots``: (name, time, description)."""
    rows = []
    for line in (output or "").splitlines():
        if line.startswith("Snapshot Name") or set(line.strip()) <= {"-"}:
            continue
        if match := _SNAPSHOT_LINE.match(line):
            rows.append((match.group(1), " ".join(match.group(2).split()), match.group(3)))
    return rows


def parse_maintenance(
    mode: str | None,
    timeout: str | None,
    maint_delay: str | None,
    snapshot_delay: str | None,
    reasons: str | None,
    profiles: str | None,
    snapshots: str | None,
) -> ProtocolView:
    """The page from the text of each read (None: not read)."""
    values: dict[str, dict[str, str]] = {}
    if (match := _TIMEOUT.search(timeout or "")) and int(match.group(1)) > 0:
        values["timeout"] = {"minutes": match.group(1)}
    for key, text in (("maint_delay", maint_delay), ("snapshot_delay", snapshot_delay)):
        if (match := _DELAY.search(text or "")) and not match.group(1):
            values[key] = {"seconds": match.group(2)}
    now = parse_reasons(reasons)
    state = parse_mode(mode)
    facts = [("System mode", state or "not read")]
    if timeout is not None and (match := _TIMEOUT.search(timeout)):
        facts.append(("Time limit", f"{match.group(1)} minutes" if int(match.group(1)) else "none"))
    for label, text in (
        ("After entering, command line held", maint_delay),
        ("After leaving, snapshot taken after", snapshot_delay),
    ):
        if match := _DELAY.search(text or ""):
            facts.append((label, f"{match.group(2)} seconds"))
    if reasons is not None:
        facts.append(
            ("Starts in maintenance mode after a restart for", ", ".join(now) or "no reason")
        )
    instances = [Instance("mode", {}, "Maintenance mode", tuple(facts), values)]
    instances += [
        Instance(
            "snapshot",
            {"name": name, "description": description},
            name,
            (("Taken", taken), ("Description", description or "none")),
        )
        for name, taken, description in parse_snapshots(snapshots)
    ]
    tables = []
    rows = parse_profiles(profiles)
    if rows:
        tables.append(
            Table(
                "Profiles",
                ("Profile", "Lines"),
                tuple((name, lines or "empty") for name, lines in rows),
                note="A profile is the commands the switch runs going into and out of "
                "maintenance mode. NXray shows them; it cannot change them.",
            )
        )
    notes = [
        "NXray does not put the switch into or out of maintenance mode: that takes it off "
        "the network. Do it at the switch (system mode maintenance)."
    ]
    if state and state != "Normal":
        notes.insert(0, f"The switch is in {state} mode now.")
    unread = [
        name
        for name, text in (("mode", mode), ("settings", timeout), ("snapshots", snapshots))
        if text is None
    ]
    if unread:
        notes.append(f"The switch did not show its {', '.join(unread)} to NXray's account.")
    return ProtocolView(tuple(instances), tuple(tables), tuple(notes))


MAINTENANCE = Protocol(
    key="maintenance",
    name="Maintenance mode",
    summary="The switch's mode, how maintenance mode behaves, and snapshots to compare",
    features=(),
    commands=(),
    parse=lambda bodies: parse_maintenance(None, None, None, None, None, None, None),
    scopes=SCOPES,
    about=(
        "Maintenance mode takes the switch out of the network so it can be worked on. Take a "
        "snapshot before and after, then compare them to see what changed."
    ),
)


@dataclass(frozen=True)
class MaintenancePage:
    """Everything the Maintenance mode page shows."""

    protocol: Protocol
    view: ProtocolView
    problem: str = ""
    missing: tuple[str, ...] = ()  # always empty: maintenance mode has no feature


def _text(client: NxapiClient, command: str) -> str | None:
    try:
        return client.show_text(command)
    except NxapiCommandError:
        return None


def load_maintenance_page(client: NxapiClient) -> MaintenancePage:
    """The seven text reads."""
    view = parse_maintenance(
        _text(client, MODE_COMMAND),
        _text(client, TIMEOUT_COMMAND),
        _text(client, MAINT_DELAY_COMMAND),
        _text(client, SNAPSHOT_DELAY_COMMAND),
        _text(client, REASONS_COMMAND),
        _text(client, PROFILE_COMMAND),
        _text(client, SNAPSHOTS_COMMAND),
    )
    return MaintenancePage(MAINTENANCE, view)


def check_maintenance_place(page: MaintenancePage, ident: dict[str, str]) -> None:
    """Every scope is the whole switch: nothing to check."""


def build_maintenance_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Maintenance mode page. Taking or deleting a snapshot is a
    command, not configuration: nothing is left to save."""
    change = build_change(MAINTENANCE, scope, setting, action, ident, values)
    if scope == "snapshot":
        return dataclasses.replace(change, config=False)
    return change
