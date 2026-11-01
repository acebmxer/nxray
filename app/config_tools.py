"""Config tools: backups of the switch's configuration kept in NXray, the switch
checkpoints that go with them, comparing two configurations, and rolling back.

A **backup** is the running configuration as ``show running-config`` printed it
at one moment, stored in NXray's database (table ``config_backups``) with who
took it and a note. When NXray's role allows it (role version 13), the switch
also keeps a **checkpoint** of that moment, named ``nxray-<backup number>``
(``NxapiClient.create_checkpoint``); deleting the backup deletes it too.

**Rolling back** makes the running configuration a checkpoint again
(``rollback running-config checkpoint``). NX-OS does that atomically: when one
line fails, nothing changes. NXray rolls back only to its own checkpoints and
only with the switch admin login typed on the Config page each time, never with
its own account, whose role has no rule for it. Before rolling back, NXray
takes a backup of the configuration it replaces, so the rollback itself can be
undone.

**Comparing** shows what differs between two configurations, line by line:
running and saved (``show startup-config``), or either and a backup, or two
backups. The lines NX-OS writes about the moment it printed
(``!Time: ...``) are left out, so only real differences show.

The shape of ``show checkpoint summary`` follows Cisco's NX-OS 9.3 System
Management Configuration Guide; it was not recorded on a switch.
"""

from __future__ import annotations

import difflib
import re
import sqlite3
import time
from dataclasses import dataclass

from app.nxapi import CHECKPOINT_PREFIX, NxapiClient, NxapiCommandError

RUNNING_COMMAND = "show running-config"
STARTUP_COMMAND = "show startup-config"
CHECKPOINTS_COMMAND = "show checkpoint summary"

# The longest note a backup may carry.
NOTE_MAX = 200
# How many backups the Config page lists.
LIST_LIMIT = 200

# Lines NX-OS writes about when it printed the configuration, not part of it.
_VOLATILE = re.compile(
    r"^!(?:Time:|Running configuration last done at|Startup config saved at|Command:)"
)


# ---- configuration text ---------------------------------------------------------


def clean_config(config: str) -> list[str]:
    """The configuration's lines without the ones about when it was printed, and
    without trailing spaces or blank lines at either end."""
    lines = [line.rstrip() for line in config.replace("\r\n", "\n").split("\n")]
    lines = [line for line in lines if not _VOLATILE.match(line)]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return lines


def config_sections(config: str) -> list[tuple[str, list[str]]]:
    """Each top-level line of a configuration with the indented lines under it,
    stripped: ``("interface Ethernet1/3", ["switchport", "ip port access-group
    web in"])``. Comments (``!``) and blank lines are left out."""
    sections: list[tuple[str, list[str]]] = []
    for raw in config.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("!"):
            continue
        if line.startswith((" ", "\t")):
            if sections:
                sections[-1][1].append(line.strip())
            continue
        sections.append((line.strip(), []))
    return sections


@dataclass(frozen=True)
class DiffLine:
    """One line of a comparison: ``kind`` is ``same``, ``removed`` (only in the
    first), ``added`` (only in the second) or ``gap`` (unchanged lines left out)."""

    kind: str
    text: str


def config_diff(first: str, second: str, context: int = 3) -> list[DiffLine]:
    """What changes from ``first`` to ``second``, with ``context`` unchanged lines
    around each change; [] when they are the same."""
    a, b = clean_config(first), clean_config(second)
    found: list[DiffLine] = []
    for group in difflib.SequenceMatcher(None, a, b, autojunk=False).get_grouped_opcodes(context):
        if found:
            found.append(DiffLine("gap", "…"))
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                found += [DiffLine("same", line) for line in a[i1:i2]]
                continue
            if tag in ("replace", "delete"):
                found += [DiffLine("removed", line) for line in a[i1:i2]]
            if tag in ("replace", "insert"):
                found += [DiffLine("added", line) for line in b[j1:j2]]
    return found


def diff_counts(diff: list[DiffLine]) -> tuple[int, int]:
    """(lines removed, lines added) in a comparison."""
    return (
        sum(1 for line in diff if line.kind == "removed"),
        sum(1 for line in diff if line.kind == "added"),
    )


# ---- checkpoints on the switch --------------------------------------------------

_CHECKPOINT_LINE = re.compile(r"^\s*\d+\)\s+(\S+?):?\s*$")


def parse_checkpoints(output: str) -> list[str]:
    """The checkpoint names in ``show checkpoint summary`` (``1) nxray-3:``), in
    the order the switch lists them."""
    return [m.group(1) for line in output.splitlines() if (m := _CHECKPOINT_LINE.match(line))]


def checkpoint_name(backup_id: int) -> str:
    """The switch checkpoint that goes with backup ``backup_id``: ``nxray-<id>``."""
    return f"{CHECKPOINT_PREFIX}{int(backup_id)}"


# ---- backups in NXray's database ------------------------------------------------


@dataclass(frozen=True)
class Backup:
    """One stored configuration. ``checkpoint`` is the switch checkpoint made with
    it ("" when there is none)."""

    id: int
    created_at: float
    created_by: str
    switch: str
    note: str
    checkpoint: str
    size: int  # characters of configuration


def _backup(row: sqlite3.Row) -> Backup:
    return Backup(
        id=row["id"],
        created_at=row["created_at"],
        created_by=row["created_by"],
        switch=row["switch"],
        note=row["note"],
        checkpoint=row["checkpoint"],
        size=row["size"],
    )


def validate_note(note: str) -> str:
    """A backup's note: one line of printable text, at most ``NOTE_MAX`` characters."""
    cleaned = " ".join(note.split())
    if len(cleaned) > NOTE_MAX:
        raise ValueError(f"the note is at most {NOTE_MAX} characters")
    if any(not ch.isprintable() for ch in cleaned):
        raise ValueError("the note can only hold printable characters")
    return cleaned


def store_backup(
    conn: sqlite3.Connection,
    *,
    config: str,
    created_by: str,
    switch: str,
    note: str = "",
    now: float | None = None,
) -> int:
    """Store a configuration; returns the backup's number."""
    cursor = conn.execute(
        "INSERT INTO config_backups (created_at, created_by, switch, note, checkpoint, config) "
        "VALUES (?, ?, ?, ?, '', ?)",
        (time.time() if now is None else now, created_by, switch, validate_note(note), config),
    )
    conn.commit()
    return int(cursor.lastrowid or 0)


def set_backup_checkpoint(conn: sqlite3.Connection, backup_id: int, checkpoint: str) -> None:
    """Note the switch checkpoint made with a backup ("" when it is gone)."""
    conn.execute(
        "UPDATE config_backups SET checkpoint = ? WHERE id = ?", (checkpoint, int(backup_id))
    )
    conn.commit()


def list_backups(conn: sqlite3.Connection, limit: int = LIST_LIMIT) -> list[Backup]:
    """The stored backups, newest first, without their text."""
    rows = conn.execute(
        "SELECT id, created_at, created_by, switch, note, checkpoint, LENGTH(config) AS size "
        "FROM config_backups ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_backup(row) for row in rows]


def get_backup(conn: sqlite3.Connection, backup_id: int) -> tuple[Backup, str] | None:
    """One backup and its configuration text, or None."""
    row = conn.execute(
        "SELECT id, created_at, created_by, switch, note, checkpoint, config, "
        "LENGTH(config) AS size FROM config_backups WHERE id = ?",
        (int(backup_id),),
    ).fetchone()
    return (_backup(row), row["config"]) if row else None


def delete_backup(conn: sqlite3.Connection, backup_id: int) -> bool:
    """Delete a stored backup; False when there was none."""
    cursor = conn.execute("DELETE FROM config_backups WHERE id = ?", (int(backup_id),))
    conn.commit()
    return cursor.rowcount > 0


# ---- reading the switch -----------------------------------------------------------


@dataclass(frozen=True)
class SwitchConfigs:
    """What the Config page reads from the switch. ``startup`` is None when NXray's
    role may not read it; ``checkpoints`` None when it may not list them."""

    running: str
    startup: str | None
    checkpoints: tuple[str, ...] | None


def load_configs(client: NxapiClient) -> SwitchConfigs:
    """The running and saved configurations and the checkpoints, as text."""
    running = client.show_text(RUNNING_COMMAND)
    try:
        startup: str | None = client.show_text(STARTUP_COMMAND)
    except NxapiCommandError:
        startup = None  # the role predates the rule that allows it
    try:
        checkpoints: tuple[str, ...] | None = tuple(
            parse_checkpoints(client.show_text(CHECKPOINTS_COMMAND))
        )
    except NxapiCommandError:
        checkpoints = None
    return SwitchConfigs(running, startup, checkpoints)


def load_running(client: NxapiClient) -> str:
    """``show running-config`` as text."""
    return client.show_text(RUNNING_COMMAND)
