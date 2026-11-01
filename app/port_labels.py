"""Port labels: NXray's own note on a port, such as "Proxmox node 2, NIC 1".

A label lives in NXray's database only and is never sent to the switch, so
it may hold characters a switch description refuses and stays when the
switch is replaced or reset. Each switch has its own labels; they go when
NXray forgets the switch. The switch's own description is a separate
thing, changed on the port's page like any other switch setting.
"""

from __future__ import annotations

import sqlite3
import time

from app.nxapi import validate_port_name

LABEL_MAX = 64


def validate_label(text: str) -> str:
    """Return the label as it will be stored, or raise ValueError.

    Spaces at either end are dropped; an empty result means "no label".
    """
    cleaned = text.strip()
    if len(cleaned) > LABEL_MAX:
        raise ValueError(f"a label is at most {LABEL_MAX} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in cleaned):
        raise ValueError("a label is one line of text, without tabs or line breaks")
    return cleaned


def get_labels(conn: sqlite3.Connection, switch_id: int | None) -> dict[str, str]:
    """Every port's label on a switch, by port name."""
    rows = conn.execute("SELECT port, label FROM port_labels WHERE switch_id = ?", (switch_id,))
    return {row["port"]: row["label"] for row in rows}


def set_label(
    conn: sqlite3.Connection, switch_id: int, port: str, label: str, username: str
) -> str:
    """Store a port's label on a switch (checked first); an empty one removes it.
    Returns what was stored."""
    validate_port_name(port)
    label = validate_label(label)
    if label:
        conn.execute(
            "INSERT INTO port_labels (switch_id, port, label, updated_at, updated_by) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (switch_id, port) DO UPDATE SET label = excluded.label, "
            "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
            (switch_id, port, label, time.time(), username),
        )
    else:
        conn.execute("DELETE FROM port_labels WHERE switch_id = ? AND port = ?", (switch_id, port))
    conn.commit()
    return label
