"""The activity log: who changed what through NXray, and when.

Every route that changes something (the switch, NXray's accounts, its settings,
the stored switch, a backup) records one line here after the change worked,
with the NXray account that made it, the area (the page it was made on), the
change in plain words (passwords and SNMP communities already masked, as on
the confirm page) and the switch's address when the switch was changed. The
Activity page lists them for admins, newest first, and downloads them as CSV.

Sign-ins and pages that only read are not recorded; the server log
(``docker logs``) has those. Lines older than ``KEEP_DAYS`` are deleted as new
ones arrive.
"""

from __future__ import annotations

import csv
import io
import sqlite3
import time
from dataclasses import dataclass

KEEP_DAYS = 365
# How many lines the Activity page shows at most.
LIST_LIMIT = 500
WHAT_MAX = 2000


@dataclass(frozen=True)
class Activity:
    """One change made through NXray."""

    id: int
    at: float
    username: str
    area: str
    what: str
    switch: str


def record_activity(
    conn: sqlite3.Connection,
    username: str,
    area: str,
    what: str,
    switch: str = "",
    now: float | None = None,
) -> None:
    """Record one change, and delete the lines older than ``KEEP_DAYS``."""
    at = time.time() if now is None else now
    conn.execute(
        "INSERT INTO activity (at, username, area, what, switch) VALUES (?, ?, ?, ?, ?)",
        (at, username, area, " ".join(what.split())[:WHAT_MAX], switch),
    )
    conn.execute("DELETE FROM activity WHERE at < ?", (at - KEEP_DAYS * 86400,))
    conn.commit()


def list_activity(
    conn: sqlite3.Connection,
    *,
    username: str = "",
    area: str = "",
    search: str = "",
    limit: int = LIST_LIMIT,
) -> list[Activity]:
    """The recorded changes, newest first: those of ``username`` and ``area`` when
    given, and containing ``search`` (any case) in what was done."""
    sql = "SELECT id, at, username, area, what, switch FROM activity WHERE 1 = 1"
    params: list[object] = []
    if username:
        sql += " AND username = ?"
        params.append(username)
    if area:
        sql += " AND area = ?"
        params.append(area)
    if search:
        sql += " AND (what LIKE ? ESCAPE '\\' OR switch LIKE ? ESCAPE '\\')"
        pattern = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        params += [pattern, pattern]
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return [
        Activity(r["id"], r["at"], r["username"], r["area"], r["what"], r["switch"])
        for r in conn.execute(sql, params).fetchall()
    ]


def activity_choices(conn: sqlite3.Connection) -> tuple[list[str], list[str]]:
    """The account names and the areas the log holds, for the page's filters."""
    users = [r[0] for r in conn.execute("SELECT DISTINCT username FROM activity ORDER BY 1")]
    areas = [r[0] for r in conn.execute("SELECT DISTINCT area FROM activity ORDER BY 1")]
    return users, areas


def utc_time(at: float) -> str:
    """A stored time as the pages show it: ``2026-11-01 14:30:05 UTC``."""
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(at))


def activity_csv(entries: list[Activity]) -> str:
    """The entries as CSV: time (UTC, ISO 8601), account, area, switch, change."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["time_utc", "account", "area", "switch", "change"])
    for entry in entries:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(entry.at))
        # A leading = + - @ would make a spreadsheet run the cell as a formula.
        cells = [entry.username, entry.area, entry.switch, entry.what]
        writer.writerow([stamp, *("'" + c if c and c[0] in "=+-@" else c for c in cells)])
    return out.getvalue()
