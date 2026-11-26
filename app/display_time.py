"""The time zone NXray shows times in (issue #110).

Every time NXray stores is a Unix time (seconds since 1970, the same everywhere).
This module turns one into the clock time the pages, graphs and alert messages
show, in the zone an admin picked on the Settings page; ``UTC`` until they pick
one. Summer time follows the zone by itself.

The choice is one value for the whole install, kept in the database and also held
here, so a graph label or a log line needs no database read. NXray runs as one
process, so the held value is the only copy that matters; ``load_zone`` fills it at
start-up and ``save_zone`` keeps it and the database together.

Only what people read follows the zone. Machine-readable times (the activity CSV's
``time_utc`` column, the alert webhook's ISO times, file-name stamps) stay UTC.
"""

from __future__ import annotations

import sqlite3
import time
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

DEFAULT_ZONE = "UTC"

# Names that are in the time zone database but would only confuse a pick list:
# copies under another folder, and the Etc/GMT+5 style whose sign is the opposite
# of what people expect.
_HIDDEN_PREFIXES = ("posix/", "right/", "Etc/", "SystemV/")

# (name, the zone, or None for UTC). One tuple, replaced whole, so a reader never
# sees a name from one choice and a zone from another.
_current: tuple[str, ZoneInfo | None] = (DEFAULT_ZONE, None)


def _find(name: str) -> ZoneInfo | None:
    """The zone called ``name``; ``ValueError`` when the database has no such name."""
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
        raise ValueError(f"{name!r} is not a time zone NXray knows.") from exc


def zone_choices() -> list[str]:
    """The names for the pick list: UTC first, then every region/city name, sorted."""
    names = sorted(
        name
        for name in available_timezones()
        if "/" in name and not name.startswith(_HIDDEN_PREFIXES)
    )
    return [DEFAULT_ZONE, *names]


def zone_name() -> str:
    """The zone in use: ``UTC`` or a name such as ``America/New_York``."""
    return _current[0]


def set_zone(name: str) -> None:
    """Use ``name`` from now on (``ValueError`` for a name the database lacks)."""
    global _current
    name = name.strip()
    if name == DEFAULT_ZONE or not name:
        _current = (DEFAULT_ZONE, None)
    else:
        _current = (name, _find(name))


def load_zone(conn: sqlite3.Connection) -> str:
    """Take the stored choice into use (start-up). A stored name this machine's time zone
    database no longer has falls back to UTC rather than stopping NXray.

    Returns the zone now in use.
    """
    row = conn.execute("SELECT time_zone FROM display_settings WHERE id = 1").fetchone()
    try:
        set_zone(row["time_zone"] if row else DEFAULT_ZONE)
    except ValueError:
        set_zone(DEFAULT_ZONE)
    return zone_name()


def save_zone(conn: sqlite3.Connection, name: str) -> None:
    """Store the choice and use it. ``ValueError`` (nothing stored) for an unknown name."""
    set_zone(name)
    conn.execute("UPDATE display_settings SET time_zone = ? WHERE id = 1", (zone_name(),))
    conn.commit()


def offset_at(moment: float) -> int:
    """Seconds the zone's clock is ahead of UTC at ``moment`` (negative west of Greenwich)."""
    zone = _current[1]
    if zone is None:
        return 0
    offset = datetime.fromtimestamp(moment, zone).utcoffset()
    return int(offset.total_seconds()) if offset else 0


def local_seconds(moment: float) -> float:
    """``moment`` shifted so that reading it as UTC gives the zone's clock time."""
    return moment + offset_at(moment)


def moment_of(local: float) -> float:
    """The reverse of ``local_seconds``: the Unix time at which the zone's clock read
    ``local``. Right except within the hour a summer-time change skips or repeats."""
    return local - offset_at(local - offset_at(local))


def clock(moment: float, pattern: str) -> str:
    """``moment`` written as ``pattern`` (strftime) on the zone's clock."""
    return time.strftime(pattern, time.gmtime(local_seconds(moment)))


def abbreviation(moment: float) -> str:
    """The short name of the zone at ``moment``: ``UTC``, ``EST``, ``CEST``... (zones the
    database gives no letters for, such as ``+03``, show as that)."""
    zone = _current[1]
    if zone is None:
        return DEFAULT_ZONE
    return datetime.fromtimestamp(moment, zone).tzname() or zone_name()


def local_time(at: float, *, seconds: bool = True) -> str:
    """A stored time as the pages show it: ``2026-11-01 14:30:05 EST`` (UTC by default).

    ``seconds=False`` drops the seconds. Also the ``local_time`` template filter.
    """
    pattern = "%Y-%m-%d %H:%M:%S" if seconds else "%Y-%m-%d %H:%M"
    return f"{clock(at, pattern)} {abbreviation(at)}"
