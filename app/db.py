"""SQLite access and schema management.

One connection factory, one schema definition, one migration path. Later
stages add tables by appending a migration, never by editing an applied one.

Each request opens its own short-lived connection (``open_db``) rather than
sharing one across the server's worker threads, so no locking is needed.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

# Each entry is applied in order and recorded in schema_version. Append only:
# editing an applied migration leaves existing databases behind.
_MIGRATIONS: list[str] = [
    # 0 -> 1: sessions and login throttling.
    """
    CREATE TABLE sessions (
        id          TEXT PRIMARY KEY,
        username    TEXT NOT NULL,
        created_at  REAL NOT NULL,
        expires_at  REAL NOT NULL
    );
    CREATE INDEX idx_sessions_expires ON sessions (expires_at);

    CREATE TABLE login_attempts (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        ip           TEXT NOT NULL,
        attempted_at REAL NOT NULL
    );
    CREATE INDEX idx_login_attempts_ip_time ON login_attempts (ip, attempted_at);
    """,
    # 1 -> 2: the switch NXray talks to, and its own account on it. One row
    # (id = 1). The password is AES-GCM encrypted (app/crypto.py); the admin
    # login used during setup is never stored.
    """
    CREATE TABLE switch_connection (
        id                 INTEGER PRIMARY KEY CHECK (id = 1),
        host               TEXT NOT NULL,
        port               INTEGER NOT NULL,
        username           TEXT NOT NULL,
        password_encrypted TEXT NOT NULL,
        switch_hostname    TEXT NOT NULL,
        created_at         REAL NOT NULL,
        config_saved       INTEGER NOT NULL,
        last_tested_at     REAL,
        last_test_ok       INTEGER,
        last_test_message  TEXT
    );
    """,
    # 2 -> 3: port changes. changes_enabled_at is when NXray's account was
    # given the port-changes role; NXray leaves the switch alone until
    # paused_until so the switch drops its cached session for the account
    # and applies the role. unsaved_changes is set by a port change and
    # cleared by Save config.
    """
    ALTER TABLE switch_connection ADD COLUMN changes_enabled_at REAL;
    ALTER TABLE switch_connection ADD COLUMN paused_until REAL;
    ALTER TABLE switch_connection ADD COLUMN unsaved_changes INTEGER NOT NULL DEFAULT 0;
    """,
    # 3 -> 4: VLAN changes. role_version is the rule set NXray's account was
    # given (app/port_changes.py ROLE_VERSION): 0 none, 1 port rules only,
    # 2 port and VLAN rules. Installs that turned port changes on before
    # this have version 1.
    """
    ALTER TABLE switch_connection ADD COLUMN role_version INTEGER NOT NULL DEFAULT 0;
    UPDATE switch_connection SET role_version = 1 WHERE changes_enabled_at IS NOT NULL;
    """,
]


def connect(db_path: Path) -> sqlite3.Connection:
    """Open the database with rows readable by column name."""
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def open_db(db_path: Path) -> Iterator[sqlite3.Connection]:
    """A connection for one unit of work, always closed afterwards."""
    conn = connect(db_path)
    try:
        yield conn
    finally:
        conn.close()


def current_version(conn: sqlite3.Connection) -> int:
    """Return the applied schema version, 0 for an untouched database."""
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    row = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
    return row["v"] or 0


def migrate(conn: sqlite3.Connection) -> int:
    """Apply every migration not yet applied. Returns the resulting version."""
    version = current_version(conn)
    for index, script in enumerate(_MIGRATIONS, start=1):
        if index <= version:
            continue
        try:
            conn.executescript("BEGIN;" + script)
            conn.execute("INSERT INTO schema_version (version) VALUES (?)", (index,))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        version = index
    return version


def init_db(db_path: Path) -> int:
    """Create or upgrade the database file. Returns the schema version."""
    with open_db(db_path) as conn:
        return migrate(conn)
