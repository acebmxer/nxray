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
    # 4 -> 5: NXray's own sign-in accounts (app/users.py). Before this, the
    # only account was the one in nxray.env; it becomes the first admin row
    # at the next start (users.bootstrap_admin). Names are unique whatever
    # their case. sessions.username stays a bare name: a session of a
    # removed or disabled account is refused when it is looked up
    # (security.get_session_user).
    """
    CREATE TABLE users (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        username       TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash  TEXT NOT NULL,
        role           TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
        disabled       INTEGER NOT NULL DEFAULT 0,
        created_at     REAL NOT NULL
    );
    """,
    # 5 -> 6: optional two-factor sign-in, per account (app/users.py,
    # app/totp.py). totp_secret_encrypted is AES-GCM encrypted like the
    # switch password: whoever reads it can make codes forever. It is
    # written when setup starts, while totp_enabled is still 0, and only
    # counts once the account confirms a code. totp_last_step is the last
    # 30-second step a code was accepted for, so the same code can't be used
    # twice. totp_backup_codes is a JSON list of SHA-256 hashes; a used code
    # is removed from it.
    """
    ALTER TABLE users ADD COLUMN totp_secret_encrypted TEXT;
    ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE users ADD COLUMN totp_backup_codes TEXT NOT NULL DEFAULT '[]';
    """,
    # 6 -> 7: self-update (app/update.py). One row (id = 1). latest_digest is
    # what GHCR's :latest pointed at when last checked; available is set when
    # that is not what this container runs. in_progress is set from pressing
    # Update until the replacement container starts and clears it
    # (update.finish_pending_update). last_result is "success", or a failure
    # message; last_result_at lets a success age off the page.
    """
    CREATE TABLE update_state (
        id                INTEGER PRIMARY KEY CHECK (id = 1),
        latest_digest     TEXT,
        latest_checked_at REAL,
        available         INTEGER NOT NULL DEFAULT 0,
        in_progress       INTEGER NOT NULL DEFAULT 0,
        started_at        REAL,
        last_result       TEXT NOT NULL DEFAULT '',
        last_result_at    REAL
    );
    """,
    # 7 -> 8: history (app/history.py). One row per number per sample: metric
    # says what it is, item names the sensor or port (empty for whole-switch
    # numbers). Rows older than 30 days are deleted by the sampler.
    """
    CREATE TABLE history (
        ts     REAL NOT NULL,
        metric TEXT NOT NULL,
        item   TEXT NOT NULL DEFAULT '',
        value  REAL NOT NULL
    );
    CREATE INDEX idx_history_series ON history (metric, item, ts);
    CREATE INDEX idx_history_ts ON history (ts);
    """,
    # 8 -> 9: port labels (app/port_labels.py). NXray's own note on a port
    # ("Proxmox node 2, NIC 1"), shown on the front-panel picture and the
    # port's page. Kept in NXray only; the switch never sees it.
    """
    CREATE TABLE port_labels (
        port        TEXT PRIMARY KEY,
        label       TEXT NOT NULL,
        updated_at  REAL NOT NULL,
        updated_by  TEXT NOT NULL
    );
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
