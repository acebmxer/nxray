"""SQLite access and schema management.

One connection factory, one schema definition, one migration path. Later
stages add tables by appending a migration, never by editing an applied one.

Each request opens its own short-lived connection (``open_db``) rather than
sharing one across the server's worker threads, so no locking is needed.
"""

from __future__ import annotations

import contextlib
import os
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
    # 9 -> 10: whether the nxray-ports role's port list names the VLAN
    # interfaces. The switch takes that line only while interface-vlan is on,
    # so a role made with it off lacks it until Update the port list.
    """
    ALTER TABLE switch_connection ADD COLUMN role_vlan_interfaces INTEGER NOT NULL DEFAULT 0;
    """,
    # 10 -> 11: the activity log (app/activity.py): who changed what through NXray,
    # and backups of the switch's configuration (app/config_tools.py). checkpoint
    # names the switch checkpoint made with a backup, "" for none.
    """
    CREATE TABLE activity (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        at        REAL NOT NULL,
        username  TEXT NOT NULL,
        area      TEXT NOT NULL,
        what      TEXT NOT NULL,
        switch    TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_activity_at ON activity (at);

    CREATE TABLE config_backups (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at  REAL NOT NULL,
        created_by  TEXT NOT NULL,
        switch      TEXT NOT NULL,
        note        TEXT NOT NULL DEFAULT '',
        checkpoint  TEXT NOT NULL DEFAULT '',
        config      TEXT NOT NULL
    );
    """,
    # 11 -> 12: alerts (app/alerts.py). alert_settings is one row (id = 1): what
    # is alerted on and the e-mail settings, the SMTP password AES-GCM encrypted.
    # alert_webhooks keeps each URL and signing secret encrypted, and the URL cut
    # to its scheme and host for the page. alert_open holds the problems open
    # now, so each is sent once when it starts and once when it ends, also across
    # a restart; alert_log every alert sent and how its delivery went.
    """
    CREATE TABLE alert_settings (
        id                      INTEGER PRIMARY KEY CHECK (id = 1),
        rule_unreachable        INTEGER NOT NULL DEFAULT 1,
        rule_temperature        INTEGER NOT NULL DEFAULT 1,
        rule_fans               INTEGER NOT NULL DEFAULT 1,
        rule_power              INTEGER NOT NULL DEFAULT 1,
        cpu_percent             INTEGER NOT NULL DEFAULT 0,
        memory_percent          INTEGER NOT NULL DEFAULT 0,
        port_down               TEXT NOT NULL DEFAULT 'off',
        port_errors             INTEGER NOT NULL DEFAULT 0,
        rule_changes            INTEGER NOT NULL DEFAULT 0,
        smtp_host               TEXT NOT NULL DEFAULT '',
        smtp_port               INTEGER NOT NULL DEFAULT 587,
        smtp_security           TEXT NOT NULL DEFAULT 'starttls',
        smtp_username           TEXT NOT NULL DEFAULT '',
        smtp_password_encrypted TEXT NOT NULL DEFAULT '',
        mail_from               TEXT NOT NULL DEFAULT '',
        mail_to                 TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE alert_webhooks (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        name             TEXT NOT NULL,
        url_encrypted    TEXT NOT NULL,
        url_shown        TEXT NOT NULL,
        format           TEXT NOT NULL,
        secret_encrypted TEXT NOT NULL DEFAULT '',
        created_at       REAL NOT NULL
    );

    CREATE TABLE alert_open (
        key     TEXT PRIMARY KEY,
        since   REAL NOT NULL,
        message TEXT NOT NULL
    );

    CREATE TABLE alert_log (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        at       REAL NOT NULL,
        kind     TEXT NOT NULL,
        message  TEXT NOT NULL,
        delivery TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_alert_log_at ON alert_log (at);
    """,
    # 12 -> 13: several switches (app/switch_choice.py). switch_connection holds a
    # row per switch; its id is never used again once a switch is forgotten, so a
    # new switch never inherits the history of an old one (with no switch stored
    # but history, labels or backups left, the next one gets id 2, and what is
    # kept under id 1 is never shown; history ages out). Each
    # switch's history, port labels, config backups and open problems name it by
    # switch_id; what was there before belongs to switch 1. alert_log keeps the
    # switch's name as alerts named it.
    """
    CREATE TABLE switch_connection_new (
        id                   INTEGER PRIMARY KEY AUTOINCREMENT,
        host                 TEXT NOT NULL,
        port                 INTEGER NOT NULL,
        username             TEXT NOT NULL,
        password_encrypted   TEXT NOT NULL,
        switch_hostname      TEXT NOT NULL,
        created_at           REAL NOT NULL,
        config_saved         INTEGER NOT NULL,
        last_tested_at       REAL,
        last_test_ok         INTEGER,
        last_test_message    TEXT,
        changes_enabled_at   REAL,
        paused_until         REAL,
        unsaved_changes      INTEGER NOT NULL DEFAULT 0,
        role_version         INTEGER NOT NULL DEFAULT 0,
        role_vlan_interfaces INTEGER NOT NULL DEFAULT 0
    );
    INSERT INTO switch_connection_new
        (id, host, port, username, password_encrypted, switch_hostname, created_at,
         config_saved, last_tested_at, last_test_ok, last_test_message,
         changes_enabled_at, paused_until, unsaved_changes, role_version,
         role_vlan_interfaces)
    SELECT id, host, port, username, password_encrypted, switch_hostname, created_at,
           config_saved, last_tested_at, last_test_ok, last_test_message,
           changes_enabled_at, paused_until, unsaved_changes, role_version,
           role_vlan_interfaces
      FROM switch_connection;
    DROP TABLE switch_connection;
    ALTER TABLE switch_connection_new RENAME TO switch_connection;
    CREATE TEMP TABLE leftovers AS
    SELECT 1 AS found
     WHERE NOT EXISTS (SELECT 1 FROM switch_connection)
       AND (EXISTS (SELECT 1 FROM history) OR EXISTS (SELECT 1 FROM port_labels)
            OR EXISTS (SELECT 1 FROM config_backups) OR EXISTS (SELECT 1 FROM alert_open));
    UPDATE sqlite_sequence SET seq = MAX(seq, 1)
     WHERE name = 'switch_connection' AND EXISTS (SELECT 1 FROM leftovers);
    INSERT INTO sqlite_sequence (name, seq)
    SELECT 'switch_connection', 1 FROM leftovers
     WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'switch_connection');
    DROP TABLE leftovers;

    ALTER TABLE history ADD COLUMN switch_id INTEGER NOT NULL DEFAULT 1;
    DROP INDEX idx_history_series;
    CREATE INDEX idx_history_series ON history (switch_id, metric, item, ts);

    CREATE TABLE port_labels_new (
        switch_id   INTEGER NOT NULL,
        port        TEXT NOT NULL,
        label       TEXT NOT NULL,
        updated_at  REAL NOT NULL,
        updated_by  TEXT NOT NULL,
        PRIMARY KEY (switch_id, port)
    );
    INSERT INTO port_labels_new (switch_id, port, label, updated_at, updated_by)
    SELECT 1, port, label, updated_at, updated_by FROM port_labels;
    DROP TABLE port_labels;
    ALTER TABLE port_labels_new RENAME TO port_labels;

    ALTER TABLE config_backups ADD COLUMN switch_id INTEGER NOT NULL DEFAULT 1;
    CREATE INDEX idx_config_backups_switch ON config_backups (switch_id, id);

    CREATE TABLE alert_open_new (
        switch_id INTEGER NOT NULL,
        key       TEXT NOT NULL,
        since     REAL NOT NULL,
        message   TEXT NOT NULL,
        PRIMARY KEY (switch_id, key)
    );
    INSERT INTO alert_open_new (switch_id, key, since, message)
    SELECT 1, key, since, message FROM alert_open;
    DROP TABLE alert_open;
    ALTER TABLE alert_open_new RENAME TO alert_open;

    ALTER TABLE alert_log ADD COLUMN switch TEXT NOT NULL DEFAULT '';
    """,
    # The switch's model and NX-OS version, shown in the strip at the top of every page.
    """
    ALTER TABLE switch_connection ADD COLUMN switch_model TEXT NOT NULL DEFAULT '';
    ALTER TABLE switch_connection ADD COLUMN nxos_version TEXT NOT NULL DEFAULT '';
    """,
    # Self-update channels (app/update.py): include_beta is the Settings switch,
    # target_tag and target_version say where Update now goes (:latest or :beta,
    # or the container's own tag when digests are compared).
    """
    ALTER TABLE update_state ADD COLUMN include_beta INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE update_state ADD COLUMN target_tag TEXT NOT NULL DEFAULT '';
    ALTER TABLE update_state ADD COLUMN target_version TEXT NOT NULL DEFAULT '';
    """,
    # Switch accounts for NXray users (app/switch_accounts.py): which local
    # account on which switch belongs to which NXray user, the roles NXray last
    # gave it, when NXray last set its password (NULL: never, for an account
    # that was linked as it was) and whether NXray locked it with a random
    # password. No password is kept. users.password_changed_at is when the
    # NXray password last changed, so a switch password set before it is out
    # of step; NULL for accounts older than this.
    """
    CREATE TABLE switch_accounts (
        user_id          INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        switch_id        INTEGER NOT NULL,
        account_name     TEXT NOT NULL,
        roles            TEXT NOT NULL,
        password_set_at  REAL,
        locked           INTEGER NOT NULL DEFAULT 0,
        linked_at        REAL NOT NULL,
        PRIMARY KEY (user_id, switch_id),
        UNIQUE (switch_id, account_name)
    );
    ALTER TABLE users ADD COLUMN password_changed_at REAL;
    """,
    # sFlow (app/sflow.py): each switch's measured traffic per minute, per VLAN
    # (kind vlan) and per device (mac_out: what a MAC address sent, mac_in: what
    # was sent to it), in bytes estimated from the samples and the number of
    # samples behind it. sflow_agent is the agent address NXray set on the switch,
    # which the datagrams carry; '' until then (the NX-API address is used).
    """
    CREATE TABLE sflow_traffic (
        switch_id INTEGER NOT NULL,
        minute    INTEGER NOT NULL,
        kind      TEXT NOT NULL,
        item      TEXT NOT NULL,
        bytes     INTEGER NOT NULL,
        samples   INTEGER NOT NULL,
        PRIMARY KEY (switch_id, minute, kind, item)
    );
    CREATE INDEX idx_sflow_traffic_minute ON sflow_traffic (minute);
    ALTER TABLE switch_connection ADD COLUMN sflow_agent TEXT NOT NULL DEFAULT '';
    """,
    # 13 -> 14: how much access NXray's switch account gets (issue #40). role_mode is
    # 'limited' (listed rules only), 'broad' (any configuration except accounts, roles,
    # AAA and the boot image) or 'stored' (limited rules, and the switch admin login
    # kept encrypted so NXray adds new rules itself). The admin login columns hold
    # something only in 'stored' mode.
    """
    ALTER TABLE switch_connection ADD COLUMN role_mode TEXT NOT NULL DEFAULT 'limited';
    ALTER TABLE switch_connection ADD COLUMN admin_user TEXT NOT NULL DEFAULT '';
    ALTER TABLE switch_connection ADD COLUMN admin_password_encrypted TEXT NOT NULL DEFAULT '';
    ALTER TABLE switch_connection ADD COLUMN admin_ssh_port INTEGER NOT NULL DEFAULT 22;
    """,
]


def restrict_files(db_path: Path) -> None:
    """Make the database and its write-ahead log files readable by the owner only.

    They hold stored switch configurations, session ids and encrypted passwords.
    Files made before this check existed get the same mode; a file the app does
    not own (a bind mount set up by someone else) is left as it is.
    """
    for suffix in ("", "-wal", "-shm"):
        with contextlib.suppress(OSError):
            Path(f"{db_path}{suffix}").chmod(0o600)


def connect(db_path: Path) -> sqlite3.Connection:
    """Open the database with rows readable by column name.

    A new database file is created mode 600 (SQLite gives its -wal and -shm
    files the same mode), so it is never readable by others, not even briefly.
    """
    if not db_path.exists():
        with contextlib.suppress(FileExistsError):
            os.close(os.open(db_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
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
        version = migrate(conn)
    restrict_files(db_path)
    return version
