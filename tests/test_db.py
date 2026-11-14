"""SQLite schema and migrations."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from app.db import _MIGRATIONS, init_db, open_db


def test_fresh_database_reaches_the_latest_version(tmp_path: Path) -> None:
    db_path = tmp_path / "nxray.db"
    assert init_db(db_path) == len(_MIGRATIONS)

    with open_db(db_path) as conn:
        tables = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert {"sessions", "login_attempts", "schema_version"} <= tables


def test_migrating_twice_changes_nothing(tmp_path: Path) -> None:
    db_path = tmp_path / "nxray.db"
    first = init_db(db_path)
    assert init_db(db_path) == first

    with open_db(db_path) as conn:
        versions = [row["version"] for row in conn.execute("SELECT version FROM schema_version")]
    assert versions == list(range(1, len(_MIGRATIONS) + 1))


def test_open_db_closes_the_connection(tmp_path: Path) -> None:
    db_path = tmp_path / "nxray.db"
    init_db(db_path)
    with open_db(db_path) as conn:
        pass
    try:
        conn.execute("SELECT 1")
    except Exception as exc:  # sqlite3.ProgrammingError: closed database
        assert "closed" in str(exc).lower()
    else:
        raise AssertionError("connection was left open")


def test_database_files_are_owner_only_from_the_start(tmp_path: Path) -> None:
    db_path = tmp_path / "nxray.db"
    old_umask = os.umask(0o022)
    try:
        with open_db(db_path) as conn:
            conn.execute("CREATE TABLE t (x)")
            conn.commit()
            # Still open: the -wal and -shm files exist now.
            for suffix in ("", "-wal", "-shm"):
                path = Path(f"{db_path}{suffix}")
                assert stat.S_IMODE(path.stat().st_mode) == 0o600, path.name
    finally:
        os.umask(old_umask)


def test_init_db_tightens_files_made_before(tmp_path: Path) -> None:
    db_path = tmp_path / "nxray.db"
    init_db(db_path)
    db_path.chmod(0o644)
    init_db(db_path)
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600
