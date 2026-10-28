"""Storing the switch connection."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.db import init_db, open_db
from app.switch_connection import (
    SWITCH_TIMEOUT,
    DecryptionError,
    delete_connection,
    get_connection,
    load_target,
    record_test_result,
    save_connection,
    set_config_saved,
)


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "nxray.db"
    init_db(path)
    return path


def _save(conn: sqlite3.Connection, **overrides) -> None:
    args = {
        "host": "192.0.2.10",
        "port": 443,
        "username": "nxray",
        "password": "Stored1Password",
        "switch_hostname": "nexus-lab",
        "config_saved": False,
        "secret_key": "key-a",
    }
    args.update(overrides)
    save_connection(conn, **args)


def test_nothing_stored_at_first(db: Path) -> None:
    with open_db(db) as conn:
        assert get_connection(conn) is None
        with pytest.raises(LookupError):
            load_target(conn, "key-a")


def test_save_get_and_load(db: Path) -> None:
    with open_db(db) as conn:
        _save(conn)
        stored = get_connection(conn)
        assert stored is not None
        assert (stored.host, stored.port, stored.username) == ("192.0.2.10", 443, "nxray")
        assert stored.switch_hostname == "nexus-lab"
        assert stored.config_saved is False
        assert stored.last_tested_at is None
        assert not hasattr(stored, "password")

        target = load_target(conn, "key-a")
        assert target.password == "Stored1Password"
        assert target.timeout == SWITCH_TIMEOUT
        assert target.url == "https://192.0.2.10:443/ins"


def test_password_is_not_stored_in_plain_text(db: Path) -> None:
    with open_db(db) as conn:
        _save(conn)
        (stored,) = conn.execute("SELECT password_encrypted FROM switch_connection").fetchone()
    assert "Stored1Password" not in stored
    assert b"Stored1Password" not in db.read_bytes()


def test_a_second_save_is_refused(db: Path) -> None:
    with open_db(db) as conn:
        _save(conn)
        with pytest.raises(sqlite3.IntegrityError):
            _save(conn, username="other")
        stored = get_connection(conn)
        assert stored is not None and stored.username == "nxray"


def test_changed_key_cannot_decrypt(db: Path) -> None:
    with open_db(db) as conn:
        _save(conn)
        with pytest.raises(DecryptionError):
            load_target(conn, "key-b")


def test_test_results_and_saved_flag(db: Path) -> None:
    with open_db(db) as conn:
        _save(conn)
        record_test_result(conn, ok=False, message="nope")
        set_config_saved(conn, True)
        stored = get_connection(conn)
    assert stored is not None
    assert stored.last_test_ok is False and stored.last_test_message == "nope"
    assert stored.last_tested_at is not None
    assert stored.config_saved is True


def test_delete(db: Path) -> None:
    with open_db(db) as conn:
        assert delete_connection(conn) is False
        _save(conn)
        assert delete_connection(conn) is True
        assert get_connection(conn) is None
