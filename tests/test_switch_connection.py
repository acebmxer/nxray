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
    find_by_address,
    get_connection,
    list_connections,
    load_target,
    record_test_result,
    save_connection,
    set_config_saved,
    set_unsaved_changes,
)


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "nxray.db"
    init_db(path)
    return path


def _save(conn: sqlite3.Connection, **overrides) -> int:
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
    return save_connection(conn, **args)


def test_nothing_stored_at_first(db: Path) -> None:
    with open_db(db) as conn:
        assert get_connection(conn, 1) is None
        assert get_connection(conn, None) is None
        assert list_connections(conn) == []
        with pytest.raises(LookupError):
            load_target(conn, 1, "key-a")


def test_save_get_and_load(db: Path) -> None:
    with open_db(db) as conn:
        switch_id = _save(conn)
        stored = get_connection(conn, switch_id)
        assert stored is not None
        assert stored.id == switch_id
        assert (stored.host, stored.port, stored.username) == ("192.0.2.10", 443, "nxray")
        assert stored.switch_hostname == "nexus-lab"
        assert stored.config_saved is False
        assert stored.last_tested_at is None
        assert not hasattr(stored, "password")

        target = load_target(conn, switch_id, "key-a")
        assert target.password == "Stored1Password"
        assert target.timeout == SWITCH_TIMEOUT
        assert target.url == "https://192.0.2.10:443/ins"


def test_password_is_not_stored_in_plain_text(db: Path) -> None:
    with open_db(db) as conn:
        _save(conn)
        (stored,) = conn.execute("SELECT password_encrypted FROM switch_connection").fetchone()
    assert "Stored1Password" not in stored
    assert b"Stored1Password" not in db.read_bytes()


def test_the_same_address_is_refused_twice(db: Path) -> None:
    with open_db(db) as conn:
        first = _save(conn)
        with pytest.raises(sqlite3.IntegrityError):
            _save(conn, username="other")
        with pytest.raises(sqlite3.IntegrityError):
            _save(conn, host="192.0.2.10".upper(), username="other")
        assert [c.username for c in list_connections(conn)] == ["nxray"]
        assert find_by_address(conn, "192.0.2.10", 443) == first
        assert find_by_address(conn, "192.0.2.10", 8443) is None


def test_several_switches_are_kept_apart(db: Path) -> None:
    with open_db(db) as conn:
        first = _save(conn)
        second = _save(conn, host="192.0.2.20", switch_hostname="leaf2", password="Other2Pass")
        assert first != second
        assert [c.switch_hostname for c in list_connections(conn)] == ["nexus-lab", "leaf2"]
        set_unsaved_changes(conn, second, True)
        record_test_result(conn, second, ok=False, message="nope")
        one, two = get_connection(conn, first), get_connection(conn, second)
        assert one is not None and two is not None
        assert not one.unsaved_changes and one.last_tested_at is None
        assert two.unsaved_changes and two.last_test_message == "nope"
        assert load_target(conn, second, "key-a").password == "Other2Pass"
        assert load_target(conn, first, "key-a").password == "Stored1Password"


def test_an_id_is_never_used_again(db: Path) -> None:
    with open_db(db) as conn:
        first = _save(conn)
        delete_connection(conn, first)
        again = _save(conn)
    assert again > first


def test_changed_key_cannot_decrypt(db: Path) -> None:
    with open_db(db) as conn:
        switch_id = _save(conn)
        with pytest.raises(DecryptionError):
            load_target(conn, switch_id, "key-b")


def test_test_results_and_saved_flag(db: Path) -> None:
    with open_db(db) as conn:
        switch_id = _save(conn)
        record_test_result(conn, switch_id, ok=False, message="nope")
        set_config_saved(conn, switch_id, True)
        stored = get_connection(conn, switch_id)
    assert stored is not None
    assert stored.last_test_ok is False and stored.last_test_message == "nope"
    assert stored.last_tested_at is not None
    assert stored.config_saved is True


def test_delete(db: Path) -> None:
    with open_db(db) as conn:
        assert delete_connection(conn, 1) is False
        switch_id = _save(conn)
        assert delete_connection(conn, switch_id) is True
        assert get_connection(conn, switch_id) is None


def test_delete_takes_what_nxray_kept_about_that_switch_only(db: Path) -> None:
    with open_db(db) as conn:
        first = _save(conn)
        second = _save(conn, host="192.0.2.20")
        for switch_id in (first, second):
            conn.execute(
                "INSERT INTO history (switch_id, ts, metric, item, value) "
                "VALUES (?, 1, 'cpu', '', 5)",
                (switch_id,),
            )
            conn.execute(
                "INSERT INTO port_labels (switch_id, port, label, updated_at, updated_by) "
                "VALUES (?, 'Ethernet1/1', 'NAS', 1, 'admin')",
                (switch_id,),
            )
            conn.execute(
                "INSERT INTO alert_open (switch_id, key, since, message) VALUES (?, 'cpu', 1, 'x')",
                (switch_id,),
            )
            conn.execute(
                "INSERT INTO config_backups (switch_id, created_at, created_by, switch, config) "
                "VALUES (?, 1, 'admin', 'x', 'hostname x')",
                (switch_id,),
            )
        conn.commit()
        delete_connection(conn, first)
        for table in ("history", "port_labels", "alert_open", "config_backups"):
            ids = [row[0] for row in conn.execute(f"SELECT switch_id FROM {table}")]
            assert ids == [second], table
