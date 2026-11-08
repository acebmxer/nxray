"""Config tools: comparing configurations, backups, checkpoints and rollback, from
the functions to the Config page against the fake switch."""

from __future__ import annotations

import html
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.config_tools import (
    clean_config,
    config_diff,
    config_sections,
    diff_counts,
    parse_checkpoints,
    validate_note,
)
from app.nxapi import validate_checkpoint_name
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

SUMMARY = """\
User Checkpoint Summary
--------------------------------------------------------------------------------
1) nxray-1:
Created by nxray
Created at Sun, 10:00:00 01 Nov 2026
Size is 1,234 bytes
Description: None

2) system-fm-vlan:
Created by admin
"""


def test_clean_config_drops_the_time_lines() -> None:
    assert clean_config("\n!Command: show running-config\n!Time: now\nhostname a  \n\n") == [
        "hostname a"
    ]


def test_config_diff() -> None:
    first = "!Time: 1\nhostname a\nvlan 10\nvlan 20\n" + "".join(f"x {n}\n" for n in range(20))
    second = "!Time: 2\nhostname b\nvlan 10\nvlan 20\n" + "".join(f"x {n}\n" for n in range(20))
    diff = config_diff(first, second)
    assert [(d.kind, d.text) for d in diff[:2]] == [
        ("removed", "hostname a"),
        ("added", "hostname b"),
    ]
    assert diff_counts(diff) == (1, 1)
    assert "x 10" not in [d.text for d in diff]  # far from the change
    assert config_diff(first, first.replace("!Time: 1", "!Time: 9")) == []
    two = config_diff("a\n" + "same\n" * 10 + "b\n", "A\n" + "same\n" * 10 + "B\n")
    assert any(d.kind == "gap" for d in two)


def test_config_sections() -> None:
    assert config_sections("! c\ninterface Ethernet1/3\n  switchport\n\nhostname a\n") == [
        ("interface Ethernet1/3", ["switchport"]),
        ("hostname a", []),
    ]


def test_checkpoints_and_names() -> None:
    assert parse_checkpoints(SUMMARY) == ["nxray-1", "system-fm-vlan"]
    assert validate_checkpoint_name("nxray-12") == "nxray-12"
    for bad in ("system-fm-vlan", "nxray-", "nxray-1 ; reload", "nxray-1x"):
        with pytest.raises(ValueError):
            validate_checkpoint_name(bad)


def test_notes() -> None:
    assert validate_note("  before   the change ") == "before the change"
    with pytest.raises(ValueError):
        validate_note("x" * 201)


# ---- the page --------------------------------------------------------------------


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _db(settings: Settings, sql: str) -> list[tuple]:
    conn = sqlite3.connect(settings.db_path)
    rows = conn.execute(sql).fetchall()
    conn.commit()
    conn.close()
    return rows


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "host": "192.0.2.10",
            "port": "443",
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "account_name": "nxray",
            "confirm_save": "yes",
        },
    )
    fake.requests.clear()
    return fake


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    response = logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    switch.requests.clear()
    return switch


def _post(client: TestClient, url: str, **fields):
    return client.post(url, data={"csrf": _csrf(client, "/config"), **fields})


def test_config_page_is_for_admins_only(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    assert 'href="/config"' in logged_in.get("/").text
    _db(settings, "UPDATE users SET role = 'operator'")
    assert logged_in.get("/config").status_code == 403
    assert 'href="/config"' not in logged_in.get("/").text


def test_page_without_the_role_to_read(logged_in: TestClient, switch: FakeSwitch) -> None:
    text = _text(logged_in.get("/config").text)
    assert "NXray reads the configuration once its role allows it" in text


def test_running_and_saved(logged_in: TestClient, enabled: FakeSwitch) -> None:
    text = _text(logged_in.get("/config").text)
    assert "The running configuration is saved" in text
    enabled.hostname = "core-9"
    text = _text(logged_in.get("/config").text)
    assert "differs from the saved one: 1 line only in the saved, 1 only in the running" in text
    assert "- hostname nexus-lab" in text and "+ hostname core-9" in text


def test_backup_checkpoint_compare_download_delete(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    done = _post(logged_in, "/config/backup", note="before the change")
    assert done.status_code == 200, _text(done.text)
    assert "Backup 1 is stored in NXray, and the switch keeps it as nxray-1" in _text(done.text)
    assert "nxray-1" in enabled.checkpoints
    rows = _db(settings, "SELECT created_by, note, checkpoint FROM config_backups")
    assert rows == [("admin", "before the change", "nxray-1")]

    enabled.hostname = "core-9"
    compared = _text(logged_in.get("/config?a=backup-1&b=running").text)
    assert "From backup 1 (before the change) to the running configuration" in compared
    assert "+ hostname core-9" in compared

    download = logged_in.get("/config/backup/1.txt")
    assert download.status_code == 200 and "hostname nexus-lab" in download.text
    assert "attachment" in download.headers["content-disposition"]

    asked = _post(logged_in, "/config/backup/delete", id="1")
    assert "The switch's checkpoint nxray-1 is deleted too" in _text(asked.text)
    assert "nxray-1" in enabled.checkpoints
    deleted = _post(logged_in, "/config/backup/delete", id="1", confirm="yes")
    assert "backup 1 is deleted" in _text(deleted.text)
    assert enabled.checkpoints == {}
    assert _db(settings, "SELECT COUNT(*) FROM config_backups") == [(0,)]


def test_backup_without_security_changes_has_no_checkpoint(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 12")
    text = _text(_post(logged_in, "/config/backup").text)
    assert "The switch made no checkpoint for it" in text
    assert enabled.checkpoints == {}
    assert "Roll back to this" not in logged_in.get("/config").text


def test_rollback_asks_for_the_admin_login_and_keeps_a_backup_first(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _post(logged_in, "/config/backup")
    enabled.hostname = "core-9"
    asked = _post(logged_in, "/config/rollback", id="1")
    text = _text(asked.text)
    assert "Roll back to backup 1" in text and "- hostname core-9" in text
    assert "+ hostname nexus-lab" in text
    assert 'name="admin_password"' in asked.text
    assert enabled.hostname == "core-9"

    missing = _post(logged_in, "/config/rollback", id="1", confirm="yes", admin_user="admin")
    assert "Enter the switch's admin username and password" in _text(missing.text)

    wrong = _post(logged_in, "/config/rollback", id="1", confirm="yes", admin_user="admin",
                  admin_password="Wrong-pw-1")  # fmt: skip
    assert "Not rolled back" in _text(wrong.text)
    assert "Wrong-pw-1" not in wrong.text
    assert enabled.hostname == "core-9"

    done = _post(logged_in, "/config/rollback", id="1", confirm="yes", admin_user="admin",
                 admin_password=ADMIN_PASSWORD)  # fmt: skip
    text = _text(done.text)
    assert "the switch is rolled back to backup 1" in text, text
    assert enabled.hostname == "nexus-lab"
    # Each attempt first kept the configuration it would replace.
    notes = [r[0] for r in _db(settings, "SELECT note FROM config_backups ORDER BY id")]
    assert notes[0] == "" and notes[-1] == "before rolling back to backup 1"
    assert "hostname core-9" in logged_in.get(f"/config/backup/{len(notes)}.txt").text
    assert _db(settings, "SELECT unsaved_changes FROM switch_connection") == [(1,)]
    # Sent once: the wrong password was refused at sign-in, before any command.
    sent = [r for r in enabled.requests if any(c.startswith("rollback") for c in r)]
    assert sent == [["rollback running-config checkpoint nxray-1"]]
    activity = _text(logged_in.get("/activity").text)
    assert "Rolled the switch back to backup 1 (nxray-1)" in activity
    assert ADMIN_PASSWORD not in logged_in.get("/activity").text


def test_rollback_refused_by_the_switch_changes_nothing(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    _post(logged_in, "/config/backup")
    enabled.hostname = "core-9"
    enabled.rollback_text = "Rollback failed: verification error.\n"
    done = _post(logged_in, "/config/rollback", id="1", confirm="yes", admin_user="admin",
                 admin_password=ADMIN_PASSWORD)  # fmt: skip
    assert done.status_code == 400
    assert "Not rolled back" in _text(done.text) and enabled.hostname == "core-9"


def test_rollback_needs_the_checkpoint_on_the_switch(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    _post(logged_in, "/config/backup")
    enabled.checkpoints.clear()
    text = _text(_post(logged_in, "/config/rollback", id="1").text)
    assert "the switch has no checkpoint for backup 1" in text
    assert "gone from the switch" in _text(logged_in.get("/config").text)


def test_save_config_from_the_config_page(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.hostname = "core-9"
    saved = _post(logged_in, "/switch/save", back="config")
    assert "The running configuration is saved" in _text(saved.text)


def test_restart_page_asks_the_right_question(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    # A role from before the restart rules: the confirm page asks for the admin login.
    _db(settings, "UPDATE switch_connection SET role_version = 17")
    saved = _post(logged_in, "/config/reload")
    text = _text(saved.text)
    assert "Are you sure you want to restart the switch" in text
    assert "Save first" not in text and "Do you want to save" not in text
    assert 'name="admin_user"' in saved.text
    enabled.hostname = "core-9"
    unsaved = _text(_post(logged_in, "/config/reload").text)
    assert "Do you want to save the changes first" in unsaved
    assert "Save first" in unsaved and "Are you sure" not in unsaved


def test_restart_goes_straight_ahead_when_nothing_is_unsaved(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    done = _text(_post(logged_in, "/config/reload").text)
    assert "the switch is restarting" in done
    assert enabled.reloads == 1
    assert enabled.saved_at_reload == [True]


def test_restart_with_unsaved_changes_asks_without_a_login(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.hostname = "core-9"
    page = _post(logged_in, "/config/reload")
    assert "Do you want to save the changes first" in _text(page.text)
    assert 'name="admin_user"' not in page.text
    assert enabled.reloads == 0
    kept = _post(logged_in, "/config/reload", confirm="yes", save="yes")
    assert "restarting, with its configuration saved first" in _text(kept.text)
    assert enabled.reloads == 1
    assert enabled.saved_at_reload == [True]


def test_restart_is_refused_when_the_role_lacks_the_rule(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 17")
    page = _post(logged_in, "/config/reload", confirm="yes")
    assert "Enter the switch" in _text(page.text)
    assert enabled.reloads == 0
