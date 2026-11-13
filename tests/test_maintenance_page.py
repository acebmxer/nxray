"""The Maintenance mode page (#95), end to end against the fake switch, and its parsers."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.maintenance import (
    build_maintenance_change,
    parse_maintenance,
    parse_mode,
    parse_profiles,
    parse_reasons,
    parse_snapshots,
)
from app.port_changes import BROAD_RULES, ROLE_NAME, SNAPSHOT_RULES
from app.switch_connection import BROAD_MAINTENANCE_VERSION, BROAD_ROLE_VERSION
from tests.fake_switch import FakeSwitch
from tests.stage_d_helpers import config_requests, csrf, enable, set_up, text

FIXTURES = Path(__file__).parent / "fixtures"
# Recorded on cisco-25gb (NX-OS 9.3(16), 2026-11-13).
SNAPSHOTS = (FIXTURES / "show_snapshots.txt").read_text()
COMPARE = (FIXTURES / "show_snapshots_compare_summary.txt").read_text()
REASONS = (
    "Reset reasons for on-reload maintenance mode:\n" + "-" * 44 + "\n"
    "HW_ERROR\nMANUAL_RELOAD\nMAINTENANCE\n\nbitmap = 0xc1\n"
)
NONE = (
    "Reset reasons for on-reload maintenance mode:\n"
    + "-" * 44
    + "\n(not configured)\n\nbitmap = 0x0\n"
)


def _lines(scope, setting="", action="set", ident=None, **values):
    return list(build_maintenance_change(scope, setting, action, ident or {}, values).lines)


def test_the_lines() -> None:
    assert _lines("mode", "timeout", minutes="30") == ["system mode maintenance timeout 30"]
    assert _lines("mode", "timeout", "remove", minutes="30") == [
        "no system mode maintenance timeout 30"
    ]
    assert _lines("mode", "maint_delay", seconds="0") == ["system mode maintenance maint-delay 0"]
    assert _lines("mode", "snapshot_delay", seconds="65535") == [
        "system mode maintenance snapshot-delay 65535"
    ]
    assert _lines("mode", "custom_profile") == ["system mode maintenance always-use-custom-profile"]
    assert _lines("mode", "reload_reason", reason="HW_ERROR") == [
        "system mode maintenance on-reload reset-reason HW_ERROR"
    ]
    one = {"name": "before", "description": "Before the upgrade"}
    assert _lines("snapshot", action="create", ident=one) == [
        "snapshot create before Before the upgrade"
    ]
    assert _lines("snapshot", action="delete", ident=one) == ["snapshot delete before"]
    assert _lines("compare", "summary", first="a", second="b") == [
        "show snapshots compare a b summary"
    ]


@pytest.mark.parametrize(
    ("scope", "setting", "values"),
    [
        ("mode", "timeout", {"minutes": "4"}),  # the switch: range is (5:65535)
        ("mode", "timeout", {"minutes": "65536"}),
        ("mode", "maint_delay", {"seconds": "65536"}),
        ("mode", "snapshot_delay", {"seconds": "-1"}),
        ("mode", "reload_reason", {"reason": "POWER"}),
        ("compare", "summary", {"first": "a", "second": "b c"}),
    ],
)
def test_the_checks(scope: str, setting: str, values: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        build_maintenance_change(scope, setting, "set", {}, values)


def test_a_snapshot_needs_a_description_and_leaves_nothing_to_save() -> None:
    with pytest.raises(ValueError):
        build_maintenance_change("snapshot", "", "create", {"name": "x"}, {})
    change = build_maintenance_change(
        "snapshot", "", "create", {"name": "x", "description": "d"}, {}
    )
    assert change.config is False


def test_the_texts_are_read() -> None:
    assert parse_mode("System Mode: Normal\n") == "Normal" and parse_mode(None) == ""
    assert parse_reasons(REASONS) == ["HW_ERROR", "MANUAL_RELOAD", "MAINTENANCE"]
    assert parse_reasons(NONE) == []
    assert parse_snapshots(SNAPSHOTS) == [
        ("nxprobe1", "Fri Nov 13 20:48:12 2026", "first probe snapshot"),
        ("nxprobe2", "Fri Nov 13 20:49:30 2026", "second"),
    ]
    assert parse_profiles("[Normal Mode]\n\n[Maintenance Mode]\nrouter bgp 1\n  shutdown\n\n") == [
        ("Normal Mode", ""),
        ("Maintenance Mode", "router bgp 1; shutdown"),
    ]


def test_the_view_shows_the_mode_and_what_is_set() -> None:
    view = parse_maintenance(
        "System Mode: Normal\n",
        "Maintenance mode timeout value: 30 minutes\n",
        "maintenance CLI release delay value: 100 seconds\n",
        "after_maintenance snapshot delay default value: 120 seconds\n",
        REASONS,
        "[Normal Mode]\n\n[Maintenance Mode]\n\n",
        SNAPSHOTS,
    )
    mode, *snapshots = view.instances
    assert mode.values == {"timeout": {"minutes": "30"}, "maint_delay": {"seconds": "100"}}
    facts = dict(mode.facts)
    assert facts["System mode"] == "Normal" and facts["Time limit"] == "30 minutes"
    assert facts["Starts in maintenance mode after a restart for"] == (
        "HW_ERROR, MANUAL_RELOAD, MAINTENANCE"
    )
    assert [s.title for s in snapshots] == ["nxprobe1", "nxprobe2"]
    assert any("does not put the switch into or out of maintenance mode" in n for n in view.notes)
    unset = parse_maintenance(
        "System Mode: Maintenance\n",
        "Maintenance mode timeout value: 0 minutes\n",
        "maintenance CLI release delay default value: 120 seconds\n",
        None,
        NONE,
        "",
        "",
    )
    assert unset.instances[0].values == {}
    assert dict(unset.instances[0].facts)["Time limit"] == "none"
    assert "The switch is in Maintenance mode now." in unset.notes[0]


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    return set_up(logged_in)


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/maintenance/change", data=data)


def _db(settings: Settings, sql: str) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(sql)
    conn.commit()
    conn.close()


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/maintenance", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/maintenance"' in logged_in.get("/").text


def test_page_reads_the_mode_and_the_snapshots(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.snapshots["nxprobe1"] = ("Fri Nov 13 20:48:12 2026", "first probe snapshot")
    page = logged_in.get("/maintenance")
    assert page.status_code == 200, text(page.text)
    shown = text(page.text)
    assert "System mode Normal" in shown and "first probe snapshot" in shown
    assert "never puts" not in shown and "does not put the switch into" in shown
    assert [r[0] for r in switch.requests][:2] == ["show system mode", "show maintenance timeout"]


def test_settings_are_sent_and_read_back(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    asked = _change(
        logged_in, confirm=False, scope="mode", setting="timeout", action="set", v_minutes="30"
    )
    assert "system mode maintenance timeout 30" in text(asked.text)
    assert config_requests(switch) == []
    done = _change(logged_in, scope="mode", setting="timeout", action="set", v_minutes="30")
    assert done.status_code == 200, text(done.text)
    assert "system mode maintenance timeout 30" in switch.mon_lines
    assert "30 minutes" in text(logged_in.get("/maintenance").text)
    back = _change(logged_in, scope="mode", setting="timeout", action="remove", v_minutes="30")
    assert back.status_code == 200 and not switch.mon_lines
    reason = _change(
        logged_in, confirm=False, scope="mode", setting="reload_reason", action="set",
        v_reason="HW_ERROR",
    )  # fmt: skip
    assert "starts in maintenance mode" in text(reason.text)
    assert "off the network" in text(reason.text)


def test_the_switchs_refusal_is_shown(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    refused = _change(logged_in, scope="mode", setting="timeout", action="set", v_minutes="4")
    assert refused.status_code == 400 and "Not changed" in text(refused.text)
    assert switch.mon_lines == []


def test_a_snapshot_is_taken_compared_and_deleted(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    for name in ("before", "after"):
        done = _change(
            logged_in, scope="snapshot", action="create", id_name=name, id_description="d"
        )
        assert done.status_code == 200, text(done.text)
        assert f"Snapshot '{name}' created" in text(done.text)
    assert set(switch.snapshots) == {"before", "after"}
    assert "NXray changed the switch" not in text(
        logged_in.get("/maintenance").text
    )  # a snapshot is no configuration, so there is nothing to save
    compared = _change(
        logged_in, scope="compare", setting="summary", action="set", v_first="before",
        v_second="after",
    )  # fmt: skip
    assert compared.status_code == 200, text(compared.text)
    assert "# of interfaces" in text(compared.text)
    gone = _change(
        logged_in, scope="snapshot", action="delete", id_name="before", id_description="d"
    )
    assert gone.status_code == 200 and set(switch.snapshots) == {"after"}
    assert switch.mon_ran == [
        "snapshot create before d",
        "snapshot create after d",
        "snapshot delete before",
    ]


def test_the_broad_role_allows_snapshots() -> None:
    assert set(SNAPSHOT_RULES) <= set(BROAD_RULES)
    assert BROAD_ROLE_VERSION == BROAD_MAINTENANCE_VERSION


def test_the_switch_refuses_a_snapshot_without_the_rule(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    for rule in SNAPSHOT_RULES:
        switch.roles[ROLE_NAME].entities.discard(rule.split(" command ", 1)[1])
    refused = _change(logged_in, scope="snapshot", action="create", id_name="x", id_description="d")
    assert refused.status_code == 400 and "may not make this change yet" in text(refused.text)
    assert switch.snapshots == {}


def test_a_broad_role_written_before_snapshots_is_refused_until_updated(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    for rule in SNAPSHOT_RULES:
        switch.roles[ROLE_NAME].entities.discard(rule.split(" command ", 1)[1])
    _db(settings, f"UPDATE switch_connection SET role_version = {BROAD_MAINTENANCE_VERSION - 1}")
    refused = _change(logged_in, scope="snapshot", action="create", id_name="x", id_description="d")
    assert refused.status_code == 400 and "Update the port list" in text(refused.text)
    assert switch.mon_ran == []
    assert "allowed taking and deleting a snapshot" in text(logged_in.get("/switch").text)
    setting = _change(logged_in, scope="mode", setting="timeout", action="set", v_minutes="30")
    assert setting.status_code == 200, text(setting.text)  # a setting needs no new rule


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "limited")
    refused = _change(logged_in, scope="mode", setting="timeout", action="set", v_minutes="30")
    assert refused.status_code == 400 and "Maintenance mode changes are off" in text(refused.text)
    assert config_requests(switch) == []


def test_nothing_here_enters_maintenance_mode() -> None:
    """The one command that takes the switch off the network is not in any scope."""
    from app.maintenance import SCOPES

    allowed = re.compile(
        r"system mode maintenance (timeout|maint-delay|snapshot-delay|always-use-custom-profile"
        r"|on-reload reset-reason) ?.*"
    )
    lines = [line for scope in SCOPES for setting in scope.settings for line in (setting.line,)]
    lines += [line for scope in SCOPES for line in (*scope.enter, *(scope.delete or ()))]
    for line in lines:
        assert "system mode" not in line or allowed.fullmatch(line), line


def test_save_config_comes_back_here(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    saved = logged_in.post("/switch/save", data={"csrf": csrf(logged_in), "back": "maintenance"})
    assert saved.status_code == 200 and "Maintenance mode" in text(saved.text) and switch.saved
