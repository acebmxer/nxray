"""The Scheduler page (#73), end to end against the fake switch, its parsers, the shared
command menu and the time values."""

from __future__ import annotations

import html
import json
import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.command_menu import BACKUP, CLEAR, PORT_OFF, SAVE, SHOW, menu_lines
from app.config import Settings
from app.protocols import Field, check_value
from app.scheduler import build_scheduler_change, parse_jobs, parse_scheduler
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"


def _body(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


BODIES = [
    _body("show_scheduler_config"),
    _body("show_scheduler_schedule"),
    _body("show_scheduler_logfile"),
]


# ---- the menu and the values ----------------------------------------------------------


def test_menu_entries_become_their_lines() -> None:
    assert menu_lines(SAVE) == ["copy running-config startup-config"]
    assert menu_lines(BACKUP, file="nightly.cfg") == ["copy running-config bootflash:nightly.cfg"]
    assert menu_lines(PORT_OFF, port="Ethernet1/5") == [
        "configure terminal",
        "interface Ethernet1/5",
        "shutdown",
    ]
    assert menu_lines(CLEAR, port="Ethernet1/5") == ["clear counters interface Ethernet1/5"]
    assert menu_lines(SHOW, show="show version") == ["show version"]
    for entry, kwargs in ((BACKUP, {}), (PORT_OFF, {}), (SHOW, {"show": "show tech-support"})):
        with pytest.raises(ValueError):
            menu_lines(entry, **kwargs)
    with pytest.raises(ValueError):
        menu_lines("username x role network-admin")


@pytest.mark.parametrize(
    ("raw", "sent"),
    [
        ("now", "now"),
        ("+2:00", "+02:00"),
        ("23:30", "23:30"),
        ("2026-12-1 3:00", "2026:12:01:03:00"),
    ],
)
def test_start_times(raw: str, sent: str) -> None:
    assert check_value(Field("s", "Start", "schedstart"), raw) == sent


@pytest.mark.parametrize(("raw", "sent"), [("2:00", "02:00"), ("1:00:00", "1:00:00")])
def test_repeats(raw: str, sent: str) -> None:
    assert check_value(Field("r", "Repeat", "schedrepeat"), raw) == sent


@pytest.mark.parametrize(
    ("kind", "raw"),
    [
        ("schedstart", "tomorrow"),
        ("schedstart", "2026-13-01 03:00"),
        ("schedrepeat", "0:00"),
        ("schedrepeat", "24:00"),
        ("flashfile", "../x.cfg"),
        ("flashfile", "a b.cfg"),
    ],
)
def test_bad_values_are_refused(kind: str, raw: str) -> None:
    with pytest.raises(ValueError):
        check_value(Field("x", "X", kind), raw)


# ---- parsing and lines ---------------------------------------------------------------


def test_jobs_schedules_and_log_are_read() -> None:
    assert parse_jobs(BODIES[0]) == {
        "probe": ["show version"],
        "clock": ["show clock"],
        "empty": [],
        "nightly": ["copy running-config bootflash:/nightly.cfg"],
    }
    view = parse_scheduler(BODIES)
    (scheduler,) = view.of("scheduler")
    assert scheduler.values == {"logfile": {"kb": "16"}}
    backup = next(i for i in view.of("schedule") if i.ident == {"schedule": "backup"})
    facts = dict(backup.facts)
    assert facts["When"] == "time start 2026:11:11:22:41 repeat 1:0"
    assert facts["Made by"] == "admin" and facts["Times run"] == "1"
    assert facts["Jobs"] == "clock (Success (0)), nightly (Success (0))"
    night = next(i for i in view.of("schedule") if i.ident == {"schedule": "night"})
    assert night.values == {"daily": {"at": "03:05"}}
    (log,) = view.tables
    assert log.rows[1][0] == "nightly" and log.rows[1][4] == "Success"
    assert "Copy complete." in log.rows[1][5]
    assert parse_scheduler([None, None, None]).of("job") == []


def test_making_a_job_sends_all_its_lines_at_once() -> None:
    change = build_scheduler_change(
        "job",
        "make",
        "set",
        {"job": "nightly"},
        {"command1": BACKUP, "command2": PORT_OFF, "file": "nightly.cfg", "port": "Ethernet1/5"},
    )
    assert change.lines == (
        "scheduler job name nightly",
        "copy running-config bootflash:nightly.cfg",
        "configure terminal",
        "interface Ethernet1/5",
        "shutdown",
    )
    assert "make job nightly" in change.describe
    with pytest.raises(ValueError):
        build_scheduler_change("job", "make", "set", {"job": "x"}, {"command1": BACKUP})
    with pytest.raises(ValueError):
        build_scheduler_change("job", "make", "set", {"job": "x"}, {"command1": "reload"})


def test_schedule_lines() -> None:
    def lines(setting: str, action: str = "set", **values: str):
        return build_scheduler_change("schedule", setting, action, {"schedule": "s"}, values).lines

    assert lines("weekly", day="Sun", at="03:00")[-1] == "time weekly Sun:03:00"
    assert lines("start", start="now", repeat="1:00:00")[-1] == "time start now repeat 1:00:00"
    assert lines("daily", "remove")[-1] == "no time"
    with pytest.raises(ValueError):
        lines("start", start="now")
    deleted = build_scheduler_change("schedule", "", "delete", {"schedule": "s"}, {})
    assert deleted.lines == (
        "scheduler schedule name s",
        "no time",
        "exit",
        "no scheduler schedule name s",
    )


# ---- the page -----------------------------------------------------------------------------


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
def on(switch: FakeSwitch) -> FakeSwitch:
    switch.feature_state["scheduler"] = True
    for command, body in zip(
        ("show scheduler config", "show scheduler schedule", "show scheduler logfile"),
        BODIES,
        strict=True,
    ):
        switch.bodies[command] = body
    return switch


@pytest.fixture
def enabled(logged_in: TestClient, on: FakeSwitch, settings: Settings) -> FakeSwitch:
    response = logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "role_mode": "broad",
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    conn = sqlite3.connect(settings.db_path)
    conn.execute(f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    conn.commit()
    conn.close()
    on.requests.clear()
    return on


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/scheduler/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/scheduler", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/scheduler"' in logged_in.get("/").text


def test_with_the_feature_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/scheduler")
    assert "off on the switch, so Scheduler is not running" in _text(page.text)
    assert switch.requests == [["show feature", "show interface brief"]]


def test_page_reads_the_switch(logged_in: TestClient, on: FakeSwitch) -> None:
    page = logged_in.get("/scheduler")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "nightly" in text and "Copy complete." in text and "time daily 03:05" in text
    assert on.requests == [
        ["show feature", "show interface brief"],
        ["show scheduler config", "show scheduler schedule", "show scheduler logfile"],
    ]


def test_a_job_is_made_from_the_menu(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {
        "scope": "job",
        "setting": "make",
        "action": "set",
        "id_job": "tidy",
        "v_command1": SHOW,
        "v_show": "show clock",
        "v_command2": SAVE,
    }
    asked = _change(logged_in, confirm=False, **fields)
    assert "scheduler job name tidy" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [
        ["scheduler job name tidy", "show clock", "copy running-config startup-config"]
    ]
    again = _change(logged_in, **fields)
    assert again.status_code == 400 and "job exists" in _text(again.text)


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "scheduler"})
    assert saved.status_code == 200 and "Schedules" in _text(saved.text)
