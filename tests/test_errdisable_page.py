"""The Errdisable page (#87), end to end against the fake switch, and its parsers."""

from __future__ import annotations

import html
import json
import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.errdisable import (
    build_errdisable_change,
    parse_err_disabled,
    parse_errdisable,
    recovery_interval,
)
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"
PORTS_TEXT = (FIXTURES / "show_interface_status_err-disabled_shaped.txt").read_text()


def _body(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _db(settings: Settings, sql: str) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(sql)
    conn.commit()
    conn.close()


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


# ---- parsing ------------------------------------------------------------------------------


def test_the_recorded_tables_give_every_cause_and_the_interval() -> None:
    view = parse_errdisable(
        [_body("show_errdisable_detect"), _body("show_errdisable_recovery")], PORTS_TEXT
    )
    causes = {row[0]: row for row in view.tables[1].rows}
    assert causes["bpduguard"] == ("bpduguard", "on", "off")
    assert causes["inline-power"][2] == "on"  # on from the start, as cisco-25gb shows
    (place,) = view.of("errdisable")
    assert dict(place.facts)["Recovery interval"] == "300 seconds"
    assert place.values == {"interval": {"seconds": "300"}}
    assert recovery_interval(_body("show_errdisable_recovery")) == "300"


def test_err_disabled_ports_are_read_from_the_text() -> None:
    assert parse_err_disabled(PORTS_TEXT) == [
        ("Eth1/5", "lab printer", "bpduguard"),
        ("Eth1/7", "--", "link-flap"),
    ]
    assert parse_err_disabled("Port Name Status Reason\n------\n") == []


def test_the_lines() -> None:
    assert build_errdisable_change(
        "errdisable", "recovery", "set", {}, {"cause": "udld"}
    ).lines == ("errdisable recovery cause udld",)
    assert build_errdisable_change(
        "errdisable", "recovery", "remove", {}, {"cause": "udld"}
    ).lines == ("no errdisable recovery cause udld",)
    assert build_errdisable_change(
        "errdisable", "interval", "set", {}, {"seconds": "600"}
    ).lines == ("errdisable recovery interval 600",)
    with pytest.raises(ValueError):
        build_errdisable_change("errdisable", "interval", "set", {}, {"seconds": "29"})
    with pytest.raises(ValueError):
        build_errdisable_change("errdisable", "recovery", "set", {}, {"cause": "miscabling"})
    with pytest.raises(ValueError):
        build_errdisable_change("errdisable", "interval", "remove", {}, {})


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
    fake.texts["show interface status err-disabled"] = PORTS_TEXT
    fake.requests.clear()
    return fake


def _enable(client: TestClient, settings: Settings, fake: FakeSwitch, mode: str) -> FakeSwitch:
    response = client.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(client, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "role_mode": mode,
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    fake.requests.clear()
    fake.signed_in.clear()
    return fake


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    return _enable(logged_in, settings, switch, "broad")


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/errdisable/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/errdisable", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/errdisable"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/errdisable")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "300 seconds" in text and "lab printer" in text and "bpduguard" in text
    assert switch.requests == [
        ["show errdisable detect", "show errdisable recovery"],
        ["show interface status err-disabled"],
    ]
    assert "/errdisable/change" not in page.text  # changes are off


def test_recovery_asks_first_then_sends(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {"scope": "errdisable", "setting": "recovery", "action": "set", "v_cause": "udld"}
    asked = _change(logged_in, confirm=False, **fields)
    assert "errdisable recovery cause udld" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["errdisable recovery cause udld"]]
    assert enabled.errdisable_lines == ["errdisable recovery cause udld"]


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "errdisable"})
    assert saved.status_code == 200
    assert "Recovery interval" in _text(saved.text) and enabled.saved


def test_with_the_admin_login_stored_the_change_is_sent_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    # The stored mode's own account has only the limited rules (#92).
    _enable(logged_in, settings, switch, "stored")
    done = _change(logged_in, scope="errdisable", setting="interval", action="set", v_seconds="600")
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(switch) == [["errdisable recovery interval 600"]]
    assert "admin" in switch.signed_in


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    refused = _change(
        logged_in, scope="errdisable", setting="recovery", action="set", v_cause="udld"
    )
    assert refused.status_code == 400 and "Errdisable changes are off" in _text(refused.text)
    assert _config_requests(switch) == []
