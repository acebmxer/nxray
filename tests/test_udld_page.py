"""The UDLD page, end to end against the fake switch: reading it with the feature off and
on, who may change it, and a change from asking to sent."""

from __future__ import annotations

import html
import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


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


def _setup_form(client: TestClient, **extra: str) -> dict[str, str]:
    return {
        "csrf": _csrf(client, "/switch"),
        "host": "192.0.2.10",
        "port": "443",
        "admin_user": "admin",
        "admin_password": ADMIN_PASSWORD,
        "account_name": "nxray",
        "confirm_save": "yes",
        **extra,
    }


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    """A switch that has been set up (read-only account nxray), udld off."""
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post("/switch/setup", data=_setup_form(logged_in))
    fake.requests.clear()
    return fake


@pytest.fixture
def on(switch: FakeSwitch) -> FakeSwitch:
    """udld on, answering with text shaped after Cisco's guide."""
    switch.feature_state["udld"] = True
    switch.texts["show udld global"] = (FIXTURES / "show_udld_global_doc.txt").read_text()
    switch.texts["show udld"] = (FIXTURES / "show_udld_doc.txt").read_text()
    return switch


@pytest.fixture
def enabled(logged_in: TestClient, on: FakeSwitch, settings: Settings) -> FakeSwitch:
    """Changes on with the broad role, and the wait over."""
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
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    on.requests.clear()
    on.saved = False
    return on


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/udld/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/udld", follow_redirects=False).status_code == 303


def test_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/udld").text)


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/udld"' in logged_in.get("/").text


def test_with_the_feature_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/udld")
    assert page.status_code == 200
    assert "off on the switch, so UDLD is not running" in _text(page.text)
    assert switch.requests == [["show feature", "show interface brief"]]


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "udld"})
    assert saved.status_code == 200
    assert "one way only" in _text(saved.text) and enabled.saved


def test_page_reads_the_switch(logged_in: TestClient, on: FakeSwitch) -> None:
    page = logged_in.get("/udld")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "enabled-aggressive" in text and "core-1" in text and "Ethernet1/49" in text
    assert on.requests == [
        ["show feature", "show interface brief"],
        ["show udld global"],
        ["show udld"],
    ]
    assert "/udld/change" not in page.text  # changes are off


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, on: FakeSwitch, settings: Settings
) -> None:
    logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    on.requests.clear()
    assert "UDLD changes are off" in _text(logged_in.get("/udld").text)
    refused = _change(
        logged_in,
        scope="udld_port",
        setting="state",
        action="set",
        id_port="Ethernet1/5",
        v_state="enable",
    )
    assert refused.status_code == 400
    assert _config_requests(on) == []


def test_enabled_page_offers_the_settings(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/udld")
    for setting in ("state", "aggressive", "message_time"):
        assert f'name="setting" value="{setting}"' in page.text
    assert '<option value="Ethernet1/1"' in page.text
    assert '<option value="port-channel' not in page.text


def test_a_port_asks_first_then_sends(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {
        "scope": "udld_port",
        "setting": "state",
        "action": "set",
        "id_port": "Ethernet1/5",
        "v_state": "enable",
    }
    asked = _change(logged_in, confirm=False, **fields)
    assert asked.status_code == 200
    assert "udld enable" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["interface Ethernet1/5", "udld enable"]]
    assert enabled.udld_lines == ["interface Ethernet1/5 ; udld enable"]


def test_the_message_interval(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(
        logged_in, scope="udld_switch", setting="message_time", action="set", v_seconds="30"
    )
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["udld message-time 30"]]


def test_a_port_channel_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _change(
        logged_in,
        scope="udld_port",
        setting="state",
        action="set",
        id_port="port-channel20",
        v_state="enable",
    )
    assert refused.status_code == 400
    assert _config_requests(enabled) == []
