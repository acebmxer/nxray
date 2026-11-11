"""The VTP page, end to end against the fake switch: reading it with the feature off and
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
    """A switch that has been set up (read-only account nxray), vtp off."""
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post("/switch/setup", data=_setup_form(logged_in))
    fake.requests.clear()
    return fake


@pytest.fixture
def on(switch: FakeSwitch) -> FakeSwitch:
    """vtp on, answering with text shaped after Cisco's guide."""
    switch.feature_state["vtp"] = True
    switch.texts["show vtp status"] = (FIXTURES / "show_vtp_status_doc.txt").read_text()
    switch.texts["show vtp interface"] = (FIXTURES / "show_vtp_interface_doc.txt").read_text()
    switch.texts["show vtp counters"] = (FIXTURES / "show_vtp_counters_doc.txt").read_text()
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
    return client.post("/vtp/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/vtp", follow_redirects=False).status_code == 303


def test_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/vtp").text)


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/vtp"' in logged_in.get("/").text


def test_with_the_feature_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/vtp")
    assert page.status_code == 200
    assert "off on the switch, so VTP is not running" in _text(page.text)
    assert switch.requests == [["show feature", "show interface brief"]]


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "vtp"})
    assert saved.status_code == 200
    assert "VTP mode" in _text(saved.text) and enabled.saved


def test_page_reads_the_switch(logged_in: TestClient, on: FakeSwitch) -> None:
    page = logged_in.get("/vtp")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "Transparent" in text and "campus" in text
    assert "Summary advertisements received" in text
    assert on.requests == [
        ["show feature", "show interface brief"],
        ["show vtp status"],
        ["show vtp interface"],
        ["show vtp counters"],
    ]
    assert "show vtp password" not in str(on.requests)
    assert "/vtp/change" not in page.text  # changes are off


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
    assert "VTP changes are off" in _text(logged_in.get("/vtp").text)
    refused = _change(logged_in, scope="vtp_switch", setting="domain", action="set", v_name="x")
    assert refused.status_code == 400
    assert _config_requests(on) == []


def test_enabled_page_offers_the_settings(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/vtp")
    for setting in ("mode", "domain", "version", "password", "vtp"):
        assert f'name="setting" value="{setting}"' in page.text
    # The domain that is set is filled in.
    assert 'value="campus"' in page.text


def test_the_domain_asks_first_then_sends(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {"scope": "vtp_switch", "setting": "domain", "action": "set", "v_name": "lab"}
    asked = _change(logged_in, confirm=False, **fields)
    assert asked.status_code == 200
    assert "vtp domain lab" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["vtp domain lab"]]


def test_the_password_stays_off_the_page(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {
        "scope": "vtp_switch",
        "setting": "password",
        "action": "set",
        "v_password": "s3cret!",
    }
    asked = _change(logged_in, confirm=False, **fields)
    assert "vtp password ***" in _text(asked.text) and "s3cret!" not in _text(asked.text)
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert "s3cret!" not in _text(done.text)
    assert _config_requests(enabled) == [["vtp password s3cret!"]]


def test_vtp_off_on_a_port(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(
        logged_in, scope="vtp_port", setting="vtp", action="remove", id_port="Ethernet1/5"
    )
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["interface Ethernet1/5", "no vtp"]]


def test_a_port_the_switch_lacks_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _change(
        logged_in, scope="vtp_port", setting="vtp", action="remove", id_port="Ethernet1/99"
    )
    assert refused.status_code == 400
    assert _config_requests(enabled) == []
