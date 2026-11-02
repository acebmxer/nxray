"""Resetting a port, several ticked ports, or a port-channel through the pages (#21)."""

from __future__ import annotations

import html
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


def _csrf(client: TestClient, path: str = "/switch") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": _csrf(logged_in),
            "host": "192.0.2.10",
            "port": "443",
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "account_name": "nxray",
            "confirm_save": "yes",
        },
    )
    return fake


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    """Every kind of change on (role version 16), the wait over."""
    response = logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE switch_connection SET paused_until = ?", (time.time() - 1,))
    conn.commit()
    conn.close()
    switch.requests.clear()
    switch.saved = False
    return switch


def _db(settings: Settings, sql: str) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(sql)
    conn.commit()
    conn.close()


# ---- one port -----------------------------------------------------------------


def test_port_page_offers_reset_and_lists_what_it_removes(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    page = logged_in.get("/ports/detail?name=Ethernet1/3").text
    assert 'action="/ports/reset"' in page and "Reset to defaults" in page

    asked = logged_in.post("/ports/reset", data={"csrf": _csrf(logged_in), "name": "Ethernet1/3"})
    assert asked.status_code == 200
    text = _text(asked.text)
    assert "Confirm the change" in text
    assert "Ethernet1/3" in text and ("loses" in text or "nothing to remove" in text)
    assert _config_requests(enabled) == []


def test_resetting_a_port_sends_default_interface(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    done = logged_in.post(
        "/ports/reset",
        data={"csrf": _csrf(logged_in), "name": "Ethernet1/3", "confirm": "yes"},
    )
    assert done.status_code == 200
    assert "Done: Ethernet1/3 was reset to its defaults" in _text(done.text)
    assert _config_requests(enabled) == [["default interface Ethernet1/3"]]


def test_reset_is_off_without_role_version_16(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 15")
    page = _text(logged_in.get("/ports/detail?name=Ethernet1/3").text)
    assert "Resetting ports is off" in page and "Reset to defaults" not in page
    refused = logged_in.post(
        "/ports/reset",
        data={"csrf": _csrf(logged_in), "name": "Ethernet1/3", "confirm": "yes"},
    )
    assert refused.status_code == 400
    assert "Resetting a port is off" in refused.text
    assert _config_requests(enabled) == []


def test_reset_needs_a_csrf_token(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = logged_in.post("/ports/reset", data={"csrf": "wrong", "name": "Ethernet1/3"})
    assert response.status_code in (400, 403)
    assert _config_requests(enabled) == []


# ---- several ticked ports -------------------------------------------------------


def test_bulk_reset_asks_then_resets_every_ticked_port(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    asked = logged_in.post(
        "/ports/reset-bulk",
        data={"csrf": _csrf(logged_in), "names": ["Ethernet1/1", "Ethernet1/2"]},
    )
    assert asked.status_code == 200
    text = _text(asked.text)
    assert "Ethernet1/1" in text and "Ethernet1/2" in text
    assert _config_requests(enabled) == []

    done = logged_in.post(
        "/ports/reset-bulk",
        data={
            "csrf": _csrf(logged_in),
            "names": ["Ethernet1/1", "Ethernet1/2"],
            "confirm": "yes",
        },
    )
    assert done.status_code == 200
    assert "Done: reset Ethernet1/1, Ethernet1/2 to their defaults" in _text(done.text)
    assert _config_requests(enabled) == [
        ["default interface Ethernet1/1", "default interface Ethernet1/2"]
    ]


def test_bulk_reset_refuses_an_unknown_port(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = logged_in.post(
        "/ports/reset-bulk",
        data={"csrf": _csrf(logged_in), "names": ["Ethernet1/99"], "confirm": "yes"},
    )
    assert response.status_code == 400
    assert "Not reset" in response.text
    assert _config_requests(enabled) == []


def test_bulk_reset_needs_a_ticked_port(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = logged_in.post(
        "/ports/reset-bulk", data={"csrf": _csrf(logged_in), "confirm": "yes"}
    )
    assert response.status_code == 400
    assert _config_requests(enabled) == []


# ---- a port-channel ---------------------------------------------------------------


def test_channel_page_offers_reset(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/port-channels").text
    assert 'action="/port-channels/reset"' in page
    assert "Reset port-channel43 to defaults" in page


def test_resetting_a_channel_sends_default_interface(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    asked = logged_in.post("/port-channels/reset", data={"csrf": _csrf(logged_in), "number": "43"})
    assert asked.status_code == 200
    assert "Confirm the change" in _text(asked.text)
    assert _config_requests(enabled) == []

    done = logged_in.post(
        "/port-channels/reset",
        data={"csrf": _csrf(logged_in), "number": "43", "confirm": "yes"},
    )
    assert done.status_code == 200
    assert "Done:" in _text(done.text) and "port-channel43" in _text(done.text)
    assert _config_requests(enabled) == [["default interface port-channel43"]]


def test_channel_reset_is_off_without_role_version_16(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 15")
    page = logged_in.get("/port-channels").text
    assert "Reset port-channel43 to defaults" not in page
    refused = logged_in.post(
        "/port-channels/reset",
        data={"csrf": _csrf(logged_in), "number": "43", "confirm": "yes"},
    )
    assert refused.status_code == 400
    assert "Resetting a port-channel is off" in refused.text
    assert _config_requests(enabled) == []


def test_resetting_an_unknown_channel_is_refused(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    response = logged_in.post(
        "/port-channels/reset",
        data={"csrf": _csrf(logged_in), "number": "7", "confirm": "yes"},
    )
    assert response.status_code == 400
    assert "no port-channel7" in response.text
    assert _config_requests(enabled) == []
