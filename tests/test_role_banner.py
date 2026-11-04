"""The banner on every page when NXray's role on a switch is behind the code."""

from __future__ import annotations

import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.port_changes import ROLE_VERSION
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

BANNER = "is behind this version of NXray"


def _flat(html: str) -> str:
    return re.sub(r"\s+", " ", html)


def _set_version(settings: Settings, version: int) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE switch_connection SET role_version = ?", (version,))
    conn.commit()
    conn.close()


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    page = logged_in.get("/switch").text
    token = re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)  # type: ignore[union-attr]
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": token,
            "host": "192.0.2.10",
            "port": "443",
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "account_name": "nxray",
            "confirm_save": "yes",
        },
    )
    return fake


def test_banner_on_every_page_when_the_role_is_behind(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _set_version(settings, 1)
    for path in ("/", "/ports", "/account"):
        html = logged_in.get(path).text
        assert BANNER in _flat(html), path
        assert 'href="/switch"' in html


def test_no_banner_when_the_role_is_current(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _set_version(settings, ROLE_VERSION)
    assert BANNER not in _flat(logged_in.get("/account").text)


def test_no_banner_when_changes_were_never_turned_on(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _set_version(settings, 0)
    assert BANNER not in _flat(logged_in.get("/account").text)


def test_no_banner_on_the_switch_page_itself(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _set_version(settings, 1)
    assert BANNER not in _flat(logged_in.get("/switch").text)
