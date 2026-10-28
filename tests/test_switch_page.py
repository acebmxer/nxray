"""The Switch page and the dashboard, against a pretend switch."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.security import SESSION_COOKIE
from tests.conftest import TEST_PASSWORD, TEST_USER, with_settings
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    return fake


def _csrf(client: TestClient, path: str = "/switch") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, "no csrf field on the page"
    return match.group(1)


def _setup_form(client: TestClient, **overrides: str) -> dict[str, str]:
    form = {
        "csrf": _csrf(client),
        "host": "192.0.2.10",
        "port": "443",
        "admin_user": "admin",
        "admin_password": ADMIN_PASSWORD,
        "account_name": "nxray",
        "confirm_save": "yes",
    }
    form.update(overrides)
    return form


def _set_up(client: TestClient, **overrides: str):
    return client.post("/switch/setup", data=_setup_form(client, **overrides))


# ---- before setup -------------------------------------------------------


def test_dashboard_points_to_setup(logged_in: TestClient) -> None:
    body = logged_in.get("/").text
    assert "No switch connected yet" in body
    assert 'href="/switch"' in body


def test_setup_form_shows_the_save_warning_and_default_name(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    body = logged_in.get("/switch").text
    assert "Set up the switch" in body
    assert 'name="account_name" type="text" value="nxray"' in body
    assert "also saves any other" in body
    assert 'name="confirm_save"' in body
    assert switch.requests == []  # showing the form talks to nothing


# ---- setup --------------------------------------------------------------


def test_setup_connects_and_never_stores_the_admin_password(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    response = _set_up(logged_in)
    assert response.status_code == 200
    assert "NXray created the account nxray on nexus-lab" in response.text
    assert "saved the switch configuration" in response.text
    assert switch.saved

    new_password = switch.users["nxray"][0]
    raw = b"".join(
        path.read_bytes() for path in settings.data_dir.iterdir() if path.name.startswith("nxray")
    )
    assert ADMIN_PASSWORD.encode() not in raw
    assert new_password.encode() not in raw  # stored, but encrypted
    assert ADMIN_PASSWORD not in response.text
    assert new_password not in response.text

    conn = sqlite3.connect(settings.db_path)
    host, user, encrypted = conn.execute(
        "SELECT host, username, password_encrypted FROM switch_connection"
    ).fetchone()
    conn.close()
    assert (host, user) == ("192.0.2.10", "nxray")
    assert encrypted and new_password not in encrypted


def test_after_setup_the_dashboard_shows_the_switch(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    _set_up(logged_in)
    body = logged_in.get("/").text
    assert "Connected to nexus-lab as nxray." in body
    assert "Nexus9000 C92160YC-X chassis" in body
    assert "9.3(16)" in body


def test_setup_without_the_confirm_tick_changes_nothing(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    response = _set_up(logged_in, confirm_save="")
    assert response.status_code == 400
    assert "Tick the box" in response.text
    assert switch.requests == []


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("host", "https://192.0.2.10/", "bare IP address or hostname"),
        ("host", "", "bare IP address or hostname"),
        ("port", "0", "1 to 65535"),
        ("port", "https", "1 to 65535"),
        ("admin_password", "", "admin username and password"),
        ("account_name", "admin", "reserved"),
        ("account_name", "bad name", "1-28 characters"),
    ],
)
def test_bad_input_is_refused_before_contacting_the_switch(
    logged_in: TestClient, switch: FakeSwitch, field: str, value: str, message: str
) -> None:
    response = _set_up(logged_in, **{field: value})
    assert response.status_code == 400
    assert message in response.text
    assert switch.users.keys() == {"admin"}


def test_a_refused_form_keeps_the_typed_values_but_not_the_password(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    response = _set_up(logged_in, admin_password="wrong-pw-123", account_name="nxray-lab")
    assert response.status_code == 400
    assert "refused the admin username or password" in response.text
    assert 'value="nxray-lab"' in response.text
    assert 'value="192.0.2.10"' in response.text
    assert "wrong-pw-123" not in response.text


def test_existing_account_name_is_refused(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.users["nxray"] = ("Other1Install", "network-operator")
    response = _set_up(logged_in)
    assert response.status_code == 400
    assert "already exists" in response.text
    assert switch.users["nxray"] == ("Other1Install", "network-operator")


def test_a_second_setup_is_refused_while_one_is_stored(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    _set_up(logged_in)
    response = logged_in.post(
        "/switch/setup", data=_setup_form(logged_in, account_name="nxray-two")
    )
    assert response.status_code == 400
    assert "already set up" in response.text
    assert "nxray-two" not in switch.users


def test_failed_save_is_shown_with_the_command_to_run(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    switch.save_text = "Copy failed\n"
    body = _set_up(logged_in).text
    assert "saving the switch configuration failed" in body
    assert "copy running-config startup-config" in body
    assert "no: run copy running-config startup-config" in logged_in.get("/switch").text


# ---- after setup: test and forget ---------------------------------------


def test_test_connection_reports_success(logged_in: TestClient, switch: FakeSwitch) -> None:
    _set_up(logged_in)
    response = logged_in.post("/switch/test", data={"csrf": _csrf(logged_in)})
    assert "Connected to nexus-lab as nxray." in response.text
    assert "worked" in response.text


def test_removed_account_shows_login_refused(logged_in: TestClient, switch: FakeSwitch) -> None:
    _set_up(logged_in)
    del switch.users["nxray"]

    tested = logged_in.post("/switch/test", data={"csrf": _csrf(logged_in)}).text
    assert "refused the NXray account (nxray) username or password" in tested
    assert "failed:" in tested
    assert "refused the NXray account" in logged_in.get("/").text


def test_unreachable_switch_shows_on_the_dashboard(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    _set_up(logged_in)
    switch.reachable = False
    body = logged_in.get("/").text
    assert "could not reach the switch at 192.0.2.10, port 443" in body


def test_changed_secret_key_is_explained(
    settings: Settings,
    make_client: Callable[[Settings], TestClient],
) -> None:
    fake = FakeSwitch()
    first = make_client(settings)
    first.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    first.post("/login", data={"username": TEST_USER, "password": TEST_PASSWORD})
    _set_up(first)

    other = make_client(with_settings(settings, secret_key="a-different-key"))
    other.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    other.post("/login", data={"username": TEST_USER, "password": TEST_PASSWORD})
    assert "cannot read the stored switch login" in other.get("/").text
    tested = other.post("/switch/test", data={"csrf": _csrf(other)}).text
    assert "cannot read the stored switch login" in tested


def test_forget_removes_only_the_stored_login(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _set_up(logged_in)
    response = logged_in.post("/switch/forget", data={"csrf": _csrf(logged_in)})
    assert "forgot the switch nexus-lab" in response.text
    assert "still on the switch" in response.text
    assert "nxray" in switch.users  # NXray never removes it on its own
    assert "Set up the switch" in logged_in.get("/switch").text

    conn = sqlite3.connect(settings.db_path)
    assert conn.execute("SELECT COUNT(*) FROM switch_connection").fetchone()[0] == 0
    conn.close()


def test_after_forgetting_a_new_name_can_be_set_up(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    _set_up(logged_in)
    logged_in.post("/switch/forget", data={"csrf": _csrf(logged_in)})
    assert "already exists" in _set_up(logged_in).text
    assert "Connected" not in logged_in.get("/").text
    assert "nexus-lab" in _set_up(logged_in, account_name="nxray-2").text
    assert "Connected to nexus-lab as nxray-2." in logged_in.get("/").text


# ---- forgery protection -------------------------------------------------


@pytest.mark.parametrize("path", ["/switch/setup", "/switch/test", "/switch/forget"])
def test_posts_without_the_token_are_refused(
    logged_in: TestClient, switch: FakeSwitch, path: str
) -> None:
    form = _setup_form(logged_in)
    for token in ("", "0" * 64):
        form["csrf"] = token
        response = logged_in.post(path, data=form)
        assert response.status_code == 403, path
        assert "could not be accepted" in response.text
    assert switch.requests == []


def test_token_from_another_session_is_refused(logged_in: TestClient, switch: FakeSwitch) -> None:
    old_token = _csrf(logged_in)
    logged_in.post("/logout")
    logged_in.cookies.clear()
    logged_in.post("/login", data={"username": TEST_USER, "password": TEST_PASSWORD})
    assert logged_in.cookies.get(SESSION_COOKIE)
    response = logged_in.post("/switch/setup", data=_setup_form(logged_in, csrf=old_token))
    assert response.status_code == 403
    assert switch.users.keys() == {"admin"}


def test_anonymous_posts_go_to_login(client: TestClient) -> None:
    for path in ("/switch/setup", "/switch/test", "/switch/forget"):
        response = client.post(path, data={"csrf": "x"})
        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")
