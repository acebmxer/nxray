"""Stage 7 on the Switch page: change the switch address, and run setup again."""

from __future__ import annotations

import re
import sqlite3
import time
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.port_changes import ROLE_NAME, ROLE_VERSION
from app.routes import switch_page
from tests.conftest import TEST_PASSWORD, TEST_USER, load_fixture, with_settings
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


def _csrf(client: TestClient, path: str = "/switch") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def _set_up(client: TestClient) -> None:
    response = client.post(
        "/switch/setup",
        data={
            "csrf": _csrf(client),
            "host": "192.0.2.10",
            "port": "443",
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "account_name": "nxray",
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200


def _row(settings: Settings) -> sqlite3.Row:
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM switch_connection").fetchone()
    conn.close()
    return row


def _set_pause(settings: Settings, until: float) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE switch_connection SET paused_until = ?", (until,))
    conn.commit()
    conn.close()


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    """A switch set up with the read-only account nxray."""
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    _set_up(logged_in)
    fake.requests.clear()
    fake.saved = False
    return fake


@pytest.fixture
def with_port_changes(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    """Port changes (with VLANs) on, and the wait already over."""
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
    _set_pause(settings, time.time() - 1)
    switch.requests.clear()
    switch.saved = False
    return switch


def _address(client: TestClient, host: str, port: str = "443"):
    form = {"csrf": _csrf(client), "host": host, "port": port}
    return client.post("/switch/address", data=form)


def _repair(client: TestClient, **overrides: str):
    form = {
        "csrf": _csrf(client),
        "host": "192.0.2.10",
        "port": "443",
        "admin_user": "admin",
        "admin_password": ADMIN_PASSWORD,
        "confirm_save": "yes",
    }
    form.update(overrides)
    return client.post("/switch/repair", data=form)


def _test_connection(client: TestClient) -> str:
    return client.post("/switch/test", data={"csrf": _csrf(client)}).text


# ---- the page -----------------------------------------------------------


def test_switch_page_offers_both_with_the_current_address(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    body = logged_in.get("/switch").text
    assert "Change the switch address" in body
    assert 'id="addr_host" name="host" type="text" value="192.0.2.10"' in body
    assert "Run setup again" in body
    assert 'id="rp_host" name="host" type="text" value="192.0.2.10"' in body
    assert "gives its account nxray a new random password" in _text(body)
    assert 'action="/switch/repair"' in body and 'action="/switch/address"' in body
    assert switch.requests == []  # showing the page talks to nothing


def test_page_before_setup_has_neither(logged_in: TestClient) -> None:
    body = logged_in.get("/switch").text
    assert "Set up the switch" in body
    assert "/switch/repair" not in body and "/switch/address" not in body


# ---- change the address -------------------------------------------------


def test_new_address_is_checked_with_nxrays_account_then_kept(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    response = _address(logged_in, "nexus.example.net", "8443")
    assert response.status_code == 200
    text = _text(response.text)
    assert "NXray now uses nexus.example.net, port 8443." in text
    assert "Connected to nexus-lab as nxray." in text
    assert switch.requests == [["show version"]]  # one read with NXray's own account
    row = _row(settings)
    assert (row["host"], row["port"]) == ("nexus.example.net", 8443)
    assert "Connected to nexus-lab as nxray." in logged_in.get("/").text


def test_new_address_that_does_not_answer_keeps_the_old_one(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    switch.reachable = False
    response = _address(logged_in, "192.0.2.99")
    assert response.status_code == 400
    text = _text(response.text)
    assert "NXray kept the address 192.0.2.10, port 443" in text
    assert "could not reach the switch at 192.0.2.99" in text
    assert 'value="192.0.2.99"' in response.text  # what was typed stays in the form
    assert (_row(settings)["host"], _row(settings)["port"]) == ("192.0.2.10", 443)


def test_new_address_where_the_login_is_refused_keeps_the_old_one(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    del switch.users["nxray"]
    response = _address(logged_in, "192.0.2.99")
    assert response.status_code == 400
    assert "NXray kept the address 192.0.2.10" in _text(response.text)
    assert _row(settings)["host"] == "192.0.2.10"


def test_a_different_switch_name_at_the_new_address_is_pointed_out(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    version = load_fixture("show_version")
    version["host_name"] = "nexus-new"
    switch.bodies["show version"] = version
    text = _text(_address(logged_in, "192.0.2.20").text)
    assert "The switch there is called nexus-new; it was called nexus-lab before." in text
    assert _row(settings)["switch_hostname"] == "nexus-new"


@pytest.mark.parametrize(
    ("host", "port", "message"),
    [
        ("https://192.0.2.20/", "443", "bare IP address or hostname"),
        ("", "443", "bare IP address or hostname"),
        ("192.0.2.20", "70000", "1 to 65535"),
        ("192.0.2.10", "443", "already uses"),
    ],
)
def test_bad_or_unchanged_address_is_refused_without_contacting_the_switch(
    logged_in: TestClient, switch: FakeSwitch, host: str, port: str, message: str
) -> None:
    response = _address(logged_in, host, port)
    assert response.status_code == 400
    assert message in response.text
    assert switch.requests == []


def test_address_change_waits_out_a_pause(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _set_pause(settings, time.time() + 300)
    response = _address(logged_in, "192.0.2.20")
    assert response.status_code == 400
    assert "leaving the switch alone" in response.text
    assert switch.requests == []
    assert _row(settings)["host"] == "192.0.2.10"


def test_address_change_with_an_unreadable_login_points_to_run_setup_again(
    settings: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    fake = FakeSwitch()
    first = make_client(settings)
    first.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    first.post("/login", data={"username": TEST_USER, "password": TEST_PASSWORD})
    _set_up(first)

    other = make_client(with_settings(settings, secret_key="a-different-key"))
    other.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    other.post("/login", data={"username": TEST_USER, "password": TEST_PASSWORD})
    fake.requests.clear()
    response = _address(other, "192.0.2.20")
    assert response.status_code == 400
    assert "Use Run setup again below with the new address" in _text(response.text)
    assert fake.requests == []


# ---- run setup again ----------------------------------------------------


def test_password_changed_on_the_switch_is_repaired(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    switch.users["nxray"] = ("Changed1Elsewhere", "network-operator")
    assert "refused the NXray account" in _test_connection(logged_in)
    old_encrypted = _row(settings)["password_encrypted"]

    response = _repair(logged_in)
    assert response.status_code == 200
    text = _text(response.text)
    assert "NXray gave its account nxray on nexus-lab a new password." in text
    assert "The switch configuration was saved." in text
    assert switch.saved

    new_password = switch.users["nxray"][0]
    assert new_password != "Changed1Elsewhere"
    assert new_password not in response.text
    assert ADMIN_PASSWORD not in response.text
    row = _row(settings)
    assert row["username"] == "nxray"
    assert row["password_encrypted"] != old_encrypted
    assert new_password not in row["password_encrypted"]
    assert "Connected to nexus-lab as nxray." in _test_connection(logged_in)


def test_removed_account_is_made_again_and_keeps_port_changes(
    logged_in: TestClient, with_port_changes: FakeSwitch, settings: Settings
) -> None:
    switch = with_port_changes
    del switch.users["nxray"]
    switch.extra_roles.pop("nxray", None)

    text = _text(_repair(logged_in).text)
    assert "The account nxray was no longer on nexus-lab, so NXray made it again" in text
    assert f"gave the account the {ROLE_NAME} role again, so port changes stay on" in text
    assert switch.roles_of("nxray") == {"network-operator", ROLE_NAME}
    row = _row(settings)
    assert row["changes_enabled_at"] is not None and row["role_version"] == ROLE_VERSION
    assert row["paused_until"] <= time.time()  # no new wait for a fresh account
    page = _text(logged_in.get("/switch").text)
    assert "read, plus port changes, VLANs and port settings" in page
    assert "leaving the switch alone" not in page


def test_existing_account_keeps_its_port_changes(
    logged_in: TestClient, with_port_changes: FakeSwitch, settings: Settings
) -> None:
    text = _text(_repair(logged_in).text)
    assert "a new password. Its port changes stay on." in text
    assert ROLE_NAME in with_port_changes.roles_of("nxray")
    assert _row(settings)["role_version"] == ROLE_VERSION


def test_account_that_lost_the_role_gets_it_back_with_the_wait(
    logged_in: TestClient, with_port_changes: FakeSwitch, settings: Settings
) -> None:
    with_port_changes.extra_roles.pop("nxray")
    text = _text(_repair(logged_in).text)
    assert f"gave the account the {ROLE_NAME} role again" in text
    assert "waits about 11 minutes" in text
    assert _row(settings)["paused_until"] > time.time() + 600
    with_port_changes.requests.clear()
    assert "leaving the switch alone" in logged_in.get("/").text
    assert with_port_changes.requests == []


def test_role_removed_from_the_switch_turns_port_changes_off(
    logged_in: TestClient, with_port_changes: FakeSwitch, settings: Settings
) -> None:
    del with_port_changes.roles[ROLE_NAME]
    with_port_changes.extra_roles.pop("nxray")
    text = _text(_repair(logged_in).text)
    assert f"Port changes are now off: the {ROLE_NAME} role is no longer on the switch" in text
    row = _row(settings)
    assert row["changes_enabled_at"] is None and row["role_version"] == 0
    assert "Turn on port, VLAN and port settings changes" in logged_in.get("/switch").text


def test_unreadable_login_after_a_key_change_is_repaired(
    settings: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    fake = FakeSwitch()
    first = make_client(settings)
    first.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    first.post("/login", data={"username": TEST_USER, "password": TEST_PASSWORD})
    _set_up(first)

    other = make_client(with_settings(settings, secret_key="a-different-key"))
    other.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    other.post("/login", data={"username": TEST_USER, "password": TEST_PASSWORD})
    assert "Press Run setup again" in _text(other.get("/").text)
    assert "a new password" in _text(_repair(other).text)
    assert "Connected to nexus-lab as nxray." in other.get("/").text


def test_repair_at_a_new_address_stores_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    text = _text(_repair(logged_in, host="192.0.2.20", port="8443").text)
    assert "NXray now uses 192.0.2.20, port 8443." in text
    row = _row(settings)
    assert (row["host"], row["port"]) == ("192.0.2.20", 8443)


def test_wrong_admin_password_keeps_the_stored_login(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    old = _row(settings)["password_encrypted"]
    response = _repair(logged_in, admin_password="Wrong1Admin")
    assert response.status_code == 400
    assert "refused the admin username or password" in response.text
    assert "Wrong1Admin" not in response.text
    assert _row(settings)["password_encrypted"] == old
    assert "Connected to nexus-lab as nxray." in _test_connection(logged_in)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("confirm_save", "", "Tick the box"),
        ("admin_password", "", "admin username and password"),
        ("host", "192.0.2.10/ins", "bare IP address or hostname"),
        ("port", "0", "1 to 65535"),
    ],
)
def test_repair_input_is_checked_before_contacting_the_switch(
    logged_in: TestClient, switch: FakeSwitch, field: str, value: str, message: str
) -> None:
    response = _repair(logged_in, **{field: value})
    assert response.status_code == 400
    assert message in response.text
    assert switch.requests == []


def test_repair_waits_out_a_pause(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _set_pause(settings, time.time() + 300)
    response = _repair(logged_in)
    assert response.status_code == 400
    assert "leaving the switch alone" in response.text
    assert switch.requests == []


def test_repair_refused_while_another_switch_change_runs(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    csrf = _csrf(logged_in)
    assert switch_page._setup_lock.acquire(blocking=False)
    try:
        repaired = _repair(logged_in, csrf=csrf)
        moved = logged_in.post(
            "/switch/address", data={"csrf": csrf, "host": "192.0.2.20", "port": "443"}
        )
    finally:
        switch_page._setup_lock.release()
    assert "already running" in repaired.text
    assert "already running" in moved.text
    assert switch.requests == []


# ---- forgery and sign-in --------------------------------------------------


@pytest.mark.parametrize("path", ["/switch/address", "/switch/repair"])
def test_posts_without_the_token_are_refused(
    logged_in: TestClient, switch: FakeSwitch, path: str
) -> None:
    for token in ("", "0" * 64):
        response = logged_in.post(
            path,
            data={
                "csrf": token,
                "host": "192.0.2.20",
                "port": "443",
                "admin_user": "admin",
                "admin_password": ADMIN_PASSWORD,
                "confirm_save": "yes",
            },
        )
        assert response.status_code == 403
    assert switch.requests == []


def test_anonymous_posts_go_to_login(client: TestClient) -> None:
    for path in ("/switch/address", "/switch/repair"):
        response = client.post(path, data={"csrf": "x"})
        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")


def test_without_a_switch_both_go_back_to_the_switch_page(logged_in: TestClient) -> None:
    csrf = _csrf(logged_in)
    assert logged_in.post("/switch/address", data={"csrf": csrf}).headers["location"] == "/switch"
    assert logged_in.post("/switch/repair", data={"csrf": csrf}).headers["location"] == "/switch"
