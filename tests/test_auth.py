"""Login, logout, sessions and throttling."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.db import open_db
from app.security import SESSION_COOKIE
from app.users import create_user, get_user, set_disabled, set_password
from tests.conftest import TEST_PASSWORD, TEST_USER, with_settings


def _login(client: TestClient, username: str, password: str, next_url: str = "/"):
    return client.post(
        "/login", data={"username": username, "password": password, "next": next_url}
    )


def test_login_page_renders(client: TestClient) -> None:
    response = client.get("/login")
    assert response.status_code == 200
    assert "NXray" in response.text
    assert 'name="password"' in response.text


def test_correct_credentials_are_accepted(client: TestClient) -> None:
    response = _login(client, TEST_USER, TEST_PASSWORD)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert client.cookies.get(SESSION_COOKIE)


def test_session_cookie_is_http_only_and_same_site(client: TestClient) -> None:
    cookie = _login(client, TEST_USER, TEST_PASSWORD).headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=lax" in cookie
    # NXRAY_HTTPS is off in these settings, so no Secure flag: a browser on
    # plain http would otherwise drop the cookie and login would look broken.
    assert "secure" not in cookie


def test_secure_flag_follows_the_https_setting(
    settings: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    client = make_client(with_settings(settings, https_only=True))
    cookie = _login(client, TEST_USER, TEST_PASSWORD).headers["set-cookie"].lower()
    assert "secure" in cookie


def test_wrong_password_is_rejected(client: TestClient) -> None:
    response = _login(client, TEST_USER, "wrong")
    assert response.status_code == 401
    assert "Incorrect username or password" in response.text
    assert not client.cookies.get(SESSION_COOKIE)


def test_wrong_username_is_rejected(client: TestClient) -> None:
    response = _login(client, "someone", TEST_PASSWORD)
    assert response.status_code == 401
    assert "Incorrect username or password" in response.text
    assert not client.cookies.get(SESSION_COOKIE)


def test_session_persists_across_requests(logged_in: TestClient) -> None:
    for _ in range(3):
        assert logged_in.get("/").status_code == 200


def test_logout_invalidates_the_session(logged_in: TestClient) -> None:
    stolen = logged_in.cookies.get(SESSION_COOKIE)
    assert stolen

    assert logged_in.post("/logout").status_code == 303
    assert logged_in.get("/").status_code == 303

    # The session is gone server-side, so replaying the old cookie fails too.
    logged_in.cookies.set(SESSION_COOKIE, stolen)
    assert logged_in.get("/").status_code == 303


def test_forged_cookie_is_rejected(client: TestClient) -> None:
    client.cookies.set(SESSION_COOKIE, "not-a-signed-value")
    assert client.get("/").status_code == 303


def test_cookie_signed_with_another_key_is_rejected(
    settings: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    first = make_client(settings)
    assert _login(first, TEST_USER, TEST_PASSWORD).status_code == 303
    cookie = first.cookies.get(SESSION_COOKIE)
    assert cookie

    other = make_client(with_settings(settings, secret_key="a-different-key"))
    other.cookies.set(SESSION_COOKIE, cookie)
    assert other.get("/").status_code == 303


@pytest.mark.parametrize("cut_off", ["disabled", "password reset", "account gone"])
def test_session_ends_when_its_account_is_cut_off(
    settings: Settings, make_client: Callable[[Settings], TestClient], cut_off: str
) -> None:
    client = make_client(settings)
    with open_db(settings.db_path) as conn:
        create_user(conn, "otto", "otto-password", "otto-password", "operator")
    assert _login(client, "otto", "otto-password").status_code == 303
    assert client.get("/").status_code == 200

    with open_db(settings.db_path) as conn:
        otto = get_user(conn, "otto")
        assert otto is not None
        if cut_off == "disabled":
            set_disabled(conn, otto.id, True)
        elif cut_off == "password reset":
            set_password(conn, otto.id, "a-new-password")
        else:
            conn.execute("DELETE FROM users WHERE id = ?", (otto.id,))
            conn.commit()
    assert client.get("/").status_code == 303


def test_expired_session_is_refused(
    settings: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    client = make_client(settings)
    assert _login(client, TEST_USER, TEST_PASSWORD).status_code == 303

    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE sessions SET expires_at = 0")
    conn.commit()
    conn.close()

    assert client.get("/").status_code == 303


def test_login_page_redirects_when_already_signed_in(logged_in: TestClient) -> None:
    response = logged_in.get("/login")
    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_rate_limit_blocks_after_repeated_failures(
    settings: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    client = make_client(with_settings(settings, login_max_attempts=3))
    for _ in range(3):
        assert _login(client, TEST_USER, "wrong").status_code == 401

    # Correct credentials now too: a lockout must not be bypassable by simply
    # guessing right on the next attempt.
    blocked = _login(client, TEST_USER, TEST_PASSWORD)
    assert blocked.status_code == 429
    assert "Too many failed attempts" in blocked.text
    assert not client.cookies.get(SESSION_COOKIE)


def test_success_clears_earlier_failures(
    settings: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    client = make_client(with_settings(settings, login_max_attempts=3))
    for _ in range(2):
        assert _login(client, TEST_USER, "wrong").status_code == 401
    assert _login(client, TEST_USER, TEST_PASSWORD).status_code == 303
    client.post("/logout")

    # Two more failures would make four in total; the count restarted at the
    # successful login, so the next correct attempt is still allowed.
    for _ in range(2):
        assert _login(client, TEST_USER, "wrong").status_code == 401
    assert _login(client, TEST_USER, TEST_PASSWORD).status_code == 303


def test_open_redirect_is_refused(client: TestClient) -> None:
    # A ?next= pointing off-site would turn the login page into an open redirect.
    for hostile in ("https://evil.example.com/", "//evil.example.com/", "/\\evil.example.com"):
        client.cookies.clear()
        response = _login(client, TEST_USER, TEST_PASSWORD, hostile)
        assert response.status_code == 303
        assert response.headers["location"] == "/", hostile


def test_local_next_is_followed(client: TestClient) -> None:
    response = _login(client, TEST_USER, TEST_PASSWORD, "/somewhere")
    assert response.headers["location"] == "/somewhere"


def test_login_form_does_not_echo_an_off_site_next(client: TestClient) -> None:
    body = client.get("/login", params={"next": "https://evil.example.com/"}).text
    assert "evil.example.com" not in body
