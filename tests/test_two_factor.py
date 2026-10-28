"""Two-factor sign-in: the codes, setup on the Account page, sign-in, recovery."""

from __future__ import annotations

import base64
import io
import json
import re
import sqlite3
import time
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from app import resetpw
from app.config import Settings
from app.db import _MIGRATIONS, open_db
from app.security import (
    PENDING_2FA_COOKIE,
    SESSION_COOKIE,
    read_pending_2fa,
    sign_pending_2fa,
    unsign_session_id,
)
from app.totp import (
    BACKUP_CODE_COUNT,
    code_at,
    generate_backup_codes,
    hash_backup_code,
    matching_step,
    provisioning_uri,
    qr_svg,
    time_step,
)
from app.users import (
    begin_two_factor,
    check_second_factor,
    create_user,
    get_user,
    set_password,
)
from tests.conftest import TEST_PASSWORD, TEST_USER, with_settings

PASSWORD = "another-long-password"


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def _password_step(client: TestClient, username: str = TEST_USER, password: str = TEST_PASSWORD):
    return client.post("/login", data={"username": username, "password": password, "next": "/"})


def _start_setup(client: TestClient) -> str:
    """Press Set up two-factor sign-in; returns the key the page shows."""
    page = client.post("/account/2fa/setup", data={"csrf": _csrf(client)})
    assert page.status_code == 200, page.text
    match = re.search(r'<code class="totp-secret">([A-Z2-7 ]+)</code>', page.text)
    assert match, "no key on the setup page"
    return match.group(1).replace(" ", "")


def _turn_on(client: TestClient) -> tuple[str, list[str]]:
    """Set up two-factor for the signed-in account; returns (secret, backup codes)."""
    secret = _start_setup(client)
    done = client.post(
        "/account/2fa/confirm",
        data={"csrf": _csrf(client), "code": code_at(secret, time_step())},
    )
    assert done.status_code == 200, done.text
    codes = re.findall(r"<li><code>([A-Z2-9]{5}-[A-Z2-9]{5})</code></li>", done.text)
    assert len(codes) == BACKUP_CODE_COUNT
    return secret, codes


def _fresh(client: TestClient) -> TestClient:
    return TestClient(client.app, follow_redirects=False)


def _next_code(secret: str) -> str:
    # The code of the next 30-second step: the current one was used to turn
    # two-factor on, and a used step is refused. Still inside the accepted
    # window of one step either side.
    return code_at(secret, time_step() + 1)


# ---- the codes themselves --------------------------------------------------------


def test_codes_match_the_rfc_6238_test_values() -> None:
    # RFC 6238 appendix B, SHA-1, key "12345678901234567890": the last six
    # digits of 94287082 and 07081804.
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert code_at(secret, 59 // 30) == "287082"
    assert code_at(secret, 1111111109 // 30) == "081804"


def test_a_code_is_accepted_one_step_either_side_only() -> None:
    secret = base64.b32encode(b"12345678901234567890").decode()
    now = 1_000_000_000.0
    step = time_step(now)
    for drift in (-1, 0, 1):
        assert matching_step(secret, code_at(secret, step + drift), at=now) == step + drift
    for drift in (-2, 2):
        assert matching_step(secret, code_at(secret, step + drift), at=now) is None
    for junk in ("", "12345", "1234567", "abcdef", "12 34 5"):
        assert matching_step(secret, junk, at=now) is None


def test_backup_codes_are_random_readable_and_matched_loosely() -> None:
    codes = generate_backup_codes()
    assert len(set(codes)) == BACKUP_CODE_COUNT
    assert all(re.fullmatch(r"[2-9A-HJ-NP-Z]{5}-[2-9A-HJ-NP-Z]{5}", c) for c in codes)
    code = codes[0]
    assert hash_backup_code(code) == hash_backup_code(code.lower().replace("-", " "))
    assert hash_backup_code(code) != hash_backup_code(codes[1])


def test_the_qr_code_is_plain_svg_the_page_policy_allows() -> None:
    svg = qr_svg(provisioning_uri("JBSWY3DPEHPK3PXP", "admin"))
    assert svg.startswith("<svg") and svg.rstrip().endswith("</svg>")
    # The Content-Security-Policy forbids inline styles and scripts.
    assert "style=" not in svg and "<script" not in svg


def test_the_uri_names_nxray_and_the_account() -> None:
    uri = provisioning_uri("JBSWY3DPEHPK3PXP", "otto@lab")
    assert uri.startswith("otpauth://totp/NXray%3Aotto%40lab?secret=JBSWY3DPEHPK3PXP")
    assert "issuer=NXray" in uri and "digits=6" in uri and "period=30" in uri


# ---- the database --------------------------------------------------------------------


def test_an_existing_account_is_upgraded_with_two_factor_off(
    settings: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    for index, script in enumerate(_MIGRATIONS[:5], start=1):
        conn.executescript(script)
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (index,))
    conn.execute(
        "INSERT INTO users (username, password_hash, role, disabled, created_at) "
        "VALUES (?, ?, 'admin', 0, ?)",
        (TEST_USER, settings.admin_password_hash, time.time()),
    )
    conn.commit()
    conn.close()

    client = make_client(settings)
    with open_db(settings.db_path) as db:
        user = get_user(db, TEST_USER)
    assert user is not None and not user.totp_enabled and user.backup_codes_left == 0
    assert _password_step(client).headers["location"] == "/", "password alone still signs in"


# ---- setting it up ---------------------------------------------------------------------


def test_the_account_page_offers_setup(logged_in: TestClient) -> None:
    text = _text(logged_in.get("/account").text)
    assert "Two-factor sign-in" in text and "Set up two-factor sign-in" in text


def test_setup_shows_a_qr_code_and_changes_nothing_until_confirmed(
    logged_in: TestClient, settings: Settings
) -> None:
    page = logged_in.post("/account/2fa/setup", data={"csrf": _csrf(logged_in)})
    assert page.status_code == 200
    assert "<svg" in page.text and 'class="totp-secret"' in page.text
    assert page.headers["cache-control"] == "no-store"
    # Left half done: the password alone still signs in.
    assert _password_step(_fresh(logged_in)).headers["location"] == "/"
    with open_db(settings.db_path) as conn:
        user = get_user(conn, TEST_USER)
    assert user is not None and not user.totp_enabled
    assert user.totp_secret_encrypted and "totp" not in user.totp_secret_encrypted.lower()


def test_setup_needs_the_csrf_token(logged_in: TestClient) -> None:
    for path in ("/account/2fa/setup", "/account/2fa/confirm", "/account/2fa/off"):
        assert logged_in.post(path, data={"csrf": "nope"}).status_code == 403, path


def test_a_wrong_code_keeps_the_same_key_and_two_factor_off(
    logged_in: TestClient, settings: Settings
) -> None:
    secret = _start_setup(logged_in)
    if code_at(secret, time_step()) == "000000":  # one in a million
        pytest.skip("the real code happened to be 000000")
    wrong = logged_in.post(
        "/account/2fa/confirm", data={"csrf": _csrf(logged_in), "code": "000000"}
    )
    assert wrong.status_code == 400 and "That code is not right" in wrong.text
    shown = re.search(r'class="totp-secret">([A-Z2-7 ]+)<', wrong.text)
    assert shown and shown.group(1).replace(" ", "") == secret, "the same key is shown again"
    with open_db(settings.db_path) as conn:
        user = get_user(conn, TEST_USER)
    assert user is not None and not user.totp_enabled


def test_turning_it_on_shows_ten_codes_once_and_signs_out_other_sessions(
    logged_in: TestClient,
) -> None:
    other = _fresh(logged_in)
    assert _password_step(other).status_code == 303
    assert other.get("/").status_code == 200

    secret = _start_setup(logged_in)
    code = code_at(secret, time_step())
    done = logged_in.post("/account/2fa/confirm", data={"csrf": _csrf(logged_in), "code": code})
    assert done.status_code == 200 and "Save these ten backup codes" in done.text
    assert done.headers["cache-control"] == "no-store"

    assert logged_in.get("/").status_code == 200, "the session that turned it on stays"
    assert other.get("/").status_code == 303, "other sessions are signed out"
    text = _text(logged_in.get("/account").text)
    assert "on Signing in asks for a code" in text and "10 backup codes left" in text
    assert not re.search(r"[A-Z2-9]{5}-[A-Z2-9]{5}", logged_in.get("/account").text), (
        "the codes are never shown again"
    )


def test_setup_cannot_replace_a_working_key(logged_in: TestClient, settings: Settings) -> None:
    secret, _ = _turn_on(logged_in)
    again = logged_in.post("/account/2fa/setup", data={"csrf": _csrf(logged_in)})
    assert again.status_code == 400 and "already on" in again.text
    with open_db(settings.db_path) as conn:
        user = get_user(conn, TEST_USER)
        assert user is not None
        with pytest.raises(Exception, match="already on"):
            begin_two_factor(conn, user.id, settings.secret_key)
    # The app's codes still work.
    client = _fresh(logged_in)
    _password_step(client)
    assert client.post("/login/2fa", data={"code": _next_code(secret)}).status_code == 303


# ---- signing in with it ----------------------------------------------------------------


def test_the_password_alone_no_longer_signs_in(logged_in: TestClient) -> None:
    _turn_on(logged_in)
    client = _fresh(logged_in)
    response = _password_step(client)
    assert response.status_code == 303
    assert response.headers["location"] == "/login/2fa?next=/"
    assert not client.cookies.get(SESSION_COOKIE)
    cookie = response.headers["set-cookie"].lower()
    assert PENDING_2FA_COOKIE in cookie and "path=/login/2fa" in cookie and "httponly" in cookie
    assert client.get("/").status_code == 303, "no page opens before the code"
    assert "Sign-in code" in client.get("/login/2fa").text


def test_the_right_code_signs_in_and_keeps_next(logged_in: TestClient) -> None:
    secret, _ = _turn_on(logged_in)
    client = _fresh(logged_in)
    first = client.post(
        "/login", data={"username": TEST_USER, "password": TEST_PASSWORD, "next": "/ports"}
    )
    assert first.headers["location"] == "/login/2fa?next=/ports"
    done = client.post("/login/2fa", data={"code": _next_code(secret), "next": "/ports"})
    assert done.status_code == 303 and done.headers["location"] == "/ports"
    assert client.cookies.get(SESSION_COOKIE)
    assert client.get("/").status_code == 200


def test_a_code_works_only_once(logged_in: TestClient) -> None:
    secret, _ = _turn_on(logged_in)
    code = _next_code(secret)
    first = _fresh(logged_in)
    _password_step(first)
    assert first.post("/login/2fa", data={"code": code}).status_code == 303

    second = _fresh(logged_in)
    _password_step(second)
    replay = second.post("/login/2fa", data={"code": code})
    assert replay.status_code == 401 and "already used" in replay.text
    assert not second.cookies.get(SESSION_COOKIE)


def test_the_same_code_sent_twice_at_once_passes_once(
    logged_in: TestClient, settings: Settings
) -> None:
    secret, _ = _turn_on(logged_in)
    code = _next_code(secret)
    with open_db(settings.db_path) as conn:
        stale = get_user(conn, TEST_USER)  # both requests read the row first
        assert stale is not None
        assert check_second_factor(conn, stale, code, settings.secret_key) == "app"
        assert check_second_factor(conn, stale, code, settings.secret_key) is None


def test_off_site_next_is_dropped_at_the_code_step(logged_in: TestClient) -> None:
    secret, _ = _turn_on(logged_in)
    client = _fresh(logged_in)
    _password_step(client)
    done = client.post(
        "/login/2fa", data={"code": _next_code(secret), "next": "https://evil.example.com/"}
    )
    assert done.headers["location"] == "/"


def test_wrong_codes_are_throttled_and_a_new_password_step_does_not_reset_the_count(
    settings: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    client = make_client(with_settings(settings, login_max_attempts=3))
    _password_step(client)
    secret, _ = _turn_on(client)
    guesser = _fresh(client)
    for _ in range(2):
        _password_step(guesser)
        assert guesser.post("/login/2fa", data={"code": "not-a-code"}).status_code == 401
    # The right password again must not wipe the two failures...
    _password_step(guesser)
    assert guesser.post("/login/2fa", data={"code": "still-wrong"}).status_code == 401
    # ...so the address is now blocked, even for the right code.
    _password_step(guesser)
    blocked = guesser.post("/login/2fa", data={"code": _next_code(secret)})
    assert blocked.status_code == 429 and "Too many failed attempts" in blocked.text


def test_the_code_page_needs_a_recent_password_step(logged_in: TestClient) -> None:
    _turn_on(logged_in)
    nobody = _fresh(logged_in)
    assert nobody.get("/login/2fa").headers["location"].startswith("/login")
    assert (
        nobody.post("/login/2fa", data={"code": "123456"}).headers["location"].startswith("/login")
    )
    nobody.cookies.set(PENDING_2FA_COOKIE, "forged", path="/login/2fa")
    assert nobody.get("/login/2fa").headers["location"].startswith("/login?")


def test_a_pending_cookie_runs_out_after_five_minutes(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = sign_pending_2fa(TEST_USER, "hash", settings.secret_key)
    assert read_pending_2fa(value, settings.secret_key) is not None
    later = time.time() + 5 * 60 + 5
    monkeypatch.setattr("app.security.time.time", lambda: later)
    assert read_pending_2fa(value, settings.secret_key) is None


def test_a_pending_cookie_is_not_a_session(logged_in: TestClient, settings: Settings) -> None:
    _turn_on(logged_in)
    client = _fresh(logged_in)
    response = _password_step(client)
    pending = re.search(rf"{PENDING_2FA_COOKIE}=([^;]+)", response.headers["set-cookie"])
    assert pending
    assert unsign_session_id(pending.group(1).strip('"'), settings.secret_key) is None
    client.cookies.set(SESSION_COOKIE, pending.group(1).strip('"'))
    assert client.get("/").status_code == 303


@pytest.mark.parametrize("change", ["new password", "two-factor off", "disabled"])
def test_a_pending_sign_in_ends_when_the_account_changes(
    logged_in: TestClient, settings: Settings, change: str
) -> None:
    secret, _ = _turn_on(logged_in)
    client = _fresh(logged_in)
    _password_step(client)
    with open_db(settings.db_path) as conn:
        user = get_user(conn, TEST_USER)
        assert user is not None
        if change == "new password":
            set_password(conn, user.id, TEST_PASSWORD)  # same text, new hash
        elif change == "two-factor off":
            conn.execute("UPDATE users SET totp_enabled = 0 WHERE id = ?", (user.id,))
        else:
            conn.execute("UPDATE users SET disabled = 1 WHERE id = ?", (user.id,))
        conn.commit()
    response = client.post("/login/2fa", data={"code": _next_code(secret)})
    assert response.status_code == 303 and response.headers["location"].startswith("/login?")
    assert not client.cookies.get(SESSION_COOKIE)


# ---- backup codes --------------------------------------------------------------------------


def test_a_backup_code_signs_in_once(logged_in: TestClient) -> None:
    _, codes = _turn_on(logged_in)
    client = _fresh(logged_in)
    _password_step(client)
    done = client.post("/login/2fa", data={"code": codes[3].lower()})
    assert done.status_code == 303 and done.headers["location"] == "/account?backup_used=1"
    text = _text(client.get("/account?backup_used=1").text)
    assert "signed in with a backup code; 9 backup codes left" in text
    assert "9 backup codes left" in _text(client.get("/account").text)

    again = _fresh(logged_in)
    _password_step(again)
    assert again.post("/login/2fa", data={"code": codes[3]}).status_code == 401


def test_new_backup_codes_replace_the_old_ones(logged_in: TestClient) -> None:
    _, old = _turn_on(logged_in)
    refused = logged_in.post(
        "/account/2fa/codes", data={"csrf": _csrf(logged_in), "current_password": "wrong"}
    )
    assert refused.status_code == 400
    page = logged_in.post(
        "/account/2fa/codes", data={"csrf": _csrf(logged_in), "current_password": TEST_PASSWORD}
    )
    assert page.status_code == 200 and "New backup codes" in page.text
    new = re.findall(r"<li><code>([A-Z2-9]{5}-[A-Z2-9]{5})</code></li>", page.text)
    assert len(new) == BACKUP_CODE_COUNT and not set(new) & set(old)

    client = _fresh(logged_in)
    _password_step(client)
    assert client.post("/login/2fa", data={"code": old[0]}).status_code == 401
    assert client.post("/login/2fa", data={"code": new[0]}).status_code == 303


def test_backup_codes_still_work_after_the_secret_key_changed(
    settings: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    first = make_client(settings)
    _password_step(first)
    secret, codes = _turn_on(first)

    moved = make_client(with_settings(settings, secret_key="a-different-secret-key"))
    _password_step(moved)
    assert moved.post("/login/2fa", data={"code": _next_code(secret)}).status_code == 401
    _password_step(moved)
    assert moved.post("/login/2fa", data={"code": codes[0]}).status_code == 303


def test_backup_codes_are_stored_as_hashes(logged_in: TestClient, settings: Settings) -> None:
    _, codes = _turn_on(logged_in)
    with open_db(settings.db_path) as conn:
        stored = conn.execute(
            "SELECT totp_backup_codes FROM users WHERE username = ?", (TEST_USER,)
        ).fetchone()[0]
    assert len(json.loads(stored)) == BACKUP_CODE_COUNT
    assert not any(code in stored or code.replace("-", "") in stored for code in codes)


# ---- turning it off ------------------------------------------------------------------------


def test_turning_it_off_needs_your_password(logged_in: TestClient) -> None:
    _turn_on(logged_in)
    wrong = logged_in.post(
        "/account/2fa/off", data={"csrf": _csrf(logged_in), "current_password": "wrong"}
    )
    assert wrong.status_code == 400 and "current password is not right" in wrong.text
    done = logged_in.post(
        "/account/2fa/off", data={"csrf": _csrf(logged_in), "current_password": TEST_PASSWORD}
    )
    assert done.status_code == 200 and "Two-factor sign-in is off" in done.text
    assert _password_step(_fresh(logged_in)).headers["location"] == "/"


def test_an_admin_turns_it_off_for_someone_else(logged_in: TestClient, settings: Settings) -> None:
    with open_db(settings.db_path) as conn:
        create_user(conn, "otto", PASSWORD, PASSWORD, "operator")
    otto = _fresh(logged_in)
    _password_step(otto, "otto", PASSWORD)
    _turn_on(otto)
    with open_db(settings.db_path) as conn:
        otto_id = get_user(conn, "otto").id  # type: ignore[union-attr]

    done = logged_in.post(
        "/users/2fa-off", data={"csrf": _csrf(logged_in, "/users"), "user_id": str(otto_id)}
    )
    assert done.status_code == 200 and "Two-factor sign-in is off for otto" in done.text
    assert _password_step(_fresh(logged_in), "otto", PASSWORD).headers["location"] == "/"


def test_an_admin_turns_off_their_own_only_on_the_account_page(
    logged_in: TestClient, settings: Settings
) -> None:
    _turn_on(logged_in)
    with open_db(settings.db_path) as conn:
        own_id = get_user(conn, TEST_USER).id  # type: ignore[union-attr]
    refused = logged_in.post(
        "/users/2fa-off", data={"csrf": _csrf(logged_in, "/users"), "user_id": str(own_id)}
    )
    assert refused.status_code == 400 and "on your Account page" in refused.text
    with open_db(settings.db_path) as conn:
        assert get_user(conn, TEST_USER).totp_enabled  # type: ignore[union-attr]


def test_the_users_page_shows_who_has_it_on(logged_in: TestClient, settings: Settings) -> None:
    with open_db(settings.db_path) as conn:
        create_user(conn, "otto", PASSWORD, PASSWORD, "operator")
    otto = _fresh(logged_in)
    _password_step(otto, "otto", PASSWORD)
    _turn_on(otto)
    page = logged_in.get("/users").text
    assert 'action="/users/2fa-off"' in page
    row = re.search(r"<tr>\s*<td>otto.*?</tr>", page, re.S)
    assert row and 'badge-ok">on<' in row.group(0)


def test_resetpw_turns_off_two_factor(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    settings: Settings,
    logged_in: TestClient,
) -> None:
    _turn_on(logged_in)
    monkeypatch.setattr(resetpw, "load_settings", lambda: settings)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert resetpw.main(["--2fa-off", TEST_USER]) == 0
    assert "Two-factor sign-in is off" in capsys.readouterr().out
    assert _password_step(_fresh(logged_in)).headers["location"] == "/"
    assert resetpw.main(["--2fa-off", TEST_USER]) == 0
    assert "already off" in capsys.readouterr().out
    assert resetpw.main(["--2fa-off"]) == 2


def test_resetpw_says_two_factor_stays_on(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    settings: Settings,
    logged_in: TestClient,
) -> None:
    _turn_on(logged_in)
    monkeypatch.setattr(resetpw, "load_settings", lambda: settings)
    monkeypatch.setattr("sys.stdin", io.StringIO("recovered-password\n"))
    assert resetpw.main([TEST_USER]) == 0
    assert "Two-factor sign-in stays on" in capsys.readouterr().out
