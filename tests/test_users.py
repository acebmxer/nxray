"""NXray's own accounts: roles, the Users page, the Account page, and what each role sees."""

from __future__ import annotations

import io
import re
import sqlite3
import time
from collections.abc import Callable, Iterable

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app import resetpw
from app.config import Settings
from app.db import _MIGRATIONS, migrate, open_db
from app.security import create_session, hash_password, sign_session_id
from app.users import (
    User,
    UserError,
    authenticate,
    bootstrap_admin,
    create_user,
    get_user,
    list_users,
    set_disabled,
    set_role,
)
from tests.conftest import TEST_PASSWORD, TEST_USER, with_settings
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

PASSWORD = "another-long-password"


def _csrf(client: TestClient, path: str) -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def _add(admin: TestClient, name: str, role: str, password: str = PASSWORD):
    return admin.post(
        "/users/create",
        data={
            "csrf": _csrf(admin, "/users"),
            "new_username": name,
            "password": password,
            "confirm_password": password,
            "role": role,
        },
    )


def _sign_in(admin: TestClient, name: str, password: str = PASSWORD) -> TestClient:
    """A second browser on the same running app, signed in as ``name``."""
    other = TestClient(admin.app, follow_redirects=False)
    response = other.post("/login", data={"username": name, "password": password, "next": "/"})
    assert response.status_code == 303, f"{name} could not sign in"
    return other


def _user_id(settings: Settings, name: str) -> int:
    with open_db(settings.db_path) as conn:
        user = get_user(conn, name)
    assert user is not None
    return user.id


@pytest.fixture
def switch(logged_in: TestClient, settings: Settings) -> FakeSwitch:
    """A switch set up with port and VLAN changes on, the wait over."""
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    admin = {"admin_user": "admin", "admin_password": ADMIN_PASSWORD, "confirm_save": "yes"}
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "host": "192.0.2.10",
            "port": "443",
            "account_name": "nxray",
            **admin,
        },
    )
    logged_in.post(
        "/switch/enable-changes",
        data={"csrf": _csrf(logged_in, "/switch"), "ssh_port": "22", **admin},
    )
    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE switch_connection SET paused_until = ?", (time.time() - 1,))
    conn.commit()
    conn.close()
    fake.requests.clear()
    return fake


# ---- the first account -------------------------------------------------------


def test_the_env_account_becomes_the_first_admin(client: TestClient, settings: Settings) -> None:
    with open_db(settings.db_path) as conn:
        user = get_user(conn, TEST_USER)
    assert user is not None and user.role == "admin" and not user.disabled


def test_the_env_hash_is_ignored_once_an_account_exists(
    settings: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    make_client(settings)
    # A different hash (and name) in nxray.env at the next start changes nothing.
    changed = with_settings(
        settings, admin_user="someone-else", admin_password_hash=hash_password("not-the-one")
    )
    client = make_client(changed)
    with open_db(settings.db_path) as conn:
        assert [u.username for u in _all(conn)] == [TEST_USER]
    response = client.post(
        "/login", data={"username": TEST_USER, "password": TEST_PASSWORD, "next": "/"}
    )
    assert response.status_code == 303
    response = client.post(
        "/login", data={"username": "someone-else", "password": "not-the-one", "next": "/"}
    )
    assert response.status_code == 401


def _all(conn: sqlite3.Connection) -> list[User]:
    return list_users(conn)


def test_bootstrap_acts_only_on_an_empty_table(settings: Settings) -> None:
    with open_db(settings.db_path) as conn:
        migrate(conn)
        assert bootstrap_admin(conn, "first", hash_password(PASSWORD)) is True
        assert bootstrap_admin(conn, "second", hash_password(PASSWORD)) is False
        assert [u.username for u in _all(conn)] == ["first"]


def test_a_session_from_before_the_upgrade_keeps_working(
    settings: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    # A database at schema v4 (no users table) with a signed-in admin, as an
    # install has it right before this upgrade.
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    for index, script in enumerate(_MIGRATIONS[:4], start=1):
        conn.executescript(script)
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (index,))
    conn.commit()
    session_id = create_session(conn, TEST_USER, 12)
    conn.close()

    client = make_client(settings)
    client.cookies.set("nxray_session", sign_session_id(session_id, settings.secret_key))
    response = client.get("/")
    assert response.status_code == 200
    assert "Log out" in response.text


# ---- signing in ----------------------------------------------------------------


def test_a_new_account_can_sign_in(logged_in: TestClient) -> None:
    assert _add(logged_in, "alice", "viewer").status_code == 200
    alice = _sign_in(logged_in, "alice")
    assert "alice (viewer)" in _text(alice.get("/").text)


def test_names_are_matched_whatever_their_case(logged_in: TestClient) -> None:
    _add(logged_in, "Alice", "viewer")
    alice = _sign_in(logged_in, "aLiCe")
    # The session carries the name as it was created.
    assert "Alice (viewer)" in _text(alice.get("/").text)


def test_a_disabled_account_is_told_so_only_with_the_right_password(
    logged_in: TestClient, settings: Settings
) -> None:
    _add(logged_in, "alice", "viewer")
    with open_db(settings.db_path) as conn:
        set_disabled(conn, _user_id(settings, "alice"), True)
    other = TestClient(logged_in.app, follow_redirects=False)
    right = other.post("/login", data={"username": "alice", "password": PASSWORD, "next": "/"})
    assert right.status_code == 401 and "This account is disabled" in right.text
    wrong = other.post("/login", data={"username": "alice", "password": "nope-nope", "next": "/"})
    assert wrong.status_code == 401 and "Incorrect username or password" in wrong.text
    assert "disabled" not in wrong.text


def test_authenticate_checks_a_password_even_for_no_such_account(settings: Settings) -> None:
    with open_db(settings.db_path) as conn:
        migrate(conn)
        assert authenticate(conn, "nobody", PASSWORD) is None


# ---- what each role may do -------------------------------------------------------

# Routes every signed-in account may use, whatever its role.
ANY_ROLE_POSTS = {"/login", "/logout", "/account/password"}
ADMIN_ONLY_POSTS_EXCEPT = {"/switch/save"}


def _post_routes(routes: Iterable[object], found: set[str]) -> None:
    for route in routes:
        if isinstance(route, APIRoute):
            if "POST" in route.methods:
                found.add(route.path)
            continue
        nested = getattr(route, "original_router", None) or getattr(route, "routes", None)
        if nested is not None:
            _post_routes(getattr(nested, "routes", nested), found)


def _all_posts(client: TestClient) -> list[str]:
    found: set[str] = set()
    _post_routes(getattr(client.app, "routes"), found)  # noqa: B009 - typed as plain ASGI
    return sorted(found)


def test_a_viewer_is_refused_every_form_that_changes_something(logged_in: TestClient) -> None:
    _add(logged_in, "vera", "viewer")
    vera = _sign_in(logged_in, "vera")
    token = _csrf(vera, "/account")
    checked = 0
    for path in _all_posts(vera):
        if path in ANY_ROLE_POSTS:
            continue
        response = vera.post(path, data={"csrf": token})
        assert response.status_code == 403, f"{path} let a viewer through"
        assert "Your role can't do that" in response.text, path
        checked += 1
    assert checked >= 10, "the route walk found too few forms; the check is not working"


def test_an_operator_is_refused_the_switch_and_users_forms(logged_in: TestClient) -> None:
    _add(logged_in, "otto", "operator")
    otto = _sign_in(logged_in, "otto")
    token = _csrf(otto, "/account")
    checked = 0
    for path in _all_posts(otto):
        if not path.startswith(("/switch", "/users")) or path in ADMIN_ONLY_POSTS_EXCEPT:
            continue
        response = otto.post(path, data={"csrf": token})
        assert response.status_code == 403, f"{path} let an operator through"
        checked += 1
    assert checked >= 8


@pytest.mark.parametrize("path", ["/switch", "/users"])
@pytest.mark.parametrize("role", ["viewer", "operator"])
def test_admin_pages_are_refused_to_other_roles(
    logged_in: TestClient, path: str, role: str
) -> None:
    _add(logged_in, "someone", role)
    other = _sign_in(logged_in, "someone")
    response = other.get(path)
    assert response.status_code == 403
    assert f"Your account is {role}" in _text(response.text)


def test_the_menu_shows_switch_and_users_to_admins_only(logged_in: TestClient) -> None:
    assert 'href="/switch"' in logged_in.get("/").text
    assert 'href="/users"' in logged_in.get("/").text
    _add(logged_in, "otto", "operator")
    page = _sign_in(logged_in, "otto").get("/").text
    assert 'href="/switch"' not in page and 'href="/users"' not in page
    assert 'href="/account"' in page


def test_a_viewer_sees_no_change_buttons(logged_in: TestClient, switch: FakeSwitch) -> None:
    _add(logged_in, "vera", "viewer")
    vera = _sign_in(logged_in, "vera")
    port = vera.get("/ports/detail", params={"name": "Ethernet1/3"}).text
    assert "Change description" not in port
    assert "Turn off this port" not in port and "Turn on this port" not in port
    assert "Change VLANs" not in port
    assert "Your role (viewer) can look at ports but not change them" in _text(port)
    vlans = vera.get("/vlans").text
    assert "Create VLAN" not in vlans and 'action="/vlans/rename"' not in vlans
    assert "Your role (viewer) can look at VLANs but not change them" in _text(vlans)


def test_an_operator_sees_and_uses_the_change_buttons(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    _add(logged_in, "otto", "operator")
    otto = _sign_in(logged_in, "otto")
    port = otto.get("/ports/detail", params={"name": "Ethernet1/3"}).text
    assert "Change description" in port and "Change VLANs" in port
    response = otto.post(
        "/ports/change",
        data={
            "csrf": _csrf(otto, "/account"),
            "name": "Ethernet1/3",
            "action": "description",
            "description": "uplink",
            "confirm": "yes",
        },
    )
    assert response.status_code == 200
    assert any("description uplink" in cmd for r in switch.requests for cmd in r)
    # ...and Save config, which lives under /switch but is an operator's button.
    saved = otto.post(
        "/switch/save",
        data={"csrf": _csrf(otto, "/account"), "back": "port", "port": "Ethernet1/3"},
    )
    assert saved.status_code == 200 and "Saved:" in saved.text


def test_operators_are_not_sent_to_the_switch_page(logged_in: TestClient) -> None:
    _add(logged_in, "otto", "operator")
    page = _text(_sign_in(logged_in, "otto").get("/").text)
    assert "Set up the switch" not in page
    assert "An NXray admin sets it up on the Switch page" in page


def test_a_new_role_applies_on_the_next_click(logged_in: TestClient, settings: Settings) -> None:
    _add(logged_in, "vera", "viewer")
    vera = _sign_in(logged_in, "vera")
    assert vera.get("/users").status_code == 403
    with open_db(settings.db_path) as conn:
        set_role(conn, _user_id(settings, "vera"), "admin")
    assert vera.get("/users").status_code == 200


# ---- the Users page --------------------------------------------------------------


def test_users_page_lists_accounts_with_their_roles(logged_in: TestClient) -> None:
    _add(logged_in, "otto", "operator")
    text = _text(logged_in.get("/users").text)
    assert "admin (you)" in text and "otto" in text
    assert "Added vera as viewer" in _text(_add(logged_in, "vera", "viewer").text)


@pytest.mark.parametrize(
    ("name", "password", "confirm", "role", "message"),
    [
        ("bad name", PASSWORD, PASSWORD, "viewer", "A username is 1 to 64"),
        ("-dash", PASSWORD, PASSWORD, "viewer", "A username is 1 to 64"),
        ("x" * 65, PASSWORD, PASSWORD, "viewer", "A username is 1 to 64"),
        ("ok", "short", "short", "viewer", "at least 8 characters"),
        ("ok", PASSWORD, PASSWORD + "x", "viewer", "not the same"),
        ("ok", PASSWORD, PASSWORD, "root", "The role must be one of"),
        ("ADMIN", PASSWORD, PASSWORD, "viewer", "There is already an account called ADMIN"),
    ],
)
def test_adding_refuses_bad_input(
    logged_in: TestClient, name: str, password: str, confirm: str, role: str, message: str
) -> None:
    response = logged_in.post(
        "/users/create",
        data={
            "csrf": _csrf(logged_in, "/users"),
            "new_username": name,
            "password": password,
            "confirm_password": confirm,
            "role": role,
        },
    )
    assert response.status_code == 400
    assert message in _text(response.text)


def test_users_forms_need_the_csrf_token(logged_in: TestClient) -> None:
    response = logged_in.post(
        "/users/create",
        data={
            "new_username": "x1",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
            "role": "admin",
        },
    )
    assert response.status_code == 403
    assert "x1" not in _text(logged_in.get("/users").text)


def test_an_admin_cannot_change_or_disable_themselves(
    logged_in: TestClient, settings: Settings
) -> None:
    own = str(_user_id(settings, TEST_USER))
    for path, extra in (
        ("/users/role", {"role": "viewer"}),
        ("/users/disable", {"disabled": "yes"}),
    ):
        response = logged_in.post(
            path, data={"csrf": _csrf(logged_in, "/users"), "user_id": own, **extra}
        )
        assert response.status_code == 400
        assert "Another admin can" in response.text
    with open_db(settings.db_path) as conn:
        me = get_user(conn, TEST_USER)
    assert me is not None and me.role == "admin" and not me.disabled


def test_the_last_active_admin_is_kept(settings: Settings) -> None:
    with open_db(settings.db_path) as conn:
        migrate(conn)
        bootstrap_admin(conn, "boss", hash_password(PASSWORD))
        boss = get_user(conn, "boss")
        assert boss is not None
        with pytest.raises(UserError, match="only admin left"):
            set_role(conn, boss.id, "viewer")
        with pytest.raises(UserError, match="only admin left"):
            set_disabled(conn, boss.id, True)
        # A disabled second admin does not count as a way back in.
        spare = create_user(conn, "spare", PASSWORD, PASSWORD, "admin")
        set_disabled(conn, spare.id, True)
        with pytest.raises(UserError, match="only admin left"):
            set_role(conn, boss.id, "operator")
        set_disabled(conn, spare.id, False)
        set_role(conn, boss.id, "operator")
        assert get_user(conn, "boss").role == "operator"  # type: ignore[union-attr]


def test_disabling_signs_the_account_out_at_once(logged_in: TestClient, settings: Settings) -> None:
    _add(logged_in, "otto", "operator")
    otto = _sign_in(logged_in, "otto")
    assert otto.get("/").status_code == 200
    response = logged_in.post(
        "/users/disable",
        data={
            "csrf": _csrf(logged_in, "/users"),
            "user_id": str(_user_id(settings, "otto")),
            "disabled": "yes",
        },
    )
    assert "otto is disabled and was signed out" in _text(response.text)
    assert otto.get("/").status_code == 303
    logged_in.post(
        "/users/disable",
        data={
            "csrf": _csrf(logged_in, "/users"),
            "user_id": str(_user_id(settings, "otto")),
            "disabled": "no",
        },
    )
    _sign_in(logged_in, "otto")


def test_an_admin_sets_a_password_and_the_account_is_signed_out(
    logged_in: TestClient, settings: Settings
) -> None:
    _add(logged_in, "otto", "operator")
    otto = _sign_in(logged_in, "otto")
    response = logged_in.post(
        "/users/password",
        data={
            "csrf": _csrf(logged_in, "/users"),
            "user_id": str(_user_id(settings, "otto")),
            "new_password": "brand-new-password",
            "confirm_password": "brand-new-password",
        },
    )
    assert "New password set for otto" in _text(response.text)
    assert otto.get("/").status_code == 303
    _sign_in(logged_in, "otto", "brand-new-password")


def test_an_admin_setting_their_own_password_here_stays_signed_in(
    logged_in: TestClient, settings: Settings
) -> None:
    logged_in.post(
        "/users/password",
        data={
            "csrf": _csrf(logged_in, "/users"),
            "user_id": str(_user_id(settings, TEST_USER)),
            "new_password": "brand-new-password",
            "confirm_password": "brand-new-password",
        },
    )
    assert logged_in.get("/").status_code == 200


# ---- the Account page --------------------------------------------------------------


def _change_own(client: TestClient, current: str, new: str, confirm: str | None = None):
    return client.post(
        "/account/password",
        data={
            "csrf": _csrf(client, "/account"),
            "current_password": current,
            "new_password": new,
            "confirm_password": new if confirm is None else confirm,
        },
    )


def test_a_viewer_can_change_their_own_password(logged_in: TestClient) -> None:
    _add(logged_in, "vera", "viewer")
    vera = _sign_in(logged_in, "vera")
    second = _sign_in(logged_in, "vera")
    response = _change_own(vera, PASSWORD, "brand-new-password")
    assert response.status_code == 200 and "Password changed" in response.text
    assert vera.get("/").status_code == 200, "the session that changed it stays"
    assert second.get("/").status_code == 303, "other sessions are signed out"
    _sign_in(logged_in, "vera", "brand-new-password")


def test_changing_your_password_needs_the_current_one(logged_in: TestClient) -> None:
    response = _change_own(logged_in, "wrong-password", "brand-new-password")
    assert response.status_code == 400 and "current password is not right" in response.text
    other = TestClient(logged_in.app, follow_redirects=False)
    ok = other.post("/login", data={"username": TEST_USER, "password": TEST_PASSWORD, "next": "/"})
    assert ok.status_code == 303


def test_wrong_current_passwords_are_throttled(
    settings: Settings, make_client: Callable[[Settings], TestClient]
) -> None:
    client = make_client(with_settings(settings, login_max_attempts=2))
    client.post("/login", data={"username": TEST_USER, "password": TEST_PASSWORD, "next": "/"})
    _change_own(client, "wrong-1", "brand-new-password")
    _change_own(client, "wrong-2", "brand-new-password")
    response = _change_own(client, TEST_PASSWORD, "brand-new-password")
    assert response.status_code == 429


def test_the_account_page_shows_name_and_role(logged_in: TestClient) -> None:
    text = _text(logged_in.get("/account").text)
    assert f"Username {TEST_USER}" in text and "Role admin" in text


# ---- the command-line reset ----------------------------------------------------------


def test_resetpw_sets_a_password_and_enables_the_account(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    settings: Settings,
    client: TestClient,
) -> None:
    with open_db(settings.db_path) as conn:
        admin = get_user(conn, TEST_USER)
        assert admin is not None
        create_user(conn, "spare", PASSWORD, PASSWORD, "admin")
        set_disabled(conn, admin.id, True)
    monkeypatch.setattr(resetpw, "load_settings", lambda: settings)
    monkeypatch.setattr("sys.stdin", io.StringIO("recovered-password\n"))
    assert resetpw.main([TEST_USER.upper()]) == 0
    assert "enabled again" in capsys.readouterr().out
    with open_db(settings.db_path) as conn:
        assert authenticate(conn, TEST_USER, "recovered-password") is not None


@pytest.mark.parametrize(("args", "stdin", "code"), [([], "", 2), (["nobody"], "x" * 9, 1)])
def test_resetpw_refuses_a_missing_or_unknown_name(
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    client: TestClient,
    args: list[str],
    stdin: str,
    code: int,
) -> None:
    monkeypatch.setattr(resetpw, "load_settings", lambda: settings)
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin + "\n"))
    assert resetpw.main(args) == code


def test_resetpw_refuses_a_short_password(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, client: TestClient
) -> None:
    monkeypatch.setattr(resetpw, "load_settings", lambda: settings)
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    assert resetpw.main([TEST_USER]) == 1
    with open_db(settings.db_path) as conn:
        assert authenticate(conn, TEST_USER, TEST_PASSWORD) is not None
