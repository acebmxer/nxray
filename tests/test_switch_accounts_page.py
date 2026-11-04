"""Switch accounts for NXray users (#17), through the Users and Account pages."""

from __future__ import annotations

import logging
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.db import open_db
from app.users import get_user
from tests.conftest import TEST_USER
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

# Letters and digits, upper and lower case, no runs: both sides take it.
GOOD = "Kx7mQ2vLp9"
OTHER = "Tz4nW8rBq3"
ADMIN = {"admin_user": "admin", "admin_password": ADMIN_PASSWORD}


def _csrf(client: TestClient, path: str = "/users") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(html: str) -> str:
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))
    return text.replace("&#39;", "'").replace("&#34;", '"')


def _db(settings: Settings, sql: str, *args) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(sql, args)
    conn.commit()
    conn.close()


@pytest.fixture
def switch(logged_in: TestClient, settings: Settings) -> FakeSwitch:
    """A switch set up (NXray's account nxray) with changes on, the wait over."""
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    login = {**ADMIN, "confirm_save": "yes"}
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "host": "192.0.2.10",
            "port": "443",
            "account_name": "nxray",
            **login,
        },
    )
    logged_in.post(
        "/switch/enable-changes",
        data={"csrf": _csrf(logged_in, "/switch"), "ssh_port": "22", **login},
    )
    _db(settings, "UPDATE switch_connection SET paused_until = ?", time.time() - 1)
    fake.requests.clear()
    fake.saved = False
    return fake


def _add(client: TestClient, name: str, role: str, password: str = GOOD, **extra):
    return client.post(
        "/users/create",
        data={
            "csrf": _csrf(client),
            "new_username": name,
            "password": password,
            "confirm_password": password,
            "role": role,
            **extra,
        },
    )


def _add_on_switch(client: TestClient, name: str, role: str, password: str = GOOD, **extra):
    fields = {"switches": ["1"], "confirm_switch": "yes", **ADMIN, **extra}
    return _add(client, name, role, password, **fields)


def _user_id(settings: Settings, name: str) -> int:
    with open_db(settings.db_path) as conn:
        user = get_user(conn, name)
    assert user is not None
    return user.id


def _post(client: TestClient, path: str, **form):
    return client.post(path, data={"csrf": _csrf(client), **form})


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


# ---- NXray only stays the default --------------------------------------------


def test_nxray_only_is_the_default(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/users").text
    assert 'name="switches" value="1"' in page
    assert 'name="switches" value="1" checked' not in page
    response = _add(logged_in, "vera", "viewer")
    assert "Added vera as viewer." in _text(response.text)
    assert "vera" not in switch.users
    assert _config_requests(switch) == []


def test_the_switch_admin_account_is_never_linked(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _add(logged_in, "vera", "viewer")
    user_id = str(_user_id(settings, "vera"))
    assert '<option value="admin"' not in logged_in.get(f"/users/switch?user_id={user_id}").text
    response = _post(
        logged_in, "/users/switch/link", user_id=user_id, switch_id="1", account_name="admin"
    )
    assert "a name the switch keeps for itself" in _text(response.text)
    text = _text(_add_on_switch(logged_in, "admin", "admin").text)
    assert "a name the switch keeps for itself" in text


def test_the_users_page_lists_the_switch_accounts(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    text = _text(logged_in.get("/users").text)
    assert "Local accounts on" in text
    assert "admin network-admin kept by the switch; never changed here" in text
    assert "nxray network-operator, nxray-ports NXray's own account; never changed here" in text
    # The role mapping is shown before anything is sent.
    assert "operator → network-operator + nxray-ports" in text


# ---- making the account with the NXray user ----------------------------------


@pytest.mark.parametrize(
    ("role", "roles"),
    [
        ("viewer", {"network-operator"}),
        ("operator", {"network-operator", "nxray-ports"}),
        ("admin", {"network-admin"}),
    ],
)
def test_nxray_and_the_switch(
    logged_in: TestClient, switch: FakeSwitch, role: str, roles: set[str]
) -> None:
    response = _add_on_switch(logged_in, "otto", role)
    text = _text(response.text)
    assert response.status_code == 200
    assert f"Added otto as {role}." in text
    assert "Also on the switch: otto on" in text and "was saved" in text
    assert switch.users["otto"][0] == GOOD
    assert switch.roles_of("otto") == roles
    assert switch.saved
    # The password never reaches the activity log or a page.
    activity = _text(logged_in.get("/activity").text)
    assert "Made the switch account otto" in activity
    assert GOOD not in activity and GOOD not in response.text
    # The user can sign in over SSH with the same name and password.
    switch.ssh_opener()("192.0.2.10", 22, "otto", GOOD, 5)


def test_an_operator_on_a_switch_with_changes_off_gets_network_operator_only(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET changes_enabled_at = NULL")
    _add_on_switch(logged_in, "otto", "operator")
    assert switch.roles_of("otto") == {"network-operator"}


@pytest.mark.parametrize(
    ("name", "password", "extra", "message"),
    [
        ("otto", "short1A", {}, "at least 8 characters"),
        ("otto", "Kx7mQ2vL p9", {}, "letters and digits"),
        ("otto", "kx7mq2vlp9", {}, "upper case, lower case and digits"),
        ("otto", "Kx7abcQ2v9", {}, "upper case, lower case and digits"),
        ("otto@lab", GOOD, {}, "the switch takes account names"),
        ("1otto", GOOD, {}, "the switch takes account names"),
        ("otto", GOOD, {"confirm_switch": ""}, "tick the box to confirm"),
        ("otto", GOOD, {"admin_password": ""}, "type the switch admin username and password"),
    ],
)
def test_refused_before_anything_is_made(
    logged_in: TestClient,
    switch: FakeSwitch,
    settings: Settings,
    name: str,
    password: str,
    extra: dict[str, str],
    message: str,
) -> None:
    response = _add_on_switch(logged_in, name, "viewer", password, **extra)
    assert response.status_code == 400
    assert message in _text(response.text)
    with open_db(settings.db_path) as conn:
        assert get_user(conn, name) is None
    assert name not in switch.users
    assert _config_requests(switch) == []


def test_nxray_takes_what_the_switch_would_refuse(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    text = _text(_add_on_switch(logged_in, "otto", "viewer", "kx7mq2vlp9").text)
    assert "NXray takes this, but the switch's password check would refuse it" in text
    # NXray only still works with that password.
    assert "Added otto" in _text(_add(logged_in, "otto", "viewer", "kx7mq2vlp9").text)


def test_a_wrong_admin_login_adds_the_user_to_nxray_only(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    response = _add_on_switch(logged_in, "otto", "viewer", admin_password="Wrong-pw-1")
    text = _text(response.text)
    assert "Added otto as viewer." in text
    assert "otto was added to NXray, but not to every switch" in text
    assert "refused the admin username or password" in text
    assert "Wrong-pw-1" not in response.text
    assert "otto" not in switch.users


def test_an_account_already_on_the_switch_is_linked_not_overwritten(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    switch.users["otto"] = ("Old0password", "network-operator")
    text = _text(_add_on_switch(logged_in, "otto", "viewer").text)
    assert "already has an account called otto; link it" in text
    assert switch.users["otto"][0] == "Old0password"
    page = _text(logged_in.get(f"/users/switch?user_id={_user_id(settings, 'otto')}").text)
    assert "Or link an account already on the switch" in page


def test_nxrays_own_account_is_never_made_linked_or_offered(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    text = _text(_add_on_switch(logged_in, "nxray", "viewer").text)
    assert "is NXray's own account" in text
    assert switch.users["nxray"][1] == "network-operator"
    user_id = _user_id(settings, "nxray")
    page = logged_in.get(f"/users/switch?user_id={user_id}").text
    assert '<option value="nxray"' not in page
    response = _post(
        logged_in, "/users/switch/link", user_id=str(user_id), switch_id="1", account_name="nxray"
    )
    assert "is NXray's own account" in _text(response.text)
    with open_db(settings.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM switch_accounts").fetchone()[0] == 0


# ---- keeping the two in step -------------------------------------------------


def test_a_role_change_is_out_of_step_until_brought_in_step(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _add_on_switch(logged_in, "otto", "viewer")
    user_id = str(_user_id(settings, "otto"))
    changed = _text(_post(logged_in, "/users/role", user_id=user_id, role="admin").text)
    assert "otto is now admin. Out of step on the switch: otto on" in changed
    assert "an NXray admin has network-admin" in changed
    assert switch.roles_of("otto") == {"network-operator"}

    done = _post(logged_in, "/users/switch/roles", user_id=user_id, switch_id="1", **ADMIN)
    assert "has the role network-admin, as an NXray admin" in _text(done.text)
    assert switch.roles_of("otto") == {"network-admin"}
    assert _config_requests(switch)[-2] == [
        "username otto role network-admin",
        "no username otto role network-operator",
    ]
    assert "out of step" not in _text(logged_in.get("/users").text)


def test_roles_nxray_does_not_give_are_left_alone(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _add_on_switch(logged_in, "otto", "viewer")
    switch.extra_roles.setdefault("otto", set()).add("priv-5")
    user_id = str(_user_id(settings, "otto"))
    _post(logged_in, "/users/role", user_id=user_id, role="operator")
    _post(logged_in, "/users/switch/roles", user_id=user_id, switch_id="1", **ADMIN)
    assert switch.roles_of("otto") == {"network-operator", "nxray-ports", "priv-5"}


def test_disable_then_lock_then_open_with_a_new_password(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _add_on_switch(logged_in, "otto", "operator")
    user_id = str(_user_id(settings, "otto"))
    disabled = _text(_post(logged_in, "/users/disable", user_id=user_id, disabled="yes").text)
    assert "the switch account can still sign in" in disabled

    refused = _post(logged_in, "/users/switch/lock", user_id=user_id, switch_id="1", **ADMIN)
    assert "tick the box to confirm" in _text(refused.text)
    assert switch.users["otto"][0] == GOOD
    switch.saved = False
    locked = _post(
        logged_in, "/users/switch/lock", user_id=user_id, switch_id="1", confirm="yes", **ADMIN
    )
    text = _text(locked.text)
    assert "Locked otto on" in text and "was saved, so it survives a restart" in text
    assert switch.users["otto"][0] != GOOD
    assert switch.saved  # a reboot keeps it locked
    assert switch.roles_of("otto") == {"network-operator", "nxray-ports"}

    enabled = _text(_post(logged_in, "/users/disable", user_id=user_id, disabled="no").text)
    assert "the switch account is locked; set a new password to open it" in enabled
    opened = _post(
        logged_in,
        "/users/switch/password",
        user_id=user_id,
        password=OTHER,
        confirm_password=OTHER,
        **ADMIN,
    )
    assert "otto on" in _text(opened.text) and "has it too" in _text(opened.text)
    assert switch.users["otto"][0] == OTHER
    assert "out of step" not in _text(logged_in.get("/users").text)


def test_a_lock_that_was_not_saved_says_a_restart_undoes_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _add_on_switch(logged_in, "otto", "viewer")
    switch.save_text = "Copy failed\n"
    response = _post(
        logged_in,
        "/users/switch/lock",
        user_id=str(_user_id(settings, "otto")),
        switch_id="1",
        confirm="yes",
        **ADMIN,
    )
    assert "was NOT saved" in _text(response.text)
    assert "a restart of the switch undoes this change" in _text(response.text)


def test_an_admin_password_reset_in_nxray_only_is_out_of_step(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _add_on_switch(logged_in, "otto", "viewer")
    user_id = str(_user_id(settings, "otto"))
    reset = _post(
        logged_in,
        "/users/password",
        user_id=user_id,
        new_password="a-long-nxray-only-password",
        confirm_password="a-long-nxray-only-password",
    )
    assert "the NXray password changed since NXray last set this one" in _text(reset.text)
    assert switch.users["otto"][0] == GOOD


def test_own_password_change_marks_the_switch_out_of_step(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _add_on_switch(logged_in, "otto", "viewer")
    otto = TestClient(logged_in.app, follow_redirects=False)
    otto.post("/login", data={"username": "otto", "password": GOOD, "next": "/"})
    response = otto.post(
        "/account/password",
        data={
            "csrf": _csrf(otto, "/account"),
            "current_password": GOOD,
            "new_password": "my-own-new-password",
            "confirm_password": "my-own-new-password",
        },
    )
    text = _text(response.text)
    assert "still has your old password: only an NXray admin can change it there" in text
    assert "out of step" in text
    assert switch.users["otto"][0] == GOOD


def test_a_new_password_for_both_sides_checks_the_switch_first(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _add_on_switch(logged_in, "otto", "viewer")
    user_id = str(_user_id(settings, "otto"))
    response = _post(
        logged_in,
        "/users/switch/password",
        user_id=user_id,
        password="nxray-only-pass!",
        confirm_password="nxray-only-pass!",
        **ADMIN,
    )
    assert response.status_code == 400
    assert "NXray takes this password, but a switch password is 8 to 64" in _text(response.text)
    with open_db(settings.db_path) as conn:
        otto = get_user(conn, "otto")
    assert otto is not None
    assert switch.users["otto"][0] == GOOD


def test_a_switch_that_refuses_a_new_password_stays_out_of_step(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _add_on_switch(logged_in, "otto", "viewer")
    switch.reject.add("username otto password")
    response = _post(
        logged_in,
        "/users/switch/password",
        user_id=str(_user_id(settings, "otto")),
        password=OTHER,
        confirm_password=OTHER,
        **ADMIN,
    )
    text = _text(response.text)
    assert "New password set for otto in NXray" in text
    assert "Out of step:" in text and "not changed" in text
    assert OTHER not in response.text
    assert "out of step" in _text(logged_in.get("/users").text)


def test_link_an_existing_account_then_set_its_password(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    switch.users["olga"] = ("Old0password", "network-operator")
    _add(logged_in, "olga", "viewer")
    user_id = str(_user_id(settings, "olga"))
    linked = _post(
        logged_in, "/users/switch/link", user_id=user_id, switch_id="1", account_name="olga"
    )
    assert "Nothing changed on the switch" in _text(linked.text)
    assert _config_requests(switch) == []
    assert "password: NXray never set it" in _text(linked.text)
    _post(
        logged_in,
        "/users/switch/password",
        user_id=user_id,
        password=OTHER,
        confirm_password=OTHER,
        **ADMIN,
    )
    assert switch.users["olga"][0] == OTHER
    page = _text(logged_in.get(f"/users/switch?user_id={user_id}").text)
    assert "in step" in page and "out of step" not in page


def test_remove_and_unlink(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> None:
    _add_on_switch(logged_in, "otto", "viewer")
    _add_on_switch(logged_in, "olga", "viewer")
    otto, olga = str(_user_id(settings, "otto")), str(_user_id(settings, "olga"))
    removed = _post(
        logged_in, "/users/switch/remove", user_id=otto, switch_id="1", confirm="yes", **ADMIN
    )
    assert "Removed the account otto from" in _text(removed.text)
    assert "otto" not in switch.users
    unlinked = _post(logged_in, "/users/switch/unlink", user_id=olga, switch_id="1")
    assert "The account is still on the switch, unchanged" in _text(unlinked.text)
    assert "olga" in switch.users
    with open_db(settings.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM switch_accounts").fetchone()[0] == 0
        assert get_user(conn, "otto") is not None


def test_forgetting_a_switch_forgets_its_links(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _add_on_switch(logged_in, "otto", "viewer")
    from app.switch_connection import delete_connection

    with open_db(settings.db_path) as conn:
        delete_connection(conn, 1)
        assert conn.execute("SELECT COUNT(*) FROM switch_accounts").fetchone()[0] == 0


def test_no_password_in_the_logs(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings, caplog
) -> None:
    caplog.set_level(logging.DEBUG)
    _add_on_switch(logged_in, "otto", "viewer")
    _post(
        logged_in,
        "/users/switch/password",
        user_id=str(_user_id(settings, "otto")),
        password=OTHER,
        confirm_password=OTHER,
        **ADMIN,
    )
    for secret in (GOOD, OTHER, ADMIN_PASSWORD):
        assert secret not in caplog.text


@pytest.mark.parametrize(
    "path",
    [
        "/users/switch/create",
        "/users/switch/link",
        "/users/switch/password",
        "/users/switch/roles",
        "/users/switch/lock",
        "/users/switch/remove",
        "/users/switch/unlink",
    ],
)
def test_every_switch_account_form_needs_the_token(
    logged_in: TestClient, switch: FakeSwitch, path: str
) -> None:
    response = logged_in.post(
        path, data={"csrf": "0" * 64, "user_id": "1", "switch_id": "1", **ADMIN, "confirm": "yes"}
    )
    assert response.status_code == 403
    assert _config_requests(switch) == []


def test_own_account_page_shows_the_switch_account(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    user_id = str(_user_id(settings, TEST_USER))
    page = _text(logged_in.get(f"/users/switch?user_id={user_id}").text)
    assert f"Switch accounts of {TEST_USER}" in page


# ---- accounts on their own (#31) ----------------------------------------------


def _switch_only(
    client: TestClient, name: str, role: str = "viewer", password: str = GOOD, **extra
):
    return _post(
        client,
        "/users/switch-account/create",
        account_name=name,
        password=password,
        confirm_password=password,
        role=role,
        switches=["1"],
        confirm_switch="yes",
        **{**ADMIN, **extra},
    )


def test_a_switch_account_with_no_nxray_user(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    response = _switch_only(logged_in, "sven", "operator")
    assert "sven on" in _text(response.text) and "network-operator + nxray-ports" in _text(
        response.text
    )
    assert "sven" in switch.users and switch.saved
    with open_db(settings.db_path) as conn:
        assert get_user(conn, "sven") is None
        assert conn.execute("SELECT COUNT(*) FROM switch_accounts").fetchone()[0] == 0
    assert "switch-account/delete?name=sven" in logged_in.get("/users").text


@pytest.mark.parametrize(
    ("change", "words"),
    [
        ({"account_name": "admin"}, "a name the switch keeps for itself"),
        ({"account_name": "nxray"}, "NXray's own account"),
        ({"account_name": "1bad"}, "starting with a letter"),
        ({"password": "short", "confirm_password": "short"}, "password"),
        ({"confirm_password": OTHER}, "not the same"),
        ({"role": "root"}, "pick the role"),
        ({"confirm_switch": ""}, "tick the box"),
        ({"switches": []}, "tick at least one switch"),
    ],
)
def test_a_switch_account_is_checked_before_anything_is_sent(
    logged_in: TestClient, switch: FakeSwitch, change: dict, words: str
) -> None:
    form = {
        "account_name": "sven",
        "password": GOOD,
        "confirm_password": GOOD,
        "role": "viewer",
        "switches": ["1"],
        "confirm_switch": "yes",
        **ADMIN,
        **change,
    }
    response = _post(logged_in, "/users/switch-account/create", **form)
    assert response.status_code == 400 and words in _text(response.text)
    assert _config_requests(switch) == []


def test_a_switch_account_is_never_made_over_an_existing_one(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    _switch_only(logged_in, "sven")
    again = _switch_only(logged_in, "sven", password=OTHER)
    assert "already has an account called sven" in _text(again.text)
    assert switch.users["sven"][0] == GOOD


def test_the_users_page_has_a_delete_button_for_others_not_for_yourself(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _add(logged_in, "otto", "viewer")
    page = logged_in.get("/users").text
    assert f'href="/users/delete?user_id={_user_id(settings, "otto")}"' in page
    assert f'href="/users/delete?user_id={_user_id(settings, TEST_USER)}"' not in page


def test_delete_an_nxray_user_only_leaves_the_switch_account(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _add_on_switch(logged_in, "otto", "viewer")
    user_id = str(_user_id(settings, "otto"))
    page = _text(logged_in.get(f"/users/delete?user_id={user_id}").text)
    assert "Also delete otto from" in page
    asked = _post(logged_in, "/users/delete", user_id=user_id)
    assert asked.status_code == 400 and "tick the box" in _text(asked.text)
    done = _post(logged_in, "/users/delete", user_id=user_id, confirm="yes")
    text = _text(done.text)
    assert "Deleted otto from NXray" in text and "Still on the switch" in text
    assert "otto" in switch.users
    with open_db(settings.db_path) as conn:
        assert get_user(conn, "otto") is None
        assert conn.execute("SELECT COUNT(*) FROM switch_accounts").fetchone()[0] == 0


def test_delete_both(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> None:
    _add_on_switch(logged_in, "otto", "viewer")
    user_id = str(_user_id(settings, "otto"))
    done = _post(
        logged_in, "/users/delete", user_id=user_id, switches=["1"], confirm="yes", **ADMIN
    )
    assert "Also deleted: otto on" in _text(done.text)
    assert "otto" not in switch.users
    with open_db(settings.db_path) as conn:
        assert get_user(conn, "otto") is None


def test_a_switch_that_refuses_keeps_the_nxray_user(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _add_on_switch(logged_in, "otto", "viewer")
    user_id = str(_user_id(settings, "otto"))
    wrong = _post(
        logged_in,
        "/users/delete",
        user_id=user_id,
        switches=["1"],
        confirm="yes",
        admin_user="admin",
        admin_password="wrong",
    )
    assert wrong.status_code == 400 and "was NOT deleted from NXray" in _text(wrong.text)
    assert "wrong" not in wrong.text
    assert "otto" in switch.users
    with open_db(settings.db_path) as conn:
        assert get_user(conn, "otto") is not None


def test_you_and_the_last_admin_are_not_deleted(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    own = str(_user_id(settings, TEST_USER))
    response = _post(logged_in, "/users/delete", user_id=own, confirm="yes")
    assert response.status_code == 400 and "your own account" in _text(response.text)
    _add(logged_in, "vera", "admin")
    vera = str(_user_id(settings, "vera"))
    _post(logged_in, "/users/role", user_id=vera, role="viewer")
    other = _post(
        logged_in, "/users/delete", user_id=str(_user_id(settings, "vera")), confirm="yes"
    )
    assert "Deleted vera" in _text(other.text)


def test_delete_a_switch_account_with_no_nxray_user(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    _switch_only(logged_in, "sven")
    page = _text(logged_in.get("/users/switch-account/delete?name=sven&switch_id=1").text)
    assert "Linked to no NXray user" in page
    refused = _post(logged_in, "/users/switch-account/delete", name="sven", switches=["1"], **ADMIN)
    assert refused.status_code == 400 and "tick the box" in _text(refused.text)
    assert "sven" in switch.users
    done = _post(
        logged_in,
        "/users/switch-account/delete",
        name="sven",
        switches=["1"],
        confirm="yes",
        **ADMIN,
    )
    assert "Deleted: sven on" in _text(done.text)
    assert "sven" not in switch.users and switch.saved


def test_delete_a_linked_switch_account_keeps_the_nxray_user(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _add_on_switch(logged_in, "otto", "viewer")
    page = _text(logged_in.get("/users/switch-account/delete?name=otto&switch_id=1").text)
    assert "Linked to the NXray user otto" in page
    _post(
        logged_in,
        "/users/switch-account/delete",
        name="otto",
        switches=["1"],
        confirm="yes",
        **ADMIN,
    )
    assert "otto" not in switch.users
    with open_db(settings.db_path) as conn:
        assert get_user(conn, "otto") is not None
        assert conn.execute("SELECT COUNT(*) FROM switch_accounts").fetchone()[0] == 0


@pytest.mark.parametrize("name", ["admin", "nxray"])
def test_guarded_switch_accounts_are_never_deleted(
    logged_in: TestClient, switch: FakeSwitch, name: str
) -> None:
    response = _post(
        logged_in,
        "/users/switch-account/delete",
        name=name,
        switches=["1"],
        confirm="yes",
        **ADMIN,
    )
    assert response.status_code == 400
    assert name in switch.users
    assert _config_requests(switch) == []


def test_a_missing_account_is_not_reported_as_deleted(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    response = _post(
        logged_in,
        "/users/switch-account/delete",
        name="ghost",
        switches=["1"],
        confirm="yes",
        **ADMIN,
    )
    assert "has no account called ghost" in _text(response.text)


def test_the_new_forms_need_an_admin_and_a_csrf_token(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    for path in ("/users/switch-account/create", "/users/switch-account/delete", "/users/delete"):
        response = logged_in.post(path, data={"csrf": "nope", "name": "x"})
        assert response.status_code in (400, 403), path


def test_no_password_in_the_logs_of_a_switch_only_account(
    logged_in: TestClient, switch: FakeSwitch, caplog
) -> None:
    with caplog.at_level(logging.DEBUG):
        _switch_only(logged_in, "sven")
    assert GOOD not in caplog.text and ADMIN_PASSWORD not in caplog.text
