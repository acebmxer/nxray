"""Run setup again against a pretend switch: new password, or the account made again."""

from __future__ import annotations

import pytest

from app.port_changes import ROLE_NAME
from app.switch_repair import (
    ROLE_GIVEN,
    ROLE_KEPT,
    ROLE_MISSING,
    role_names,
    run_repair,
)
from app.switch_setup import SetupError
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch, Role

OLD_PASSWORD = "Old1PasswordXy"


class Store:
    def __init__(self, fail: bool = False) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail = fail

    def __call__(self, password: str, hostname: str) -> None:
        if self.fail:
            raise RuntimeError("disk full")
        self.calls.append((password, hostname))


def _switch(*, account: bool = True, role_on_switch: bool = True, has_role: bool = True):
    """A switch where NXray's account nxray was set up with port changes on."""
    switch = FakeSwitch()
    if role_on_switch:
        switch.roles[ROLE_NAME] = Role(entities={"copy running-config startup-config"})
    if account:
        switch.users["nxray"] = (OLD_PASSWORD, "network-operator")
        if has_role:
            switch.extra_roles["nxray"] = {ROLE_NAME}
    return switch


def _repair(switch: FakeSwitch, store: Store, **overrides):
    args = {
        "host": "192.0.2.10",
        "port": 443,
        "admin_user": "admin",
        "admin_password": ADMIN_PASSWORD,
        "account_name": "nxray",
        "port_changes": True,
        "store": store,
        "transport": switch.transport(),
    }
    args.update(overrides)
    return run_repair(**args)


def _request_index(switch: FakeSwitch, command: str) -> int:
    for index, commands in enumerate(switch.requests):
        if command in commands:
            return index
    raise AssertionError(f"{command!r} was never sent")


def test_existing_account_gets_a_new_password_and_keeps_its_roles() -> None:
    switch, store = _switch(), Store()
    result = _repair(switch, store)

    new_password = switch.users["nxray"][0]
    assert new_password != OLD_PASSWORD
    assert store.calls == [(new_password, "nexus-lab")]
    assert switch.roles_of("nxray") == {"network-operator", ROLE_NAME}
    assert not result.recreated
    assert result.port_role == ROLE_KEPT
    assert result.pause_seconds == 0
    assert result.config_saved and switch.saved
    # No role command: the account already had it.
    assert not any(c.startswith("username nxray role") for r in switch.requests for c in r)


def test_removed_account_is_made_again_with_the_role_before_it_signs_in() -> None:
    switch, store = _switch(account=False), Store()
    result = _repair(switch, store)

    assert result.recreated
    assert result.port_role == ROLE_GIVEN
    assert result.pause_seconds == 0  # a fresh account gets the role at once
    assert switch.roles_of("nxray") == {"network-operator", ROLE_NAME}
    assert store.calls and store.calls[0][0] == switch.users["nxray"][0]
    # The role came before the new account's first sign-in (show hostname).
    assert _request_index(switch, f"username nxray role {ROLE_NAME}") < _request_index(
        switch, "show hostname"
    )


def test_existing_account_that_lost_the_role_gets_it_back_and_a_wait() -> None:
    switch = _switch(has_role=False)
    result = _repair(switch, Store())
    assert result.port_role == ROLE_GIVEN
    assert result.pause_seconds == 11 * 60  # its NX-API session may still hold the old roles
    assert ROLE_NAME in switch.roles_of("nxray")


def test_role_gone_from_the_switch_turns_port_changes_off() -> None:
    switch = _switch(account=False, role_on_switch=False)
    result = _repair(switch, Store())
    assert result.recreated
    assert result.port_role == ROLE_MISSING
    assert switch.roles_of("nxray") == {"network-operator"}
    assert not any(c.startswith("username nxray role") for r in switch.requests for c in r)


def test_port_changes_off_never_touches_the_role() -> None:
    switch = _switch(account=False)
    result = _repair(switch, Store(), port_changes=False)
    assert result.port_role is None
    assert switch.roles_of("nxray") == {"network-operator"}


def test_wrong_admin_password_changes_nothing() -> None:
    switch, store = _switch(), Store()
    with pytest.raises(SetupError, match="refused the admin username or password"):
        _repair(switch, store, admin_password="Wrong1Admin")
    assert switch.users["nxray"][0] == OLD_PASSWORD
    assert store.calls == []
    assert not switch.saved


def test_refused_password_change_keeps_both_passwords_out_of_the_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.switch_repair.generate_password", lambda: "Known1PasswordXy")
    switch = _switch()
    switch.reject = {"username nxray password"}  # the fake echoes the whole command
    with pytest.raises(SetupError) as excinfo:
        _repair(switch, Store())
    message = str(excinfo.value)
    assert "did not change the account" in message
    assert "Known1PasswordXy" not in message
    assert ADMIN_PASSWORD not in message


def test_new_password_that_does_not_sign_in_says_to_run_it_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.switch_setup._VERIFY_PAUSE_SECONDS", 0)
    switch, store = _switch(), Store()
    original = switch._authenticate

    def refuse_nxray(request):
        user = original(request)
        return None if user == "nxray" else user

    switch._authenticate = refuse_nxray  # type: ignore[method-assign]
    with pytest.raises(SetupError) as excinfo:
        _repair(switch, store)
    message = str(excinfo.value)
    assert "Press Run setup again" in message
    assert switch.users["nxray"][0] not in message
    assert store.calls == []
    assert not switch.saved
    assert "nxray" in switch.users  # never removed: running it again repairs it


def test_store_failure_leaves_the_account_and_says_to_run_it_again() -> None:
    switch = _switch()
    with pytest.raises(SetupError) as excinfo:
        _repair(switch, Store(fail=True))
    assert "could not store the login" in str(excinfo.value)
    assert "Press Run setup again" in str(excinfo.value)
    assert "nxray" in switch.users
    assert not any("no username" in c for r in switch.requests for c in r)


def test_failed_save_still_stores_and_says_so() -> None:
    switch, store = _switch(), Store()
    switch.save_text = "Copy failed: not enough space\n"
    result = _repair(switch, store)
    assert not result.config_saved
    assert "Copy failed" in (result.save_error or "")
    assert store.calls


def test_role_names_reads_one_or_many_rows() -> None:
    one = {"TABLE_role": {"ROW_role": {"role_name": "network-admin"}}}
    many = {"TABLE_role": {"ROW_role": [{"role_name": "network-admin"}, {"role_name": ROLE_NAME}]}}
    assert role_names(one) == {"network-admin"}
    assert role_names(many) == {"network-admin", ROLE_NAME}
    assert role_names({}) == set()
