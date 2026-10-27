"""Setup against a pretend switch: the account is made, checked, stored, saved."""

from __future__ import annotations

import pytest

from app.nxapi import SwitchTarget
from app.switch_setup import (
    ACCOUNT_ROLE,
    PASSWORD_LENGTH,
    SetupError,
    _strong_enough,
    account_names,
    check_connection,
    generate_password,
    load_dashboard_status,
    run_setup,
)
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


class Store:
    def __init__(self, fail: bool = False) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail = fail

    def __call__(self, password: str, hostname: str) -> None:
        if self.fail:
            raise RuntimeError("disk full")
        self.calls.append((password, hostname))


def _setup(switch: FakeSwitch, store: Store, **overrides):
    args = {
        "host": "192.0.2.10",
        "port": 443,
        "admin_user": "admin",
        "admin_password": ADMIN_PASSWORD,
        "account_name": "nxray",
        "store": store,
        "transport": switch.transport(),
    }
    args.update(overrides)
    return run_setup(**args)


def test_setup_creates_a_read_only_account_and_saves() -> None:
    switch, store = FakeSwitch(), Store()
    result = _setup(switch, store)

    password, role = switch.users["nxray"]
    assert role == ACCOUNT_ROLE == "network-operator"
    assert store.calls == [(password, "nexus-lab")]
    assert result.switch_hostname == "nexus-lab"
    assert result.config_saved and switch.saved
    assert result.save_error is None


def test_the_new_account_is_checked_with_its_own_login() -> None:
    switch = FakeSwitch()
    _setup(switch, Store())
    # admin: show version + show user-account, create, (new account) show
    # hostname, admin: save.
    assert switch.requests == [
        ["show version", "show user-account"],
        [switch.requests[1][0]],
        ["show hostname"],
        ["copy running-config startup-config"],
    ]
    assert switch.requests[1][0].startswith("username nxray password ")


def test_existing_name_stops_setup_before_anything_changes() -> None:
    switch = FakeSwitch()
    switch.users["NXray"] = ("Whatever123", "network-operator")
    store = Store()
    with pytest.raises(SetupError) as excinfo:
        _setup(switch, store)
    assert "already exists" in str(excinfo.value)
    assert "nxray-dev" in str(excinfo.value)
    assert store.calls == []
    assert switch.users["NXray"] == ("Whatever123", "network-operator")
    assert not switch.saved
    assert len(switch.requests) == 1  # only the read


def test_wrong_admin_password_is_reported_plainly() -> None:
    switch = FakeSwitch()
    with pytest.raises(SetupError) as excinfo:
        _setup(switch, Store(), admin_password="wrong")
    assert "refused the admin username or password" in str(excinfo.value)
    assert set(switch.users) == {"admin"}


def test_unreachable_switch_is_reported_plainly() -> None:
    switch = FakeSwitch(reachable=False)
    with pytest.raises(SetupError) as excinfo:
        _setup(switch, Store())
    assert "could not reach the switch at 192.0.2.10, port 443" in str(excinfo.value)
    assert "feature nxapi" in str(excinfo.value)


@pytest.mark.parametrize("name", ["admin", "root", "1nxray", "nx ray", "a" * 29, ""])
def test_bad_account_names_are_refused_before_connecting(name: str) -> None:
    switch = FakeSwitch()
    with pytest.raises(SetupError):
        _setup(switch, Store(), account_name=name)
    assert switch.requests == []


def test_rejected_create_keeps_both_passwords_out_of_the_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.switch_setup.generate_password", lambda: "Known1PasswordXy")
    switch = FakeSwitch(reject={"username "})
    with pytest.raises(SetupError) as excinfo:
        _setup(switch, Store())
    message = str(excinfo.value)
    assert "did not create the account" in message
    assert "Rejected by the fake switch" in message  # the switch's own words
    assert "Known1PasswordXy" not in message
    assert ADMIN_PASSWORD not in message
    assert "***" in message


def test_store_failure_removes_the_account_again() -> None:
    switch = FakeSwitch()
    with pytest.raises(SetupError) as excinfo:
        _setup(switch, Store(fail=True))
    assert "removed from the switch again" in str(excinfo.value)
    assert set(switch.users) == {"admin"}
    assert not switch.saved


def test_new_account_that_cannot_sign_in_is_removed_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    switch = FakeSwitch()
    monkeypatch.setattr("app.switch_setup._VERIFY_PAUSE_SECONDS", 0)
    original = switch._authenticate

    def refuse_new_account(request):
        user = original(request)
        return None if user == "nxray" else user

    switch._authenticate = refuse_new_account  # type: ignore[method-assign]
    store = Store()
    with pytest.raises(SetupError) as excinfo:
        _setup(switch, store)
    assert "removed from the switch again" in str(excinfo.value)
    assert set(switch.users) == {"admin"}
    assert store.calls == []


def test_undo_refused_by_a_live_session_says_the_account_is_still_there() -> None:
    # cisco-25gb refuses "no username" for an account that signed in in the
    # last 10 minutes, which the new account just did.
    switch = FakeSwitch(sessions_block_delete=True)
    with pytest.raises(SetupError) as excinfo:
        _setup(switch, Store(fail=True))
    message = str(excinfo.value)
    assert "nxray" in switch.users  # the switch kept it
    assert "removed from the switch again" not in message
    assert "still on the switch" in message
    assert "wait 10 minutes" in message
    assert "no username nxray" in message
    assert "different account name" in message
    assert switch.requests[-1] == ["no username nxray"]  # NXray did try
    assert not switch.saved


def test_undo_refused_keeps_both_passwords_out_of_the_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.switch_setup.generate_password", lambda: "Known1PasswordXy")
    switch = FakeSwitch(sessions_block_delete=True)
    with pytest.raises(SetupError) as excinfo:
        _setup(switch, Store(fail=True))
    assert "Known1PasswordXy" not in str(excinfo.value)
    assert ADMIN_PASSWORD not in str(excinfo.value)


def test_failed_save_still_connects_and_says_so() -> None:
    switch = FakeSwitch(save_text="Copy failed: not enough space\n")
    store = Store()
    result = _setup(switch, store)
    assert not result.config_saved
    assert "Copy failed" in (result.save_error or "")
    assert "nxray" in switch.users and store.calls


def test_rejected_save_still_connects_and_says_so() -> None:
    switch = FakeSwitch(reject={"copy running-config"})
    result = _setup(switch, Store())
    assert not result.config_saved
    assert result.save_error


def test_generated_passwords_are_long_varied_and_unique() -> None:
    passwords = {generate_password() for _ in range(200)}
    assert len(passwords) == 200
    for password in passwords:
        assert len(password) == PASSWORD_LENGTH
        assert password.isalnum()
        assert _strong_enough(password)


def test_strength_rule_matches_nx_os() -> None:
    assert _strong_enough("Ab1xQ9zLm")
    assert not _strong_enough("abcdefgh1")  # no upper case
    assert not _strong_enough("Abc9QzLm2")  # "abc" run
    assert not _strong_enough("Ax111zLm2")  # "111" repeat
    assert not _strong_enough("AbCdEfGhI")  # no digit


def test_account_names_reads_one_or_many_rows() -> None:
    one = {"TABLE_template": {"ROW_template": {"usr_name": "admin"}}}
    many = {"TABLE_template": {"ROW_template": [{"usr_name": "admin"}, {"usr_name": "Ops"}]}}
    assert account_names(one) == {"admin"}
    assert account_names(many) == {"admin", "ops"}
    assert account_names({}) == set()


def _target(password: str) -> SwitchTarget:
    return SwitchTarget(host="192.0.2.10", port=443, username="nxray", password=password, timeout=5)


def test_check_connection_reads_the_switch_identity() -> None:
    switch = FakeSwitch()
    switch.users["nxray"] = ("Good1Password", "network-operator")
    status = check_connection(_target("Good1Password"), transport=switch.transport())
    assert status.ok
    assert status.system is not None and status.system.hostname == "nexus-lab"
    assert status.message == "Connected to nexus-lab as nxray."


def test_check_connection_reports_a_refused_login_with_the_fix() -> None:
    switch = FakeSwitch()
    status = check_connection(_target("Gone1Password"), transport=switch.transport())
    assert not status.ok
    assert "refused the NXray account (nxray)" in status.message
    assert "set it up again" in status.message
    assert "Gone1Password" not in status.message


def test_check_connection_reports_an_unreachable_switch() -> None:
    status = check_connection(_target("x"), transport=FakeSwitch(reachable=False).transport())
    assert not status.ok
    assert "could not reach the switch" in status.message


def test_load_dashboard_status_reads_everything() -> None:
    switch = FakeSwitch()
    switch.users["nxray"] = ("Good1Password", "network-operator")
    status, data = load_dashboard_status(_target("Good1Password"), transport=switch.transport())
    assert status.ok and status.message == "Connected to nexus-lab as nxray."
    assert data is not None
    assert data.environment.total_draw_w == 126
    assert data.ports.total == 54


def test_load_dashboard_status_reports_a_failure_without_data() -> None:
    status, data = load_dashboard_status(
        _target("Gone1Password"), transport=FakeSwitch().transport()
    )
    assert not status.ok and data is None
    assert "refused the NXray account (nxray)" in status.message
    assert "Gone1Password" not in status.message
