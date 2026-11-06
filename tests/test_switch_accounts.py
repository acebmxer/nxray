"""Switch accounts for NXray users (app/switch_accounts.py), without a switch."""

from __future__ import annotations

from dataclasses import replace

import pytest

from app.switch_accounts import (
    AccountLink,
    check_switch_name,
    check_switch_side_password,
    guard_account,
    out_of_step,
    parse_user_accounts,
    reserved,
    switch_roles,
)
from app.switch_connection import SwitchConnection
from app.users import User

CONNECTION = SwitchConnection(
    id=1,
    host="192.0.2.10",
    port=443,
    username="nxray",
    switch_hostname="lab-sw1",
    created_at=0.0,
    config_saved=True,
    last_tested_at=None,
    last_test_ok=None,
    last_test_message=None,
    changes_enabled_at=1.0,
)
USER = User(
    id=7,
    username="otto",
    password_hash="",
    role="viewer",
    disabled=False,
    created_at=0.0,
    password_changed_at=100.0,
)
LINK = AccountLink(7, 1, "otto", ("network-operator",), 200.0, False, 200.0)


@pytest.mark.parametrize(
    ("role", "changes_on", "roles"),
    [
        ("viewer", True, ("network-operator",)),
        ("operator", True, ("network-operator", "nxray-ports")),
        ("operator", False, ("network-operator",)),
        ("admin", False, ("network-admin",)),
    ],
)
def test_switch_roles(role: str, changes_on: bool, roles: tuple[str, ...]) -> None:
    assert switch_roles(role, changes_on) == roles


def test_names_the_switch_takes() -> None:
    assert check_switch_name("otto.lab") == "otto.lab"
    for name in ("otto@lab", "1otto", "x" * 29, "a b"):
        with pytest.raises(ValueError, match="the switch takes account names"):
            check_switch_name(name)
    with pytest.raises(ValueError, match="keeps for itself"):
        check_switch_name("Admin")
    assert reserved("root") and not reserved("otto")


@pytest.mark.parametrize(
    ("password", "message"),
    [
        ("Kx7mQ2vL p9", "letters and digits"),
        ("Kx7mQ2vL!p9", "letters and digits"),
        ("short1A", "letters and digits"),
        ("kx7mq2vlp9", "password check"),
        ("Kx7mQ2vLaaa9", "password check"),
        ("Kx7mQ2vL321", "password check"),
    ],
)
def test_passwords_the_switch_would_refuse(password: str, message: str) -> None:
    with pytest.raises(ValueError, match=message) as caught:
        check_switch_side_password(password)
    assert password not in str(caught.value)


def test_nxrays_own_and_reserved_accounts_are_guarded() -> None:
    guard_account("otto", CONNECTION)
    for name in ("nxray", "NXRAY", "admin"):
        with pytest.raises(ValueError):
            guard_account(name, CONNECTION)


def test_in_step() -> None:
    assert out_of_step(USER, LINK, CONNECTION) == []


def test_out_of_step_reasons() -> None:
    admin = replace(USER, role="admin")
    assert "an NXray admin has network-admin" in out_of_step(admin, LINK, CONNECTION)[0]
    newer = replace(USER, password_changed_at=300.0)
    assert out_of_step(newer, LINK, CONNECTION) == [
        "password: the NXray password changed since NXray last set this one"
    ]
    never = replace(LINK, password_set_at=None)
    assert "NXray never set it" in out_of_step(USER, never, CONNECTION)[0]
    disabled = replace(USER, disabled=True)
    assert "can still sign in" in out_of_step(disabled, LINK, CONNECTION)[0]
    locked = replace(LINK, locked=True)
    assert out_of_step(disabled, locked, CONNECTION) == []
    assert "locked" in out_of_step(USER, locked, CONNECTION)[0]


def test_other_roles_do_not_count() -> None:
    link = replace(LINK, roles=("network-operator", "priv-5"))
    assert out_of_step(USER, link, CONNECTION) == []


def test_parse_user_accounts() -> None:
    body = {
        "TABLE_template": {
            "ROW_template": [
                {
                    "usr_name": "nxray",
                    "TABLE_role": {
                        "ROW_role": [{"role": "network-operator"}, {"role": "nxray-ports"}]
                    },
                },
                {"usr_name": "admin", "TABLE_role": {"ROW_role": {"role": "network-admin"}}},
                {"usr_name": ""},
            ]
        }
    }
    accounts = parse_user_accounts(body)
    assert [a.name for a in accounts] == ["admin", "nxray"]
    assert accounts[1].roles == ("network-operator", "nxray-ports")
