"""Run setup again: repair NXray's existing account on the switch.

For when NXray's login stopped working: the account's password was changed
or the account was removed on the switch, or NXray can no longer read its
stored copy (a changed secret key). Signs in to NX-API once with the admin
login, gives the account a new random password (or makes it again under the
same name if it is gone), checks it signs in, hands the login to the caller
to store, and saves the switch configuration. The admin login is used only
inside ``run_repair`` and never stored.

The account keeps its name and its permissions. On cisco-25gb (NX-OS
9.3(16)) ``username <name> password <pw> role network-operator`` for an
existing account changes the password and keeps every role the account
already has, and the new password works at once even while the account
has a live NX-API session (the old one is refused from then on). An account
made again gets the port-changes role before it first signs in, so the
switch applies it at once; only an existing account that lost the role
makes NXray wait for its NX-API session to end (see app/port_changes.py).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from app.nxapi import NxapiClient, NxapiError, SwitchTarget, validate_account_name
from app.port_changes import ROLE_NAME, account_roles, pause_seconds
from app.switch import parse_version, rows
from app.switch_connection import SWITCH_TIMEOUT
from app.switch_setup import (
    ACCOUNT_ROLE,
    SetupError,
    account_names,
    describe_error,
    generate_password,
    verify_account,
)

log = logging.getLogger("nxray.repair")

# What happened to the port-changes role (only looked at when port changes
# were on): already on the account, given back, or gone from the switch.
ROLE_KEPT = "kept"
ROLE_GIVEN = "given"
ROLE_MISSING = "missing"


@dataclass(frozen=True)
class RepairResult:
    switch_hostname: str
    # True when the account was no longer on the switch and was made again.
    recreated: bool
    # ROLE_KEPT, ROLE_GIVEN, ROLE_MISSING, or None when port changes were off.
    port_role: str | None
    pause_seconds: int
    config_saved: bool
    save_error: str | None


def role_names(role_body: dict) -> set[str]:
    """Every role name in ``show role``."""
    return {
        str(row.get("role_name", ""))
        for row in rows(role_body, "TABLE_role", "ROW_role")
        if row.get("role_name")
    }


def _scrub(text: str, *secrets_to_hide: str) -> str:
    for value in secrets_to_hide:
        if value:
            text = text.replace(value, "***")
    return text


def run_repair(
    *,
    host: str,
    port: int,
    admin_user: str,
    admin_password: str,
    account_name: str,
    port_changes: bool,
    store: Callable[[str, str], None],
    transport: httpx.BaseTransport | None = None,
) -> RepairResult:
    """Give NXray's account a new password (or make it again) and store it.

    ``port_changes`` says whether the account had the port-changes role;
    it gets it back when the switch still has the role. Raises SetupError
    with a message for the page when anything stops the repair.
    """
    try:
        validate_account_name(account_name)
    except ValueError as exc:
        raise SetupError(str(exc)) from exc

    admin = SwitchTarget(
        host=host,
        port=port,
        username=admin_user,
        password=admin_password,
        timeout=SWITCH_TIMEOUT,
    )
    with NxapiClient(admin, transport=transport) as client:
        try:
            version, users, roles_body, nxapi = client.show(
                "show version", "show user-account", "show role", "show nxapi"
            )
        except NxapiError as exc:
            raise SetupError(
                _scrub(describe_error(exc, host, port, "admin"), admin_password)
            ) from exc
        hostname = parse_version(version).hostname
        existed = account_name.lower() in account_names(users)
        had_role = ROLE_NAME in account_roles(users, account_name)

        password = generate_password()
        try:
            # For an existing account this changes the password and keeps its roles.
            client.create_user(account_name, password, ACCOUNT_ROLE)
        except NxapiError as exc:
            message = _scrub(str(exc), password, admin_password)
            raise SetupError(f"The switch did not change the account: {message}") from exc
        log.info(
            "%s switch account %s on %s (%s)",
            "gave a new password to" if existed else "made again",
            account_name,
            host,
            hostname,
        )

        port_role: str | None = None
        wait = 0
        if port_changes:
            if had_role:
                port_role = ROLE_KEPT
            elif ROLE_NAME in role_names(roles_body):
                try:
                    client.give_role(account_name, ROLE_NAME)
                except NxapiError as exc:
                    raise SetupError(
                        _scrub(
                            f"NXray gave {account_name} a new password but could not give it "
                            f"the {ROLE_NAME} role again: {exc}. Press Run setup again to "
                            "retry.",
                            password,
                            admin_password,
                        )
                    ) from exc
                port_role = ROLE_GIVEN
                # A fresh account gets the role before its first sign-in; an
                # existing one may still have a session holding its old roles.
                wait = pause_seconds(nxapi) if existed else 0
            else:
                port_role = ROLE_MISSING

        try:
            verify_account(host, port, account_name, password, transport)
            store(password, hostname)
        except Exception as exc:
            if isinstance(exc, NxapiError):
                detail = describe_error(exc, host, port, f"repaired {account_name}")
            else:
                detail = f"NXray could not store the login: {exc}"
            raise SetupError(
                _scrub(
                    detail + f" The account {account_name} now has a password NXray does not "
                    "keep. Press Run setup again to give it another one.",
                    password,
                    admin_password,
                )
            ) from exc

        try:
            client.save_config()
        except NxapiError as exc:
            log.warning("switch config not saved after repairing %s: %s", account_name, exc)
            return RepairResult(
                hostname,
                not existed,
                port_role,
                wait,
                False,
                _scrub(str(exc), password, admin_password),
            )

    log.info("saved the switch configuration on %s", host)
    return RepairResult(hostname, not existed, port_role, wait, True, None)
