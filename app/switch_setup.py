"""Switch setup: create NXray's own account on the switch, and check it works.

Setup signs in to NX-API once with the switch's admin login, creates a
read-only account with a long random password nobody ever sees, checks that
account can sign in, hands its login to the caller to store, and saves the
switch configuration so the account survives a reboot. The admin login is
used only inside ``run_setup`` and never stored or logged.
"""

from __future__ import annotations

import logging
import secrets
import string
import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from app.nxapi import (
    NxapiAuthError,
    NxapiClient,
    NxapiCommandError,
    NxapiError,
    NxapiUnreachable,
    SwitchTarget,
    validate_account_name,
)
from app.switch import Dashboard, SystemInfo, load_dashboard, parse_version, rows
from app.switch_connection import SWITCH_TIMEOUT

log = logging.getLogger("nxray.setup")

# The role NXray's account gets: NX-OS's built-in read-only role.
ACCOUNT_ROLE = "network-operator"

PASSWORD_LENGTH = 32
_ALPHABET = string.ascii_letters + string.digits

# How often to retry the new account's first sign-in, in case the switch
# takes a moment to accept a freshly created user.
_VERIFY_ATTEMPTS = 3
_VERIFY_PAUSE_SECONDS = 1.0


# Shown when the stored password cannot be decrypted.
KEY_CHANGED_MESSAGE = (
    "NXray cannot read the stored switch login. This happens when NXRAY_SECRET_KEY "
    "(or the data volume's secret_key file) changed. Forget this switch on the Switch "
    "page and set it up again with a new account name."
)


class SetupError(Exception):
    """Setup stopped; the message says why and what to do, in plain words."""


@dataclass(frozen=True)
class SetupResult:
    switch_hostname: str
    config_saved: bool
    save_error: str | None


@dataclass(frozen=True)
class ConnectionStatus:
    """The answer to "can NXray reach the switch with its own account?"."""

    ok: bool
    message: str
    system: SystemInfo | None = None


def generate_password() -> str:
    """A random password NX-OS's password strength check accepts.

    Letters and digits only, so it is always safe inside a command line.
    NX-OS refuses passwords without upper case, lower case and digits, and
    ones with runs like "aaa" or "abc", so candidates with those are drawn
    again.
    """
    while True:
        candidate = "".join(secrets.choice(_ALPHABET) for _ in range(PASSWORD_LENGTH))
        if _strong_enough(candidate):
            return candidate


def _strong_enough(password: str) -> bool:
    if not (
        any(c.islower() for c in password)
        and any(c.isupper() for c in password)
        and any(c.isdigit() for c in password)
    ):
        return False
    lowered = password.lower()
    for a, b, c in zip(lowered, lowered[1:], lowered[2:], strict=False):
        if a == b == c:
            return False
        if ord(b) - ord(a) == ord(c) - ord(b) and abs(ord(b) - ord(a)) == 1:
            return False
    return True


def account_names(user_account_body: dict) -> set[str]:
    """Lower-cased names of every local account in ``show user-account``."""
    return {
        str(row.get("usr_name", "")).lower()
        for row in rows(user_account_body, "TABLE_template", "ROW_template")
        if row.get("usr_name")
    }


def _scrub(text: str, *secrets_to_hide: str) -> str:
    for value in secrets_to_hide:
        if value:
            text = text.replace(value, "***")
    return text


def describe_error(exc: NxapiError, host: str, port: int, who: str) -> str:
    """A plain-words message for an NX-API failure, naming the fix."""
    if isinstance(exc, NxapiUnreachable):
        return (
            f"NXray could not reach the switch at {host}, port {port}. Check the address, "
            "that this machine can reach it, and that NX-API is on (feature nxapi). "
            f"Details: {exc}"
        )
    if isinstance(exc, NxapiAuthError):
        return f"The switch refused the {who} username or password."
    if isinstance(exc, NxapiCommandError):
        return f"The switch refused a command: {exc}"
    return f"The switch gave an answer NXray did not understand: {exc}"


def run_setup(
    *,
    host: str,
    port: int,
    admin_user: str,
    admin_password: str,
    account_name: str,
    store: Callable[[str, str], None],
    transport: httpx.BaseTransport | None = None,
) -> SetupResult:
    """Create NXray's account and hand its login to ``store(password, hostname)``.

    Raises SetupError with a message for the page when anything stops the
    setup. An account created before a later step failed is removed again,
    so a retry with the same name is not blocked by a leftover.
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
            version, users = client.show("show version", "show user-account")
        except NxapiError as exc:
            raise SetupError(
                _scrub(describe_error(exc, host, port, "admin"), admin_password)
            ) from exc

        if account_name.lower() in account_names(users):
            raise SetupError(
                f"An account named {account_name} already exists on the switch, perhaps "
                "used by another NXray install. Pick a different name, for example "
                f"{account_name}-dev."
            )
        hostname = parse_version(version).hostname

        password = generate_password()
        try:
            client.create_user(account_name, password, ACCOUNT_ROLE)
        except NxapiError as exc:
            message = _scrub(str(exc), password, admin_password)
            raise SetupError(f"The switch did not create the account: {message}") from exc
        log.info("created switch account %s on %s (%s)", account_name, host, hostname)

        try:
            _verify_new_account(host, port, account_name, password, transport)
            store(password, hostname)
        except Exception as exc:
            _undo(client, account_name, host)
            if isinstance(exc, NxapiError):
                detail = describe_error(exc, host, port, f"new {account_name}")
            else:
                detail = f"NXray could not store the login: {exc}"
            raise SetupError(
                _scrub(f"{detail} The account was removed from the switch again.", password)
            ) from exc

        try:
            client.save_config()
        except NxapiError as exc:
            log.warning("switch config not saved after creating %s: %s", account_name, exc)
            return SetupResult(hostname, False, _scrub(str(exc), password, admin_password))

    log.info("saved the switch configuration on %s", host)
    return SetupResult(hostname, True, None)


def _verify_new_account(
    host: str,
    port: int,
    name: str,
    password: str,
    transport: httpx.BaseTransport | None,
) -> None:
    target = SwitchTarget(host=host, port=port, username=name, password=password, timeout=10)
    for attempt in range(1, _VERIFY_ATTEMPTS + 1):
        try:
            with NxapiClient(target, transport=transport) as client:
                client.show("show hostname")
            return
        except NxapiAuthError:
            if attempt == _VERIFY_ATTEMPTS:
                raise
            time.sleep(_VERIFY_PAUSE_SECONDS)


def _undo(client: NxapiClient, name: str, host: str) -> None:
    try:
        client.delete_user(name)
        log.info("removed switch account %s on %s after a failed setup", name, host)
    except NxapiError as exc:
        log.error("could not remove switch account %s on %s: %s", name, host, exc)


def connection_error(exc: NxapiError, target: SwitchTarget) -> str:
    """The message for a failed call made with NXray's own account."""
    message = describe_error(exc, target.host, target.port, f"NXray account ({target.username})")
    if isinstance(exc, NxapiAuthError):
        message += (
            " The account may have been removed or changed on the switch. Forget this "
            "switch on the Switch page and set it up again."
        )
    return _scrub(message, target.password)


def check_connection(
    target: SwitchTarget, transport: httpx.BaseTransport | None = None
) -> ConnectionStatus:
    """Sign in with NXray's own account and read the switch's identity."""
    try:
        with NxapiClient(target, transport=transport) as client:
            (version,) = client.show("show version")
    except NxapiError as exc:
        return ConnectionStatus(False, connection_error(exc, target))
    system = parse_version(version)
    return ConnectionStatus(True, f"Connected to {system.hostname} as {target.username}.", system)


def load_dashboard_status(
    target: SwitchTarget, transport: httpx.BaseTransport | None = None
) -> tuple[ConnectionStatus, Dashboard | None]:
    """Everything the dashboard shows, or why it could not be read."""
    try:
        with NxapiClient(target, transport=transport) as client:
            dashboard = load_dashboard(client)
    except NxapiError as exc:
        return ConnectionStatus(False, connection_error(exc, target)), None
    message = f"Connected to {dashboard.system.hostname} as {target.username}."
    return ConnectionStatus(True, message, dashboard.system), dashboard
