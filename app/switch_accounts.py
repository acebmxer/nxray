"""Switch accounts for NXray users: the same person on the switch's command line.

An NXray user exists only in NXray unless an admin also gives them a local
account on a switch, with the same name and password, so they can sign in
over SSH or the console too. Every change to such an account is made with
the switch admin login typed on the form, used for that one request and
never stored or logged: NXray's own account cannot make accounts, and is not
given that power. The commands come from ``NxapiClient.create_person_account``,
``set_person_password``, ``set_person_roles`` and ``remove_person_account``,
which build each one from checked values.

NXray keeps no switch password, only an Argon2 hash of the NXray one, so a
switch password is set while the plain password is in hand: when the account
is made, and when an admin sets a new password for both sides. Someone who
changes their own password on the Account page changes NXray's only; the
switch account is then out of step until an admin sets a new one for both.

The role on the switch follows the NXray role (``switch_roles``):

- viewer   -> ``network-operator`` (look only)
- operator -> ``network-operator`` plus ``nxray-ports``, the role NXray's own
              account gets when changes are on, so the person may change over
              SSH exactly what NXray may; ``network-operator`` only on a switch
              where changes are off
- admin    -> ``network-admin``

Only these roles are ever added or taken off; any other role an account has
is left as it is.

NX-OS has no switch to turn a local account off, so locking one (when its
NXray user is disabled) gives it a random password nobody knows. A reboot
puts back the saved configuration, which would undo a lock, a new account or
a new password that was not saved, so every change here saves the switch
configuration straight away, as setup does.

NXray's own account on a switch, and the names the switch keeps for itself
(its ``admin`` account among them), are never offered for linking, changing
or removing (``guard_account``).
"""

from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from app.nxapi import (
    PERSON_ROLES,
    PORT_CHANGES_ROLE,
    RESERVED_ACCOUNT_NAMES,
    NxapiClient,
    NxapiError,
    SwitchTarget,
    check_switch_password,
    validate_account_name,
)
from app.switch import rows
from app.switch_connection import SWITCH_TIMEOUT, SwitchConnection
from app.switch_setup import (
    describe_error,
    generate_password,
    password_strong_enough,
    scrub_secrets,
)
from app.users import User

log = logging.getLogger("nxray.switch_accounts")

# What each NXray role is on the switch, in words, for the Users page.
ROLE_MAP_WORDS = {
    "viewer": "network-operator (look only)",
    "operator": f"network-operator + {PORT_CHANGES_ROLE} (what NXray may change)",
    "admin": "network-admin (everything)",
}


class SwitchAccountError(Exception):
    """A switch account change did not happen; the message says why, with no secret."""


def switch_roles(role: str, changes_on: bool) -> tuple[str, ...]:
    """The roles a switch account gets for an NXray role. An operator gets
    ``nxray-ports`` only where changes are on, since only then does the switch
    have that role."""
    if role == "admin":
        return ("network-admin",)
    if role == "operator" and changes_on:
        return ("network-operator", PORT_CHANGES_ROLE)
    return ("network-operator",)


def reserved(name: str) -> bool:
    """True for a name NX-OS keeps for itself, or the switch's own admin account:
    NXray never makes, links, changes or removes those."""
    return name.lower() in RESERVED_ACCOUNT_NAMES


def check_switch_name(name: str) -> str:
    """The NXray username as a switch account name, or ValueError naming the switch's rule."""
    if reserved(name):
        raise ValueError(
            f"{name} is a name the switch keeps for itself (or its own admin account), so "
            "NXray does not make or change it there"
        )
    try:
        return validate_account_name(name)
    except ValueError:
        raise ValueError(
            f"the switch takes account names of 1 to 28 letters, digits, dots, dashes or "
            f"underscores, starting with a letter, so {name!r} cannot be made there"
        ) from None


def check_switch_side_password(password: str) -> None:
    """Raise ValueError when the switch would refuse the password, saying it is the
    switch's rule: letters and digits only (NXray's own rule), and its strength
    check (upper case, lower case, digits, no runs like "aaa" or "abc")."""
    check_switch_password(password)
    if not password_strong_enough(password):
        raise ValueError(
            "the switch's password check would refuse it: it needs upper case, lower case "
            'and digits, and no three alike or in a row such as "aaa", "abc" or "321"'
        )


def guard_account(name: str, connection: SwitchConnection) -> None:
    """Raise ValueError for NXray's own account on the switch, and for the names
    the switch keeps for itself (its admin account among them): no one links,
    changes or removes those here."""
    if name.lower() == connection.username.lower():
        raise ValueError(
            f"{name} is NXray's own account on {connection.label}; NXray never links, "
            "changes or removes it"
        )
    if reserved(name):
        raise ValueError(
            f"{name} is a name the switch keeps for itself (or its own admin account); "
            "NXray never links, changes or removes it"
        )


@dataclass(frozen=True)
class SwitchAccount:
    """A local account on the switch, from ``show user-account``."""

    name: str
    roles: tuple[str, ...]


def parse_user_accounts(body: dict) -> list[SwitchAccount]:
    """Every local account and its roles, from ``show user-account``, by name."""
    found: list[SwitchAccount] = []
    for row in rows(body, "TABLE_template", "ROW_template"):
        name = str(row.get("usr_name", "")).strip()
        if not name:
            continue
        roles = tuple(
            str(item.get("role", "")).strip()
            for item in rows(row, "TABLE_role", "ROW_role")
            if str(item.get("role", "")).strip()
        )
        found.append(SwitchAccount(name, roles))
    return sorted(found, key=lambda account: account.name.lower())


def load_switch_accounts(client: NxapiClient) -> list[SwitchAccount]:
    """The switch's local accounts, read with whatever login ``client`` has."""
    (body,) = client.show("show user-account")
    return parse_user_accounts(body)


# ---- which switch account belongs to which NXray user -----------------------


@dataclass(frozen=True)
class AccountLink:
    """An NXray user's account on one switch, as NXray last left it."""

    user_id: int
    switch_id: int
    account_name: str
    roles: tuple[str, ...]  # the roles NXray last gave it (or read, when linked)
    password_set_at: float | None  # None: NXray never set its password
    locked: bool
    linked_at: float


def _link(row: sqlite3.Row) -> AccountLink:
    return AccountLink(
        user_id=int(row["user_id"]),
        switch_id=int(row["switch_id"]),
        account_name=row["account_name"],
        roles=tuple(row["roles"].split()),
        password_set_at=row["password_set_at"],
        locked=bool(row["locked"]),
        linked_at=float(row["linked_at"]),
    )


def list_links(conn: sqlite3.Connection, *, user_id: int | None = None) -> list[AccountLink]:
    """Every link (or one user's), by switch."""
    if user_id is None:
        found = conn.execute("SELECT * FROM switch_accounts ORDER BY switch_id, user_id")
    else:
        found = conn.execute(
            "SELECT * FROM switch_accounts WHERE user_id = ? ORDER BY switch_id", (user_id,)
        )
    return [_link(row) for row in found.fetchall()]


def get_link(conn: sqlite3.Connection, user_id: int, switch_id: int) -> AccountLink | None:
    row = conn.execute(
        "SELECT * FROM switch_accounts WHERE user_id = ? AND switch_id = ?", (user_id, switch_id)
    ).fetchone()
    return _link(row) if row is not None else None


def save_link(
    conn: sqlite3.Connection,
    user_id: int,
    switch_id: int,
    account_name: str,
    roles: tuple[str, ...],
    *,
    password_set: bool,
) -> None:
    """Record that ``account_name`` on the switch belongs to the user.

    ``password_set`` is True when NXray just set its password (so it is in step
    with NXray's), False when an existing account was linked as it was.
    Raises ValueError when another NXray user already has that account.
    """
    taken = conn.execute(
        "SELECT user_id FROM switch_accounts WHERE switch_id = ? AND account_name = ? "
        "AND user_id != ?",
        (switch_id, account_name, user_id),
    ).fetchone()
    if taken is not None:
        raise ValueError(f"{account_name} on this switch already belongs to another NXray user")
    conn.execute(
        "INSERT OR REPLACE INTO switch_accounts "
        "(user_id, switch_id, account_name, roles, password_set_at, locked, linked_at) "
        "VALUES (?, ?, ?, ?, ?, 0, ?)",
        (
            user_id,
            switch_id,
            account_name,
            " ".join(roles),
            time.time() if password_set else None,
            time.time(),
        ),
    )
    conn.commit()


def update_link(
    conn: sqlite3.Connection,
    user_id: int,
    switch_id: int,
    *,
    roles: tuple[str, ...] | None = None,
    password_set: bool = False,
    locked: bool | None = None,
) -> None:
    """Note what NXray just changed on a linked account."""
    if roles is not None:
        conn.execute(
            "UPDATE switch_accounts SET roles = ? WHERE user_id = ? AND switch_id = ?",
            (" ".join(roles), user_id, switch_id),
        )
    if password_set:
        conn.execute(
            "UPDATE switch_accounts SET password_set_at = ? WHERE user_id = ? AND switch_id = ?",
            (time.time(), user_id, switch_id),
        )
    if locked is not None:
        conn.execute(
            "UPDATE switch_accounts SET locked = ? WHERE user_id = ? AND switch_id = ?",
            (int(locked), user_id, switch_id),
        )
    conn.commit()


def remove_link(conn: sqlite3.Connection, user_id: int, switch_id: int) -> None:
    """Forget the link; the account on the switch is not touched."""
    conn.execute(
        "DELETE FROM switch_accounts WHERE user_id = ? AND switch_id = ?", (user_id, switch_id)
    )
    conn.commit()


def out_of_step(user: User, link: AccountLink, connection: SwitchConnection) -> list[str]:
    """What differs between the NXray user and its switch account, in words; [] when in step."""
    found: list[str] = []
    expected = switch_roles(user.role, connection.changes_enabled)
    if set(expected) != {role for role in link.roles if role in PERSON_ROLES}:
        found.append(
            f"role: the switch account has {' + '.join(link.roles) or 'none'}, "
            f"an NXray {user.role} has {' + '.join(expected)}"
        )
    if user.disabled and not link.locked:
        found.append("the NXray user is disabled, but the switch account can still sign in")
    elif link.locked and not user.disabled:
        found.append("the switch account is locked; set a new password to open it")
    elif not link.locked:
        if link.password_set_at is None:
            found.append("password: NXray never set it, so it may differ from the NXray one")
        elif (user.password_changed_at or 0) > link.password_set_at:
            found.append("password: the NXray password changed since NXray last set this one")
    return found


# ---- changes made with the switch admin login --------------------------------


@dataclass(frozen=True)
class AccountChange:
    """What one switch did with a change: saved, or why the save failed."""

    saved: bool
    save_error: str = ""


def run_as_admin(
    connection: SwitchConnection,
    admin_user: str,
    admin_password: str,
    change: Callable[[NxapiClient], None],
    *,
    secrets: tuple[str, ...] = (),
    transport: httpx.BaseTransport | None = None,
) -> AccountChange:
    """Sign in with the admin login typed on the form, make the change, save.

    The admin login is used for this one request and never stored or logged.
    Raises SwitchAccountError, with the admin password and ``secrets`` (a new
    password) scrubbed out, when the change did not happen. A failed save is
    returned, not raised: the change is made but a reboot would undo it.
    """
    if not admin_user.strip() or not admin_password:
        raise SwitchAccountError("Type the switch admin username and password.")
    target = SwitchTarget(
        host=connection.host,
        port=connection.port,
        username=admin_user.strip(),
        password=admin_password,
        timeout=SWITCH_TIMEOUT,
    )
    hide = (admin_password, *secrets)
    try:
        with NxapiClient(target, transport=transport) as client:
            try:
                change(client)
            except ValueError as exc:
                raise SwitchAccountError(scrub_secrets(str(exc), *hide)) from None
            try:
                client.save_config()
            except NxapiError as exc:
                log.warning("switch config not saved on %s after an account change", target.host)
                return AccountChange(False, scrub_secrets(str(exc), *hide))
    except NxapiError as exc:
        message = describe_error(exc, target.host, target.port, "admin")
        raise SwitchAccountError(scrub_secrets(message, *hide)) from None
    return AccountChange(True)


def create_on_switch(client: NxapiClient, name: str, password: str, roles: tuple[str, ...]) -> None:
    """Make the account, unless the switch already has one by that name (then it
    is to be linked instead, so it is never overwritten)."""
    existing = {account.name.lower() for account in load_switch_accounts(client)}
    if name.lower() in existing:
        raise ValueError(
            f"the switch already has an account called {name}; link it to the NXray user "
            "instead of making a second one"
        )
    client.create_person_account(name, password, roles)


def remove_from_switch(client: NxapiClient, name: str) -> None:
    """Remove the account, unless the switch has none by that name (then there
    is nothing to remove, and a silent success would hide a typo)."""
    existing = {account.name for account in load_switch_accounts(client)}
    if name not in existing:
        raise ValueError(f"the switch has no account called {name} any more")
    client.remove_person_account(name)


def bring_roles_in_step(client: NxapiClient, name: str, wanted: tuple[str, ...]) -> tuple[str, ...]:
    """Add the wanted roles the account lacks and take off the other roles NXray
    gives people; other roles stay. Returns the account's roles afterwards."""
    current = next(
        (account for account in load_switch_accounts(client) if account.name == name), None
    )
    if current is None:
        raise ValueError(f"the switch has no account called {name} any more")
    add = [role for role in wanted if role not in current.roles]
    remove = [role for role in current.roles if role in PERSON_ROLES and role not in wanted]
    if add or remove:
        client.set_person_roles(name, add=add, remove=remove)
    return tuple(role for role in (*current.roles, *add) if role not in remove)


def lock_password() -> str:
    """A random password nobody sees, which locks a switch account."""
    return generate_password()


def save_words(change: AccountChange, connection: SwitchConnection) -> str:
    """What the page says about saving the switch configuration after a change."""
    if change.saved:
        return f"The configuration of {connection.label} was saved, so it survives a restart."
    return (
        f"The configuration of {connection.label} was NOT saved ({change.save_error}): a "
        "restart of the switch undoes this change until you press Save config there."
    )
