"""NXray's own sign-in accounts and their roles.

Before this module, the only account was the username and password hash in
nxray.env (``NXRAY_ADMIN_USER`` / ``NXRAY_ADMIN_PASSWORD_HASH``). Those still
work, but only as the seed for the first admin account (``bootstrap_admin``),
so an existing install keeps signing in unchanged after the upgrade. Once an
account exists, nxray.env is no longer read for sign-in.

Three roles, enforced by the users table's CHECK constraint and by the route
guards in app/dependencies.py:

- ``admin``    everything: the Switch page (setup, address, Run setup again,
               turning on changes, forgetting the switch) and the Users page,
               plus everything an operator can do.
- ``operator`` changes the switch through NXray's own account: ports on or
               off, descriptions, VLANs, Save config. Not the Switch page and
               not users.
- ``viewer``   looks only: dashboard, ports, VLANs. No button that changes
               anything.

Every account can change its own password on the Account page; only an admin
can reset someone else's.

Each account can also turn on two-factor sign-in for itself on the Account
page: after the password, sign-in asks for a six-digit code from an
authenticator app, or one of ten one-time backup codes. An admin can turn it
off for someone who lost their phone and their backup codes.

These are NXray sign-ins only. They are unrelated to the account NXray uses
on the switch (app/switch_setup.py).
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from dataclasses import dataclass

from app.crypto import DecryptionError, decrypt, encrypt
from app.security import DUMMY_HASH, destroy_user_sessions, hash_password, verify_password
from app.totp import generate_backup_codes, generate_secret, hash_backup_code, matching_step

ROLES = ("admin", "operator", "viewer")

# What each role may do, in words, for the Users page.
ROLE_HELP = {
    "admin": "everything, including the Switch page and users",
    "operator": "port and VLAN changes and Save config",
    "viewer": "look only",
}

MIN_PASSWORD_LENGTH = 8
# Long enough for any passphrase; stops a megabyte-sized form field reaching
# Argon2.
MAX_PASSWORD_LENGTH = 1024

# Letters, digits and . _ @ - ; starts with a letter or digit. Keeps names
# readable on the page and free of spaces that look alike.
_USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}")


class UserError(ValueError):
    """A user change was refused. The message is shown on the page."""


class AccountDisabled(Exception):
    """The password was right, but the account is disabled.

    Raised only for the correct password: a wrong password on a disabled
    account fails like any other wrong password, so only someone who already
    knows the password learns that the account exists and is disabled.
    """


@dataclass(frozen=True)
class User:
    id: int
    username: str
    password_hash: str
    role: str
    disabled: bool
    created_at: float
    # Two-factor sign-in; see the 5 -> 6 migration in app/db.py.
    totp_secret_encrypted: str | None = None
    totp_enabled: bool = False
    totp_last_step: int = 0
    totp_backup_codes: tuple[str, ...] = ()  # SHA-256 hashes, never the codes

    @property
    def backup_codes_left(self) -> int:
        return len(self.totp_backup_codes)

    @property
    def can_change(self) -> bool:
        """True for roles that may change the switch (operator and admin)."""
        return self.role in ("admin", "operator")

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def _row_to_user(row: sqlite3.Row) -> User:
    return User(
        id=int(row["id"]),
        username=row["username"],
        password_hash=row["password_hash"],
        role=row["role"],
        disabled=bool(row["disabled"]),
        created_at=float(row["created_at"]),
        totp_secret_encrypted=row["totp_secret_encrypted"],
        totp_enabled=bool(row["totp_enabled"]),
        totp_last_step=int(row["totp_last_step"]),
        totp_backup_codes=tuple(json.loads(row["totp_backup_codes"] or "[]")),
    )


def bootstrap_admin(conn: sqlite3.Connection, admin_user: str, admin_password_hash: str) -> bool:
    """Create the first admin from nxray.env when there are no accounts yet.

    Runs at every start but acts only once: as soon as any account exists,
    nxray.env is no longer consulted, so a stale hash there can never reset
    the admin's real password on a restart. Returns True when it created one.
    """
    row = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
    if int(row["n"]) > 0:
        return False
    conn.execute(
        "INSERT INTO users (username, password_hash, role, disabled, created_at) "
        "VALUES (?, ?, 'admin', 0, ?)",
        (admin_user, admin_password_hash, time.time()),
    )
    conn.commit()
    return True


def get_user(conn: sqlite3.Connection, username: str) -> User | None:
    """The account with this name (upper/lower case ignored), or None."""
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return _row_to_user(row) if row is not None else None


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> User | None:
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _row_to_user(row) if row is not None else None


def list_users(conn: sqlite3.Connection) -> list[User]:
    """Every account, oldest first."""
    rows = conn.execute("SELECT * FROM users ORDER BY created_at, id").fetchall()
    return [_row_to_user(row) for row in rows]


def check_new_password(password: str, confirm: str) -> None:
    """Raise UserError unless the password is usable and typed the same twice."""
    if password != confirm:
        raise UserError("The two passwords are not the same.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise UserError(f"The password needs at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise UserError(f"The password can have at most {MAX_PASSWORD_LENGTH} characters.")


def _check_role(role: str) -> None:
    if role not in ROLES:
        raise UserError(f"The role must be one of {', '.join(ROLES)}.")


def create_user(
    conn: sqlite3.Connection, username: str, password: str, confirm: str, role: str
) -> User:
    """Add an account. Raises UserError with the reason when it can't."""
    username = username.strip()
    if not _USERNAME.fullmatch(username):
        raise UserError(
            "A username is 1 to 64 letters, digits, dots, dashes, underscores or @, "
            "starting with a letter or digit."
        )
    _check_role(role)
    check_new_password(password, confirm)
    if get_user(conn, username) is not None:
        raise UserError(f"There is already an account called {username}.")
    cursor = conn.execute(
        "INSERT INTO users (username, password_hash, role, disabled, created_at) "
        "VALUES (?, ?, ?, 0, ?)",
        (username, hash_password(password), role, time.time()),
    )
    conn.commit()
    user = get_user_by_id(conn, int(cursor.lastrowid or 0))
    assert user is not None
    return user


def _active_admins_besides(conn: sqlite3.Connection, user_id: int) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?",
        (user_id,),
    ).fetchone()
    return int(row["n"])


def set_role(conn: sqlite3.Connection, user_id: int, role: str) -> User:
    """Give an account another role; the change applies to its next page."""
    _check_role(role)
    user = get_user_by_id(conn, user_id)
    if user is None:
        raise UserError("That account no longer exists.")
    if user.is_admin and not user.disabled and role != "admin":
        if _active_admins_besides(conn, user_id) == 0:
            raise UserError(
                f"{user.username} is the only admin left, so it stays admin. "
                "Make another account admin first."
            )
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    conn.commit()
    return get_user_by_id(conn, user_id) or user


def set_disabled(conn: sqlite3.Connection, user_id: int, disabled: bool) -> User:
    """Disable an account (it is signed out at once) or enable it again."""
    user = get_user_by_id(conn, user_id)
    if user is None:
        raise UserError("That account no longer exists.")
    if disabled and user.is_admin and not user.disabled:
        if _active_admins_besides(conn, user_id) == 0:
            raise UserError(
                f"{user.username} is the only admin left, so it cannot be disabled. "
                "Make another account admin first."
            )
    conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id))
    conn.commit()
    if disabled:
        destroy_user_sessions(conn, user.username)
    return get_user_by_id(conn, user_id) or user


def set_password(
    conn: sqlite3.Connection, user_id: int, password: str, *, keep_session: str | None = None
) -> None:
    """Store a new password and sign the account out everywhere.

    ``keep_session`` is the session that made the change, when someone
    changes their own password: that one stays signed in. Who may call this
    for which account is decided by the route, not here.
    """
    user = get_user_by_id(conn, user_id)
    if user is None:
        raise UserError("That account no longer exists.")
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), user_id)
    )
    conn.commit()
    destroy_user_sessions(conn, user.username, keep=keep_session)


def authenticate(conn: sqlite3.Connection, username: str, password: str) -> User | None:
    """The account if the password is right; None otherwise.

    The password is checked even when there is no such account (against a
    dummy hash), so a wrong name and a wrong password take the same time.
    Raises AccountDisabled for the right password on a disabled account.
    """
    user = get_user(conn, username.strip())
    password_ok = verify_password(password, user.password_hash if user else DUMMY_HASH)
    if user is None or not password_ok:
        return None
    if user.disabled:
        raise AccountDisabled()
    return user


# ---- two-factor sign-in ------------------------------------------------------------


def begin_two_factor(conn: sqlite3.Connection, user_id: int, secret_key: str) -> str:
    """Start two-factor setup: store a new key (encrypted) and return it.

    Two-factor stays off until ``confirm_two_factor`` sees a right code, so
    a setup left half done changes nothing at sign-in. Starting again
    replaces the unconfirmed key. Refused while two-factor is on: replacing
    a working key would leave the account's app making wrong codes.
    """
    user = get_user_by_id(conn, user_id)
    if user is None:
        raise UserError("That account no longer exists.")
    if user.totp_enabled:
        raise UserError("Two-factor sign-in is already on. Turn it off first to set it up again.")
    secret = generate_secret()
    conn.execute(
        "UPDATE users SET totp_secret_encrypted = ?, totp_last_step = 0, "
        "totp_backup_codes = '[]' WHERE id = ?",
        (encrypt(secret, secret_key), user_id),
    )
    conn.commit()
    return secret


def two_factor_secret(user: User, secret_key: str) -> str | None:
    """The account's key in plain text (to draw the setup page again), or None.

    None when there is no key, or it can't be read with this secret key.
    """
    if not user.totp_secret_encrypted:
        return None
    try:
        return decrypt(user.totp_secret_encrypted, secret_key)
    except DecryptionError:
        return None


def confirm_two_factor(
    conn: sqlite3.Connection,
    user_id: int,
    code: str,
    secret_key: str,
    *,
    keep_session: str | None = None,
) -> list[str] | None:
    """Turn two-factor on once a code from the new key is right.

    Returns the ten backup codes in plain text, to be shown once (only
    their hashes are kept), or None for a wrong code. The account is signed
    out everywhere except ``keep_session``: a session someone else already
    had should not outlive the account getting stronger protection.
    """
    user = get_user_by_id(conn, user_id)
    if user is None or user.totp_enabled:
        return None
    secret = two_factor_secret(user, secret_key)
    if secret is None:
        return None
    step = matching_step(secret, code)
    if step is None:
        return None
    codes = generate_backup_codes()
    conn.execute(
        "UPDATE users SET totp_enabled = 1, totp_last_step = ?, totp_backup_codes = ? "
        "WHERE id = ? AND totp_enabled = 0",
        (step, json.dumps([hash_backup_code(c) for c in codes]), user_id),
    )
    conn.commit()
    destroy_user_sessions(conn, user.username, keep=keep_session)
    return codes


def new_backup_codes(conn: sqlite3.Connection, user_id: int) -> list[str]:
    """Replace an account's backup codes with ten new ones; the old ones stop working.

    Returns them in plain text, to be shown once.
    """
    user = get_user_by_id(conn, user_id)
    if user is None or not user.totp_enabled:
        raise UserError("Two-factor sign-in is off for this account.")
    codes = generate_backup_codes()
    conn.execute(
        "UPDATE users SET totp_backup_codes = ? WHERE id = ?",
        (json.dumps([hash_backup_code(c) for c in codes]), user_id),
    )
    conn.commit()
    return codes


def turn_off_two_factor(conn: sqlite3.Connection, user_id: int) -> User:
    """Turn two-factor off and forget the key and the backup codes.

    Forgetting the key means turning it on again always starts from a new
    key and a new QR code. Who may do this for which account (yourself with
    your password, an admin for someone else) is decided by the route.
    """
    user = get_user_by_id(conn, user_id)
    if user is None:
        raise UserError("That account no longer exists.")
    conn.execute(
        "UPDATE users SET totp_enabled = 0, totp_secret_encrypted = NULL, "
        "totp_last_step = 0, totp_backup_codes = '[]' WHERE id = ?",
        (user_id,),
    )
    conn.commit()
    return get_user_by_id(conn, user_id) or user


def check_second_factor(
    conn: sqlite3.Connection, user: User, code: str, secret_key: str
) -> str | None:
    """Check a sign-in's second step: ``"app"``, ``"backup"`` or None for wrong.

    An app code is accepted once: its 30-second step is stored and that
    step or an earlier one is refused afterwards, so a code someone saw
    can't be used again. A backup code is removed when it is used. Both
    writes only succeed if the row still holds what was read, so two
    sign-ins sending the same code at the same moment can't both pass.
    A key that can't be read (the secret key changed) still lets backup
    codes in, since those are only hashes.
    """
    if not user.totp_enabled:
        return None
    secret = two_factor_secret(user, secret_key)
    if secret is not None:
        step = matching_step(secret, code)
        if step is not None and step > user.totp_last_step:
            cursor = conn.execute(
                "UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?",
                (step, user.id, step),
            )
            conn.commit()
            if cursor.rowcount == 1:
                return "app"
            return None

    hashed = hash_backup_code(code)
    if hashed not in user.totp_backup_codes:
        return None
    remaining = [c for c in user.totp_backup_codes if c != hashed]
    cursor = conn.execute(
        "UPDATE users SET totp_backup_codes = ? WHERE id = ? AND totp_backup_codes = ?",
        (json.dumps(remaining), user.id, json.dumps(list(user.totp_backup_codes))),
    )
    conn.commit()
    return "backup" if cursor.rowcount == 1 else None
