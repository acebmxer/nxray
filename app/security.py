"""Authentication: password hashing, sessions, and login throttling.

Sessions are stored server-side in SQLite and referenced by a signed cookie.
The signature stops a client forging a session id; the database row is what
makes logout really invalidate a session rather than merely asking the
browser to forget it.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Request
from itsdangerous import BadSignature, URLSafeSerializer

from app.db import open_db

SESSION_COOKIE = "nxray_session"

# argon2-cffi's defaults are the RFC 9106 low-memory profile, which suits a
# cost paid once per interactive login.
_hasher = PasswordHasher()

# Checked against when there is no such account (app/users.py authenticate),
# so a wrong username and a wrong password cost the same time and cannot be
# told apart from outside.
DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(plain: str) -> str:
    """Return an Argon2id hash for storage."""
    return _hasher.hash(plain)


def verify_password(plain: str, stored_hash: str) -> bool:
    """Check a password against its hash; False on any mismatch or bad hash."""
    try:
        return _hasher.verify(stored_hash, plain)
    except (VerifyMismatchError, VerificationError, InvalidHashError, ValueError):
        return False


def _serializer(secret_key: str) -> URLSafeSerializer:
    return URLSafeSerializer(secret_key, salt="nxray-session")


def sign_session_id(session_id: str, secret_key: str) -> str:
    """Wrap a session id in a signed cookie value."""
    return _serializer(secret_key).dumps(session_id)


def unsign_session_id(cookie_value: str, secret_key: str) -> str | None:
    """Recover a session id from a cookie value; None if the signature fails."""
    try:
        value = _serializer(secret_key).loads(cookie_value)
    except BadSignature:
        return None
    return value if isinstance(value, str) else None


def create_session(conn: sqlite3.Connection, username: str, session_hours: int) -> str:
    """Record a new session and return its id."""
    session_id = secrets.token_urlsafe(32)
    now = time.time()
    conn.execute(
        "INSERT INTO sessions (id, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (session_id, username, now, now + session_hours * 3600),
    )
    conn.commit()
    return session_id


def get_session_user(conn: sqlite3.Connection, session_id: str) -> str | None:
    """Return the username of a live session.

    None, and the session ended, when it expired or its account no longer
    exists or is disabled: disabling an account signs it out on its next
    click, not when its session runs out hours later.
    """
    row = conn.execute(
        "SELECT username, expires_at FROM sessions WHERE id = ?", (session_id,)
    ).fetchone()
    if row is None:
        return None
    if row["expires_at"] < time.time():
        destroy_session(conn, session_id)
        return None
    account = conn.execute(
        "SELECT username, disabled FROM users WHERE username = ?", (row["username"],)
    ).fetchone()
    if account is None or account["disabled"]:
        destroy_session(conn, session_id)
        return None
    return account["username"]


def touch_session(conn: sqlite3.Connection, session_id: str, session_hours: int) -> None:
    """Extend a session's expiry: the sliding window on continued use."""
    conn.execute(
        "UPDATE sessions SET expires_at = ? WHERE id = ?",
        (time.time() + session_hours * 3600, session_id),
    )
    conn.commit()


def destroy_session(conn: sqlite3.Connection, session_id: str) -> None:
    """Delete a session so its cookie stops working immediately."""
    conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
    conn.commit()


def destroy_user_sessions(
    conn: sqlite3.Connection, username: str, *, keep: str | None = None
) -> int:
    """Sign an account out everywhere, except the session ``keep``.

    Used when its password changes or it is disabled. Returns how many
    sessions ended.
    """
    cursor = conn.execute(
        "DELETE FROM sessions WHERE username = ? COLLATE NOCASE AND id != ?",
        (username, keep or ""),
    )
    conn.commit()
    return cursor.rowcount


def purge_expired_sessions(conn: sqlite3.Connection) -> int:
    """Delete every expired session. Returns how many were removed."""
    cursor = conn.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
    conn.commit()
    return cursor.rowcount


def client_ip(request: Request) -> str:
    """The address login throttling is counted against.

    The direct peer address only. X-Forwarded-For is deliberately ignored:
    anyone can send that header, and honouring it would let a caller pick a
    fresh address for every guess. Support for a trusted reverse proxy is a
    planned setting, not a default.
    """
    return request.client.host if request.client else "unknown"


def record_login_failure(conn: sqlite3.Connection, ip: str) -> None:
    """Record a failed login for rate-limiting purposes."""
    conn.execute("INSERT INTO login_attempts (ip, attempted_at) VALUES (?, ?)", (ip, time.time()))
    conn.commit()


def clear_login_failures(conn: sqlite3.Connection, ip: str) -> None:
    """Forget an address's failures after it succeeds."""
    conn.execute("DELETE FROM login_attempts WHERE ip = ?", (ip,))
    conn.commit()


def is_rate_limited(
    conn: sqlite3.Connection, ip: str, max_attempts: int, window_minutes: int
) -> bool:
    """True when an address has failed too often to be allowed another try."""
    cutoff = time.time() - window_minutes * 60
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND attempted_at > ?",
        (ip, cutoff),
    ).fetchone()
    return int(row["n"]) >= max_attempts


def purge_old_login_attempts(conn: sqlite3.Connection, window_minutes: int) -> int:
    """Drop login attempts older than the window. Returns how many were removed."""
    cutoff = time.time() - window_minutes * 60
    cursor = conn.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (cutoff,))
    conn.commit()
    return cursor.rowcount


def session_id_from_request(request: Request) -> str | None:
    """The session id in the request's signed cookie, or None."""
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie:
        return None
    return unsign_session_id(cookie, request.app.state.settings.secret_key)


def csrf_token(request: Request) -> str:
    """The anti-forgery token forms on this session must send back.

    Derived from the session id with the secret key, so it needs no storage,
    changes with every login, and cannot be computed by another site.
    """
    session_id = session_id_from_request(request) or ""
    key = request.app.state.settings.secret_key.encode()
    return hmac.new(key, f"csrf:{session_id}".encode(), hashlib.sha256).hexdigest()


def csrf_valid(request: Request, token: str) -> bool:
    """True when a submitted form carries this session's token."""
    if session_id_from_request(request) is None or not token:
        return False
    return hmac.compare_digest(token, csrf_token(request))


def current_user(request: Request) -> str | None:
    """Return the logged-in username for a request, or None.

    Reads the signed cookie, resolves it against the sessions table (which
    also checks the account still exists and is not disabled), and slides the
    expiry forward.
    """
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie:
        return None

    settings = request.app.state.settings
    session_id = unsign_session_id(cookie, settings.secret_key)
    if session_id is None:
        return None

    with open_db(settings.db_path) as conn:
        username = get_session_user(conn, session_id)
        if username is None:
            return None
        touch_session(conn, session_id, settings.session_hours)
    return username
