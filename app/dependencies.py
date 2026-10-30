"""Shared FastAPI dependencies, middleware and the template environment.

Kept separate from main.py so routers can import these without importing the
app, which would be a circular import.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path

from fastapi import Request, Response
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app import __version__
from app.db import open_db
from app.nxapi import SwitchTarget
from app.ports import human_bytes, human_rate
from app.security import csrf_valid, current_user
from app.switch_connection import DecryptionError, SwitchConnection, get_connection, load_target
from app.switch_setup import KEY_CHANGED_MESSAGE
from app.users import User, get_user

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
# Every template shows the version in the footer; injecting it globally avoids
# each route having to remember to pass it.
templates.env.globals["app_version"] = __version__
templates.env.filters["bytes"] = human_bytes
templates.env.filters["rate"] = human_rate

# Sent on every response. The pages use no inline script, no inline style and
# nothing from another site, so the policy can be strict. frame-ancestors and
# X-Frame-Options stop another site from framing NXray and tricking a
# logged-in user into clicking buttons that change the switch.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
        "form-action 'self'; base-uri 'none'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
}


async def add_security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """HTTP middleware: add SECURITY_HEADERS to every response."""
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


class RedirectToLogin(Exception):
    """Raised by login_required; turned into a 303 by the exception handler.

    A dependency cannot return a response, so it signals with an exception and
    main.py registers the handler that renders it.
    """

    def __init__(self, next_url: str) -> None:
        self.next_url = next_url
        super().__init__(f"login required for {next_url}")


class CsrfFailed(Exception):
    """A form arrived without this session's anti-forgery token.

    main.py turns it into a 403 page. Raised by require_csrf.
    """


def require_csrf(request: Request, token: str) -> None:
    """Refuse a state-changing form that did not come from NXray's own page.

    Every POST that changes something (the switch, the stored connection)
    calls this first, before reading anything else from the form.
    """
    if not csrf_valid(request, token):
        raise CsrfFailed()


def login_required(request: Request) -> str:
    """Return the logged-in username, or send an anonymous caller to /login."""
    username = current_user(request)
    if username is None:
        raise RedirectToLogin(request.url.path)
    return username


class Forbidden(Exception):
    """A signed-in account's role may not do this; main.py renders a 403 page.

    Not a redirect to /login like RedirectToLogin: the caller is signed in,
    just not allowed.
    """

    def __init__(self, required_role: str) -> None:
        self.required_role = required_role
        super().__init__(f"requires the {required_role} role")


def current_account(request: Request) -> User | None:
    """The signed-in account, or None. Looked up once per request."""
    if getattr(request.state, "account_looked_up", False):
        return request.state.account
    account = None
    username = current_user(request)
    if username is not None:
        with open_db(request.app.state.settings.db_path) as conn:
            account = get_user(conn, username)
    request.state.account = account
    request.state.account_looked_up = True
    return account


def operator_required(request: Request) -> str:
    """The username, for routes that change the switch: operator or admin."""
    username = login_required(request)
    account = current_account(request)
    if account is None or not account.can_change:
        raise Forbidden("operator")
    return username


def admin_required(request: Request) -> str:
    """The username, for the Switch page and user management: admin only."""
    username = login_required(request)
    account = current_account(request)
    if account is None or not account.is_admin:
        raise Forbidden("admin")
    return username


def current_role(request: Request) -> str | None:
    """The signed-in account's role, for templates deciding which buttons to show.

    A button that answers "not permitted" when pressed is worse than no
    button, so pages hide what the role can't do. The route guards above
    still refuse it if someone sends the form anyway.
    """
    account = current_account(request)
    return account.role if account is not None else None


templates.env.globals["current_role"] = current_role


def paused_message(seconds: int) -> str:
    """What every page says while NXray leaves the switch alone after a role change."""
    minutes = max(1, (seconds + 59) // 60)
    return (
        "NXray is leaving the switch alone for about "
        f"{minutes} more minute{'s' if minutes != 1 else ''} so the switch applies the "
        "new permissions for NXray's changes. The switch is not contacted until then; "
        "reload this page afterwards."
    )


def stored_switch(
    request: Request,
) -> tuple[SwitchConnection | None, SwitchTarget | None, str | None]:
    """The stored switch, its decrypted login, and an error message.

    (None, None, None) when no switch is set up; (connection, None, message)
    when the stored login cannot be decrypted, or while NXray waits for the
    switch to apply a new role (see app/port_changes.py).
    """
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        connection = get_connection(conn)
        if connection is None:
            return None, None, None
        if waiting := connection.paused_seconds():
            return connection, None, paused_message(waiting)
        try:
            return connection, load_target(conn, settings.secret_key), None
        except DecryptionError:
            return connection, None, KEY_CHANGED_MESSAGE


def safe_next(target: str) -> str:
    """A post-login destination on this site only; "/" for anything else.

    An attacker-supplied ?next=https://... or //host/... would otherwise turn
    the login page into an open redirect.
    """
    if target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return "/"


def redirect(url: str, status_code: int = 303) -> RedirectResponse:
    """Redirect after a successful POST.

    303 is the default so the browser follows with GET; a plain 302 leaves the
    method up to the client.
    """
    return RedirectResponse(url=url, status_code=status_code)
