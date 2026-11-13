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
from app.activity import record_activity, utc_time
from app.alerts import notify_change, switch_label
from app.db import open_db
from app.features import feature_anchor
from app.live import LIVE_CHOICES, refreshes_whole_page, shared_show_reads
from app.nxapi import SwitchTarget, shared_reads
from app.port_changes import ROLE_VERSION, missing_changes
from app.ports import human_bytes, human_rate
from app.preferences import THEMES, ui_preferences
from app.security import LIVE_REQUEST, csrf_token, csrf_valid, current_user
from app.switch_choice import selected_switch_id
from app.switch_connection import (
    DecryptionError,
    SwitchConnection,
    get_connection,
    list_connections,
    load_target,
)
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
templates.env.filters["utc"] = utc_time

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

# Sent only when HTTPS is on (NXRAY_ENABLE_HTTPS or NXRAY_HTTPS): after one
# visit the browser keeps to https:// for a year. No includeSubDomains or
# preload: NXray does not know what else runs on the same domain.
HSTS_VALUE = "max-age=31536000"


async def add_security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """HTTP middleware: add SECURITY_HEADERS to every response."""
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if request.app.state.settings.https_only:
        response.headers.setdefault("Strict-Transport-Security", HSTS_VALUE)
    return response


async def share_switch_reads(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """HTTP middleware: a page that refreshes itself as a whole (``live.js`` asks
    with ``X-Requested-With: nxray-live``) reads the switch through the shared
    cache, so many open pages cost the switch one read per interval. Every
    other request, a page opened or a form sent, reads the switch itself."""
    if request.headers.get("x-requested-with") != LIVE_REQUEST or not refreshes_whole_page(
        request.method, request.url.path
    ):
        return await call_next(request)
    settings = request.app.state.settings
    token = shared_reads.set(
        shared_show_reads(
            request.app.state.live_cache,
            settings.live_min_interval,
            settings.live_clients_min_interval,
        )
    )
    try:
        return await call_next(request)
    finally:
        shared_reads.reset(token)


def request_target(request: Request) -> str:
    """The path and query string of a request, to come back to after sign-in."""
    query = request.url.query
    return f"{request.url.path}?{query}" if query else request.url.path


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
        raise RedirectToLogin(request_target(request))
    return username


def live_login_required(request: Request) -> str:
    """Like ``login_required`` for the self-refreshing figures: it does not
    slide the session's expiry. Signed out, it redirects to the sign-in page
    like any other route, and the page's script, seeing the redirect, stops
    asking."""
    username = current_user(request, touch=False)
    if username is None:
        raise RedirectToLogin(request_target(request))
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


def may_change(request: Request) -> bool:
    """True when the signed-in account may change the switch (operator or admin).

    The one place pages ask this before showing change buttons; the roles
    themselves are decided by ``User.can_change``. A page adds its own
    ``*_changes_enabled`` flag on top.
    """
    account = current_account(request)
    return account is not None and account.can_change


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
    """The switch this request is for (``app/switch_choice.py``), its decrypted
    login, and an error message.

    (None, None, None) when no switch is set up; (connection, None, message)
    when the stored login cannot be decrypted, or while NXray waits for the
    switch to apply a new role (see app/port_changes.py).
    """
    settings = request.app.state.settings
    switch_id = selected_switch_id(request)
    with open_db(settings.db_path) as conn:
        connection = get_connection(conn, switch_id)
        if connection is None:
            return None, None, None
        if waiting := connection.paused_seconds():
            return connection, None, paused_message(waiting)
        try:
            return connection, load_target(conn, connection.id, settings.secret_key), None
        except DecryptionError:
            return connection, None, KEY_CHANGED_MESSAGE


def selected_connection(request: Request) -> SwitchConnection | None:
    """The switch this request is for, without its login; None with none set up."""
    with open_db(request.app.state.settings.db_path) as conn:
        return get_connection(conn, selected_switch_id(request))


def switch_picker(request: Request) -> tuple[list[SwitchConnection], int | None]:
    """Every switch and the one this page is for, for the top bar's picker."""
    if getattr(request.state, "picker", None) is None:
        with open_db(request.app.state.settings.db_path) as conn:
            switches = list_connections(conn)
        request.state.picker = (switches, selected_switch_id(request))
    return request.state.picker


def role_behind(request: Request) -> list[tuple[SwitchConnection, str]]:
    """Switches whose NXray role lacks rules this version of NXray can use, with
    the missing kinds of change in words, for the banner on every page.

    Only for an admin, who alone can fix it on the Switch page, and only for a
    switch that already had changes turned on (``role_version`` above 0); one
    that never had them is simply off, not behind. Empty on the Switch page,
    which has its own card for this.
    """
    account = current_account(request)
    if account is None or not account.is_admin or request.url.path.startswith("/switch"):
        return []
    switches, _ = switch_picker(request)
    return [
        (switch, missing_changes(switch.role_version))
        for switch in switches
        if 0 < switch.role_version < ROLE_VERSION
    ]


def broad_behind(request: Request) -> list[SwitchConnection]:
    """Switches whose broad role was written before its latest denies
    (``SwitchConnection.broad_role_behind``), for a warning on every page. Like
    ``role_behind``: for an admin only, and not on the Switch page, which has its own
    card for it."""
    account = current_account(request)
    if account is None or not account.is_admin or request.url.path.startswith("/switch"):
        return []
    switches, _ = switch_picker(request)
    return [switch for switch in switches if switch.broad_role_behind]


templates.env.globals["switch_picker"] = switch_picker
templates.env.globals["role_behind"] = role_behind
templates.env.globals["broad_behind"] = broad_behind
templates.env.globals["ui_preferences"] = ui_preferences
templates.env.globals["themes"] = THEMES
templates.env.globals["live_choices"] = LIVE_CHOICES
templates.env.globals["refreshes_whole_page"] = refreshes_whole_page
# Links to one feature's row on the Features page.
templates.env.globals["feature_anchor"] = feature_anchor
# The top bar's own form; a page's forms get ``csrf_token`` from their route.
templates.env.globals["form_token"] = csrf_token


def note_activity(request: Request, username: str, area: str, what: str, switch: str = "") -> None:
    """Record a change in the activity log (``app/activity.py``), after it worked,
    and send it as an alert when the Alerts page asks for changes.

    ``switch`` is the switch's address when the switch itself was changed;
    the alert names the switch this request is for, or that address when it
    is gone (Forget this switch).
    """
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        record_activity(conn, username, area, what, switch)
        # A change to NXray's own settings names no switch.
        label = switch_label(get_connection(conn, selected_switch_id(request))) if switch else ""
    notify_change(
        settings,
        username,
        area,
        what,
        label or switch,
        request.app.state.alert_transport,
        background=request.app.state.alerts_background,
    )


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
