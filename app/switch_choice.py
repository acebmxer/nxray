"""Which of NXray's switches a browser is looking at.

NXray can hold several switches (``switch_connection``, one row each). Every
page shows one of them: the one named by the ``nxray_switch`` cookie, or,
when that names none (never chosen, or since forgotten), the first one
added. The switch picker in the top bar sets the cookie.

Choosing is per browser, not per tab. So that a page loaded for one switch
can never change another after a different switch was picked in another
tab, the anti-forgery token every form carries names the switch the page
was shown for (``app/security.py`` ``csrf_token``); a form for another
switch is refused like an expired one.
"""

from __future__ import annotations

import sqlite3

from fastapi import Request, Response

from app.db import open_db

SWITCH_COOKIE = "nxray_switch"
# A year: the choice is a convenience, not a secret, and it is checked on
# every request against the switches that exist.
SWITCH_COOKIE_DAYS = 365


def resolve_switch_id(conn: sqlite3.Connection, wanted: int | None) -> int | None:
    """``wanted`` when that switch exists, else the first one added; None with none."""
    if wanted is not None:
        row = conn.execute("SELECT id FROM switch_connection WHERE id = ?", (wanted,)).fetchone()
        if row is not None:
            return int(row["id"])
    row = conn.execute("SELECT MIN(id) AS id FROM switch_connection").fetchone()
    return None if row is None or row["id"] is None else int(row["id"])


def _cookie_switch_id(request: Request) -> int | None:
    value = request.cookies.get(SWITCH_COOKIE, "")
    return int(value) if value.isdigit() and len(value) < 10 else None


def selected_switch_id(request: Request) -> int | None:
    """The id of the switch this request is for; None when NXray has none.
    Looked up once per request."""
    if getattr(request.state, "switch_looked_up", False):
        return request.state.switch_id
    with open_db(request.app.state.settings.db_path) as conn:
        switch_id = resolve_switch_id(conn, _cookie_switch_id(request))
    request.state.switch_id = switch_id
    request.state.switch_looked_up = True
    return switch_id


def choose_switch(request: Request, switch_id: int | None) -> None:
    """Make ``switch_id`` the switch for the rest of this request (a page that
    just added or forgot one); ``remember_switch`` keeps it for the next."""
    request.state.switch_id = switch_id
    request.state.switch_looked_up = True


def remember_switch(request: Request, response: Response) -> Response:
    """Set the cookie to the switch this request ended on, and return ``response``."""
    switch_id = selected_switch_id(request)
    if switch_id is None:
        response.delete_cookie(SWITCH_COOKIE)
        return response
    response.set_cookie(
        key=SWITCH_COOKIE,
        value=str(switch_id),
        max_age=SWITCH_COOKIE_DAYS * 86400,
        httponly=True,
        samesite="lax",
        secure=request.app.state.settings.https_only,
    )
    return response
