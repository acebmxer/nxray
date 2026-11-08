"""The theme and menu-width buttons, and the refresh picker."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import Response

from app.db import open_db
from app.dependencies import CsrfFailed, login_required, redirect, safe_next
from app.preferences import remember_preferences
from app.security import csrf_valid_any_switch
from app.switch_connection import list_connections

router = APIRouter()


@router.post("/preferences")
def preferences(
    request: Request,
    username: str = Depends(login_required),
    csrf: str = Form(""),
    theme: str = Form(""),
    menu: str = Form(""),
    live: str = Form(""),
    next: str = Form("/"),
) -> Response:
    """Keep this browser's theme, menu width or refresh interval, then go back.

    Changes nothing on a switch, so like the switch picker it takes a form
    shown for any switch.
    """
    with open_db(request.app.state.settings.db_path) as conn:
        known = [connection.id for connection in list_connections(conn)]
    if not csrf_valid_any_switch(request, csrf, known):
        raise CsrfFailed()
    response = redirect(safe_next(next))
    return remember_preferences(request, response, theme=theme, menu=menu, live=live)
