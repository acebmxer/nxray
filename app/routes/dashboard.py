"""The landing page after logging in.

Shows whether NXray can reach the switch with its own account. The full
dashboard (temperatures, fans, power, ports) arrives in a later stage.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import login_required, templates
from app.switch_connection import DecryptionError, get_connection, load_target
from app.switch_setup import KEY_CHANGED_MESSAGE, ConnectionStatus, check_connection

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, username: str = Depends(login_required)) -> Response:
    settings = request.app.state.settings
    status: ConnectionStatus | None = None
    target = None
    with open_db(settings.db_path) as conn:
        connection = get_connection(conn)
        if connection is not None:
            try:
                target = load_target(conn, settings.secret_key)
            except DecryptionError:
                status = ConnectionStatus(False, KEY_CHANGED_MESSAGE)

    # Outside the database block: the switch can take seconds to answer.
    if target is not None:
        status = check_connection(target, transport=request.app.state.nxapi_transport)

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"username": username, "connection": connection, "status": status},
    )
