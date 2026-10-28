"""The landing page after logging in: the switch's health at a glance.

Everything comes from one NX-API request made with NXray's own read-only
account each time the page opens.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, stored_switch, templates
from app.switch import Dashboard, health_problems
from app.switch_setup import ConnectionStatus, load_dashboard_status

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, username: str = Depends(login_required)) -> Response:
    connection, target, error = stored_switch(request)
    status = ConnectionStatus(False, error) if error else None
    data: Dashboard | None = None
    # Outside any database block: the switch can take seconds to answer.
    if target is not None:
        status, data = load_dashboard_status(target, transport=request.app.state.nxapi_transport)

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "username": username,
            "connection": connection,
            "status": status,
            "data": data,
            "problems": health_problems(data) if data else [],
        },
    )
