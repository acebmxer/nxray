"""The landing page after logging in: the switch's health at a glance.

Everything comes from one NX-API request made with NXray's own read-only
account each time the page opens.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import login_required, stored_switch, templates
from app.live import HEALTH, health_trail_chart
from app.switch import Dashboard, health_problems
from app.switch_connection import set_switch_identity
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
    if data is not None and connection is not None:
        with open_db(request.app.state.settings.db_path) as conn:
            set_switch_identity(conn, connection, data.system)

    cache = request.app.state.live_cache
    trail = cache.trail(connection.id, HEALTH) if connection is not None else ()
    trail_chart = health_trail_chart(
        trail, now=time.time(), floor=request.app.state.settings.live_min_interval
    )
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "username": username,
            "connection": connection,
            "status": status,
            "data": data,
            "problems": health_problems(data) if data else [],
            "live_page": HEALTH,
            "live_url": "/live/dashboard",
            "live_at": int(time.time()),
            "live_problem": "",
            "trail_chart": trail_chart,
        },
    )
