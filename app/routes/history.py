"""The History page: temperatures, power, fans, CPU, memory and traffic over time,
and each VLAN's traffic estimated from its access ports.

Reads what app/history.py recorded. Only the Live window asks the switch, and
through the live cache (app/routes/live.py), never directly.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import login_required, stored_switch, templates
from app.history import (
    KEEP_DAYS,
    LIVE,
    PAGE_RANGE_LABELS,
    last_sample_time,
    page_range_key,
    system_charts,
    vlan_charts,
)
from app.live import live_window_context
from app.routes.live import history_live_view
from app.switch_choice import selected_switch_id
from app.switch_connection import get_connection

router = APIRouter()


@router.get("/history", response_class=HTMLResponse)
def history_page(
    request: Request,
    username: str = Depends(login_required),
    period: str = Query("", alias="range"),
) -> Response:
    settings = request.app.state.settings
    key = page_range_key(period)
    now = time.time()
    # The Live window reads the switch (through the live cache) before the
    # database is opened: the switch can take seconds to answer.
    live: dict[str, object] = {}
    if key == LIVE:
        live_connection, target, _error = stored_switch(request)
        if live_connection is not None and target is not None:
            live = history_live_view(request, live_connection, target, now)
    with open_db(settings.db_path) as conn:
        connection = get_connection(conn, selected_switch_id(request))
        charts = []
        if connection and "charts" in live:
            charts = live["charts"]
        elif connection:
            # Stored samples only: the Live window of a switch NXray cannot read.
            charts = system_charts(conn, connection.id, key, now)
            charts += vlan_charts(conn, connection.id, key, now)
        last_sample = last_sample_time(conn, connection.id) if connection else None
    return templates.TemplateResponse(
        request,
        "history.html",
        {
            "username": username,
            "connection": connection,
            "charts": charts,
            "range": key,
            "ranges": PAGE_RANGE_LABELS,
            "live_problem": live.get("live_problem", ""),
            "live_floor": settings.live_min_interval,
            **live_window_context(request, key, "/live/history"),
            "interval": settings.history_interval,
            "keep_days": KEEP_DAYS,
            "last_sample_ago": None if last_sample is None else int(now - last_sample),
        },
    )
