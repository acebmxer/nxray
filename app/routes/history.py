"""The History page: temperatures, power, fans, CPU, memory and traffic over time.

Reads what app/history.py recorded; it never calls the switch.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import login_required, templates
from app.history import (
    KEEP_DAYS,
    RANGE_LABELS,
    last_sample_time,
    range_key,
    system_charts,
)
from app.switch_connection import get_connection

router = APIRouter()


@router.get("/history", response_class=HTMLResponse)
def history_page(
    request: Request,
    username: str = Depends(login_required),
    period: str = Query("", alias="range"),
) -> Response:
    settings = request.app.state.settings
    key = range_key(period)
    now = time.time()
    with open_db(settings.db_path) as conn:
        connection = get_connection(conn)
        charts = system_charts(conn, key, now) if connection else []
        last_sample = last_sample_time(conn)
    return templates.TemplateResponse(
        request,
        "history.html",
        {
            "username": username,
            "connection": connection,
            "charts": charts,
            "range": key,
            "ranges": RANGE_LABELS,
            "interval": settings.history_interval,
            "keep_days": KEEP_DAYS,
            "last_sample_ago": None if last_sample is None else int(now - last_sample),
        },
    )
