"""The Activity page: who changed what through NXray, for admins.

``GET /activity`` lists the newest changes, filtered by account, area and text;
``GET /activity.csv`` downloads the same list as CSV.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.activity import KEEP_DAYS, LIST_LIMIT, activity_choices, activity_csv, list_activity
from app.db import open_db
from app.dependencies import admin_required, templates

router = APIRouter()


def _filters(user: str, area: str, search: str) -> dict[str, str]:
    return {"username": user[:64], "area": area[:64], "search": search.strip()[:100]}


@router.get("/activity", response_class=HTMLResponse)
def activity_page(
    request: Request,
    username: str = Depends(admin_required),
    user: str = "",
    area: str = "",
    search: str = "",
) -> Response:
    """``GET /activity?user=&area=&search=``: the newest changes made through NXray,
    newest first; admins only."""
    filters = _filters(user, area, search)
    with open_db(request.app.state.settings.db_path) as conn:
        entries = list_activity(conn, **filters)
        users, areas = activity_choices(conn)
    return templates.TemplateResponse(
        request,
        "activity.html",
        {
            "username": username,
            "entries": entries,
            "users": users,
            "areas": areas,
            "user": filters["username"],
            "area": filters["area"],
            "search": filters["search"],
            "limit": LIST_LIMIT,
            "keep_days": KEEP_DAYS,
        },
    )


@router.get("/activity.csv")
def activity_download(
    request: Request,
    username: str = Depends(admin_required),
    user: str = "",
    area: str = "",
    search: str = "",
) -> Response:
    """``GET /activity.csv``: the same list as the page, as a CSV file."""
    with open_db(request.app.state.settings.db_path) as conn:
        entries = list_activity(conn, **_filters(user, area, search))
    return Response(
        activity_csv(entries),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="nxray-activity.csv"'},
    )
