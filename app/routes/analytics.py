"""The Flow analytics page, with the changes its forms make, on the same parts as the Monitor
sessions page.

``GET /analytics`` shows it; every change goes through ``POST /analytics/change`` with the
same form fields as a protocol page (scope, setting, action, ``id_<name>``,
``v_<name>``) and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.analytics import (
    ANALYTICS,
    build_analytics_change,
    check_analytics_place,
    load_analytics_page,
)
from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

ANALYTICS_CHANGES_OFF = (
    "Flow analytics changes are off. An NXray admin turns on changes on the Switch "
    "page first, with the broad role or a stored admin login: the limited role has no rules "
    "for them."
)


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_analytics(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/analytics",
    back_url="/features",
    back_label="Features",
    save_back={"back": "analytics"},
    changes_name="Flow analytics",
    subject="Flow analytics",
    off_message=ANALYTICS_CHANGES_OFF,
    enabled=lambda connection: connection.analytics_changes_enabled,
    load=load_analytics_page,
    check_place=check_analytics_place,
    build=build_analytics_change,
    send=_send,
    stored_login=True,
)


def render_analytics_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Flow analytics page, with a message."""
    return render_site_page(
        request, username, ANALYTICS, SITE, error=error, notice=notice, form=form
    )


@router.get("/analytics", response_class=HTMLResponse)
def analytics_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /analytics``: read live; every role looks, operators and admins change."""
    return render_analytics_page(request, username)


@router.post("/analytics/change", response_class=HTMLResponse)
def analytics_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Flow analytics page. Without confirm=yes, asks first."""
    return site_change(request, username, form, ANALYTICS, SITE)
