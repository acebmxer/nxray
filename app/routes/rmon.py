"""The RMON page, with the changes its forms make, on the same parts as the Monitor
sessions page.

``GET /rmon`` shows it; every change goes through ``POST /rmon/change`` with the
same form fields as a protocol page (scope, setting, action, ``id_<name>``,
``v_<name>``) and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.rmon import (
    RMON,
    build_rmon_change,
    check_rmon_place,
    load_rmon_page,
)
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

RMON_CHANGES_OFF = (
    "RMON changes are off. An NXray admin turns on changes on the Switch "
    "page first, with the broad role or a stored admin login: the limited role has no rules "
    "for them."
)


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_rmon(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/rmon",
    back_url="/features",
    back_label="Features",
    save_back={"back": "rmon"},
    changes_name="RMON",
    subject="RMON",
    off_message=RMON_CHANGES_OFF,
    enabled=lambda connection: connection.rmon_changes_enabled,
    load=load_rmon_page,
    check_place=check_rmon_place,
    build=build_rmon_change,
    send=_send,
    stored_login=True,
)


def render_rmon_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the RMON page, with a message."""
    return render_site_page(request, username, RMON, SITE, error=error, notice=notice, form=form)


@router.get("/rmon", response_class=HTMLResponse)
def rmon_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /rmon``: read live; every role looks, operators and admins change."""
    return render_rmon_page(request, username)


@router.post("/rmon/change", response_class=HTMLResponse)
def rmon_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the RMON page. Without confirm=yes, asks first."""
    return site_change(request, username, form, RMON, SITE)
