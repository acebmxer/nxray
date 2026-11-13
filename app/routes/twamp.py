"""The TWAMP server page, with the changes its forms make, on the same parts as the Monitor
sessions page.

``GET /twamp`` shows it; every change goes through ``POST /twamp/change`` with the
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
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.twamp import (
    TWAMP,
    build_twamp_change,
    check_twamp_place,
    load_twamp_page,
)

router = APIRouter()

TWAMP_CHANGES_OFF = (
    "TWAMP server changes are off. An NXray admin turns on changes on the Switch "
    "page first, with the broad role or a stored admin login: the limited role has no rules "
    "for them."
)


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_twamp(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/twamp",
    back_url="/ip-sla",
    back_label="IP SLA",
    save_back={"back": "twamp"},
    changes_name="TWAMP server",
    subject="TWAMP server",
    off_message=TWAMP_CHANGES_OFF,
    enabled=lambda connection: connection.twamp_changes_enabled,
    load=load_twamp_page,
    check_place=check_twamp_place,
    build=build_twamp_change,
    send=_send,
    links=(("/ip-sla", "IP SLA, to measure from the switch"),),
    stored_login=True,
)


def render_twamp_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the TWAMP server page, with a message."""
    return render_site_page(request, username, TWAMP, SITE, error=error, notice=notice, form=form)


@router.get("/twamp", response_class=HTMLResponse)
def twamp_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /twamp``: read live; every role looks, operators and admins change."""
    return render_twamp_page(request, username)


@router.post("/twamp/change", response_class=HTMLResponse)
def twamp_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the TWAMP server page. Without confirm=yes, asks first."""
    return site_change(request, username, form, TWAMP, SITE)
