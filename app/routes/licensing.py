"""The Smart Licensing page: the licences in use and the registration, with the one change it
makes, on the same parts as the Monitor sessions page.

``GET /licensing`` shows it; every change goes through ``POST /licensing/change`` with the
same form fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``)
and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.licensing import (
    SMART_LICENSING,
    build_licensing_change,
    check_licensing_place,
    load_licensing_page,
)
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

LICENSING_CHANGES_OFF = (
    "Smart Licensing changes are off. An NXray admin turns on changes on the Switch "
    "page first, with the broad role or a stored admin login: the limited role has no rules "
    "for them."
)


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_licensing(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/licensing",
    back_url="/switch-admin",
    back_label="Switch admin",
    save_back={"back": "licensing"},
    changes_name="Smart Licensing",
    subject="Smart Licensing",
    off_message=LICENSING_CHANGES_OFF,
    enabled=lambda connection: connection.licensing_changes_enabled,
    load=load_licensing_page,
    check_place=check_licensing_place,
    build=build_licensing_change,
    send=_send,
    stored_login=True,
)


def render_licensing_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Smart Licensing page, with a message."""
    return render_site_page(
        request, username, SMART_LICENSING, SITE, error=error, notice=notice, form=form
    )


@router.get("/licensing", response_class=HTMLResponse)
def licensing_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /licensing``: the licences, read live; every role
    looks, operators and admins change."""
    return render_licensing_page(request, username)


@router.post("/licensing/change", response_class=HTMLResponse)
def licensing_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Smart Licensing page. Without confirm=yes, asks first."""
    return site_change(request, username, form, SMART_LICENSING, SITE)
