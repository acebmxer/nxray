"""The MPLS page: whether MPLS is on, the label range, the interfaces with MPLS and the
static bindings, and the changes its forms make, on the same parts as the Monitor sessions
page.

``GET /mpls`` shows it; every change goes through ``POST /mpls/change`` with the same form
fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a
confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.mpls import MPLS, build_mpls_change, check_mpls_place, load_mpls_page
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

MPLS_CHANGES_OFF = (
    "MPLS changes are off. An NXray admin turns on changes on the Switch page first, with "
    "the broad role or a stored admin login: the limited role has no rules for them."
)


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_mpls(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/mpls",
    back_url="/routing",
    back_label="Routing",
    save_back={"back": "mpls"},
    changes_name="MPLS",
    subject="MPLS",
    off_message=MPLS_CHANGES_OFF,
    enabled=lambda connection: connection.mpls_changes_enabled,
    load=load_mpls_page,
    check_place=check_mpls_place,
    build=build_mpls_change,
    send=_send,
    stored_login=True,
)


def render_mpls_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the MPLS page, with a message."""
    return render_site_page(request, username, MPLS, SITE, error=error, notice=notice, form=form)


@router.get("/mpls", response_class=HTMLResponse)
def mpls_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /mpls``: whether MPLS is on, the label range, interfaces and bindings, read
    live; every role looks, operators and admins change."""
    return render_mpls_page(request, username)


@router.post("/mpls/change", response_class=HTMLResponse)
def mpls_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the MPLS page. Without confirm=yes, asks first."""
    return site_change(request, username, form, MPLS, SITE)
