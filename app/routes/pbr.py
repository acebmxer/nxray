"""The Policy-based routing page: the route-maps with their entries, where they are
applied and their counters, and the changes its forms make, on the same parts as the
Monitor sessions page.

``GET /pbr`` shows it; every change goes through ``POST /pbr/change`` with the same form
fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a
confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.pbr import PBR, build_pbr_change, check_pbr_place, load_pbr_page
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

PBR_CHANGES_OFF = (
    "Policy-based routing changes are off. An NXray admin turns on changes on the Switch "
    "page first, with the broad role or a stored admin login: the limited role has no rules "
    "for them."
)


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_pbr(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/pbr",
    back_url="/routing",
    back_label="Routing",
    save_back={"back": "pbr"},
    changes_name="Policy-based routing",
    subject="policy-based routing",
    off_message=PBR_CHANGES_OFF,
    enabled=lambda connection: connection.pbr_changes_enabled,
    load=load_pbr_page,
    check_place=check_pbr_place,
    build=build_pbr_change,
    send=_send,
    links=(("/security/acls", "ACLs, for the traffic a route-map matches"),),
    stored_login=True,
)


def render_pbr_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Policy-based routing page, with a message."""
    return render_site_page(request, username, PBR, SITE, error=error, notice=notice, form=form)


@router.get("/pbr", response_class=HTMLResponse)
def pbr_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /pbr``: the route-maps, the applied policies and their counters, read live;
    every role looks, operators and admins change."""
    return render_pbr_page(request, username)


@router.post("/pbr/change", response_class=HTMLResponse)
def pbr_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Policy-based routing page. Without confirm=yes, asks first."""
    return site_change(request, username, form, PBR, SITE)
