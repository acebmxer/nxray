"""The Enhanced policy-based routing page: the services with their end-points and probes,
the policies with their matches and service chains, where they are applied, the chains'
state and the counters, and the changes its forms make, on the same parts as the Monitor
sessions page.

``GET /epbr`` shows it; every change goes through ``POST /epbr/change`` with the same form
fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a
confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.epbr import EPBR, build_epbr_change, check_epbr_place, load_epbr_page
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.switch_connection import SwitchConnection

router = APIRouter()

EPBR_CHANGES_OFF = (
    "Enhanced policy-based routing changes are off. An NXray admin turns on changes on the "
    "Switch page first, with the broad role or a stored admin login: the limited role has no "
    "rules for them."
)
ROLE_WITHOUT_EPBR_CLEAR = (
    "Not changed: NXray's broad role on the switch was written before it allowed clearing "
    "ePBR's counters, so the switch refuses it. An NXray admin presses Update the port list "
    "on the Switch page first."
)


def epbr_needs(connection: SwitchConnection, scope: str, setting: str) -> str:
    """Why the role may not clear ePBR's counters yet: a broad role written before it
    allowed it ("" when it may)."""
    if scope == "counters" and connection.broad_role_without_epbr_clear:
        return ROLE_WITHOUT_EPBR_CLEAR
    return ""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_epbr(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/epbr",
    back_url="/routing",
    back_label="Routing",
    save_back={"back": "epbr"},
    changes_name="Enhanced policy-based routing",
    subject="enhanced policy-based routing",
    off_message=EPBR_CHANGES_OFF,
    enabled=lambda connection: connection.epbr_changes_enabled,
    load=load_epbr_page,
    check_place=check_epbr_place,
    build=build_epbr_change,
    send=_send,
    links=(
        ("/security/acls", "ACLs, for the traffic a policy takes"),
        ("/track", "Tracked objects, for an end-point's probe"),
    ),
    needs=epbr_needs,
    scroll_tables=True,
    stored_login=True,
)


def render_epbr_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Enhanced policy-based routing page, with a
    message."""
    return render_site_page(request, username, EPBR, SITE, error=error, notice=notice, form=form)


@router.get("/epbr", response_class=HTMLResponse)
def epbr_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /epbr``: the ePBR services, policies, chains and counters, read live; every
    role looks, operators and admins change."""
    return render_epbr_page(request, username)


@router.post("/epbr/change", response_class=HTMLResponse)
def epbr_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Enhanced policy-based routing page. Without confirm=yes, asks
    first."""
    return site_change(request, username, form, EPBR, SITE)
