"""The Edge Virtual Bridging page: the VDP address and timers, and the hosts and VSIs the
servers announced, with the changes its forms make, on the same parts as the Monitor
sessions page.

``GET /evb`` shows it; every change goes through ``POST /evb/change`` with the same form
fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a confirm
page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.evb import EVB, build_evb_change, check_evb_place, load_evb_page
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

EVB_CHANGES_OFF = (
    "Edge Virtual Bridging changes are off. An NXray admin turns on changes on the Switch "
    "page first, with the broad role or a stored admin login: the limited role has no rules "
    "for them."
)


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_evb(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/evb",
    back_url="/vlans",
    back_label="VLANs",
    save_back={"back": "evb"},
    changes_name="Edge Virtual Bridging",
    subject="Edge Virtual Bridging",
    off_message=EVB_CHANGES_OFF,
    enabled=lambda connection: connection.layer2_changes_enabled,
    load=load_evb_page,
    check_place=check_evb_place,
    build=build_evb_change,
    send=_send,
    links=(("/vmtracker", "VM Tracker, which learns the VMs from vCenter instead"),),
    scroll_tables=True,
    stored_login=True,
)


def render_evb_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Edge Virtual Bridging page, with a message."""
    return render_site_page(request, username, EVB, SITE, error=error, notice=notice, form=form)


@router.get("/evb", response_class=HTMLResponse)
def evb_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /evb``: EVB's settings, hosts and VSIs, read live; every role
    looks, operators and admins change."""
    return render_evb_page(request, username)


@router.post("/evb/change", response_class=HTMLResponse)
def evb_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Edge Virtual Bridging page. Without confirm=yes, asks first."""
    return site_change(request, username, form, EVB, SITE)
