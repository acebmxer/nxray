"""The Loopbacks page: every loopback with its state, VRF and addresses, and the changes
its forms make, on the same parts as the Monitor sessions page.

``GET /loopbacks`` shows it; every change goes through ``POST /loopbacks/change`` with the
same form fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``)
and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.loopbacks import LOOPBACKS, LoopbackPage, build_loopback_change, load_loopback_page
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.switch_connection import SwitchConnection

router = APIRouter()

LOOPBACK_CHANGES_OFF = (
    "Loopback changes are off. An NXray admin turns on changes on the Switch page first, "
    "with the broad role or a stored admin login: the limited role does not name the "
    "loopbacks."
)
ROLE_WITHOUT_LOOPBACKS = (
    "Not changed: NXray's broad role on the switch was written before it named the "
    "loopbacks, so the switch refuses them. An NXray admin presses Update the port list on "
    "the Switch page first."
)


def check_loopback_place(page: LoopbackPage, ident: dict[str, str]) -> None:
    """Nothing to refuse: naming a loopback the switch lacks makes it, as the switch does."""


def loopback_needs(connection: SwitchConnection, scope: str, setting: str) -> str:
    """Why the role may not change loopbacks yet: a broad role written before it named
    them ("" when it may)."""
    return ROLE_WITHOUT_LOOPBACKS if connection.broad_role_without_loopbacks else ""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_loopbacks(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/loopbacks",
    back_url="/routing",
    back_label="Routing",
    save_back={"back": "loopbacks"},
    changes_name="Loopback",
    subject="loopbacks",
    off_message=LOOPBACK_CHANGES_OFF,
    enabled=lambda connection: connection.loopback_changes_enabled,
    load=load_loopback_page,
    check_place=check_loopback_place,
    build=build_loopback_change,
    send=_send,
    needs=loopback_needs,
    stored_login=True,
)


def render_loopbacks_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Loopbacks page, with a message."""
    return render_site_page(
        request, username, LOOPBACKS, SITE, error=error, notice=notice, form=form
    )


@router.get("/loopbacks", response_class=HTMLResponse)
def loopbacks_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /loopbacks``: every loopback with its state, VRF and addresses, read live; every
    role looks, operators and admins change."""
    return render_loopbacks_page(request, username)


@router.post("/loopbacks/change", response_class=HTMLResponse)
def loopbacks_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Loopbacks page. Without confirm=yes, asks first."""
    return site_change(request, username, form, LOOPBACKS, SITE)
