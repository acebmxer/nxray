"""The VTP page: the switch's VTP mode, domain and version, the ports that take part,
and the changes its forms make, on the same parts as the Monitor sessions page.

``GET /vtp`` shows it; every change goes through ``POST /vtp/change`` with the same
form fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``)
and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.vtp import VTP, VtpPage, build_vtp_change, load_vtp_page

router = APIRouter()

VTP_CHANGES_OFF = (
    "VTP changes are off. An NXray admin turns on changes on the Switch page first, with "
    "the broad role or a stored admin login: the limited role has no room for them."
)


def check_vtp_place(page: VtpPage, ident: dict[str, str]) -> None:
    """Refuse a port that is not a switched front port or port-channel of the switch."""
    port = ident.get("port", "").strip()
    if port and port not in page.ports:
        raise ValueError(f"{port} is not a switched port or port-channel on the switch")


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_vtp(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/vtp",
    back_url="/vlans",
    back_label="VLANs",
    save_back={"back": "vtp"},
    changes_name="VTP",
    subject="VTP",
    off_message=VTP_CHANGES_OFF,
    enabled=lambda connection: connection.vtp_changes_enabled,
    load=load_vtp_page,
    check_place=check_vtp_place,
    build=build_vtp_change,
    send=_send,
    stored_login=True,
)


def render_vtp_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the VTP page, with a message."""
    return render_site_page(request, username, VTP, SITE, error=error, notice=notice, form=form)


@router.get("/vtp", response_class=HTMLResponse)
def vtp_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /vtp``: the VTP status, ports and counters, read live; every role looks,
    operators and admins change."""
    return render_vtp_page(request, username)


@router.post("/vtp/change", response_class=HTMLResponse)
def vtp_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the VTP page. Without confirm=yes, asks first."""
    return site_change(request, username, form, VTP, SITE)
