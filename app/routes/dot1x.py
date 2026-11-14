"""The 802.1X page: the switch's 802.1X state, the ports set up for it and the devices
signed in, and the changes its forms make, on the same parts as the Monitor sessions page.

``GET /dot1x`` shows it; every change goes through ``POST /dot1x/change`` with the same
form fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``)
and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.dot1x import DOT1X, Dot1xPage, build_dot1x_change, load_dot1x_page
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

DOT1X_CHANGES_OFF = (
    "802.1X changes are off. An NXray admin turns on changes on the Switch page first, with "
    "the broad role or a stored admin login: the limited role has no room for them."
)


def check_dot1x_place(page: Dot1xPage, ident: dict[str, str]) -> None:
    """Refuse a port that is not a switched front port (802.1X is not for port-channels
    or routed ports)."""
    port = ident.get("port", "").strip()
    if port and port not in page.ports:
        raise ValueError(
            f"{port} is not a front port carrying VLANs; 802.1X works on switched front ports only"
        )


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_dot1x(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/dot1x",
    back_url="/security/acls",
    back_label="Security",
    save_back={"back": "dot1x"},
    changes_name="802.1X",
    subject="802.1X",
    off_message=DOT1X_CHANGES_OFF,
    enabled=lambda connection: connection.dot1x_changes_enabled,
    load=load_dot1x_page,
    check_place=check_dot1x_place,
    build=build_dot1x_change,
    send=_send,
    scroll_tables=True,
    stored_login=True,
)


def render_dot1x_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the 802.1X page, with a message."""
    return render_site_page(request, username, DOT1X, SITE, error=error, notice=notice, form=form)


@router.get("/dot1x", response_class=HTMLResponse)
def dot1x_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /dot1x``: the ports set up for 802.1X and the devices signed in, read live;
    every role looks, operators and admins change."""
    return render_dot1x_page(request, username)


@router.post("/dot1x/change", response_class=HTMLResponse)
def dot1x_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the 802.1X page. Without confirm=yes, asks first."""
    return site_change(request, username, form, DOT1X, SITE)
