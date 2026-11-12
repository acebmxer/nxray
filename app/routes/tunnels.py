"""The Tunnels page: every GRE and IP-in-IP tunnel with its state, mode, ends and address,
and the changes its forms make, on the same parts as the Monitor sessions page.

``GET /tunnels`` shows it; every change goes through ``POST /tunnels/change`` with the
same form fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``)
and a confirm page first. Changes need the stored admin login: the switch takes tunnels
into a role's port list only while tunnel is on, so NXray's roles cannot name them.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.tunnels import TUNNELS, TunnelPage, build_tunnel_change, load_tunnel_page

router = APIRouter()

TUNNEL_CHANGES_OFF = (
    "Tunnel changes need the stored admin login. NXray's roles name the interfaces they "
    "may change, and the switch does not let them name tunnels. An NXray admin picks "
    "Limited role, and store the switch admin login, on the Switch page."
)


def check_tunnel_place(page: TunnelPage, ident: dict[str, str]) -> None:
    """Nothing to refuse: naming a tunnel the switch lacks makes it, as the switch does."""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_tunnels(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/tunnels",
    back_url="/routing",
    back_label="Routing",
    save_back={"back": "tunnels"},
    changes_name="Tunnel",
    subject="tunnels",
    off_message=TUNNEL_CHANGES_OFF,
    enabled=lambda connection: connection.tunnel_changes_enabled,
    load=load_tunnel_page,
    check_place=check_tunnel_place,
    build=build_tunnel_change,
    send=_send,
    stored_login=True,
)


def render_tunnels_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Tunnels page, with a message."""
    return render_site_page(request, username, TUNNELS, SITE, error=error, notice=notice, form=form)


@router.get("/tunnels", response_class=HTMLResponse)
def tunnels_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /tunnels``: every tunnel with its state, mode, ends and address, read live;
    every role looks, operators and admins change (with the stored admin login)."""
    return render_tunnels_page(request, username)


@router.post("/tunnels/change", response_class=HTMLResponse)
def tunnels_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Tunnels page. Without confirm=yes, asks first."""
    return site_change(request, username, form, TUNNELS, SITE)
