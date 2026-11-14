"""The VXLAN tunnel encryption page: the key chains, policies, peers and links of CloudSec
between the sites of a VXLAN EVPN multi-site fabric, their sessions, and the changes its forms
make, on the same parts as the Monitor sessions page.

``GET /tunnel-encryption`` shows it; every change goes through ``POST
/tunnel-encryption/change`` with the same form fields as a protocol page (scope, setting,
action, ``id_<name>``, ``v_<name>``) and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.tunnel_encryption import (
    TUNNEL_ENCRYPTION,
    build_tunnel_encryption_change,
    check_tunnel_encryption_place,
    load_tunnel_encryption_page,
)

router = APIRouter()

TUNNEL_ENCRYPTION_CHANGES_OFF = (
    "VXLAN tunnel encryption changes are off. An NXray admin turns on changes on the Switch "
    "page first, with the broad role or a stored admin login: the limited role has no rules "
    "for them."
)


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_tunnel_encryption(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/tunnel-encryption",
    back_url="/vxlan",
    back_label="VXLAN",
    save_back={"back": "tunnel-encryption"},
    changes_name="VXLAN tunnel encryption",
    subject="VXLAN tunnel encryption",
    off_message=TUNNEL_ENCRYPTION_CHANGES_OFF,
    enabled=lambda connection: connection.vxlan_extra_changes_enabled,
    load=load_tunnel_encryption_page,
    check_place=check_tunnel_encryption_place,
    build=build_tunnel_encryption_change,
    send=_send,
    links=(
        ("/vxlan", "VXLAN, which carries the traffic it encrypts"),
        ("/loopbacks", "Loopbacks, for the source loopback"),
        ("/pki", "SSH and certificates, for peers that use certificates"),
    ),
    scroll_tables=True,
    stored_login=True,
)


def render_tunnel_encryption_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the VXLAN tunnel encryption page, with a message."""
    return render_site_page(
        request, username, TUNNEL_ENCRYPTION, SITE, error=error, notice=notice, form=form
    )


@router.get("/tunnel-encryption", response_class=HTMLResponse)
def tunnel_encryption_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /tunnel-encryption``: the key chains, policies, peers, links and sessions, read
    live; every role looks, operators and admins change."""
    return render_tunnel_encryption_page(request, username)


@router.post("/tunnel-encryption/change", response_class=HTMLResponse)
def tunnel_encryption_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the VXLAN tunnel encryption page. Without confirm=yes, asks first."""
    return site_change(request, username, form, TUNNEL_ENCRYPTION, SITE)
