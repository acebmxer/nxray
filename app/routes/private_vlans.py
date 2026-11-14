"""The Private VLANs page: primary, isolated and community VLANs, the ports and VLAN
interfaces that use them, and the changes its forms make, on the same parts as the
Monitor sessions page.

``GET /private-vlans`` shows it; every change goes through ``POST
/private-vlans/change`` with the same form fields as a protocol page (scope, setting,
action, ``id_<name>``, ``v_<name>``) and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.private_vlans import (
    PRIVATE_VLANS,
    PrivateVlanPage,
    build_private_vlan_change,
    load_private_vlan_page,
)
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

PRIVATE_VLAN_CHANGES_OFF = (
    "Private VLAN changes are off. An NXray admin turns on changes on the Switch page "
    "first, with the broad role or a stored admin login: the limited role has no room "
    "for them."
)


def check_private_vlan_place(page: PrivateVlanPage, ident: dict[str, str]) -> None:
    """Refuse a VLAN the switch does not have (naming it would make one), a port it does
    not have, and a VLAN interface it does not have (naming it would make one)."""
    vlan = ident.get("vlan", "").strip()
    if vlan and vlan not in page.vlans:
        raise ValueError(f"the switch has no VLAN {vlan}; make it on the VLANs page first")
    port = ident.get("port", "").strip()
    if port and page.ports and port not in page.ports:
        raise ValueError(f"{port} is not a switched port or port-channel on the switch")
    interface = ident.get("interface", "").strip()
    if interface and interface not in page.interfaces:
        raise ValueError(
            f"the switch has no VLAN interface {interface}; make it on the Routing page first"
        )


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_private_vlans(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/private-vlans",
    back_url="/vlans",
    back_label="VLANs",
    save_back={"back": "private-vlans"},
    changes_name="Private VLAN",
    subject="private VLANs",
    off_message=PRIVATE_VLAN_CHANGES_OFF,
    enabled=lambda connection: connection.private_vlan_changes_enabled,
    load=load_private_vlan_page,
    check_place=check_private_vlan_place,
    build=build_private_vlan_change,
    send=_send,
    stored_login=True,
)


def render_private_vlans_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Private VLANs page, with a message."""
    return render_site_page(
        request, username, PRIVATE_VLANS, SITE, error=error, notice=notice, form=form
    )


@router.get("/private-vlans", response_class=HTMLResponse)
def private_vlans_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /private-vlans``: the private VLANs, ports and VLAN interface mappings, read
    live; every role looks, operators and admins change."""
    return render_private_vlans_page(request, username)


@router.post("/private-vlans/change", response_class=HTMLResponse)
def private_vlans_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Private VLANs page. Without confirm=yes, asks first."""
    return site_change(request, username, form, PRIVATE_VLANS, SITE)
