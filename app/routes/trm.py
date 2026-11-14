"""The Multicast over VXLAN page: tenant routed multicast's switch-wide lines, the layer 3
VNIs' groups, the VRFs' MVPN settings and BGP's overlay families, and the changes its forms
make, on the same parts as the Monitor sessions page.

``GET /trm`` shows it; every change goes through ``POST /trm/change`` with the same form
fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a
confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.trm import TRM, build_trm_change, check_trm_place, load_trm_page

router = APIRouter()

TRM_CHANGES_OFF = (
    "Multicast over VXLAN changes are off. An NXray admin turns on changes on the Switch page "
    "first, with the broad role or a stored admin login: the limited role has no rules for "
    "them."
)


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_trm(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/trm",
    back_url="/vxlan",
    back_label="VXLAN",
    save_back={"back": "trm"},
    changes_name="Multicast over VXLAN",
    subject="multicast over VXLAN",
    off_message=TRM_CHANGES_OFF,
    enabled=lambda connection: connection.multicast_changes_enabled,
    load=load_trm_page,
    check_place=check_trm_place,
    build=build_trm_change,
    send=_send,
    links=(
        ("/vxlan", "VXLAN, for the NVE interface and layer 3 VNIs"),
        ("/routing/protocols/bgp", "BGP, for the neighbors' ipv4 mvpn family (Protocols)"),
        ("/routing/protocols/pim", "PIM, for each VRF's rendezvous point (Protocols)"),
        ("/igmp-snooping", "IGMP snooping, for snooping in the VXLAN VLANs"),
    ),
    scroll_tables=True,
    stored_login=True,
)


def render_trm_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Multicast over VXLAN page, with a message."""
    return render_site_page(request, username, TRM, SITE, error=error, notice=notice, form=form)


@router.get("/trm", response_class=HTMLResponse)
def trm_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /trm``: multicast over VXLAN's settings and layer 3 VNIs, read live; every role looks,
    operators and admins change."""
    return render_trm_page(request, username)


@router.post("/trm/change", response_class=HTMLResponse)
def trm_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Multicast over VXLAN page. Without confirm=yes, asks first."""
    return site_change(request, username, form, TRM, SITE)
