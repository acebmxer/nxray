"""The VXLAN page: the NVE interface, its peers and VNIs the switch reports, and the
changes its forms make, on the same parts as the routing protocol pages.

``GET /vxlan`` shows it; every change goes through ``POST /vxlan/change`` with the same
form fields as a protocol page (scope, setting, action, ``id_<name>``,
``v_<name>``) and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.vxlan import VXLAN, VxlanPage, build_vxlan_change, load_vxlan_page

router = APIRouter()

VXLAN_CHANGES_OFF = (
    "VXLAN changes are off. An NXray admin turns them on on the Switch page "
    "first: NXray's role on the switch does not allow them yet, and its port list must "
    "name the NVE interface, which the switch takes only while the nve feature is on "
    "(Features page, then Update the port list on the Switch page)."
)


def check_vxlan_place(page: VxlanPage, ident: dict[str, str]) -> None:
    """Refuse a VLAN or VRF the switch does not have (naming it would make one)."""
    vlan = ident.get("vlan", "").strip()
    if vlan and vlan not in page.vlans:
        raise ValueError(f"the switch has no VLAN {vlan}; make it on the VLANs page first")
    vrf = ident.get("vrf", "").strip()
    if vrf and vrf not in page.vrfs:
        raise ValueError(f"the switch has no VRF {vrf}; make it on the Routing page first")


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_vxlan(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/vxlan",
    back_url="/vlans",
    back_label="VLANs",
    save_back={"back": "vxlan"},
    changes_name="VXLAN",
    subject="VXLAN",
    off_message=VXLAN_CHANGES_OFF,
    enabled=lambda connection: connection.vxlan_changes_enabled,
    load=load_vxlan_page,
    check_place=check_vxlan_place,
    build=build_vxlan_change,
    send=_send,
)


def render_vxlan_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the VXLAN page, with a message."""
    return render_site_page(request, username, VXLAN, SITE, error=error, notice=notice, form=form)


@router.get("/vxlan", response_class=HTMLResponse)
def vxlan_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /vxlan``: the NVE interface, peers and VNIs, read live; every role looks,
    operators and admins change."""
    return render_vxlan_page(request, username)


@router.post("/vxlan/change", response_class=HTMLResponse)
def vxlan_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the VXLAN page. Without confirm=yes, asks first."""
    return site_change(request, username, form, VXLAN, SITE)
