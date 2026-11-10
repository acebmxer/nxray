"""The vPC page: the vPC domain, peer-link and vPCs the switch reports, and the
changes its forms make, on the same parts as the routing protocol pages.

``GET /vpc`` shows it; every change goes through ``POST /vpc/change`` with the same
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
from app.vpc import VPC, VpcPage, build_vpc_change, load_vpc_page

router = APIRouter()

VPC_CHANGES_OFF = (
    "vPC changes are off. An NXray admin turns them on on the Switch page "
    "first: NXray's role on the switch does not allow them yet."
)


def check_vpc_place(page: VpcPage, ident: dict[str, str]) -> None:
    """Refuse a port-channel the switch does not have (naming it would make one), and
    a second vPC domain (a switch has one)."""
    channel = ident.get("channel", "").strip()
    if channel and channel not in page.channels:
        raise ValueError(
            f"{channel} is not a switched port-channel on the switch; make it on the "
            "Port-channels page first"
        )
    domain = ident.get("domain", "").strip()
    if domain and page.domain and domain != page.domain:
        raise ValueError(
            f"the switch already has vPC domain {page.domain}; a switch has one vPC domain"
        )


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_vpc(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/vpc",
    back_url="/port-channels",
    back_label="Port-channels",
    save_back={"back": "vpc"},
    changes_name="vPC",
    subject="vPC",
    off_message=VPC_CHANGES_OFF,
    enabled=lambda connection: connection.vpc_changes_enabled,
    load=load_vpc_page,
    check_place=check_vpc_place,
    build=build_vpc_change,
    send=_send,
)


def render_vpc_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the vPC page, with a message."""
    return render_site_page(request, username, VPC, SITE, error=error, notice=notice, form=form)


@router.get("/vpc", response_class=HTMLResponse)
def vpc_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /vpc``: the domain, peer-link and vPCs, read live; every role looks,
    operators and admins change."""
    return render_vpc_page(request, username)


@router.post("/vpc/change", response_class=HTMLResponse)
def vpc_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the vPC page. Without confirm=yes, asks first."""
    return site_change(request, username, form, VPC, SITE)
