"""The Spanning tree page: every tree and port the switch reports, and the changes
its forms make, on the same parts as the routing protocol pages.

``GET /spanning-tree`` shows it; every change goes through ``POST
/spanning-tree/change`` with the same form fields as a protocol page (scope,
setting, action, ``id_<name>``, ``v_<name>``) and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.spanning_tree import (
    SPANNING_TREE,
    SpanningTreePage,
    build_stp_change,
    load_spanning_tree_page,
)

router = APIRouter()

STP_CHANGES_OFF = (
    "Spanning tree changes are off. An NXray admin turns them on on the Switch page "
    "first: NXray's role on the switch does not allow them yet."
)


def check_stp_place(page: SpanningTreePage, ident: dict[str, str]) -> None:
    """Refuse a port or VLAN the switch does not have (or that is routed)."""
    port = ident.get("port", "").strip()
    if port and port not in page.ports:
        raise ValueError(
            f"{port} is not a front port or port-channel carrying VLANs on the switch "
            "(routed ports have no spanning tree)"
        )
    vlan = ident.get("vlan", "").strip()
    if vlan and vlan not in page.vlans:
        raise ValueError(f"the switch has no VLAN {vlan}; make it on the VLANs page first")


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_spanning_tree(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/spanning-tree",
    back_url="/vlans",
    back_label="VLANs",
    save_back={"back": "spanning-tree"},
    changes_name="Spanning tree",
    subject="spanning tree",
    off_message=STP_CHANGES_OFF,
    enabled=lambda connection: connection.stp_changes_enabled,
    load=load_spanning_tree_page,
    check_place=check_stp_place,
    build=build_stp_change,
    send=_send,
)


def render_spanning_tree_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Spanning tree page, with a message."""
    return render_site_page(
        request, username, SPANNING_TREE, SITE, error=error, notice=notice, form=form
    )


@router.get("/spanning-tree", response_class=HTMLResponse)
def spanning_tree_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /spanning-tree``: the trees, ports and settings, read live; every role
    looks, operators and admins change."""
    return render_spanning_tree_page(request, username)


@router.post("/spanning-tree/change", response_class=HTMLResponse)
def spanning_tree_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Spanning tree page. Without confirm=yes, asks first."""
    return site_change(request, username, form, SPANNING_TREE, SITE)
