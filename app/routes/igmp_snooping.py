"""The IGMP snooping page: snooping switch-wide and per VLAN, the queriers, router ports,
static groups, the groups the hosts joined and the counters, and the changes its forms make
(clearing a VLAN's groups and counters too), on the same parts as the Monitor sessions
page.

``GET /igmp-snooping`` shows it; every change goes through ``POST /igmp-snooping/change``
with the same form fields as a protocol page (scope, setting, action, ``id_<name>``,
``v_<name>``) and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.igmp_snooping import (
    IGMP_SNOOPING,
    build_snooping_change,
    check_snooping_place,
    load_snooping_page,
)
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.switch_connection import SwitchConnection

router = APIRouter()

SNOOPING_CHANGES_OFF = (
    "IGMP snooping changes are off. An NXray admin turns on changes on the Switch page "
    "first, with the broad role or a stored admin login: the limited role has no rules for "
    "them."
)
ROLE_WITHOUT_SNOOPING_CLEAR = (
    "Not changed: NXray's broad role on the switch was written before it allowed clearing "
    "IGMP snooping's groups and counters, so the switch refuses it. An NXray admin presses "
    "Update the port list on the Switch page first."
)


def snooping_needs(connection: SwitchConnection, scope: str, setting: str) -> str:
    """Why the role may not clear a VLAN's groups or counters yet: a broad role written
    before it allowed them ("" when it may)."""
    if scope == "clear" and connection.broad_role_without_snooping_clear:
        return ROLE_WITHOUT_SNOOPING_CLEAR
    return ""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_igmp_snooping(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/igmp-snooping",
    back_url="/vlans",
    back_label="VLANs",
    save_back={"back": "igmp-snooping"},
    changes_name="IGMP snooping",
    subject="IGMP snooping",
    off_message=SNOOPING_CHANGES_OFF,
    enabled=lambda connection: connection.multicast_changes_enabled,
    load=load_snooping_page,
    check_place=check_snooping_place,
    build=build_snooping_change,
    send=_send,
    links=(
        ("/vlans", "VLANs, which snooping works in"),
        ("/routing/protocols/igmp", "IGMP on routed interfaces (Protocols)"),
        ("/trm", "Multicast over VXLAN"),
    ),
    needs=snooping_needs,
    scroll_tables=True,
    stored_login=True,
)


def render_snooping_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the IGMP snooping page, with a message."""
    return render_site_page(
        request, username, IGMP_SNOOPING, SITE, error=error, notice=notice, form=form
    )


@router.get("/igmp-snooping", response_class=HTMLResponse)
def snooping_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /igmp-snooping``: IGMP snooping's settings, queriers, router ports and groups, read
    live; every role looks, operators and admins change."""
    return render_snooping_page(request, username)


@router.post("/igmp-snooping/change", response_class=HTMLResponse)
def snooping_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the IGMP snooping page. Without confirm=yes, asks first."""
    return site_change(request, username, form, IGMP_SNOOPING, SITE)
