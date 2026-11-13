"""The VM Tracker page: the vCenter connections, the VMs on each port and the ports it is
off on, and the changes its forms make (syncing a connection now too), on the same parts as
the Monitor sessions page.

``GET /vmtracker`` shows it; every change goes through ``POST /vmtracker/change`` with the same form
fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a confirm
page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.switch_connection import SwitchConnection
from app.vmtracker import (
    VMTRACKER,
    build_vmtracker_change,
    check_vmtracker_place,
    load_vmtracker_page,
)

router = APIRouter()

VMTRACKER_CHANGES_OFF = (
    "VM Tracker changes are off. An NXray admin turns on changes on the Switch "
    "page first, with the broad role or a stored admin login: the limited role has no rules "
    "for them."
)
ROLE_WITHOUT_VMTRACKER_REFRESH = (
    "Not changed: NXray's broad role on the switch was written before it allowed syncing a "
    "VM Tracker connection now, so the switch refuses it. An NXray admin presses Update the "
    "port list on the Switch page first."
)


def vmtracker_needs(connection: SwitchConnection, scope: str, setting: str) -> str:
    """Why the role may not sync a connection now yet: a broad role written before it
    allowed it ("" when it may)."""
    if scope == "sync" and connection.broad_role_without_vmtracker_refresh:
        return ROLE_WITHOUT_VMTRACKER_REFRESH
    return ""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_vmtracker(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/vmtracker",
    back_url="/vlans",
    back_label="VLANs",
    save_back={"back": "vmtracker"},
    changes_name="VM Tracker",
    subject="VM Tracker",
    off_message=VMTRACKER_CHANGES_OFF,
    enabled=lambda connection: connection.layer2_changes_enabled,
    load=load_vmtracker_page,
    check_place=check_vmtracker_place,
    build=build_vmtracker_change,
    send=_send,
    links=(
        ("/vlans", "VLANs, which VM Tracker makes on the ports"),
        ("/evb", "Edge Virtual Bridging, the other way servers announce their VMs"),
    ),
    needs=vmtracker_needs,
    scroll_tables=True,
    stored_login=True,
)


def render_vmtracker_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the VM Tracker page, with a message."""
    return render_site_page(
        request, username, VMTRACKER, SITE, error=error, notice=notice, form=form
    )


@router.get("/vmtracker", response_class=HTMLResponse)
def vmtracker_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /vmtracker``: the vCenter connections and the VMs on each port, read live; every role
    looks, operators and admins change."""
    return render_vmtracker_page(request, username)


@router.post("/vmtracker/change", response_class=HTMLResponse)
def vmtracker_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the VM Tracker page. Without confirm=yes, asks first."""
    return site_change(request, username, form, VMTRACKER, SITE)
