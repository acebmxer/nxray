"""The VXLAN OAM page: ping, traceroute and pathtrace across the VXLAN fabric with what the
switch printed, the profiles they use, loop detection and the tools' counters, and the changes
its forms make, on the same parts as the Monitor sessions page.

``GET /ngoam`` shows it; every change and every tool run goes through ``POST /ngoam/change``
with the same form fields as a protocol page (scope, setting, action, ``id_<name>``,
``v_<name>``) and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.ngoam import NGOAM, build_ngoam_change, check_ngoam_place, load_ngoam_page
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.switch_connection import SwitchConnection

router = APIRouter()

NGOAM_CHANGES_OFF = (
    "VXLAN OAM changes and tools are off. An NXray admin turns on changes on the Switch "
    "page first, with the broad role or a stored admin login: the limited role has no rules "
    "for them."
)
ROLE_WITHOUT_NGOAM_TOOLS = (
    "Not run: NXray's broad role on the switch was written before it allowed VXLAN OAM's "
    "ping, traceroute and pathtrace, so the switch refuses them. An NXray admin presses Update "
    "the port list on the Switch page first."
)
# The scopes whose commands are typed outside configuration mode (NGOAM_RULES).
_EXEC_SCOPES = ("ping", "traceroute", "pathtrace", "counters", "loop_now")


def ngoam_needs(connection: SwitchConnection, scope: str, setting: str) -> str:
    """Why the role may not run a tool, clear the counters or probe for loops yet: a broad
    role written before it allowed them ("" when it may)."""
    if scope in _EXEC_SCOPES and connection.broad_role_without_ngoam_tools:
        return ROLE_WITHOUT_NGOAM_TOOLS
    return ""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> str | None:
    return client.configure_ngoam(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/ngoam",
    back_url="/vxlan",
    back_label="VXLAN",
    save_back={"back": "ngoam"},
    changes_name="VXLAN OAM",
    subject="VXLAN OAM",
    off_message=NGOAM_CHANGES_OFF,
    enabled=lambda connection: connection.vxlan_extra_changes_enabled,
    load=load_ngoam_page,
    check_place=check_ngoam_place,
    build=build_ngoam_change,
    send=_send,
    links=(
        ("/vxlan", "VXLAN, the VNIs and peers the tools reach"),
        ("/routing", "Routing, for the VRFs"),
    ),
    needs=ngoam_needs,
    scroll_tables=True,
    stored_login=True,
)


def render_ngoam_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the VXLAN OAM page, with a message."""
    return render_site_page(request, username, NGOAM, SITE, error=error, notice=notice, form=form)


@router.get("/ngoam", response_class=HTMLResponse)
def ngoam_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /ngoam``: the VXLAN OAM profiles, settings and counters, read live; every role
    looks, operators and admins change and run the tools."""
    return render_ngoam_page(request, username)


@router.post("/ngoam/change", response_class=HTMLResponse)
def ngoam_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change or tool run on the VXLAN OAM page. Without confirm=yes, asks first."""
    return site_change(request, username, form, NGOAM, SITE)
