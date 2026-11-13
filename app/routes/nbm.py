"""The Non-blocking multicast page: NBM's mode, flow defaults, flow policies, host policies,
flow definitions and external links, with the flows and the bandwidth left, and the changes
its forms make, on the same parts as the Monitor sessions page.

``GET /nbm`` shows it; every change goes through ``POST /nbm/change`` with the same form
fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a
confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nbm import NBM, build_nbm_change, check_nbm_place, load_nbm_page
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

NBM_CHANGES_OFF = (
    "Non-blocking multicast changes are off. An NXray admin turns on changes on the Switch page "
    "first, with the broad role or a stored admin login: the limited role has no rules for "
    "them."
)


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_nbm(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/nbm",
    back_url="/routing",
    back_label="Routing",
    save_back={"back": "nbm"},
    changes_name="Non-blocking multicast",
    subject="non-blocking multicast",
    off_message=NBM_CHANGES_OFF,
    enabled=lambda connection: connection.multicast_changes_enabled,
    load=load_nbm_page,
    check_place=check_nbm_place,
    build=build_nbm_change,
    send=_send,
    links=(
        ("/routing/protocols/pim", "PIM, which sets the flows up (Protocols)"),
        ("/igmp-snooping", "IGMP snooping"),
        ("/security/acls", "Security: the TCAM regions NBM needs"),
    ),
    scroll_tables=True,
    stored_login=True,
)


def render_nbm_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Non-blocking multicast page, with a message."""
    return render_site_page(request, username, NBM, SITE, error=error, notice=notice, form=form)


@router.get("/nbm", response_class=HTMLResponse)
def nbm_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /nbm``: NBM's settings, policies, flows and bandwidth, read live; every role looks,
    operators and admins change."""
    return render_nbm_page(request, username)


@router.post("/nbm/change", response_class=HTMLResponse)
def nbm_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Non-blocking multicast page. Without confirm=yes, asks first."""
    return site_change(request, username, form, NBM, SITE)
