"""The NAT page: the inside and outside interfaces, static and dynamic translations, pools,
timeouts and limits, the translations and counters, whether the switch has TCAM space for
NAT, and the changes its forms make, on the same parts as the Monitor sessions page.

``GET /nat`` shows it; every change goes through ``POST /nat/change`` with the same form
fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a
confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nat import NAT, build_nat_change, check_nat_place, load_nat_page
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.switch_connection import SwitchConnection

router = APIRouter()

NAT_CHANGES_OFF = (
    "NAT changes are off. An NXray admin turns on changes on the Switch page first, with "
    "the broad role or a stored admin login: the limited role has no rules for them."
)
ROLE_WITHOUT_NAT_CLEAR = (
    "Not changed: NXray's broad role on the switch was written before it allowed clearing "
    "NAT's translations and counters, so the switch refuses it. An NXray admin presses "
    "Update the port list on the Switch page first."
)


def nat_needs(connection: SwitchConnection, scope: str, setting: str) -> str:
    """Why the role may not clear NAT's translations or counters yet: a broad role written
    before it allowed them ("" when it may)."""
    if scope == "clear" and connection.broad_role_without_nat_clear:
        return ROLE_WITHOUT_NAT_CLEAR
    return ""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_nat(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/nat",
    back_url="/routing",
    back_label="Routing",
    save_back={"back": "nat"},
    changes_name="NAT",
    subject="NAT",
    off_message=NAT_CHANGES_OFF,
    enabled=lambda connection: connection.nat_changes_enabled,
    load=load_nat_page,
    check_place=check_nat_place,
    build=build_nat_change,
    send=_send,
    links=(
        ("/security/acls", "ACLs, for the traffic a dynamic translation takes, and TCAM space"),
    ),
    needs=nat_needs,
    scroll_tables=True,
    stored_login=True,
)


def render_nat_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the NAT page, with a message."""
    return render_site_page(request, username, NAT, SITE, error=error, notice=notice, form=form)


@router.get("/nat", response_class=HTMLResponse)
def nat_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /nat``: the NAT setup, translations and counters, read live; every role looks,
    operators and admins change."""
    return render_nat_page(request, username)


@router.post("/nat/change", response_class=HTMLResponse)
def nat_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the NAT page. Without confirm=yes, asks first."""
    return site_change(request, username, form, NAT, SITE)
