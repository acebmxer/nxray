"""The ITD page: the device groups with their nodes and probes, the services with their
state, and their counters, and the changes its forms make, on the same parts as the
Monitor sessions page.

``GET /itd`` shows it; every change goes through ``POST /itd/change`` with the same form
fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a
confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.itd import ITD, build_itd_change, check_itd_place, load_itd_page
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.switch_connection import SwitchConnection

router = APIRouter()

ITD_CHANGES_OFF = (
    "ITD changes are off. An NXray admin turns on changes on the Switch page first, with "
    "the broad role or a stored admin login: the limited role has no rules for them."
)
ROLE_WITHOUT_ITD_COUNTERS = (
    "Not changed: NXray's broad role on the switch was written before it allowed ITD's "
    "counters, so the switch refuses them. An NXray admin presses Update the port list on "
    "the Switch page first."
)


def itd_needs(connection: SwitchConnection, scope: str, setting: str) -> str:
    """Why the role may not change ITD's counters yet: a broad role written before it
    allowed them ("" when it may)."""
    if scope == "counters" and connection.broad_role_without_itd_statistics:
        return ROLE_WITHOUT_ITD_COUNTERS
    return ""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_itd(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/itd",
    back_url="/routing",
    back_label="Routing",
    save_back={"back": "itd"},
    changes_name="ITD",
    subject="ITD",
    off_message=ITD_CHANGES_OFF,
    enabled=lambda connection: connection.itd_changes_enabled,
    load=load_itd_page,
    check_place=check_itd_place,
    build=build_itd_change,
    send=_send,
    needs=itd_needs,
    stored_login=True,
)


def render_itd_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the ITD page, with a message."""
    return render_site_page(request, username, ITD, SITE, error=error, notice=notice, form=form)


@router.get("/itd", response_class=HTMLResponse)
def itd_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /itd``: the device groups, services and counters, read live; every role looks,
    operators and admins change."""
    return render_itd_page(request, username)


@router.post("/itd/change", response_class=HTMLResponse)
def itd_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the ITD page. Without confirm=yes, asks first."""
    return site_change(request, username, form, ITD, SITE)
