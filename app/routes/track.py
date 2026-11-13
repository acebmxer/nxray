"""The Tracked objects page: the objects that follow an interface, a route, an IP SLA
entry or a list of other objects, with their state, and the changes its forms make, on the
same parts as the Monitor sessions page.

``GET /track`` shows it; every change goes through ``POST /track/change`` with the same
form fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a
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
from app.track import TRACK, build_track_change, check_track_place, load_track_page

router = APIRouter()

TRACK_CHANGES_OFF = (
    "Tracked object changes are off. An NXray admin turns on changes on the Switch page "
    "first, with the broad role or a stored admin login: the limited role has no rules for "
    "them."
)


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_track(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/track",
    back_url="/routing",
    back_label="Routing",
    save_back={"back": "track"},
    changes_name="Tracked object",
    subject="tracked objects",
    off_message=TRACK_CHANGES_OFF,
    enabled=lambda connection: connection.track_changes_enabled,
    load=load_track_page,
    check_place=check_track_place,
    build=build_track_change,
    send=_send,
    links=(
        ("/ip-sla", "IP SLA, for the entries an object follows"),
        ("/routing/protocols", "Routing protocols: HSRP and VRRP groups follow these objects"),
        ("/eem", "EEM, whose applets can act when an object changes"),
    ),
    stored_login=True,
)


def render_track_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Tracked objects page, with a message."""
    return render_site_page(request, username, TRACK, SITE, error=error, notice=notice, form=form)


@router.get("/track", response_class=HTMLResponse)
def track_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /track``: the tracked objects with their state, read live; every role looks,
    operators and admins change."""
    return render_track_page(request, username)


@router.post("/track/change", response_class=HTMLResponse)
def track_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Tracked objects page. Without confirm=yes, asks first."""
    return site_change(request, username, form, TRACK, SITE)
