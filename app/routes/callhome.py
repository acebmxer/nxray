"""The Call Home page: the contact details, the destination profiles, the transport and a
test message, and the changes its forms make, on the same parts as the Monitor sessions
page.

``GET /callhome`` shows it; every change goes through ``POST /callhome/change`` with the
same form fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``)
and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.callhome import CALLHOME, CallhomePage, build_callhome_change, load_callhome_page
from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

CALLHOME_CHANGES_OFF = (
    "Call Home changes are off. An NXray admin turns on changes on the Switch page first, "
    "with the broad role or a stored admin login: the limited role has no room for them."
)


def check_callhome_place(page: CallhomePage, ident: dict[str, str]) -> None:
    """Nothing to check: a profile's name is the page's only place value, and a new name
    makes a new profile."""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_callhome(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/callhome",
    back_url="/switch-admin",
    back_label="Switch admin",
    save_back={"back": "callhome"},
    changes_name="Call Home",
    subject="Call Home",
    off_message=CALLHOME_CHANGES_OFF,
    enabled=lambda connection: connection.callhome_changes_enabled,
    load=load_callhome_page,
    check_place=check_callhome_place,
    build=build_callhome_change,
    send=_send,
    stored_login=True,
)


def render_callhome_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Call Home page, with a message."""
    return render_site_page(
        request, username, CALLHOME, SITE, error=error, notice=notice, form=form
    )


@router.get("/callhome", response_class=HTMLResponse)
def callhome_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /callhome``: Call Home's state, contact details, transport and destination
    profiles, read live; every role looks, operators and admins change."""
    return render_callhome_page(request, username)


@router.post("/callhome/change", response_class=HTMLResponse)
def callhome_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Call Home page. Without confirm=yes, asks first."""
    return site_change(request, username, form, CALLHOME, SITE)
