"""The Errdisable page: which causes the switch detects and recovers from, the recovery
interval, the ports err-disabled now, and the changes its forms make, on the same parts
as the Monitor sessions page.

``GET /errdisable`` shows it; every change goes through ``POST /errdisable/change`` with
the same form fields as a protocol page (scope, setting, action, ``v_<name>``) and a
confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.errdisable import ERRDISABLE, ErrdisablePage, build_errdisable_change, load_errdisable_page
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

ERRDISABLE_CHANGES_OFF = (
    "Errdisable changes are off. An NXray admin turns on changes on the Switch page first, "
    "with the broad role or a stored admin login: the limited role has no room for them."
)


def check_errdisable_place(page: ErrdisablePage, ident: dict[str, str]) -> None:
    """Nothing to check: the page's only place is the switch."""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_errdisable(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/errdisable",
    back_url="/ports",
    back_label="Ports",
    save_back={"back": "errdisable"},
    changes_name="Errdisable",
    subject="errdisable",
    off_message=ERRDISABLE_CHANGES_OFF,
    enabled=lambda connection: connection.errdisable_changes_enabled,
    load=load_errdisable_page,
    check_place=check_errdisable_place,
    build=build_errdisable_change,
    send=_send,
    stored_login=True,
)


def render_errdisable_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Errdisable page, with a message."""
    return render_site_page(
        request, username, ERRDISABLE, SITE, error=error, notice=notice, form=form
    )


@router.get("/errdisable", response_class=HTMLResponse)
def errdisable_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /errdisable``: detection, recovery and the err-disabled ports, read live; every
    role looks, operators and admins change."""
    return render_errdisable_page(request, username)


@router.post("/errdisable/change", response_class=HTMLResponse)
def errdisable_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Errdisable page. Without confirm=yes, asks first."""
    return site_change(request, username, form, ERRDISABLE, SITE)
