"""The UDLD page: each port's UDLD state and neighbours, and the changes its forms make,
on the same parts as the Monitor sessions page.

``GET /udld`` shows it; every change goes through ``POST /udld/change`` with the same
form fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``)
and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.udld import UDLD, UdldPage, build_udld_change, load_udld_page

router = APIRouter()

UDLD_CHANGES_OFF = (
    "UDLD changes are off. An NXray admin turns on changes on the Switch page first, with "
    "the broad role or a stored admin login: the limited role has no room for them."
)


def check_udld_place(page: UdldPage, ident: dict[str, str]) -> None:
    """Refuse a port that is not a front port of the switch (UDLD is not set on a
    port-channel)."""
    port = ident.get("port", "").strip()
    if port and port not in page.ports:
        raise ValueError(f"{port} is not a front port on the switch; UDLD is set per front port")


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_udld(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/udld",
    back_url="/ports",
    back_label="Ports",
    save_back={"back": "udld"},
    changes_name="UDLD",
    subject="UDLD",
    off_message=UDLD_CHANGES_OFF,
    enabled=lambda connection: connection.udld_changes_enabled,
    load=load_udld_page,
    check_place=check_udld_place,
    build=build_udld_change,
    send=_send,
    scroll_tables=True,
)


def render_udld_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the UDLD page, with a message."""
    return render_site_page(request, username, UDLD, SITE, error=error, notice=notice, form=form)


@router.get("/udld", response_class=HTMLResponse)
def udld_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /udld``: each port's UDLD state and neighbours, read live; every role looks,
    operators and admins change."""
    return render_udld_page(request, username)


@router.post("/udld/change", response_class=HTMLResponse)
def udld_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the UDLD page. Without confirm=yes, asks first."""
    return site_change(request, username, form, UDLD, SITE)
