"""The Priority flow control page: each port's PFC mode and pause counters, and the
changes its forms make, on the same parts as the Monitor sessions page.

``GET /pfc`` shows it; every change goes through ``POST /pfc/change`` with the same form
fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a
confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.pfc import PFC, PfcPage, build_pfc_change, load_pfc_page
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

PFC_CHANGES_OFF = (
    "Priority flow control changes are off. An NXray admin turns on changes on the Switch "
    "page first, with the broad role or a stored admin login: the limited role has no room "
    "for them."
)


def check_pfc_place(page: PfcPage, ident: dict[str, str]) -> None:
    """Refuse a port the switch does not have."""
    port = ident.get("port", "").strip()
    if port and page.ports and port not in page.ports:
        raise ValueError(f"the switch has no port {port}")


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_pfc(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/pfc",
    back_url="/ports",
    back_label="Ports",
    save_back={"back": "pfc"},
    changes_name="Priority flow control",
    subject="priority flow control",
    off_message=PFC_CHANGES_OFF,
    enabled=lambda connection: connection.pfc_changes_enabled,
    load=load_pfc_page,
    check_place=check_pfc_place,
    build=build_pfc_change,
    send=_send,
    scroll_tables=True,
)


def render_pfc_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Priority flow control page, with a message."""
    return render_site_page(request, username, PFC, SITE, error=error, notice=notice, form=form)


@router.get("/pfc", response_class=HTMLResponse)
def pfc_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /pfc``: each port's PFC mode and pause counters, read live; every role looks,
    operators and admins change."""
    return render_pfc_page(request, username)


@router.post("/pfc/change", response_class=HTMLResponse)
def pfc_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Priority flow control page. Without confirm=yes, asks first."""
    return site_change(request, username, form, PFC, SITE)
