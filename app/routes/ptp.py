"""The PTP page: the switch's PTP clock, the ports that run PTP with their state and
counters, and the changes its forms make, on the same parts as the Monitor sessions page.

``GET /ptp`` shows it; every change goes through ``POST /ptp/change`` with the same form
fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a
confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.ptp import PTP, PtpPage, build_ptp_change, load_ptp_page
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

PTP_CHANGES_OFF = (
    "PTP changes are off. An NXray admin turns on changes on the Switch page first, with "
    "the broad role or a stored admin login: the limited role has no room for them."
)


def check_ptp_place(page: PtpPage, ident: dict[str, str]) -> None:
    """Refuse a port that is not one of the switch's front ports (PTP does not run on
    port-channels)."""
    port = ident.get("port", "").strip()
    if port and port not in page.ports:
        raise ValueError(f"{port} is not a front port of this switch; PTP runs on front ports")


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_ptp(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/ptp",
    back_url="/switch-admin",
    back_label="Switch admin",
    save_back={"back": "ptp"},
    changes_name="PTP",
    subject="PTP",
    off_message=PTP_CHANGES_OFF,
    enabled=lambda connection: connection.ptp_changes_enabled,
    load=load_ptp_page,
    check_place=check_ptp_place,
    build=build_ptp_change,
    send=_send,
    stored_login=True,
)


def render_ptp_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the PTP page, with a message."""
    return render_site_page(request, username, PTP, SITE, error=error, notice=notice, form=form)


@router.get("/ptp", response_class=HTMLResponse)
def ptp_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /ptp``: the PTP clock and the ports that run PTP, read live; every role looks,
    operators and admins change."""
    return render_ptp_page(request, username)


@router.post("/ptp/change", response_class=HTMLResponse)
def ptp_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the PTP page. Without confirm=yes, asks first."""
    return site_change(request, username, form, PTP, SITE)
