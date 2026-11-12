"""The EEM page: the applets, environment variables, system policies and recent EEM
events, and the changes its forms make, on the same parts as the Monitor sessions page.

``GET /eem`` shows it; every change goes through ``POST /eem/change`` with the same form
fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a
confirm page first. Changes need the stored admin login: an applet's commands run as the
switch's admin, so NXray's broad role denies EEM.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.eem import EEM, EemPage, build_eem_change, load_eem_page
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

EEM_CHANGES_OFF = (
    "EEM changes need the stored admin login. An applet's commands run as the switch's "
    "admin, so NXray's broad role does not allow EEM. An NXray admin picks Limited role, "
    "and store the switch admin login, on the Switch page."
)


def check_eem_place(page: EemPage, ident: dict[str, str]) -> None:
    """Refuse a system policy the switch does not have."""
    policy = ident.get("policy", "").strip()
    if policy and policy not in page.policies:
        raise ValueError(f"the switch has no system policy {policy}")


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_eem(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/eem",
    back_url="/switch-admin",
    back_label="Switch admin",
    save_back={"back": "eem"},
    changes_name="EEM",
    subject="EEM",
    off_message=EEM_CHANGES_OFF,
    enabled=lambda connection: connection.eem_changes_enabled,
    load=load_eem_page,
    check_place=check_eem_place,
    build=build_eem_change,
    send=_send,
    stored_login=True,
)


def render_eem_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the EEM page, with a message."""
    return render_site_page(request, username, EEM, SITE, error=error, notice=notice, form=form)


@router.get("/eem", response_class=HTMLResponse)
def eem_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /eem``: the applets, variables, system policies and recent events, read live;
    every role looks, operators and admins change (with the stored admin login)."""
    return render_eem_page(request, username)


@router.post("/eem/change", response_class=HTMLResponse)
def eem_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the EEM page. Without confirm=yes, asks first."""
    return site_change(request, username, form, EEM, SITE)
