"""The AAA page: how people sign in, what is recorded, and the RADIUS and TACACS+ servers
and groups, and the changes its forms make, on the same parts as the Monitor sessions page.

``GET /aaa`` shows it; every change goes through ``POST /aaa/change`` with the same form
fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a
confirm page first. Changes need the stored admin login and an NXray admin: they decide
who may sign in to the switch, NXray's own account included.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.aaa import AAA, AaaPage, build_aaa_change, load_aaa_page
from app.dependencies import admin_required, login_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

AAA_CHANGES_OFF = (
    "AAA changes need the stored admin login. They decide who may sign in to the switch, "
    "NXray's own account included, so NXray's broad role does not allow them. An NXray "
    "admin picks Limited role, and store the switch admin login, on the Switch page."
)


def check_aaa_place(page: AaaPage, ident: dict[str, str]) -> None:
    """Nothing to refuse beforehand: a group or server named here is made by the change."""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_aaa(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/aaa",
    back_url="/switch-admin",
    back_label="Switch admin",
    save_back={"back": "aaa"},
    changes_name="AAA",
    subject="AAA",
    off_message=AAA_CHANGES_OFF,
    enabled=lambda connection: connection.aaa_changes_enabled,
    load=load_aaa_page,
    check_place=check_aaa_place,
    build=build_aaa_change,
    send=_send,
    stored_login=True,
    admin_only=True,
    stored_read=True,
)


def render_aaa_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the AAA page, with a message."""
    return render_site_page(request, username, AAA, SITE, error=error, notice=notice, form=form)


@router.get("/aaa", response_class=HTMLResponse)
def aaa_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /aaa``: sign-in and accounting, the RADIUS and TACACS+ servers and groups, read
    live; every role looks, NXray admins change (with the stored admin login)."""
    return render_aaa_page(request, username)


@router.post("/aaa/change", response_class=HTMLResponse)
def aaa_change(
    request: Request,
    username: str = Depends(admin_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the AAA page. Without confirm=yes, asks first."""
    return site_change(request, username, form, AAA, SITE)
