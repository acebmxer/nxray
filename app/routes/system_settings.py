"""The Switch-wide settings page, with the changes its forms make, on the same parts as the
Monitor sessions page.

``GET /system-settings`` shows it; every change goes through ``POST /system-settings/change``
with the same form fields as a protocol page (scope, setting, action, ``id_<name>``,
``v_<name>``) and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.system_settings import (
    SYSTEM_SETTINGS,
    build_system_settings_change,
    check_system_settings_place,
    load_system_settings_page,
)

router = APIRouter()

SYSTEM_SETTINGS_CHANGES_OFF = (
    "Switch-wide settings changes are off. An NXray admin turns on changes on the Switch "
    "page first, with the broad role or a stored admin login: the limited role has no rules "
    "for them."
)


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_system_settings(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/system-settings",
    back_url="/switch",
    back_label="Switch",
    save_back={"back": "system-settings"},
    changes_name="Switch-wide settings",
    subject="Switch-wide settings",
    off_message=SYSTEM_SETTINGS_CHANGES_OFF,
    enabled=lambda connection: connection.system_settings_changes_enabled,
    load=load_system_settings_page,
    check_place=check_system_settings_place,
    build=build_system_settings_change,
    send=_send,
    stored_login=True,
)


def render_system_settings_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Switch-wide settings page, with a message."""
    return render_site_page(
        request, username, SYSTEM_SETTINGS, SITE, error=error, notice=notice, form=form
    )


@router.get("/system-settings", response_class=HTMLResponse)
def system_settings_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /system-settings``: read live; every role looks, operators and admins change."""
    return render_system_settings_page(request, username)


@router.post("/system-settings/change", response_class=HTMLResponse)
def system_settings_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Switch-wide settings page. Without confirm=yes, asks first."""
    return site_change(request, username, form, SYSTEM_SETTINGS, SITE)
