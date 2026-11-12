"""The Telemetry page: the destination profile, destination groups, sensor groups and
subscriptions, the collectors with their state, and the changes its forms make, on the
same parts as the Monitor sessions page.

``GET /telemetry`` shows it; every change goes through ``POST /telemetry/change`` with the
same form fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``)
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
from app.telemetry import TELEMETRY, TelemetryPage, build_telemetry_change, load_telemetry_page

router = APIRouter()

TELEMETRY_CHANGES_OFF = (
    "Telemetry changes are off. An NXray admin turns on changes on the Switch page first, "
    "with the broad role or a stored admin login: the limited role has no room for them."
)


def check_telemetry_place(page: TelemetryPage, ident: dict[str, str]) -> None:
    """Nothing to refuse: naming a group the switch lacks makes it, as the switch does."""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_telemetry(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/telemetry",
    back_url="/switch-admin",
    back_label="Switch admin",
    save_back={"back": "telemetry"},
    changes_name="Telemetry",
    subject="telemetry",
    off_message=TELEMETRY_CHANGES_OFF,
    enabled=lambda connection: connection.telemetry_changes_enabled,
    load=load_telemetry_page,
    check_place=check_telemetry_place,
    build=build_telemetry_change,
    send=_send,
    scroll_tables=True,
    stored_login=True,
)


def render_telemetry_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Telemetry page, with a message."""
    return render_site_page(
        request, username, TELEMETRY, SITE, error=error, notice=notice, form=form
    )


@router.get("/telemetry", response_class=HTMLResponse)
def telemetry_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /telemetry``: the telemetry groups and collectors, read live; every role looks,
    operators and admins change."""
    return render_telemetry_page(request, username)


@router.post("/telemetry/change", response_class=HTMLResponse)
def telemetry_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Telemetry page. Without confirm=yes, asks first."""
    return site_change(request, username, form, TELEMETRY, SITE)
