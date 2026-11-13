"""The Maintenance mode page, with the changes its forms make, on the same parts as the Monitor
sessions page.

``GET /maintenance`` shows it; every change goes through ``POST /maintenance/change`` with the
same form fields as a protocol page (scope, setting, action, ``id_<name>``,
``v_<name>``) and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.maintenance import (
    MAINTENANCE,
    build_maintenance_change,
    check_maintenance_place,
    load_maintenance_page,
)
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.switch_connection import SwitchConnection

router = APIRouter()

MAINTENANCE_CHANGES_OFF = (
    "Maintenance mode changes are off. An NXray admin turns on changes on the Switch "
    "page first, with the broad role or a stored admin login: the limited role has no rules "
    "for them."
)

ROLE_WITHOUT_SNAPSHOTS = (
    "Not run: NXray's broad role on the switch was written before it allowed taking and "
    "deleting a snapshot, so the switch refuses them. An NXray admin presses Update the port "
    "list on the Switch page first."
)


def maintenance_needs(connection: SwitchConnection, scope: str, setting: str) -> str:
    """Why the role may not take or delete a snapshot yet: a broad role written before it
    allowed them ("" when it may). Comparing two is a show command and needs no rule."""
    if scope == "snapshot" and connection.broad_role_without_snapshots:
        return ROLE_WITHOUT_SNAPSHOTS
    return ""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> str | None:
    return client.configure_maintenance(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/maintenance",
    back_url="/features",
    back_label="Features",
    save_back={"back": "maintenance"},
    changes_name="Maintenance mode",
    subject="Maintenance mode",
    off_message=MAINTENANCE_CHANGES_OFF,
    enabled=lambda connection: connection.maintenance_changes_enabled,
    load=load_maintenance_page,
    check_place=check_maintenance_place,
    build=build_maintenance_change,
    send=_send,
    needs=maintenance_needs,
    stored_login=True,
)


def render_maintenance_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Maintenance mode page, with a message."""
    return render_site_page(
        request, username, MAINTENANCE, SITE, error=error, notice=notice, form=form
    )


@router.get("/maintenance", response_class=HTMLResponse)
def maintenance_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /maintenance``: read live; every role looks, operators and admins change."""
    return render_maintenance_page(request, username)


@router.post("/maintenance/change", response_class=HTMLResponse)
def maintenance_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Maintenance mode page. Without confirm=yes, asks first."""
    return site_change(request, username, form, MAINTENANCE, SITE)
