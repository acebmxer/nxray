"""The Monitor sessions page: SPAN and ERSPAN sessions the switch reports, and the
changes its forms make, on the same parts as the routing protocol pages.

``GET /monitor`` shows it; every change goes through ``POST /monitor/change`` with the
same form fields as a protocol page (scope, setting, action, ``id_<name>``,
``v_<name>``) and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.monitor import MONITOR, MonitorPage, build_monitor_change, load_monitor_page
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

MONITOR_CHANGES_OFF = (
    "Monitor session changes are off. An NXray admin turns on changes on the Switch page "
    "first, with the broad role or a stored admin login: the limited role has no room "
    "for them."
)


def check_monitor_place(page: MonitorPage, ident: dict[str, str]) -> None:
    """Refuse a port the switch does not have (naming it would be refused anyway, but
    only after the lines before it ran)."""
    port = ident.get("port", "").strip()
    if port and page.ports and port not in page.ports:
        raise ValueError(f"the switch has no port {port}")


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_monitor(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/monitor",
    back_url="/ports",
    back_label="Ports",
    save_back={"back": "monitor"},
    changes_name="Monitor session",
    subject="monitor sessions",
    off_message=MONITOR_CHANGES_OFF,
    enabled=lambda connection: connection.monitor_changes_enabled,
    load=load_monitor_page,
    check_place=check_monitor_place,
    build=build_monitor_change,
    send=_send,
)


def render_monitor_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Monitor sessions page, with a message."""
    return render_site_page(request, username, MONITOR, SITE, error=error, notice=notice, form=form)


@router.get("/monitor", response_class=HTMLResponse)
def monitor_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /monitor``: the SPAN and ERSPAN sessions, read live; every role looks,
    operators and admins change."""
    return render_monitor_page(request, username)


@router.post("/monitor/change", response_class=HTMLResponse)
def monitor_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Monitor sessions page. Without confirm=yes, asks first."""
    return site_change(request, username, form, MONITOR, SITE)
