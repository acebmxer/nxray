"""The Switch admin page (hostname, clock and NTP, DNS, logging, SNMP, banner) and
the Switch log page, which shows the switch's own log.

``GET /switch-admin`` shows the settings; every change goes through ``POST
/switch-admin/change`` with the same form fields as a protocol page (scope,
setting, action, ``id_<name>``, ``v_<name>``) and a confirm page first.
``GET /switch-admin/log`` shows the newest lines of the switch's log file.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import login_required, operator_required, stored_switch, templates
from app.nxapi import DEFAULT_VRF, NxapiClient, NxapiCommandError
from app.port_changes import ROLE_VERSION_CLOCK_SOURCE
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.switch_admin import (
    LOG_LINES,
    SWITCH_ADMIN,
    SwitchAdminPage,
    build_admin_change,
    load_switch_admin_page,
    load_switch_log,
    parse_log,
)
from app.switch_choice import selected_switch_id
from app.switch_connection import ROLE_BROAD, SwitchConnection, set_switch_hostname
from app.switch_setup import read_switch

router = APIRouter()

ADMIN_CHANGES_OFF = (
    "Switch admin changes are off. An NXray admin turns them on on the Switch page "
    "first: NXray's role on the switch does not allow them yet."
)


def check_admin_place(page: SwitchAdminPage, ident: dict[str, str]) -> None:
    """Refuse a VRF the switch does not have."""
    for name in ("vrf", "context"):
        vrf = ident.get(name, "").strip()
        if vrf and vrf not in page.vrfs:
            raise ValueError(f"the switch has no VRF {vrf}")
    if ident.get("context", "").strip() == DEFAULT_VRF:
        raise ValueError("the default VRF has no configuration of its own")


ROLE_WITHOUT_CLOCK_SOURCE = (
    "Not changed: NXray's role on the switch was written before it could choose the clock "
    "source. An NXray admin presses Update on the Switch page, then try again."
)

CLOCK_SET_REFUSED = (
    "setting the time by hand is not allowed while the switch's clock follows NTP or PTP. "
    "Choose the Clock source none under Clock first (NTP and PTP then stop setting the "
    "clock), then set the time. The switch said: {said}"
)


def admin_needs(connection: SwitchConnection, scope: str, setting: str) -> str:
    """Why the role may not choose the clock source yet: a limited role written before
    version 21 (the broad role allows every configuration line) ("" when it may)."""
    if (
        setting == "clock_source"
        and connection.role_mode != ROLE_BROAD
        and connection.role_version < ROLE_VERSION_CLOCK_SOURCE
    ):
        return ROLE_WITHOUT_CLOCK_SOURCE
    return ""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    try:
        client.configure_switch_admin(change.scope, change.setting, change.action, ident, values)
    except NxapiCommandError as exc:
        if change.setting == "clock_set" and "not allowed in this vdc" in str(exc).lower():
            raise NxapiCommandError(CLOCK_SET_REFUSED.format(said=exc)) from exc
        raise


def _after(request: Request, change: ProtocolChange) -> None:
    """A new hostname is stored too, so the Switch page names the switch right."""
    if change.setting == "hostname" and change.action == "set":
        name = change.lines[-1].removeprefix("hostname ").strip()
        with open_db(request.app.state.settings.db_path) as conn:
            set_switch_hostname(conn, selected_switch_id(request), name)


SITE = ProtocolSite(
    url="/switch-admin",
    back_url="/",
    back_label="Dashboard",
    save_back={"back": "switch-admin"},
    changes_name="Switch admin",
    subject="the switch's settings",
    off_message=ADMIN_CHANGES_OFF,
    enabled=lambda connection: connection.admin_changes_enabled,
    load=load_switch_admin_page,
    check_place=check_admin_place,
    build=build_admin_change,
    send=_send,
    after=_after,
    needs=admin_needs,
    links=(("/switch-admin/log", "Switch log: the switch's own messages"),),
)


def render_switch_admin_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Switch admin page, with a message."""
    return render_site_page(
        request, username, SWITCH_ADMIN, SITE, error=error, notice=notice, form=form
    )


@router.get("/switch-admin", response_class=HTMLResponse)
def switch_admin_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /switch-admin``: the switch's name, clock, NTP, DNS, logging, SNMP and
    banner, read live; every role looks, operators and admins change."""
    return render_switch_admin_page(request, username)


@router.post("/switch-admin/change", response_class=HTMLResponse)
def switch_admin_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Switch admin page. Without confirm=yes, asks first."""
    return site_change(request, username, form, SWITCH_ADMIN, SITE)


@router.get("/switch-admin/log", response_class=HTMLResponse)
def switch_log_page(
    request: Request,
    username: str = Depends(login_required),
    lines: str = "200",
    search: str = "",
    level: str = "",
) -> Response:
    """``GET /switch-admin/log``: the newest lines of the switch's log, newest first.
    ``lines`` is how many to read (one of ``LOG_LINES``); ``search`` keeps the
    lines containing it, ``level`` (0-7) those of that severity or worse."""
    count = int(lines) if lines.isdigit() and int(lines) in LOG_LINES else 200
    worst = int(level) if level.isdigit() and int(level) <= 7 else None
    search = search[:100]
    connection, target, problem = stored_switch(request)
    status = output = None
    if target is not None:
        status, output = read_switch(
            target,
            lambda client: load_switch_log(client, count),
            transport=request.app.state.nxapi_transport,
        )
    return templates.TemplateResponse(
        request,
        "switch_log.html",
        {
            "username": username,
            "connection": connection,
            "status": status,
            "problem": problem,
            "log": parse_log(output, search, worst) if output is not None else None,
            "lines": count,
            "line_choices": LOG_LINES,
            "search": search,
            "level": "" if worst is None else str(worst),
        },
    )
