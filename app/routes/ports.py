"""The Ports page: every front-panel port, one port in detail, and port changes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import login_required, require_csrf, stored_switch, templates
from app.nxapi import (
    NxapiClient,
    NxapiCommandError,
    NxapiError,
    SwitchTarget,
    validate_description,
)
from app.ports import COUNTER_LABELS, Port, load_ports
from app.security import csrf_token
from app.switch_connection import SwitchConnection, set_unsaved_changes
from app.switch_setup import ConnectionStatus, connection_error, read_switch

router = APIRouter()
log = logging.getLogger("nxray.ports")

# The filters offered above the table, and which ports each keeps.
FILTERS = {
    "all": lambda port: True,
    "up": lambda port: port.up,
    "down": lambda port: not port.up,
    "errors": lambda port: port.errors > 0,
}

# What the change form on a port's page can ask for.
ACTIONS = ("description", "off", "on")


def _read_ports(
    request: Request,
) -> tuple[
    SwitchConnection | None, SwitchTarget | None, ConnectionStatus | None, list[Port] | None
]:
    """(connection, target, status, ports): ports is None when they could not be read."""
    connection, target, error = stored_switch(request)
    if target is None:
        status = ConnectionStatus(False, error) if error else None
        return connection, None, status, None
    status, ports = read_switch(target, load_ports, transport=request.app.state.nxapi_transport)
    return connection, target, status, ports


@router.get("/ports", response_class=HTMLResponse)
def ports_page(
    request: Request, username: str = Depends(login_required), show: str = "all"
) -> Response:
    connection, _, status, ports = _read_ports(request)
    if show not in FILTERS:
        show = "all"
    shown: list[Port] = [port for port in ports or [] if FILTERS[show](port)]
    counts = {name: sum(1 for port in ports or [] if keep(port)) for name, keep in FILTERS.items()}
    return templates.TemplateResponse(
        request,
        "ports.html",
        {
            "username": username,
            "connection": connection,
            "status": status,
            "ports": ports,
            "shown": shown,
            "show": show,
            "counts": counts,
        },
    )


def _render_port(
    request: Request,
    username: str,
    name: str,
    connection: SwitchConnection | None,
    status: ConnectionStatus | None,
    ports: list[Port] | None,
    *,
    error: str | None = None,
    notice: str | None = None,
    description: str | None = None,
    status_code: int | None = None,
) -> Response:
    port = next((p for p in ports or [] if p.name == name), None)
    if status_code is None:
        status_code = 404 if ports is not None and port is None else 200
    if description is None:
        description = port.description if port else ""
    return templates.TemplateResponse(
        request,
        "port.html",
        {
            "username": username,
            "connection": connection,
            "status": status,
            "ports": ports,
            "port": port,
            "name": name,
            "counter_labels": COUNTER_LABELS,
            "csrf_token": csrf_token(request),
            "error": error,
            "notice": notice,
            # After a refusal the box keeps what was typed.
            "description": description,
        },
        status_code=status_code,
    )


@router.get("/ports/detail", response_class=HTMLResponse)
def port_detail(
    request: Request, name: str = "", username: str = Depends(login_required)
) -> Response:
    connection, _, status, ports = _read_ports(request)
    return _render_port(request, username, name, connection, status, ports)


def change_summary(port: Port, action: str, description: str) -> tuple[str, str | None]:
    """(what the change does, in words; a warning for the confirm page or None)."""
    if action == "off":
        warning = (
            "This port is up now: whatever is plugged into it loses its connection at once."
            if port.up
            else None
        )
        return f"Turn off {port.name}.", warning
    if action == "on":
        return f"Turn on {port.name}.", None
    before = port.description or "none"
    after = description or "none"
    return f'Change the description of {port.name} from "{before}" to "{after}".', None


def change_refused(exc: NxapiError, target: SwitchTarget) -> str:
    """The message for a port change the switch did not make."""
    if isinstance(exc, NxapiCommandError) and "permission denied" in str(exc).lower():
        return (
            "The switch refused: NXray's account may not make this change yet. If port "
            "changes were turned on a few minutes ago the switch may not have applied them; "
            "leave NXray's pages closed for 10 minutes, then try again."
        )
    return connection_error(exc, target)


@router.post("/ports/change", response_class=HTMLResponse)
def port_change(
    request: Request,
    username: str = Depends(login_required),
    csrf: str = Form(""),
    name: str = Form(""),
    action: str = Form(""),
    description: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Change one port. Without confirm=yes, shows what would happen and asks."""
    require_csrf(request, csrf)
    connection, target, status, ports = _read_ports(request)
    port = next((p for p in ports or [] if p.name == name), None)

    def again(**kwargs) -> Response:
        return _render_port(request, username, name, connection, status, ports, **kwargs)

    if connection is None or target is None or port is None:
        return again()
    if not connection.changes_enabled:
        return again(
            error="Port changes are off. Turn them on on the Switch page first.",
            status_code=400,
        )
    if action not in ACTIONS:
        return again(error="Pick a change to make.", status_code=400)
    if action == "description":
        try:
            description = validate_description(description)
        except ValueError as exc:
            return again(error=f"Not changed: {exc}.", description=description, status_code=400)
        if description == port.description:
            return again(notice="Nothing to change: the port already has that description.")

    summary, warning = change_summary(port, action, description)
    if confirm != "yes":
        return templates.TemplateResponse(
            request,
            "port_confirm.html",
            {
                "username": username,
                "port": port,
                "action": action,
                "description": description,
                "summary": summary,
                "warning": warning,
                "csrf_token": csrf_token(request),
            },
        )

    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            if action == "description":
                client.configure_port(name, description=description)
            else:
                client.configure_port(name, enabled=action == "on")
    except NxapiError as exc:
        log.warning("port change on %s refused: %s", name, exc)
        return again(error=change_refused(exc, target), status_code=400)

    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        set_unsaved_changes(conn, True)
    log.info("port change on %s by %s: %s", connection.host, username, summary)

    # Read the port back so the page shows what the switch now reports.
    connection, _, status, ports = _read_ports(request)
    if action == "description":
        done = (
            f'{name} now has the description "{description}".'
            if description
            else f"{name} no longer has a description."
        )
    else:
        done = f"{name} is turned {action}."
    return _render_port(
        request,
        username,
        name,
        connection,
        status,
        ports,
        notice=f"Done: {done} Not saved yet: Save config keeps it over a restart of the switch.",
    )
