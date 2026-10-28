"""The Ports page: every front-panel port, one port in detail, and port changes."""

from __future__ import annotations

import logging
import time
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import (
    login_required,
    operator_required,
    require_csrf,
    stored_switch,
    templates,
)
from app.face import MODES, color_mode, draw_face
from app.history import RANGE_LABELS, port_charts, range_key
from app.nxapi import (
    NxapiClient,
    NxapiCommandError,
    NxapiError,
    SwitchTarget,
    validate_description,
)
from app.port_labels import LABEL_MAX, get_labels, set_label
from app.ports import COUNTER_LABELS, Port, load_ports
from app.security import csrf_token
from app.switch_connection import SwitchConnection, set_unsaved_changes
from app.switch_setup import ConnectionStatus, connection_error, read_switch
from app.vlans import VlanView, describe_port_vlans, load_ports_with_vlans, plan_port_vlans

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


def _read_port_page(
    request: Request,
) -> tuple[
    SwitchConnection | None,
    SwitchTarget | None,
    ConnectionStatus | None,
    list[Port] | None,
    VlanView | None,
]:
    """Like _read_ports, plus the VLANs, for a port's own page: one request."""
    connection, target, error = stored_switch(request)
    if target is None:
        status = ConnectionStatus(False, error) if error else None
        return connection, None, status, None, None
    status, both = read_switch(
        target, load_ports_with_vlans, transport=request.app.state.nxapi_transport
    )
    ports, view = both if both else (None, None)
    return connection, target, status, ports, view


def _labels(request: Request) -> dict[str, str]:
    with open_db(request.app.state.settings.db_path) as conn:
        return get_labels(conn)


@router.get("/ports", response_class=HTMLResponse)
def ports_page(
    request: Request,
    username: str = Depends(login_required),
    show: str = "all",
    color: str = "state",
) -> Response:
    color = color_mode(color)
    vlan_names: dict[int, str] = {}
    if color == "vlan":
        # Only this mode needs the VLAN names, so only it asks the switch for them.
        connection, _, status, ports, view = _read_port_page(request)
        vlan_names = {vlan.id: vlan.name for vlan in view.vlans} if view else {}
    else:
        connection, _, status, ports = _read_ports(request)
    if show not in FILTERS:
        show = "all"
    labels = _labels(request)
    shown: list[Port] = [port for port in ports or [] if FILTERS[show](port)]
    counts = {name: sum(1 for port in ports or [] if keep(port)) for name, keep in FILTERS.items()}
    face = draw_face(ports, color, labels, vlan_names) if ports else None
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
            "labels": labels,
            "face": face,
            "color": color,
            "modes": MODES,
        },
    )


def _render_port(
    request: Request,
    username: str,
    name: str,
    connection: SwitchConnection | None,
    status: ConnectionStatus | None,
    ports: list[Port] | None,
    view: VlanView | None = None,
    *,
    error: str | None = None,
    notice: str | None = None,
    description: str | None = None,
    vlan_form: dict[str, str] | None = None,
    label: str | None = None,
    status_code: int | None = None,
) -> Response:
    port = next((p for p in ports or [] if p.name == name), None)
    stored_label = _labels(request).get(name, "")
    if label is None:
        label = stored_label
    vlans = view.ports.get(name) if view else None
    if vlan_form is None and vlans is not None:
        vlan_form = {
            "mode": vlans.mode,
            "access_vlan": str(vlans.access_vlan),
            "native_vlan": str(vlans.native_vlan),
            "allowed": vlans.allowed_text,
        }
    if status_code is None:
        status_code = 404 if ports is not None and port is None else 200
    if description is None:
        description = port.description if port else ""
    period = range_key(request.query_params.get("range"))
    charts = []
    if port:
        with open_db(request.app.state.settings.db_path) as conn:
            charts = port_charts(conn, name, period, time.time())
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
            "view": view,
            "vlans": vlans,
            "vlan_form": vlan_form,
            "charts": charts,
            "range": period,
            "ranges": RANGE_LABELS,
            # The stored label, and what the label box holds (what was typed, after a refusal).
            "stored_label": stored_label,
            "label": label,
            "label_max": LABEL_MAX,
        },
        status_code=status_code,
    )


@router.get("/ports/detail", response_class=HTMLResponse)
def port_detail(
    request: Request, name: str = "", username: str = Depends(login_required)
) -> Response:
    return render_port_page(request, username, name)


def render_port_page(
    request: Request,
    username: str,
    name: str,
    *,
    error: str | None = None,
    notice: str | None = None,
) -> Response:
    """Read the switch fresh and show one port's page, with an optional message."""
    connection, _, status, ports, view = _read_port_page(request)
    return _render_port(
        request, username, name, connection, status, ports, view, error=error, notice=notice
    )


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
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    name: str = Form(""),
    action: str = Form(""),
    description: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Change one port. Without confirm=yes, shows what would happen and asks."""
    require_csrf(request, csrf)
    connection, target, status, ports, view = _read_port_page(request)
    port = next((p for p in ports or [] if p.name == name), None)

    def again(**kwargs) -> Response:
        return _render_port(request, username, name, connection, status, ports, view, **kwargs)

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
    connection, _, status, ports, view = _read_port_page(request)
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
        view,
        notice=f"Done: {done} Not saved yet: Save config keeps it over a restart of the switch.",
    )


@router.post("/ports/vlans", response_class=HTMLResponse)
def port_vlans_change(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    name: str = Form(""),
    mode: str = Form(""),
    access_vlan: str = Form(""),
    native_vlan: str = Form(""),
    allowed: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Set a port's mode and VLANs. Without confirm=yes, shows what would happen and asks."""
    require_csrf(request, csrf)
    connection, target, status, ports, view = _read_port_page(request)
    port = next((p for p in ports or [] if p.name == name), None)
    current = view.ports.get(name) if view else None
    form = {
        "mode": mode,
        "access_vlan": access_vlan,
        "native_vlan": native_vlan,
        "allowed": allowed,
    }

    def again(**kwargs) -> Response:
        return _render_port(request, username, name, connection, status, ports, view, **kwargs)

    if connection is None or target is None or port is None or view is None:
        return again()
    if not connection.vlan_changes_enabled:
        return again(
            error="VLAN changes are off. Turn them on on the Switch page first.",
            status_code=400,
        )
    if current is None:
        return again(error=f"The switch reported no VLAN settings for {name}.", status_code=400)
    try:
        change = plan_port_vlans(
            current,
            view,
            mode=mode,
            access_vlan=access_vlan,
            native_vlan=native_vlan,
            allowed=allowed,
        )
    except ValueError as exc:
        return again(error=f"Not changed: {exc}.", vlan_form=form, status_code=400)
    if change.empty:
        return again(notice="Nothing to change: the port already has these VLAN settings.")

    lines, warnings = describe_port_vlans(current, change)
    if confirm != "yes":
        return templates.TemplateResponse(
            request,
            "confirm.html",
            {
                "username": username,
                "title": port.name,
                "back_url": f"/ports/detail?name={quote(port.name, safe='')}",
                "back_label": port.name,
                "lines": lines,
                "warnings": warnings,
                "action": "/ports/vlans",
                "fields": {"name": port.name, **form},
                "csrf_token": csrf_token(request),
            },
        )

    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            client.configure_port_vlans(
                name,
                mode=change.mode,
                access_vlan=change.access_vlan,
                native_vlan=change.native_vlan,
                allowed_vlans=change.allowed_vlans,
            )
    except NxapiError as exc:
        log.warning("VLAN change on %s refused: %s", name, exc)
        return again(error=change_refused(exc, target), vlan_form=form, status_code=400)

    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        set_unsaved_changes(conn, True)
    log.info("VLAN change on %s by %s: %s %s", connection.host, username, name, " ".join(lines))

    connection, _, status, ports, view = _read_port_page(request)
    return _render_port(
        request,
        username,
        name,
        connection,
        status,
        ports,
        view,
        notice=(
            f"Done: {' '.join(lines)} Not saved yet: Save config keeps it over a restart of "
            "the switch."
        ),
    )


@router.post("/ports/label", response_class=HTMLResponse)
def port_label(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    name: str = Form(""),
    label: str = Form(""),
) -> Response:
    """Set or remove a port's label. Kept in NXray only, so no confirm step and no switch call."""
    require_csrf(request, csrf)
    connection, _, status, ports, view = _read_port_page(request)
    port = next((p for p in ports or [] if p.name == name), None)

    def again(**kwargs) -> Response:
        return _render_port(request, username, name, connection, status, ports, view, **kwargs)

    if port is None:
        return again()
    try:
        with open_db(request.app.state.settings.db_path) as conn:
            stored = set_label(conn, name, label, username)
    except ValueError as exc:
        return again(error=f"Label not saved: {exc}.", label=label, status_code=400)
    log.info("port label on %s by %s: %r", name, username, stored)
    done = f'{name} now has the label "{stored}".' if stored else f"{name} no longer has a label."
    return again(notice=f"Done: {done} Labels are kept in NXray only; the switch is not changed.")
