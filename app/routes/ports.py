"""The Ports page: every front-panel port, one port in detail, and port changes."""

from __future__ import annotations

import logging
import time
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import (
    login_required,
    note_activity,
    operator_required,
    require_csrf,
    stored_switch,
    templates,
)
from app.face import MODES, color_mode, draw_face
from app.history import RANGE_LABELS, port_charts, range_key
from app.neighbor_changes import (
    PortDiscovery,
    describe_port_discovery,
    load_port_discovery,
    plan_port_discovery,
)
from app.neighbors import NeighborView, try_load_neighbors
from app.nxapi import (
    NxapiClient,
    NxapiCommandError,
    NxapiError,
    SwitchTarget,
    validate_description,
)
from app.port_labels import LABEL_MAX, get_labels, set_label
from app.port_settings import (
    BREAKOUT_LABELS,
    FEC_LABELS,
    JUMBO_MTU,
    STANDARD_MTU,
    PortSettings,
    describe_port_settings,
    guess_breakout_map,
    plan_breakout,
    plan_port_settings,
    speed_label,
    try_load_port_settings,
)
from app.ports import COUNTER_LABELS, Port, load_ports
from app.security import csrf_token
from app.switch_choice import selected_switch_id
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
    SwitchConnection | None,
    SwitchTarget | None,
    ConnectionStatus | None,
    list[Port] | None,
    NeighborView | None,
]:
    """(connection, target, status, ports, neighbors): ports is None when they
    could not be read, neighbors when the switch refused to give them."""
    connection, target, error = stored_switch(request)
    if target is None:
        status = ConnectionStatus(False, error) if error else None
        return connection, None, status, None, None

    def reader(client: NxapiClient) -> tuple[list[Port], NeighborView | None]:
        return load_ports(client), try_load_neighbors(client)

    status, found = read_switch(target, reader, transport=request.app.state.nxapi_transport)
    ports, neighbors = found if found else (None, None)
    return connection, target, status, ports, neighbors


def _read_port_page(
    request: Request, name: str | None = None
) -> tuple[
    SwitchConnection | None,
    SwitchTarget | None,
    ConnectionStatus | None,
    list[Port] | None,
    VlanView | None,
    PortSettings | None,
    NeighborView | None,
    PortDiscovery | None,
]:
    """Like _read_ports, plus the VLANs, for a port's own page.

    With ``name``, also that port's settings and what it does with CDP and
    LLDP, read in later requests once the first shows the port exists (a
    show command naming a missing port would fail the whole request). Each
    of settings, neighbors and discovery is None when it could not be read.
    """
    connection, target, error = stored_switch(request)
    if target is None:
        status = ConnectionStatus(False, error) if error else None
        return connection, None, status, None, None, None, None, None

    def reader(
        client: NxapiClient,
    ) -> tuple[
        list[Port], VlanView, PortSettings | None, NeighborView | None, PortDiscovery | None
    ]:
        ports, view = load_ports_with_vlans(client)
        port = next((p for p in ports if p.name == name), None)
        settings = None
        discovery = None
        if port is not None:
            settings = try_load_port_settings(client, port, view.ports.get(port.name))
        neighbors = try_load_neighbors(client)
        if port is not None:
            lldp_on = neighbors.lldp_enabled if neighbors else False
            discovery = load_port_discovery(client, port.name, lldp_on)
        return ports, view, settings, neighbors, discovery

    status, found = read_switch(target, reader, transport=request.app.state.nxapi_transport)
    ports, view, settings, neighbors, discovery = found if found else (None,) * 5
    return connection, target, status, ports, view, settings, neighbors, discovery


def _labels(request: Request) -> dict[str, str]:
    with open_db(request.app.state.settings.db_path) as conn:
        return get_labels(conn, selected_switch_id(request))


@router.get("/ports", response_class=HTMLResponse)
def ports_page(
    request: Request,
    username: str = Depends(login_required),
    show: str = "all",
    color: str = "state",
    select: str = "",
) -> Response:
    return render_ports_page(request, username, show=show, color=color, tick_all=select == "all")


def render_ports_page(
    request: Request,
    username: str,
    *,
    show: str = "all",
    color: str = "state",
    error: str | None = None,
    notice: str | None = None,
    tick_all: bool = False,
    ticked: list[str] | None = None,
    bulk: dict[str, str] | None = None,
    status_code: int = 200,
) -> Response:
    """Read the switch fresh and show the Ports page, with an optional message.

    ``tick_all`` ticks every port the filter shows; ``ticked`` keeps the ports
    ticked and ``bulk`` the change picked (action, description) after a refusal.
    """
    color = color_mode(color)
    vlan_names: dict[int, str] = {}
    if color == "vlan":
        # Only this mode needs the VLAN names, so only it asks the switch for them.
        connection, _, status, ports, view, _, neighbors, _ = _read_port_page(request)
        vlan_names = {vlan.id: vlan.name for vlan in view.vlans} if view else {}
    else:
        connection, _, status, ports, neighbors = _read_ports(request)
    if show not in FILTERS:
        show = "all"
    labels = _labels(request)
    shown: list[Port] = [port for port in ports or [] if FILTERS[show](port)]
    counts = {name: sum(1 for port in ports or [] if keep(port)) for name, keep in FILTERS.items()}
    face = draw_face(ports, color, labels, vlan_names, neighbors) if ports else None
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
            "neighbors": neighbors,
            "csrf_token": csrf_token(request),
            "error": error,
            "notice": notice,
            "ticked": {port.name for port in shown} if tick_all else set(ticked or []),
            "bulk": bulk or {"action": "", "description": ""},
        },
        status_code=status_code,
    )


def _render_port(
    request: Request,
    username: str,
    name: str,
    connection: SwitchConnection | None,
    status: ConnectionStatus | None,
    ports: list[Port] | None,
    view: VlanView | None = None,
    port_settings: PortSettings | None = None,
    neighbors: NeighborView | None = None,
    discovery: PortDiscovery | None = None,
    *,
    error: str | None = None,
    notice: str | None = None,
    description: str | None = None,
    vlan_form: dict[str, str] | None = None,
    settings_form: dict[str, str] | None = None,
    label: str | None = None,
    status_code: int | None = None,
) -> Response:
    port = next((p for p in ports or [] if p.name == name), None)
    if settings_form is None and port_settings is not None:
        settings_form = _settings_form(port_settings)
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
    devices = neighbors.for_port(name) if neighbors and port else None
    period = range_key(request.query_params.get("range"))
    charts = []
    if port:
        with open_db(request.app.state.settings.db_path) as conn:
            charts = port_charts(conn, selected_switch_id(request), name, period, time.time())
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
            "settings": port_settings,
            "settings_form": settings_form,
            "speed_label": speed_label,
            "fec_labels": FEC_LABELS,
            "breakout_labels": BREAKOUT_LABELS,
            "breakout_guess": _breakout_guess(port_settings, ports),
            "standard_mtu": STANDARD_MTU,
            "jumbo_mtu": JUMBO_MTU,
            "neighbors": neighbors,
            "discovery": discovery,
            "devices": devices,
            "device_ips": {m.mac: neighbors.ips_of(m.mac) for m in devices.macs}
            if neighbors and devices
            else {},
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
    connection, _, status, ports, view, port_settings, neighbors, discovery = _read_port_page(
        request, name
    )
    return _render_port(
        request,
        username,
        name,
        connection,
        status,
        ports,
        view,
        port_settings,
        neighbors,
        discovery,
        error=error,
        notice=notice,
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


def plan_bulk_change(
    ports: list[Port], names: list[str], action: str, description: str
) -> tuple[list[Port], list[str], list[str], list[str]]:
    """Check a change asked for several ports at once.

    Returns (the ports to change, in front-panel order; what happens to each,
    one line per port; a warning for each up port about to be turned off;
    one line per ticked port that already is as asked). Raises ValueError
    with the reason for a change that cannot be made.
    """
    if not names:
        raise ValueError("tick at least one port")
    if action not in ACTIONS:
        raise ValueError("pick a change to make")
    known = {port.name for port in ports}
    unknown = sorted(set(names) - known)
    if unknown:
        raise ValueError(f"the switch has no port called {', '.join(unknown)}")
    if action == "description":
        description = validate_description(description)
    wanted = set(names)
    changing: list[Port] = []
    lines: list[str] = []
    warnings: list[str] = []
    already: list[str] = []
    for port in ports:  # already in front-panel order
        if port.name not in wanted:
            continue
        if action == "off" and not port.admin_up:
            already.append(f"{port.name} is already off.")
            continue
        if action == "on" and port.admin_up:
            already.append(f"{port.name} is already on.")
            continue
        if action == "description" and port.description == description:
            already.append(f"{port.name} already has that description.")
            continue
        summary, warning = change_summary(port, action, description)
        changing.append(port)
        lines.append(summary)
        if warning:
            warnings.append(f"{port.name}: {warning}")
    return changing, lines, warnings, already


def change_refused(exc: NxapiError, target: SwitchTarget) -> str:
    """The message for a port change the switch did not make."""
    text = str(exc).lower()
    if isinstance(exc, NxapiCommandError) and "interface permission denied" in text:
        return (
            "The switch refused: NXray's role on the switch does not name this port. That "
            "happens to the ports a 100G port was split into, or joined back into. An NXray "
            "admin presses Update the port list on the Switch page, then try again."
        )
    if isinstance(exc, NxapiCommandError) and "permission denied" in text:
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
    connection, target, status, ports, view, port_settings, neighbors, discovery = _read_port_page(
        request, name
    )
    port = next((p for p in ports or [] if p.name == name), None)

    def again(**kwargs) -> Response:
        return _render_port(
            request,
            username,
            name,
            connection,
            status,
            ports,
            view,
            port_settings,
            neighbors,
            discovery,
            **kwargs,
        )

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
        set_unsaved_changes(conn, selected_switch_id(request), True)
    log.info("port change on %s by %s: %s", connection.host, username, summary)
    note_activity(request, username, "Ports", summary, connection.host)

    # Read the port back so the page shows what the switch now reports.
    connection, _, status, ports, view, port_settings, neighbors, discovery = _read_port_page(
        request, name
    )
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
        port_settings,
        neighbors,
        discovery,
        notice=f"Done: {done} Not saved yet: Save config keeps it over a restart of the switch.",
    )


def _bulk_done(action: str, description: str, names: list[str]) -> str:
    """What a change of several ports did, in words, naming the ports."""
    listed = ", ".join(names)
    if action == "description":
        if description:
            return f'{listed} now have the description "{description}".'
        return f"{listed} no longer have a description."
    return f"Turned {action}: {listed}."


@router.post("/ports/bulk", response_class=HTMLResponse)
def ports_bulk_change(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    names: Annotated[list[str] | None, Form()] = None,
    action: str = Form(""),
    description: str = Form(""),
    show: str = Form("all"),
    color: str = Form("state"),
    confirm: str = Form(""),
) -> Response:
    """Turn several ports off or on, or give them one description.

    Without confirm=yes, shows every port and what would happen to it, and
    asks. The ports are changed one request at a time; the first refusal
    stops the rest, and the page names what changed and what did not.
    """
    require_csrf(request, csrf)
    names = list(dict.fromkeys(names or []))
    bulk = {"action": action, "description": description}

    def again(**kwargs) -> Response:
        return render_ports_page(
            request, username, show=show, color=color, ticked=names, bulk=bulk, **kwargs
        )

    connection, target, status, ports, _ = _read_ports(request)
    if connection is None or target is None or ports is None:
        return again()
    if not connection.changes_enabled:
        return again(
            error="Port changes are off. Turn them on on the Switch page first.",
            status_code=400,
        )
    try:
        changing, lines, warnings, already = plan_bulk_change(ports, names, action, description)
    except ValueError as exc:
        return again(error=f"Not changed: {exc}.", status_code=400)
    if action == "description":
        description = validate_description(description)
    if not changing:
        return again(notice="Nothing to change: " + " ".join(already))

    if confirm != "yes":
        return templates.TemplateResponse(
            request,
            "confirm.html",
            {
                "username": username,
                "title": "Ports",
                "back_url": "/ports",
                "back_label": "All ports",
                "lines": lines + [f"Unchanged: {line}" for line in already],
                "warnings": warnings,
                "action": "/ports/bulk",
                "fields": {
                    "names": [port.name for port in changing],
                    "action": action,
                    "description": description,
                    "show": show,
                    "color": color,
                },
                "csrf_token": csrf_token(request),
            },
        )

    changed: list[Port] = []
    refusal: str | None = None
    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            for port in changing:
                if action == "description":
                    client.configure_port(port.name, description=description)
                else:
                    client.configure_port(port.name, enabled=action == "on")
                changed.append(port)
    except NxapiError as exc:
        failed = changing[len(changed)].name
        log.warning("port change on %s refused: %s", failed, exc)
        refusal = f"{failed} was not changed. {change_refused(exc, target)}"

    if changed:
        settings = request.app.state.settings
        with open_db(settings.db_path) as conn:
            set_unsaved_changes(conn, selected_switch_id(request), True)
        summary = " ".join(lines[: len(changed)])
        log.info("port change on %s by %s: %s", connection.host, username, summary)
        note_activity(request, username, "Ports", summary, connection.host)

    done_names = [port.name for port in changed]
    not_saved = "Not saved yet: Save config keeps the changes over a restart of the switch."
    if refusal is None:
        return render_ports_page(
            request,
            username,
            show=show,
            color=color,
            notice=f"Done: {_bulk_done(action, description, done_names)} {not_saved}",
        )
    untried = [port.name for port in changing[len(changed) + 1 :]]
    parts = [f"Changed: {_bulk_done(action, description, done_names)}" if changed else ""]
    parts.append(refusal)
    if untried:
        parts.append(f"Not tried: {', '.join(untried)}.")
    if changed:
        parts.append(not_saved)
    return again(error=" ".join(part for part in parts if part), status_code=400)


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
    connection, target, status, ports, view, port_settings, neighbors, discovery = _read_port_page(
        request, name
    )
    port = next((p for p in ports or [] if p.name == name), None)
    current = view.ports.get(name) if view else None
    form = {
        "mode": mode,
        "access_vlan": access_vlan,
        "native_vlan": native_vlan,
        "allowed": allowed,
    }

    def again(**kwargs) -> Response:
        return _render_port(
            request,
            username,
            name,
            connection,
            status,
            ports,
            view,
            port_settings,
            neighbors,
            discovery,
            **kwargs,
        )

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
        set_unsaved_changes(conn, selected_switch_id(request), True)
    log.info("VLAN change on %s by %s: %s %s", connection.host, username, name, " ".join(lines))
    note_activity(request, username, "Ports", f"{name}: {'; '.join(lines)}", connection.host)

    connection, _, status, ports, view, port_settings, neighbors, discovery = _read_port_page(
        request, name
    )
    return _render_port(
        request,
        username,
        name,
        connection,
        status,
        ports,
        view,
        port_settings,
        neighbors,
        discovery,
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
    connection, _, status, ports, view, port_settings, neighbors, discovery = _read_port_page(
        request, name
    )
    port = next((p for p in ports or [] if p.name == name), None)

    def again(**kwargs) -> Response:
        return _render_port(
            request,
            username,
            name,
            connection,
            status,
            ports,
            view,
            port_settings,
            neighbors,
            discovery,
            **kwargs,
        )

    if port is None:
        return again()
    try:
        with open_db(request.app.state.settings.db_path) as conn:
            stored = set_label(conn, selected_switch_id(request), name, label, username)
    except ValueError as exc:
        return again(error=f"Label not saved: {exc}.", label=label, status_code=400)
    log.info("port label on %s by %s: %r", name, username, stored)
    note_activity(
        request,
        username,
        "Ports",
        f"{name}: label set to {stored!r}" if stored else f"{name}: label removed",
    )
    done = f'{name} now has the label "{stored}".' if stored else f"{name} no longer has a label."
    return again(notice=f"Done: {done} Labels are kept in NXray only; the switch is not changed.")


# ---- port settings and breakout ---------------------------------------------


def _settings_form(current: PortSettings) -> dict[str, str]:
    """The settings form filled with what the switch reports now."""
    return {
        "layer": current.layer,
        "ip_address": current.ip_address,
        "speed": current.speed,
        "mtu": str(current.mtu),
        "fec": current.fec,
        "flow_receive": current.flow_receive,
        "flow_send": current.flow_send,
        "storm_broadcast": current.storm_field("broadcast"),
        "storm_multicast": current.storm_field("multicast"),
        "storm_unicast": current.storm_field("unicast"),
        "storm_action": current.storm_action,
    }


def _breakout_guess(settings: PortSettings | None, ports: list[Port] | None) -> str | None:
    """For one of four split ports: the split they were made with, when it shows."""
    if settings is None or not settings.is_breakout_port:
        return None
    prefix = settings.parent + "/"
    return guess_breakout_map(
        [port.status_speed for port in ports or [] if port.name.startswith(prefix)]
    )


@router.post("/ports/settings", response_class=HTMLResponse)
def port_settings_change(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    name: str = Form(""),
    layer: str = Form(""),
    ip_address: str = Form(""),
    speed: str = Form(""),
    mtu: str = Form(""),
    fec: str = Form(""),
    flow_receive: str = Form(""),
    flow_send: str = Form(""),
    storm_broadcast: str = Form(""),
    storm_multicast: str = Form(""),
    storm_unicast: str = Form(""),
    storm_action: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Change a port's settings. Without confirm=yes, shows what would happen and asks."""
    require_csrf(request, csrf)
    form = {
        "layer": layer,
        "ip_address": ip_address,
        "speed": speed,
        "mtu": mtu,
        "fec": fec,
        "flow_receive": flow_receive,
        "flow_send": flow_send,
        "storm_broadcast": storm_broadcast,
        "storm_multicast": storm_multicast,
        "storm_unicast": storm_unicast,
        "storm_action": storm_action,
    }
    connection, target, status, ports, view, current, neighbors, discovery = _read_port_page(
        request, name
    )
    port = next((p for p in ports or [] if p.name == name), None)

    def again(**kwargs) -> Response:
        return _render_port(
            request,
            username,
            name,
            connection,
            status,
            ports,
            view,
            current,
            neighbors,
            discovery,
            **kwargs,
        )

    if connection is None or target is None or port is None:
        return again()
    if not connection.settings_changes_enabled:
        return again(
            error="Port settings changes are off. Turn them on on the Switch page first.",
            status_code=400,
        )
    if current is None:
        return again(error=f"The switch did not report the settings of {name}.", status_code=400)
    try:
        change = plan_port_settings(current, form)
    except ValueError as exc:
        return again(error=f"Not changed: {exc}.", settings_form=form, status_code=400)
    if change.empty:
        return again(notice="Nothing to change: the port already has these settings.")

    lines, warnings = describe_port_settings(current, change, up=port.up)
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
                "action": "/ports/settings",
                "fields": {"name": port.name, **form},
                "csrf_token": csrf_token(request),
            },
        )

    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            client.configure_port_settings(
                name,
                layer=change.layer,
                remove_extra=change.remove_extra,
                remove_ip=change.remove_ip,
                ip_address=change.ip_address,
                speed=change.speed,
                mtu=change.mtu,
                fec=change.fec,
                flow_receive=change.flow_receive,
                flow_send=change.flow_send,
                storm_levels=change.storm_levels,
                storm_action=change.storm_action,
                old_storm_action=current.storm_action,
            )
    except NxapiError as exc:
        log.warning("settings change on %s refused: %s", name, exc)
        return again(error=change_refused(exc, target), settings_form=form, status_code=400)

    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, selected_switch_id(request), True)
    log.info("settings change on %s by %s: %s %s", connection.host, username, name, " ".join(lines))
    note_activity(request, username, "Ports", f"{name}: {'; '.join(lines)}", connection.host)

    connection, _, status, ports, view, current, neighbors, discovery = _read_port_page(
        request, name
    )
    return _render_port(
        request,
        username,
        name,
        connection,
        status,
        ports,
        view,
        current,
        neighbors,
        discovery,
        notice=(
            f"Done: {' '.join(lines)} Not saved yet: Save config keeps it over a restart of "
            "the switch."
        ),
    )


@router.post("/ports/breakout", response_class=HTMLResponse)
def port_breakout(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    name: str = Form(""),
    action: str = Form(""),
    mapping: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Split a 100G port into four, or join four back. Asks to confirm first."""
    require_csrf(request, csrf)
    connection, target, status, ports, view, current, neighbors, discovery = _read_port_page(
        request, name
    )
    port = next((p for p in ports or [] if p.name == name), None)

    def again(**kwargs) -> Response:
        return _render_port(
            request,
            username,
            name,
            connection,
            status,
            ports,
            view,
            current,
            neighbors,
            discovery,
            **kwargs,
        )

    if connection is None or target is None or port is None:
        return again()
    if not connection.settings_changes_enabled:
        return again(
            error="Port settings changes are off. Turn them on on the Switch page first.",
            status_code=400,
        )
    if current is None:
        return again(error=f"The switch did not report the settings of {name}.", status_code=400)
    try:
        plan = plan_breakout(current, action, mapping)
    except ValueError as exc:
        return again(error=f"Not changed: {exc}.", status_code=400)

    if confirm != "yes":
        return templates.TemplateResponse(
            request,
            "confirm.html",
            {
                "username": username,
                "title": port.name,
                "back_url": f"/ports/detail?name={quote(port.name, safe='')}",
                "back_label": port.name,
                "lines": plan.lines,
                "warnings": plan.warnings,
                "action": "/ports/breakout",
                "fields": {"name": port.name, "action": action, "mapping": mapping},
                "csrf_token": csrf_token(request),
            },
        )

    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            if plan.action == "split":
                client.breakout_port(plan.port, plan.mapping)
            else:
                client.join_port(plan.port, plan.mapping)
    except NxapiError as exc:
        log.warning("%s of %s refused: %s", plan.action, plan.port, exc)
        return again(error=change_refused(exc, target), status_code=400)

    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, selected_switch_id(request), True)
    log.info("%s of %s by %s (%s)", plan.action, plan.port, username, plan.mapping)
    note_activity(
        request,
        username,
        "Ports",
        f"{plan.action} of {plan.port} ({plan.mapping})",
        connection.host,
    )

    # The port this page was for is gone now; show the one that replaced it.
    shown = f"{plan.port}/1" if plan.action == "split" else plan.port
    connection, _, status, ports, view, current, neighbors, discovery = _read_port_page(
        request, shown
    )
    return _render_port(
        request,
        username,
        shown,
        connection,
        status,
        ports,
        view,
        current,
        neighbors,
        discovery,
        notice=(
            f"Done: {' '.join(plan.lines)} An NXray admin now presses Update the port list on "
            "the Switch page so NXray may change the new ports. Not saved yet: Save config "
            "keeps it over a restart of the switch."
        ),
    )


# ---- CDP and LLDP on a port --------------------------------------------------


@router.post("/ports/discovery", response_class=HTMLResponse)
def port_discovery_change(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    name: str = Form(""),
    cdp: str = Form(""),
    lldp_transmit: str = Form(""),
    lldp_receive: str = Form(""),
    lldp_shown: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Turn CDP and LLDP sending and listening on or off on a port. Asks first.

    The form is tick boxes: a box that is not sent means off.
    """
    require_csrf(request, csrf)
    connection, target, status, ports, view, current, neighbors, discovery = _read_port_page(
        request, name
    )
    port = next((p for p in ports or [] if p.name == name), None)

    def again(**kwargs) -> Response:
        return _render_port(
            request,
            username,
            name,
            connection,
            status,
            ports,
            view,
            current,
            neighbors,
            discovery,
            **kwargs,
        )

    if connection is None or target is None or port is None:
        return again()
    if not connection.neighbor_changes_enabled:
        return again(
            error="Neighbor changes are off. Turn them on on the Switch page first.",
            status_code=400,
        )
    if discovery is None:
        return again(error=f"The switch did not report CDP on {name}.", status_code=400)
    change = plan_port_discovery(
        discovery,
        cdp=cdp == "on",
        lldp_transmit=lldp_transmit == "on",
        lldp_receive=lldp_receive == "on",
        lldp_shown=lldp_shown == "yes",
    )
    if change.empty:
        return again(notice="Nothing to change: the port already does this.")
    lines, warnings = describe_port_discovery(name, change)
    if confirm != "yes":
        fields = {"name": port.name, "lldp_shown": lldp_shown}
        # Only the ticked boxes are sent, as the browser sends them.
        for key, value in (
            ("cdp", cdp),
            ("lldp_transmit", lldp_transmit),
            ("lldp_receive", lldp_receive),
        ):
            if value == "on":
                fields[key] = "on"
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
                "action": "/ports/discovery",
                "fields": fields,
                "csrf_token": csrf_token(request),
            },
        )

    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            client.set_port_discovery(
                name,
                cdp=change.cdp,
                lldp_transmit=change.lldp_transmit,
                lldp_receive=change.lldp_receive,
            )
    except NxapiError as exc:
        log.warning("CDP/LLDP change on %s refused: %s", name, exc)
        return again(error=change_refused(exc, target), status_code=400)

    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, selected_switch_id(request), True)
    log.info("CDP/LLDP change on %s by %s: %s %s", connection.host, username, name, " ".join(lines))
    note_activity(request, username, "Ports", f"{name}: {'; '.join(lines)}", connection.host)

    connection, _, status, ports, view, current, neighbors, discovery = _read_port_page(
        request, name
    )
    return _render_port(
        request,
        username,
        name,
        connection,
        status,
        ports,
        view,
        current,
        neighbors,
        discovery,
        notice=(
            f"Done: {' '.join(lines)} Not saved yet: Save config keeps it over a restart of "
            "the switch."
        ),
    )
