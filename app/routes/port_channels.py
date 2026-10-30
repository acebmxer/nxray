"""The Port-channels page: every port-channel with its ports and LACP state, and
its changes (create, add and remove ports, delete, settings, LACP options)."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import (
    current_role,
    login_required,
    operator_required,
    require_csrf,
    stored_switch,
    templates,
)
from app.nxapi import (
    CHANNEL_MAX,
    CHANNEL_MIN,
    LACP_PRIORITY_MAX,
    LACP_PRIORITY_MIN,
    MIN_LINKS_MAX,
    MIN_LINKS_MIN,
    NxapiClient,
    NxapiError,
)
from app.port_channels import (
    DEFAULT_PORT_PRIORITY,
    DEFAULT_SYSTEM_PRIORITY,
    MODE_WORDS,
    ChannelView,
    load_channels,
    plan_add,
    plan_channel_settings,
    plan_create,
    plan_delete,
    plan_port_lacp,
    plan_remove,
    plan_system_priority,
)
from app.routes.ports import change_refused
from app.security import csrf_token
from app.switch_connection import SwitchConnection, set_unsaved_changes
from app.switch_setup import ConnectionStatus, read_switch

router = APIRouter()
log = logging.getLogger("nxray.port_channels")

NOT_SAVED = "Not saved yet: Save config keeps it over a restart of the switch."
CHANNEL_CHANGES_OFF = (
    "Port-channel changes are off. An NXray admin turns them on on the Switch page first: "
    "NXray's role on the switch does not allow them yet."
)


def _read(
    request: Request,
) -> tuple[SwitchConnection | None, ConnectionStatus | None, ChannelView | None]:
    connection, target, problem = stored_switch(request)
    if target is None:
        return connection, ConnectionStatus(False, problem) if problem else None, None
    status, view = read_switch(target, load_channels, transport=request.app.state.nxapi_transport)
    return connection, status, view


def _can_change(request: Request, connection: SwitchConnection | None) -> bool:
    return (
        connection is not None
        and connection.channel_changes_enabled
        and current_role(request) in ("admin", "operator")
    )


def _render(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
    status_code: int = 200,
) -> Response:
    """Read the switch fresh and show the page. ``form`` keeps what was typed
    into the create form after a refusal."""
    connection, status, view = _read(request)
    return templates.TemplateResponse(
        request,
        "port_channels.html",
        {
            "username": username,
            "connection": connection,
            "status": status,
            "view": view,
            "error": error,
            "notice": notice,
            "form": form or {},
            "csrf_token": csrf_token(request),
            "can_change": _can_change(request, connection),
            "mode_words": MODE_WORDS,
            "channel_min": CHANNEL_MIN,
            "channel_max": CHANNEL_MAX,
            "priority_min": LACP_PRIORITY_MIN,
            "priority_max": LACP_PRIORITY_MAX,
            "links_min": MIN_LINKS_MIN,
            "links_max": MIN_LINKS_MAX,
            "default_system_priority": DEFAULT_SYSTEM_PRIORITY,
            "default_port_priority": DEFAULT_PORT_PRIORITY,
        },
        status_code=status_code,
    )


@router.get("/port-channels", response_class=HTMLResponse)
def port_channels_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /port-channels``: read fresh from the switch."""
    return _render(request, username)


def render_port_channels_page(
    request: Request, username: str, *, error: str | None = None, notice: str | None = None
) -> Response:
    """Read the switch fresh and show the Port-channels page, with an optional message."""
    return _render(request, username, error=error, notice=notice)


def _confirm(
    request: Request,
    username: str,
    *,
    action: str,
    lines: list[str],
    warnings: list[str],
    fields: dict[str, str | list[str]],
) -> Response:
    return templates.TemplateResponse(
        request,
        "confirm.html",
        {
            "username": username,
            "title": "Port-channels",
            "back_url": "/port-channels",
            "back_label": "Port-channels",
            "lines": lines,
            "warnings": warnings,
            "action": action,
            "fields": fields,
            "csrf_token": csrf_token(request),
            "not_config": False,
        },
    )


def _start(request: Request) -> tuple[str | None, SwitchConnection | None, ChannelView | None]:
    """The checks every change shares, then the switch read fresh.

    (why it cannot go ahead or None, connection, port-channels).
    """
    connection, target, problem = stored_switch(request)
    if connection is None:
        return "No switch is set up yet.", None, None
    if target is None:
        return problem or "The switch could not be read.", None, None
    if not connection.channel_changes_enabled:
        return CHANNEL_CHANGES_OFF, None, None
    connection, status, view = _read(request)
    if view is None:
        return (status.message if status else "The switch could not be read."), None, None
    return None, connection, view


def _send(request: Request, change: Callable[[NxapiClient], None]) -> str | None:
    """Run ``change(client)`` with NXray's account; the refusal message, or None."""
    _, target, _ = stored_switch(request)
    assert target is not None  # _start checked it
    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            change(client)
    except NxapiError as exc:
        return change_refused(exc, target)
    return None


def _done(request: Request, username: str, line: str, what: str, connection) -> Response:
    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, True)
    log.info("%s on %s by %s", what, connection.host, username)
    return _render(request, username, notice=f"Done: {line} {NOT_SAVED}")


def _refused(request: Request, username: str, what: str, refused: str, form=None) -> Response:
    log.warning("%s refused: %s", what, refused)
    return _render(request, username, error=refused, form=form, status_code=400)


def _bad(request: Request, username: str, words: str, exc: ValueError, form=None) -> Response:
    return _render(request, username, error=f"{words}: {exc}.", form=form, status_code=400)


@router.post("/port-channels/create", response_class=HTMLResponse)
def channel_create(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    number: str = Form(""),
    ports: Annotated[list[str] | None, Form()] = None,
    mode: str = Form(""),
    fast_rate: str = Form(""),
    description: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Make a port-channel from free ports. Without confirm=yes, asks first."""
    require_csrf(request, csrf)
    form = {"number": number, "mode": mode, "fast_rate": fast_rate, "description": description}
    problem, connection, view = _start(request)
    if problem is not None:
        return _render(request, username, error=problem, form=form, status_code=400)
    assert connection is not None and view is not None
    try:
        join, lines, warnings = plan_create(
            view,
            number=number,
            ports=ports or [],
            mode=mode,
            fast_rate=fast_rate == "yes",
            description=description,
        )
    except ValueError as exc:
        return _bad(request, username, "Not made", exc, form)
    if confirm != "yes":
        return _confirm(
            request,
            username,
            action="/port-channels/create",
            lines=lines,
            warnings=warnings,
            fields={
                "number": str(join.number),
                "ports": list(join.ports),
                "mode": join.mode,
                "fast_rate": "yes" if join.fast_rate else "",
                "description": join.description or "",
            },
        )
    refused = _send(
        request,
        lambda client: client.join_port_channel(
            join.number,
            list(join.ports),
            join.mode,
            fast_rate=join.fast_rate,
            description=join.description,
        ),
    )
    if refused:
        return _refused(request, username, f"port-channel{join.number}", refused, form)
    return _done(request, username, lines[0], f"port-channel{join.number} made", connection)


@router.post("/port-channels/add", response_class=HTMLResponse)
def channel_add(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    number: str = Form(""),
    port: str = Form(""),
    mode: str = Form(""),
    fast_rate: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Add a free port to a port-channel. Without confirm=yes, asks first."""
    require_csrf(request, csrf)
    problem, connection, view = _start(request)
    if problem is not None:
        return _render(request, username, error=problem, status_code=400)
    assert connection is not None and view is not None
    try:
        join, lines, warnings = plan_add(
            view, number=number, port=port, mode=mode, fast_rate=fast_rate == "yes"
        )
    except ValueError as exc:
        return _bad(request, username, "Not added", exc)
    if confirm != "yes":
        return _confirm(
            request,
            username,
            action="/port-channels/add",
            lines=lines,
            warnings=warnings,
            fields={
                "number": str(join.number),
                "port": join.ports[0],
                "mode": join.mode,
                "fast_rate": "yes" if join.fast_rate else "",
            },
        )
    refused = _send(
        request,
        lambda client: client.join_port_channel(
            join.number, list(join.ports), join.mode, fast_rate=join.fast_rate
        ),
    )
    if refused:
        return _refused(request, username, f"adding {join.ports[0]}", refused)
    what = f"{join.ports[0]} added to port-channel{join.number}"
    return _done(request, username, lines[0], what, connection)


@router.post("/port-channels/remove", response_class=HTMLResponse)
def channel_remove(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    port: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Take a port out of its port-channel. Without confirm=yes, asks first."""
    require_csrf(request, csrf)
    problem, connection, view = _start(request)
    if problem is not None:
        return _render(request, username, error=problem, status_code=400)
    assert connection is not None and view is not None
    try:
        name, lines, warnings = plan_remove(view, port=port)
    except ValueError as exc:
        return _bad(request, username, "Not removed", exc)
    if confirm != "yes":
        return _confirm(
            request,
            username,
            action="/port-channels/remove",
            lines=lines,
            warnings=warnings,
            fields={"port": name},
        )
    if refused := _send(request, lambda client: client.leave_port_channel(name)):
        return _refused(request, username, f"taking {name} out", refused)
    return _done(request, username, lines[0], f"{name} taken out of its port-channel", connection)


@router.post("/port-channels/delete", response_class=HTMLResponse)
def channel_delete(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    number: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Delete an empty port-channel. Without confirm=yes, asks first."""
    require_csrf(request, csrf)
    problem, connection, view = _start(request)
    if problem is not None:
        return _render(request, username, error=problem, status_code=400)
    assert connection is not None and view is not None
    try:
        channel, lines, warnings = plan_delete(view, number=number)
    except ValueError as exc:
        return _bad(request, username, "Not deleted", exc)
    if confirm != "yes":
        return _confirm(
            request,
            username,
            action="/port-channels/delete",
            lines=lines,
            warnings=warnings,
            fields={"number": str(channel)},
        )
    if refused := _send(request, lambda client: client.delete_port_channel(channel)):
        return _refused(request, username, f"deleting port-channel{channel}", refused)
    return _done(request, username, lines[0], f"port-channel{channel} deleted", connection)


@router.post("/port-channels/settings", response_class=HTMLResponse)
def channel_settings(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    number: str = Form(""),
    description: str = Form(""),
    min_links: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """A port-channel's description and minimum links. Without confirm=yes, asks first."""
    require_csrf(request, csrf)
    problem, connection, view = _start(request)
    if problem is not None:
        return _render(request, username, error=problem, status_code=400)
    assert connection is not None and view is not None
    try:
        change, lines, warnings = plan_channel_settings(
            view, number=number, description=description, min_links=min_links
        )
    except ValueError as exc:
        return _bad(request, username, "Not changed", exc)
    if confirm != "yes":
        return _confirm(
            request,
            username,
            action="/port-channels/settings",
            lines=lines,
            warnings=warnings,
            fields={
                "number": str(change.number),
                "description": description,
                "min_links": "" if change.min_links is None else str(change.min_links),
            },
        )
    refused = _send(
        request,
        lambda client: client.configure_port_channel(
            change.number, description=change.description, min_links=change.min_links
        ),
    )
    if refused:
        return _refused(request, username, f"port-channel{change.number} settings", refused)
    what = f"port-channel{change.number} settings changed"
    return _done(request, username, " ".join(lines), what, connection)


@router.post("/port-channels/port-lacp", response_class=HTMLResponse)
def port_lacp(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    port: str = Form(""),
    rate: str = Form(""),
    priority: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """A member's LACP rate and port priority. Without confirm=yes, asks first."""
    require_csrf(request, csrf)
    problem, connection, view = _start(request)
    if problem is not None:
        return _render(request, username, error=problem, status_code=400)
    assert connection is not None and view is not None
    try:
        change, lines, warnings = plan_port_lacp(view, port=port, rate=rate, priority=priority)
    except ValueError as exc:
        return _bad(request, username, "Not changed", exc)
    if confirm != "yes":
        return _confirm(
            request,
            username,
            action="/port-channels/port-lacp",
            lines=lines,
            warnings=warnings,
            fields={"port": change.port, "rate": rate, "priority": priority},
        )
    refused = _send(
        request,
        lambda client: client.set_port_lacp(
            change.port, rate=change.rate, priority=change.priority
        ),
    )
    if refused:
        return _refused(request, username, f"LACP settings of {change.port}", refused)
    what = f"LACP settings of {change.port} changed"
    return _done(request, username, " ".join(lines), what, connection)


@router.post("/port-channels/system-priority", response_class=HTMLResponse)
def system_priority(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    priority: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """The switch's LACP priority. Without confirm=yes, asks first."""
    require_csrf(request, csrf)
    problem, connection, view = _start(request)
    if problem is not None:
        return _render(request, username, error=problem, status_code=400)
    assert connection is not None and view is not None
    try:
        value, lines, warnings = plan_system_priority(view, priority)
    except ValueError as exc:
        return _bad(request, username, "Not changed", exc)
    if confirm != "yes":
        return _confirm(
            request,
            username,
            action="/port-channels/system-priority",
            lines=lines,
            warnings=warnings,
            fields={"priority": str(value)},
        )
    if refused := _send(request, lambda client: client.set_lacp_system_priority(value)):
        return _refused(request, username, "LACP system priority", refused)
    return _done(request, username, lines[0], f"LACP system priority set to {value}", connection)
