"""The Routing page: VLAN interfaces, routed ports and their addresses, and their
changes (make, change and delete VLAN interfaces; add and remove addresses)."""

from __future__ import annotations

import logging
from collections.abc import Callable

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
from app.nxapi import MTU_MAX, MTU_MIN, VLAN_INTERFACE_MAX, NxapiClient, NxapiError
from app.routes.ports import change_refused
from app.routing import (
    DEFAULT_MTU,
    RoutingView,
    load_routing,
    plan_add_address,
    plan_create_vlan_interface,
    plan_delete_vlan_interface,
    plan_remove_address,
    plan_vlan_interface_settings,
)
from app.security import csrf_token
from app.switch_connection import SwitchConnection, set_unsaved_changes
from app.switch_setup import ConnectionStatus, read_switch

router = APIRouter()
log = logging.getLogger("nxray.routing")

NOT_SAVED = "Not saved yet: Save config keeps it over a restart of the switch."
LAYER3_CHANGES_OFF = (
    "VLAN interface changes are off. An NXray admin turns them on on the Switch page first: "
    "NXray's role on the switch does not allow them yet."
)

VLAN_INTERFACES_NOT_LISTED = (
    "NXray's role on the switch does not name the VLAN interfaces yet: interface-vlan was "
    "off when it was written. An NXray admin presses Update the port list on the Switch "
    "page once interface-vlan is on."
)


def _read(
    request: Request,
) -> tuple[SwitchConnection | None, ConnectionStatus | None, RoutingView | None]:
    connection, target, problem = stored_switch(request)
    if target is None:
        return connection, ConnectionStatus(False, problem) if problem else None, None
    status, view = read_switch(target, load_routing, transport=request.app.state.nxapi_transport)
    return connection, status, view


def _can_change(request: Request, connection: SwitchConnection | None) -> bool:
    return (
        connection is not None
        and connection.layer3_changes_enabled
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
    into the make form after a refusal."""
    connection, status, view = _read(request)
    return templates.TemplateResponse(
        request,
        "routing.html",
        {
            "username": username,
            "connection": connection,
            "status": status,
            "view": view,
            "error": error,
            "notice": notice,
            "form": form or {"enabled": "yes", "vlan": request.query_params.get("vlan", "")},
            "csrf_token": csrf_token(request),
            "can_change": _can_change(request, connection),
            "vlan_ready": connection is not None and connection.vlan_interface_changes_enabled,
            "vlan_interface_max": VLAN_INTERFACE_MAX,
            "mtu_min": MTU_MIN,
            "mtu_max": MTU_MAX,
            "default_mtu": DEFAULT_MTU,
        },
        status_code=status_code,
    )


@router.get("/routing", response_class=HTMLResponse)
def routing_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /routing``: read fresh from the switch. ``?vlan=N`` picks that VLAN in
    the make form (the VLANs page links here)."""
    return _render(request, username)


def render_routing_page(
    request: Request, username: str, *, error: str | None = None, notice: str | None = None
) -> Response:
    """Read the switch fresh and show the Routing page, with an optional message."""
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
            "title": "Routing",
            "back_url": "/routing",
            "back_label": "Routing",
            "lines": lines,
            "warnings": warnings,
            "action": action,
            "fields": fields,
            "csrf_token": csrf_token(request),
            "not_config": False,
        },
    )


def _start(
    request: Request, vlan_interface: bool = False
) -> tuple[str | None, SwitchConnection | None, RoutingView | None]:
    """The checks every change shares, then the switch read fresh.

    ``vlan_interface``: the change acts on a VLAN interface, which also needs
    the role's port list to name them. (why it cannot go ahead or None,
    connection, view).
    """
    connection, target, problem = stored_switch(request)
    if connection is None:
        return "No switch is set up yet.", None, None
    if target is None:
        return problem or "The switch could not be read.", None, None
    if not connection.layer3_changes_enabled:
        return LAYER3_CHANGES_OFF, None, None
    if vlan_interface and not connection.vlan_interface_changes_enabled:
        return VLAN_INTERFACES_NOT_LISTED, None, None
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


def _done(request: Request, username: str, lines: list[str], what: str, connection) -> Response:
    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, True)
    log.info("%s on %s by %s", what, connection.host, username)
    return _render(request, username, notice=f"Done: {' '.join(lines)} {NOT_SAVED}")


def _refused(request: Request, username: str, what: str, refused: str, form=None) -> Response:
    log.warning("%s refused: %s", what, refused)
    return _render(request, username, error=refused, form=form, status_code=400)


def _bad(request: Request, username: str, words: str, exc: ValueError, form=None) -> Response:
    return _render(request, username, error=f"{words}: {exc}.", form=form, status_code=400)


@router.post("/routing/vlan-interface/create", response_class=HTMLResponse)
def vlan_interface_create(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    vlan: str = Form(""),
    ipv4: str = Form(""),
    ipv6: str = Form(""),
    description: str = Form(""),
    mtu: str = Form(""),
    enabled: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Make a VLAN interface. Without confirm=yes, asks first."""
    require_csrf(request, csrf)
    form: dict[str, str | list[str]] = {
        "vlan": vlan,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "description": description,
        "mtu": mtu,
        "enabled": enabled,
    }
    problem, connection, view = _start(request, vlan_interface=True)
    if problem is not None:
        return _render(request, username, error=problem, form=form, status_code=400)
    assert connection is not None and view is not None
    try:
        change, lines, warnings = plan_create_vlan_interface(
            view,
            vlan=vlan,
            ipv4=ipv4,
            ipv6=ipv6,
            description=description,
            mtu=mtu,
            enabled=enabled == "yes",
        )
    except ValueError as exc:
        return _bad(request, username, "Not made", exc, form)
    if confirm != "yes":
        return _confirm(
            request,
            username,
            action="/routing/vlan-interface/create",
            lines=lines,
            warnings=warnings,
            fields=dict(form),
        )
    refused = _send(
        request,
        lambda client: client.configure_vlan_interface(
            change.vlan,
            description=change.description,
            mtu=change.mtu,
            enabled=change.enabled,
            add=change.add,
        ),
    )
    if refused:
        return _refused(request, username, f"Vlan{change.vlan}", refused, form)
    return _done(request, username, lines, f"Vlan{change.vlan} made", connection)


@router.post("/routing/vlan-interface/settings", response_class=HTMLResponse)
def vlan_interface_settings(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    vlan: str = Form(""),
    ipv4: str = Form(""),
    description: str = Form(""),
    mtu: str = Form(""),
    state: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """A VLAN interface's IPv4 address, description, MTU and on/off. Without
    confirm=yes, asks first."""
    require_csrf(request, csrf)
    problem, connection, view = _start(request, vlan_interface=True)
    if problem is not None:
        return _render(request, username, error=problem, status_code=400)
    assert connection is not None and view is not None
    if state not in ("on", "off"):
        return _render(request, username, error="Not changed: pick on or off.", status_code=400)
    try:
        change, lines, warnings = plan_vlan_interface_settings(
            view, vlan=vlan, ipv4=ipv4, description=description, mtu=mtu, enabled=state == "on"
        )
    except ValueError as exc:
        return _bad(request, username, "Not changed", exc)
    if confirm != "yes":
        return _confirm(
            request,
            username,
            action="/routing/vlan-interface/settings",
            lines=lines,
            warnings=warnings,
            fields={
                "vlan": str(change.vlan),
                "ipv4": ipv4,
                "description": description,
                "mtu": mtu,
                "state": state,
            },
        )
    refused = _send(
        request,
        lambda client: client.configure_vlan_interface(
            change.vlan,
            description=change.description,
            mtu=change.mtu,
            enabled=change.enabled,
            remove=change.remove,
            add=change.add,
        ),
    )
    if refused:
        return _refused(request, username, f"Vlan{change.vlan} settings", refused)
    return _done(request, username, lines, f"Vlan{change.vlan} changed", connection)


@router.post("/routing/vlan-interface/delete", response_class=HTMLResponse)
def vlan_interface_delete(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    vlan: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Delete a VLAN interface. Without confirm=yes, asks first."""
    require_csrf(request, csrf)
    problem, connection, view = _start(request, vlan_interface=True)
    if problem is not None:
        return _render(request, username, error=problem, status_code=400)
    assert connection is not None and view is not None
    try:
        number, lines, warnings = plan_delete_vlan_interface(view, vlan=vlan)
    except ValueError as exc:
        return _bad(request, username, "Not deleted", exc)
    if confirm != "yes":
        return _confirm(
            request,
            username,
            action="/routing/vlan-interface/delete",
            lines=lines,
            warnings=warnings,
            fields={"vlan": str(number)},
        )
    if refused := _send(request, lambda client: client.delete_vlan_interface(number)):
        return _refused(request, username, f"deleting Vlan{number}", refused)
    return _done(request, username, lines[:1], f"Vlan{number} deleted", connection)


@router.post("/routing/address/add", response_class=HTMLResponse)
def address_add(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    name: str = Form(""),
    address: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Put one more address on a VLAN interface or routed port. Without confirm=yes,
    asks first."""
    require_csrf(request, csrf)
    problem, connection, view = _start(
        request, vlan_interface=name.strip().lower().startswith("vlan")
    )
    if problem is not None:
        return _render(request, username, error=problem, status_code=400)
    assert connection is not None and view is not None
    try:
        change, lines, warnings = plan_add_address(view, name=name, address=address)
    except ValueError as exc:
        return _bad(request, username, "Not added", exc)
    if confirm != "yes":
        return _confirm(
            request,
            username,
            action="/routing/address/add",
            lines=lines,
            warnings=warnings,
            fields={"name": change.name, "address": change.add[0][0]},
        )
    refused = _send(
        request, lambda client: client.set_interface_addresses(change.name, add=change.add)
    )
    if refused:
        return _refused(request, username, f"address on {change.name}", refused)
    return _done(request, username, lines, f"address added to {change.name}", connection)


@router.post("/routing/address/remove", response_class=HTMLResponse)
def address_remove(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    name: str = Form(""),
    address: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Take one address off a VLAN interface or routed port. Without confirm=yes,
    asks first."""
    require_csrf(request, csrf)
    problem, connection, view = _start(
        request, vlan_interface=name.strip().lower().startswith("vlan")
    )
    if problem is not None:
        return _render(request, username, error=problem, status_code=400)
    assert connection is not None and view is not None
    try:
        change, lines, warnings = plan_remove_address(view, name=name, address=address)
    except ValueError as exc:
        return _bad(request, username, "Not removed", exc)
    if confirm != "yes":
        return _confirm(
            request,
            username,
            action="/routing/address/remove",
            lines=lines,
            warnings=warnings,
            fields={"name": change.name, "address": change.remove[0][0]},
        )
    refused = _send(
        request, lambda client: client.set_interface_addresses(change.name, remove=change.remove)
    )
    if refused:
        return _refused(request, username, f"address on {change.name}", refused)
    return _done(request, username, lines, f"address removed from {change.name}", connection)
