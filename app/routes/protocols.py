"""The Routing protocols pages: an overview with the route table, one page per
protocol (OSPF, BGP, HSRP, PIM, ...) and Routing policy (route-maps,
prefix-lists, key chains), and the changes their forms make.

Every change goes through one route, ``POST /routing/protocols/<key>/change``:
the form names the scope (a process, an interface, a neighbor, ...), the
setting, the action (set, remove, create, delete), the place's identity fields
(``id_<name>``) and the setting's values (``v_<name>``). The lines are built
and checked from the protocol's description (``app/protocols.py``); a confirm
page shows them before anything is sent.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, Depends, Request
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
from app.nxapi import NxapiClient, NxapiError
from app.protocols import ACTIONS, Protocol
from app.routes.ports import change_refused
from app.routing_protocols import (
    ALL_PROTOCOLS,
    ProtocolPage,
    build_protocol_change,
    feature_command,
    load_overview,
    load_protocol_page,
    protocol,
)
from app.security import csrf_token
from app.switch_connection import SwitchConnection, set_unsaved_changes
from app.switch_setup import read_switch

router = APIRouter()
log = logging.getLogger("nxray.protocols")

NOT_SAVED = "Not saved yet: Save config keeps it over a restart of the switch."
PROTOCOL_CHANGES_OFF = (
    "Routing protocol changes are off. An NXray admin turns them on on the Switch page "
    "first: NXray's role on the switch does not allow them yet."
)


async def form_fields(request: Request) -> dict[str, str]:
    """The posted form as plain strings (the protocol forms' field names vary)."""
    form = await request.form()
    return {key: value for key, value in form.items() if isinstance(value, str)}


def _can_change(request: Request, connection: SwitchConnection | None) -> bool:
    return (
        connection is not None
        and connection.protocol_changes_enabled
        and current_role(request) in ("admin", "operator")
    )


# ---- the overview -------------------------------------------------------------------


def render_protocols_page(
    request: Request, username: str, *, error: str | None = None, notice: str | None = None
) -> Response:
    """Read the switch fresh and show the Routing protocols overview, with a message."""
    connection, target, problem = stored_switch(request)
    status = view = None
    if target is not None:
        status, view = read_switch(
            target, load_overview, transport=request.app.state.nxapi_transport
        )
    return templates.TemplateResponse(
        request,
        "protocols.html",
        {
            "username": username,
            "connection": connection,
            "status": status,
            "problem": problem,
            "view": view,
            "error": error,
            "notice": notice,
            "csrf_token": csrf_token(request),
            "can_change": _can_change(request, connection),
            "feature_command": feature_command,
        },
        status_code=400 if error else 200,
    )


@router.get("/routing/protocols", response_class=HTMLResponse)
def protocols_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /routing/protocols``: every protocol with whether it is on, and the
    switch's route table, read live."""
    return render_protocols_page(request, username)


# ---- one protocol ---------------------------------------------------------------------


def _ident(form: dict[str, str]) -> dict[str, str]:
    return {k[3:]: v for k, v in form.items() if k.startswith("id_")}


def _values(form: dict[str, str]) -> dict[str, str]:
    return {k[2:]: v for k, v in form.items() if k.startswith("v_")}


def render_protocol_page(
    request: Request,
    username: str,
    key: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show one protocol's page, with a message.

    ``form`` keeps what was typed into the form that was refused.
    """
    proto = protocol(key)
    if proto is None:
        return templates.TemplateResponse(
            request,
            "protocol.html",
            {"username": username, "unknown": key, "connection": None},
            status_code=404,
        )
    connection, target, problem = stored_switch(request)
    status = page = None
    if target is not None:
        status, page = read_switch(
            target,
            lambda client: load_protocol_page(client, proto),
            transport=request.app.state.nxapi_transport,
        )
    return templates.TemplateResponse(
        request,
        "protocol.html",
        {
            "username": username,
            "connection": connection,
            "status": status,
            "problem": problem,
            "proto": proto,
            "page": page,
            "protocols": ALL_PROTOCOLS,
            "error": error,
            "notice": notice,
            "form": form or {},
            "csrf_token": csrf_token(request),
            "can_change": _can_change(request, connection),
            "feature_command": feature_command,
        },
        status_code=400 if error else 200,
    )


@router.get("/routing/protocols/{key}", response_class=HTMLResponse)
def protocol_page(key: str, request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /routing/protocols/<key>``: one protocol read live; every role looks,
    operators and admins change."""
    return render_protocol_page(request, username, key)


def _secrets(proto: Protocol, scope: str, setting: str, values: dict[str, str]) -> list[str]:
    """The secret values a change carries (passwords, keys), to keep them off the page."""
    place = proto.scope(scope)
    found = place.setting(setting) if place is not None else None
    if found is None:
        return []
    return [values[name].strip() for name in found.secret_fields if values.get(name, "").strip()]


def _check_place(page: ProtocolPage, ident: dict[str, str]) -> None:
    """Refuse an interface or VRF the switch does not have (or NXray may not change)."""
    interface = ident.get("interface", "").strip()
    if interface and interface not in page.interfaces:
        known = ", ".join(page.interfaces) or "none"
        raise ValueError(
            f"{interface} is not a VLAN interface (up to Vlan254), routed port or routed "
            f"port-channel on the switch; those are: {known}"
        )
    vrf = ident.get("vrf", "").strip()
    if vrf and vrf not in page.vrfs:
        raise ValueError(f"the switch has no VRF {vrf}; make it on the Routing page first")


def _confirm(
    request: Request,
    username: str,
    proto: Protocol,
    lines: list[str],
    warnings: list[str],
    fields: dict[str, Any],
) -> Response:
    return templates.TemplateResponse(
        request,
        "confirm.html",
        {
            "username": username,
            "title": proto.name,
            "back_url": f"/routing/protocols/{proto.key}",
            "back_label": proto.name,
            "lines": lines,
            "warnings": warnings,
            "action": f"/routing/protocols/{proto.key}/change",
            "fields": fields,
            "csrf_token": csrf_token(request),
            "not_config": False,
        },
    )


@router.post("/routing/protocols/{key}/change", response_class=HTMLResponse)
def protocol_change(
    key: str,
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on a protocol's page. Without confirm=yes, asks first."""
    require_csrf(request, form.get("csrf", ""))
    proto = protocol(key)
    if proto is None:
        return render_protocol_page(request, username, key)
    kept = {k: v for k, v in form.items() if k not in ("csrf", "confirm")}

    def refuse(message: str) -> Response:
        return render_protocol_page(request, username, key, error=message, form=kept)

    connection, target, problem = stored_switch(request)
    if connection is None:
        return refuse("No switch is set up yet.")
    if target is None:
        return refuse(problem or "The switch could not be read.")
    if not connection.protocol_changes_enabled:
        return refuse(PROTOCOL_CHANGES_OFF)
    action = form.get("action", "")
    if action not in ACTIONS:
        return refuse("Not changed: the form named no action.")
    status, page = read_switch(
        target,
        lambda client: load_protocol_page(client, proto),
        transport=request.app.state.nxapi_transport,
    )
    if page is None:
        return refuse(status.message if status else "The switch could not be read.")
    if page.missing:
        names = ", ".join(feature_command(n) for n in page.missing)
        return refuse(
            f"Not changed: {names} is off on the switch; turn it on on the Features page."
        )
    ident, values = _ident(form), _values(form)
    try:
        _check_place(page, ident)
        change = build_protocol_change(
            key, form.get("scope", ""), form.get("setting", ""), action, ident, values
        )
    except ValueError as exc:
        return refuse(f"Not changed: {exc}.")
    if form.get("confirm") != "yes":
        lines = [change.describe, "The switch gets these lines:", *change.labels]
        return _confirm(
            request, username, proto, lines, [change.warning] if change.warning else [], kept
        )
    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            client.configure_protocol(
                key, change.scope, change.setting, change.action, ident, values
            )
    except NxapiError as exc:
        refused = change_refused(exc, target)
        for secret in _secrets(proto, change.scope, change.setting, values):
            refused = refused.replace(secret, "***")
        log.warning("%s change refused: %s", proto.name, refused)
        return refuse(refused)
    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, True)
    log.info("%s on %s by %s", change.describe, connection.host, username)
    return render_protocol_page(
        request, username, key, notice=f"Done: {change.describe} {NOT_SAVED}"
    )
