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
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import (
    current_role,
    login_required,
    note_activity,
    operator_required,
    require_csrf,
    stored_switch,
    templates,
)
from app.nxapi import NxapiClient, NxapiError
from app.protocols import ACTIONS, Protocol, ProtocolChange
from app.routes.ports import change_refused
from app.routing_protocols import (
    ProtocolPage,
    build_protocol_change,
    feature_command,
    load_overview,
    load_protocol_page,
    protocol,
)
from app.security import csrf_token
from app.switch_choice import selected_switch_id
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


def _ident(form: Mapping[str, str]) -> dict[str, str]:
    return {k[3:]: v for k, v in form.items() if k.startswith("id_")}


def _values(form: Mapping[str, str]) -> dict[str, str]:
    return {k[2:]: v for k, v in form.items() if k.startswith("v_")}


@dataclass(frozen=True)
class ProtocolSite:
    """Where a page built from ``app/protocols.py`` lives, what it reads, and how a
    change on it is checked and sent: one routing protocol's page, the Spanning
    tree page or the Switch admin page. ``load`` reads the page (an object with
    ``view``, ``missing`` and ``problem``, plus the lists its field kinds offer);
    ``check_place`` refuses an
    identity value the switch does not have; ``send`` sends a checked change;
    ``after``, when given, runs once the switch took one (with the request, to
    update what NXray stores); ``links`` are related pages shown under the title;
    ``needs``, when given, gets the connection, scope and setting of a change and
    returns why NXray's role may not make it yet ("" when it may), for pages whose
    newer parts need a newer role than the page itself."""

    url: str
    back_url: str
    back_label: str
    save_back: dict[str, str]  # the hidden fields Save config sends to come back here
    changes_name: str  # "Routing protocol", "Spanning tree"
    subject: str  # what a viewer may look at: "routing protocols", "spanning tree"
    off_message: str
    enabled: Callable[[SwitchConnection], bool]
    load: Callable[[NxapiClient], Any]
    check_place: Callable[[Any, dict[str, str]], None]
    build: Callable[[str, str, str, dict[str, str], dict[str, str]], ProtocolChange]
    send: Callable[[NxapiClient, ProtocolChange, dict[str, str], dict[str, str]], None]
    after: Callable[[Request, ProtocolChange], None] | None = None
    links: tuple[tuple[str, str], ...] = ()  # (url, label) of related pages, under the title
    needs: Callable[[SwitchConnection, str, str], str] | None = None


def _routing_site(proto: Protocol) -> ProtocolSite:
    def send(
        client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
    ) -> None:
        client.configure_protocol(
            proto.key, change.scope, change.setting, change.action, ident, values
        )

    return ProtocolSite(
        url=f"/routing/protocols/{proto.key}",
        back_url="/routing/protocols",
        back_label="Routing protocols",
        save_back={"back": "protocol", "protocol": proto.key},
        changes_name="Routing protocol",
        subject="routing protocols",
        off_message=PROTOCOL_CHANGES_OFF,
        enabled=lambda connection: connection.protocol_changes_enabled,
        load=lambda client: load_protocol_page(client, proto),
        check_place=_check_place,
        build=lambda scope, setting, action, ident, values: build_protocol_change(
            proto.key, scope, setting, action, ident, values
        ),
        send=send,
    )


def render_site_page(
    request: Request,
    username: str,
    proto: Protocol,
    site: ProtocolSite,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show a page built from ``app/protocols.py``, with a
    message. ``form`` keeps what was typed into the form that was refused."""
    connection, target, problem = stored_switch(request)
    status = page = None
    if target is not None:
        status, page = read_switch(target, site.load, transport=request.app.state.nxapi_transport)
    can_change = (
        connection is not None
        and site.enabled(connection)
        and current_role(request) in ("admin", "operator")
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
            "site": site,
            "page": page,
            "error": error,
            "notice": notice,
            "form": form or {},
            "csrf_token": csrf_token(request),
            "can_change": can_change,
            "feature_command": feature_command,
        },
        status_code=400 if error else 200,
    )


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
    return render_site_page(
        request, username, proto, _routing_site(proto), error=error, notice=notice, form=form
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
    site: ProtocolSite,
    lines: list[str],
    warnings: list[str],
    fields: dict[str, Any],
    not_config: bool = False,
) -> Response:
    return templates.TemplateResponse(
        request,
        "confirm.html",
        {
            "username": username,
            "title": proto.name,
            "back_url": site.url,
            "back_label": proto.name,
            "lines": lines,
            "warnings": warnings,
            "action": f"{site.url}/change",
            "fields": fields,
            "csrf_token": csrf_token(request),
            "not_config": not_config,
        },
    )


def site_change(
    request: Request,
    username: str,
    form: Mapping[str, str],
    proto: Protocol,
    site: ProtocolSite,
) -> Response:
    """One change on a page built from ``app/protocols.py``. Without confirm=yes,
    asks first, showing the lines."""
    require_csrf(request, form.get("csrf", ""))
    kept = {k: v for k, v in form.items() if k not in ("csrf", "confirm")}

    def refuse(message: str) -> Response:
        return render_site_page(request, username, proto, site, error=message, form=kept)

    connection, target, problem = stored_switch(request)
    if connection is None:
        return refuse("No switch is set up yet.")
    if target is None:
        return refuse(problem or "The switch could not be read.")
    if not site.enabled(connection):
        return refuse(site.off_message)
    if site.needs is not None:
        if refusal := site.needs(connection, form.get("scope", ""), form.get("setting", "")):
            return refuse(refusal)
    action = form.get("action", "")
    if action not in ACTIONS:
        return refuse("Not changed: the form named no action.")
    status, page = read_switch(target, site.load, transport=request.app.state.nxapi_transport)
    if page is None:
        return refuse(status.message if status else "The switch could not be read.")
    if page.missing:
        names = ", ".join(feature_command(n) for n in page.missing)
        return refuse(
            f"Not changed: {names} is off on the switch; turn it on on the Features page."
        )
    ident, values = _ident(form), _values(form)
    try:
        site.check_place(page, ident)
        change = site.build(form.get("scope", ""), form.get("setting", ""), action, ident, values)
    except ValueError as exc:
        return refuse(f"Not changed: {exc}.")
    if form.get("confirm") != "yes":
        lines = [change.describe, "The switch gets these lines:", *change.labels]
        return _confirm(
            request,
            username,
            proto,
            site,
            lines,
            [change.warning] if change.warning else [],
            kept,
            not_config=not change.config,
        )
    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            site.send(client, change, ident, values)
    except NxapiError as exc:
        refused = change_refused(exc, target)
        for secret in _secrets(proto, change.scope, change.setting, values):
            refused = refused.replace(secret, "***")
        log.warning("%s change refused: %s", proto.name, refused)
        return refuse(refused)
    if change.config:
        with open_db(request.app.state.settings.db_path) as conn:
            set_unsaved_changes(conn, selected_switch_id(request), True)
    if site.after is not None:
        site.after(request, change)
    log.info("%s on %s by %s", change.describe, connection.host, username)
    note_activity(request, username, proto.name, change.describe, connection.host)
    done = f"Done: {change.describe}" + (f" {NOT_SAVED}" if change.config else "")
    return render_site_page(request, username, proto, site, notice=done)


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
    return site_change(request, username, form, proto, _routing_site(proto))
