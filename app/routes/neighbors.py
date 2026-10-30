"""The Neighbors page: CDP and LLDP neighbors, the MAC address table and ARP,
and the MAC address table's changes (aging time, static entries, clearing)."""

from __future__ import annotations

import logging
from collections.abc import Callable
from urllib.parse import quote

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
from app.neighbor_changes import (
    CLEAR_SCOPES,
    DROP,
    plan_clear,
    plan_mac_aging,
    plan_static_mac,
    plan_static_removal,
    static_entries,
    static_target,
)
from app.neighbors import NeighborView, filter_macs, load_neighbors
from app.nxapi import MAC_AGING_MAX, MAC_AGING_MIN, NxapiClient, NxapiError, validate_port_name
from app.oui import format_mac
from app.ports import port_sort_key
from app.routes.ports import change_refused, render_port_page
from app.security import csrf_token
from app.switch_connection import SwitchConnection, set_unsaved_changes
from app.switch_setup import ConnectionStatus, read_switch
from app.vlans import VlanView, load_vlans

router = APIRouter()
log = logging.getLogger("nxray.neighbors")

# Longest search kept; anything longer cannot match a MAC address, port or maker.
QUERY_MAX = 64

NOT_SAVED = "Not saved yet: Save config keeps it over a restart of the switch."
NEIGHBOR_CHANGES_OFF = (
    "Neighbor changes are off. An NXray admin turns them on on the Switch page first: "
    "NXray's role on the switch does not allow them yet."
)


def _front_ports(vlans: VlanView | None) -> list[str]:
    """The front ports, in panel order, from the ports ``show interface switchport`` lists."""
    names = []
    for name in vlans.ports if vlans else {}:
        try:
            names.append(validate_port_name(name))
        except ValueError:
            continue
    return sorted(names, key=port_sort_key)


def _read(
    request: Request, with_vlans: bool
) -> tuple[
    SwitchConnection | None,
    ConnectionStatus | None,
    NeighborView | None,
    VlanView | None,
]:
    """(connection, status, neighbors, VLANs): the VLANs only when asked for,
    since only the change forms need them."""
    connection, target, problem = stored_switch(request)
    if target is None:
        return connection, ConnectionStatus(False, problem) if problem else None, None, None

    def reader(client: NxapiClient) -> tuple[NeighborView, VlanView | None]:
        return load_neighbors(client), load_vlans(client) if with_vlans else None

    status, found = read_switch(target, reader, transport=request.app.state.nxapi_transport)
    view, vlans = found if found else (None, None)
    return connection, status, view, vlans


def _can_change(request: Request, connection: SwitchConnection | None) -> bool:
    return (
        connection is not None
        and connection.neighbor_changes_enabled
        and current_role(request) in ("admin", "operator")
    )


def _render(
    request: Request,
    username: str,
    *,
    query: str = "",
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
    status_code: int = 200,
) -> Response:
    """Read the switch fresh and show the page. ``form`` keeps what was typed
    into a change form after a refusal."""
    connection = stored_switch(request)[0]
    connection, status, view, vlans = _read(request, _can_change(request, connection))
    macs = filter_macs(view.macs, query) if view else []
    ips = {entry.mac: view.ips_of(entry.mac) for entry in macs} if view else {}
    statics = static_entries(view) if view else []
    return templates.TemplateResponse(
        request,
        "neighbors.html",
        {
            "username": username,
            "connection": connection,
            "status": status,
            "view": view,
            "macs": macs,
            "ips": ips,
            "query": query,
            "query_max": QUERY_MAX,
            "error": error,
            "notice": notice,
            "csrf_token": csrf_token(request),
            "can_change": _can_change(request, connection),
            "statics": [(entry, static_target(entry)) for entry in statics],
            "vlans": vlans,
            "front_ports": _front_ports(vlans),
            "form": form or {},
            "aging_min": MAC_AGING_MIN,
            "aging_max": MAC_AGING_MAX,
            "drop": DROP,
        },
        status_code=status_code,
    )


@router.get("/neighbors", response_class=HTMLResponse)
def neighbors_page(
    request: Request, username: str = Depends(login_required), q: str = ""
) -> Response:
    """``GET /neighbors``: read fresh from the switch; ``?q=`` narrows the MAC address table."""
    return _render(request, username, query=q.strip()[:QUERY_MAX])


def render_neighbors_page(
    request: Request, username: str, *, error: str | None = None, notice: str | None = None
) -> Response:
    """Read the switch fresh and show the Neighbors page, with an optional message."""
    return _render(request, username, error=error, notice=notice)


def _confirm(
    request: Request,
    username: str,
    *,
    action: str,
    lines: list[str],
    warnings: list[str],
    fields: dict[str, str],
    back_url: str = "/neighbors",
    back_label: str = "Neighbors",
    not_config: bool = False,
) -> Response:
    return templates.TemplateResponse(
        request,
        "confirm.html",
        {
            "username": username,
            "title": back_label,
            "back_url": back_url,
            "back_label": back_label,
            "lines": lines,
            "warnings": warnings,
            "action": action,
            "fields": fields,
            "csrf_token": csrf_token(request),
            "not_config": not_config,
        },
    )


def _start(
    request: Request,
) -> tuple[str | None, SwitchConnection | None, NeighborView | None, VlanView | None]:
    """The checks every change shares, then the switch read fresh.

    (why it cannot go ahead or None, connection, neighbors, VLANs).
    """
    connection, target, problem = stored_switch(request)
    if connection is None:
        return "No switch is set up yet.", None, None, None
    if target is None:
        return problem or "The switch could not be read.", None, None, None
    if not connection.neighbor_changes_enabled:
        return NEIGHBOR_CHANGES_OFF, None, None, None
    connection, status, view, vlans = _read(request, True)
    if view is None or vlans is None:
        return (status.message if status else "The switch could not be read."), None, None, None
    return None, connection, view, vlans


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


@router.post("/neighbors/aging", response_class=HTMLResponse)
def mac_aging_change(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    aging: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Set how long learned addresses are kept. Without confirm=yes, asks first."""
    require_csrf(request, csrf)
    form = {"aging": aging}
    problem, connection, view, _ = _start(request)
    if problem is not None:
        return _render(request, username, error=problem, form=form, status_code=400)
    assert connection is not None and view is not None
    try:
        seconds, lines, warnings = plan_mac_aging(view, aging)
    except ValueError as exc:
        return _render(request, username, error=f"Not changed: {exc}.", form=form, status_code=400)
    if confirm != "yes":
        return _confirm(
            request,
            username,
            action="/neighbors/aging",
            lines=lines,
            warnings=warnings,
            fields={"aging": str(seconds)},
        )
    if refused := _send(request, lambda client: client.set_mac_aging(seconds)):
        log.warning("MAC aging change refused: %s", refused)
        return _render(request, username, error=refused, form=form, status_code=400)
    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, True)
    log.info("MAC aging time on %s set to %d by %s", connection.host, seconds, username)
    return _render(request, username, notice=f"Done: {lines[0]} {NOT_SAVED}")


@router.post("/neighbors/static", response_class=HTMLResponse)
def static_mac_add(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    mac: str = Form(""),
    vlan: str = Form(""),
    where: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Add a static MAC address entry. Without confirm=yes, asks first."""
    require_csrf(request, csrf)
    form = {"mac": mac, "vlan": vlan, "where": where}
    problem, connection, view, vlans = _start(request)
    if problem is not None:
        return _render(request, username, error=problem, form=form, status_code=400)
    assert connection is not None and view is not None and vlans is not None
    try:
        entry, lines, warnings = plan_static_mac(
            view, mac=mac, vlan=vlan, where=where, vlan_ids=vlans.ids, ports=_front_ports(vlans)
        )
    except ValueError as exc:
        return _render(request, username, error=f"Not added: {exc}.", form=form, status_code=400)
    if confirm != "yes":
        return _confirm(
            request,
            username,
            action="/neighbors/static",
            lines=lines,
            warnings=warnings,
            fields={"mac": entry.mac, "vlan": str(entry.vlan), "where": entry.port or DROP},
        )
    if refused := _send(
        request, lambda client: client.add_static_mac(entry.mac, entry.vlan, entry.port)
    ):
        log.warning("static MAC %s refused: %s", entry.mac, refused)
        return _render(request, username, error=refused, form=form, status_code=400)
    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, True)
    log.info(
        "static MAC %s vlan %d %s added on %s by %s",
        entry.mac,
        entry.vlan,
        entry.where,
        connection.host,
        username,
    )
    return _render(request, username, notice=f"Done: {lines[0]} {NOT_SAVED}")


@router.post("/neighbors/static/remove", response_class=HTMLResponse)
def static_mac_remove(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    mac: str = Form(""),
    vlan: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Remove a static MAC address entry the table shows. Without confirm=yes, asks first."""
    require_csrf(request, csrf)
    problem, connection, view, _ = _start(request)
    if problem is not None:
        return _render(request, username, error=problem, status_code=400)
    assert connection is not None and view is not None
    try:
        entry, lines, warnings = plan_static_removal(view, mac=mac, vlan=vlan)
    except ValueError as exc:
        return _render(request, username, error=f"Not removed: {exc}.", status_code=400)
    if confirm != "yes":
        return _confirm(
            request,
            username,
            action="/neighbors/static/remove",
            lines=lines,
            warnings=warnings,
            fields={"mac": entry.mac, "vlan": str(entry.vlan)},
        )
    if refused := _send(
        request, lambda client: client.remove_static_mac(entry.mac, entry.vlan, entry.port)
    ):
        log.warning("removing static MAC %s refused: %s", entry.mac, refused)
        return _render(request, username, error=refused, status_code=400)
    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, True)
    log.info(
        "static MAC %s vlan %d removed on %s by %s",
        entry.mac,
        entry.vlan,
        connection.host,
        username,
    )
    done = f"the static entry for {format_mac(entry.mac)} in VLAN {entry.vlan} is removed."
    return _render(request, username, notice=f"Done: {done} {NOT_SAVED}")


@router.post("/neighbors/clear", response_class=HTMLResponse)
def learned_macs_clear(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    scope: str = Form(""),
    port: str = Form(""),
    vlan: str = Form(""),
    mac: str = Form(""),
    back: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Clear learned addresses: all, one port, one VLAN or one address. Asks first.

    ``back=port`` (from a port's page, with ``port`` set) answers on that
    port's page; anything else on the Neighbors page, so the field can never
    send the browser elsewhere.
    """
    require_csrf(request, csrf)
    form = {"scope": scope, "port": port, "vlan": vlan, "mac": mac}
    on_port = back == "port" and bool(port)

    def answer(*, error: str | None = None, notice: str | None = None) -> Response:
        if on_port:
            return render_port_page(request, username, port, error=error, notice=notice)
        code = 400 if error else 200
        return _render(request, username, error=error, notice=notice, form=form, status_code=code)

    problem, connection, view, vlans = _start(request)
    if problem is not None:
        return answer(error=problem)
    assert connection is not None and view is not None
    if scope not in CLEAR_SCOPES:
        return answer(error="Not cleared: choose what to clear.")
    try:
        clear, lines, warnings = plan_clear(
            view, scope=scope, ports=_front_ports(vlans), port=port, vlan=vlan, mac=mac
        )
    except ValueError as exc:
        return answer(error=f"Not cleared: {exc}.")
    if confirm != "yes":
        fields = {**form, "back": "port" if on_port else ""}
        if on_port:
            back_url = f"/ports/detail?name={quote(port, safe='')}"
            return _confirm(
                request,
                username,
                action="/neighbors/clear",
                lines=lines,
                warnings=warnings,
                fields=fields,
                back_url=back_url,
                back_label=port,
                not_config=True,
            )
        return _confirm(
            request,
            username,
            action="/neighbors/clear",
            lines=lines,
            warnings=warnings,
            fields=fields,
            not_config=True,
        )
    if refused := _send(
        request,
        lambda client: client.clear_learned_macs(port=clear.port, vlan=clear.vlan, mac=clear.mac),
    ):
        log.warning("clearing learned addresses refused: %s", refused)
        return answer(error=refused)
    log.info("cleared learned addresses on %s by %s: %s", connection.host, username, lines[0])
    return answer(notice=f"Done: {clear.done} Static entries stay; there is nothing to save.")
