"""The Traffic page: traffic per VLAN and per device, measured with sFlow.

Shows what the collector (app/sflow.py) has stored for the selected switch,
whether the switch is sending, and, for operators once traffic measuring
changes are on, the form that sets sFlow up on the switch.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import (
    login_required,
    may_change,
    note_activity,
    operator_required,
    require_csrf,
    stored_switch,
    templates,
)
from app.history import RANGE_LABELS, RANGES, range_key
from app.neighbors import NeighborView, try_load_neighbors
from app.nxapi import SFLOW_SAMPLING_RATES, NxapiClient, NxapiError
from app.oui import mac_maker, normalize_mac
from app.ports import Port, load_ports
from app.routes.ports import change_refused
from app.security import csrf_token
from app.sflow import (
    MAC_RECEIVES,
    MAC_SENDS,
    OTHER,
    VLAN,
    TopItem,
    device_label,
    latest_minute,
    load_agents,
    sflow_charts,
    top_items,
    vlan_cards,
    vlan_label,
)
from app.sflow_switch import SCOPES, SflowConfig, load_sflow_config, plan_sflow, sflow_form
from app.switch_choice import selected_switch_id
from app.switch_connection import set_sflow_agent, set_unsaved_changes
from app.switch_setup import ConnectionStatus, read_switch

router = APIRouter()
log = logging.getLogger("nxray.traffic")

NOT_SAVED = "Not saved yet: Save config keeps it over a restart of the switch."
CHANGES_OFF = (
    "Traffic measuring changes are off. An NXray admin turns them on on the Switch page "
    "first: NXray's role on the switch does not allow sFlow yet."
)
FORM_FIELDS = ("collector", "vrf", "collector_port", "agent", "sampling_rate", "scope", "ports")
# The most devices the page lists.
DEVICE_ROWS = 25


@dataclass(frozen=True)
class DeviceRow:
    mac: str
    maker: str
    ips: list[str]
    port: str
    sends: int  # bits per second over the range
    receives: int


def _ipv4(text: str | None) -> str:
    """``text`` when it is one host's IPv4 address, else ""."""
    try:
        address = ipaddress.IPv4Address((text or "").strip())
    except ValueError:
        return ""
    return "" if address.is_loopback or address.is_unspecified else str(address)


def device_rows(
    sends: list[TopItem], receives: list[TopItem], neighbors: NeighborView | None
) -> list[DeviceRow]:
    """The busiest devices both ways, with what NXray knows of each from the
    switch's MAC address and ARP tables; the left-over OTHER is not one device."""
    by_mac: dict[str, list[int]] = {}
    for kind, found in ((0, sends), (1, receives)):
        for top in found:
            if top.item != OTHER:
                by_mac.setdefault(top.item, [0, 0])[kind] += top.bits_per_second
    ports = {}
    if neighbors is not None:
        for entry in neighbors.macs:
            ports.setdefault(normalize_mac(entry.mac), entry.port)
    rows = [
        DeviceRow(
            mac=mac,
            maker=mac_maker(mac),
            ips=neighbors.ips_of(mac) if neighbors else [],
            port=ports.get(normalize_mac(mac), ""),
            sends=values[0],
            receives=values[1],
        )
        for mac, values in by_mac.items()
    ]
    rows.sort(key=lambda row: -(row.sends + row.receives))
    return rows[:DEVICE_ROWS]


def _read(
    request: Request,
) -> tuple[Any, Any, ConnectionStatus | None, SflowConfig | None, list[Port] | None, Any]:
    """(connection, target, status, sFlow on the switch, its ports, its neighbor view)."""
    connection, target, problem = stored_switch(request)
    if target is None:
        status = ConnectionStatus(False, problem) if problem else None
        return connection, None, status, None, None, None

    def reader(client: NxapiClient) -> tuple[SflowConfig, list[Port], NeighborView | None]:
        return load_sflow_config(client), load_ports(client), try_load_neighbors(client)

    status, found = read_switch(target, reader, transport=request.app.state.nxapi_transport)
    config, ports, neighbors = found if found else (None, None, None)
    return connection, target, status, config, ports, neighbors


def _render(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
    status_code: int = 200,
    found: tuple | None = None,
) -> Response:
    connection, _target, status, config, ports, neighbors = found or _read(request)
    settings = request.app.state.settings
    collector = request.app.state.sflow_collector
    switch_id = selected_switch_id(request)
    period = range_key(request.query_params.get("range"))
    mac_param = normalize_mac(request.query_params.get("mac", "") or "")
    mac = ":".join(mac_param[i : i + 2] for i in range(0, 12, 2)) if mac_param else ""
    now = time.time()
    start = now - RANGES[period]
    charts, vlan_chart_cards, vlans, devices, newest = [], [], [], [], None
    if connection is not None:
        with open_db(settings.db_path) as conn:
            charts = sflow_charts(conn, switch_id, period, now, mac=mac)
            vlan_chart_cards = vlan_cards(conn, switch_id, period, now)
            vlans = top_items(conn, switch_id, VLAN, start=start, end=now, limit=30)
            devices = device_rows(
                top_items(conn, switch_id, MAC_SENDS, start=start, end=now, limit=DEVICE_ROWS),
                top_items(conn, switch_id, MAC_RECEIVES, start=start, end=now, limit=DEVICE_ROWS),
                neighbors,
            )
            newest = latest_minute(conn, switch_id)
    if form is None and connection is not None:
        form = sflow_form(
            config,
            collector=_ipv4(request.url.hostname),
            agent=_ipv4(connection.sflow_agent) or _ipv4(connection.host),
            port=settings.sflow_port,
            front=[port.name for port in ports or []],
        )
    vlan_total = sum(top.bits_per_second for top in vlans) or 1
    return templates.TemplateResponse(
        request,
        "traffic.html",
        {
            "username": username,
            "connection": connection,
            "status": status,
            "config": config,
            "ports": ports,
            "error": error,
            "notice": notice,
            "form": form or {},
            "csrf_token": csrf_token(request),
            "can_change": may_change(request),
            "listening_port": collector.listening_port,
            "sflow_port": settings.sflow_port,
            "keep_days": settings.sflow_keep_days,
            "heard": collector.status(switch_id) if connection else None,
            "unknown_agents": collector.unknown_agents(),
            "newest": newest,
            "charts": charts,
            "vlan_cards": vlan_chart_cards,
            "vlans": vlans,
            "vlan_total": vlan_total,
            "vlan_label": vlan_label,
            "devices": devices,
            "device_label": device_label,
            "mac": mac,
            "range": period,
            "ranges": RANGE_LABELS,
            "rates": SFLOW_SAMPLING_RATES,
            "scopes": SCOPES,
            "now": now,
        },
        status_code=status_code,
    )


@router.get("/traffic", response_class=HTMLResponse)
def traffic_page(request: Request, username: str = Depends(login_required)) -> Response:
    return _render(request, username)


def render_traffic_page(
    request: Request, username: str, *, error: str | None = None, notice: str | None = None
) -> Response:
    """Read the switch fresh and show the Traffic page, with an optional message."""
    return _render(request, username, error=error, notice=notice)


@router.post("/traffic/sflow", response_class=HTMLResponse)
def traffic_sflow_setup(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    collector: str = Form(""),
    vrf: str = Form(""),
    collector_port: str = Form(""),
    agent: str = Form(""),
    sampling_rate: str = Form(""),
    scope: str = Form(""),
    ports: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Set sFlow up on the switch so it sends its samples to NXray. Asks first."""
    require_csrf(request, csrf)
    form = {
        "collector": collector.strip(),
        "vrf": vrf.strip(),
        "collector_port": collector_port.strip(),
        "agent": agent.strip(),
        "sampling_rate": sampling_rate.strip(),
        "scope": scope.strip(),
        "ports": ports.strip()[:2000],
    }
    found = _read(request)
    connection, target, status, config, front, _neighbors = found

    def fail(message: str) -> Response:
        return _render(request, username, error=message, form=form, status_code=400, found=found)

    if connection is None:
        return fail("No switch is set up yet.")
    if target is None or config is None or front is None:
        return fail(status.message if status else "The switch could not be read.")
    if not connection.traffic_changes_enabled:
        return fail(CHANGES_OFF)
    try:
        plan = plan_sflow(config, front, form)
    except ValueError as exc:
        return fail(str(exc))
    if plan.empty:
        return _render(
            request,
            username,
            notice="Nothing to change: the switch already does this.",
            form=form,
            found=found,
        )
    if confirm != "yes":
        return templates.TemplateResponse(
            request,
            "confirm.html",
            {
                "username": username,
                "title": "sFlow",
                "back_url": "/traffic",
                "back_label": "Traffic",
                "lines": plan.lines,
                "warnings": plan.warnings,
                "action": "/traffic/sflow",
                "fields": form,
                "csrf_token": csrf_token(request),
            },
        )

    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            if plan.turn_on_feature:
                client.set_feature("sflow", True)
            if plan.configures:
                client.configure_sflow(
                    sampling_rate=plan.sampling_rate,
                    collector=plan.collector,
                    vrf=plan.vrf,
                    collector_port=plan.collector_port,
                    agent=plan.agent,
                    add_ports=plan.add_ports,
                    remove_ports=plan.remove_ports,
                )
    except NxapiError as exc:
        log.warning("sFlow setup on %s refused: %s", connection.host, exc)
        message = change_refused(exc, target)
        if plan.turn_on_feature or plan.configures:
            # NX-API keeps every line before the refused one, so the switch
            # may already hold part of the change.
            message += " Lines before the refused one have taken effect and are not saved yet."
            with open_db(request.app.state.settings.db_path) as conn:
                set_unsaved_changes(conn, connection.id, True)
        return fail(message)

    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        set_sflow_agent(conn, connection.id, form["agent"])
        set_unsaved_changes(conn, connection.id, True)
    request.app.state.sflow_collector.set_agents(*load_agents(settings.db_path))
    words = " ".join(plan.lines)
    log.info("sFlow setup on %s by %s: %s", connection.host, username, words)
    note_activity(request, username, "Traffic", f"sFlow: {words}", connection.host)
    listening = (
        ""
        if settings.sflow_port
        else (
            " NXray's collector is off, though: set NXRAY_SFLOW_PORT in nxray.env and publish the "
            "port in docker-compose.yml, or nothing is counted."
        )
    )
    return _render(request, username, notice=f"Done: {words}{listening} {NOT_SAVED}")


@router.post("/traffic/sflow-off", response_class=HTMLResponse)
def traffic_sflow_off(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Turn the sflow feature off on the switch, which removes its sFlow lines. Asks first."""
    require_csrf(request, csrf)
    connection, target, problem = stored_switch(request)

    def fail(message: str) -> Response:
        return _render(request, username, error=message, status_code=400)

    if connection is None or target is None:
        return fail(problem or "No switch is set up yet.")
    if not connection.traffic_changes_enabled:
        return fail(CHANGES_OFF)
    if confirm != "yes":
        return templates.TemplateResponse(
            request,
            "confirm.html",
            {
                "username": username,
                "title": "sFlow",
                "back_url": "/traffic",
                "back_label": "Traffic",
                "lines": ["Turn off the sflow feature on the switch."],
                "warnings": [
                    "The switch stops sending samples and forgets every sFlow line: where they "
                    "went, the sampling rate and the ports. The traffic NXray already measured "
                    "is kept."
                ],
                "action": "/traffic/sflow-off",
                "fields": {},
                "csrf_token": csrf_token(request),
            },
        )
    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            client.set_feature("sflow", False)
    except NxapiError as exc:
        log.warning("sFlow off on %s refused: %s", connection.host, exc)
        return fail(change_refused(exc, target))
    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, connection.id, True)
    note_activity(
        request, username, "Traffic", "sFlow: turned the sflow feature off", connection.host
    )
    return _render(request, username, notice=f"Done: sFlow is off on the switch. {NOT_SAVED}")
