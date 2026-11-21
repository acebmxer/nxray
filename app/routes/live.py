"""The figures that refresh themselves: one small answer per page.

Each route returns the same piece of HTML the full page draws for its figures,
read through ``LiveCache`` so any number of open pages cost the switch one
read per interval. Read-only: nothing here changes a switch, so there are no
forms and no CSRF tokens. The session is not extended (``live_login_required``).
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import live_login_required, may_change, stored_switch, templates
from app.face import color_mode, draw_face, short_device_name, speed_class
from app.history import LIVE
from app.live import (
    CLIENTS,
    HEALTH,
    PORTS,
    LiveAnswer,
    PortReading,
    health_trail_chart,
    health_trail_figures,
    measure_rates,
    port_figures,
    port_trail_chart,
)
from app.live_history import live_system_charts, live_vlan_charts
from app.neighbors import NeighborView, filter_macs, try_load_neighbors
from app.nxapi import SwitchTarget
from app.port_labels import get_labels
from app.ports import COUNTER_LABELS, ERROR_KEYS, load_ports
from app.routes.neighbors import QUERY_MAX
from app.routes.ports import FILTERS, ports_link, ports_summary
from app.sflow import vlan_cards
from app.switch import health_problems
from app.switch_choice import selected_switch_id
from app.switch_connection import SwitchConnection
from app.switch_setup import load_dashboard_status, read_switch
from app.traffic import busiest_devices, device_traffic, port_device

router = APIRouter()


def live_problem_message(answer: LiveAnswer) -> str:
    """The banner for a failed read: why, and that the figures shown are older."""
    if not answer.problem:
        return ""
    older = " The figures below are from the last successful read." if answer.value else ""
    wait = f" Trying again in {answer.retry_in} s." if answer.retry_in else ""
    return f"The switch did not answer: {answer.problem}{older}{wait}"


def no_cache(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    return response


def read_health(request: Request, switch_id: int, target: SwitchTarget, floor: int) -> LiveAnswer:
    """The newest dashboard reading of a switch (CPU, memory, temperatures, fans,
    power), through the cache: the Dashboard and the History page's Live window
    share it, so open pages of either cost the switch the same."""
    transport = request.app.state.nxapi_transport

    def reader(_previous: object) -> tuple[object, str]:
        status, data = load_dashboard_status(target, transport=transport)
        return ((status, data), "") if data is not None else (None, status.message)

    return request.app.state.live_cache.get(
        switch_id, HEALTH, floor, reader, figures=health_trail_figures
    )


@router.get("/live/dashboard", response_class=HTMLResponse)
def live_dashboard(request: Request, username: str = Depends(live_login_required)) -> Response:
    connection, target, error = stored_switch(request)
    if connection is None or target is None:
        # Nothing to read; the page shows why when it is reloaded.
        return Response(status_code=204)
    floor = request.app.state.settings.live_min_interval
    answer = read_health(request, connection.id, target, floor)
    status, data = answer.value if answer.value else (None, None)
    return no_cache(
        templates.TemplateResponse(
            request,
            "_dashboard_live.html",
            {
                "status": status,
                "data": data,
                "problems": health_problems(data) if data else [],
                "live_at": int(answer.read_at),
                "live_problem": live_problem_message(answer),
                "trail_chart": health_trail_chart(answer.trail, now=time.time(), floor=floor),
            },
        )
    )


def read_port_answer(
    request: Request, switch_id: int, target: SwitchTarget, floor: int
) -> LiveAnswer:
    """The newest reading of every port of a switch, with rates measured from
    the byte counters between two readings, through the cache (see
    ``shared_readings``; the History page's Live window reads the ports alone)."""
    transport = request.app.state.nxapi_transport

    def read_ports(previous: PortReading | None) -> tuple[object, str]:
        status, ports = read_switch(target, load_ports, transport)
        if ports is None:
            return None, status.message
        return measure_rates(previous, ports, time.time()), ""

    return request.app.state.live_cache.get(
        switch_id, PORTS, floor, read_ports, figures=port_figures
    )


def shared_readings(
    request: Request, switch_id: int, target: SwitchTarget, ports_floor: int | None = None
) -> tuple[LiveAnswer, NeighborView | None]:
    """The newest port reading and neighbour/MAC reading for a switch, through
    the cache: the Ports page and every port's page share them, so open pages
    of either cost the switch the same. Neighbours are asked for less often.
    ``ports_floor`` raises the wait before the ports are read again, for a page
    that needs them less often than the Ports page does."""
    settings = request.app.state.settings
    transport = request.app.state.nxapi_transport
    cache = request.app.state.live_cache

    def read_neighbors(_previous: object) -> tuple[object, str]:
        status, found = read_switch(target, try_load_neighbors, transport)
        return (found, "") if status.ok else (None, status.message)

    floor = max(settings.live_min_interval, ports_floor or 0)
    answer = read_port_answer(request, switch_id, target, floor)
    neighbors = cache.get(
        switch_id, CLIENTS, settings.live_clients_min_interval, read_neighbors
    ).value
    return answer, neighbors


@router.get("/live/ports", response_class=HTMLResponse)
def live_ports(
    request: Request,
    username: str = Depends(live_login_required),
    show: str = "all",
    color: str = "state",
    port: str = "",
    rates: str = "",
) -> Response:
    """The Ports page's changing figures: counts, front panel, port rows.

    ``rates=live`` asks for In and Out measured from the byte counters between
    two readings instead of the switch's own 30-second average. The port
    table's Connected column and the port-channels come from the slower
    MAC/ARP/neighbour reading, so the switch is asked for those less often.
    """
    connection, target, error = stored_switch(request)
    if connection is None or target is None:
        return Response(status_code=204)
    settings = request.app.state.settings
    answer, neighbors = shared_readings(request, connection.id, target)
    reading: PortReading | None = answer.value
    color = color_mode(color)
    show = show if show in FILTERS else "all"
    measured = rates == "live" and reading is not None and reading.window > 0
    ports = (reading.live if measured else reading.ports) if reading else None
    channels, shown, counts = ports_summary(ports, neighbors, show)
    with open_db(settings.db_path) as conn:
        labels = get_labels(conn, selected_switch_id(request))
    open_port = next((p for p in ports or [] if p.name == port), None)
    face = (
        draw_face(
            ports,
            color,
            labels,
            {},
            neighbors,
            model=connection.switch_model,
            link=lambda name: ports_link(show, color, name),
            selected=open_port.name if open_port else "",
        )
        # The VLAN colours need the VLAN tables, which this does not read.
        if ports and color != "vlan"
        else None
    )
    return no_cache(
        templates.TemplateResponse(
            request,
            "_ports_live_answer.html",
            {
                "ports": ports,
                "shown": shown,
                "counts": counts,
                "channels": channels,
                "labels": labels,
                "neighbors": neighbors,
                "face": face,
                "color": color,
                "show": show,
                "selected": open_port.name if open_port else "",
                "ticked": set(),
                "bulk_on": may_change(request) and connection.changes_enabled,
                "ports_link": ports_link,
                "speed_class": speed_class,
                "short_device_name": short_device_name,
                "throughput": sum(
                    p.in_bits_per_second + p.out_bits_per_second for p in ports or []
                ),
                "rates_window": reading.window if measured and reading else 0,
                "live_at": int(answer.read_at),
                "live_problem": live_problem_message(answer),
            },
        )
    )


@router.get("/live/port", response_class=HTMLResponse)
def live_port(
    request: Request,
    username: str = Depends(live_login_required),
    name: str = "",
    rates: str = "",
) -> Response:
    """One port's page: its state, rates, counters and the devices on it.

    Read like the Ports page's figures (shared readings); 204 for a port the
    switch does not have, so the page is left as it is.
    """
    connection, target, error = stored_switch(request)
    if connection is None or target is None:
        return Response(status_code=204)
    answer, neighbors = shared_readings(request, connection.id, target)
    reading: PortReading | None = answer.value
    measured = rates == "live" and reading is not None and reading.window > 0
    ports = (reading.live if measured else reading.ports) if reading else []
    port = next((p for p in ports if p.name == name), None)
    if port is None:
        return Response(status_code=204)
    devices = neighbors.for_port(name) if neighbors else None
    with open_db(request.app.state.settings.db_path) as conn:
        stored_label = get_labels(conn, selected_switch_id(request)).get(name, "")
    return no_cache(
        templates.TemplateResponse(
            request,
            "_port_live_answer.html",
            {
                "name": name,
                "port": port,
                "stored_label": stored_label,
                "counter_labels": COUNTER_LABELS,
                "error_keys": ERROR_KEYS,
                "neighbors": neighbors,
                "devices": devices,
                "port_traffic": device_traffic([port], neighbors) if neighbors else {},
                "traffic_reason": port_device(port, devices)[1] if devices else "",
                "device_ips": {m.mac: neighbors.ips_of(m.mac) for m in devices.macs}
                if neighbors and devices
                else {},
                "rates_window": reading.window if measured and reading else 0,
                "live_at": int(answer.read_at),
                "live_problem": live_problem_message(answer),
                "trail_chart": port_trail_chart(
                    answer.trail,
                    name,
                    measured=rates == "live",
                    now=time.time(),
                    floor=request.app.state.settings.live_min_interval,
                ),
            },
        )
    )


@router.get("/live/neighbors", response_class=HTMLResponse)
def live_neighbors(
    request: Request,
    username: str = Depends(live_login_required),
    q: str = "",
) -> Response:
    """The Neighbors page's changing figures: who announces themselves, the
    busiest devices and the MAC address table (narrowed by ``q``).

    Read at the slower pace for clients (``NXRAY_LIVE_CLIENTS_MIN_INTERVAL``),
    ports included, since the traffic per device comes from them.
    """
    connection, target, error = stored_switch(request)
    if connection is None or target is None:
        return Response(status_code=204)
    settings = request.app.state.settings
    answer, view = shared_readings(
        request, connection.id, target, ports_floor=settings.live_clients_min_interval
    )
    if view is None:
        # The switch refused the tables; the page keeps what it shows.
        return Response(status_code=204)
    reading: PortReading | None = answer.value
    traffic = device_traffic(reading.ports, view) if reading else {}
    macs = filter_macs(view.macs, q.strip()[:QUERY_MAX])
    busiest = busiest_devices(traffic)
    ips = {entry.mac: view.ips_of(entry.mac) for entry in macs}
    for item in busiest:
        ips.setdefault(item.mac, view.ips_of(item.mac))
    return no_cache(
        templates.TemplateResponse(
            request,
            "_neighbors_live_answer.html",
            {
                "view": view,
                "macs": macs,
                "ips": ips,
                "traffic": traffic,
                "busiest": busiest,
                "makers": {entry.mac: entry.maker_text for entry in view.macs},
                "query": q.strip()[:QUERY_MAX],
                "live_at": int(answer.read_at),
                "live_problem": live_problem_message(answer),
            },
        )
    )


# The dashboard reading (temperatures, fans, power, CPU, memory) changes slowly and
# costs the switch several commands, so the History page's Live window takes it
# this often at most; the ports (the traffic charts) at the usual floor.
HISTORY_HEALTH_SECONDS = 10


def history_live_view(
    request: Request, connection: SwitchConnection, target: SwitchTarget, now: float
) -> dict[str, object]:
    """What the History page's Live window shows: its charts, when the switch was
    last read and, if the newest read failed, why. The switch is read first,
    through the cache and outside any database block."""
    settings = request.app.state.settings
    health = read_health(
        request, connection.id, target, max(settings.live_min_interval, HISTORY_HEALTH_SECONDS)
    )
    ports = read_port_answer(request, connection.id, target, settings.live_min_interval)
    with open_db(settings.db_path) as conn:
        charts = live_system_charts(conn, connection.id, health.trail, ports.trail, now)
        charts += live_vlan_charts(conn, connection.id, ports.trail, now)
    return {
        "charts": charts,
        "live_at": int(max(health.read_at, ports.read_at) or now),
        "live_problem": live_problem_message(ports) or live_problem_message(health),
    }


@router.get("/live/history", response_class=HTMLResponse)
def live_history(request: Request, username: str = Depends(live_login_required)) -> Response:
    """The History page's Live window charts, alone (``_history_live.html``)."""
    connection, target, _error = stored_switch(request)
    if connection is None or target is None:
        return Response(status_code=204)
    return no_cache(
        templates.TemplateResponse(
            request,
            "_history_live.html",
            {"range": LIVE, **history_live_view(request, connection, target, time.time())},
        )
    )


@router.get("/live/traffic", response_class=HTMLResponse)
def live_traffic(request: Request, username: str = Depends(live_login_required)) -> Response:
    """The Traffic page's VLAN cards for the Live window, alone (``_vlan_cards.html``).

    Drawn from what the sFlow collector holds in memory and the stored minutes:
    the switch is not asked at all."""
    settings = request.app.state.settings
    switch_id = selected_switch_id(request)
    now = time.time()
    with open_db(settings.db_path) as conn:
        cards = vlan_cards(conn, switch_id, LIVE, now, request.app.state.sflow_collector)
    return no_cache(
        templates.TemplateResponse(
            request,
            "_vlan_cards.html",
            {"range": LIVE, "vlan_cards": cards, "live_at": int(now)},
        )
    )
