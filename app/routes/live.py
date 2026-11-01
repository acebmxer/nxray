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
from app.dependencies import current_role, live_login_required, stored_switch, templates
from app.face import color_mode, draw_face, short_device_name, speed_class
from app.live import CLIENTS, HEALTH, PORTS, LiveAnswer, PortReading, measure_rates
from app.neighbors import NeighborView, filter_macs, try_load_neighbors
from app.nxapi import SwitchTarget
from app.port_labels import get_labels
from app.ports import COUNTER_LABELS, load_ports
from app.routes.neighbors import QUERY_MAX
from app.routes.ports import FILTERS, ports_link, ports_summary
from app.switch import health_problems
from app.switch_choice import selected_switch_id
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


@router.get("/live/dashboard", response_class=HTMLResponse)
def live_dashboard(request: Request, username: str = Depends(live_login_required)) -> Response:
    connection, target, error = stored_switch(request)
    if connection is None or target is None:
        # Nothing to read; the page shows why when it is reloaded.
        return Response(status_code=204)
    transport = request.app.state.nxapi_transport

    def reader(_previous: object) -> tuple[object, str]:
        status, data = load_dashboard_status(target, transport=transport)
        return ((status, data), "") if data is not None else (None, status.message)

    answer = request.app.state.live_cache.get(
        connection.id, HEALTH, request.app.state.settings.live_min_interval, reader
    )
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
            },
        )
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

    def read_ports(previous: PortReading | None) -> tuple[object, str]:
        status, ports = read_switch(target, load_ports, transport)
        if ports is None:
            return None, status.message
        return measure_rates(previous, ports, time.time()), ""

    def read_neighbors(_previous: object) -> tuple[object, str]:
        status, found = read_switch(target, try_load_neighbors, transport)
        return (found, "") if status.ok else (None, status.message)

    floor = max(settings.live_min_interval, ports_floor or 0)
    answer = cache.get(switch_id, PORTS, floor, read_ports)
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
    role = current_role(request)
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
                "bulk_on": role in ("admin", "operator") and connection.changes_enabled,
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
