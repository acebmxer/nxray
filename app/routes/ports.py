"""The Ports page: every front-panel port, and one port in detail. Read-only."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, stored_switch, templates
from app.ports import COUNTER_LABELS, Port, load_ports
from app.switch_setup import ConnectionStatus, read_switch

router = APIRouter()

# The filters offered above the table, and which ports each keeps.
FILTERS = {
    "all": lambda port: True,
    "up": lambda port: port.up,
    "down": lambda port: not port.up,
    "errors": lambda port: port.errors > 0,
}


def _read_ports(request: Request):
    """(connection, status, ports): ports is None when they could not be read."""
    connection, target, error = stored_switch(request)
    if target is None:
        status = ConnectionStatus(False, error) if error else None
        return connection, status, None
    status, ports = read_switch(target, load_ports, transport=request.app.state.nxapi_transport)
    return connection, status, ports


@router.get("/ports", response_class=HTMLResponse)
def ports_page(
    request: Request, username: str = Depends(login_required), show: str = "all"
) -> Response:
    connection, status, ports = _read_ports(request)
    if show not in FILTERS:
        show = "all"
    shown: list[Port] = [port for port in ports or [] if FILTERS[show](port)]
    counts = {name: sum(1 for port in ports or [] if keep(port)) for name, keep in FILTERS.items()}
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
        },
    )


@router.get("/ports/detail", response_class=HTMLResponse)
def port_detail(
    request: Request, name: str = "", username: str = Depends(login_required)
) -> Response:
    connection, status, ports = _read_ports(request)
    port = next((p for p in ports or [] if p.name == name), None)
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
        },
        status_code=404 if ports is not None and port is None else 200,
    )
