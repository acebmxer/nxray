"""The Neighbors page: CDP and LLDP neighbors, the MAC address table and ARP."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, stored_switch, templates
from app.neighbors import NeighborView, filter_macs, load_neighbors
from app.switch_setup import ConnectionStatus, read_switch

router = APIRouter()

# Longest search kept; anything longer cannot match a MAC address, port or maker.
QUERY_MAX = 64


@router.get("/neighbors", response_class=HTMLResponse)
def neighbors_page(
    request: Request, username: str = Depends(login_required), q: str = ""
) -> Response:
    """``GET /neighbors``: read fresh from the switch; ``?q=`` narrows the MAC address table."""
    query = q.strip()[:QUERY_MAX]
    connection, target, problem = stored_switch(request)
    status = None
    view: NeighborView | None = None
    if target is not None:
        status, view = read_switch(
            target, load_neighbors, transport=request.app.state.nxapi_transport
        )
    elif problem:
        status = ConnectionStatus(False, problem)
    macs = filter_macs(view.macs, query) if view else []
    ips = {entry.mac: view.ips_of(entry.mac) for entry in macs} if view else {}
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
        },
    )
