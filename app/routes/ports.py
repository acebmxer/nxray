"""The Ports page: every front-panel port, one port in detail, and port changes."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import (
    login_required,
    note_activity,
    operator_required,
    require_csrf,
    stored_switch,
    templates,
)
from app.face import MODES, color_mode, draw_face, short_device_name, speed_class
from app.history import RANGE_LABELS, port_charts, range_key
from app.live import PORTS, port_trail_chart
from app.neighbor_changes import (
    PortDiscovery,
    describe_port_discovery,
    load_port_discovery,
    plan_port_discovery,
)
from app.neighbors import NeighborView, try_load_neighbors
from app.nxapi import (
    DEFAULT_LOAD_INTERVAL,
    LOAD_INTERVALS,
    NxapiClient,
    NxapiCommandError,
    NxapiError,
    SwitchTarget,
    validate_description,
)
from app.port_bulk import (
    BULK_FIELDS,
    SPEED_CHOICES,
    BulkStep,
    PortPlan,
    bulk_kinds,
    change_summary,
    check_bulk_form,
    empty_bulk_form,
    form_from_port,
    group_warnings,
    plan_bulk,
)
from app.port_labels import LABEL_MAX, get_labels, set_label
from app.port_settings import (
    BREAKOUT_LABELS,
    FEC_LABELS,
    JUMBO_MTU,
    STANDARD_MTU,
    PortSettings,
    describe_port_settings,
    guess_breakout_map,
    load_interval_label,
    plan_breakout,
    plan_load_interval,
    plan_port_settings,
    speed_label,
    try_load_port_settings,
)
from app.port_settings import settings_form as make_settings_form
from app.ports import COUNTER_LABELS, Port, load_ports
from app.preferences import ui_preferences
from app.security import csrf_token
from app.switch_choice import selected_switch_id
from app.switch_connection import SwitchConnection, set_unsaved_changes
from app.switch_setup import ConnectionStatus, connection_error, read_switch
from app.traffic import device_traffic, port_device
from app.vlans import VlanView, describe_port_vlans, load_ports_with_vlans, plan_port_vlans

router = APIRouter()
log = logging.getLogger("nxray.ports")

# The filters offered above the table: their words, and which ports each keeps
# (given the port and the port-channel it is in, "" for none). None in the
# list is a gap between two groups of filters.
FILTERS: dict[str, Callable[[Port, str], bool]] = {
    "all": lambda port, channel: True,
    "up": lambda port, channel: port.up,
    "down": lambda port, channel: not port.up,
    "off": lambda port, channel: not port.admin_up,
    "errors": lambda port, channel: port.errors > 0,
    "1g": lambda port, channel: port.up and port.bandwidth_bits == 1_000_000_000,
    "10g": lambda port, channel: port.up and port.bandwidth_bits == 10_000_000_000,
    "25g": lambda port, channel: port.up and port.bandwidth_bits == 25_000_000_000,
    "40g": lambda port, channel: port.up and port.bandwidth_bits >= 40_000_000_000,
    "trunk": lambda port, channel: port.vlan == "trunk",
    "channel": lambda port, channel: bool(channel),
}
FILTER_LABELS: list[tuple[str, str] | None] = [
    ("all", "All"),
    ("up", "Up"),
    ("down", "Down"),
    ("off", "Turned off"),
    ("errors", "With errors"),
    None,
    ("1g", "1G"),
    ("10g", "10G"),
    ("25g", "25G"),
    ("40g", "40G / 100G"),
    None,
    ("trunk", "Trunks"),
    ("channel", "In a port-channel"),
]

# What the change form on a port's page can ask for.
ACTIONS = ("description", "off", "on")


@dataclass(frozen=True)
class PortsOrigin:
    """A change sent from a port's side panel on the Ports page: the filter
    and colour mode to show that page with again, the panel still open."""

    show: str
    color: str

    @property
    def fields(self) -> dict[str, str]:
        """The hidden fields that carry this origin through a confirm page."""
        return {"back": "ports", "show": self.show, "color": self.color}


def ports_origin(back: str, show: str, color: str) -> PortsOrigin | None:
    """The Ports page to answer on when ``back`` is "ports", else None (the
    port's own page). Unknown filters and colour modes fall back to the
    defaults, so the fields can never send the browser elsewhere."""
    if back != "ports":
        return None
    return PortsOrigin(show if show in FILTERS else "all", color_mode(color))


def _read_ports(
    request: Request,
) -> tuple[
    SwitchConnection | None,
    SwitchTarget | None,
    ConnectionStatus | None,
    list[Port] | None,
    NeighborView | None,
]:
    """(connection, target, status, ports, neighbors): ports is None when they
    could not be read, neighbors when the switch refused to give them."""
    connection, target, error = stored_switch(request)
    if target is None:
        status = ConnectionStatus(False, error) if error else None
        return connection, None, status, None, None

    def reader(client: NxapiClient) -> tuple[list[Port], NeighborView | None]:
        return load_ports(client), try_load_neighbors(client)

    status, found = read_switch(target, reader, transport=request.app.state.nxapi_transport)
    ports, neighbors = found if found else (None, None)
    return connection, target, status, ports, neighbors


def _read_port_page(
    request: Request, name: str | None = None
) -> tuple[
    SwitchConnection | None,
    SwitchTarget | None,
    ConnectionStatus | None,
    list[Port] | None,
    VlanView | None,
    PortSettings | None,
    NeighborView | None,
    PortDiscovery | None,
]:
    """Like _read_ports, plus the VLANs, for a port's own page.

    With ``name``, also that port's settings and what it does with CDP and
    LLDP, read in later requests once the first shows the port exists (a
    show command naming a missing port would fail the whole request). Each
    of settings, neighbors and discovery is None when it could not be read.
    """
    connection, target, error = stored_switch(request)
    if target is None:
        status = ConnectionStatus(False, error) if error else None
        return connection, None, status, None, None, None, None, None

    def reader(
        client: NxapiClient,
    ) -> tuple[
        list[Port], VlanView, PortSettings | None, NeighborView | None, PortDiscovery | None
    ]:
        ports, view = load_ports_with_vlans(client)
        port = next((p for p in ports if p.name == name), None)
        settings = None
        discovery = None
        if port is not None:
            settings = try_load_port_settings(client, port, view.ports.get(port.name))
        neighbors = try_load_neighbors(client)
        if port is not None:
            lldp_on = neighbors.lldp_enabled if neighbors else False
            discovery = load_port_discovery(client, port.name, lldp_on)
        return ports, view, settings, neighbors, discovery

    status, found = read_switch(target, reader, transport=request.app.state.nxapi_transport)
    ports, view, settings, neighbors, discovery = found if found else (None,) * 5
    return connection, target, status, ports, view, settings, neighbors, discovery


def _labels(request: Request) -> dict[str, str]:
    with open_db(request.app.state.settings.db_path) as conn:
        return get_labels(conn, selected_switch_id(request))


@router.get("/ports", response_class=HTMLResponse)
def ports_page(
    request: Request,
    username: str = Depends(login_required),
    show: str = "all",
    color: str = "state",
    select: str = "",
    port: str = "",
    tick: Annotated[list[str] | None, Query()] = None,
) -> Response:
    return render_ports_page(
        request,
        username,
        show=show,
        color=color,
        tick_all=select == "all",
        ticked=tick,
        selected=port,
    )


def live_ports_link(show: str, color: str, port: str = "") -> str:
    """The address of the Ports page's refreshing figures, for the same filter,
    colour mode and open panel as ``ports_link``."""
    return ports_link(show, color, port).replace("/ports?", "/live/ports?", 1)


def ports_link(show: str, color: str, port: str = "") -> str:
    """The Ports page's address with a filter, a colour mode and, optionally,
    the port whose side panel is open."""
    link = f"/ports?show={quote(show)}&color={quote(color)}"
    return link + (f"&port={quote(port, safe='/')}" if port else "")


def ports_summary(
    ports: list[Port] | None, neighbors: NeighborView | None, show: str
) -> tuple[dict[str, str], list[Port], dict[str, int]]:
    """(channels, shown, counts) for the Ports page: each port's port-channel
    name ("" for none), the ports the filter ``show`` keeps, and how many ports
    each filter would keep."""
    channels = (
        {
            port.name: (pc.name if (pc := neighbors.channel_of(port.name)) else "")
            for port in ports or []
        }
        if neighbors
        else {}
    )

    def keeps(name: str, port: Port) -> bool:
        return FILTERS[name](port, channels.get(port.name, ""))

    shown = [port for port in ports or [] if keeps(show, port)]
    counts = {name: sum(1 for port in ports or [] if keeps(name, port)) for name in FILTERS}
    return channels, shown, counts


def render_ports_page(
    request: Request,
    username: str,
    *,
    show: str = "all",
    color: str = "state",
    error: str | None = None,
    notice: str | None = None,
    tick_all: bool = False,
    ticked: list[str] | None = None,
    bulk: dict[str, str] | None = None,
    selected: str = "",
    form_values: dict[str, Any] | None = None,
    found: tuple | None = None,
    status_code: int = 200,
) -> Response:
    """Read the switch fresh and show the Ports page, with an optional message.

    ``tick_all`` ticks every port the filter shows; ``ticked`` keeps the ports
    ticked and ``bulk`` what the shared form holds after a refusal (or a fill
    from one port; see app/port_bulk.py).
    ``selected`` names the port whose side panel is open; ``form_values`` keeps
    what was typed in one of its forms after a refusal (see port_forms), and
    ``found`` is what _read_port_page just read for it, to skip a second read.
    """
    color = color_mode(color)
    vlan_names: dict[int, str] = {}
    view: VlanView | None = None
    port_settings: PortSettings | None = None
    discovery: PortDiscovery | None = None
    if color == "vlan" or selected:
        # The VLAN colours and an open panel's forms need the VLANs (and the
        # panel its port's settings and CDP/LLDP), so only they ask for them.
        connection, _, status, ports, view, port_settings, neighbors, discovery = (
            found or _read_port_page(request, selected or None)
        )
        if color == "vlan" and view:
            vlan_names = {vlan.id: vlan.name for vlan in view.vlans}
    else:
        connection, _, status, ports, neighbors = _read_ports(request)
    if show not in FILTERS:
        show = "all"
    labels = _labels(request)
    channels, shown, counts = ports_summary(ports, neighbors, show)
    open_port = next((port for port in ports or [] if port.name == selected), None)
    face = (
        draw_face(
            ports,
            color,
            labels,
            vlan_names,
            neighbors,
            model=connection.switch_model if connection else "",
            link=lambda name: ports_link(show, color, name),
            selected=open_port.name if open_port else "",
        )
        if ports
        else None
    )
    names = [port.name for port in ports or []]
    drawer = None
    if open_port is not None and connection is not None:
        at = names.index(open_port.name)
        with open_db(request.app.state.settings.db_path) as conn:
            charts = port_charts(conn, connection.id, open_port.name, range_key(None), time.time())
        drawer = {
            "port": open_port,
            "forms": port_forms(
                request,
                open_port.name,
                ports,
                view,
                port_settings,
                neighbors,
                discovery,
                **(form_values or {}),
            ),
            "back": PortsOrigin(show, color).fields,
            "devices": neighbors.for_port(open_port.name) if neighbors else None,
            "device_traffic": device_traffic([open_port], neighbors) if neighbors else {},
            "chart": charts[0] if charts else None,
            "previous": ports_link(show, color, names[at - 1]),
            "next": ports_link(show, color, names[(at + 1) % len(names)]),
            "close": ports_link(show, color),
        }
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
            "labels": labels,
            "face": face,
            "color": color,
            "modes": MODES,
            "neighbors": neighbors,
            "csrf_token": csrf_token(request),
            "error": error,
            "notice": notice,
            "ticked": {port.name for port in shown} if tick_all else set(ticked or []),
            "bulk": bulk or empty_bulk_form(),
            "bulk_speeds": SPEED_CHOICES,
            "speed_label": speed_label,
            "fec_labels": FEC_LABELS,
            "filter_labels": FILTER_LABELS,
            "channels": channels,
            "drawer": drawer,
            "selected": open_port.name if open_port else "",
            "ports_link": ports_link,
            "speed_class": speed_class,
            "short_device_name": short_device_name,
            "throughput": sum(
                port.in_bits_per_second + port.out_bits_per_second for port in ports or []
            ),
            # Figures that refresh themselves (app/live.py), only on the plain
            # view: never on a result, a refusal or a form being filled in.
            **(
                {
                    "live_page": PORTS,
                    "live_url": live_ports_link(show, color, open_port.name if open_port else ""),
                    "live_at": int(time.time()),
                    "live_problem": "",
                    "rates_window": 0,
                }
                if ports
                and status_code == 200
                and not (error or notice or tick_all or ticked or bulk or form_values)
                else {"live_at": 0, "live_problem": "", "rates_window": 0}
            ),
        },
        status_code=status_code,
    )


def port_forms(
    request: Request,
    name: str,
    ports: list[Port] | None,
    view: VlanView | None,
    port_settings: PortSettings | None,
    neighbors: NeighborView | None,
    discovery: PortDiscovery | None,
    *,
    description: str | None = None,
    vlan_form: dict[str, str] | None = None,
    settings_form: dict[str, str] | None = None,
    label: str | None = None,
) -> dict[str, Any]:
    """What the forms that change one port need (templates/_port_forms.html),
    for the port's own page and its side panel alike.

    ``description``, ``vlan_form``, ``settings_form`` and ``label`` keep what
    was typed after a refusal; left out, each form shows what the switch (or,
    for the label, NXray) has now.
    """
    port = next((p for p in ports or [] if p.name == name), None)
    if settings_form is None and port_settings is not None:
        settings_form = make_settings_form(port_settings)
    stored_label = _labels(request).get(name, "")
    if label is None:
        label = stored_label
    vlans = view.ports.get(name) if view else None
    if vlan_form is None and vlans is not None:
        vlan_form = {
            "mode": vlans.mode,
            "access_vlan": str(vlans.access_vlan),
            "native_vlan": str(vlans.native_vlan),
            "allowed": vlans.allowed_text,
        }
    if description is None:
        description = port.description if port else ""
    return {
        "port": port,
        # After a refusal the box keeps what was typed.
        "description": description,
        "view": view,
        "vlans": vlans,
        "vlan_form": vlan_form,
        # The stored label, and what the label box holds (what was typed, after a refusal).
        "stored_label": stored_label,
        "label": label,
        "label_max": LABEL_MAX,
        "settings": port_settings,
        "settings_form": settings_form,
        "speed_label": speed_label,
        "fec_labels": FEC_LABELS,
        "breakout_labels": BREAKOUT_LABELS,
        "breakout_guess": _breakout_guess(port_settings, ports),
        "standard_mtu": STANDARD_MTU,
        "jumbo_mtu": JUMBO_MTU,
        "neighbors": neighbors,
        "discovery": discovery,
        "load_intervals": [n for n in LOAD_INTERVALS if n != DEFAULT_LOAD_INTERVAL],
        "default_load_interval": DEFAULT_LOAD_INTERVAL,
        "load_interval_label": load_interval_label,
    }


def _render_port(
    request: Request,
    username: str,
    name: str,
    connection: SwitchConnection | None,
    status: ConnectionStatus | None,
    ports: list[Port] | None,
    view: VlanView | None = None,
    port_settings: PortSettings | None = None,
    neighbors: NeighborView | None = None,
    discovery: PortDiscovery | None = None,
    *,
    error: str | None = None,
    notice: str | None = None,
    status_code: int | None = None,
    **form_values: Any,
) -> Response:
    forms = port_forms(
        request, name, ports, view, port_settings, neighbors, discovery, **form_values
    )
    port = forms["port"]
    if status_code is None:
        status_code = 404 if ports is not None and port is None else 200
    devices = neighbors.for_port(name) if neighbors and port else None
    # The port's traffic is a device's own only when it is alone on an access port.
    traffic_reason = port_device(port, devices)[1] if port and devices else ""
    port_traffic = device_traffic([port], neighbors) if port and neighbors else {}
    period = range_key(request.query_params.get("range"))
    trail_chart = None
    if port and connection is not None:
        trail_chart = port_trail_chart(
            request.app.state.live_cache.trail(connection.id, PORTS),
            name,
            measured=ui_preferences(request).live == "live",
            now=time.time(),
            floor=request.app.state.settings.live_min_interval,
        )
    charts = []
    if port:
        with open_db(request.app.state.settings.db_path) as conn:
            charts = port_charts(conn, selected_switch_id(request), name, period, time.time())
    return templates.TemplateResponse(
        request,
        "port.html",
        {
            **forms,
            "forms": forms,
            "username": username,
            "connection": connection,
            "status": status,
            "ports": ports,
            "name": name,
            "counter_labels": COUNTER_LABELS,
            "csrf_token": csrf_token(request),
            "error": error,
            "notice": notice,
            "charts": charts,
            "range": period,
            "ranges": RANGE_LABELS,
            "devices": devices,
            "port_traffic": port_traffic,
            "traffic_reason": traffic_reason,
            "device_ips": {m.mac: neighbors.ips_of(m.mac) for m in devices.macs}
            if neighbors and devices
            else {},
            "live_at": int(time.time()),
            "live_problem": "",
            "rates_window": 0,
            "trail_chart": trail_chart,
            # Figures that refresh themselves, only on the plain view.
            **(
                {"live_page": PORTS, "live_url": f"/live/port?name={quote(name, safe='')}"}
                if port and status_code == 200 and not (error or notice or form_values)
                else {}
            ),
        },
        status_code=status_code,
    )


def answer_port_change(
    request: Request,
    username: str,
    name: str,
    origin: PortsOrigin | None,
    found: tuple | None = None,
    **kwargs: Any,
) -> Response:
    """The page a change of one port answers on: the port's own page, or the
    Ports page with the port's side panel open when the form came from there.

    ``found`` is what _read_port_page read for ``name``; left out, the switch
    is read fresh (as after a change). ``kwargs`` are the message, status
    code and what was typed, as _render_port takes them.
    """
    if origin is not None:
        error = kwargs.pop("error", None)
        return render_ports_page(
            request,
            username,
            show=origin.show,
            color=origin.color,
            selected=name,
            error=error,
            notice=kwargs.pop("notice", None),
            status_code=kwargs.pop("status_code", None) or 200,
            form_values=kwargs,
            found=found,
        )
    connection, _, status, ports, view, port_settings, neighbors, discovery = (
        found or _read_port_page(request, name)
    )
    return _render_port(
        request,
        username,
        name,
        connection,
        status,
        ports,
        view,
        port_settings,
        neighbors,
        discovery,
        **kwargs,
    )


def change_back(origin: PortsOrigin | None, name: str) -> tuple[str, str]:
    """(where a confirm page's Cancel goes, its words) for a change of one port."""
    if origin is not None:
        return ports_link(origin.show, origin.color, name), "Ports"
    return f"/ports/detail?name={quote(name, safe='')}", name


@router.get("/ports/detail", response_class=HTMLResponse)
def port_detail(
    request: Request, name: str = "", username: str = Depends(login_required)
) -> Response:
    return render_port_page(request, username, name)


def render_port_page(
    request: Request,
    username: str,
    name: str,
    *,
    error: str | None = None,
    notice: str | None = None,
) -> Response:
    """Read the switch fresh and show one port's page, with an optional message."""
    connection, _, status, ports, view, port_settings, neighbors, discovery = _read_port_page(
        request, name
    )
    return _render_port(
        request,
        username,
        name,
        connection,
        status,
        ports,
        view,
        port_settings,
        neighbors,
        discovery,
        error=error,
        notice=notice,
    )


def change_refused(exc: NxapiError, target: SwitchTarget) -> str:
    """The message for a port change the switch did not make."""
    text = str(exc).lower()
    if isinstance(exc, NxapiCommandError) and "interface permission denied" in text:
        return (
            "The switch refused: NXray's role on the switch does not name this port. That "
            "happens to the ports a 100G port was split into, or joined back into. An NXray "
            "admin presses Update the port list on the Switch page, then try again."
        )
    if isinstance(exc, NxapiCommandError) and "permission denied" in text:
        return (
            "The switch refused: NXray's account may not make this change yet. If port "
            "changes were turned on a few minutes ago the switch may not have applied them; "
            "leave NXray's pages closed for 10 minutes, then try again."
        )
    return connection_error(exc, target)


@router.post("/ports/change", response_class=HTMLResponse)
def port_change(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    name: str = Form(""),
    action: str = Form(""),
    description: str = Form(""),
    back: str = Form(""),
    show: str = Form(""),
    color: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Change one port. Without confirm=yes, shows what would happen and asks."""
    require_csrf(request, csrf)
    origin = ports_origin(back, show, color)
    found = _read_port_page(request, name)
    connection, target, status, ports, view, port_settings, neighbors, discovery = found
    port = next((p for p in ports or [] if p.name == name), None)

    def again(**kwargs) -> Response:
        return answer_port_change(request, username, name, origin, found, **kwargs)

    if connection is None or target is None or port is None:
        return again()
    if not connection.changes_enabled:
        return again(
            error="Port changes are off. Turn them on on the Switch page first.",
            status_code=400,
        )
    if action not in ACTIONS:
        return again(error="Pick a change to make.", status_code=400)
    if action == "description":
        try:
            description = validate_description(description)
        except ValueError as exc:
            return again(error=f"Not changed: {exc}.", description=description, status_code=400)
        if description == port.description:
            return again(notice="Nothing to change: the port already has that description.")

    summary, warning = change_summary(port, action, description)
    if confirm != "yes":
        back_url, back_label = change_back(origin, name)
        return templates.TemplateResponse(
            request,
            "port_confirm.html",
            {
                "username": username,
                "port": port,
                "back_url": back_url,
                "back_label": back_label,
                "origin": origin.fields if origin else {},
                "action": action,
                "description": description,
                "summary": summary,
                "warning": warning,
                "csrf_token": csrf_token(request),
            },
        )

    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            if action == "description":
                client.configure_port(name, description=description)
            else:
                client.configure_port(name, enabled=action == "on")
    except NxapiError as exc:
        log.warning("port change on %s refused: %s", name, exc)
        return again(error=change_refused(exc, target), status_code=400)

    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        set_unsaved_changes(conn, selected_switch_id(request), True)
    log.info("port change on %s by %s: %s", connection.host, username, summary)
    note_activity(request, username, "Ports", summary, connection.host)

    if action == "description":
        done = (
            f'{name} now has the description "{description}".'
            if description
            else f"{name} no longer has a description."
        )
    else:
        done = f"{name} is turned {action}."
    return answer_port_change(
        request,
        username,
        name,
        origin,
        # Read again, so the page shows what the switch now reports.
        notice=f"Done: {done} Not saved yet: Save config keeps it over a restart of the switch.",
    )


# The Switch page switch each kind of change in the shared form needs: the
# connection's attribute, and the words of the refusal while it is off.
BULK_SWITCHES = {
    "port": ("changes_enabled", "Port changes are off."),
    "vlans": ("vlan_changes_enabled", "VLAN changes are off."),
    "settings": ("settings_changes_enabled", "Port settings changes are off."),
    "discovery": ("neighbor_changes_enabled", "Neighbor changes are off."),
    "macs": ("neighbor_changes_enabled", "Neighbor changes are off."),
}


def _read_bulk(
    request: Request, target: SwitchTarget, names: list[str], kinds: set[str]
) -> tuple[ConnectionStatus, tuple | None]:
    """Read what the shared form is checked against: (ports, VLANs, neighbors,
    settings by port, CDP/LLDP by port). Each ticked port's settings and
    CDP/LLDP are read only when the form changes them, and only for ports
    the switch reported (a show command naming a missing port fails the
    whole request)."""

    def reader(client: NxapiClient) -> tuple:
        ports, view = load_ports_with_vlans(client)
        neighbors = try_load_neighbors(client)
        settings: dict[str, PortSettings | None] = {}
        discovery: dict[str, PortDiscovery | None] = {}
        wanted = set(names)
        for port in ports:
            if port.name not in wanted:
                continue
            if "settings" in kinds:
                settings[port.name] = try_load_port_settings(
                    client, port, view.ports.get(port.name)
                )
            if "discovery" in kinds:
                lldp_on = neighbors.lldp_enabled if neighbors else False
                discovery[port.name] = load_port_discovery(client, port.name, lldp_on)
        return ports, view, neighbors, settings, discovery

    return read_switch(target, reader, transport=request.app.state.nxapi_transport)


def _bulk_failure(
    done: list[PortPlan], failed: PortPlan, made: list[BulkStep], reason: str, untried: list[str]
) -> str:
    """What a change of several ports did when the switch refused part of it."""
    parts = []
    if done:
        parts.append("Changed: " + " ".join(plan.summary for plan in done))
    step = failed.steps[len(made)]
    name = failed.port.name
    if made:
        lines = " ".join(line for kept in made for line in kept.lines)
        parts.append(
            f"{name} was changed only in part: {lines} Then the switch refused the next part "
            f"({step.what})."
        )
    else:
        parts.append(f"{name} was not changed.")
    parts.append(reason)
    if untried:
        parts.append(f"Not tried: {', '.join(untried)}.")
    return " ".join(parts)


@router.post("/ports/bulk", response_class=HTMLResponse)
def ports_bulk_change(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    names: Annotated[list[str] | None, Form()] = None,
    power: str = Form(""),
    set_description: str = Form(""),
    description: str = Form(""),
    mode: str = Form(""),
    access_vlan: str = Form(""),
    native_vlan: str = Form(""),
    allowed: str = Form(""),
    layer: str = Form(""),
    speed: str = Form(""),
    mtu: str = Form(""),
    fec: str = Form(""),
    flow_receive: str = Form(""),
    flow_send: str = Form(""),
    storm_broadcast: str = Form(""),
    storm_multicast: str = Form(""),
    storm_unicast: str = Form(""),
    storm_action: str = Form(""),
    cdp: str = Form(""),
    lldp_transmit: str = Form(""),
    lldp_receive: str = Form(""),
    clear_macs: str = Form(""),
    start: str = Form(""),
    fill: str = Form(""),
    show: str = Form("all"),
    color: str = Form("state"),
    confirm: str = Form(""),
) -> Response:
    """Apply one shared configuration to every ticked port.

    Every setting left empty stays as each port has it. With fill=yes, fills
    the form from the port named in ``start`` instead, and changes nothing.
    Without confirm=yes, shows every port and what would change on it, and
    asks. The ports are changed one at a time, each kind of change in its
    own request; the first refusal stops the rest, and the page names what
    changed, what was refused and what was not tried.
    """
    require_csrf(request, csrf)
    # The shared form's fields are this function's parameters of the same names.
    given = locals()
    raw = {key: str(given[key]) for key in BULK_FIELDS}
    names = list(dict.fromkeys(names or []))

    def again(bulk: dict[str, str] = raw, **kwargs) -> Response:
        return render_ports_page(
            request, username, show=show, color=color, ticked=names, bulk=bulk, **kwargs
        )

    connection, target, _ = stored_switch(request)
    if connection is None or target is None:
        return again()
    if not connection.changes_enabled:
        return again(
            error="Port changes are off. Turn them on on the Switch page first.",
            status_code=400,
        )
    if fill == "yes":
        return _fill_bulk_form(request, username, start, raw, again)

    try:
        form = check_bulk_form(raw)
    except ValueError as exc:
        return again(error=f"Not changed: {exc}.", status_code=400)
    kinds = bulk_kinds(form)
    for kind in sorted(kinds):
        attribute, words = BULK_SWITCHES[kind]
        if not getattr(connection, attribute):
            return again(error=f"{words} Turn them on on the Switch page first.", status_code=400)

    status, found = _read_bulk(request, target, names, kinds)
    if found is None:
        return again(error=status.message, status_code=400)
    ports, view, neighbors, settings, discovery = found
    try:
        changing, already = plan_bulk(
            ports,
            names,
            form,
            view=view,
            settings=settings,
            discovery=discovery,
            neighbors=neighbors,
        )
    except ValueError as exc:
        return again(error=f"Not changed: {exc}.", status_code=400)
    if not changing:
        return again(notice="Nothing to change: " + " ".join(already))

    if confirm != "yes":
        return templates.TemplateResponse(
            request,
            "confirm.html",
            {
                "username": username,
                "title": "Ports",
                "back_url": "/ports",
                "back_label": "All ports",
                "lines": [plan.summary for plan in changing]
                + [f"Unchanged: {line}" for line in already],
                "warnings": group_warnings(changing),
                "action": "/ports/bulk",
                "fields": {
                    "names": [plan.port.name for plan in changing],
                    **form,
                    "show": show,
                    "color": color,
                },
                "csrf_token": csrf_token(request),
            },
        )

    done: list[PortPlan] = []
    current: PortPlan | None = None
    made: list[BulkStep] = []
    refusal: str | None = None
    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            for plan in changing:
                current, made = plan, []
                for step in plan.steps:
                    step.run(client)
                    made.append(step)
                done.append(plan)
    except NxapiError as exc:
        failed = current or changing[0]
        log.warning("bulk change on %s refused: %s", failed.port.name, exc)
        untried = [plan.port.name for plan in changing[len(done) + 1 :]]
        refusal = _bulk_failure(done, failed, made, change_refused(exc, target), untried)

    applied = [step for plan in done for step in plan.steps] + (made if refusal else [])
    if applied:
        if any(step.config for step in applied):
            with open_db(request.app.state.settings.db_path) as conn:
                set_unsaved_changes(conn, selected_switch_id(request), True)
        summary = " ".join(plan.summary for plan in done)
        if refusal and made and current is not None:
            summary += f" {current.port.name} (in part): " + " ".join(
                line for step in made for line in step.lines
            )
        summary = summary.strip()
        log.info("bulk port change on %s by %s: %s", connection.host, username, summary)
        note_activity(request, username, "Ports", summary, connection.host)

    not_saved = (
        " Not saved yet: Save config keeps the changes over a restart of the switch."
        if any(step.config for step in applied)
        else ""
    )
    if refusal is None:
        listed = ", ".join(plan.port.name for plan in done)
        details = " ".join(plan.summary for plan in done)
        left = f" Left as they were: {' '.join(already)}" if already else ""
        return render_ports_page(
            request,
            username,
            show=show,
            color=color,
            notice=f"Done: changed {listed}. {details}{left}{not_saved}",
        )
    return again(error=refusal + not_saved, status_code=400)


def _fill_bulk_form(
    request: Request,
    username: str,
    start: str,
    raw: dict[str, str],
    again: Callable[..., Response],
) -> Response:
    """The Ports page with the shared form filled from one port ("Start from
    port"): its VLANs, settings and CDP/LLDP; on/off and the description stay
    as they were typed. Changes nothing on the switch."""
    found = _read_port_page(request, start or None)
    _, _, status, ports, view, port_settings, _, discovery = found
    port = next((p for p in ports or [] if p.name == start), None)
    if ports is None:
        return again(error=status.message if status else None, status_code=400)
    if port is None:
        return again(error="Pick a port to start from.", status_code=400)
    filled = form_from_port(
        port, port_settings, view.ports.get(port.name) if view else None, discovery
    )
    for key in ("power", "set_description", "description", "clear_macs"):
        filled[key] = raw.get(key, "")
    filled["start"] = port.name
    return again(
        bulk=filled,
        notice=(
            f"The form now holds the VLANs, port settings and CDP/LLDP of {port.name}. "
            "Nothing was changed yet: change what you need, tick the ports and press "
            "Change the ticked ports."
        ),
    )


@router.post("/ports/vlans", response_class=HTMLResponse)
def port_vlans_change(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    name: str = Form(""),
    mode: str = Form(""),
    access_vlan: str = Form(""),
    native_vlan: str = Form(""),
    allowed: str = Form(""),
    back: str = Form(""),
    show: str = Form(""),
    color: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Set a port's mode and VLANs. Without confirm=yes, shows what would happen and asks."""
    require_csrf(request, csrf)
    origin = ports_origin(back, show, color)
    back_url, back_label = change_back(origin, name)
    found = _read_port_page(request, name)
    connection, target, status, ports, view, port_settings, neighbors, discovery = found
    port = next((p for p in ports or [] if p.name == name), None)
    current = view.ports.get(name) if view else None
    form = {
        "mode": mode,
        "access_vlan": access_vlan,
        "native_vlan": native_vlan,
        "allowed": allowed,
    }

    def again(**kwargs) -> Response:
        return answer_port_change(request, username, name, origin, found, **kwargs)

    if connection is None or target is None or port is None or view is None:
        return again()
    if not connection.vlan_changes_enabled:
        return again(
            error="VLAN changes are off. Turn them on on the Switch page first.",
            status_code=400,
        )
    if current is None:
        return again(error=f"The switch reported no VLAN settings for {name}.", status_code=400)
    try:
        change = plan_port_vlans(
            current,
            view,
            mode=mode,
            access_vlan=access_vlan,
            native_vlan=native_vlan,
            allowed=allowed,
        )
    except ValueError as exc:
        return again(error=f"Not changed: {exc}.", vlan_form=form, status_code=400)
    if change.empty:
        return again(notice="Nothing to change: the port already has these VLAN settings.")

    lines, warnings = describe_port_vlans(current, change)
    if confirm != "yes":
        return templates.TemplateResponse(
            request,
            "confirm.html",
            {
                "username": username,
                "title": port.name,
                "back_url": back_url,
                "back_label": back_label,
                "lines": lines,
                "warnings": warnings,
                "action": "/ports/vlans",
                "fields": {"name": port.name, **form, **(origin.fields if origin else {})},
                "csrf_token": csrf_token(request),
            },
        )

    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            client.configure_port_vlans(
                name,
                mode=change.mode,
                access_vlan=change.access_vlan,
                native_vlan=change.native_vlan,
                allowed_vlans=change.allowed_vlans,
            )
    except NxapiError as exc:
        log.warning("VLAN change on %s refused: %s", name, exc)
        return again(error=change_refused(exc, target), vlan_form=form, status_code=400)

    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        set_unsaved_changes(conn, selected_switch_id(request), True)
    log.info("VLAN change on %s by %s: %s %s", connection.host, username, name, " ".join(lines))
    note_activity(request, username, "Ports", f"{name}: {'; '.join(lines)}", connection.host)

    return answer_port_change(
        request,
        username,
        name,
        origin,
        notice=(
            f"Done: {' '.join(lines)} Not saved yet: Save config keeps it over a restart of "
            "the switch."
        ),
    )


@router.post("/ports/label", response_class=HTMLResponse)
def port_label(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    name: str = Form(""),
    label: str = Form(""),
    back: str = Form(""),
    show: str = Form(""),
    color: str = Form(""),
) -> Response:
    """Set or remove a port's label. Kept in NXray only, so no confirm step and no switch call."""
    require_csrf(request, csrf)
    origin = ports_origin(back, show, color)
    found = _read_port_page(request, name)
    connection, _, status, ports, view, port_settings, neighbors, discovery = found
    port = next((p for p in ports or [] if p.name == name), None)

    def again(**kwargs) -> Response:
        return answer_port_change(request, username, name, origin, found, **kwargs)

    if port is None:
        return again()
    try:
        with open_db(request.app.state.settings.db_path) as conn:
            stored = set_label(conn, selected_switch_id(request), name, label, username)
    except ValueError as exc:
        return again(error=f"Label not saved: {exc}.", label=label, status_code=400)
    log.info("port label on %s by %s: %r", name, username, stored)
    note_activity(
        request,
        username,
        "Ports",
        f"{name}: label set to {stored!r}" if stored else f"{name}: label removed",
    )
    done = f'{name} now has the label "{stored}".' if stored else f"{name} no longer has a label."
    return again(notice=f"Done: {done} Labels are kept in NXray only; the switch is not changed.")


# ---- port settings and breakout ---------------------------------------------


def _breakout_guess(settings: PortSettings | None, ports: list[Port] | None) -> str | None:
    """For one of four split ports: the split they were made with, when it shows."""
    if settings is None or not settings.is_breakout_port:
        return None
    prefix = settings.parent + "/"
    return guess_breakout_map(
        [port.status_speed for port in ports or [] if port.name.startswith(prefix)]
    )


@router.post("/ports/settings", response_class=HTMLResponse)
def port_settings_change(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    name: str = Form(""),
    layer: str = Form(""),
    ip_address: str = Form(""),
    speed: str = Form(""),
    mtu: str = Form(""),
    fec: str = Form(""),
    flow_receive: str = Form(""),
    flow_send: str = Form(""),
    storm_broadcast: str = Form(""),
    storm_multicast: str = Form(""),
    storm_unicast: str = Form(""),
    storm_action: str = Form(""),
    back: str = Form(""),
    show: str = Form(""),
    color: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Change a port's settings. Without confirm=yes, shows what would happen and asks."""
    require_csrf(request, csrf)
    origin = ports_origin(back, show, color)
    back_url, back_label = change_back(origin, name)
    form = {
        "layer": layer,
        "ip_address": ip_address,
        "speed": speed,
        "mtu": mtu,
        "fec": fec,
        "flow_receive": flow_receive,
        "flow_send": flow_send,
        "storm_broadcast": storm_broadcast,
        "storm_multicast": storm_multicast,
        "storm_unicast": storm_unicast,
        "storm_action": storm_action,
    }
    found = _read_port_page(request, name)
    connection, target, status, ports, view, current, neighbors, discovery = found
    port = next((p for p in ports or [] if p.name == name), None)

    def again(**kwargs) -> Response:
        return answer_port_change(request, username, name, origin, found, **kwargs)

    if connection is None or target is None or port is None:
        return again()
    if not connection.settings_changes_enabled:
        return again(
            error="Port settings changes are off. Turn them on on the Switch page first.",
            status_code=400,
        )
    if current is None:
        return again(error=f"The switch did not report the settings of {name}.", status_code=400)
    try:
        change = plan_port_settings(current, form)
    except ValueError as exc:
        return again(error=f"Not changed: {exc}.", settings_form=form, status_code=400)
    if change.empty:
        return again(notice="Nothing to change: the port already has these settings.")

    lines, warnings = describe_port_settings(current, change, up=port.up)
    if confirm != "yes":
        return templates.TemplateResponse(
            request,
            "confirm.html",
            {
                "username": username,
                "title": port.name,
                "back_url": back_url,
                "back_label": back_label,
                "lines": lines,
                "warnings": warnings,
                "action": "/ports/settings",
                "fields": {"name": port.name, **form, **(origin.fields if origin else {})},
                "csrf_token": csrf_token(request),
            },
        )

    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            client.configure_port_settings(
                name,
                layer=change.layer,
                remove_extra=change.remove_extra,
                remove_ip=change.remove_ip,
                ip_address=change.ip_address,
                speed=change.speed,
                mtu=change.mtu,
                fec=change.fec,
                flow_receive=change.flow_receive,
                flow_send=change.flow_send,
                storm_levels=change.storm_levels,
                storm_action=change.storm_action,
                old_storm_action=current.storm_action,
            )
    except NxapiError as exc:
        log.warning("settings change on %s refused: %s", name, exc)
        return again(error=change_refused(exc, target), settings_form=form, status_code=400)

    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, selected_switch_id(request), True)
    log.info("settings change on %s by %s: %s %s", connection.host, username, name, " ".join(lines))
    note_activity(request, username, "Ports", f"{name}: {'; '.join(lines)}", connection.host)

    return answer_port_change(
        request,
        username,
        name,
        origin,
        notice=(
            f"Done: {' '.join(lines)} Not saved yet: Save config keeps it over a restart of "
            "the switch."
        ),
    )


@router.post("/ports/breakout", response_class=HTMLResponse)
def port_breakout(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    name: str = Form(""),
    action: str = Form(""),
    mapping: str = Form(""),
    back: str = Form(""),
    show: str = Form(""),
    color: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Split a 100G port into four, or join four back. Asks to confirm first."""
    require_csrf(request, csrf)
    origin = ports_origin(back, show, color)
    back_url, back_label = change_back(origin, name)
    found = _read_port_page(request, name)
    connection, target, status, ports, view, current, neighbors, discovery = found
    port = next((p for p in ports or [] if p.name == name), None)

    def again(**kwargs) -> Response:
        return answer_port_change(request, username, name, origin, found, **kwargs)

    if connection is None or target is None or port is None:
        return again()
    if not connection.settings_changes_enabled:
        return again(
            error="Port settings changes are off. Turn them on on the Switch page first.",
            status_code=400,
        )
    if current is None:
        return again(error=f"The switch did not report the settings of {name}.", status_code=400)
    try:
        plan = plan_breakout(current, action, mapping)
    except ValueError as exc:
        return again(error=f"Not changed: {exc}.", status_code=400)

    if confirm != "yes":
        return templates.TemplateResponse(
            request,
            "confirm.html",
            {
                "username": username,
                "title": port.name,
                "back_url": back_url,
                "back_label": back_label,
                "lines": plan.lines,
                "warnings": plan.warnings,
                "action": "/ports/breakout",
                "fields": {
                    "name": port.name,
                    "action": action,
                    "mapping": mapping,
                    **(origin.fields if origin else {}),
                },
                "csrf_token": csrf_token(request),
            },
        )

    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            if plan.action == "split":
                client.breakout_port(plan.port, plan.mapping)
            else:
                client.join_port(plan.port, plan.mapping)
    except NxapiError as exc:
        log.warning("%s of %s refused: %s", plan.action, plan.port, exc)
        return again(error=change_refused(exc, target), status_code=400)

    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, selected_switch_id(request), True)
    log.info("%s of %s by %s (%s)", plan.action, plan.port, username, plan.mapping)
    note_activity(
        request,
        username,
        "Ports",
        f"{plan.action} of {plan.port} ({plan.mapping})",
        connection.host,
    )

    # The port this page was for is gone now; show the one that replaced it.
    shown = f"{plan.port}/1" if plan.action == "split" else plan.port
    return answer_port_change(
        request,
        username,
        shown,
        origin,
        notice=(
            f"Done: {' '.join(plan.lines)} An NXray admin now presses Update the port list on "
            "the Switch page so NXray may change the new ports. Not saved yet: Save config "
            "keeps it over a restart of the switch."
        ),
    )


# ---- CDP and LLDP on a port --------------------------------------------------


@router.post("/ports/discovery", response_class=HTMLResponse)
def port_discovery_change(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    name: str = Form(""),
    cdp: str = Form(""),
    lldp_transmit: str = Form(""),
    lldp_receive: str = Form(""),
    lldp_shown: str = Form(""),
    back: str = Form(""),
    show: str = Form(""),
    color: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Turn CDP and LLDP sending and listening on or off on a port. Asks first.

    The form is tick boxes: a box that is not sent means off.
    """
    require_csrf(request, csrf)
    origin = ports_origin(back, show, color)
    back_url, back_label = change_back(origin, name)
    found = _read_port_page(request, name)
    connection, target, status, ports, view, current, neighbors, discovery = found
    port = next((p for p in ports or [] if p.name == name), None)

    def again(**kwargs) -> Response:
        return answer_port_change(request, username, name, origin, found, **kwargs)

    if connection is None or target is None or port is None:
        return again()
    if not connection.neighbor_changes_enabled:
        return again(
            error="Neighbor changes are off. Turn them on on the Switch page first.",
            status_code=400,
        )
    if discovery is None:
        return again(error=f"The switch did not report CDP on {name}.", status_code=400)
    change = plan_port_discovery(
        discovery,
        cdp=cdp == "on",
        lldp_transmit=lldp_transmit == "on",
        lldp_receive=lldp_receive == "on",
        lldp_shown=lldp_shown == "yes",
    )
    if change.empty:
        return again(notice="Nothing to change: the port already does this.")
    lines, warnings = describe_port_discovery(name, change)
    if confirm != "yes":
        fields = {"name": port.name, "lldp_shown": lldp_shown, **(origin.fields if origin else {})}
        # Only the ticked boxes are sent, as the browser sends them.
        for key, value in (
            ("cdp", cdp),
            ("lldp_transmit", lldp_transmit),
            ("lldp_receive", lldp_receive),
        ):
            if value == "on":
                fields[key] = "on"
        return templates.TemplateResponse(
            request,
            "confirm.html",
            {
                "username": username,
                "title": port.name,
                "back_url": back_url,
                "back_label": back_label,
                "lines": lines,
                "warnings": warnings,
                "action": "/ports/discovery",
                "fields": fields,
                "csrf_token": csrf_token(request),
            },
        )

    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            client.set_port_discovery(
                name,
                cdp=change.cdp,
                lldp_transmit=change.lldp_transmit,
                lldp_receive=change.lldp_receive,
            )
    except NxapiError as exc:
        log.warning("CDP/LLDP change on %s refused: %s", name, exc)
        return again(error=change_refused(exc, target), status_code=400)

    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, selected_switch_id(request), True)
    log.info("CDP/LLDP change on %s by %s: %s %s", connection.host, username, name, " ".join(lines))
    note_activity(request, username, "Ports", f"{name}: {'; '.join(lines)}", connection.host)

    return answer_port_change(
        request,
        username,
        name,
        origin,
        notice=(
            f"Done: {' '.join(lines)} Not saved yet: Save config keeps it over a restart of "
            "the switch."
        ),
    )


# ---- how long a port averages its rates over ------------------------------------


@router.post("/ports/rate-interval", response_class=HTMLResponse)
def port_rate_interval_change(
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    name: str = Form(""),
    seconds: str = Form(""),
    back: str = Form(""),
    show: str = Form(""),
    color: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Set how many seconds the switch averages one port's In and Out over
    (``load-interval counter 1``). Asks first."""
    require_csrf(request, csrf)
    origin = ports_origin(back, show, color)
    back_url, back_label = change_back(origin, name)
    found = _read_port_page(request, name)
    connection, target, status, ports, view, current, neighbors, discovery = found
    port = next((p for p in ports or [] if p.name == name), None)

    def again(**kwargs) -> Response:
        return answer_port_change(request, username, name, origin, found, **kwargs)

    if connection is None or target is None or port is None:
        return again()
    if not connection.traffic_changes_enabled:
        return again(
            error=(
                "Traffic measuring changes are off. An NXray admin turns them on on the "
                "Switch page first."
            ),
            status_code=400,
        )
    try:
        plan = plan_load_interval(name, port.load_interval, seconds)
    except ValueError as exc:
        return again(error=str(exc), status_code=400)
    if plan.empty:
        return again(notice="Nothing to change: the port already averages over that long.")
    if confirm != "yes":
        return templates.TemplateResponse(
            request,
            "confirm.html",
            {
                "username": username,
                "title": port.name,
                "back_url": back_url,
                "back_label": back_label,
                "lines": plan.lines,
                "warnings": plan.warnings,
                "action": "/ports/rate-interval",
                "fields": {
                    "name": port.name,
                    "seconds": seconds.strip(),
                    **(origin.fields if origin else {}),
                },
                "csrf_token": csrf_token(request),
            },
        )

    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            client.set_load_interval(name, plan.seconds)
    except NxapiError as exc:
        log.warning("Rate interval change on %s refused: %s", name, exc)
        return again(error=change_refused(exc, target), status_code=400)

    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, selected_switch_id(request), True)
    words = " ".join(plan.lines)
    log.info("Rate interval change on %s by %s: %s", connection.host, username, words)
    note_activity(request, username, "Ports", f"{name}: {words}", connection.host)
    return answer_port_change(
        request,
        username,
        name,
        origin,
        notice=(f"Done: {words} Not saved yet: Save config keeps it over a restart of the switch."),
    )
