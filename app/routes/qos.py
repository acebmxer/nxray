"""The QoS page: class-maps, policy-maps, where they are applied, and the queue counters,
and the changes its forms make, on the same parts as the routing protocol pages.

``GET /qos`` shows it; every change goes through ``POST /qos/change`` with the same form
fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a
confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.qos import QOS, QosPage, build_qos_change, is_built_in, load_qos_page
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

QOS_CHANGES_OFF = (
    "QoS changes are off. An NXray admin turns on changes on the Switch page first, with "
    "the broad role or a stored admin login: the limited role has no room for them."
)


def check_qos_place(page: QosPage, ident: dict[str, str]) -> None:
    """Refuse a port, class-map or name the switch would refuse or has by itself (naming
    one that is missing would be refused too, but only after the lines before it ran)."""
    port = ident.get("port", "").strip()
    if port and page.ports and port not in page.ports:
        raise ValueError(f"the switch has no port {port}")
    for key in ("cmap", "nqmap", "policy", "nqpolicy", "qpolicy"):
        if (name := ident.get(key, "").strip()) and is_built_in(name):
            raise ValueError(f"{name} is a name the switch keeps for its own defaults")
    name = ident.get("class", "").strip()
    if name and name != "class-default" and name not in page.classes:
        raise ValueError(f"the switch has no class-map {name}; make it first")
    name = ident.get("nqclass", "").strip()
    if name and name not in page.nq_classes:
        raise ValueError(f"the switch has no network-qos class-map {name}; make it first")


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_qos(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/qos",
    back_url="/ports",
    back_label="Ports",
    save_back={"back": "qos"},
    changes_name="QoS",
    subject="QoS",
    off_message=QOS_CHANGES_OFF,
    enabled=lambda connection: connection.qos_changes_enabled,
    load=load_qos_page,
    check_place=check_qos_place,
    build=build_qos_change,
    send=_send,
    scroll_tables=True,
)


def render_qos_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the QoS page, with a message."""
    return render_site_page(request, username, QOS, SITE, error=error, notice=notice, form=form)


@router.get("/qos", response_class=HTMLResponse)
def qos_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /qos``: the class-maps, policy-maps, what is applied and the queue counters,
    read live; every role looks, operators and admins change."""
    return render_qos_page(request, username)


@router.post("/qos/change", response_class=HTMLResponse)
def qos_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the QoS page. Without confirm=yes, asks first."""
    return site_change(request, username, form, QOS, SITE)
