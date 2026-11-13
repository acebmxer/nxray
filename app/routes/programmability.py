"""The Programmability page: gRPC, NETCONF, RESTCONF, NX-SDK, Container Tracker and OpenFlow,
with the changes its forms make, on the same parts as the Monitor sessions page.

``GET /programmability`` shows it; every change goes through ``POST
/programmability/change`` with the same form fields as a protocol page (scope, setting,
action, ``id_<name>``, ``v_<name>``) and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.programmability import (
    PROGRAMMABILITY,
    build_programmability_change,
    check_programmability_place,
    load_programmability_page,
)
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

PROGRAMMABILITY_CHANGES_OFF = (
    "Programmability changes are off. An NXray admin turns on changes on the Switch "
    "page first, with the broad role or a stored admin login: the limited role has no rules "
    "for them."
)


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_programmability(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/programmability",
    back_url="/features",
    back_label="Features",
    save_back={"back": "programmability"},
    changes_name="Programmability",
    subject="Programmability",
    off_message=PROGRAMMABILITY_CHANGES_OFF,
    enabled=lambda connection: connection.programmability_changes_enabled,
    load=load_programmability_page,
    check_place=check_programmability_place,
    build=build_programmability_change,
    send=_send,
    stored_login=True,
)


def render_programmability_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Programmability page, with a message."""
    return render_site_page(
        request, username, PROGRAMMABILITY, SITE, error=error, notice=notice, form=form
    )


@router.get("/programmability", response_class=HTMLResponse)
def programmability_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /programmability``: the interfaces, read live; every role
    looks, operators and admins change."""
    return render_programmability_page(request, username)


@router.post("/programmability/change", response_class=HTMLResponse)
def programmability_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Programmability page. Without confirm=yes, asks first."""
    return site_change(request, username, form, PROGRAMMABILITY, SITE)
