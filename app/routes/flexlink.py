"""The Flex Links page: the pairs of an active and a backup port, their state and
preemption, and the changes its forms make, on the same parts as the Monitor sessions page.

``GET /flexlink`` shows it; every change goes through ``POST /flexlink/change`` with the same form
fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``) and a confirm
page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.flexlink import FLEXLINK, build_flexlink_change, check_flexlink_place, load_flexlink_page
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

FLEXLINK_CHANGES_OFF = (
    "Flex Links changes are off. An NXray admin turns on changes on the Switch "
    "page first, with the broad role or a stored admin login: the limited role has no rules "
    "for them."
)


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_flexlink(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/flexlink",
    back_url="/port-channels",
    back_label="Port-channels",
    save_back={"back": "flexlink"},
    changes_name="Flex Links",
    subject="Flex Links",
    off_message=FLEXLINK_CHANGES_OFF,
    enabled=lambda connection: connection.layer2_changes_enabled,
    load=load_flexlink_page,
    check_place=check_flexlink_place,
    build=build_flexlink_change,
    send=_send,
    links=(
        ("/port-channels", "Port-channels, which can be either port of a pair"),
        ("/spanning-tree", "Spanning tree, which is off on both ports of a pair"),
    ),
    scroll_tables=True,
    stored_login=True,
)


def render_flexlink_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Flex Links page, with a message."""
    return render_site_page(
        request, username, FLEXLINK, SITE, error=error, notice=notice, form=form
    )


@router.get("/flexlink", response_class=HTMLResponse)
def flexlink_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /flexlink``: the Flex Link pairs and their state, read live; every role
    looks, operators and admins change."""
    return render_flexlink_page(request, username)


@router.post("/flexlink/change", response_class=HTMLResponse)
def flexlink_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Flex Links page. Without confirm=yes, asks first."""
    return site_change(request, username, form, FLEXLINK, SITE)
