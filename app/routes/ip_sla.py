"""The IP SLA page: the entries that measure the network from the switch, their results,
schedules and reactions, and the changes its forms make, on the same parts as the
Monitor sessions page.

``GET /ip-sla`` shows it; every change goes through ``POST /ip-sla/change`` with the
same form fields as a protocol page (scope, setting, action, ``id_<name>``,
``v_<name>``) and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.ip_sla import IP_SLA, IpSlaPage, build_ip_sla_change, load_ip_sla_page
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change

router = APIRouter()

IP_SLA_CHANGES_OFF = (
    "IP SLA changes are off. An NXray admin turns on changes on the Switch page first, "
    "with the broad role or a stored admin login: the limited role has no room for them."
)


def check_ip_sla_place(page: IpSlaPage, ident: dict[str, str]) -> None:
    """Refuse a schedule or reaction for an entry the switch does not have: the switch
    would take the line and keep it for an entry that is not there."""
    entry = ident.get("sla", "").strip()
    if entry and entry not in page.entries:
        raise ValueError(f"the switch has no IP SLA entry {entry}; make it first")


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_ip_sla(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/ip-sla",
    back_url="/features",
    back_label="Features",
    save_back={"back": "ip-sla"},
    changes_name="IP SLA",
    subject="IP SLA",
    off_message=IP_SLA_CHANGES_OFF,
    enabled=lambda connection: connection.ip_sla_changes_enabled,
    load=load_ip_sla_page,
    check_place=check_ip_sla_place,
    build=build_ip_sla_change,
    send=_send,
    stored_login=True,
)


def render_ip_sla_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the IP SLA page, with a message."""
    return render_site_page(request, username, IP_SLA, SITE, error=error, notice=notice, form=form)


@router.get("/ip-sla", response_class=HTMLResponse)
def ip_sla_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /ip-sla``: the IP SLA entries with their latest results, schedules and
    reactions, read live; every role looks, operators and admins change."""
    return render_ip_sla_page(request, username)


@router.post("/ip-sla/change", response_class=HTMLResponse)
def ip_sla_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the IP SLA page. Without confirm=yes, asks first."""
    return site_change(request, username, form, IP_SLA, SITE)
