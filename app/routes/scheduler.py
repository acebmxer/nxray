"""The Scheduler page: the switch's jobs and schedules with their log, and the changes its
forms make, on the same parts as the Monitor sessions page.

``GET /scheduler`` shows it; every change goes through ``POST /scheduler/change`` with the
same form fields as a protocol page (scope, setting, action, ``id_<name>``, ``v_<name>``)
and a confirm page first.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.dependencies import login_required, operator_required
from app.nxapi import NxapiClient
from app.protocols import ProtocolChange
from app.routes.protocols import ProtocolSite, form_fields, render_site_page, site_change
from app.scheduler import SCHEDULER, SchedulerPage, build_scheduler_change, load_scheduler_page

router = APIRouter()

SCHEDULER_CHANGES_OFF = (
    "Scheduler changes are off. An NXray admin turns on changes on the Switch page first, "
    "with the broad role or a stored admin login: the limited role has no room for them."
)


def check_scheduler_place(page: SchedulerPage, ident: dict[str, str]) -> None:
    """Nothing to check: a new job or schedule name makes a new one."""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_scheduler(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/scheduler",
    back_url="/switch-admin",
    back_label="Switch admin",
    save_back={"back": "scheduler"},
    changes_name="Scheduler",
    subject="the scheduler",
    off_message=SCHEDULER_CHANGES_OFF,
    enabled=lambda connection: connection.scheduler_changes_enabled,
    load=load_scheduler_page,
    check_place=check_scheduler_place,
    build=build_scheduler_change,
    send=_send,
    stored_login=True,
)


def render_scheduler_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the Scheduler page, with a message."""
    return render_site_page(
        request, username, SCHEDULER, SITE, error=error, notice=notice, form=form
    )


@router.get("/scheduler", response_class=HTMLResponse)
def scheduler_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /scheduler``: the jobs, schedules and log, read live; every role looks,
    operators and admins change."""
    return render_scheduler_page(request, username)


@router.post("/scheduler/change", response_class=HTMLResponse)
def scheduler_change(
    request: Request,
    username: str = Depends(operator_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the Scheduler page. Without confirm=yes, asks first."""
    return site_change(request, username, form, SCHEDULER, SITE)
