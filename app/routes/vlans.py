"""The VLANs page: list, create, rename and delete VLANs."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import login_required, require_csrf, stored_switch, templates
from app.nxapi import (
    VLAN_NAME_MAX,
    NxapiClient,
    NxapiError,
    validate_vlan_id,
    validate_vlan_name,
)
from app.routes.ports import change_refused
from app.security import csrf_token
from app.switch_connection import set_unsaved_changes
from app.switch_setup import ConnectionStatus, read_switch
from app.vlans import VlanView, load_vlans

router = APIRouter()
log = logging.getLogger("nxray.vlans")

NOT_SAVED = "Not saved yet: Save config keeps it over a restart of the switch."
VLAN_CHANGES_OFF = "VLAN changes are off. Turn them on on the Switch page first."


def _render(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
    status_code: int = 200,
) -> Response:
    """Read the VLANs fresh from the switch and show the page."""
    connection, target, problem = stored_switch(request)
    status = None
    view: VlanView | None = None
    if target is not None:
        status, view = read_switch(target, load_vlans, transport=request.app.state.nxapi_transport)
    elif problem:
        status = ConnectionStatus(False, problem)
    usage = {vlan.id: view.ports_using(vlan.id) for vlan in view.vlans} if view else {}
    return templates.TemplateResponse(
        request,
        "vlans.html",
        {
            "username": username,
            "connection": connection,
            "status": status,
            "view": view,
            "usage": usage,
            "error": error,
            "notice": notice,
            "form": form or {"vlan_id": "", "name": ""},
            "name_max": VLAN_NAME_MAX,
            "csrf_token": csrf_token(request),
        },
        status_code=status_code,
    )


@router.get("/vlans", response_class=HTMLResponse)
def vlans_page(request: Request, username: str = Depends(login_required)) -> Response:
    return _render(request, username)


def _changing(request: Request):
    """(connection, target, view, error message) for a VLAN change."""
    connection, target, problem = stored_switch(request)
    if connection is None:
        return None, None, None, "No switch is set up yet."
    if target is None:
        return connection, None, None, problem
    if not connection.vlan_changes_enabled:
        return connection, None, None, VLAN_CHANGES_OFF
    status, view = read_switch(target, load_vlans, transport=request.app.state.nxapi_transport)
    if view is None:
        return connection, None, None, status.message
    return connection, target, view, None


def _changed(request: Request, connection, username: str, what: str) -> None:
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        set_unsaved_changes(conn, True)
    log.info("VLAN change on %s by %s: %s", connection.host, username, what)


@router.post("/vlans/create", response_class=HTMLResponse)
def vlan_create(
    request: Request,
    username: str = Depends(login_required),
    csrf: str = Form(""),
    vlan_id: str = Form(""),
    name: str = Form(""),
) -> Response:
    require_csrf(request, csrf)
    form = {"vlan_id": vlan_id.strip(), "name": name.strip()}

    def fail(message: str) -> Response:
        return _render(request, username, error=message, form=form, status_code=400)

    connection, target, view, problem = _changing(request)
    if problem or target is None or view is None:
        return fail(problem or "The switch could not be read.")
    try:
        number = validate_vlan_id(vlan_id)
        label = validate_vlan_name(name) if name.strip() else None
    except ValueError as exc:
        return fail(f"Not created: {exc}.")
    if number in view.ids:
        return fail(f"VLAN {number} already exists. Rename it in the list below instead.")
    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            client.configure_vlan(number, label)
    except NxapiError as exc:
        log.warning("creating VLAN %s refused: %s", number, exc)
        return fail(f"Not created: {change_refused(exc, target)}")
    _changed(request, connection, username, f"created VLAN {number} ({label or 'no name'})")
    named = f' named "{label}"' if label else ""
    return _render(request, username, notice=f"Done: VLAN {number}{named} created. {NOT_SAVED}")


@router.post("/vlans/rename", response_class=HTMLResponse)
def vlan_rename(
    request: Request,
    username: str = Depends(login_required),
    csrf: str = Form(""),
    vlan_id: str = Form(""),
    name: str = Form(""),
) -> Response:
    require_csrf(request, csrf)

    def fail(message: str) -> Response:
        return _render(request, username, error=message, status_code=400)

    connection, target, view, problem = _changing(request)
    if problem or target is None or view is None:
        return fail(problem or "The switch could not be read.")
    try:
        number = validate_vlan_id(vlan_id)
        label = validate_vlan_name(name)
    except ValueError as exc:
        return fail(f"Not renamed: {exc}.")
    vlan = view.get(number)
    if vlan is None:
        return fail(f"VLAN {number} does not exist on the switch.")
    if number == 1:
        return fail("VLAN 1 is the switch's default VLAN; its name cannot be changed.")
    if vlan.name == label:
        return _render(request, username, notice=f'VLAN {number} is already named "{label}".')
    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            client.configure_vlan(number, label)
    except NxapiError as exc:
        log.warning("renaming VLAN %s refused: %s", number, exc)
        return fail(f"Not renamed: {change_refused(exc, target)}")
    _changed(request, connection, username, f"renamed VLAN {number} to {label}")
    return _render(
        request,
        username,
        notice=f'Done: VLAN {number} renamed from "{vlan.name}" to "{label}". {NOT_SAVED}',
    )


@router.post("/vlans/delete", response_class=HTMLResponse)
def vlan_delete(
    request: Request,
    username: str = Depends(login_required),
    csrf: str = Form(""),
    vlan_id: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Delete a VLAN no port uses. Without confirm=yes, asks first."""
    require_csrf(request, csrf)

    def fail(message: str) -> Response:
        return _render(request, username, error=message, status_code=400)

    connection, target, view, problem = _changing(request)
    if problem or target is None or view is None:
        return fail(problem or "The switch could not be read.")
    try:
        number = validate_vlan_id(vlan_id)
    except ValueError as exc:
        return fail(f"Not deleted: {exc}.")
    vlan = view.get(number)
    if vlan is None:
        return fail(f"VLAN {number} does not exist on the switch.")
    if number == 1:
        return fail("VLAN 1 is the switch's default VLAN and cannot be deleted.")
    using = view.ports_using(number)
    if using:
        return fail(
            f"Not deleted: VLAN {number} is still used by {', '.join(using)}. Move "
            f"{'that port' if len(using) == 1 else 'those ports'} to another VLAN on "
            f"{'its' if len(using) == 1 else 'their'} own page first."
        )
    if confirm != "yes":
        return templates.TemplateResponse(
            request,
            "confirm.html",
            {
                "username": username,
                "title": f"VLAN {number}",
                "back_url": "/vlans",
                "back_label": "VLANs",
                "lines": [f'Delete VLAN {number} ("{vlan.name}").'],
                "warnings": [],
                "action": "/vlans/delete",
                "fields": {"vlan_id": str(number)},
                "csrf_token": csrf_token(request),
            },
        )
    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            client.delete_vlan(number)
    except NxapiError as exc:
        log.warning("deleting VLAN %s refused: %s", number, exc)
        return fail(f"Not deleted: {change_refused(exc, target)}")
    _changed(request, connection, username, f"deleted VLAN {number} ({vlan.name})")
    return _render(
        request, username, notice=f'Done: VLAN {number} ("{vlan.name}") deleted. {NOT_SAVED}'
    )
