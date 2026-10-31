"""The Features page: every switch feature, and turning one on or off (admins)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import admin_required, login_required, require_csrf, stored_switch, templates
from app.features import OFF_WARNING, ON_WARNINGS, FeatureView, load_features
from app.nxapi import NxapiClient, NxapiError
from app.routes.ports import change_refused
from app.security import csrf_token
from app.switch_connection import set_unsaved_changes
from app.switch_setup import ConnectionStatus, read_switch

router = APIRouter()
log = logging.getLogger("nxray.features")

NOT_SAVED = "Not saved yet: Save config keeps it over a restart of the switch."
FEATURE_CHANGES_OFF = (
    "Feature changes are off. Turn them on on the Switch page first: NXray's role on "
    "the switch does not allow them yet."
)


def _render(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    status_code: int = 200,
) -> Response:
    """Read the features fresh from the switch and show the page."""
    connection, target, problem = stored_switch(request)
    status = None
    view: FeatureView | None = None
    if target is not None:
        status, view = read_switch(
            target, load_features, transport=request.app.state.nxapi_transport
        )
    elif problem:
        status = ConnectionStatus(False, problem)
    return templates.TemplateResponse(
        request,
        "features.html",
        {
            "username": username,
            "connection": connection,
            "status": status,
            "view": view,
            "error": error,
            "notice": notice,
            "csrf_token": csrf_token(request),
        },
        status_code=status_code,
    )


@router.get("/features", response_class=HTMLResponse)
def features_page(request: Request, username: str = Depends(login_required)) -> Response:
    return _render(request, username)


def render_features_page(
    request: Request, username: str, *, error: str | None = None, notice: str | None = None
) -> Response:
    """Read the switch fresh and show the Features page, with an optional message."""
    return _render(request, username, error=error, notice=notice)


@router.post("/features/set", response_class=HTMLResponse)
def feature_set(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    name: str = Form(""),
    state: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Turn one feature on or off. Without confirm=yes, asks first."""
    require_csrf(request, csrf)

    def fail(message: str) -> Response:
        return _render(request, username, error=message, status_code=400)

    if state not in ("on", "off"):
        return fail("Choose to turn the feature on or off.")
    turn_on = state == "on"
    connection, target, problem = stored_switch(request)
    if connection is None:
        return fail("No switch is set up yet.")
    if target is None:
        return fail(problem or "The switch could not be read.")
    if not connection.feature_changes_enabled:
        return fail(FEATURE_CHANGES_OFF)
    status, view = read_switch(target, load_features, transport=request.app.state.nxapi_transport)
    if view is None:
        return fail(status.message)
    feature = view.get(name)
    if feature is None:
        return fail("The switch does not list that feature.")
    if feature.enabled == turn_on:
        return _render(
            request, username, notice=f"{feature.label} is already {'on' if turn_on else 'off'}."
        )
    if refusal := feature.refusal(turn_on):
        return fail(refusal)
    assert feature.command is not None  # refusal() covers a feature without one

    if confirm != "yes":
        lines = [f"Turn {state} {feature.label}."]
        if feature.description:
            lines.append(feature.description)
        if turn_on:
            warnings = [ON_WARNINGS[feature.name]] if feature.name in ON_WARNINGS else []
        else:
            warnings = [OFF_WARNING]
        return templates.TemplateResponse(
            request,
            "confirm.html",
            {
                "username": username,
                "title": f"Feature {feature.label}",
                "back_url": "/features",
                "back_label": "Features",
                "lines": lines,
                "warnings": warnings,
                "action": "/features/set",
                "fields": {"name": feature.name, "state": state},
                "csrf_token": csrf_token(request),
            },
        )

    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            client.set_feature(feature.command, turn_on)
    except NxapiError as exc:
        log.warning("turning %s feature %s refused: %s", state, feature.command, exc)
        return fail(f"Not turned {state}: {change_refused(exc, target)}")
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        set_unsaved_changes(conn, True)
    log.info(
        "feature change on %s by %s: turned %s %s",
        connection.host,
        username,
        state,
        feature.command,
    )
    notice = f"Done: {feature.label} is {state}. {NOT_SAVED}"
    if feature.name == "interface-vlan" and turn_on and not connection.role_vlan_interfaces:
        notice += (
            " To make VLAN interfaces on the Routing page, press Update the port list on the "
            "Switch page: NXray's role names them only once interface-vlan is on."
        )
    return _render(request, username, notice=notice)
