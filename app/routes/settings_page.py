"""The Settings page (admin only): built-in HTTPS, its certificate, and self-update."""

from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import admin_required, require_csrf, templates
from app.security import csrf_token
from app.tls import MAX_PEM_BYTES, CertificateError, current_certificate, install_certificate
from app.update import (
    apply_update,
    check_for_updates,
    clear_result,
    current_state,
    reap_stalled_update,
)

router = APIRouter()
log = logging.getLogger("nxray.settings")

# Optional at the form level so a missing file gets NXray's own message
# ("Choose both ...") instead of FastAPI's 422. Module-level, not in the
# signature, so the default is not a call (ruff B008); one object per field,
# since FastAPI keeps each field's name on it.
_CERT_FILE = File(None)
_KEY_FILE = File(None)


def _render(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    status_code: int = 200,
) -> Response:
    settings = request.app.state.settings
    update = None
    checked_at = ""
    if settings.enable_self_update:
        with open_db(settings.db_path) as conn:
            reap_stalled_update(conn)
            update = current_state(conn)
        if update.latest_checked_at:
            checked_at = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(update.latest_checked_at))
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "username": username,
            "enable_self_update": settings.enable_self_update,
            "dev_build": settings.dev_build,
            "update": update,
            "update_checked_at": checked_at,
            "enable_https": settings.enable_https,
            "https_port": settings.https_port,
            "certificate": current_certificate(settings.tls_dir) if settings.enable_https else None,
            "error": error,
            "notice": notice,
            "csrf_token": csrf_token(request),
        },
        status_code=status_code,
    )


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, username: str = Depends(admin_required)) -> Response:
    return _render(request, username)


@router.post("/settings/certificate", response_class=HTMLResponse)
async def settings_certificate(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    cert_file: UploadFile | None = _CERT_FILE,
    key_file: UploadFile | None = _KEY_FILE,
) -> Response:
    """Replace the certificate nginx serves with an uploaded one; no restart needed."""
    require_csrf(request, csrf)
    settings = request.app.state.settings
    if not settings.enable_https:
        return _render(
            request,
            username,
            error="Built-in HTTPS is off, so there is no certificate to replace.",
            status_code=400,
        )
    cert_pem = await cert_file.read(MAX_PEM_BYTES + 1) if cert_file else b""
    key_pem = await key_file.read(MAX_PEM_BYTES + 1) if key_file else b""
    try:
        info = install_certificate(settings.tls_dir, cert_pem, key_pem)
    except CertificateError as exc:
        return _render(request, username, error=str(exc), status_code=400)
    log.info("%s uploaded a new HTTPS certificate (%s)", username, info.subject)
    return _render(
        request,
        username,
        notice=(
            f"Certificate saved and in use ({info.subject}, valid until {info.not_after}). "
            "Reload the page if your browser still shows the old one."
        ),
    )


@router.post("/settings/update/check", response_class=HTMLResponse)
def settings_update_check(
    request: Request, username: str = Depends(admin_required), csrf: str = Form("")
) -> Response:
    """Look at GHCR now instead of waiting for the daily check."""
    require_csrf(request, csrf)
    settings = request.app.state.settings
    if not settings.enable_self_update:
        return _render(request, username, error="Self-update is off.", status_code=400)
    with open_db(settings.db_path) as conn:
        reap_stalled_update(conn)
        outcome = check_for_updates(conn, dev_build=settings.dev_build)
    if outcome == "available":
        return _render(request, username, notice="A newer image is available.")
    if outcome == "current":
        return _render(request, username, notice="NXray is up to date.")
    return _render(request, username, error=outcome)


@router.post("/settings/update/apply", response_class=HTMLResponse)
def settings_update_apply(
    request: Request, username: str = Depends(admin_required), csrf: str = Form("")
) -> Response:
    """Pull the new image and have Docker recreate this container."""
    require_csrf(request, csrf)
    settings = request.app.state.settings
    if not settings.enable_self_update:
        return _render(request, username, error="Self-update is off.", status_code=400)
    with open_db(settings.db_path) as conn:
        state = current_state(conn)
    if state.in_progress:
        return _render(request, username, error="An update is already running.", status_code=409)
    if not state.available:
        return _render(request, username, error="No update is available.", status_code=409)
    log.info("%s started an update to %s", username, state.latest_digest[:19])
    error = apply_update(settings.db_path)
    if error:
        return _render(request, username, error=f"Could not start the update: {error}")
    return _render(
        request,
        username,
        notice="Update started. NXray pulls the new image and restarts; this page reloads itself.",
    )


@router.post("/settings/update/dismiss", response_class=HTMLResponse)
def settings_update_dismiss(
    request: Request, username: str = Depends(admin_required), csrf: str = Form("")
) -> Response:
    """Hide the last update result (success or failure)."""
    require_csrf(request, csrf)
    settings = request.app.state.settings
    if settings.enable_self_update:
        with open_db(settings.db_path) as conn:
            clear_result(conn)
    return _render(request, username)
