"""The Alerts page (admins only): what NXray alerts on, where alerts go, and
what was sent.

``GET /alerts`` shows the problems open now, the rules, the e-mail settings,
the webhooks and the newest alerts sent. The forms change NXray only, never
the switch, so they take effect at once with no confirm page; each is
recorded in the activity log. The test buttons send at once and say how it
went.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.alerts import (
    FORMATS,
    KEEP_DAYS,
    MAX_WEBHOOKS,
    PORT_WATCH,
    SECURITY_CHOICES,
    AlertSettingsError,
    add_webhook,
    delete_email,
    delete_webhook,
    list_open,
    list_sent,
    list_webhooks,
    load_email,
    load_rules,
    parse_rules,
    save_email,
    save_rules,
    send_test,
    validate_email,
    validate_webhook,
)
from app.db import open_db
from app.dependencies import admin_required, note_activity, require_csrf, templates
from app.routes.protocols import form_fields
from app.security import csrf_token

router = APIRouter()
log = logging.getLogger("nxray.alerts")


def _render(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    status_code: int = 200,
) -> Response:
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        context = {
            "rules": load_rules(conn),
            "email": load_email(conn),
            "webhooks": list_webhooks(conn),
            "open_problems": list_open(conn),
            "sent": list_sent(conn),
        }
    return templates.TemplateResponse(
        request,
        "alerts.html",
        {
            **context,
            "username": username,
            "interval": settings.history_interval,
            "security_choices": SECURITY_CHOICES,
            "formats": FORMATS,
            "port_watch": PORT_WATCH,
            "max_webhooks": MAX_WEBHOOKS,
            "keep_days": KEEP_DAYS,
            "error": error,
            "notice": notice,
            "csrf_token": csrf_token(request),
        },
        status_code=status_code,
    )


@router.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request, username: str = Depends(admin_required)) -> Response:
    """``GET /alerts``: open problems, the rules, e-mail, webhooks and the alerts
    sent; admins only."""
    return _render(request, username)


def _rules_words(rules) -> str:
    parts = [
        name
        for name, on in (
            ("switch unreachable", rules.unreachable),
            ("temperatures", rules.temperature),
            ("fans", rules.fans),
            ("power supplies", rules.power),
            ("changes", rules.changes),
        )
        if on
    ]
    if rules.cpu_percent:
        parts.append(f"CPU at {rules.cpu_percent}%")
    if rules.memory_percent:
        parts.append(f"memory at {rules.memory_percent}%")
    if rules.port_down != "off":
        parts.append(f"ports down ({PORT_WATCH[rules.port_down].lower()})")
    if rules.port_errors:
        parts.append(f"{rules.port_errors} port errors")
    return ", ".join(parts) or "nothing"


@router.post("/alerts/rules", response_class=HTMLResponse)
async def alerts_rules(request: Request, username: str = Depends(admin_required)) -> Response:
    """``POST /alerts/rules``: what NXray alerts on; an unticked box is off."""
    form = await form_fields(request)
    require_csrf(request, form.get("csrf", ""))
    try:
        rules = parse_rules(form)
    except AlertSettingsError as exc:
        return _render(request, username, error=str(exc), status_code=400)
    with open_db(request.app.state.settings.db_path) as conn:
        save_rules(conn, rules)
    note_activity(request, username, "Alerts", f"Set what is alerted on: {_rules_words(rules)}")
    return _render(request, username, notice="Saved. The next check uses these rules.")


@router.post("/alerts/email", response_class=HTMLResponse)
def alerts_email(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    host: str = Form(""),
    port: str = Form("587"),
    security: str = Form("starttls"),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    clear_password: str = Form(""),
    sender: str = Form(""),
    recipients: str = Form(""),
) -> Response:
    """``POST /alerts/email``: the mail server and the addresses; an empty
    password keeps the stored one unless ``clear_password`` is ticked."""
    require_csrf(request, csrf)
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        stored = load_email(conn).has_password
    try:
        email = validate_email(
            host=host,
            port=port,
            security=security,
            username=smtp_username,
            password=smtp_password,
            keep_password=stored and clear_password != "yes" and not smtp_password,
            sender=sender,
            recipients=recipients,
        )
    except AlertSettingsError as exc:
        return _render(request, username, error=str(exc), status_code=400)
    with open_db(settings.db_path) as conn:
        save_email(conn, email, smtp_password, settings.secret_key)
    note_activity(
        request,
        username,
        "Alerts",
        f"Set e-mail alerts: server {email.host} port {email.port} ({email.security}), "
        f"from {email.sender} to {', '.join(email.recipients)}"
        + (", with a password" if email.has_password else ""),
    )
    return _render(request, username, notice="E-mail settings saved. Send a test to check them.")


@router.post("/alerts/email/delete", response_class=HTMLResponse)
def alerts_email_delete(
    request: Request, username: str = Depends(admin_required), csrf: str = Form("")
) -> Response:
    """``POST /alerts/email/delete``: forget the e-mail settings and password."""
    require_csrf(request, csrf)
    with open_db(request.app.state.settings.db_path) as conn:
        delete_email(conn)
    note_activity(request, username, "Alerts", "Removed the e-mail settings")
    return _render(request, username, notice="E-mail settings removed; no more e-mail alerts.")


@router.post("/alerts/email/test", response_class=HTMLResponse)
def alerts_email_test(
    request: Request, username: str = Depends(admin_required), csrf: str = Form("")
) -> Response:
    """``POST /alerts/email/test``: send a test e-mail now and say how it went."""
    require_csrf(request, csrf)
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        configured = load_email(conn).configured
    if not configured:
        return _render(request, username, error="Save the e-mail settings first.", status_code=400)
    outcome = send_test(settings, email_only=True)
    if outcome.startswith("e-mail sent"):
        return _render(request, username, notice=f"Test: {outcome}.")
    return _render(request, username, error=f"Test: {outcome}.")


@router.post("/alerts/webhook/add", response_class=HTMLResponse)
def alerts_webhook_add(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    name: str = Form(""),
    url: str = Form(""),
    format: str = Form("json"),
    secret: str = Form(""),
) -> Response:
    """``POST /alerts/webhook/add``: keep a webhook, its URL and secret encrypted."""
    require_csrf(request, csrf)
    settings = request.app.state.settings
    try:
        name, url, fmt, secret = validate_webhook(name, url, format, secret)
        with open_db(settings.db_path) as conn:
            add_webhook(conn, name, url, fmt, secret, settings.secret_key)
            shown = list_webhooks(conn)[-1].shown
    except AlertSettingsError as exc:
        return _render(request, username, error=str(exc), status_code=400)
    note_activity(
        request,
        username,
        "Alerts",
        f"Added the webhook {name} ({FORMATS[fmt]}, {shown})" + (", signed" if secret else ""),
    )
    return _render(request, username, notice=f"Webhook {name} added. Send a test to check it.")


def _webhook_id(value: str) -> int:
    return int(value) if value.isdigit() else 0


@router.post("/alerts/webhook/delete", response_class=HTMLResponse)
def alerts_webhook_delete(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    id: str = Form(""),
) -> Response:
    """``POST /alerts/webhook/delete``: forget one webhook."""
    require_csrf(request, csrf)
    with open_db(request.app.state.settings.db_path) as conn:
        removed = delete_webhook(conn, _webhook_id(id))
    if removed is None:
        return _render(request, username, error="There is no such webhook.", status_code=404)
    note_activity(request, username, "Alerts", f"Deleted the webhook {removed.name}")
    return _render(request, username, notice=f"Webhook {removed.name} deleted.")


@router.post("/alerts/webhook/test", response_class=HTMLResponse)
def alerts_webhook_test(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    id: str = Form(""),
) -> Response:
    """``POST /alerts/webhook/test``: send a test to one webhook now."""
    require_csrf(request, csrf)
    settings = request.app.state.settings
    webhook_id = _webhook_id(id)
    with open_db(settings.db_path) as conn:
        known = any(hook.id == webhook_id for hook in list_webhooks(conn))
    if not known:
        return _render(request, username, error="There is no such webhook.", status_code=404)
    outcome = send_test(settings, request.app.state.alert_transport, webhook_id=webhook_id)
    if outcome.endswith(" sent"):
        return _render(request, username, notice=f"Test: {outcome}.")
    return _render(request, username, error=f"Test: {outcome}.")
