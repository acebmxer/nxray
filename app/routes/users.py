"""The Users page (admin only) and each account's own Account page."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import (
    admin_required,
    current_account,
    login_required,
    require_csrf,
    templates,
)
from app.security import (
    client_ip,
    csrf_token,
    is_rate_limited,
    record_login_failure,
    session_id_from_request,
    verify_password,
)
from app.users import (
    MIN_PASSWORD_LENGTH,
    ROLE_HELP,
    ROLES,
    User,
    UserError,
    check_new_password,
    create_user,
    get_user,
    get_user_by_id,
    list_users,
    set_disabled,
    set_password,
    set_role,
)

router = APIRouter()
log = logging.getLogger("nxray.users")


def _render_users(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
    status_code: int = 200,
) -> Response:
    with open_db(request.app.state.settings.db_path) as conn:
        users = list_users(conn)
    return templates.TemplateResponse(
        request,
        "users.html",
        {
            "username": username,
            "users": users,
            "roles": ROLES,
            "role_help": ROLE_HELP,
            "min_password": MIN_PASSWORD_LENGTH,
            "error": error,
            "notice": notice,
            "form": form or {"new_username": "", "role": "viewer"},
            "csrf_token": csrf_token(request),
        },
        status_code=status_code,
    )


def _user_id(raw: str) -> int:
    try:
        return int(raw)
    except ValueError:
        return 0


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, username: str = Depends(admin_required)) -> Response:
    return _render_users(request, username)


@router.post("/users/create", response_class=HTMLResponse)
def users_create(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    new_username: str = Form(""),
    password: str = Form(""),
    confirm_password: str = Form(""),
    role: str = Form(""),
) -> Response:
    require_csrf(request, csrf)
    with open_db(request.app.state.settings.db_path) as conn:
        try:
            created = create_user(conn, new_username, password, confirm_password, role)
        except UserError as exc:
            return _render_users(
                request,
                username,
                error=str(exc),
                form={"new_username": new_username.strip(), "role": role},
                status_code=400,
            )
    log.info("%s added the NXray account %s (%s)", username, created.username, created.role)
    return _render_users(request, username, notice=f"Added {created.username} as {created.role}.")


def _change_other(request: Request, user_id: str) -> tuple[int, str | None]:
    """The target account's id, and a refusal when it is the admin's own account.

    An admin can't change their own role or disable themselves here: one
    misclick would lock them out of the page they need to undo it.
    """
    target_id = _user_id(user_id)
    account = current_account(request)
    if account is not None and account.id == target_id:
        return target_id, (
            "You can't change your own role or disable your own account. Another admin can."
        )
    return target_id, None


@router.post("/users/role", response_class=HTMLResponse)
def users_role(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    user_id: str = Form(""),
    role: str = Form(""),
) -> Response:
    require_csrf(request, csrf)
    target_id, refusal = _change_other(request, user_id)
    if refusal:
        return _render_users(request, username, error=refusal, status_code=400)
    with open_db(request.app.state.settings.db_path) as conn:
        try:
            changed = set_role(conn, target_id, role)
        except UserError as exc:
            return _render_users(request, username, error=str(exc), status_code=400)
    log.info("%s made %s %s", username, changed.username, changed.role)
    return _render_users(request, username, notice=f"{changed.username} is now {changed.role}.")


@router.post("/users/disable", response_class=HTMLResponse)
def users_disable(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    user_id: str = Form(""),
    disabled: str = Form(""),
) -> Response:
    """Disable an account (``disabled=yes``) or enable it again (anything else)."""
    require_csrf(request, csrf)
    target_id, refusal = _change_other(request, user_id)
    if refusal:
        return _render_users(request, username, error=refusal, status_code=400)
    disable = disabled == "yes"
    with open_db(request.app.state.settings.db_path) as conn:
        try:
            changed = set_disabled(conn, target_id, disable)
        except UserError as exc:
            return _render_users(request, username, error=str(exc), status_code=400)
    if disable:
        log.info("%s disabled the NXray account %s", username, changed.username)
        notice = f"{changed.username} is disabled and was signed out."
    else:
        log.info("%s enabled the NXray account %s", username, changed.username)
        notice = f"{changed.username} can sign in again."
    return _render_users(request, username, notice=notice)


@router.post("/users/password", response_class=HTMLResponse)
def users_password(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    user_id: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
) -> Response:
    """An admin sets someone's password; no old password needed, that is the point."""
    require_csrf(request, csrf)
    target_id = _user_id(user_id)
    with open_db(request.app.state.settings.db_path) as conn:
        target = get_user_by_id(conn, target_id)
        if target is None:
            return _render_users(
                request, username, error="That account no longer exists.", status_code=400
            )
        try:
            check_new_password(new_password, confirm_password)
            set_password(conn, target.id, new_password, keep_session=_own_session(request, target))
        except UserError as exc:
            return _render_users(request, username, error=str(exc), status_code=400)
    log.info("%s set a new password for %s", username, target.username)
    return _render_users(
        request,
        username,
        notice=f"New password set for {target.username}. It was signed out everywhere.",
    )


def _own_session(request: Request, target: User) -> str | None:
    """This session's id when the target is the signed-in account, so it stays signed in."""
    account = current_account(request)
    if account is not None and target.id == account.id:
        return session_id_from_request(request)
    return None


def _render_account(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    status_code: int = 200,
) -> Response:
    return templates.TemplateResponse(
        request,
        "account.html",
        {
            "username": username,
            "account": current_account(request),
            "role_help": ROLE_HELP,
            "min_password": MIN_PASSWORD_LENGTH,
            "error": error,
            "notice": notice,
            "csrf_token": csrf_token(request),
        },
        status_code=status_code,
    )


@router.get("/account", response_class=HTMLResponse)
def account_page(request: Request, username: str = Depends(login_required)) -> Response:
    return _render_account(request, username)


@router.post("/account/password", response_class=HTMLResponse)
def account_password(
    request: Request,
    username: str = Depends(login_required),
    csrf: str = Form(""),
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
) -> Response:
    """Change your own password. Needs the current one; other sessions are signed out."""
    require_csrf(request, csrf)
    settings = request.app.state.settings
    ip = client_ip(request)
    with open_db(settings.db_path) as conn:
        # Wrong current passwords count like failed sign-ins, so a stolen
        # session can't be used to guess the password at full speed.
        if is_rate_limited(conn, ip, settings.login_max_attempts, settings.login_lockout_minutes):
            return _render_account(
                request,
                username,
                error=(
                    "Too many wrong passwords. Try again in "
                    f"{settings.login_lockout_minutes} minutes."
                ),
                status_code=429,
            )
        account = get_user(conn, username)
        if account is None or not verify_password(current_password, account.password_hash):
            record_login_failure(conn, ip)
            return _render_account(
                request, username, error="Your current password is not right.", status_code=400
            )
        try:
            check_new_password(new_password, confirm_password)
        except UserError as exc:
            return _render_account(request, username, error=str(exc), status_code=400)
        set_password(conn, account.id, new_password, keep_session=session_id_from_request(request))
    log.info("%s changed their NXray password", username)
    return _render_account(
        request,
        username,
        notice="Password changed. Your other sessions were signed out; this one stays.",
    )
