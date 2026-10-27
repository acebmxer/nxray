"""The Users page (admin only) and each account's own Account page."""

from __future__ import annotations

import logging
import sqlite3

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
from app.totp import provisioning_uri, qr_svg, spaced_secret
from app.users import (
    MIN_PASSWORD_LENGTH,
    ROLE_HELP,
    ROLES,
    User,
    UserError,
    begin_two_factor,
    check_new_password,
    confirm_two_factor,
    create_user,
    get_user,
    get_user_by_id,
    list_users,
    new_backup_codes,
    set_disabled,
    set_password,
    set_role,
    turn_off_two_factor,
    two_factor_secret,
)

router = APIRouter()
log = logging.getLogger("nxray.users")

# Pages showing a two-factor key or backup codes: the browser must not keep a
# copy that the Back button or a shared computer's cache would show again.
NO_STORE = {"Cache-Control": "no-store"}


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


@router.post("/users/2fa-off", response_class=HTMLResponse)
def users_2fa_off(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    user_id: str = Form(""),
) -> Response:
    """An admin turns off someone else's two-factor sign-in, with no code needed.

    For someone who lost their phone and their backup codes, the way a
    password reset is for a lost password. Your own goes through the Account
    page, which asks for your password.
    """
    require_csrf(request, csrf)
    target_id = _user_id(user_id)
    account = current_account(request)
    if account is not None and account.id == target_id:
        return _render_users(
            request,
            username,
            error="Turn off your own two-factor sign-in on your Account page.",
            status_code=400,
        )
    with open_db(request.app.state.settings.db_path) as conn:
        try:
            changed = turn_off_two_factor(conn, target_id)
        except UserError as exc:
            return _render_users(request, username, error=str(exc), status_code=400)
    log.info("%s turned off two-factor sign-in for %s", username, changed.username)
    return _render_users(
        request,
        username,
        notice=(
            f"Two-factor sign-in is off for {changed.username}. They sign in with their "
            "password alone and can set it up again on their Account page."
        ),
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
    # Read again rather than the per-request cache: a form on this page may
    # just have changed the account (two-factor on or off).
    with open_db(request.app.state.settings.db_path) as conn:
        account = get_user(conn, username)
    return templates.TemplateResponse(
        request,
        "account.html",
        {
            "username": username,
            "account": account,
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
    notice = None
    if request.query_params.get("backup_used"):
        account = current_account(request)
        left = account.backup_codes_left if account is not None else 0
        notice = (
            f"You signed in with a backup code; {left} backup code{'s' if left != 1 else ''} left. "
        )
        if left <= 3:
            notice += "Press New backup codes below to get ten new ones."
    return _render_account(request, username, notice=notice)


def _check_current_password(
    request: Request, conn: sqlite3.Connection, username: str, password: str
) -> tuple[User | None, Response | None]:
    """The account when ``password`` is its current password, else the page saying why.

    Wrong current passwords count like failed sign-ins, so a stolen session
    can't be used to guess the password at full speed.
    """
    settings = request.app.state.settings
    ip = client_ip(request)
    if is_rate_limited(conn, ip, settings.login_max_attempts, settings.login_lockout_minutes):
        return None, _render_account(
            request,
            username,
            error=(
                f"Too many wrong passwords. Try again in {settings.login_lockout_minutes} minutes."
            ),
            status_code=429,
        )
    account = get_user(conn, username)
    if account is None or not verify_password(password, account.password_hash):
        record_login_failure(conn, ip)
        return None, _render_account(
            request, username, error="Your current password is not right.", status_code=400
        )
    return account, None


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
    with open_db(request.app.state.settings.db_path) as conn:
        account, refused = _check_current_password(request, conn, username, current_password)
        if account is None:
            assert refused is not None
            return refused
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


# ---- two-factor sign-in, on the Account page ----------------------------------------


def _render_two_factor_setup(
    request: Request,
    username: str,
    secret: str,
    *,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    return templates.TemplateResponse(
        request,
        "account_2fa_setup.html",
        {
            "username": username,
            "qr_svg": qr_svg(provisioning_uri(secret, username)),
            "secret": spaced_secret(secret),
            "error": error,
            "csrf_token": csrf_token(request),
        },
        status_code=status_code,
        headers=NO_STORE,
    )


def _render_backup_codes(
    request: Request, username: str, codes: list[str], *, turned_on: bool
) -> Response:
    heading = "Two-factor sign-in is on" if turned_on else "New backup codes"
    return templates.TemplateResponse(
        request,
        "account_2fa_codes.html",
        {"username": username, "codes": codes, "heading": heading, "turned_on": turned_on},
        headers=NO_STORE,
    )


@router.post("/account/2fa/setup", response_class=HTMLResponse)
def account_2fa_setup(
    request: Request, username: str = Depends(login_required), csrf: str = Form("")
) -> Response:
    """Start two-factor setup: a new key and its QR code. Nothing changes at sign-in yet."""
    require_csrf(request, csrf)
    with open_db(request.app.state.settings.db_path) as conn:
        account = get_user(conn, username)
        if account is None:
            return _render_account(request, username, error="Your account no longer exists.")
        try:
            secret = begin_two_factor(conn, account.id, request.app.state.settings.secret_key)
        except UserError as exc:
            return _render_account(request, username, error=str(exc), status_code=400)
    return _render_two_factor_setup(request, username, secret)


@router.post("/account/2fa/confirm", response_class=HTMLResponse)
def account_2fa_confirm(
    request: Request,
    username: str = Depends(login_required),
    csrf: str = Form(""),
    code: str = Form(""),
) -> Response:
    """Turn two-factor on once the app's code is right, then show the backup codes once."""
    require_csrf(request, csrf)
    secret_key = request.app.state.settings.secret_key
    with open_db(request.app.state.settings.db_path) as conn:
        account = get_user(conn, username)
        if account is None or account.totp_enabled:
            return _render_account(request, username)
        codes = confirm_two_factor(
            conn, account.id, code[:64], secret_key, keep_session=session_id_from_request(request)
        )
        if codes is None:
            # Same key and QR code again: a wrong code is far more often a
            # typo or a code that just changed than a bad scan.
            secret = two_factor_secret(account, secret_key)
            if secret is None:
                return _render_account(
                    request,
                    username,
                    error="Two-factor setup was not started. Press Set up two-factor sign-in.",
                    status_code=400,
                )
            return _render_two_factor_setup(
                request,
                username,
                secret,
                error=(
                    "That code is not right. Type the code the app shows now for "
                    f"NXray ({username}); if it changed while you typed, use the new one."
                ),
                status_code=400,
            )
    log.info("%s turned on two-factor sign-in", username)
    return _render_backup_codes(request, username, codes, turned_on=True)


@router.post("/account/2fa/codes", response_class=HTMLResponse)
def account_2fa_codes(
    request: Request,
    username: str = Depends(login_required),
    csrf: str = Form(""),
    current_password: str = Form(""),
) -> Response:
    """Ten new backup codes for your own account; needs your password. The old ones stop."""
    require_csrf(request, csrf)
    with open_db(request.app.state.settings.db_path) as conn:
        account, refused = _check_current_password(request, conn, username, current_password)
        if account is None:
            assert refused is not None
            return refused
        try:
            codes = new_backup_codes(conn, account.id)
        except UserError as exc:
            return _render_account(request, username, error=str(exc), status_code=400)
    log.info("%s made new backup codes", username)
    return _render_backup_codes(request, username, codes, turned_on=False)


@router.post("/account/2fa/off", response_class=HTMLResponse)
def account_2fa_off(
    request: Request,
    username: str = Depends(login_required),
    csrf: str = Form(""),
    current_password: str = Form(""),
) -> Response:
    """Turn off two-factor for your own account; needs your password, like changing it."""
    require_csrf(request, csrf)
    with open_db(request.app.state.settings.db_path) as conn:
        account, refused = _check_current_password(request, conn, username, current_password)
        if account is None:
            assert refused is not None
            return refused
        turn_off_two_factor(conn, account.id)
    log.info("%s turned off two-factor sign-in", username)
    return _render_account(
        request,
        username,
        notice="Two-factor sign-in is off. You can delete NXray from your authenticator app.",
    )
