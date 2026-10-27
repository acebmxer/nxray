"""Login and logout, including the code step of two-factor sign-in."""

from __future__ import annotations

import logging
import sqlite3
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import redirect, safe_next, templates
from app.security import (
    PENDING_2FA_COOKIE,
    PENDING_2FA_MINUTES,
    SESSION_COOKIE,
    clear_login_failures,
    client_ip,
    create_session,
    current_user,
    destroy_session,
    is_rate_limited,
    pending_matches,
    read_pending_2fa,
    record_login_failure,
    sign_pending_2fa,
    sign_session_id,
    unsign_session_id,
)
from app.users import AccountDisabled, User, authenticate, check_second_factor, get_user

router = APIRouter()
log = logging.getLogger("nxray.auth")


def _set_session_cookie(response: Response, request: Request, session_id: str) -> None:
    settings = request.app.state.settings
    response.set_cookie(
        key=SESSION_COOKIE,
        value=sign_session_id(session_id, settings.secret_key),
        max_age=settings.session_hours * 3600,
        httponly=True,
        samesite="lax",
        secure=settings.https_only,
        path="/",
    )


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/") -> Response:
    # Already signed in: no reason to show the form again.
    if current_user(request) is not None:
        return redirect(safe_next(next))
    return templates.TemplateResponse(request, "login.html", {"next_url": safe_next(next)})


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),
) -> Response:
    settings = request.app.state.settings
    ip = client_ip(request)
    next_url = safe_next(next)

    with open_db(settings.db_path) as conn:
        if is_rate_limited(conn, ip, settings.login_max_attempts, settings.login_lockout_minutes):
            return templates.TemplateResponse(
                request,
                "login.html",
                {
                    "error": (
                        "Too many failed attempts. Try again in "
                        f"{settings.login_lockout_minutes} minutes."
                    ),
                    "next_url": next_url,
                },
                status_code=429,
            )

        try:
            user = authenticate(conn, username, password)
        except AccountDisabled:
            record_login_failure(conn, ip)
            return templates.TemplateResponse(
                request,
                "login.html",
                {
                    "error": "This account is disabled. Ask an NXray admin to enable it.",
                    "next_url": next_url,
                },
                status_code=401,
            )
        if user is None:
            record_login_failure(conn, ip)
            return templates.TemplateResponse(
                request,
                "login.html",
                {"error": "Incorrect username or password.", "next_url": next_url},
                status_code=401,
            )

        if user.totp_enabled:
            # The password alone opens nothing: the code step still has to
            # pass. Earlier failures are NOT cleared here, or someone who has
            # the password could reset the count before every few code
            # guesses by signing in again.
            response = redirect(f"/login/2fa?next={quote(next_url, safe='/')}")
            response.set_cookie(
                key=PENDING_2FA_COOKIE,
                value=sign_pending_2fa(user.username, user.password_hash, settings.secret_key),
                max_age=PENDING_2FA_MINUTES * 60,
                httponly=True,
                samesite="lax",
                secure=settings.https_only,
                path="/login/2fa",
            )
            return response

        clear_login_failures(conn, ip)
        session_id = create_session(conn, user.username, settings.session_hours)

    response = redirect(next_url)
    _set_session_cookie(response, request, session_id)
    return response


def _pending_account(request: Request, conn: sqlite3.Connection) -> User | None:
    """The account a recent password step was right for, if it still needs a code.

    None when the pending cookie is missing, forged or older than
    PENDING_2FA_MINUTES, or the account was disabled, got a new password or
    had two-factor turned off since: the sign-in then starts again.
    """
    cookie = request.cookies.get(PENDING_2FA_COOKIE)
    if not cookie:
        return None
    pending = read_pending_2fa(cookie, request.app.state.settings.secret_key)
    if pending is None:
        return None
    username, mark = pending
    user = get_user(conn, username)
    if user is None or user.disabled or not user.totp_enabled:
        return None
    if not pending_matches(mark, user.password_hash):
        return None
    return user


def _two_factor_page(
    request: Request, next_url: str, *, error: str | None = None, status_code: int = 200
) -> Response:
    return templates.TemplateResponse(
        request,
        "login_2fa.html",
        {"next_url": next_url, "error": error},
        status_code=status_code,
    )


def _back_to_login(next_url: str) -> Response:
    response = redirect(f"/login?next={quote(next_url, safe='/')}")
    response.delete_cookie(PENDING_2FA_COOKIE, path="/login/2fa")
    return response


@router.get("/login/2fa", response_class=HTMLResponse)
def login_2fa_form(request: Request, next: str = "/") -> Response:
    next_url = safe_next(next)
    if current_user(request) is not None:
        return redirect(next_url)
    with open_db(request.app.state.settings.db_path) as conn:
        if _pending_account(request, conn) is None:
            return _back_to_login(next_url)
    return _two_factor_page(request, next_url)


@router.post("/login/2fa", response_class=HTMLResponse)
def login_2fa_submit(request: Request, code: str = Form(""), next: str = Form("/")) -> Response:
    settings = request.app.state.settings
    ip = client_ip(request)
    next_url = safe_next(next)

    with open_db(settings.db_path) as conn:
        # Checked before the cookie, so a blocked address learns nothing.
        if is_rate_limited(conn, ip, settings.login_max_attempts, settings.login_lockout_minutes):
            return _two_factor_page(
                request,
                next_url,
                error=(
                    "Too many failed attempts. Try again in "
                    f"{settings.login_lockout_minutes} minutes."
                ),
                status_code=429,
            )
        user = _pending_account(request, conn)
        if user is None:
            return _back_to_login(next_url)

        used = check_second_factor(conn, user, code[:64], settings.secret_key)
        if used is None:
            record_login_failure(conn, ip)
            return _two_factor_page(
                request,
                next_url,
                error=(
                    "That code is not right, or was already used. Type the code your "
                    "app shows now, or a backup code."
                ),
                status_code=401,
            )

        clear_login_failures(conn, ip)
        session_id = create_session(conn, user.username, settings.session_hours)
        left = len(user.totp_backup_codes) - 1 if used == "backup" else None

    if left is not None:
        log.info("%s signed in with a backup code (%d left)", user.username, left)
    response = redirect(next_url if left is None else "/account?backup_used=1")
    _set_session_cookie(response, request, session_id)
    response.delete_cookie(PENDING_2FA_COOKIE, path="/login/2fa")
    return response


@router.post("/logout")
def logout(request: Request) -> Response:
    settings = request.app.state.settings
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        session_id = unsign_session_id(cookie, settings.secret_key)
        if session_id:
            with open_db(settings.db_path) as conn:
                destroy_session(conn, session_id)

    response = redirect("/login")
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response
