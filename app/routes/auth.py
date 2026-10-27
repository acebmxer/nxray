"""Login and logout."""

from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import redirect, safe_next, templates
from app.security import (
    SESSION_COOKIE,
    check_credentials,
    clear_login_failures,
    client_ip,
    create_session,
    current_user,
    destroy_session,
    is_rate_limited,
    record_login_failure,
    sign_session_id,
    unsign_session_id,
)

router = APIRouter()


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

        if not check_credentials(
            username, password, settings.admin_user, settings.admin_password_hash
        ):
            record_login_failure(conn, ip)
            return templates.TemplateResponse(
                request,
                "login.html",
                {"error": "Incorrect username or password.", "next_url": next_url},
                status_code=401,
            )

        clear_login_failures(conn, ip)
        session_id = create_session(conn, settings.admin_user, settings.session_hours)

    response = redirect(next_url)
    _set_session_cookie(response, request, session_id)
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
