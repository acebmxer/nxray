"""Application entry point: builds the FastAPI app and wires everything up."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.config import Settings, load_settings
from app.db import init_db, open_db
from app.dependencies import (
    STATIC_DIR,
    CsrfFailed,
    Forbidden,
    RedirectToLogin,
    add_security_headers,
    current_role,
    templates,
)
from app.history import start_sampler
from app.logging_conf import configure_logging
from app.routes import (
    auth,
    dashboard,
    health,
    history,
    ports,
    settings_page,
    switch_page,
    users,
    vlans,
)
from app.security import current_user, purge_expired_sessions, purge_old_login_attempts
from app.update import finish_pending_update, start_background_checker
from app.users import bootstrap_admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    log = configure_logging(settings.log_level)

    schema = init_db(settings.db_path)

    # Rows from a previous run are worthless: expired sessions cannot be used
    # and stale failures would keep an address locked out past its window.
    with open_db(settings.db_path) as conn:
        # The account in nxray.env becomes the first admin, once; see
        # app/users.py bootstrap_admin.
        if bootstrap_admin(conn, settings.admin_user, settings.admin_password_hash):
            log.info(
                "created the first NXray account %s (admin) from nxray.env", settings.admin_user
            )
        # An update still marked in progress means this is the container the
        # update just created; see app/update.py.
        finish_pending_update(conn)
        sessions = purge_expired_sessions(conn)
        attempts = purge_old_login_attempts(conn, settings.login_lockout_minutes)
    log.info(
        "NXray %s started (data=%s, schema v%d, purged %d sessions, %d login attempts)",
        __version__,
        settings.data_dir,
        schema,
        sessions,
        attempts,
    )

    start_background_checker(settings)
    stop_sampler = start_sampler(settings, lambda: app.state.nxapi_transport)

    yield

    if stop_sampler is not None:
        stop_sampler.set()
    log.info("NXray stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the app. Tests pass their own settings; production loads the env."""
    app = FastAPI(
        title="NXray",
        description="A web interface for Cisco Nexus switches, built on NX-API.",
        version=__version__,
        lifespan=lifespan,
        # The docs are unauthenticated in FastAPI, and this app stands in front
        # of a switch, so they stay off until there is a reason to expose them.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings or load_settings()
    # Tests put an httpx.MockTransport here so no request reaches a real switch.
    app.state.nxapi_transport = None
    # ...and a pretend SSH shell opener here (app/switch_ssh.py).
    app.state.ssh_opener = None

    @app.exception_handler(RedirectToLogin)
    async def _redirect_to_login(request: Request, exc: RedirectToLogin) -> RedirectResponse:
        return RedirectResponse(url=f"/login?next={exc.next_url}", status_code=303)

    @app.exception_handler(CsrfFailed)
    async def _csrf_failed(request: Request, exc: CsrfFailed) -> Response:
        return templates.TemplateResponse(request, "403.html", {}, status_code=403)

    @app.exception_handler(Forbidden)
    async def _forbidden(request: Request, exc: Forbidden) -> Response:
        # Only raised once the caller is signed in, so the top bar still shows.
        return templates.TemplateResponse(
            request,
            "forbidden.html",
            {
                "username": current_user(request),
                "required_role": exc.required_role,
                "role": current_role(request),
            },
            status_code=403,
        )

    app.middleware("http")(add_security_headers)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(dashboard.router)
    app.include_router(ports.router)
    app.include_router(history.router)
    app.include_router(switch_page.router)
    app.include_router(vlans.router)
    app.include_router(users.router)
    app.include_router(settings_page.router)
    return app


def __getattr__(name: str) -> FastAPI:
    """Build the production app only when `app` is actually asked for.

    uvicorn imports `app.main:app`, which must construct the app. Building it
    at import time would read the environment and create the data directory
    as a side effect of merely importing this module, which breaks tests and
    any tooling that imports it. PEP 562 defers the work until the attribute
    is reached.
    """
    if name == "app":
        return create_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
