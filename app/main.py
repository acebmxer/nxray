"""Application entry point: builds the FastAPI app and wires everything up."""

from __future__ import annotations

import threading
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import quote

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
    share_switch_reads,
    templates,
)
from app.history import start_sampler
from app.live import LiveCache
from app.logging_conf import configure_logging
from app.role_upgrade import upgrade_stored_roles
from app.routes import (
    aaa,
    activity,
    alerts,
    auth,
    callhome,
    config_page,
    copp,
    dashboard,
    dot1x,
    eem,
    errdisable,
    features,
    health,
    history,
    ip_sla,
    itd,
    live,
    loopbacks,
    monitor,
    mpls,
    nat,
    neighbors,
    pbr,
    pfc,
    pki,
    port_channels,
    ports,
    preferences,
    private_vlans,
    protocols,
    ptp,
    qos,
    routing,
    scheduler,
    security,
    settings_page,
    spanning_tree,
    switch_accounts,
    switch_admin,
    switch_files,
    switch_page,
    telemetry,
    track,
    traffic,
    tunnels,
    udld,
    users,
    vlans,
    vpc,
    vtp,
    vxlan,
)
from app.security import current_user, purge_expired_sessions, purge_old_login_attempts
from app.sflow import SflowCollector, start_collector
from app.switch_jobs import Jobs
from app.update import finish_pending_update, start_background_checker
from app.users import bootstrap_admin


class RevalidatedStaticFiles(StaticFiles):
    """The static files, sent with ``Cache-Control: no-cache``: the browser asks again on
    every load (an unchanged file is a short 304 answer), so a new stylesheet or script
    shows at once after an update instead of the old copy it kept."""

    def file_response(self, *args: Any, **kwargs: Any) -> Response:
        response = super().file_response(*args, **kwargs)
        response.headers.setdefault("Cache-Control", "no-cache")
        return response


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
    # A switch whose admin login is stored gets this version's new role rules at
    # once; on its own thread, since the switch may be slow or unreachable.
    threading.Thread(
        target=upgrade_stored_roles,
        args=(settings,),
        kwargs={
            "transport": app.state.nxapi_transport,
            "ssh_opener": app.state.ssh_opener,
            "alert_transport": app.state.alert_transport,
        },
        name="nxray-role-upgrade",
        daemon=True,
    ).start()
    stop_sampler = start_sampler(
        settings,
        lambda: app.state.nxapi_transport,
        lambda: app.state.alert_transport,
        app.state.sflow_collector,
    )
    stop_sflow = start_collector(
        settings.sflow_port, app.state.sflow_collector, settings.db_path, settings.sflow_keep_days
    )

    yield

    if stop_sampler is not None:
        stop_sampler.set()
    if stop_sflow is not None:
        stop_sflow.set()
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
    # The newest switch readings the self-refreshing pages share (app/live.py).
    app.state.live_cache = LiveCache()
    # sFlow samples added up per switch and minute (app/sflow.py); listened for
    # only with NXRAY_SFLOW_PORT set.
    app.state.sflow_collector = SflowCollector()
    # ...and a pretend SSH shell opener here (app/switch_ssh.py), and a pretend SSH
    # session opener for the switch file pages' commands and copies.
    app.state.ssh_opener = None
    app.state.ssh_session_opener = None
    # The switch file pages' slow work (app/switch_jobs.py); tests run it at once.
    app.state.jobs = Jobs()
    # ...and an httpx.MockTransport for webhooks here (app/alerts.py), and set
    # this to False so a change alert is sent before the request answers.
    app.state.alert_transport = None
    app.state.alerts_background = True

    @app.exception_handler(RedirectToLogin)
    async def _redirect_to_login(request: Request, exc: RedirectToLogin) -> RedirectResponse:
        return RedirectResponse(url=f"/login?next={quote(exc.next_url, safe='/')}", status_code=303)

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

    app.middleware("http")(share_switch_reads)
    app.middleware("http")(add_security_headers)
    app.mount("/static", RevalidatedStaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(dashboard.router)
    app.include_router(live.router)
    app.include_router(ports.router)
    app.include_router(history.router)
    app.include_router(traffic.router)
    app.include_router(switch_page.router)
    app.include_router(vlans.router)
    app.include_router(neighbors.router)
    app.include_router(port_channels.router)
    app.include_router(routing.router)
    app.include_router(protocols.router)
    app.include_router(spanning_tree.router)
    app.include_router(vpc.router)
    app.include_router(vxlan.router)
    app.include_router(monitor.router)
    app.include_router(qos.router)
    app.include_router(pfc.router)
    app.include_router(private_vlans.router)
    app.include_router(udld.router)
    app.include_router(vtp.router)
    app.include_router(dot1x.router)
    app.include_router(errdisable.router)
    app.include_router(callhome.router)
    app.include_router(scheduler.router)
    app.include_router(eem.router)
    app.include_router(ip_sla.router)
    app.include_router(loopbacks.router)
    app.include_router(tunnels.router)
    app.include_router(ptp.router)
    app.include_router(telemetry.router)
    app.include_router(aaa.router)
    app.include_router(pki.router)
    app.include_router(switch_files.router)
    app.include_router(pbr.router)
    app.include_router(itd.router)
    app.include_router(mpls.router)
    app.include_router(nat.router)
    app.include_router(track.router)
    app.include_router(copp.router)
    app.include_router(switch_admin.router)
    app.include_router(security.router)
    app.include_router(config_page.router)
    app.include_router(activity.router)
    app.include_router(alerts.router)
    app.include_router(features.router)
    app.include_router(users.router)
    app.include_router(switch_accounts.router)
    app.include_router(settings_page.router)
    app.include_router(preferences.router)
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
