"""The Switch page: set up the connection, test it, or forget it."""

from __future__ import annotations

import logging
import threading

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import (
    login_required,
    paused_message,
    redirect,
    require_csrf,
    stored_switch,
    templates,
)
from app.nxapi import NxapiClient, NxapiError, is_valid_host
from app.port_changes import ROLE_NAME, ROLE_VERSION, enable_port_changes
from app.security import csrf_token
from app.switch_connection import (
    DecryptionError,
    delete_connection,
    get_connection,
    load_target,
    record_test_result,
    save_connection,
    set_changes_enabled,
    set_config_saved,
    set_unsaved_changes,
)
from app.switch_setup import (
    KEY_CHANGED_MESSAGE,
    SetupError,
    check_connection,
    connection_error,
    run_setup,
)

router = APIRouter()
log = logging.getLogger("nxray.switch")

DEFAULT_ACCOUNT_NAME = "nxray"

# One setup at a time. Two at once (a double-clicked button) could both find
# the name free, and the second "username" command would silently change the
# first one's password on the switch.
_setup_lock = threading.Lock()


def _render(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
    status_code: int = 200,
) -> Response:
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        connection = get_connection(conn)
    return templates.TemplateResponse(
        request,
        "switch.html",
        {
            "username": username,
            "connection": connection,
            "error": error,
            "notice": notice,
            "form": form or {"host": "", "port": "443", "account_name": DEFAULT_ACCOUNT_NAME},
            "csrf_token": csrf_token(request),
            "role_name": ROLE_NAME,
            "role_version": ROLE_VERSION,
            "paused": paused_message(connection.paused_seconds())
            if connection and connection.paused_seconds()
            else None,
        },
        status_code=status_code,
    )


@router.get("/switch", response_class=HTMLResponse)
def switch_page(request: Request, username: str = Depends(login_required)) -> Response:
    return _render(request, username)


@router.post("/switch/setup", response_class=HTMLResponse)
def switch_setup(
    request: Request,
    username: str = Depends(login_required),
    csrf: str = Form(""),
    host: str = Form(""),
    port: str = Form("443"),
    admin_user: str = Form(""),
    admin_password: str = Form(""),
    account_name: str = Form(DEFAULT_ACCOUNT_NAME),
    confirm_save: str = Form(""),
) -> Response:
    require_csrf(request, csrf)
    settings = request.app.state.settings
    host = host.strip()
    account_name = account_name.strip()
    admin_user = admin_user.strip()
    # Everything but the admin password goes back into the form on an error.
    form = {"host": host, "port": port.strip(), "account_name": account_name}

    def fail(message: str) -> Response:
        return _render(request, username, error=message, form=form, status_code=400)

    if not is_valid_host(host):
        return fail("Enter the switch's address as a bare IP address or hostname.")
    try:
        port_number = int(port)
    except ValueError:
        port_number = 0
    if not 1 <= port_number <= 65535:
        return fail("The NX-API port is a number from 1 to 65535 (normally 443).")
    if not admin_user or not admin_password:
        return fail("Enter the switch's admin username and password.")
    if confirm_save != "yes":
        return fail("Tick the box to confirm NXray may save the switch configuration.")

    def store(password: str, switch_hostname: str) -> None:
        with open_db(settings.db_path) as conn:
            save_connection(
                conn,
                host=host,
                port=port_number,
                username=account_name,
                password=password,
                switch_hostname=switch_hostname,
                config_saved=False,
                secret_key=settings.secret_key,
            )

    if not _setup_lock.acquire(blocking=False):
        return fail("A setup is already running. Wait for it to finish, then reload this page.")
    try:
        with open_db(settings.db_path) as conn:
            if get_connection(conn) is not None:
                return fail("A switch is already set up. Forget it first to set up another.")
        result = run_setup(
            host=host,
            port=port_number,
            admin_user=admin_user,
            admin_password=admin_password,
            account_name=account_name,
            store=store,
            transport=request.app.state.nxapi_transport,
        )
    except SetupError as exc:
        return fail(str(exc))
    finally:
        _setup_lock.release()

    with open_db(settings.db_path) as conn:
        set_config_saved(conn, result.config_saved)
        record_test_result(conn, ok=True, message="Setup signed in with the new account.")

    if result.config_saved:
        notice = (
            f"Set up. NXray created the account {account_name} on {result.switch_hostname} "
            "and saved the switch configuration."
        )
        return _render(request, username, notice=notice)
    return _render(
        request,
        username,
        error=(
            f"NXray created the account {account_name} on {result.switch_hostname} and can "
            "use it, but saving the switch configuration failed, so the account is lost if "
            "the switch restarts. Run copy running-config startup-config on the switch. "
            f"Details: {result.save_error}"
        ),
    )


@router.post("/switch/test", response_class=HTMLResponse)
def switch_test(
    request: Request, username: str = Depends(login_required), csrf: str = Form("")
) -> Response:
    require_csrf(request, csrf)
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        connection = get_connection(conn)
        if connection is None:
            return redirect("/switch")
        if waiting := connection.paused_seconds():
            return _render(request, username, error=paused_message(waiting))
        try:
            target = load_target(conn, settings.secret_key)
        except LookupError:
            return redirect("/switch")
        except DecryptionError:
            record_test_result(conn, ok=False, message=KEY_CHANGED_MESSAGE)
            return _render(request, username, error=KEY_CHANGED_MESSAGE)

    status = check_connection(target, transport=request.app.state.nxapi_transport)
    with open_db(settings.db_path) as conn:
        record_test_result(conn, ok=status.ok, message=status.message)
    if status.ok:
        return _render(request, username, notice=status.message)
    return _render(request, username, error=status.message)


@router.post("/switch/enable-changes", response_class=HTMLResponse)
def switch_enable_changes(
    request: Request,
    username: str = Depends(login_required),
    csrf: str = Form(""),
    admin_user: str = Form(""),
    admin_password: str = Form(""),
    ssh_port: str = Form("22"),
    confirm_save: str = Form(""),
) -> Response:
    require_csrf(request, csrf)
    settings = request.app.state.settings
    admin_user = admin_user.strip()
    with open_db(settings.db_path) as conn:
        connection = get_connection(conn)
    if connection is None:
        return redirect("/switch")

    def fail(message: str) -> Response:
        return _render(request, username, error=message, status_code=400)

    try:
        ssh_port_number = int(ssh_port)
    except ValueError:
        ssh_port_number = 0
    if not 1 <= ssh_port_number <= 65535:
        return fail("The SSH port is a number from 1 to 65535 (normally 22).")
    if not admin_user or not admin_password:
        return fail("Enter the switch's admin username and password.")
    if confirm_save != "yes":
        return fail("Tick the box to confirm NXray may save the switch configuration.")

    # Shares the setup lock: both change NXray's account on the switch.
    if not _setup_lock.acquire(blocking=False):
        return fail("A switch change is already running. Wait for it, then reload this page.")
    try:
        result = enable_port_changes(
            host=connection.host,
            nxapi_port=connection.port,
            ssh_port=ssh_port_number,
            admin_user=admin_user,
            admin_password=admin_password,
            account_name=connection.username,
            transport=request.app.state.nxapi_transport,
            ssh_opener=request.app.state.ssh_opener,
        )
    except SetupError as exc:
        return fail(str(exc))
    finally:
        _setup_lock.release()

    with open_db(settings.db_path) as conn:
        set_changes_enabled(conn, pause_seconds=result.pause_seconds, role_version=ROLE_VERSION)
    if result.had_role:
        done = (
            f"VLAN changes are on: {connection.username} may now also create, rename and "
            f"delete VLANs and set the VLANs of the {result.port_count} front ports. The "
            "switch applies this at once, so there is no wait."
        )
    else:
        minutes = result.pause_seconds // 60
        done = (
            f"Port changes are on: {connection.username} may now turn the "
            f"{result.port_count} front ports on or off, edit their descriptions and set "
            "their VLANs, and create, rename and delete VLANs. The switch applies this once "
            "it has not heard from NXray for a while, so NXray now waits about "
            f"{minutes} minutes before contacting it again."
        )
    if result.config_saved:
        return _render(request, username, notice=done + " The switch configuration was saved.")
    return _render(
        request,
        username,
        error=(
            done + " Saving the switch configuration failed, so this is lost if the switch "
            "restarts. Run copy running-config startup-config on the switch. "
            f"Details: {result.save_error}"
        ),
    )


@router.post("/switch/save", response_class=HTMLResponse)
def switch_save(
    request: Request, username: str = Depends(login_required), csrf: str = Form("")
) -> Response:
    """Save config: copy running-config startup-config with NXray's own account."""
    require_csrf(request, csrf)
    connection, target, error = stored_switch(request)
    if connection is None:
        return redirect("/switch")
    if target is None:
        return _render(request, username, error=error)
    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            client.save_config()
    except NxapiError as exc:
        return _render(
            request,
            username,
            error=connection_error(exc, target)
            + " The changes are still active, but are lost if the switch restarts.",
        )
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        set_unsaved_changes(conn, False)
    log.info("saved the switch configuration on %s", connection.host)
    return _render(
        request, username, notice="Saved: the switch keeps its current configuration on restart."
    )


@router.post("/switch/forget", response_class=HTMLResponse)
def switch_forget(
    request: Request, username: str = Depends(login_required), csrf: str = Form("")
) -> Response:
    require_csrf(request, csrf)
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        connection = get_connection(conn)
        delete_connection(conn)
    if connection is None:
        return redirect("/switch")
    log.info("forgot the switch %s (account %s)", connection.host, connection.username)
    return _render(
        request,
        username,
        notice=(
            f"NXray forgot the switch {connection.switch_hostname}. The account "
            f"{connection.username} is still on the switch; the Switch page help says how "
            "to remove it."
        ),
    )
