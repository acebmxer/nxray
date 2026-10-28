"""The Switch page: set up the connection, test it, change it, repair it, or forget it."""

from __future__ import annotations

import dataclasses
import logging
import threading

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import (
    admin_required,
    operator_required,
    paused_message,
    redirect,
    require_csrf,
    stored_switch,
    templates,
)
from app.nxapi import NxapiClient, NxapiError, is_valid_host
from app.port_changes import ROLE_NAME, ROLE_VERSION, enable_port_changes
from app.routes.ports import render_port_page
from app.routes.vlans import render_vlans_page
from app.security import csrf_token
from app.switch_connection import (
    DecryptionError,
    delete_connection,
    get_connection,
    load_target,
    record_test_result,
    replace_login,
    save_connection,
    set_address,
    set_changes_enabled,
    set_changes_off,
    set_config_saved,
    set_unsaved_changes,
)
from app.switch_repair import ROLE_GIVEN, ROLE_KEPT, ROLE_MISSING, run_repair
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
    if form is None:
        if connection is not None:
            form = {"host": connection.host, "port": str(connection.port)}
        else:
            form = {"host": "", "port": "443", "account_name": DEFAULT_ACCOUNT_NAME}
    return templates.TemplateResponse(
        request,
        "switch.html",
        {
            "username": username,
            "connection": connection,
            "error": error,
            "notice": notice,
            "form": form,
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
def switch_page(request: Request, username: str = Depends(admin_required)) -> Response:
    return _render(request, username)


def _check_address(host: str, port: str) -> tuple[int, str | None]:
    """The NX-API port as a number, and what is wrong with the address (None: nothing)."""
    if not is_valid_host(host):
        return 0, "Enter the switch's address as a bare IP address or hostname."
    try:
        port_number = int(port)
    except ValueError:
        port_number = 0
    if not 1 <= port_number <= 65535:
        return 0, "The NX-API port is a number from 1 to 65535 (normally 443)."
    return port_number, None


@router.post("/switch/setup", response_class=HTMLResponse)
def switch_setup(
    request: Request,
    username: str = Depends(admin_required),
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

    port_number, problem = _check_address(host, port)
    if problem:
        return fail(problem)
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
    request: Request, username: str = Depends(admin_required), csrf: str = Form("")
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


@router.post("/switch/address", response_class=HTMLResponse)
def switch_address(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    host: str = Form(""),
    port: str = Form("443"),
) -> Response:
    """Change the switch's address, after NXray's account signed in at the new one."""
    require_csrf(request, csrf)
    settings = request.app.state.settings
    host = host.strip()
    form = {"host": host, "port": port.strip()}
    with open_db(settings.db_path) as conn:
        connection = get_connection(conn)
    if connection is None:
        return redirect("/switch")

    def fail(message: str) -> Response:
        return _render(request, username, error=message, form=form, status_code=400)

    port_number, problem = _check_address(host, port.strip())
    if problem:
        return fail(problem)
    if host == connection.host and port_number == connection.port:
        return fail("That is the address NXray already uses.")
    # Signing in now would keep the account's NX-API session alive, so the
    # switch would not apply the new role the pause is waiting for.
    if waiting := connection.paused_seconds():
        return fail(paused_message(waiting))
    with open_db(settings.db_path) as conn:
        try:
            target = load_target(conn, settings.secret_key)
        except LookupError:
            return redirect("/switch")
        except DecryptionError:
            return fail(
                "NXray cannot read the stored switch login, so it cannot sign in at the new "
                "address to check it. Use Run setup again below with the new address instead."
            )

    if not _setup_lock.acquire(blocking=False):
        return fail("A switch change is already running. Wait for it, then reload this page.")
    try:
        new_target = dataclasses.replace(target, host=host, port=port_number)
        status = check_connection(new_target, transport=request.app.state.nxapi_transport)
        if not status.ok or status.system is None:
            return fail(
                f"NXray kept the address {connection.host}, port {connection.port}, because "
                f"its account could not sign in at the new one. {status.message}"
            )
        with open_db(settings.db_path) as conn:
            set_address(conn, host=host, port=port_number, switch_hostname=status.system.hostname)
            record_test_result(conn, ok=True, message=status.message)
    finally:
        _setup_lock.release()

    log.info("switch address changed from %s to %s", connection.host, host)
    notice = f"NXray now uses {host}, port {port_number}. {status.message}"
    if status.system.hostname != connection.switch_hostname:
        notice += (
            f" The switch there is called {status.system.hostname}; it was called "
            f"{connection.switch_hostname} before."
        )
    return _render(request, username, notice=notice)


@router.post("/switch/repair", response_class=HTMLResponse)
def switch_repair(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    host: str = Form(""),
    port: str = Form("443"),
    admin_user: str = Form(""),
    admin_password: str = Form(""),
    confirm_save: str = Form(""),
) -> Response:
    """Run setup again: a new password for NXray's account, or the account made again."""
    require_csrf(request, csrf)
    settings = request.app.state.settings
    host = host.strip()
    admin_user = admin_user.strip()
    form = {"host": host, "port": port.strip()}
    with open_db(settings.db_path) as conn:
        connection = get_connection(conn)
    if connection is None:
        return redirect("/switch")

    def fail(message: str) -> Response:
        return _render(request, username, error=message, form=form, status_code=400)

    port_number, problem = _check_address(host, port.strip())
    if problem:
        return fail(problem)
    if not admin_user or not admin_password:
        return fail("Enter the switch's admin username and password.")
    if confirm_save != "yes":
        return fail("Tick the box to confirm NXray may save the switch configuration.")
    # Checking the new password signs the account in, which would keep its
    # NX-API session alive and hold up the role the pause is waiting for.
    if waiting := connection.paused_seconds():
        return fail(paused_message(waiting))

    def store(password: str, switch_hostname: str) -> None:
        with open_db(settings.db_path) as conn:
            replace_login(
                conn,
                host=host,
                port=port_number,
                password=password,
                switch_hostname=switch_hostname,
                secret_key=settings.secret_key,
            )

    if not _setup_lock.acquire(blocking=False):
        return fail("A switch change is already running. Wait for it, then reload this page.")
    try:
        result = run_repair(
            host=host,
            port=port_number,
            admin_user=admin_user,
            admin_password=admin_password,
            account_name=connection.username,
            port_changes=connection.changes_enabled,
            store=store,
            transport=request.app.state.nxapi_transport,
        )
    except SetupError as exc:
        return fail(str(exc))
    finally:
        _setup_lock.release()

    with open_db(settings.db_path) as conn:
        set_config_saved(conn, result.config_saved)
        record_test_result(
            conn, ok=True, message="Run setup again signed in with the new password."
        )
        if result.port_role == ROLE_GIVEN:
            set_changes_enabled(
                conn, pause_seconds=result.pause_seconds, role_version=connection.role_version
            )
        elif result.port_role == ROLE_MISSING:
            set_changes_off(conn)

    name = connection.username
    if result.recreated:
        done = (
            f"The account {name} was no longer on {result.switch_hostname}, so NXray made it "
            "again with a new password."
        )
    else:
        done = f"NXray gave its account {name} on {result.switch_hostname} a new password."
    if result.port_role == ROLE_KEPT:
        done += " Its port changes stay on."
    elif result.port_role == ROLE_GIVEN and result.pause_seconds:
        minutes = result.pause_seconds // 60
        done += (
            f" It also gave the account the {ROLE_NAME} role again. The switch applies that "
            "once it has not heard from NXray for a while, so NXray now waits about "
            f"{minutes} minutes before contacting it again."
        )
    elif result.port_role == ROLE_GIVEN:
        done += f" It also gave the account the {ROLE_NAME} role again, so port changes stay on."
    elif result.port_role == ROLE_MISSING:
        done += (
            f" Port changes are now off: the {ROLE_NAME} role is no longer on the switch. "
            "Turn them on again below."
        )
    if (host, port_number) != (connection.host, connection.port):
        done += f" NXray now uses {host}, port {port_number}."
    log.info("ran setup again for switch account %s on %s", name, host)
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


@router.post("/switch/enable-changes", response_class=HTMLResponse)
def switch_enable_changes(
    request: Request,
    username: str = Depends(admin_required),
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
    account = connection.username
    count = result.port_count
    settings_words = (
        f"set the speed, MTU, FEC, flow control, storm control and layer (switched or "
        f"routed) of the {count} front ports, and split or join the 100G ports"
    )
    if not result.had_role:
        minutes = result.pause_seconds // 60
        done = (
            f"Port, VLAN and port settings changes are on: {account} may now turn the "
            f"{count} front ports on or off, edit their descriptions, set their VLANs and "
            "their speed, MTU, FEC, flow control, storm control and layer (switched or "
            "routed), split or join the 100G ports, and create, rename and delete VLANs. "
            "The switch applies this once it has not heard from NXray for a while, so NXray "
            f"now waits about {minutes} minutes before contacting it again."
        )
    elif connection.role_version >= ROLE_VERSION:
        done = (
            f"The port list is updated: NXray's role now names the {count} front ports the "
            "switch has now. The switch applies this at once, so there is no wait."
        )
    elif connection.role_version < 2:
        done = (
            f"VLAN and port settings changes are on: {account} may now also create, rename "
            f"and delete VLANs, set the VLANs of the front ports, and {settings_words}. The "
            "switch applies this at once, so there is no wait."
        )
    else:
        done = (
            f"Port settings changes are on: {account} may now also {settings_words}. The "
            "switch applies this at once, so there is no wait."
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
    request: Request,
    username: str = Depends(operator_required),
    csrf: str = Form(""),
    back: str = Form(""),
    port: str = Form(""),
) -> Response:
    """Save config: copy running-config startup-config with NXray's own account.

    ``back`` names the page the button was on (``port`` with ``port`` set,
    or ``vlans``); the answer is shown there. Anything else means the
    Switch page, so the field can never send the browser elsewhere.
    """
    require_csrf(request, csrf)

    def answer(*, error: str | None = None, notice: str | None = None) -> Response:
        if back == "port" and port:
            return render_port_page(request, username, port, error=error, notice=notice)
        if back == "vlans":
            return render_vlans_page(request, username, error=error, notice=notice)
        return _render(request, username, error=error, notice=notice)

    connection, target, error = stored_switch(request)
    if connection is None:
        return redirect("/switch")
    if target is None:
        return answer(error=error)
    try:
        with NxapiClient(target, transport=request.app.state.nxapi_transport) as client:
            client.save_config()
    except NxapiError as exc:
        return answer(
            error=connection_error(exc, target)
            + " The changes are still active, but are lost if the switch restarts.",
        )
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        set_unsaved_changes(conn, False)
    log.info("saved the switch configuration on %s", connection.host)
    return answer(notice="Saved: the switch keeps its current configuration on restart.")


@router.post("/switch/forget", response_class=HTMLResponse)
def switch_forget(
    request: Request, username: str = Depends(admin_required), csrf: str = Form("")
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
