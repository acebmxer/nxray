"""The Switch page: add a switch, test it, change it, repair it, or forget it; and
the switch picker in the top bar, which chooses the switch every page shows."""

from __future__ import annotations

import dataclasses
import logging
import threading

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import (
    CsrfFailed,
    admin_required,
    current_role,
    login_required,
    note_activity,
    operator_required,
    paused_message,
    redirect,
    require_csrf,
    safe_next,
    stored_switch,
    templates,
)
from app.nxapi import NxapiClient, NxapiError, is_valid_host
from app.port_changes import (
    ROLE_NAME,
    ROLE_VERSION,
    EnableResult,
    enable_port_changes,
    missing_changes,
)
from app.routes.config_page import render_config_page
from app.routes.features import render_features_page
from app.routes.neighbors import render_neighbors_page
from app.routes.port_channels import render_port_channels_page
from app.routes.ports import ports_origin, render_port_page, render_ports_page
from app.routes.protocols import render_protocol_page, render_protocols_page
from app.routes.routing import render_routing_page
from app.routes.security import render_acls_page, render_dhcp_page, render_port_security_page
from app.routes.spanning_tree import render_spanning_tree_page
from app.routes.switch_admin import render_switch_admin_page
from app.routes.traffic import render_traffic_page
from app.routes.vlans import render_vlans_page
from app.routing_protocols import protocol as find_protocol
from app.security import csrf_token, csrf_valid_any_switch
from app.switch_choice import choose_switch, remember_switch, resolve_switch_id, selected_switch_id
from app.switch_connection import (
    DecryptionError,
    delete_connection,
    find_by_address,
    get_connection,
    list_connections,
    load_target,
    record_test_result,
    replace_login,
    save_connection,
    set_address,
    set_changes_enabled,
    set_changes_off,
    set_config_saved,
    set_switch_identity,
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
    add_form: dict[str, str] | None = None,
    status_code: int = 200,
) -> Response:
    """The Switch page for the switch this request is for. ``form`` refills the
    forms about that switch, ``add_form`` the one adding another."""
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        switches = list_connections(conn)
        connection = get_connection(conn, selected_switch_id(request))
    empty = {"host": "", "port": "443", "account_name": DEFAULT_ACCOUNT_NAME}
    if form is None:
        if connection is not None:
            form = {"host": connection.host, "port": str(connection.port)}
        else:
            form = add_form or empty
    return templates.TemplateResponse(
        request,
        "switch.html",
        {
            "username": username,
            "connection": connection,
            "switches": switches,
            "error": error,
            "notice": notice,
            "form": form,
            "add_form": add_form or empty,
            "csrf_token": csrf_token(request),
            "role_name": ROLE_NAME,
            "role_version": ROLE_VERSION,
            "missing_changes": missing_changes(connection.role_version) if connection else "",
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


def _check_ssh_port(ssh_port: str) -> tuple[int, str | None]:
    """The SSH port as a number, and what is wrong with it (None: nothing)."""
    try:
        port_number = int(ssh_port)
    except ValueError:
        port_number = 0
    if not 1 <= port_number <= 65535:
        return 0, "The SSH port is a number from 1 to 65535 (normally 22)."
    return port_number, None


# Added to a message when the role was written while interface-vlan is off.
_VLAN_INTERFACES_OFF = (
    " VLAN interfaces are off on the switch (interface-vlan), and the switch only "
    "takes them into the role while they are on, so NXray cannot make them yet: "
    "turn interface-vlan on on the Features page, then press Update the port list "
    "here."
)


def _changes_on_at_setup(role: EnableResult) -> str:
    """What setup tells the admin after it also gave the account the role."""
    minutes = role.pause_seconds // 60
    words = (
        f" Changes are on too: the account has the {ROLE_NAME} role, so NXray can make "
        "every change this version offers. The switch applies the role once it has not "
        "heard from NXray for a while, so NXray now waits about "
        f"{minutes} minutes before contacting it again."
    )
    if not role.vlan_interfaces:
        words += _VLAN_INTERFACES_OFF
    return words


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
    turn_on_changes: str = Form(""),
    ssh_port: str = Form("22"),
) -> Response:
    require_csrf(request, csrf)
    settings = request.app.state.settings
    host = host.strip()
    account_name = account_name.strip()
    admin_user = admin_user.strip()
    turn_on = turn_on_changes == "yes"
    # Everything but the admin password goes back into the form on an error.
    add_form = {
        "host": host,
        "port": port.strip(),
        "account_name": account_name,
        "ssh_port": ssh_port.strip(),
        "turn_on_changes": "yes" if turn_on else "",
    }

    def fail(message: str) -> Response:
        return _render(request, username, error=message, add_form=add_form, status_code=400)

    port_number, problem = _check_address(host, port)
    if problem:
        return fail(problem)
    ssh_port_number = 0
    if turn_on:
        ssh_port_number, problem = _check_ssh_port(ssh_port)
        if problem:
            return fail(problem)
    if not admin_user or not admin_password:
        return fail("Enter the switch's admin username and password.")
    if confirm_save != "yes":
        return fail("Tick the box to confirm NXray may save the switch configuration.")

    added: list[int] = []
    role: EnableResult | None = None
    role_error = ""

    def store(password: str, switch_hostname: str) -> None:
        with open_db(settings.db_path) as conn:
            added.append(
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
            )

    if not _setup_lock.acquire(blocking=False):
        return fail("A setup is already running. Wait for it to finish, then reload this page.")
    try:
        with open_db(settings.db_path) as conn:
            if find_by_address(conn, host, port_number) is not None:
                return fail(
                    f"NXray already has the switch at {host}, port {port_number}. Pick it in "
                    "the switch list and use Run setup again to give its account a new login."
                )
        result = run_setup(
            host=host,
            port=port_number,
            admin_user=admin_user,
            admin_password=admin_password,
            account_name=account_name,
            store=store,
            transport=request.app.state.nxapi_transport,
        )
        # The account exists now; giving it the role uses the same admin
        # login, so a new switch needs it typed only once. A failure here
        # leaves the switch set up, read-only, with the Turn on button.
        if turn_on:
            try:
                role = enable_port_changes(
                    host=host,
                    nxapi_port=port_number,
                    ssh_port=ssh_port_number,
                    admin_user=admin_user,
                    admin_password=admin_password,
                    account_name=account_name,
                    transport=request.app.state.nxapi_transport,
                    ssh_opener=request.app.state.ssh_opener,
                )
            except SetupError as exc:
                role_error = str(exc)
    except SetupError as exc:
        return fail(str(exc))
    finally:
        _setup_lock.release()

    switch_id = added[0]
    with open_db(settings.db_path) as conn:
        set_config_saved(conn, switch_id, result.config_saved)
        record_test_result(
            conn, switch_id, ok=True, message="Setup signed in with the new account."
        )
        if role is not None:
            set_changes_enabled(
                conn,
                switch_id,
                pause_seconds=role.pause_seconds,
                role_version=ROLE_VERSION,
                vlan_interfaces=role.vlan_interfaces,
            )
    # The new switch is the one the pages show from now on.
    choose_switch(request, switch_id)
    note_activity(
        request,
        username,
        "Switch",
        f"Set up the switch {result.switch_hostname} with the account {account_name}",
        host,
    )
    if role is not None:
        note_activity(
            request,
            username,
            "Switch",
            f"Gave NXray's account the {ROLE_NAME} role, version {ROLE_VERSION}",
            host,
        )

    failed = not result.config_saved
    if result.config_saved:
        done = (
            f"Set up. NXray created the account {account_name} on {result.switch_hostname} "
            "and saved the switch configuration."
        )
    else:
        done = (
            f"NXray created the account {account_name} on {result.switch_hostname} and "
            "can use it, but saving the switch configuration failed, so the account is "
            "lost if the switch restarts. Run copy running-config startup-config on the "
            f"switch. Details: {result.save_error}"
        )
    if role is not None:
        done += _changes_on_at_setup(role)
        if not role.config_saved:
            failed = True
            done += (
                " Saving the switch configuration after giving the role failed, so the role "
                "is lost if the switch restarts. Run copy running-config startup-config on "
                f"the switch. Details: {role.save_error}"
            )
    elif role_error:
        failed = True
        done += (
            f" Turning changes on failed, so the account can only read for now: {role_error} "
            "Fix that, then turn them on below."
        )
    if failed:
        return remember_switch(request, _render(request, username, error=done))
    return remember_switch(request, _render(request, username, notice=done))


@router.post("/switch/test", response_class=HTMLResponse)
def switch_test(
    request: Request, username: str = Depends(admin_required), csrf: str = Form("")
) -> Response:
    require_csrf(request, csrf)
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        connection = get_connection(conn, selected_switch_id(request))
        if connection is None:
            return redirect("/switch")
        if waiting := connection.paused_seconds():
            return _render(request, username, error=paused_message(waiting))
        try:
            target = load_target(conn, connection.id, settings.secret_key)
        except LookupError:
            return redirect("/switch")
        except DecryptionError:
            record_test_result(conn, connection.id, ok=False, message=KEY_CHANGED_MESSAGE)
            return _render(request, username, error=KEY_CHANGED_MESSAGE)

    status = check_connection(target, transport=request.app.state.nxapi_transport)
    with open_db(settings.db_path) as conn:
        record_test_result(conn, connection.id, ok=status.ok, message=status.message)
        if status.system is not None:
            set_switch_identity(conn, connection, status.system)
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
        connection = get_connection(conn, selected_switch_id(request))
    if connection is None:
        return redirect("/switch")

    def fail(message: str) -> Response:
        return _render(request, username, error=message, form=form, status_code=400)

    port_number, problem = _check_address(host, port.strip())
    if problem:
        return fail(problem)
    if host == connection.host and port_number == connection.port:
        return fail("That is the address NXray already uses.")
    if (problem := _taken(request, connection.id, host, port_number)) is not None:
        return fail(problem)
    # Signing in now would keep the account's NX-API session alive, so the
    # switch would not apply the new role the pause is waiting for.
    if waiting := connection.paused_seconds():
        return fail(paused_message(waiting))
    with open_db(settings.db_path) as conn:
        try:
            target = load_target(conn, connection.id, settings.secret_key)
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
            set_address(
                conn,
                connection.id,
                host=host,
                port=port_number,
                switch_hostname=status.system.hostname,
            )
            record_test_result(conn, connection.id, ok=True, message=status.message)
            set_switch_identity(conn, connection, status.system)
    finally:
        _setup_lock.release()

    log.info("switch address changed from %s to %s", connection.host, host)
    note_activity(
        request,
        username,
        "Switch",
        f"Changed the switch address from {connection.host} to {host}",
        host,
    )
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
        connection = get_connection(conn, selected_switch_id(request))
    if connection is None:
        return redirect("/switch")

    def fail(message: str) -> Response:
        return _render(request, username, error=message, form=form, status_code=400)

    port_number, problem = _check_address(host, port.strip())
    if problem:
        return fail(problem)
    if (problem := _taken(request, connection.id, host, port_number)) is not None:
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
                connection.id,
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
        set_config_saved(conn, connection.id, result.config_saved)
        record_test_result(
            conn, connection.id, ok=True, message="Run setup again signed in with the new password."
        )
        if result.port_role == ROLE_GIVEN:
            set_changes_enabled(
                conn,
                connection.id,
                pause_seconds=result.pause_seconds,
                role_version=connection.role_version,
            )
        elif result.port_role == ROLE_MISSING:
            set_changes_off(conn, connection.id)

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
    note_activity(request, username, "Switch", f"Ran setup again for the account {name}", host)
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
        connection = get_connection(conn, selected_switch_id(request))
    if connection is None:
        return redirect("/switch")

    def fail(message: str) -> Response:
        return _render(request, username, error=message, status_code=400)

    ssh_port_number, problem = _check_ssh_port(ssh_port)
    if problem:
        return fail(problem)
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
            role_version=connection.role_version,
            vlan_interfaces_listed=connection.role_vlan_interfaces,
            transport=request.app.state.nxapi_transport,
            ssh_opener=request.app.state.ssh_opener,
        )
    except SetupError as exc:
        return fail(str(exc))
    finally:
        _setup_lock.release()

    with open_db(settings.db_path) as conn:
        set_changes_enabled(
            conn,
            connection.id,
            pause_seconds=result.pause_seconds,
            role_version=ROLE_VERSION,
            vlan_interfaces=result.vlan_interfaces,
        )
    note_activity(
        request,
        username,
        "Switch",
        f"Gave NXray's account the {ROLE_NAME} role, version {ROLE_VERSION}",
        connection.host,
    )
    account = connection.username
    count = result.port_count
    settings_words = (
        f"set the speed, MTU, FEC, flow control, storm control and layer (switched or "
        f"routed) of the {count} front ports, and split or join the 100G ports"
    )
    features_words = "turn switch features on and off on the Features page"
    neighbor_words = (
        "turn CDP and LLDP on or off on the front ports, set how long learned MAC "
        "addresses are kept, add and remove static MAC addresses and clear learned ones"
    )
    channel_words = (
        "make, change and delete port-channels and set their LACP options on the Port-channels page"
    )
    layer3_words = (
        "make, change and delete VLAN interfaces and put IPv4 and IPv6 addresses on them and "
        "on routed ports on the Routing page"
    )
    vrf_words = (
        "make and delete VRFs and move VLAN interfaces and routed ports between them on the "
        "Routing page"
    )
    route_words = "add and remove static routes on the Routing page"
    protocol_words = (
        "run the routing protocols and change their settings, route-maps, prefix-lists and key "
        "chains on the Routing protocols page"
    )
    stp_words = (
        "change spanning tree for the whole switch, each VLAN, the MST region and each port on "
        "the Spanning tree page"
    )
    admin_words = (
        "change the switch's hostname, banner, clock, NTP, DNS, logging and SNMP settings and "
        "read its configuration on the Switch admin page"
    )
    security_words = (
        "make and delete IPv4 and IPv6 ACLs and apply them on the ACLs page, set port security "
        "on the Port security page, and read the saved configuration and keep checkpoints for "
        "backups on the Config page"
    )
    layer2_words = (
        "set DHCP snooping, the DHCP relay, ARP inspection and IP Source Guard on the DHCP and "
        "ARP page, and make MAC ACLs, object groups and VLAN access maps and size the TCAM "
        "regions on the ACLs page"
    )
    traffic_words = (
        "set how long the front ports average their In and Out rates over on each port's page, "
        "and have the switch send sFlow samples to NXray on the Traffic page"
    )
    reset_words = (
        "put a port or a port-channel back to how it came out of the box, on its own page or "
        "the Port-channels page"
    )
    if not result.had_role:
        minutes = result.pause_seconds // 60
        done = (
            "Port, VLAN, port settings, feature, neighbor, port-channel, VLAN interface, VRF, "
            "static route, routing protocol, spanning tree, switch admin, security and config, "
            "layer 2 security, traffic measuring and reset to defaults changes are on: "
            f"{account} may now turn the {count} front ports on or off, edit their "
            "descriptions, set their VLANs and their speed, MTU, FEC, flow control, storm "
            "control and layer (switched or routed), split or join the 100G ports, create, "
            f"rename and delete VLANs, {features_words}, {neighbor_words}, {channel_words}, "
            f"{layer3_words}, {vrf_words}, {route_words}, {protocol_words}, {stp_words}, "
            f"{admin_words}, {security_words}, {layer2_words}, {traffic_words}, and "
            f"{reset_words}. "
            "The switch applies this once it has not heard from NXray for a while, so NXray "
            f"now waits about {minutes} minutes before contacting it again."
        )
    elif connection.role_version >= ROLE_VERSION:
        vlans = (
            " and the VLAN interfaces"
            if result.vlan_interfaces and not connection.role_vlan_interfaces
            else ""
        )
        done = (
            f"The port list is updated: NXray's role now names the {count} front ports the "
            f"switch has now{vlans}. The switch applies this at once, so there is no wait."
        )
    else:
        parts = []
        if connection.role_version < 2:
            parts.append("create, rename and delete VLANs, set the VLANs of the front ports")
        if connection.role_version < 3:
            parts.append(settings_words)
        if connection.role_version < 4:
            parts.append(features_words)
        if connection.role_version < 5:
            parts.append(neighbor_words)
        if connection.role_version < 6:
            parts.append(channel_words)
        if connection.role_version < 7:
            parts.append(layer3_words)
        if connection.role_version < 8:
            parts.append(vrf_words)
        if connection.role_version < 9:
            parts.append(route_words)
        if connection.role_version < 10:
            parts.append(protocol_words)
        if connection.role_version < 11:
            parts.append(stp_words)
        if connection.role_version < 12:
            parts.append(admin_words)
        if connection.role_version < 13:
            parts.append(security_words)
        if connection.role_version < 14:
            parts.append(layer2_words)
        if connection.role_version < 15:
            parts.append(traffic_words)
        parts.append(reset_words)
        allowed = parts[0] if len(parts) == 1 else f"{', '.join(parts[:-1])}, and {parts[-1]}"
        kinds = missing_changes(connection.role_version)
        done = (
            f"{kinds[:1].upper()}{kinds[1:]} are on: {account} may now also {allowed}. "
            "The switch applies this at once, so there is no wait."
        )
    if not result.vlan_interfaces:
        done += _VLAN_INTERFACES_OFF
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
    protocol: str = Form(""),
    show: str = Form(""),
    color: str = Form(""),
) -> Response:
    """Save config: copy running-config startup-config with NXray's own account.

    ``back`` names the page the button was on (``port`` with ``port`` set,
    ``ports``, ``vlans``, ``features``, ``neighbors``, ``port-channels``, ``routing``,
    ``protocols``, ``protocol`` with ``protocol`` set to a protocol page's key, ``spanning-tree``,
    ``switch-admin``, ``acls``, ``port-security``, ``dhcp`` or ``config``); the answer is
    shown there. From the Ports page, ``show``, ``color`` and ``port`` keep its
    filter, colour mode and open side panel.
    Anything else means the
    Switch page, so the field can never send the browser elsewhere.
    """
    require_csrf(request, csrf)

    def answer(*, error: str | None = None, notice: str | None = None) -> Response:
        if back == "port" and port:
            return render_port_page(request, username, port, error=error, notice=notice)
        if back == "ports":
            origin = ports_origin(back, show, color)
            assert origin is not None
            return render_ports_page(
                request,
                username,
                show=origin.show,
                color=origin.color,
                selected=port,
                error=error,
                notice=notice,
            )
        if back == "vlans":
            return render_vlans_page(request, username, error=error, notice=notice)
        if back == "traffic":
            return render_traffic_page(request, username, error=error, notice=notice)
        if back == "features":
            return render_features_page(request, username, error=error, notice=notice)
        if back == "neighbors":
            return render_neighbors_page(request, username, error=error, notice=notice)
        if back == "port-channels":
            return render_port_channels_page(request, username, error=error, notice=notice)
        if back == "routing":
            return render_routing_page(request, username, error=error, notice=notice)
        if back == "protocols":
            return render_protocols_page(request, username, error=error, notice=notice)
        if back == "protocol" and find_protocol(protocol) is not None:
            return render_protocol_page(request, username, protocol, error=error, notice=notice)
        if back == "spanning-tree":
            return render_spanning_tree_page(request, username, error=error, notice=notice)
        if back == "switch-admin":
            return render_switch_admin_page(request, username, error=error, notice=notice)
        if back == "acls":
            return render_acls_page(request, username, error=error, notice=notice)
        if back == "port-security":
            return render_port_security_page(request, username, error=error, notice=notice)
        if back == "dhcp":
            return render_dhcp_page(request, username, error=error, notice=notice)
        if back == "config" and current_role(request) == "admin":
            return render_config_page(request, username, error=error, notice=notice)
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
        set_unsaved_changes(conn, connection.id, False)
    log.info("saved the switch configuration on %s", connection.host)
    note_activity(request, username, "Switch", "Saved the configuration", connection.host)
    return answer(notice="Saved: the switch keeps its current configuration on restart.")


@router.post("/switch/forget", response_class=HTMLResponse)
def switch_forget(
    request: Request, username: str = Depends(admin_required), csrf: str = Form("")
) -> Response:
    require_csrf(request, csrf)
    settings = request.app.state.settings
    with open_db(settings.db_path) as conn:
        connection = get_connection(conn, selected_switch_id(request))
        if connection is None:
            return redirect("/switch")
        # Its history, port labels, backups and open problems go with it.
        delete_connection(conn, connection.id)
    log.info("forgot the switch %s (account %s)", connection.host, connection.username)
    note_activity(
        request,
        username,
        "Switch",
        f"Forgot the switch {connection.switch_hostname}",
        connection.host,
    )
    with open_db(settings.db_path) as conn:
        choose_switch(request, resolve_switch_id(conn, None))
    notice = (
        f"NXray forgot the switch {connection.switch_hostname}, with its history, port "
        f"labels, config backups and open alerts. The account {connection.username} is "
        "still on the switch; the help below says how to remove it."
    )
    response = _render(request, username, notice=notice)
    return remember_switch(request, response)


def _taken(request: Request, switch_id: int, host: str, port: int) -> str | None:
    """Why another switch already stored at ``host`` and ``port`` stops this one
    moving there; None when none is."""
    with open_db(request.app.state.settings.db_path) as conn:
        other = find_by_address(conn, host, port)
        found = get_connection(conn, other) if other not in (None, switch_id) else None
    if found is None:
        return None
    return (
        f"NXray already has another switch at {host}, port {port}: "
        f"{found.switch_hostname}. Forget one of them first."
    )


@router.post("/switches/select")
def switches_select(
    request: Request,
    username: str = Depends(login_required),
    csrf: str = Form(""),
    switch_id: str = Form(""),
    next: str = Form("/"),
) -> Response:
    """The top bar's switch picker: show ``switch_id`` on every page from now on.

    Changes nothing on a switch, so it takes a form shown for any switch; a
    page that changes one still refuses a form shown for another.
    """
    with open_db(request.app.state.settings.db_path) as conn:
        known = [connection.id for connection in list_connections(conn)]
    if not csrf_valid_any_switch(request, csrf, known):
        raise CsrfFailed()
    wanted = int(switch_id) if switch_id.isdigit() and len(switch_id) < 10 else None
    if wanted not in known:
        return redirect(safe_next(next))
    choose_switch(request, wanted)
    log.info("%s now looks at switch %s", username, wanted)
    return remember_switch(request, redirect(safe_next(next)))
