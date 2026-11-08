"""The Config page: backups of the switch's configuration, comparing two
configurations, and rolling back to a backup. Admins only: a configuration
holds every setting of the switch, SNMP communities included.

``GET /config`` shows the backups and what differs between the running and the
saved configuration; ``?a=&b=`` compares two of running, ``startup`` and
``backup-<n>``. ``POST /config/backup`` takes a backup, ``POST
/config/backup/delete`` deletes one (after a confirm page), ``GET
/config/backup/<n>.txt`` downloads one, and ``POST /config/rollback`` rolls the
switch back to one, after a confirm page that shows what changes and asks for
the switch admin login (used once, never stored). ``POST /config/reload``
restarts the switch, saving its configuration first when asked, after a confirm
page that asks for the switch admin login and SSH port (used once, never
stored).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, Response

from app.config_tools import (
    NOTE_MAX,
    Backup,
    SwitchConfigs,
    checkpoint_name,
    config_diff,
    delete_backup,
    diff_counts,
    get_backup,
    list_backups,
    load_configs,
    load_running,
    set_backup_checkpoint,
    store_backup,
    validate_note,
)
from app.db import open_db
from app.dependencies import (
    admin_required,
    note_activity,
    require_csrf,
    stored_switch,
    templates,
)
from app.nxapi import NxapiClient, NxapiError, SwitchTarget
from app.port_changes import SSH_TIMEOUT
from app.security import csrf_token
from app.switch_choice import selected_switch_id
from app.switch_connection import SWITCH_TIMEOUT, SwitchConnection, set_unsaved_changes
from app.switch_setup import connection_error, read_switch
from app.switch_ssh import SshAuthError, SshCommandError, SshError, reload_switch

router = APIRouter()
log = logging.getLogger("nxray.config")

ROLLBACK_WARNING = (
    "The whole running configuration becomes the backup's: every change made since, "
    "through NXray or not, is undone, and connections that depend on it may drop. "
    "NXray first takes a backup of the configuration it replaces, so this can be undone "
    "the same way."
)


RELOAD_WARNING = (
    "The switch restarts: every port goes down and all traffic through it stops for "
    "several minutes, NXray included, until it is back. "
    "TCAM region sizes set since the last restart take effect."
)


def _backup_id(value: str) -> int | None:
    return int(value) if value.isascii() and value.isdigit() and len(value) <= 9 else None


def _label(name: str, backups: dict[int, Backup]) -> str | None:
    """'running', 'startup' or 'backup-<n>' in words; None when unknown."""
    if name == "running":
        return "the running configuration"
    if name == "startup":
        return "the saved configuration"
    number = _backup_id(name.removeprefix("backup-")) if name.startswith("backup-") else None
    backup = backups.get(number) if number is not None else None
    if backup is None:
        return None
    return f"backup {backup.id}" + (f" ({backup.note})" if backup.note else "")


def _text(name: str, configs: SwitchConfigs | None, request: Request) -> str | None:
    if name == "running":
        return configs.running if configs else None
    if name == "startup":
        return configs.startup if configs else None
    number = _backup_id(name.removeprefix("backup-"))
    if number is None:
        return None
    with open_db(request.app.state.settings.db_path) as conn:
        found = get_backup(conn, selected_switch_id(request), number)
    return found[1] if found else None


def render_config_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    a: str = "",
    b: str = "",
) -> Response:
    """Read the switch fresh and show the Config page, with a message, comparing
    ``a`` with ``b`` when both are given."""
    connection, target, problem = stored_switch(request)
    with open_db(request.app.state.settings.db_path) as conn:
        backups = list_backups(conn, selected_switch_id(request))
    status = configs = None
    if target is not None:
        status, configs = read_switch(
            target, load_configs, transport=request.app.state.nxapi_transport
        )
    by_id = {backup.id: backup for backup in backups}
    unsaved = None
    if configs is not None and configs.startup is not None:
        unsaved = config_diff(configs.startup, configs.running)
    compare = None
    if a and b:
        first, second = _label(a, by_id), _label(b, by_id)
        text_a, text_b = _text(a, configs, request), _text(b, configs, request)
        if first is None or second is None or text_a is None or text_b is None:
            error = error or "Cannot compare: pick two configurations NXray can read."
        else:
            diff = config_diff(text_a, text_b)
            compare = {"a": first, "b": second, "diff": diff, "counts": diff_counts(diff)}
    return templates.TemplateResponse(
        request,
        "config.html",
        {
            "username": username,
            "connection": connection,
            "status": status,
            "problem": problem,
            "configs": configs,
            "backups": backups,
            "unsaved": unsaved,
            "unsaved_counts": diff_counts(unsaved) if unsaved is not None else None,
            "compare": compare,
            "a": a,
            "b": b,
            "error": error,
            "notice": notice,
            "note_max": NOTE_MAX,
            "csrf_token": csrf_token(request),
        },
        status_code=400 if error else 200,
    )


@router.get("/config", response_class=HTMLResponse)
def config_page(
    request: Request, username: str = Depends(admin_required), a: str = "", b: str = ""
) -> Response:
    """``GET /config?a=&b=``: the backups and the unsaved changes; with ``a`` and ``b``
    (``running``, ``startup`` or ``backup-<n>``), what differs between them."""
    return render_config_page(request, username, a=a[:20], b=b[:20])


@router.get("/config/backup/{number}.txt")
def config_download(
    number: int, request: Request, username: str = Depends(admin_required)
) -> Response:
    """``GET /config/backup/<n>.txt``: one backup's configuration as a text file."""
    with open_db(request.app.state.settings.db_path) as conn:
        found = get_backup(conn, selected_switch_id(request), number)
    if found is None:
        return render_config_page(request, username, error=f"There is no backup {number}.")
    backup, text = found
    return Response(
        text,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="nxray-backup-{backup.id}.txt"'},
    )


def _take_backup(
    request: Request,
    username: str,
    connection: SwitchConnection,
    target: SwitchTarget,
    note: str,
) -> tuple[int | None, str]:
    """Read the running configuration, store it, and make the checkpoint that goes
    with it when NXray's role allows. (backup number or None, a message)."""
    transport = request.app.state.nxapi_transport
    status, running = read_switch(target, load_running, transport=transport)
    if running is None:
        return None, f"No backup taken: {status.message}"
    with open_db(request.app.state.settings.db_path) as conn:
        number = store_backup(
            conn,
            connection.id,
            config=running,
            created_by=username,
            switch=connection.host,
            note=note,
        )
    if not connection.security_changes_enabled:
        return number, (
            f"Backup {number} is stored in NXray. The switch made no checkpoint for it, so it "
            "cannot be rolled back to: security and config changes are off on the Switch page."
        )
    name = checkpoint_name(number)
    try:
        with NxapiClient(target, transport=transport) as client:
            client.create_checkpoint(name)
    except NxapiError as exc:
        log.warning("checkpoint %s refused: %s", name, exc)
        return number, (
            f"Backup {number} is stored in NXray, but the switch made no checkpoint for it, so "
            f"it cannot be rolled back to: {connection_error(exc, target)}"
        )
    with open_db(request.app.state.settings.db_path) as conn:
        set_backup_checkpoint(conn, selected_switch_id(request), number, name)
    return number, f"Backup {number} is stored in NXray, and the switch keeps it as {name}."


@router.post("/config/backup", response_class=HTMLResponse)
def config_backup(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    note: str = Form(""),
) -> Response:
    """Take a backup of the running configuration now."""
    require_csrf(request, csrf)
    try:
        note = validate_note(note)
    except ValueError as exc:
        return render_config_page(request, username, error=f"No backup taken: {exc}.")
    connection, target, problem = stored_switch(request)
    if connection is None or target is None:
        return render_config_page(request, username, error=problem or "No switch is set up yet.")
    number, message = _take_backup(request, username, connection, target, note)
    if number is None:
        return render_config_page(request, username, error=message)
    note_activity(
        request,
        username,
        "Config",
        f"Took backup {number}" + (f" ({note})" if note else ""),
        connection.host,
    )
    return render_config_page(request, username, notice=f"Done: {message}")


def _confirm(request: Request, username: str, lines: list[str], fields: dict[str, str]) -> Response:
    return templates.TemplateResponse(
        request,
        "confirm.html",
        {
            "username": username,
            "title": "Config",
            "back_url": "/config",
            "back_label": "Config",
            "lines": lines,
            "warnings": [],
            "action": "/config/backup/delete",
            "fields": fields,
            "csrf_token": csrf_token(request),
            "not_config": True,
        },
    )


@router.post("/config/backup/delete", response_class=HTMLResponse)
def config_backup_delete(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    id: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Delete a backup, and its checkpoint on the switch. Without confirm=yes, asks."""
    require_csrf(request, csrf)
    number = _backup_id(id)
    with open_db(request.app.state.settings.db_path) as conn:
        found = (
            get_backup(conn, selected_switch_id(request), number) if number is not None else None
        )
    if found is None:
        return render_config_page(request, username, error="Not deleted: there is no such backup.")
    backup = found[0]
    if confirm != "yes":
        lines = [f"Delete backup {backup.id} from NXray?"]
        if backup.checkpoint:
            lines.append(f"The switch's checkpoint {backup.checkpoint} is deleted too.")
        return _confirm(request, username, lines, {"id": str(backup.id)})
    connection, target, problem = stored_switch(request)
    if backup.checkpoint:
        if connection is None or target is None:
            return render_config_page(
                request,
                username,
                error=f"Not deleted: {problem or 'no switch is set up'}; the switch's "
                f"checkpoint {backup.checkpoint} would stay behind.",
            )
        transport = request.app.state.nxapi_transport
        status, configs = read_switch(target, load_configs, transport=transport)
        if configs is None:
            return render_config_page(request, username, error=f"Not deleted: {status.message}")
        if configs.checkpoints and backup.checkpoint in configs.checkpoints:
            try:
                with NxapiClient(target, transport=transport) as client:
                    client.delete_checkpoint(backup.checkpoint)
            except NxapiError as exc:
                return render_config_page(
                    request,
                    username,
                    error=f"Not deleted: the switch kept its checkpoint "
                    f"{backup.checkpoint}: {connection_error(exc, target)}",
                )
    with open_db(request.app.state.settings.db_path) as conn:
        delete_backup(conn, selected_switch_id(request), backup.id)
    note_activity(
        request,
        username,
        "Config",
        f"Deleted backup {backup.id}"
        + (f" and checkpoint {backup.checkpoint}" if backup.checkpoint else ""),
        connection.host if connection else "",
    )
    return render_config_page(request, username, notice=f"Done: backup {backup.id} is deleted.")


def _rollback_form(
    request: Request,
    username: str,
    backup: Backup,
    diff: list,
    *,
    admin_user: str = "",
    error: str | None = None,
) -> Response:
    return templates.TemplateResponse(
        request,
        "config_rollback.html",
        {
            "username": username,
            "backup": backup,
            "diff": diff,
            "counts": diff_counts(diff),
            "warning": ROLLBACK_WARNING,
            "admin_user": admin_user,
            "error": error,
            "csrf_token": csrf_token(request),
        },
        status_code=400 if error else 200,
    )


@router.post("/config/rollback", response_class=HTMLResponse)
def config_rollback(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    id: str = Form(""),
    admin_user: str = Form(""),
    admin_password: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Roll the switch back to a backup's checkpoint. Without confirm=yes, shows what
    changes and asks for the switch admin login."""
    require_csrf(request, csrf)
    number = _backup_id(id)
    with open_db(request.app.state.settings.db_path) as conn:
        found = (
            get_backup(conn, selected_switch_id(request), number) if number is not None else None
        )
    if found is None:
        return render_config_page(
            request, username, error="Not rolled back: there is no such backup."
        )
    backup, text = found
    connection, target, problem = stored_switch(request)
    if connection is None or target is None:
        return render_config_page(
            request, username, error=f"Not rolled back: {problem or 'no switch is set up'}."
        )
    if not connection.security_changes_enabled:
        return render_config_page(
            request,
            username,
            error="Not rolled back: security and config changes are off. Turn them on on the "
            "Switch page first.",
        )
    transport = request.app.state.nxapi_transport
    status, configs = read_switch(target, load_configs, transport=transport)
    if configs is None:
        return render_config_page(request, username, error=f"Not rolled back: {status.message}")
    if (
        not backup.checkpoint
        or configs.checkpoints is None
        or backup.checkpoint not in configs.checkpoints
    ):
        return render_config_page(
            request,
            username,
            error=f"Not rolled back: the switch has no checkpoint for backup {backup.id} (it "
            "loses them when its configuration is erased). Its text can still be downloaded.",
        )
    diff = config_diff(configs.running, text)
    if confirm != "yes":
        return _rollback_form(request, username, backup, diff)
    admin_user = admin_user.strip()
    if not admin_user or not admin_password:
        return _rollback_form(
            request,
            username,
            backup,
            diff,
            admin_user=admin_user,
            error="Enter the switch's admin username and password.",
        )

    before, message = _take_backup(
        request, username, connection, target, f"before rolling back to backup {backup.id}"
    )
    if before is None:
        return render_config_page(request, username, error=f"Not rolled back: {message}")
    admin = SwitchTarget(
        host=connection.host,
        port=connection.port,
        username=admin_user,
        password=admin_password,
        timeout=SWITCH_TIMEOUT,
    )
    try:
        with NxapiClient(admin, transport=transport) as client:
            client.rollback_to_checkpoint(backup.checkpoint)
    except NxapiError as exc:
        refused = connection_error(exc, admin).replace(admin_password, "***")
        log.warning("rollback to %s refused: %s", backup.checkpoint, refused)
        return render_config_page(
            request,
            username,
            error=f"Not rolled back: {refused} The switch rolls back all or nothing, so its "
            f"configuration is as it was. ({message})",
        )
    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, selected_switch_id(request), True)
    log.info("rolled %s back to %s by %s", connection.host, backup.checkpoint, username)
    note_activity(
        request,
        username,
        "Config",
        f"Rolled the switch back to backup {backup.id} ({backup.checkpoint}); the configuration "
        f"before is backup {before}",
        connection.host,
    )
    return render_config_page(
        request,
        username,
        notice=f"Done: the switch is rolled back to backup {backup.id}. The configuration it "
        f"replaced is backup {before}. Not saved yet: Save config keeps it over a restart of "
        "the switch.",
    )


def _reload_form(
    request: Request,
    username: str,
    unsaved: int | None,
    *,
    admin_user: str = "",
    ssh_port: str = "22",
    save: bool = True,
    error: str | None = None,
    needs_login: bool = True,
) -> Response:
    return templates.TemplateResponse(
        request,
        "config_reload.html",
        {
            "username": username,
            "unsaved": unsaved,
            "needs_login": needs_login,
            "warning": RELOAD_WARNING,
            "admin_user": admin_user,
            "ssh_port": ssh_port,
            "save": save,
            "error": error,
            "csrf_token": csrf_token(request),
        },
        status_code=400 if error else 200,
    )


@router.post("/config/reload", response_class=HTMLResponse)
def config_reload(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    admin_user: str = Form(""),
    admin_password: str = Form(""),
    ssh_port: str = Form("22"),
    save: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Restart the switch. Without confirm=yes, shows what is not saved and asks for
    the switch admin login; with ``save``, saves the configuration first."""
    require_csrf(request, csrf)
    connection, target, problem = stored_switch(request)
    if connection is None or target is None:
        return render_config_page(
            request, username, error=f"Not restarted: {problem or 'no switch is set up'}."
        )
    transport = request.app.state.nxapi_transport
    status, configs = read_switch(target, load_configs, transport=transport)
    unsaved = None
    if configs is not None and configs.startup is not None:
        unsaved = sum(diff_counts(config_diff(configs.startup, configs.running)))
    own_restart = connection.can_restart
    if confirm != "yes":
        if own_restart and unsaved == 0:
            # Nothing to save and no login to ask for: restart at once.
            confirm = "yes"
        else:
            return _reload_form(request, username, unsaved, needs_login=not own_restart)
    admin_user = admin_user.strip()
    keep = save == "yes"

    def again(message: str) -> Response:
        return _reload_form(
            request,
            username,
            unsaved,
            admin_user=admin_user,
            ssh_port=ssh_port,
            save=keep,
            error=message,
            needs_login=not own_restart,
        )

    port = 22
    if not own_restart:
        if not admin_user or not admin_password:
            return again("Enter the switch's admin username and password.")
        port = int(ssh_port) if ssh_port.isascii() and ssh_port.isdigit() else 0
        if not 1 <= port <= 65535:
            return again("The SSH port is a number from 1 to 65535.")
    if keep:
        try:
            with NxapiClient(target, transport=transport) as client:
                client.save_config()
        except NxapiError as exc:
            return again(
                f"Not restarted: the configuration could not be saved first: "
                f"{connection_error(exc, target)}"
            )
        with open_db(request.app.state.settings.db_path) as conn:
            set_unsaved_changes(conn, selected_switch_id(request), False)
    if own_restart:
        try:
            with NxapiClient(target, transport=transport) as client:
                client.reload_switch()
        except NxapiError as exc:
            return again(f"Not restarted: {connection_error(exc, target)}")
    else:
        try:
            reload_switch(
                host=connection.host,
                port=port,
                username=admin_user,
                password=admin_password,
                timeout=SSH_TIMEOUT,
                opener=request.app.state.ssh_opener,
            )
        except SshAuthError:
            return again("Not restarted: the switch refused that admin username or password.")
        except SshCommandError as exc:
            message = str(exc).replace(admin_password, "***")
            log.warning("reload refused: %s", message)
            return again(f"Not restarted: the switch refused it: {message}")
        except SshError as exc:
            message = str(exc).replace(admin_password, "***")
            return again(f"Not restarted: {message}")
    log.info("restarted %s by %s", connection.host, username)
    note_activity(
        request,
        username,
        "Config",
        "Restarted the switch" + (", after saving its configuration" if keep else ""),
        connection.host,
    )
    return render_config_page(
        request,
        username,
        notice="Done: the switch is restarting"
        + (", with its configuration saved first" if keep else "")
        + ". It answers again in several minutes; until then NXray cannot reach it.",
    )
