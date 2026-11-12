"""The Files, Software and Tech support pages (``app/switch_files.py``).

Every role looks. Only an NXray admin copies, deletes, checks, installs or collects, and
only with the stored admin login: SCP, the slow commands and ``delete`` sign in as that
account. Copying a file to the switch, a checksum, the install check, the install and
tech-support run as background jobs (``app/switch_jobs.py``); their page reloads itself
until the job ends.
"""

from __future__ import annotations

import dataclasses
import logging
import time
from collections.abc import Callable, Iterator
from typing import Any

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, Response, StreamingResponse

from app.dependencies import (
    admin_required,
    current_role,
    login_required,
    note_activity,
    require_csrf,
    stored_switch,
    templates,
)
from app.nxapi import NxapiClient, NxapiError
from app.port_changes import SSH_TIMEOUT
from app.routes.ports import change_refused
from app.routes.protocols import NO_ADMIN_LOGIN, admin_login, reading_target
from app.security import csrf_token
from app.switch_connection import SwitchConnection
from app.switch_files import (
    FILESYSTEM,
    check_delete,
    check_image,
    check_upload,
    checksum_word,
    checksum_work,
    impact_work,
    install_work,
    load_files_page,
    load_software_page,
    ready_to_install,
    save_upload,
    tech_file,
    tech_path,
    tech_work,
    upload_work,
)
from app.switch_jobs import JobBusy
from app.switch_setup import read_switch, scrub_secrets
from app.switch_ssh import Session, SshError, open_paramiko_session

router = APIRouter()
log = logging.getLogger("nxray.files")

FILE_CHANGES_OFF = (
    "Copying, deleting and installing files, and collecting tech-support, need the stored "
    "admin login: they sign in to the switch as that account. An NXray admin picks Limited "
    "role, and store the switch admin login, on the Switch page."
)
SCP_OFF = (
    "Copying files to and from the switch needs its SCP server: turn on scp-server on the "
    "Features page."
)
_BUSY = "{what} is still running; wait until it ends."


def _jobs(request: Request) -> Any:
    return request.app.state.jobs


def _can_change(request: Request, connection: SwitchConnection | None) -> bool:
    return (
        connection is not None
        and connection.file_changes_enabled
        and current_role(request) == "admin"
    )


def _session_opener(
    request: Request, connection: SwitchConnection
) -> tuple[Callable[[], Session] | None, str]:
    """A way to open an SSH session with the stored admin login, or why there is none."""
    if not connection.file_changes_enabled:
        return None, FILE_CHANGES_OFF
    login = admin_login(request, connection)
    if login is None:
        return None, NO_ADMIN_LOGIN[0].upper() + NO_ADMIN_LOGIN[1:]
    user, password, port = login
    opener = request.app.state.ssh_session_opener or open_paramiko_session

    def session() -> Session:
        return opener(connection.host, port, user, password, SSH_TIMEOUT)

    return session, ""


def _render(
    request: Request,
    username: str,
    template: str,
    loader: Callable[[NxapiClient], Any] | None,
    extra: dict[str, Any],
    *,
    error: str | None = None,
    notice: str | None = None,
) -> Response:
    connection, target, problem = stored_switch(request)
    status = page = None
    if target is not None and loader is not None:
        status, page = read_switch(
            reading_target(request, connection, target),
            loader,
            transport=request.app.state.nxapi_transport,
        )
    jobs = {
        kind: _jobs(request).get(connection.id, kind) if connection else None
        for kind in ("upload", "checksum", "impact", "install", "techsupport")
    }
    return templates.TemplateResponse(
        request,
        template,
        {
            "username": username,
            "connection": connection,
            "status": status,
            "problem": problem,
            "page": page,
            "jobs": jobs,
            "running": any(job is not None and job.running for job in jobs.values()),
            "error": error,
            "notice": notice,
            "csrf_token": csrf_token(request),
            "can_change": _can_change(request, connection),
            "changes_off": FILE_CHANGES_OFF,
            **extra,
        },
        status_code=400 if error else 200,
    )


def _start(
    request: Request,
    connection: SwitchConnection,
    kind: str,
    subject: str,
    username: str,
    work: Callable[..., str],
) -> str | None:
    """Start a job; None, or why it did not start."""
    try:
        _jobs(request).start(connection.id, kind, subject, username, work)
    except JobBusy:
        return _BUSY.format(
            what={"upload": "A copy", "techsupport": "Tech-support"}.get(kind, "A check or install")
        )
    return None


# ---- Files ----------------------------------------------------------------------------------


def render_files_page(
    request: Request, username: str, *, error: str | None = None, notice: str | None = None
) -> Response:
    """Read the switch fresh and show the Files page, with a message."""
    return _render(
        request,
        username,
        "files.html",
        load_files_page,
        {"scp_off": SCP_OFF},
        error=error,
        notice=notice,
    )


@router.get("/files", response_class=HTMLResponse)
def files_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /files``: the files on bootflash and the space left; every role looks."""
    return render_files_page(request, username)


@router.post("/files/delete", response_class=HTMLResponse)
def files_delete(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    name: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Delete one file from bootflash. Without confirm=yes, asks first."""
    require_csrf(request, csrf)
    connection, target, problem = stored_switch(request)
    if connection is None or target is None:
        return render_files_page(request, username, error=problem or "No switch is set up yet.")
    if not connection.file_changes_enabled:
        return render_files_page(request, username, error=FILE_CHANGES_OFF)
    status, page = read_switch(
        reading_target(request, connection, target),
        load_files_page,
        transport=request.app.state.nxapi_transport,
    )
    if page is None:
        return render_files_page(request, username, error=status.message)
    try:
        check_delete(page, name)
    except ValueError as exc:
        return render_files_page(request, username, error=f"Not deleted: {exc}.")
    if confirm != "yes":
        return templates.TemplateResponse(
            request,
            "confirm.html",
            {
                "username": username,
                "title": "Files",
                "back_url": "/files",
                "back_label": "Files",
                "lines": [
                    f"Files: delete {name} ({page.listing.size_of(name)} bytes) from bootflash.",
                    "The switch gets these lines:",
                    f"delete {FILESYSTEM}{name} no-prompt",
                ],
                "warnings": ["A deleted file cannot be brought back."],
                "action": "/files/delete",
                "fields": {"name": name},
                "csrf_token": csrf_token(request),
                "not_config": True,
            },
        )
    login = admin_login(request, connection)
    if login is None:
        return render_files_page(request, username, error=f"Not deleted: {NO_ADMIN_LOGIN}")
    sender = dataclasses.replace(target, username=login[0], password=login[1])
    try:
        with NxapiClient(sender, transport=request.app.state.nxapi_transport) as client:
            client.delete_file(name)
    except NxapiError as exc:
        refused = scrub_secrets(change_refused(exc, target), login[1])
        return render_files_page(request, username, error=f"Not deleted: {refused}")
    note_activity(request, username, "Files", f"Deleted {name} from bootflash", connection.host)
    return render_files_page(request, username, notice=f"Done: {name} is deleted from bootflash.")


@router.post("/files/upload", response_class=HTMLResponse)
def files_upload(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    upload: UploadFile = File(...),  # noqa: B008 - FastAPI's way of naming a file field
) -> Response:
    """Copy a file from this computer to bootflash, as a background job."""
    require_csrf(request, csrf)
    connection, target, problem = stored_switch(request)
    if connection is None or target is None:
        return render_files_page(request, username, error=problem or "No switch is set up yet.")
    session, why = _session_opener(request, connection)
    if session is None:
        return render_files_page(request, username, error=f"Not copied: {why}")
    status, page = read_switch(
        reading_target(request, connection, target),
        load_files_page,
        transport=request.app.state.nxapi_transport,
    )
    if page is None:
        return render_files_page(request, username, error=status.message)
    if not page.scp_on:
        return render_files_page(request, username, error=f"Not copied: {SCP_OFF}")
    name = (upload.filename or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    size = upload.size or 0
    try:
        check_upload(page, name, size)
    except ValueError as exc:
        return render_files_page(request, username, error=f"Not copied: {exc}.")
    local, size = save_upload(upload.file, request.app.state.settings.data_dir)
    try:
        check_upload(page, name, size)
    except ValueError as exc:
        local.unlink(missing_ok=True)
        return render_files_page(request, username, error=f"Not copied: {exc}.")
    busy = _start(
        request, connection, "upload", name, username, upload_work(session, local, size, name)
    )
    if busy:
        local.unlink(missing_ok=True)
        return render_files_page(request, username, error=f"Not copied: {busy}")
    note_activity(
        request, username, "Files", f"Started copying {name} to bootflash", connection.host
    )
    return render_files_page(request, username, notice=f"Copying {name} to bootflash.")


@router.get("/files/download")
def files_download(
    request: Request, name: str = "", username: str = Depends(admin_required)
) -> Response:
    """Copy one file off bootflash to this computer."""
    connection, target, problem = stored_switch(request)
    if connection is None or target is None:
        return render_files_page(request, username, error=problem or "No switch is set up yet.")
    session, why = _session_opener(request, connection)
    if session is None:
        return render_files_page(request, username, error=f"Not copied: {why}")
    status, page = read_switch(
        reading_target(request, connection, target),
        load_files_page,
        transport=request.app.state.nxapi_transport,
    )
    if page is None:
        return render_files_page(request, username, error=status.message)
    if not page.scp_on:
        return render_files_page(request, username, error=f"Not copied: {SCP_OFF}")
    if not page.listing.has(name):
        return render_files_page(
            request, username, error=f"Not copied: bootflash has no file {name!r}."
        )
    try:
        ssh = session()
    except SshError as exc:
        return render_files_page(request, username, error=f"Not copied: {exc}")
    try:
        size, chunks = ssh.download(f"{FILESYSTEM}{name}")
    except SshError as exc:
        ssh.close()
        return render_files_page(request, username, error=f"Not copied: {exc}")

    def body() -> Iterator[bytes]:
        try:
            yield from chunks
        finally:
            ssh.close()

    log.info("%s copied %s off %s", username, name, connection.host)
    return StreamingResponse(
        body(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Content-Length": str(size),
        },
    )


# ---- Software -------------------------------------------------------------------------------


def render_software_page(
    request: Request, username: str, *, error: str | None = None, notice: str | None = None
) -> Response:
    """Read the switch fresh and show the Software page, with a message."""
    connection = stored_switch(request)[0]
    jobs = _jobs(request)
    blocked = {}
    if connection is not None:
        checksum, impact = jobs.get(connection.id, "checksum"), jobs.get(connection.id, "impact")
        image = impact.subject if impact else (checksum.subject if checksum else "")
        blocked = {
            "image": image,
            "why": ready_to_install(checksum, impact, image) if image else "",
        }
    return _render(
        request,
        username,
        "software.html",
        load_software_page,
        {"install": blocked},
        error=error,
        notice=notice,
    )


@router.get("/software", response_class=HTMLResponse)
def software_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /software``: the running and boot images, the images on bootflash and the last
    install; every role looks."""
    return render_software_page(request, username)


def _software_job(
    request: Request, username: str, image: str, kind: str, make_work: Callable[..., Any]
) -> Response | None:
    """Start a Software job for ``image``; None, or the page saying why it did not."""
    connection, target, problem = stored_switch(request)
    if connection is None or target is None:
        return render_software_page(request, username, error=problem or "No switch is set up yet.")
    session, why = _session_opener(request, connection)
    if session is None:
        return render_software_page(request, username, error=f"Not started: {why}")
    status, page = read_switch(
        reading_target(request, connection, target),
        load_software_page,
        transport=request.app.state.nxapi_transport,
    )
    if page is None:
        return render_software_page(request, username, error=status.message)
    try:
        check_image(page, image)
        work = make_work(session)
    except ValueError as exc:
        return render_software_page(request, username, error=f"Not started: {exc}.")
    if busy := _start(request, connection, kind, image, username, work):
        return render_software_page(request, username, error=f"Not started: {busy}")
    return None


@router.post("/software/checksum", response_class=HTMLResponse)
def software_checksum(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    image: str = Form(""),
    checksum: str = Form(""),
) -> Response:
    """Have the switch work out an image's checksum and compare it with the pasted one."""
    require_csrf(request, csrf)
    try:
        checksum_word(checksum)
    except ValueError as exc:
        return render_software_page(request, username, error=f"Not started: {exc}.")
    refused = _software_job(
        request, username, image, "checksum", lambda s: checksum_work(s, image, checksum)
    )
    if refused is not None:
        return refused
    return render_software_page(request, username, notice=f"Checking {image}'s checksum.")


@router.post("/software/check", response_class=HTMLResponse)
def software_check(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    image: str = Form(""),
) -> Response:
    """Run the switch's own compatibility check for an image (changes nothing)."""
    require_csrf(request, csrf)
    refused = _software_job(request, username, image, "impact", lambda s: impact_work(s, image))
    if refused is not None:
        return refused
    return render_software_page(request, username, notice=f"Checking whether {image} installs.")


@router.post("/software/install", response_class=HTMLResponse)
def software_install(
    request: Request,
    username: str = Depends(admin_required),
    csrf: str = Form(""),
    image: str = Form(""),
    hostname: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Install an image whose checksum and compatibility check passed. Asks first, with
    the switch's name typed to confirm: the install restarts the switch."""
    require_csrf(request, csrf)
    connection = stored_switch(request)[0]
    if connection is None:
        return render_software_page(request, username, error="No switch is set up yet.")
    jobs = _jobs(request)
    checksum, impact = jobs.get(connection.id, "checksum"), jobs.get(connection.id, "impact")
    if why := ready_to_install(checksum, impact, image):
        return render_software_page(request, username, error=f"Not installed: {why}.")
    name = connection.switch_hostname or connection.host
    if confirm != "yes" or hostname.strip() != name:
        return templates.TemplateResponse(
            request,
            "software_install.html",
            {
                "username": username,
                "image": image,
                "impact": impact.result if impact else {},
                "name": name,
                "error": "Type the switch's name to confirm." if confirm == "yes" else None,
                "csrf_token": csrf_token(request),
            },
            status_code=400 if confirm == "yes" else 200,
        )
    refused = _software_job(request, username, image, "install", lambda s: install_work(s, image))
    if refused is not None:
        return refused
    note_activity(request, username, "Software", f"Started installing {image}", connection.host)
    return render_software_page(
        request, username, notice=f"Installing {image}. The switch restarts when it is done."
    )


# ---- Tech support ---------------------------------------------------------------------------


def render_tech_page(
    request: Request, username: str, *, error: str | None = None, notice: str | None = None
) -> Response:
    """Show the Tech support page, with a message. It reads nothing from the switch."""
    connection = stored_switch(request)[0]
    found = tech_file(request.app.state.settings.data_dir, connection.id) if connection else None
    return _render(
        request,
        username,
        "tech_support.html",
        None,
        {"tech": found, "now": time.time()},
        error=error,
        notice=notice,
    )


@router.get("/tech-support", response_class=HTMLResponse)
def tech_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /tech-support``: the last collected tech-support and the button to collect
    it again; every role looks, admins collect and download."""
    return render_tech_page(request, username)


@router.post("/tech-support/collect", response_class=HTMLResponse)
def tech_collect(
    request: Request, username: str = Depends(admin_required), csrf: str = Form("")
) -> Response:
    """Run ``show tech-support`` as a background job and keep what it prints."""
    require_csrf(request, csrf)
    connection = stored_switch(request)[0]
    if connection is None:
        return render_tech_page(request, username, error="No switch is set up yet.")
    session, why = _session_opener(request, connection)
    if session is None:
        return render_tech_page(request, username, error=f"Not started: {why}")
    target = tech_path(request.app.state.settings.data_dir, connection.id)
    if busy := _start(request, connection, "techsupport", "", username, tech_work(session, target)):
        return render_tech_page(request, username, error=f"Not started: {busy}")
    note_activity(request, username, "Tech support", "Collected show tech-support", connection.host)
    return render_tech_page(request, username, notice="Collecting show tech-support.")


@router.get("/tech-support/download")
def tech_download(request: Request, username: str = Depends(admin_required)) -> Response:
    """The last collected tech-support, gzipped."""
    connection = stored_switch(request)[0]
    found = tech_file(request.app.state.settings.data_dir, connection.id) if connection else None
    if connection is None or found is None:
        return render_tech_page(request, username, error="No tech-support is collected yet.")
    stamp = time.strftime("%Y%m%d-%H%M", time.gmtime(found.made))
    name = f"{connection.switch_hostname or connection.host}-tech-support-{stamp}.txt.gz"
    return FileResponse(found.path, media_type="application/gzip", filename=name)


@router.post("/tech-support/delete", response_class=HTMLResponse)
def tech_delete(
    request: Request, username: str = Depends(admin_required), csrf: str = Form("")
) -> Response:
    """Remove the collected tech-support from NXray (it holds the switch's configuration)."""
    require_csrf(request, csrf)
    connection = stored_switch(request)[0]
    if connection is not None:
        tech_path(request.app.state.settings.data_dir, connection.id).unlink(missing_ok=True)
    return render_tech_page(
        request, username, notice="Done: the collected tech-support is removed."
    )
