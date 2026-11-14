"""The SSH and certificates page: the switch's SSH host key, key pairs, trustpoints and
certificates, and the changes its forms make, on the same parts as the Monitor sessions page.

``GET /pki`` shows it; every setting goes through ``POST /pki/change`` with the same form
fields as a protocol page and a confirm page first. Pasting a CA certificate goes through
``POST /pki/authenticate``: NXray reads the certificates, shows them, and on confirm types
them to the switch over SSH and accepts them only when the switch shows the same
fingerprints. Changes need the broad role or the stored admin login, and an NXray admin.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.db import open_db
from app.dependencies import (
    admin_required,
    login_required,
    note_activity,
    require_csrf,
    stored_switch,
    templates,
)
from app.nxapi import NxapiClient
from app.pki import PKI, PkiPage, build_pki_change, check_ca_certificates, load_pki_page
from app.port_changes import SSH_TIMEOUT
from app.protocols import ProtocolChange
from app.routes.protocols import (
    NO_ADMIN_LOGIN,
    ProtocolSite,
    admin_login,
    form_fields,
    render_site_page,
    site_change,
)
from app.security import csrf_token
from app.switch_choice import selected_switch_id
from app.switch_connection import ROLE_STORED, set_unsaved_changes
from app.switch_setup import read_switch, scrub_secrets
from app.switch_ssh import SshAuthError, SshError, authenticate_ca

router = APIRouter()
log = logging.getLogger("nxray.pki")

PKI_CHANGES_OFF = (
    "SSH and certificate changes are off. An NXray admin turns on changes on the Switch page "
    "first, with the broad role or a stored admin login: the limited role has no room for them."
)


def check_pki_place(page: PkiPage, ident: dict[str, str]) -> None:
    """Nothing to refuse beforehand: a key pair or trustpoint named here is made by the
    change, and the switch refuses one it does not have."""


def _send(
    client: NxapiClient, change: ProtocolChange, ident: dict[str, str], values: dict[str, str]
) -> None:
    client.configure_pki(change.scope, change.setting, change.action, ident, values)


SITE = ProtocolSite(
    url="/pki",
    back_url="/switch-admin",
    back_label="Switch admin",
    save_back={"back": "pki"},
    changes_name="SSH and certificate",
    subject="SSH keys and certificates",
    off_message=PKI_CHANGES_OFF,
    enabled=lambda connection: connection.pki_changes_enabled,
    load=load_pki_page,
    check_place=check_pki_place,
    build=build_pki_change,
    send=_send,
    stored_login=True,
    admin_only=True,
    extra_template="_pki_paste.html",
)


def render_pki_page(
    request: Request,
    username: str,
    *,
    error: str | None = None,
    notice: str | None = None,
    form: dict[str, str] | None = None,
) -> Response:
    """Read the switch fresh and show the SSH and certificates page, with a message."""
    return render_site_page(request, username, PKI, SITE, error=error, notice=notice, form=form)


@router.get("/pki", response_class=HTMLResponse)
def pki_page(request: Request, username: str = Depends(login_required)) -> Response:
    """``GET /pki``: the SSH host key, key pairs, trustpoints and certificates, read live;
    every role looks, NXray admins change."""
    return render_pki_page(request, username)


@router.post("/pki/change", response_class=HTMLResponse)
def pki_change(
    request: Request,
    username: str = Depends(admin_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """One change on the SSH and certificates page. Without confirm=yes, asks first."""
    return site_change(request, username, form, PKI, SITE)


@router.post("/pki/authenticate", response_class=HTMLResponse)
def pki_authenticate(
    request: Request,
    username: str = Depends(admin_required),
    form: Mapping[str, str] = Depends(form_fields),
) -> Response:
    """Give a trustpoint its CA certificate from pasted PEM text. Without confirm=yes,
    shows the certificates read from it first."""
    require_csrf(request, form.get("csrf", ""))
    trustpoint = form.get("trustpoint", "").strip()
    pasted = form.get("pem", "")
    kept = {"pem_trustpoint": trustpoint}

    def refuse(message: str) -> Response:
        return render_pki_page(request, username, error=message, form=kept)

    connection, target, problem = stored_switch(request)
    if connection is None:
        return refuse("No switch is set up yet.")
    if target is None:
        return refuse(problem or "The switch could not be read.")
    if not connection.pki_changes_enabled:
        return refuse(PKI_CHANGES_OFF)
    status, page = read_switch(target, load_pki_page, transport=request.app.state.nxapi_transport)
    if page is None:
        return refuse(status.message if status else "The switch could not be read.")
    if trustpoint not in page.trustpoints:
        return refuse(f"Not changed: the switch has no trustpoint {trustpoint!r}; make it first.")
    try:
        ca = check_ca_certificates(pasted)
    except ValueError as exc:
        return refuse(f"Not changed: {exc}.")
    if form.get("confirm") != "yes":
        lines = [
            f"SSH and certificates: give trustpoint {trustpoint} its CA certificate.",
            *(
                f"Certificate: {subject}, valid from {start}"
                for subject, start in zip(ca.subjects, ca.not_before, strict=True)
            ),
            "SHA1 fingerprints: " + ", ".join(sorted(ca.fingerprints)),
            "Over SSH the switch gets: configure terminal, crypto ca authenticate "
            f"{trustpoint}, the certificate lines, END OF INPUT, and yes once it shows "
            "the same fingerprints.",
        ]
        return templates.TemplateResponse(
            request,
            "confirm.html",
            {
                "username": username,
                "title": PKI.name,
                "back_url": SITE.url,
                "back_label": PKI.name,
                "lines": lines,
                "warnings": [
                    "The switch trusts certificates this authority signs from now on. A "
                    "certificate dated after the switch's clock is refused."
                ],
                "action": "/pki/authenticate",
                "fields": {"trustpoint": trustpoint, "pem": pasted},
                "csrf_token": csrf_token(request),
            },
        )
    user, password, port = target.username, target.password, connection.admin_ssh_port
    if connection.role_mode == ROLE_STORED:
        login = admin_login(request, connection)
        if login is None:
            return refuse(f"Not changed: {NO_ADMIN_LOGIN}")
        user, password, port = login
    try:
        authenticate_ca(
            host=connection.host,
            port=port,
            username=user,
            password=password,
            trustpoint=trustpoint,
            pem_lines=list(ca.lines),
            fingerprints=ca.fingerprints,
            timeout=SSH_TIMEOUT,
            opener=request.app.state.ssh_opener,
        )
    except SshAuthError:
        return refuse("Not changed: the switch refused the SSH login.")
    except SshError as exc:
        message = scrub_secrets(str(exc), password)
        log.warning("CA certificate refused: %s", message)
        return refuse(f"Not changed: the switch refused it: {message}")
    with open_db(request.app.state.settings.db_path) as conn:
        set_unsaved_changes(conn, selected_switch_id(request), True)
    describe = f"gave trustpoint {trustpoint} its CA certificate ({', '.join(ca.subjects)})"
    log.info("%s on %s by %s", describe, connection.host, username)
    note_activity(request, username, PKI.name, describe, connection.host)
    return render_pki_page(
        request,
        username,
        notice=f"Done: {describe}. Not saved yet: Save config keeps it over a restart of the "
        "switch.",
    )
