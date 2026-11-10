"""Adding new rules to NXray's role by itself, for a switch whose admin login is stored.

NX-OS will not let an account change its own role, so new rules need the
switch admin login. A switch in the ``stored`` role mode (issue #40) keeps that
login encrypted, and ``upgrade_stored_roles`` uses it once at start-up when this
version of NXray knows rules the switch's role lacks. A failure is logged and
left for the Switch page, which still shows the update and its button.
"""

from __future__ import annotations

import logging
import threading

import httpx

from app.activity import record_activity
from app.alerts import notify_change, switch_label
from app.config import Settings
from app.db import open_db
from app.port_changes import ROLE_NAME, ROLE_VERSION, enable_port_changes
from app.switch_connection import (
    ROLE_STORED,
    DecryptionError,
    SwitchConnection,
    list_connections,
    set_changes_enabled,
    stored_admin_login,
)
from app.switch_setup import SetupError
from app.switch_ssh import ShellOpener

log = logging.getLogger("nxray.role_upgrade")

# One change to NXray's account on a switch at a time: setup, Turn on changes,
# a role mode change and this upgrade all share it. Two at once could write the
# role together.
SETUP_LOCK = threading.Lock()

ACTOR = "NXray"


def needs_upgrade(connection: SwitchConnection) -> bool:
    """True when the switch keeps the admin login and its role lacks rules this
    version knows."""
    return (
        connection.role_mode == ROLE_STORED
        and connection.changes_enabled
        and 0 < connection.role_version < ROLE_VERSION
    )


def upgrade_stored_roles(
    settings: Settings,
    *,
    transport: httpx.BaseTransport | None = None,
    ssh_opener: ShellOpener | None = None,
    alert_transport: httpx.BaseTransport | None = None,
) -> int:
    """Add the new rules to the role of every switch that needs it. Returns how
    many switches were updated. Never raises."""
    updated = 0
    try:
        with open_db(settings.db_path) as conn:
            behind = [c for c in list_connections(conn) if needs_upgrade(c)]
        for connection in behind:
            if not SETUP_LOCK.acquire(blocking=False):
                log.warning("a switch change is running; %s keeps its old role", connection.host)
                continue
            try:
                updated += _upgrade_one(
                    settings, connection, transport, ssh_opener, alert_transport
                )
            finally:
                SETUP_LOCK.release()
    except Exception:  # noqa: BLE001 - start-up must never fail because of this
        log.exception("could not update the stored-login roles")
    return updated


def _upgrade_one(
    settings: Settings,
    connection: SwitchConnection,
    transport: httpx.BaseTransport | None,
    ssh_opener: ShellOpener | None,
    alert_transport: httpx.BaseTransport | None,
) -> int:
    try:
        with open_db(settings.db_path) as conn:
            login = stored_admin_login(conn, connection.id, settings.secret_key)
    except DecryptionError:
        log.warning(
            "the stored admin login for %s cannot be read (secret key changed)", connection.host
        )
        return 0
    if login is None:
        log.warning("%s is in the stored-login mode but has no stored login", connection.host)
        return 0
    admin_user, admin_password, ssh_port = login
    try:
        result = enable_port_changes(
            host=connection.host,
            nxapi_port=connection.port,
            ssh_port=ssh_port,
            admin_user=admin_user,
            admin_password=admin_password,
            account_name=connection.username,
            role_version=connection.role_version,
            vlan_interfaces_listed=connection.role_vlan_interfaces,
            nve_listed=connection.role_nve,
            mode=ROLE_STORED,
            previous_mode=ROLE_STORED,
            transport=transport,
            ssh_opener=ssh_opener,
        )
    except SetupError as exc:
        log.warning("could not update the role on %s: %s", connection.host, exc)
        return 0
    what = (
        f"Added the new rules to NXray's {ROLE_NAME} role with the stored admin login, "
        f"version {ROLE_VERSION}"
    )
    with open_db(settings.db_path) as conn:
        set_changes_enabled(
            conn,
            connection.id,
            pause_seconds=result.pause_seconds,
            role_version=ROLE_VERSION,
            vlan_interfaces=result.vlan_interfaces,
            nve=result.nve,
            role_mode=ROLE_STORED,
        )
        record_activity(conn, ACTOR, "Switch", what, connection.host)
    log.info("updated the %s role on %s to version %d", ROLE_NAME, connection.host, ROLE_VERSION)
    notify_change(
        settings,
        ACTOR,
        "Switch",
        what,
        switch_label(connection) or connection.host,
        alert_transport,
        background=False,
    )
    return 1
