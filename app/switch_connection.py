"""Storing and retrieving the switches NXray talks to.

Each switch is a row of ``switch_connection``, named by its ``id``; every
function here takes that id, so nothing reads or changes "the" switch by
default. Which one a page shows is ``app/switch_choice.py``'s job. The
account password is encrypted on the way in and decrypted only when a
call to the switch is about to be made. Nothing here hands the password to a
template: pages show which account is used, never its password.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass

from app.crypto import DecryptionError, decrypt, encrypt
from app.nxapi import SwitchTarget
from app.switch import SystemInfo

# How long one NX-API call may take before the switch counts as unreachable.
SWITCH_TIMEOUT = 10.0

# How much access NXray's switch account gets (issue #40). See app/port_changes.py.
ROLE_LIMITED = "limited"
ROLE_BROAD = "broad"
ROLE_STORED = "stored"
ROLE_MODES = (ROLE_LIMITED, ROLE_BROAD, ROLE_STORED)

# The role version kept for a broad role: it permits every configuration command,
# so no later NXray version can add a permit it lacks. Above any real ROLE_VERSION.
# It counts the broad role's own deny lists instead: 1000 had the account, role, AAA
# and boot denies; 1001 added the EEM denies (app/port_changes.py EEM_DENY_RULES). A
# broad role below it is written again by Update the port list on the Switch page.
BROAD_ROLE_VERSION = 1001


@dataclass(frozen=True)
class SwitchConnection:
    """The stored connection, without the password."""

    id: int
    host: str
    port: int
    username: str
    switch_hostname: str
    created_at: float
    config_saved: bool
    last_tested_at: float | None
    last_test_ok: bool | None
    last_test_message: str | None
    changes_enabled_at: float | None = None
    paused_until: float | None = None
    unsaved_changes: bool = False
    role_version: int = 0
    # The role's port list names the VLAN interfaces (needs interface-vlan on).
    role_vlan_interfaces: bool = False
    # The role's port list names the NVE interface (needs the nve feature on).
    role_nve: bool = False
    # As last read from the switch (dashboard, connection test); empty until then.
    switch_model: str = ""
    nxos_version: str = ""
    # The sFlow agent address NXray set on the switch; "" until then.
    sflow_agent: str = ""
    # ROLE_LIMITED, ROLE_BROAD or ROLE_STORED; with ROLE_STORED the switch admin login
    # (admin_user, and the SSH port to use) is kept encrypted, see ``stored_admin_login``.
    role_mode: str = ROLE_LIMITED
    admin_user: str = ""
    admin_ssh_port: int = 22

    @property
    def label(self) -> str:
        """The switch in words: its hostname, else its address."""
        return self.switch_hostname or self.host

    @property
    def changes_enabled(self) -> bool:
        """True once NXray's account has been given the port-changes role."""
        return self.changes_enabled_at is not None

    @property
    def broad_role_behind(self) -> bool:
        """True when the account has a broad role written before its latest denies
        (``BROAD_ROLE_VERSION``): Update the port list on the Switch page adds them."""
        return (
            self.changes_enabled
            and self.role_mode == ROLE_BROAD
            and self.role_version < BROAD_ROLE_VERSION
        )

    @property
    def vlan_changes_enabled(self) -> bool:
        """True once that role includes the VLAN rules (role version 2 or later)."""
        return self.changes_enabled and self.role_version >= 2

    @property
    def settings_changes_enabled(self) -> bool:
        """True once that role includes the port settings rules (role version 3 or later)."""
        return self.changes_enabled and self.role_version >= 3

    @property
    def feature_changes_enabled(self) -> bool:
        """True once that role includes the feature rules (role version 4 or later)."""
        return self.changes_enabled and self.role_version >= 4

    @property
    def neighbor_changes_enabled(self) -> bool:
        """True once that role includes the neighbor rules: CDP and LLDP per port and
        the MAC address table (role version 5 or later)."""
        return self.changes_enabled and self.role_version >= 5

    @property
    def channel_changes_enabled(self) -> bool:
        """True once that role includes the port-channel rules and names the
        port-channels (role version 6 or later)."""
        return self.changes_enabled and self.role_version >= 6

    @property
    def layer3_changes_enabled(self) -> bool:
        """True once that role includes the VLAN interface and IPv6 rules and names
        the VLAN interfaces (role version 7 or later)."""
        return self.changes_enabled and self.role_version >= 7

    @property
    def vlan_interface_changes_enabled(self) -> bool:
        """True once the role also names the VLAN interfaces in its port list, which
        the switch takes only while interface-vlan is on."""
        return self.layer3_changes_enabled and self.role_vlan_interfaces

    @property
    def vxlan_changes_enabled(self) -> bool:
        """True once that role includes the VXLAN rules and names the NVE interface in
        its port list (role version 20 or later, with the nve feature on when it was
        written)."""
        return self.changes_enabled and self.role_version >= 20 and self.role_nve

    @property
    def monitor_changes_enabled(self) -> bool:
        """True when NXray may make monitor sessions: with the broad role, or the stored
        admin login, which both allow every configuration command. The limited role has
        a rule for each command and no rule numbers left for these (a role holds 256)."""
        return self.changes_enabled and self.role_mode in (ROLE_BROAD, ROLE_STORED)

    @property
    def qos_changes_enabled(self) -> bool:
        """True when NXray may make QoS class-maps and policy-maps: the same as for monitor
        sessions (the broad role or the stored admin login; the limited role has no rule
        numbers left)."""
        return self.monitor_changes_enabled

    @property
    def pfc_changes_enabled(self) -> bool:
        """True when NXray may change priority flow control: the same as for monitor
        sessions (the broad role or the stored admin login; the limited role has no rule
        numbers left)."""
        return self.monitor_changes_enabled

    @property
    def private_vlan_changes_enabled(self) -> bool:
        """True when NXray may change private VLANs: the same as for monitor sessions (the
        broad role or the stored admin login; the limited role has no rule numbers left)."""
        return self.monitor_changes_enabled

    @property
    def udld_changes_enabled(self) -> bool:
        """True when NXray may change UDLD: the same as for monitor sessions (the broad
        role or the stored admin login; the limited role has no rule numbers left)."""
        return self.monitor_changes_enabled

    @property
    def vtp_changes_enabled(self) -> bool:
        """True when NXray may change VTP: the same as for monitor sessions (the broad
        role or the stored admin login; the limited role has no rule numbers left)."""
        return self.monitor_changes_enabled

    @property
    def dot1x_changes_enabled(self) -> bool:
        """True when NXray may change 802.1X: the same as for monitor sessions (the broad
        role or the stored admin login; the limited role has no rule numbers left)."""
        return self.monitor_changes_enabled

    @property
    def ip_sla_changes_enabled(self) -> bool:
        """True when NXray may change IP SLA: the same as for monitor sessions (the broad
        role or the stored admin login; the limited role has no rule numbers left)."""
        return self.monitor_changes_enabled

    @property
    def errdisable_changes_enabled(self) -> bool:
        """True when NXray may change errdisable detection and recovery: the same as for
        monitor sessions (the broad role or the stored admin login)."""
        return self.monitor_changes_enabled

    @property
    def callhome_changes_enabled(self) -> bool:
        """True when NXray may change Call Home: the same as for monitor sessions (the broad
        role or the stored admin login)."""
        return self.monitor_changes_enabled

    @property
    def scheduler_changes_enabled(self) -> bool:
        """True when NXray may make scheduler jobs and schedules: the same as for monitor
        sessions (the broad role or the stored admin login). A job runs as the account
        that made it, so with the broad role its commands keep that role's limits."""
        return self.monitor_changes_enabled

    @property
    def eem_changes_enabled(self) -> bool:
        """True when NXray may change EEM: with the stored admin login only. An applet's
        commands run as the switch's admin, so the broad role denies EEM."""
        return self.changes_enabled and self.role_mode == ROLE_STORED

    @property
    def vrf_changes_enabled(self) -> bool:
        """True once that role includes the VRF rules (role version 8 or later)."""
        return self.changes_enabled and self.role_version >= 8

    @property
    def route_changes_enabled(self) -> bool:
        """True once that role includes the static route rules (role version 9 or later)."""
        return self.changes_enabled and self.role_version >= 9

    @property
    def protocol_changes_enabled(self) -> bool:
        """True once that role includes the routing protocol rules (role version 10 or
        later): OSPF, BGP, HSRP and the others, and route-maps, prefix-lists and key
        chains."""
        return self.changes_enabled and self.role_version >= 10

    @property
    def stp_changes_enabled(self) -> bool:
        """True once that role includes the spanning tree rules (role version 11 or
        later)."""
        return self.changes_enabled and self.role_version >= 11

    @property
    def admin_changes_enabled(self) -> bool:
        """True once that role includes the switch admin rules (role version 12 or
        later)."""
        return self.changes_enabled and self.role_version >= 12

    @property
    def security_changes_enabled(self) -> bool:
        """True once that role includes the security and config rules (role version 13
        or later): ACLs, port security, the saved configuration and checkpoints."""
        return self.changes_enabled and self.role_version >= 13

    @property
    def layer2_security_changes_enabled(self) -> bool:
        """True once that role includes the layer 2 security rules (role version 14 or
        later): DHCP snooping and relay, ARP inspection, IP Source Guard, MAC ACLs,
        object groups, VLAN access maps and TCAM regions."""
        return self.changes_enabled and self.role_version >= 14

    @property
    def traffic_changes_enabled(self) -> bool:
        """True once that role includes the traffic measuring rules (role version 15
        or later): how long the front ports average their In and Out rates over."""
        return self.changes_enabled and self.role_version >= 15

    @property
    def reset_changes_enabled(self) -> bool:
        """True once that role includes the reset rule (role version 16 or later):
        putting a port or a port-channel back to how it came out of the box."""
        return self.changes_enabled and self.role_version >= 16

    @property
    def vpc_changes_enabled(self) -> bool:
        """True once that role includes the vPC rules (role version 19 or later)."""
        return self.changes_enabled and self.role_version >= 19

    @property
    def can_restart(self) -> bool:
        """True once that role includes the restart rules (role version 18 or
        later): NXray restarts the switch itself, with no admin login typed."""
        return self.changes_enabled and self.role_version >= 18

    def paused_seconds(self, now: float | None = None) -> int:
        """Seconds NXray still leaves the switch alone; 0 when not paused."""
        if self.paused_until is None:
            return 0
        return max(0, int(self.paused_until - (time.time() if now is None else now) + 0.999))


def save_connection(
    conn: sqlite3.Connection,
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    switch_hostname: str,
    config_saved: bool,
    secret_key: str,
) -> int:
    """Store a new switch, encrypting the password. Returns its id.

    Refuses (sqlite3.IntegrityError) a second switch at the same address and
    NX-API port: setting it up again would orphan the first account on it
    unnoticed. Run setup again is the way to give that one a new login.
    """
    if find_by_address(conn, host, port) is not None:
        raise sqlite3.IntegrityError(f"a switch at {host}, port {port} is already stored")
    cursor = conn.execute(
        """
        INSERT INTO switch_connection
            (host, port, username, password_encrypted, switch_hostname,
             created_at, config_saved, last_tested_at, last_test_ok, last_test_message)
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
        """,
        (
            host,
            port,
            username,
            encrypt(password, secret_key),
            switch_hostname,
            time.time(),
            1 if config_saved else 0,
        ),
    )
    conn.commit()
    return int(cursor.lastrowid or 0)


def _connection(row: sqlite3.Row) -> SwitchConnection:
    return SwitchConnection(
        id=row["id"],
        host=row["host"],
        port=row["port"],
        username=row["username"],
        switch_hostname=row["switch_hostname"],
        created_at=row["created_at"],
        config_saved=bool(row["config_saved"]),
        last_tested_at=row["last_tested_at"],
        last_test_ok=None if row["last_test_ok"] is None else bool(row["last_test_ok"]),
        last_test_message=row["last_test_message"],
        changes_enabled_at=row["changes_enabled_at"],
        paused_until=row["paused_until"],
        unsaved_changes=bool(row["unsaved_changes"]),
        role_version=row["role_version"],
        role_vlan_interfaces=bool(row["role_vlan_interfaces"]),
        role_nve=bool(row["role_nve"]),
        switch_model=row["switch_model"],
        nxos_version=row["nxos_version"],
        sflow_agent=row["sflow_agent"],
        role_mode=row["role_mode"],
        admin_user=row["admin_user"],
        admin_ssh_port=row["admin_ssh_port"],
    )


def get_connection(conn: sqlite3.Connection, switch_id: int | None) -> SwitchConnection | None:
    """The stored switch with this id, or None when there is none."""
    if switch_id is None:
        return None
    row = conn.execute("SELECT * FROM switch_connection WHERE id = ?", (switch_id,)).fetchone()
    return None if row is None else _connection(row)


def list_connections(conn: sqlite3.Connection) -> list[SwitchConnection]:
    """Every stored switch, in the order they were added."""
    return [_connection(row) for row in conn.execute("SELECT * FROM switch_connection ORDER BY id")]


def find_by_address(conn: sqlite3.Connection, host: str, port: int) -> int | None:
    """The id of the stored switch at this address and NX-API port, or None.

    The host is compared without regard to case, as DNS names are."""
    row = conn.execute(
        "SELECT id FROM switch_connection WHERE host = ? COLLATE NOCASE AND port = ?",
        (host, port),
    ).fetchone()
    return None if row is None else int(row["id"])


def set_changes_enabled(
    conn: sqlite3.Connection,
    switch_id: int,
    *,
    pause_seconds: float,
    role_version: int,
    vlan_interfaces: bool | None = None,
    role_mode: str | None = None,
    nve: bool | None = None,
) -> None:
    """Record that port changes are on with the given role version, and whether
    its port list names the VLAN interfaces and the NVE interface (None keeps what
    is stored).
    ``role_mode`` (None keeps it) is stored with ``BROAD_ROLE_VERSION`` as the
    version for a broad role; the admin login is kept by ``set_admin_login``.

    Switch calls pause for ``pause_seconds`` (0: no new pause). A pause
    still running from an earlier change is kept, never shortened: the
    switch may still be holding the account's old permissions.
    """
    until = time.time() + max(pause_seconds, 0)
    conn.execute(
        """
        UPDATE switch_connection
           SET changes_enabled_at = ?,
               paused_until = MAX(COALESCE(paused_until, 0), ?),
               role_version = ?,
               role_vlan_interfaces = COALESCE(?, role_vlan_interfaces),
               role_nve = COALESCE(?, role_nve),
               role_mode = COALESCE(?, role_mode)
         WHERE id = ?
        """,
        (
            time.time(),
            until,
            BROAD_ROLE_VERSION if role_mode == ROLE_BROAD else role_version,
            None if vlan_interfaces is None else int(vlan_interfaces),
            None if nve is None else int(nve),
            role_mode,
            switch_id,
        ),
    )
    conn.commit()


def set_changes_off(conn: sqlite3.Connection, switch_id: int) -> None:
    """Record that port changes are off (the role is gone from the switch)."""
    conn.execute(
        "UPDATE switch_connection SET changes_enabled_at = NULL, role_version = 0, "
        "role_vlan_interfaces = 0, role_nve = 0, role_mode = 'limited', admin_user = '', "
        "admin_password_encrypted = '', admin_ssh_port = 22 WHERE id = ?",
        (switch_id,),
    )
    conn.commit()


def set_admin_login(
    conn: sqlite3.Connection,
    switch_id: int,
    *,
    admin_user: str,
    admin_password: str,
    ssh_port: int,
    secret_key: str,
) -> None:
    """Keep the switch admin login, encrypted, for ROLE_STORED."""
    conn.execute(
        "UPDATE switch_connection SET admin_user = ?, admin_password_encrypted = ?, "
        "admin_ssh_port = ? WHERE id = ?",
        (admin_user, encrypt(admin_password, secret_key), ssh_port, switch_id),
    )
    conn.commit()


def delete_admin_login(conn: sqlite3.Connection, switch_id: int) -> None:
    """Forget the stored switch admin login. A switch in ROLE_STORED goes back to
    ROLE_LIMITED: the same rules, applied by an admin typing the login again."""
    conn.execute(
        "UPDATE switch_connection SET admin_user = '', admin_password_encrypted = '', "
        "admin_ssh_port = 22, role_mode = CASE WHEN role_mode = 'stored' THEN 'limited' "
        "ELSE role_mode END WHERE id = ?",
        (switch_id,),
    )
    conn.commit()


def stored_admin_login(
    conn: sqlite3.Connection, switch_id: int, secret_key: str
) -> tuple[str, str, int] | None:
    """The stored switch admin login as (username, password, SSH port), or None
    when none is stored. Raises DecryptionError when the secret key changed."""
    row = conn.execute(
        "SELECT admin_user, admin_password_encrypted, admin_ssh_port FROM switch_connection "
        "WHERE id = ?",
        (switch_id,),
    ).fetchone()
    if row is None or not row["admin_password_encrypted"]:
        return None
    return (
        row["admin_user"],
        decrypt(row["admin_password_encrypted"], secret_key),
        row["admin_ssh_port"],
    )


def replace_login(
    conn: sqlite3.Connection,
    switch_id: int,
    *,
    host: str,
    port: int,
    password: str,
    switch_hostname: str,
    secret_key: str,
) -> None:
    """Store the new password Run setup again gave the account, and where it worked.

    The account name, port-change state and pause are left as they are.
    """
    conn.execute(
        """
        UPDATE switch_connection
           SET host = ?, port = ?, password_encrypted = ?, switch_hostname = ?
         WHERE id = ?
        """,
        (host, port, encrypt(password, secret_key), switch_hostname, switch_id),
    )
    conn.commit()


def set_switch_hostname(conn: sqlite3.Connection, switch_id: int, switch_hostname: str) -> None:
    """Store the switch's new name, after NXray renamed it on the Switch admin page."""
    conn.execute(
        "UPDATE switch_connection SET switch_hostname = ? WHERE id = ?",
        (switch_hostname, switch_id),
    )
    conn.commit()


def set_switch_identity(
    conn: sqlite3.Connection, connection: SwitchConnection, system: SystemInfo
) -> None:
    """Store the model and NX-OS version the switch just reported, when they changed."""
    if (connection.switch_model, connection.nxos_version) == (system.model, system.nxos_version):
        return
    conn.execute(
        "UPDATE switch_connection SET switch_model = ?, nxos_version = ? WHERE id = ?",
        (system.model, system.nxos_version, connection.id),
    )
    conn.commit()


def set_address(
    conn: sqlite3.Connection, switch_id: int, *, host: str, port: int, switch_hostname: str
) -> None:
    """Store a new switch address that NXray's account has already signed in at."""
    conn.execute(
        "UPDATE switch_connection SET host = ?, port = ?, switch_hostname = ? WHERE id = ?",
        (host, port, switch_hostname, switch_id),
    )
    conn.commit()


def set_unsaved_changes(conn: sqlite3.Connection, switch_id: int, unsaved: bool) -> None:
    """Remember whether NXray changed the switch since the config was last saved."""
    conn.execute(
        "UPDATE switch_connection SET unsaved_changes = ? WHERE id = ?", (int(unsaved), switch_id)
    )
    conn.commit()


def set_config_saved(conn: sqlite3.Connection, switch_id: int, saved: bool) -> None:
    """Record whether the switch config was saved after the account was made."""
    conn.execute(
        "UPDATE switch_connection SET config_saved = ? WHERE id = ?", (int(saved), switch_id)
    )
    conn.commit()


def delete_connection(conn: sqlite3.Connection, switch_id: int) -> bool:
    """Forget a switch: its login, and what NXray kept about it (history, port
    labels, config backups, open problems, which of its accounts belong to
    which NXray user, its sFlow traffic). True if one was removed.

    The account stays on the switch; only NXray's copy of the login goes. The
    activity log and the alert log keep their lines: they name the switch in
    words.
    """
    cursor = conn.execute("DELETE FROM switch_connection WHERE id = ?", (switch_id,))
    for table in (
        "history",
        "port_labels",
        "config_backups",
        "alert_open",
        "switch_accounts",
        "sflow_traffic",
    ):
        conn.execute(f"DELETE FROM {table} WHERE switch_id = ?", (switch_id,))  # fixed names
    conn.commit()
    return cursor.rowcount > 0


def set_sflow_agent(conn: sqlite3.Connection, switch_id: int, agent: str) -> None:
    """Remember the sFlow agent address NXray set on a switch, so the collector
    knows its datagrams."""
    conn.execute("UPDATE switch_connection SET sflow_agent = ? WHERE id = ?", (agent, switch_id))
    conn.commit()


def record_test_result(conn: sqlite3.Connection, switch_id: int, *, ok: bool, message: str) -> None:
    """Remember the outcome of the last connection test."""
    conn.execute(
        """
        UPDATE switch_connection
           SET last_tested_at = ?, last_test_ok = ?, last_test_message = ?
         WHERE id = ?
        """,
        (time.time(), 1 if ok else 0, message, switch_id),
    )
    conn.commit()


def load_target(conn: sqlite3.Connection, switch_id: int | None, secret_key: str) -> SwitchTarget:
    """The stored switch as a SwitchTarget, password decrypted.

    Raises LookupError when there is no such switch and DecryptionError when
    the secret key no longer matches: distinct failures with distinct fixes.
    """
    row = conn.execute(
        "SELECT host, port, username, password_encrypted FROM switch_connection WHERE id = ?",
        (switch_id,),
    ).fetchone()
    if row is None:
        raise LookupError("no such switch is set up")
    return SwitchTarget(
        host=row["host"],
        port=row["port"],
        username=row["username"],
        password=decrypt(row["password_encrypted"], secret_key),
        timeout=SWITCH_TIMEOUT,
    )


__all__ = [
    "BROAD_ROLE_VERSION",
    "ROLE_BROAD",
    "ROLE_LIMITED",
    "ROLE_MODES",
    "ROLE_STORED",
    "SWITCH_TIMEOUT",
    "DecryptionError",
    "SwitchConnection",
    "delete_admin_login",
    "delete_connection",
    "find_by_address",
    "get_connection",
    "list_connections",
    "load_target",
    "record_test_result",
    "replace_login",
    "save_connection",
    "set_address",
    "set_admin_login",
    "set_changes_enabled",
    "set_changes_off",
    "set_config_saved",
    "set_switch_hostname",
    "set_unsaved_changes",
    "stored_admin_login",
]
