"""Storing and retrieving the switch NXray talks to.

The account password is encrypted on the way in and decrypted only when a
call to the switch is about to be made. Nothing here hands the password to a
template: pages show which account is used, never its password.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass

from app.crypto import DecryptionError, decrypt, encrypt
from app.nxapi import SwitchTarget

# How long one NX-API call may take before the switch counts as unreachable.
SWITCH_TIMEOUT = 10.0


@dataclass(frozen=True)
class SwitchConnection:
    """The stored connection, without the password."""

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

    @property
    def changes_enabled(self) -> bool:
        """True once NXray's account has been given the port-changes role."""
        return self.changes_enabled_at is not None

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
) -> None:
    """Store the connection, encrypting the password.

    Refuses to replace an existing one: a second setup must forget the first
    on purpose, or its account on the switch would be orphaned unnoticed.
    """
    conn.execute(
        """
        INSERT INTO switch_connection
            (id, host, port, username, password_encrypted, switch_hostname,
             created_at, config_saved, last_tested_at, last_test_ok, last_test_message)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
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


def get_connection(conn: sqlite3.Connection) -> SwitchConnection | None:
    """The stored connection, or None when no switch is set up."""
    row = conn.execute("SELECT * FROM switch_connection WHERE id = 1").fetchone()
    if row is None:
        return None
    return SwitchConnection(
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
    )


def set_changes_enabled(
    conn: sqlite3.Connection,
    *,
    pause_seconds: float,
    role_version: int,
    vlan_interfaces: bool | None = None,
) -> None:
    """Record that port changes are on with the given role version, and whether
    its port list names the VLAN interfaces (None keeps what is stored).

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
               role_vlan_interfaces = COALESCE(?, role_vlan_interfaces)
         WHERE id = 1
        """,
        (
            time.time(),
            until,
            role_version,
            None if vlan_interfaces is None else int(vlan_interfaces),
        ),
    )
    conn.commit()


def set_changes_off(conn: sqlite3.Connection) -> None:
    """Record that port changes are off (the role is gone from the switch)."""
    conn.execute(
        "UPDATE switch_connection SET changes_enabled_at = NULL, role_version = 0, "
        "role_vlan_interfaces = 0 WHERE id = 1"
    )
    conn.commit()


def replace_login(
    conn: sqlite3.Connection,
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
         WHERE id = 1
        """,
        (host, port, encrypt(password, secret_key), switch_hostname),
    )
    conn.commit()


def set_address(conn: sqlite3.Connection, *, host: str, port: int, switch_hostname: str) -> None:
    """Store a new switch address that NXray's account has already signed in at."""
    conn.execute(
        "UPDATE switch_connection SET host = ?, port = ?, switch_hostname = ? WHERE id = 1",
        (host, port, switch_hostname),
    )
    conn.commit()


def set_unsaved_changes(conn: sqlite3.Connection, unsaved: bool) -> None:
    """Remember whether NXray changed the switch since the config was last saved."""
    conn.execute("UPDATE switch_connection SET unsaved_changes = ? WHERE id = 1", (int(unsaved),))
    conn.commit()


def set_config_saved(conn: sqlite3.Connection, saved: bool) -> None:
    """Record whether the switch config was saved after the account was made."""
    conn.execute("UPDATE switch_connection SET config_saved = ? WHERE id = 1", (int(saved),))
    conn.commit()


def delete_connection(conn: sqlite3.Connection) -> bool:
    """Forget the stored connection and its password. True if one was removed.

    The account stays on the switch; only NXray's copy of the login goes.
    """
    cursor = conn.execute("DELETE FROM switch_connection WHERE id = 1")
    conn.commit()
    return cursor.rowcount > 0


def record_test_result(conn: sqlite3.Connection, *, ok: bool, message: str) -> None:
    """Remember the outcome of the last connection test."""
    conn.execute(
        """
        UPDATE switch_connection
           SET last_tested_at = ?, last_test_ok = ?, last_test_message = ?
         WHERE id = 1
        """,
        (time.time(), 1 if ok else 0, message),
    )
    conn.commit()


def load_target(conn: sqlite3.Connection, secret_key: str) -> SwitchTarget:
    """The stored connection as a SwitchTarget, password decrypted.

    Raises LookupError when nothing is set up and DecryptionError when the
    secret key no longer matches: distinct failures with distinct fixes.
    """
    row = conn.execute(
        "SELECT host, port, username, password_encrypted FROM switch_connection WHERE id = 1"
    ).fetchone()
    if row is None:
        raise LookupError("no switch is set up")
    return SwitchTarget(
        host=row["host"],
        port=row["port"],
        username=row["username"],
        password=decrypt(row["password_encrypted"], secret_key),
        timeout=SWITCH_TIMEOUT,
    )


__all__ = [
    "SWITCH_TIMEOUT",
    "DecryptionError",
    "SwitchConnection",
    "delete_connection",
    "get_connection",
    "load_target",
    "record_test_result",
    "replace_login",
    "save_connection",
    "set_address",
    "set_changes_enabled",
    "set_changes_off",
    "set_config_saved",
    "set_unsaved_changes",
]
