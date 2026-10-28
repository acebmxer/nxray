"""Turning on port changes: give NXray's switch account a role that allows them.

The role allows exactly these: on the front-panel Ethernet ports only,
turning a port on or off, setting or removing its description, setting its
mode (access or trunk) and VLANs, and its settings (speed, MTU, FEC, flow
control, storm control, switched or routed with an IPv4 address);
switch-wide, creating, naming and deleting VLANs, splitting a 100G port into
four and joining it again; and saving the configuration. Everything else
(mgmt0, a VLAN's own on/off state, accounts, other switch-wide settings)
stays refused by the switch itself, not just by NXray.

NX-API refuses the ";" these rules need, so the role is typed over SSH with
the admin login entered on the Switch page (``app/switch_ssh.py``). Checks
and saving go through NX-API. The admin login is used only inside
``enable_port_changes`` and never stored.

The role is named ``nxray-ports`` and is the same for every NXray install on
a switch, so a second install turning port changes on rewrites it with the
same rules.

NX-OS caches an account's roles in its NX-API session, which ends after
NX-API's idle timeout (``show nxapi``, 10 minutes by default). Until then the
account keeps its old permissions, so NXray stops calling the switch for that
long plus a minute. New rules in a role the account already has apply at
once, so an account that already had the role (port changes turned on
before VLAN changes existed) needs no wait. Both were measured on an
N9K-C92160YC-X with NX-OS 9.3(16).

``ROLE_VERSION`` counts the rule sets: 1 had the port rules only, 2 added
the VLAN rules, 3 the port settings rules. NXray stores the version it gave its account, so the
Switch page can offer the update when the code knows newer rules.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from app.nxapi import (
    PORT_CHANGES_ROLE,
    NxapiClient,
    NxapiError,
    SwitchTarget,
    validate_account_name,
    validate_port_name,
)
from app.switch import rows, to_int
from app.switch_connection import SWITCH_TIMEOUT
from app.switch_setup import SetupError, account_names, describe_error
from app.switch_ssh import (
    ShellOpener,
    SshAuthError,
    SshCommandError,
    SshError,
    run_config,
)

log = logging.getLogger("nxray.port_changes")

ROLE_NAME = PORT_CHANGES_ROLE

# How long one SSH step may stay silent before it counts as stuck.
SSH_TIMEOUT = 30.0

# Added to NX-API's idle timeout before NXray calls the switch again.
PAUSE_MARGIN_SECONDS = 60
DEFAULT_NXAPI_TIMEOUT_MINUTES = 10

# The role's command rules. "conf t ; interface * ; <cmd>" is how NX-OS
# names a command typed inside an interface's configuration; a rule without
# the "conf t ; interface *" part never matches there (checked on the switch).
ROLE_RULES = (
    "rule 1 permit command conf t ; interface * ; shutdown",
    "rule 2 permit command conf t ; interface * ; no shutdown",
    "rule 3 permit command conf t ; interface * ; description *",
    "rule 4 permit command conf t ; interface * ; no description",
    "rule 5 permit command copy running-config startup-config",
)

# VLAN rules, added in ROLE_VERSION 2. "conf t ; vlan * ; name *" also lets
# the account create a VLAN (entering a VLAN is allowed when a rule names a
# command inside it) but not shut one down or suspend it; a bare
# "conf t ; vlan *" would allow every VLAN setting. The "no switchport ..."
# forms are not needed: setting the default values back leaves a port's
# configuration as bare as removing them does (checked on the switch).
VLAN_RULES = (
    "rule 6 permit command conf t ; vlan * ; name *",
    "rule 7 permit command conf t ; no vlan *",
    "rule 8 permit command conf t ; interface * ; switchport mode *",
    "rule 9 permit command conf t ; interface * ; switchport access vlan *",
    "rule 10 permit command conf t ; interface * ; switchport trunk allowed vlan *",
    "rule 11 permit command conf t ; interface * ; switchport trunk native vlan *",
)

# Port settings rules, added in ROLE_VERSION 3. Each names one command
# with its value as "*", so the account can set these and nothing else
# inside a port. A storm-control level goes back to "no limit" by setting
# 100.00 (the switch's default), so only the action needs a "no" form. The
# breakout lines are typed outside any port: the role's port list does not
# cover them, so they are named on their own. The ports a split makes are not
# in the role's port list until it is updated (Switch page).
SETTINGS_RULES = (
    "rule 12 permit command conf t ; interface * ; speed *",
    "rule 13 permit command conf t ; interface * ; mtu *",
    "rule 14 permit command conf t ; interface * ; fec *",
    "rule 15 permit command conf t ; interface * ; flowcontrol receive *",
    "rule 16 permit command conf t ; interface * ; flowcontrol send *",
    "rule 17 permit command conf t ; interface * ; storm-control broadcast level *",
    "rule 18 permit command conf t ; interface * ; storm-control multicast level *",
    "rule 19 permit command conf t ; interface * ; storm-control unicast level *",
    "rule 20 permit command conf t ; interface * ; storm-control action *",
    "rule 21 permit command conf t ; interface * ; no storm-control action *",
    "rule 22 permit command conf t ; interface * ; switchport",
    "rule 23 permit command conf t ; interface * ; no switchport",
    "rule 24 permit command conf t ; interface * ; ip address *",
    "rule 25 permit command conf t ; interface * ; no ip address *",
    "rule 26 permit command conf t ; interface breakout module * port * map *",
    "rule 27 permit command conf t ; no interface breakout module * port * map *",
)

ROLE_VERSION = 3


@dataclass(frozen=True)
class EnableResult:
    pause_seconds: int
    port_count: int
    config_saved: bool
    save_error: str | None
    # True when the account already had the role, so only its rules changed.
    had_role: bool = False


def front_ports(interface_brief_body: dict) -> list[str]:
    """Every front-panel Ethernet port name in ``show interface brief``."""
    names = []
    for row in rows(interface_brief_body, "TABLE_interface", "ROW_interface"):
        name = str(row.get("interface", ""))
        try:
            names.append(validate_port_name(name))
        except ValueError:
            continue
    return names


def role_lines(ports: list[str], account_name: str) -> list[str]:
    """The configuration lines that create the role and give it to the account.

    Typed after ``configure terminal``. Every value is checked first, so the
    lines can only ever be these.
    """
    validate_account_name(account_name)
    if not ports:
        raise ValueError("the switch reported no front-panel ports")
    permits = [f"permit interface {validate_port_name(port)}" for port in ports]
    return [
        f"role name {ROLE_NAME}",
        "description NXray: front ports, their settings, VLANs, save config",
        *ROLE_RULES,
        *VLAN_RULES,
        *SETTINGS_RULES,
        "interface policy deny",
        *permits,
        "exit",
        "exit",
        f"username {account_name} role {ROLE_NAME}",
    ]


def account_roles(user_account_body: dict, account_name: str) -> set[str]:
    """The roles ``show user-account`` lists for one account."""
    for row in rows(user_account_body, "TABLE_template", "ROW_template"):
        if str(row.get("usr_name", "")).lower() == account_name.lower():
            return {
                str(role.get("role", ""))
                for role in rows(row, "TABLE_role", "ROW_role")
                if role.get("role")
            }
    return set()


def pause_seconds(nxapi_body: dict) -> int:
    """NX-API's idle timeout from ``show nxapi``, in seconds, plus the margin."""
    minutes = to_int(nxapi_body.get("timeout")) or DEFAULT_NXAPI_TIMEOUT_MINUTES
    return max(minutes, 1) * 60 + PAUSE_MARGIN_SECONDS


def _scrub(text: str, secret: str) -> str:
    return text.replace(secret, "***") if secret else text


def enable_port_changes(
    *,
    host: str,
    nxapi_port: int,
    ssh_port: int,
    admin_user: str,
    admin_password: str,
    account_name: str,
    transport: httpx.BaseTransport | None = None,
    ssh_opener: ShellOpener | None = None,
) -> EnableResult:
    """Create the role over SSH, give it to NXray's account, check it, save the config.

    Raises SetupError with a message for the page when it stops.
    """
    admin = SwitchTarget(
        host=host,
        port=nxapi_port,
        username=admin_user,
        password=admin_password,
        timeout=SWITCH_TIMEOUT,
    )
    with NxapiClient(admin, transport=transport) as client:
        try:
            brief, users, nxapi = client.show(
                "show interface brief", "show user-account", "show nxapi"
            )
        except NxapiError as exc:
            raise SetupError(
                _scrub(describe_error(exc, host, nxapi_port, "admin"), admin_password)
            ) from exc
        if account_name.lower() not in account_names(users):
            raise SetupError(
                f"NXray's account {account_name} is no longer on the switch. Press Run "
                "setup again on the Switch page: it makes the account again."
            )
        had_role = ROLE_NAME in account_roles(users, account_name)
        ports = front_ports(brief)
        lines = role_lines(ports, account_name)

        try:
            run_config(
                host=host,
                port=ssh_port,
                username=admin_user,
                password=admin_password,
                lines=lines,
                timeout=SSH_TIMEOUT,
                opener=ssh_opener,
            )
        except SshAuthError as exc:
            raise SetupError("The switch refused the admin username or password over SSH.") from exc
        except SshCommandError as exc:
            raise SetupError(
                _scrub(f"The switch refused a line while creating the role: {exc}", admin_password)
            ) from exc
        except SshError as exc:
            raise SetupError(
                _scrub(
                    f"NXray could not reach the switch over SSH at {host}, port {ssh_port}. "
                    "Check that SSH is on and that this machine can reach it. "
                    f"Details: {exc}",
                    admin_password,
                )
            ) from exc
        log.info(
            "%s switch account %s the %s role (version %d) on %s",
            "updated" if had_role else "gave",
            account_name,
            ROLE_NAME,
            ROLE_VERSION,
            host,
        )
        # Rules added to a role the account already has apply at once.
        wait = 0 if had_role else pause_seconds(nxapi)

        try:
            (users,) = client.show("show user-account")
        except NxapiError as exc:
            raise SetupError(
                _scrub(describe_error(exc, host, nxapi_port, "admin"), admin_password)
            ) from exc
        if ROLE_NAME not in account_roles(users, account_name):
            raise SetupError(
                f"The switch accepted the commands, but {account_name} does not have the "
                f"{ROLE_NAME} role. Nothing was saved."
            )

        try:
            client.save_config()
        except NxapiError as exc:
            log.warning("switch config not saved after adding %s: %s", ROLE_NAME, exc)
            return EnableResult(wait, len(ports), False, _scrub(str(exc), admin_password), had_role)

    log.info("saved the switch configuration on %s", host)
    return EnableResult(wait, len(ports), True, None, had_role)
