"""Turning on port changes: give NXray's switch account a role that allows them.

The role allows exactly these, on the front-panel Ethernet ports only:
turning a port on or off, setting or removing its description, and saving
the configuration. Everything else (mgmt0, speed, MTU, VLANs, accounts,
switch-wide settings) stays refused by the switch itself, not just by NXray.

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
long plus a minute. The wait was measured on an N9K-C92160YC-X with NX-OS
9.3(16).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from app.nxapi import (
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

ROLE_NAME = "nxray-ports"

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


@dataclass(frozen=True)
class EnableResult:
    pause_seconds: int
    port_count: int
    config_saved: bool
    save_error: str | None


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
        "description NXray: turn front ports on or off, edit descriptions, save config",
        *ROLE_RULES,
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
                f"NXray's account {account_name} is no longer on the switch. Forget this "
                "switch and set it up again."
            )
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
        log.info("gave switch account %s the %s role on %s", account_name, ROLE_NAME, host)

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
            return EnableResult(
                pause_seconds(nxapi), len(ports), False, _scrub(str(exc), admin_password)
            )

    log.info("saved the switch configuration on %s", host)
    return EnableResult(pause_seconds(nxapi), len(ports), True, None)
