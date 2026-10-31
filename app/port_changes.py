"""Turning on port changes: give NXray's switch account a role that allows them.

The role allows exactly these: on the front-panel Ethernet ports only,
turning a port on or off, setting or removing its description, setting its
mode (access or trunk) and VLANs, and its settings (speed, MTU, FEC, flow
control, storm control, switched or routed with an IPv4 address),
turning CDP and LLDP on or off on them, and putting them into port-channels
and taking them out again, with their LACP rate and priority, and their IPv4
and IPv6 addresses when routed; on the port-channels, the same settings plus
their description and LACP minimum links, and deleting them; on the VLAN
interfaces, making and deleting them, their addresses, description, MTU and
on/off; the VRFs, making and deleting them and moving VLAN interfaces and
routed ports between them; switch-wide, creating, naming and deleting VLANs,
splitting a 100G port into four and joining it again, turning switch
features on and off, setting how long learned MAC addresses are kept,
adding and removing static MAC addresses, clearing learned ones, and the
switch's LACP priority; and saving the configuration. Everything else
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

When the role gains the port-channels (``CHANNEL_PERMIT``) or the VLAN
interfaces (``VLAN_INTERFACE_PERMIT``), NXray checks the role and saves the
configuration over SSH instead of over NX-API: on that switch NX-API stopped
answering every account for 10 to 15 minutes right after such a line was
typed (once for the port-channels, once for the VLAN interfaces), while SSH
kept working. The cause was not confirmed (a later port-channel change went
through with NX-API answering at once), so NXray adds no wait for it.

``ROLE_VERSION`` counts the rule sets: 1 had the port rules only, 2 added
the VLAN rules, 3 the port settings rules, 4 the feature rules, 5 the
neighbor rules (CDP, LLDP and the MAC address table), 6 the port-channel
rules and the port-channels in the role's port list, 7 the VLAN interface
rules and the VLAN interfaces in the port list, 8 the VRF rules.

The switch knows the ``Vlan`` interface type only while the interface-vlan
feature is on: with it off, ``VLAN_INTERFACE_PERMIT`` is refused
("Invalid interface format"). So the port list names the VLAN interfaces only
when the feature is on; once an admin turns it on, Update the port list adds
them. NXray
stores the version it gave its account, so the
Switch page can offer the update when the code knows newer rules.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import httpx

from app.features import feature_states
from app.nxapi import (
    PORT_CHANGES_ROLE,
    VLAN_INTERFACE_MAX,
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
    run_commands,
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

# Feature rules, added in ROLE_VERSION 4: "feature <name>" and "no feature
# <name>", typed in configuration mode. Proven on cisco-25gb (2026-10-30)
# with a throwaway account holding only these two rules: it turned the
# scheduler feature on and off over NX-API and was refused everything else.
# NXray itself never turns off NX-API or SSH (NxapiClient.set_feature).
FEATURE_RULES = (
    "rule 28 permit command conf t ; feature *",
    "rule 29 permit command conf t ; no feature *",
)

# Neighbor rules, added in ROLE_VERSION 5: CDP and LLDP per port, the MAC
# address aging time, static MAC addresses and clearing learned ones. Proven on
# cisco-25gb (2026-10-30) with a throwaway account holding the CDP, MAC table
# and clearing rules: each worked over NX-API on the one port its role named.
# The static entry's port is checked by NXray (NxapiClient.add_static_mac takes
# front ports only). The LLDP lines need the lldp feature on and were not
# tried on the switch. Clearing is not a configuration command, so its rule has
# no "conf t"; the bare form clears every learned address.
NEIGHBOR_RULES = (
    "rule 30 permit command conf t ; interface * ; cdp enable",
    "rule 31 permit command conf t ; interface * ; no cdp enable",
    "rule 32 permit command conf t ; interface * ; lldp transmit",
    "rule 33 permit command conf t ; interface * ; no lldp transmit",
    "rule 34 permit command conf t ; interface * ; lldp receive",
    "rule 35 permit command conf t ; interface * ; no lldp receive",
    "rule 36 permit command conf t ; mac address-table aging-time *",
    "rule 37 permit command conf t ; mac address-table static *",
    "rule 38 permit command conf t ; no mac address-table static *",
    "rule 39 permit command clear mac address-table dynamic",
    "rule 40 permit command clear mac address-table dynamic *",
)

# Port-channel rules, added in ROLE_VERSION 6, with every port-channel added
# to the role's port list (CHANNEL_PERMIT). Proven on cisco-25gb (2026-10-30)
# with a throwaway account on two unused ports: "channel-group" on a port
# creates the port-channel even without CHANNEL_PERMIT, but its description,
# minimum links and "no interface port-channel" are "Interface permission
# denied" until the role names port-channels, and that line is taken only
# inside "interface policy deny" (stored as one line). Naming port-channels
# also lets rules 1-27 act on them, as on the front ports. The switch-wide
# "lacp system-priority" line was not tried on the switch: it makes every
# LACP port-channel negotiate again.
CHANNEL_RULES = (
    "rule 41 permit command conf t ; interface * ; channel-group *",
    "rule 42 permit command conf t ; interface * ; no channel-group",
    "rule 43 permit command conf t ; interface * ; lacp rate *",
    "rule 44 permit command conf t ; interface * ; lacp port-priority *",
    "rule 45 permit command conf t ; interface * ; lacp min-links *",
    "rule 46 permit command conf t ; no interface port-channel *",
    "rule 47 permit command conf t ; lacp system-priority *",
)
CHANNEL_PERMIT = "permit interface port-channel1-4096"

# VLAN interface rules, added in ROLE_VERSION 7, with every VLAN interface added
# to the role's port list (VLAN_INTERFACE_PERMIT). Proven on cisco-25gb
# (2026-10-30) with a throwaway account: without the permit the switch refuses
# "interface vlan<n>"; with it, rules 1-4, 13, 24 and 25 act on VLAN interfaces
# (on/off, description, MTU, IPv4 addresses, secondary ones too), and the two
# IPv6 rules below put IPv6 addresses on them and on routed ports. Deleting one
# needs the rule written exactly as below: "no interface vlan *" and
# "no interface vlan*" never matched "no interface vlan3900", "no interface
# Vlan *" matched every way of typing it.
LAYER3_RULES = (
    "rule 48 permit command conf t ; interface * ; ipv6 address *",
    "rule 49 permit command conf t ; interface * ; no ipv6 address *",
    "rule 50 permit command conf t ; no interface Vlan *",
)
# One range, which the switch stores as one line per VLAN interface, so it stays
# small (see VLAN_INTERFACE_MAX).
VLAN_INTERFACE_PERMIT = f"permit interface Vlan1-{VLAN_INTERFACE_MAX}"

# VRF rules, added in ROLE_VERSION 8. Proven on cisco-25gb (2026-10-30) with a
# throwaway account: "vrf context <name>" made a VRF and "no vrf context"
# deleted it, and on a permitted port "vrf member" and "no vrf member" moved
# it into the VRF and out again. Entering a VRF's configuration (which makes
# it) is allowed when a rule names a command inside it, as with VLANs: rule 51
# is there for that. NXray sends no VRF description, since no show command
# its account may run lists one. The port list stays as it was, so this needs
# no SSH save and no wait.
VRF_RULES = (
    "rule 51 permit command conf t ; vrf context * ; description *",
    "rule 52 permit command conf t ; no vrf context *",
    "rule 53 permit command conf t ; interface * ; vrf member *",
    "rule 54 permit command conf t ; interface * ; no vrf member *",
)

# Role versions whose port list gained a line, and so are checked and saved
# over SSH (see the module notes): accounts below this one get one.
LAST_PERMIT_VERSION = 7

ROLE_VERSION = 8

# What each role version added, for the Switch page's button names.
_ADDED_BY_VERSION = {
    2: "VLAN",
    3: "port settings",
    4: "feature",
    5: "neighbor",
    6: "port-channel",
    7: "VLAN interface",
    8: "VRF",
}


def missing_changes(role_version: int) -> str:
    """The kinds of change a role of ``role_version`` lacks, in words.

    ``missing_changes(4)`` is "neighbor and port-channel changes"; "" when
    nothing is missing.
    """
    names = [name for version, name in _ADDED_BY_VERSION.items() if version > role_version]
    if not names:
        return ""
    if len(names) == 1:
        return f"{names[0]} changes"
    return f"{', '.join(names[:-1])} and {names[-1]} changes"


@dataclass(frozen=True)
class EnableResult:
    pause_seconds: int
    port_count: int
    config_saved: bool
    save_error: str | None
    # True when the account already had the role, so only its rules changed.
    had_role: bool = False
    # True when the role's port list names the VLAN interfaces (interface-vlan on).
    vlan_interfaces: bool = False


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


def role_lines(ports: list[str], account_name: str, vlan_interfaces: bool = True) -> list[str]:
    """The configuration lines that create the role and give it to the account.

    Typed after ``configure terminal``. Every value is checked first, so the
    lines can only ever be these. ``vlan_interfaces`` adds the VLAN interfaces
    to the port list; the switch refuses that line while interface-vlan is off.
    """
    validate_account_name(account_name)
    if not ports:
        raise ValueError("the switch reported no front-panel ports")
    permits = [f"permit interface {validate_port_name(port)}" for port in ports]
    return [
        f"role name {ROLE_NAME}",
        "description NXray: ports, port-channels, VLANs, layer 3, features, MAC, save",
        *ROLE_RULES,
        *VLAN_RULES,
        *SETTINGS_RULES,
        *FEATURE_RULES,
        *NEIGHBOR_RULES,
        *CHANNEL_RULES,
        *LAYER3_RULES,
        *VRF_RULES,
        "interface policy deny",
        *permits,
        CHANNEL_PERMIT,
        *([VLAN_INTERFACE_PERMIT] if vlan_interfaces else []),
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


SAVE_COMMAND = "copy running-config startup-config"


def _check_role_output(roles_output: str, account_name: str) -> None:
    """Stop unless ``show user-account <name>`` (typed over SSH) lists the role."""
    if not re.search(rf"(?<![\w-]){re.escape(ROLE_NAME)}(?![\w-])", roles_output):
        raise SetupError(
            f"The switch accepted the commands, but {account_name} does not have the "
            f"{ROLE_NAME} role. Nothing was saved."
        )


def _saved_over_ssh(
    ssh: dict, admin_password: str, port_count: int, had_role: bool, wait: int, vlans: bool
) -> EnableResult:
    """Save the configuration over SSH, and the result."""
    try:
        (output,) = run_commands(lines=(SAVE_COMMAND,), **ssh)
    except SshError as exc:
        output = _scrub(str(exc), admin_password)
    if "Copy complete" not in output:
        log.warning("switch config not saved after adding %s: %s", ROLE_NAME, output)
        return EnableResult(wait, port_count, False, output or "no answer", had_role, vlans)
    log.info("saved the switch configuration over SSH")
    return EnableResult(wait, port_count, True, None, had_role, vlans)


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
    role_version: int = 0,
    vlan_interfaces_listed: bool = False,
    transport: httpx.BaseTransport | None = None,
    ssh_opener: ShellOpener | None = None,
) -> EnableResult:
    """Create the role over SSH, give it to NXray's account, check it, save the config.

    ``role_version`` is the version NXray gave its account before (0 for
    none). Below ``LAST_PERMIT_VERSION`` the role's port list gains a line,
    and so does it when interface-vlan is on and ``vlan_interfaces_listed``
    (the port list names the VLAN interfaces already) is false; then the
    check and the save go over SSH, which does not depend on NX-API answering.
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
            brief, users, nxapi, features = client.show(
                "show interface brief", "show user-account", "show nxapi", "show feature"
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
        vlans = feature_states(features).get("interface-vlan", False)
        lines = role_lines(ports, account_name, vlan_interfaces=vlans)
        over_ssh = role_version < LAST_PERMIT_VERSION or (vlans and not vlan_interfaces_listed)
        then = (f"show user-account {account_name}",) if over_ssh else ()

        try:
            outputs = run_config(
                host=host,
                port=ssh_port,
                username=admin_user,
                password=admin_password,
                lines=lines,
                timeout=SSH_TIMEOUT,
                opener=ssh_opener,
                then=then,
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
        if over_ssh:
            _check_role_output(outputs[0], account_name)
            ssh = {
                "host": host,
                "port": ssh_port,
                "username": admin_user,
                "password": admin_password,
                "timeout": SSH_TIMEOUT,
                "opener": ssh_opener,
            }
            return _saved_over_ssh(ssh, admin_password, len(ports), had_role, wait, vlans)

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
                wait, len(ports), False, _scrub(str(exc), admin_password), had_role, vlans
            )

    log.info("saved the switch configuration on %s", host)
    return EnableResult(wait, len(ports), True, None, had_role, vlans)
