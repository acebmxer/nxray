"""VM Tracker: the switch signs in to VMware vCenter and learns which virtual machines sit
behind which of its ports, and (with automatic VLANs on) makes the VLANs those VMs need on
those ports and removes them when the VMs leave.

A **connection** is one vCenter (up to four): its address, port and VRF (``remote ip address
<a> port <p> vrf <v>``), the vCenter account the switch signs in with (``username <u>
password 0 <p>``), ``connect`` to start, how often it looks for new hosts and syncs
everything (``set interval find-new-host|sync-full-info|pending-task-polling``), whether it
makes VLANs (``autovlan enable``, on by default) and which ones it may make
(``allowed-vlans``). Per port, ``no vmtracker enable`` keeps VM Tracker off a port; ``vmtracker
fabric auto-config`` hands the VLANs to the fabric's auto-configuration instead. ``vmtracker
connection <name> refresh`` syncs a connection now.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (the whole switch, a connection, a port, and syncing a
connection), each setting the one line it sends with checked values in its blanks, and
``build_change`` building the lines. ``NxapiClient.configure_vmtracker`` sends them. The
vCenter password is typed in the clear (``password 0``), stored by the switch encrypted
(``password 5``) and never shown back, as the AAA page does with server keys.

Read from the switch: ``show feature`` and ``show interface brief`` in one request; while
the feature is on, ``show vmtracker status``, then ``show vmtracker info detail`` and ``show
running-config`` as text.

Tried on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-13) with a throwaway
connection to a documentation address, all removed afterwards; there is no vCenter there,
so ``connect`` and syncing with one were not tried, and the VM table follows the guide's
columns (Interface, Host, VMNIC, VM, State, PortGroup, VLAN-Range) without having been
seen. Taken: ``remote ip address <a> port <1-65355> vrf <v>`` (one line, ``remote port`` and
``remote vrf`` change their part), ``username <u> password [0] <p>`` (no switch account is
made), ``no username <u> password <any word>``, ``set interval find-new-host|sync-full-info
<0-65355>`` and ``pending-task-polling <1-65355>`` with their ``no`` forms (which take any
value), ``set extension-key <key>`` (never shown back) and its ``no`` form, ``no autovlan
enable`` (``autovlan enable`` is the default and is not written), ``allowed-vlans <list>``,
``allowed-vlans except <list>`` and ``allowed-vlans all``, ``no vmtracker enable`` on a port,
and ``vmtracker fabric auto-config`` once ``feature fabric forwarding`` was on (refused
without: "Verify feature fabric forwarding is enabled before enabling auto-config");
``vmtracker connection <name> refresh`` answered "ERROR: failure" with no vCenter. The switch
refuses every ``no remote`` form ("Please specify IP and Port together"), so the address is
changed, never removed; ``remote hostname`` was refused, so only an address is offered;
``allowed-vlans add|remove`` start from every VLAN there (``add`` after a list allows them
all), so they are not offered; ``no allowed-vlans`` is not a command. ``vmtracker set
device-id`` is in the switch's command list, but neither the guide nor the switch says what
it takes: not offered.

Syncing now is typed outside configuration mode, which NXray's broad role allows from
version ``BROAD_VMTRACKER_VERSION`` (rule 34); a broad role written before needs Update the
port list first.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.features import feature_states
from app.monitor import all_port_names
from app.nxapi import NxapiClient, NxapiCommandError
from app.protocols import (
    Field,
    Instance,
    Protocol,
    ProtocolChange,
    ProtocolView,
    Scope,
    Setting,
    Table,
    build_change,
    check_value,
    port_field,
    table_rows,
)
from app.routing import long_name
from app.switch import text
from app.vxlan import parse_vxlan_config

FEATURE = "vmtracker"
PAGE_COMMANDS = ("show feature", "show interface brief")
STATUS_COMMAND = "show vmtracker status"
INFO_COMMAND = "show vmtracker info detail"
CONFIG_COMMAND = "show running-config"
CONNECTIONS_MAX = 4  # vCenter connections, as Cisco's guide says
NUMBER_MAX = 65355  # the switch's own top for ports and intervals (sic)


def _name() -> Field:
    return Field(
        "name",
        "Connection",
        "name",
        maximum=32,
        hint="A name for this vCenter, such as vcenter1",
        placeholder="vcenter1",
    )


def _seconds(low: int, hint: str) -> Field:
    return Field("seconds", "Seconds", "int", minimum=low, maximum=NUMBER_MAX, hint=hint)


def _interval(key: str, label: str, word: str, low: int, hint: str, help_text: str) -> Setting:
    return Setting(
        key,
        label,
        f"set interval {word} {{seconds}}",
        (_seconds(low, hint),),
        group="Timers",
        help=help_text,
    )


def _vlans(label: str = "VLANs") -> Field:
    return Field("vlans", label, "vlans", placeholder="100-199,300")


# ---- the whole switch ------------------------------------------------------------------------

_GLOBAL = Scope(
    key="global",
    label="Whole switch",
    ident=(),
    enter=(),
    help="VM Tracker for every connection.",
    settings=(
        Setting(
            "auto_config",
            "Fabric auto-configuration",
            "vmtracker fabric auto-config",
            group="Fabric",
            help="Hand the VLANs VM Tracker finds to the fabric's auto-configuration. It needs "
            "fabric forwarding on (Features page).",
        ),
    ),
)

# ---- a vCenter connection ----------------------------------------------------------------------

_CONNECTION = Scope(
    key="connection",
    label="vCenter connection",
    ident=(_name(),),
    enter=("vmtracker connection {name}",),
    create=True,
    create_label="Add a vCenter connection",
    delete=("no vmtracker connection {name}",),
    delete_warning="The switch stops following this vCenter's VMs.",
    help=f"Up to {CONNECTIONS_MAX} vCenters. Give the address and the login, then connect.",
    settings=(
        Setting(
            "remote",
            "vCenter address",
            "remote ip address {address}[ port {port}][ vrf {vrf}]",
            (
                Field("address", "Address", "ipv4", placeholder="192.0.2.50"),
                Field(
                    "port",
                    "Port",
                    "int",
                    minimum=1,
                    maximum=NUMBER_MAX,
                    optional=True,
                    hint="vCenter's web port, such as 443",
                ),
                Field(
                    "vrf",
                    "VRF",
                    "name",
                    optional=True,
                    hint="Where vCenter is reached: management, default or a VRF on the "
                    "Routing page",
                    placeholder="management",
                ),
            ),
            removable=False,
            group="vCenter",
            help="The switch keeps an address once it has one: set a new one to change it.",
        ),
        Setting(
            "login",
            "vCenter login",
            "username {user} password 0 {password}",
            (
                Field(
                    "user",
                    "User",
                    "account",
                    placeholder="administrator@vsphere.local",
                ),
                Field("password", "Password", "secret", hint="Never shown back"),
            ),
            no_line="no username {user} password removed",
            group="vCenter",
            help="The vCenter account the switch signs in with; read-only rights are enough "
            "to follow the VMs.",
        ),
        Setting(
            "connect",
            "Connected",
            "connect",
            group="vCenter",
            help="Sign in to vCenter and start following its VMs. Remove disconnects.",
        ),
        Setting(
            "extension_key",
            "Extension key",
            "set extension-key {key}",
            (Field("key", "Key", "name", maximum=63, hint="The switch never shows it"),),
            group="vCenter",
            help="The key vCenter knows this switch by, when vCenter asks for one. Removing "
            "it needs the key typed again.",
        ),
        _interval(
            "find_new_host",
            "Look for new hosts every",
            "find-new-host",
            0,
            "Default 3600",
            "How often the switch asks vCenter for hosts newly plugged in.",
        ),
        _interval(
            "sync_full_info",
            "Full sync every",
            "sync-full-info",
            0,
            "Default 3600",
            "How often the switch reads every host, VM and port group again.",
        ),
        _interval(
            "pending_task_polling",
            "Check pending tasks every",
            "pending-task-polling",
            1,
            "1 or more",
            "How often the switch checks the vCenter tasks it is waiting on.",
        ),
        Setting(
            "autovlan",
            "Make VLANs by itself",
            "autovlan enable",
            no_line="no autovlan enable",
            group="VLANs",
            help="Make the VLANs the VMs need on their ports, and remove them when the VMs "
            "go. On by default; Remove turns it off.",
        ),
        Setting(
            "allowed_vlans",
            "Only these VLANs",
            "allowed-vlans {vlans}",
            (_vlans(),),
            removable=False,
            group="VLANs",
            help="The VLANs it may make. Every VLAN by default.",
        ),
        Setting(
            "allowed_except",
            "Every VLAN except",
            "allowed-vlans except {vlans}",
            (_vlans("VLANs left out"),),
            removable=False,
            group="VLANs",
        ),
        Setting(
            "allowed_all",
            "Every VLAN",
            "allowed-vlans all",
            removable=False,
            group="VLANs",
        ),
    ),
)

# ---- a port ------------------------------------------------------------------------------------

_PORT = Scope(
    key="port",
    label="Port",
    ident=(port_field(),),
    enter=("interface {port}",),
    help="VM Tracker runs on every port unless it is turned off there. Cisco asks for no "
    "switchport or VLAN changes by hand on a port it runs on.",
    settings=(
        Setting(
            "tracking",
            "VM Tracker on this port",
            "vmtracker enable",
            no_line="no vmtracker enable",
            group="Port",
            help="On by default; Remove turns it off on this port.",
        ),
    ),
)

# ---- syncing now -------------------------------------------------------------------------------

_SYNC = Scope(
    key="sync",
    label="Sync now",
    ident=(_name(),),
    enter=(),
    help="Read the connection's hosts, VMs and port groups from vCenter now, not at the next "
    "full sync. Nothing here is saved.",
    settings=(
        Setting(
            "refresh",
            "Sync now",
            "vmtracker connection {name} refresh",
            removable=False,
            config=False,
            ident=("name",),
            group="Sync",
        ),
    ),
)

SCOPES = (_GLOBAL, _CONNECTION, _PORT, _SYNC)


# ---- reading -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class VmtrackerConfig:
    """What ``show running-config`` says about VM Tracker."""

    auto_config: bool
    connections: dict[str, dict[str, dict[str, str]]]  # name -> setting values
    passwords: frozenset[str]  # the connections with a login password
    ports_off: tuple[str, ...]  # ports with ``no vmtracker enable``


def _connection_values(lines: list[str]) -> tuple[dict[str, dict[str, str]], bool]:
    values: dict[str, dict[str, str]] = {"autovlan": {}}
    password = False
    for line in lines:
        if match := re.fullmatch(r"remote ip address (\S+)(?: port (\d+))?(?: vrf (\S+))?", line):
            address, port, vrf = match.groups()
            values["remote"] = {"address": address, "port": port or "", "vrf": vrf or ""}
        elif match := re.fullmatch(r"remote vrf (\S+)", line):
            values.setdefault("remote", {"address": "", "port": ""})["vrf"] = match.group(1)
        elif match := re.fullmatch(r"username (\S+)(?: password .+)?", line):
            values["login"] = {"user": match.group(1)}
            password = " password " in line
        elif line == "connect":
            values["connect"] = {}
        elif match := re.fullmatch(
            r"set interval (find-new-host|sync-full-info|pending-task-polling) (\d+)", line
        ):
            values[match.group(1).replace("-", "_")] = {"seconds": match.group(2)}
        elif line == "no autovlan enable":
            values.pop("autovlan", None)
        elif match := re.fullmatch(r"allowed-vlans (\S+)", line):
            values["allowed_vlans"] = {"vlans": match.group(1)}
    return values, password


def parse_vmtracker_config(config: str) -> VmtrackerConfig:
    """The VM Tracker lines of ``show running-config``."""
    tree = parse_vxlan_config(config)
    auto = False
    connections: dict[str, dict[str, dict[str, str]]] = {}
    passwords = set()
    ports_off = []
    for line in tree.children():
        if line == "vmtracker fabric auto-config":
            auto = True
        elif match := re.fullmatch(r"vmtracker connection (\S+)", line):
            values, password = _connection_values(tree.children(line))
            connections[match.group(1)] = values
            if password:
                passwords.add(match.group(1))
        elif line.startswith("interface ") and "no vmtracker enable" in tree.children(line):
            ports_off.append(line.split(" ", 1)[1])
    return VmtrackerConfig(auto, connections, frozenset(passwords), tuple(ports_off))


def parse_status(body: Any) -> dict[str, tuple[str, str]]:
    """``show vmtracker status``: each connection's vCenter address and state."""
    return {
        text(row.get("name")): (text(row.get("host_or_ip")), text(row.get("conn_status")))
        for row in table_rows(body, "TABLE_connection", "ROW_connection")
        if text(row.get("name"))
    }


_INFO_COLUMNS = ("Interface", "Host", "VMNIC", "VM", "State", "PortGroup", "VLAN-Range")


def parse_vm_info(output: str | None) -> list[tuple[str, ...]]:
    """``show vmtracker info detail`` as text: (port, host, VMNIC, VM, state, port group,
    VLANs), from the rows under its ``Interface  Host  VMNIC  VM  State  PortGroup
    VLAN-Range`` heading. The port, host and host NIC hold no space; after them, columns are
    told apart by two or more spaces, since a VM's or port group's name may hold one."""
    rows = []
    started = False
    for line in (output or "").splitlines():
        stripped = line.strip()
        if stripped.split()[:2] == ["Interface", "Host"]:
            started = True
            continue
        if not started or not stripped or set(stripped) <= {"-"}:
            continue
        cells = re.split(r"\s{2,}", stripped)
        fixed: list[str] = []
        while cells and len(fixed) < 3:
            fixed += cells.pop(0).split()
        if len(fixed) > 3:
            cells.insert(0, " ".join(fixed[3:]))
        if len(fixed) >= 3 and len(cells) == len(_INFO_COLUMNS) - 3:
            rows.append((long_name(fixed[0]), fixed[1], fixed[2], *cells))
    return rows


def _facts(
    values: dict[str, dict[str, str]], status: tuple[str, str] | None, password: bool
) -> tuple[tuple[str, str], ...]:
    remote = values.get("remote", {})
    where = remote.get("address") or (status[0] if status else "") or "not set"
    if remote.get("port"):
        where += f" port {remote['port']}"
    login = values.get("login", {}).get("user")
    facts = [
        ("vCenter", where),
        ("VRF", remote.get("vrf") or "default"),
        ("State", status[1] if status else "not reported"),
        ("Login", f"{login} (password set)" if login and password else login or "not set"),
        ("Connect", "yes" if "connect" in values else "no"),
        ("Makes VLANs", "yes" if "autovlan" in values else "no"),
        ("Allowed VLANs", values.get("allowed_vlans", {}).get("vlans", "all")),
    ]
    for key, label in (
        ("find_new_host", "New hosts every"),
        ("sync_full_info", "Full sync every"),
        ("pending_task_polling", "Pending tasks every"),
    ):
        seconds = values.get(key, {}).get("seconds")
        facts.append((label, f"{seconds} seconds" if seconds else "default"))
    return tuple(facts)


def parse_vmtracker(
    config: str | None, status: Any = None, info: str | None = None
) -> ProtocolView:
    """The page from the configuration text (None: not shown), ``show vmtracker status`` and
    the VM text (None: not shown)."""
    states = parse_status(status)
    found = parse_vmtracker_config(config or "")
    instances = [
        Instance(
            "global",
            {},
            "Whole switch",
            (("Fabric auto-configuration", "on" if found.auto_config else "off"),),
            {"auto_config": {}} if found.auto_config else {},
        )
    ]
    names = list(dict.fromkeys([*found.connections, *states]))
    for name in names:
        values = found.connections.get(name, {})
        instances.append(
            Instance(
                "connection",
                {"name": name},
                name,
                _facts(values, states.get(name), name in found.passwords),
                values,
            )
        )
    for port in found.ports_off:
        instances.append(Instance("port", {"port": port}, port, (("VM Tracker", "off"),), {}))
    for name in names:
        instances.append(Instance("sync", {"name": name}, name))
    notes = []
    if config is None:
        notes.append(
            "The switch did not show its configuration to NXray's account: the connections' "
            "settings and the ports VM Tracker is off on are not listed."
        )
    tables = (
        Table(
            "Connections",
            ("Connection", "vCenter", "State"),
            tuple((name, *states[name]) for name in states),
            empty="No vCenter connection yet.",
        ),
        Table(
            "Virtual machines",
            ("Port", "Host", "Host NIC", "VM", "State", "Port group", "VLANs"),
            tuple(parse_vm_info(info)),
            empty="No VM seen yet: the switch learns them once it is connected to vCenter."
            if info is not None
            else "The switch did not report its VMs.",
            wrap_column=3,
        ),
    )
    return ProtocolView(tuple(instances), tables, tuple(notes))


VMTRACKER = Protocol(
    key="vmtracker",
    name="VM Tracker",
    summary="Which VMware virtual machines sit behind which port, learned from vCenter",
    features=(FEATURE,),
    commands=(),
    parse=lambda bodies: parse_vmtracker(None),
    scopes=SCOPES,
    about=(
        "Add a vCenter with its address and a login, then connect: the switch lists the "
        "VMs on each port, and makes the VLANs they need there while Make VLANs by itself "
        "is on. Hosts must plug straight into the switch (or a FEX). On a vPC pair, give "
        "both switches the same connection."
    ),
)


@dataclass(frozen=True)
class VmtrackerPage:
    """Everything the VM Tracker page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # the front ports and port-channels
    problem: str = ""
    missing: tuple[str, ...] = ()  # the vmtracker feature, when it is off


def load_vmtracker_page(client: NxapiClient) -> VmtrackerPage:
    """One request for the features and ports; while VM Tracker is on, its status, the VMs
    as text and the configuration text."""
    feature, brief = client.show(*PAGE_COMMANDS)
    ports = all_port_names(brief or {})
    if not feature_states(feature).get(FEATURE, False):
        return VmtrackerPage(VMTRACKER, ProtocolView(), ports, missing=(FEATURE,))
    problem = ""
    try:
        (status,) = client.show(STATUS_COMMAND)
    except NxapiCommandError as exc:
        status, problem = None, f"The switch did not report its vCenter connections: {exc}"
    try:
        info: str | None = client.show_text(INFO_COMMAND)
    except NxapiCommandError:
        info = None
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = None
    return VmtrackerPage(VMTRACKER, parse_vmtracker(config, status, info), ports, problem)


def check_vmtracker_place(page: VmtrackerPage, ident: dict[str, str]) -> None:
    """Refuse a port the switch does not have (unless the page lists it, so it can still be
    turned back on) and a fifth connection."""
    try:
        port = check_value(port_field(), ident.get("port", "")) if ident.get("port") else ""
        name = check_value(_name(), ident.get("name", "")) if ident.get("name") else ""
    except ValueError:
        return  # build_change names the field
    listed = {i.ident.get("port") for i in page.view.of("port")}
    if port and port not in page.ports and port not in listed:
        raise ValueError(f"the switch has no port {port}")
    known = {i.ident["name"] for i in page.view.of("connection")}
    if name and name not in known and len(known) >= CONNECTIONS_MAX:
        raise ValueError(f"the switch takes {CONNECTIONS_MAX} vCenter connections at most")


def build_vmtracker_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the VM Tracker page."""
    return build_change(VMTRACKER, scope, setting, action, ident, values)
