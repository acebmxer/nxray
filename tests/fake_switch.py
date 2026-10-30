"""A pretend NX-API switch for tests, served through httpx.MockTransport.

It keeps local accounts and roles, checks Basic auth on every request,
answers the show commands NXray uses from recorded output, and applies the
configuration commands NXray sends, so setup and port changes can be tested
end to end without a switch. ``ssh_opener()`` gives a pretend SSH command
line into the same switch, which understands the role lines NXray types.

Permissions copy what cisco-25gb did when tried (see app/port_changes.py):
network-admin may do anything; another account may enter an Ethernet port
only when one of its roles has a "conf t ; interface * ; ..." rule and its
interface policy permits that port, and may then run only the commands its
rules name. Entering a VLAN (which creates it) likewise needs a
"conf t ; vlan * ; ..." rule. A batch stops at the first refused command.

VLANs live in ``vlans`` (number -> name) and each port's VLAN settings in
``port_state`` next to its description, so ``show vlan brief`` and ``show
interface switchport`` answer with what the commands set. Port settings
(speed, MTU, FEC, flow control, storm control, routed with an address) live
there too, and a split 100G port in ``breakouts`` (port -> map), so the show
commands list its four ports instead.

The MAC address table starts as recorded and lives in ``mac_rows`` once
anything changes it (static entries, clearing), with the aging time in
``mac_aging``; CDP and LLDP per port are in ``port_state`` too.

Port-channels live in ``channels`` (number -> member port -> mode), starting
as recorded (port-channel43 of Ethernet1/43-44, LACP active); a member's LACP
rate and priority in ``port_state``, the switch's LACP priority in
``lacp_priority``. As on cisco-25gb, "channel-group" creates a missing
port-channel, a role reaches a port-channel's own settings only when its port
list names port-channels, and a member's LACP rate changes only while the
port is turned off.
"""

from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.features import CATALOG
from app.switch_ssh import SshAuthError, SshUnreachable
from tests.conftest import load_fixture

ADMIN_PASSWORD = "Adm1n-switch-pw"

# cisco-25gb's answer to a copy sent while another one runs.
SAVE_BUSY = (
    "Configuration update aborted: another request for config change is already in progress\n"
)

_RECORDED = {
    "show version": "show_version",
    "show environment": "show_environment",
    "show system resources": "show_system_resources",
    "show interface brief": "show_interface_brief",
    "show interface status": "show_interface_status",
    "show interface transceiver": "show_interface_transceiver",
    "show cdp global": "show_cdp_global",
    "show cdp neighbors detail": "show_cdp_neighbors_detail",
    "show ip arp detail vrf all": "show_ip_arp_detail_vrf_all",
}

_INTERFACE_COMMANDS = ("shutdown", "no shutdown", "no description")

# Port settings commands, the rule entity that permits each, and the
# port_state key the value goes to (None: the command itself is the value).
_SETTINGS = (
    (re.compile(r"speed (\S+)"), "speed *", "speed"),
    (re.compile(r"mtu (\d+)"), "mtu *", "mtu"),
    (re.compile(r"fec (\S+)"), "fec *", "fec"),
    (re.compile(r"flowcontrol receive (on|off)"), "flowcontrol receive *", "flow_receive"),
    (re.compile(r"flowcontrol send (on|off)"), "flowcontrol send *", "flow_send"),
    (
        re.compile(r"storm-control broadcast level (\S+)"),
        "storm-control broadcast level *",
        "storm_broadcast",
    ),
    (
        re.compile(r"storm-control multicast level (\S+)"),
        "storm-control multicast level *",
        "storm_multicast",
    ),
    (
        re.compile(r"storm-control unicast level (\S+)"),
        "storm-control unicast level *",
        "storm_unicast",
    ),
    (re.compile(r"storm-control action (shutdown|trap)"), "storm-control action *", "storm_action"),
    (re.compile(r"no storm-control action (\S+)"), "no storm-control action *", None),
    (re.compile(r"switchport"), "switchport", None),
    (re.compile(r"no switchport"), "no switchport", None),
    (re.compile(r"ip address (\S+)"), "ip address *", "ip"),
    (re.compile(r"no ip address (\S+)"), "no ip address *", None),
)

# The speed column of show interface status for a speed command's value.
_STATUS_SPEED = {"auto": "auto", "1000": "1000", "100": "100"}

_BREAKOUT = re.compile(r"(no )?interface breakout module (\d+) port (\d+) map (10g-4x|25g-4x)")

# CDP and LLDP per port: the command, its port_state key and the value it sets.
_DISCOVERY = {
    "cdp enable": ("cdp", True),
    "no cdp enable": ("cdp", False),
    "lldp transmit": ("lldp_transmit", True),
    "no lldp transmit": ("lldp_transmit", False),
    "lldp receive": ("lldp_receive", True),
    "no lldp receive": ("lldp_receive", False),
}

_STATIC_MAC = re.compile(
    r"(no )?mac address-table static ([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}) vlan (\d+) "
    r"(?:interface (Ethernet\S+)|drop)"
)
_CLEAR_MAC = re.compile(
    r"clear mac address-table dynamic"
    r"(?: interface (Ethernet\S+)| address ([0-9a-f.]+)(?: vlan (\d+))?| vlan (\d+))?"
)

# Interface commands with a value, and the rule entity that permits each.
_SWITCHPORT = (
    (re.compile(r"switchport mode (access|trunk)"), "switchport mode *", "mode"),
    (re.compile(r"switchport access vlan (\d+)"), "switchport access vlan *", "access"),
    (re.compile(r"switchport trunk native vlan (\d+)"), "switchport trunk native vlan *", "native"),
    (
        re.compile(r"switchport trunk allowed vlan ([0-9,-]+|none|all)"),
        "switchport trunk allowed vlan *",
        "allowed",
    ),
)

# What follows "feature" -> the name show feature uses for it.
_FEATURE_NAMES = {info.command: name for name, info in CATALOG.items() if info.command is not None}

# VLANs NX-OS keeps for itself (show system vlan reserved).
RESERVED_VLANS = range(3968, 4096)

# Two of the roles every NX-OS switch has (cisco-25gb lists 27).
BUILTIN_ROLES = ("network-admin", "network-operator")


@dataclass
class Role:
    entities: set[str] = field(default_factory=set)  # what each "permit command" rule names
    interface_policy_deny: bool = False
    interfaces: set[str] = field(default_factory=set)  # lower-cased port names

    def names(self, interface: str) -> bool:
        """Whether the port list covers ``interface`` (a range for port-channels)."""
        lowered = interface.lower()
        if lowered in self.interfaces:
            return True
        number = lowered.removeprefix("port-channel")
        if number == lowered or not number.isdigit():
            return False
        for entry in self.interfaces:
            match = re.fullmatch(r"port-channel(\d+)-(\d+)", entry)
            if match and int(match.group(1)) <= int(number) <= int(match.group(2)):
                return True
        return False


@dataclass
class FakeSwitch:
    users: dict[str, tuple[str, str]] = field(
        default_factory=lambda: {"admin": (ADMIN_PASSWORD, "network-admin")}
    )
    # Roles given to an account on top of the one in ``users``.
    extra_roles: dict[str, set[str]] = field(default_factory=dict)
    roles: dict[str, Role] = field(default_factory=dict)
    saved: bool = False
    reachable: bool = True
    ssh_reachable: bool = True
    # Command prefixes the switch rejects with an NX-API error.
    reject: set[str] = field(default_factory=set)
    # Line prefixes the SSH command line refuses.
    ssh_reject: set[str] = field(default_factory=set)
    save_text: str | None = None
    requests: list[list[str]] = field(default_factory=list)
    ssh_lines: list[str] = field(default_factory=list)
    # As on cisco-25gb: once a role's port list gains port-channels, NX-API
    # stops answering every account for a while (SSH keeps working). Off unless
    # a test asks, since the freeze ends on its own on the switch.
    freeze_on_channel_permit: bool = False
    nxapi_frozen: bool = False
    # Show commands answered from these bodies instead of the recorded ones.
    bodies: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Port settings changed through NX-API: name -> {"desc": str, "admin_up": bool,
    # "mode": str, "access": str, "native": str, "allowed": str}.
    port_state: dict[str, dict[str, Any]] = field(default_factory=dict)
    vlans: dict[int, str] = field(default_factory=lambda: {1: "default"})
    # As on cisco-25gb: an account that made an NX-API call keeps a session,
    # and "no username" is refused while it lives. Off by default.
    sessions_block_delete: bool = False
    signed_in: set[str] = field(default_factory=set)
    # As on cisco-25gb: a copy takes a while (2-3 s there), and a second copy
    # sent meanwhile is refused. 0 means instant.
    save_seconds: float = 0.0
    # Split 100G ports: "Ethernet1/50" -> "25g-4x".
    breakouts: dict[str, str] = field(default_factory=dict)
    # The lldp feature, off as on cisco-25gb: every "show lldp" command is then
    # "% Invalid command". On, "show lldp neighbors detail" answers from a body
    # shaped after Cisco's NX-API reference (never recorded on cisco-25gb).
    lldp: bool = False
    # Other features turned on or off since the start: show name -> on. The
    # rest answer as in the recording (show_feature_full: icam, lacp, nxapi
    # and sshServer on).
    feature_state: dict[str, bool] = field(default_factory=dict)
    # The MAC address table's rows once something changed it; None: as recorded.
    mac_rows: list[dict[str, Any]] | None = None
    mac_aging: int = 1800
    # Port-channels: number -> {member port: "active" | "passive" | "on"}.
    channels: dict[int, dict[str, str]] = field(
        default_factory=lambda: {43: {"Ethernet1/43": "active", "Ethernet1/44": "active"}}
    )
    lacp_priority: int = 32768
    _copying: bool = False

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def roles_of(self, user: str) -> set[str]:
        return {self.users[user][1], *self.extra_roles.get(user, set())}

    def handle(self, request: httpx.Request) -> httpx.Response:
        if not self.reachable:
            raise httpx.ConnectError("connection refused", request=request)
        if self.nxapi_frozen:
            raise httpx.ReadTimeout("timed out", request=request)
        user = self._authenticate(request)
        if user is None:
            return httpx.Response(401, text="Unauthorized")
        self.signed_in.add(user)
        entries = json.loads(request.content)
        self.requests.append([entry["params"]["cmd"] for entry in entries])
        replies: list[dict[str, Any]] = []
        context: tuple[str, str] | None = None  # ("interface", name) or ("vlan", number)
        for entry in entries:
            ident = entry["id"]
            if replies and "error" in replies[-1]:
                replies.append(_error(ident, "Command not ran due to previous failures"))
                continue
            reply, context = self._run(user, entry["params"]["cmd"], ident, context)
            replies.append(reply)
        status = 500 if any("error" in reply for reply in replies) else 200
        return httpx.Response(status, json=replies[0] if len(replies) == 1 else replies)

    def _authenticate(self, request: httpx.Request) -> str | None:
        header = request.headers.get("authorization", "")
        if not header.startswith("Basic "):
            return None
        name, _, password = base64.b64decode(header[6:]).decode().partition(":")
        known = self.users.get(name)
        return name if known and known[0] == password else None

    # ---- NX-API -------------------------------------------------------------

    def _role_allows(self, user: str, entity: str, interface: str | None) -> bool:
        for name in self.roles_of(user):
            role = self.roles.get(name)
            if role is None:
                continue
            if interface is not None and role.interface_policy_deny:
                if not role.names(interface):
                    continue
            if entity in ("interface", "vlan"):
                if any(e.startswith(f"conf t ; {entity} * ; ") for e in role.entities):
                    return True
            elif entity in role.entities:
                return True
        return False

    def _run(
        self, user: str, cmd: str, ident: int, context: tuple[str, str] | None
    ) -> tuple[dict[str, Any], tuple[str, str] | None]:
        if any(cmd.startswith(prefix) for prefix in self.reject):
            # Echoes the whole command, password included, so tests can check
            # NXray never passes a switch error on unscrubbed.
            return _error(ident, f"% Rejected by the fake switch: {cmd}\n"), context
        if ";" in cmd or "?" in cmd:
            return _error(ident, "Request contains invalid special characters"), context
        is_admin = "network-admin" in self.roles_of(user)
        denied = _error(ident, "% Permission denied for the role\n")
        interface = context[1] if context and context[0] == "interface" else None
        vlan = int(context[1]) if context and context[0] == "vlan" else None

        if cmd in self.bodies:
            return _ok(ident, self.bodies[cmd]), context
        if cmd.startswith("show "):
            return self._show(cmd, ident), context

        if match := re.fullmatch(r"interface (Ethernet\d+/\d+(?:/\d+)?)", cmd):
            name = match.group(1)
            if name not in self.port_names():
                return _error(ident, "% Invalid interface\n"), None
            if not (is_admin or self._role_allows(user, "interface", name)):
                if self._role_allows(user, "interface", None):
                    # As on cisco-25gb: the role has port rules, but not for this port.
                    return _error(ident, "% Interface permission denied\n"), None
                return denied, None
            return _ok(ident, None), ("interface", name)
        if match := re.fullmatch(r"(no )?interface port-channel(\d+)", cmd):
            undo, number = match.group(1), int(match.group(2))
            name = f"port-channel{number}"
            rule = "conf t ; no interface port-channel *" if undo else "interface"
            if not (is_admin or self._role_allows(user, rule, name)):
                if self._role_allows(user, "interface", None):
                    return _error(ident, "% Interface permission denied\n"), None
                return denied, None
            if undo:
                if number not in self.channels:
                    return _ok(ident, {"msg": f"{name}: port-channel not present\n"}), context
                # As on cisco-25gb: the ports leave the channel with it.
                del self.channels[number]
                self.port_state.pop(name, None)
                return _ok(ident, None), context
            self.channels.setdefault(number, {})
            return _ok(ident, None), ("interface", name)
        if match := re.fullmatch(r"lacp system-priority (\d+)", cmd):
            if not (is_admin or self._role_allows(user, "conf t ; lacp system-priority *", None)):
                return denied, context
            self.lacp_priority = int(match.group(1))
            return _ok(ident, None), context
        if interface is not None and (
            reply := self._channel_command(user, is_admin, cmd, ident, interface)
        ):
            return reply, context
        if match := _BREAKOUT.fullmatch(cmd):
            undo, module, port, mapping = match.groups()
            rule = (
                "conf t ; no interface breakout module * port * map *"
                if undo
                else "conf t ; interface breakout module * port * map *"
            )
            if not (is_admin or self._role_allows(user, rule, None)):
                return denied, context
            parent = f"Ethernet{module}/{port}"
            if undo:
                if self.breakouts.get(parent) != mapping:
                    return _error(ident, "% Breakout not configured with this map\n"), context
                del self.breakouts[parent]
            elif parent not in ("Ethernet1/50", "Ethernet1/52") or parent in self.breakouts:
                return _error(ident, "% Port does not support breakout\n"), context
            else:
                self.breakouts[parent] = mapping
            for name in list(self.port_state):
                if name == parent or name.startswith(parent + "/"):
                    del self.port_state[name]
            return _ok(ident, None), context
        if interface is not None and (cmd in _INTERFACE_COMMANDS or cmd.startswith("description ")):
            entity = "description *" if cmd.startswith("description ") else cmd
            if not (
                is_admin or self._role_allows(user, f"conf t ; interface * ; {entity}", interface)
            ):
                return denied, context
            state = self.port_state.setdefault(interface, {})
            if cmd == "shutdown":
                state["admin_up"] = False
            elif cmd == "no shutdown":
                state["admin_up"] = True
            elif cmd == "no description":
                state["desc"] = ""
            else:
                state["desc"] = cmd[len("description ") :]
            return _ok(ident, None), context
        if interface is not None:
            for pattern, entity, key in _SETTINGS:
                if match := pattern.fullmatch(cmd):
                    if not (
                        is_admin
                        or self._role_allows(user, f"conf t ; interface * ; {entity}", interface)
                    ):
                        return denied, context
                    return self._setting(ident, interface, cmd, key, match), context
            for pattern, entity, key in _SWITCHPORT:
                if match := pattern.fullmatch(cmd):
                    if not (
                        is_admin
                        or self._role_allows(user, f"conf t ; interface * ; {entity}", interface)
                    ):
                        return denied, context
                    value = match.group(1)
                    self.port_state.setdefault(interface, {})[key] = (
                        "1-4094" if value == "all" else value
                    )
                    return _ok(ident, None), context
        if interface is not None and cmd in _DISCOVERY:
            if not (
                is_admin or self._role_allows(user, f"conf t ; interface * ; {cmd}", interface)
            ):
                return denied, context
            if cmd.removeprefix("no ").startswith("lldp") and not self.lldp:
                # As NX-OS answers a command of a feature that is off.
                return _error(ident, "% Invalid command at '^' marker.\n"), context
            key, value = _DISCOVERY[cmd]
            self.port_state.setdefault(interface, {})[key] = value
            return _ok(ident, None), context
        if match := re.fullmatch(r"mac address-table aging-time (\d+)", cmd):
            rule = "conf t ; mac address-table aging-time *"
            if not (is_admin or self._role_allows(user, rule, None)):
                return denied, context
            self.mac_aging = int(match.group(1))
            return _ok(ident, None), context
        if match := _STATIC_MAC.fullmatch(cmd):
            undo, mac, vlan_text, port = match.groups()
            rule = (
                "conf t ; no mac address-table static *"
                if undo
                else "conf t ; mac address-table static *"
            )
            if not (is_admin or self._role_allows(user, rule, None)):
                return denied, context
            return self._static_mac(ident, bool(undo), mac, vlan_text, port), context
        if match := _CLEAR_MAC.fullmatch(cmd):
            rule = "clear mac address-table dynamic" + (" *" if cmd.count(" ") > 3 else "")
            if not (is_admin or self._role_allows(user, rule, None)):
                return denied, context
            port, mac, mac_vlan, vlan = match.groups()
            self._clear_macs(port, mac, mac_vlan or vlan)
            return _ok(ident, None), context
        if match := re.fullmatch(r"vlan (\d+)", cmd):
            number = int(match.group(1))
            if not (is_admin or self._role_allows(user, "vlan", None)):
                return denied, None
            if number in RESERVED_VLANS:
                return _error(ident, "invalid vlans (reserved values)\n"), None
            self.vlans.setdefault(number, f"VLAN{number:04d}")
            return _ok(ident, None), ("vlan", str(number))
        if vlan is not None and (match := re.fullmatch(r"name (\S+)", cmd)):
            if not (is_admin or self._role_allows(user, "conf t ; vlan * ; name *", None)):
                return denied, context
            self.vlans[vlan] = match.group(1)
            return _ok(ident, None), context
        if match := re.fullmatch(r"no vlan (\d+)", cmd):
            if not (is_admin or self._role_allows(user, "conf t ; no vlan *", None)):
                return denied, context
            number = int(match.group(1))
            if number == 1:
                return _error(ident, "Deletion of VLAN 1 is not allowed!!\n"), context
            self.vlans.pop(number, None)
            return _ok(ident, None), context
        if match := re.fullmatch(r"(no )?feature (.+)", cmd):
            rule = "conf t ; no feature *" if match.group(1) else "conf t ; feature *"
            if not (is_admin or self._role_allows(user, rule, None)):
                return denied, context
            name = _FEATURE_NAMES.get(match.group(2))
            if name is None:
                return _error(ident, f"% Invalid command at '^' marker: {cmd}\n"), context
            if name == "lldp":
                self.lldp = not match.group(1)
            else:
                self.feature_state[name] = not match.group(1)
            return _ok(ident, None), context
        if cmd == "copy running-config startup-config":
            if not (is_admin or self._role_allows(user, cmd, None)):
                return denied, context
            if self.save_text is not None:
                return _ok(ident, self.save_text), context
            if self._copying:
                return _error(ident, SAVE_BUSY), context
            self._copying = True
            try:
                time.sleep(self.save_seconds)
            finally:
                self._copying = False
            self.saved = True
            return _ok(ident, None), context
        if not is_admin:
            return denied, context
        if match := re.fullmatch(r"username (\S+) password (\S+) role (\S+)", cmd):
            name, password, role = match.groups()
            if name in self.users:
                # As on cisco-25gb: an existing account gets the new password at
                # once and keeps every role it had; the named role is added.
                primary = self.users[name][1]
                self.users[name] = (password, primary)
                if role != primary:
                    self.extra_roles.setdefault(name, set()).add(role)
            else:
                self.users[name] = (password, role)
            return _ok(ident, None), context
        if match := re.fullmatch(r"username (\S+) role (\S+)", cmd):
            name, role = match.groups()
            if name not in self.users:
                return _error(ident, f"% User {name} does not exist\n"), context
            if role not in self.roles and role not in BUILTIN_ROLES:
                return _error(ident, "% Role does not exist\n"), context
            self.extra_roles.setdefault(name, set()).add(role)
            return _ok(ident, None), context
        if match := re.fullmatch(r"no username (\S+)", cmd):
            if self.sessions_block_delete and match.group(1) in self.signed_in:
                return _error(ident, f"{match.group(1)} account cannot be deactivated\n"), context
            self.users.pop(match.group(1), None)
            self.extra_roles.pop(match.group(1), None)
            return _ok(ident, None), context
        return _error(ident, f"% Invalid command: {cmd.split()[0]}\n"), context

    def _setting(
        self, ident: int, interface: str, cmd: str, key: str | None, match: re.Match[str]
    ) -> dict[str, Any]:
        state = self.port_state.setdefault(interface, {})
        routed = state.get("routed", False)
        if cmd == "switchport":
            if state.get("ip"):
                return _error(ident, "ERROR: Remove the IP address first\n")
            state["routed"] = False
        elif cmd == "no switchport":
            state["routed"] = True
        elif cmd.startswith("no storm-control action"):
            state.pop("storm_action", None)
        elif cmd.startswith("no ip address"):
            if state.get("ip") != match.group(1):
                return _error(ident, "% Address not found\n")
            state.pop("ip", None)
        elif key == "ip" and not routed:
            return _error(ident, "% IP address not allowed on a switched port\n")
        elif key == "mtu" and not routed and match.group(1) not in ("1500", "9216"):
            return _error(ident, "ERROR: MTU on L2 interfaces can only be 1500 or 9216\n")
        elif key is not None:
            state[key] = match.group(1)
        return _ok(ident, None)

    def _channel_command(
        self, user: str, is_admin: bool, cmd: str, ident: int, interface: str
    ) -> dict[str, Any] | None:
        """The port-channel and LACP commands inside an interface; None for any other."""
        denied = _error(ident, "% Permission denied for the role\n")
        checks = (
            (
                re.fullmatch(r"channel-group (\d+)(?: mode (active|passive|on))?", cmd),
                "channel-group *",
            ),
            (re.fullmatch(r"no channel-group", cmd), "no channel-group"),
            (re.fullmatch(r"lacp rate (normal|fast)", cmd), "lacp rate *"),
            (re.fullmatch(r"lacp port-priority (\d+)", cmd), "lacp port-priority *"),
            (re.fullmatch(r"lacp min-links (\d+)", cmd), "lacp min-links *"),
        )
        for match, entity in checks:
            if match is None:
                continue
            if not (
                is_admin or self._role_allows(user, f"conf t ; interface * ; {entity}", interface)
            ):
                return denied
            state = self.port_state.setdefault(interface, {})
            current = self.channel_of(interface)
            if entity == "channel-group *":
                number, mode = int(match.group(1)), match.group(2) or "on"
                if mode != "on" and not self.lacp_on():
                    return _error(ident, "% LACP is not enabled\n")
                if current is not None and current != number:
                    return _error(ident, f"{interface} is already in port-channel{current}\n")
                members = self.channels.setdefault(number, {})
                if any(other != mode for port, other in members.items() if port != interface):
                    return _error(
                        ident,
                        "Port-channel mode cannot be changed in a non-empty port-channel, and "
                        "port mode must match with port-channel mode\n",
                    )
                members[interface] = mode
            elif entity == "no channel-group":
                if current is not None:
                    del self.channels[current][interface]
            elif entity == "lacp rate *":
                if current is not None and state.get("admin_up", True):
                    return _error(
                        ident, "Cannot set lacp rate. Port is not admin down in port-channel\n"
                    )
                state["lacp_rate"] = match.group(1)
            elif entity == "lacp port-priority *":
                state["lacp_priority"] = int(match.group(1))
            else:
                state["min_links"] = int(match.group(1))
            return _ok(ident, None)
        return None

    def lacp_on(self) -> bool:
        return self.feature_state.get("lacp", True)

    def channel_of(self, port: str) -> int | None:
        return next((n for n, members in self.channels.items() if port in members), None)

    def channel_summary(self) -> dict[str, Any]:
        """``show port-channel summary`` for ``channels``: port-channel43's two ports as
        recorded (up), any other port down (nothing is plugged in)."""
        recorded = {
            m["port"]: m["port-status"]
            for m in load_fixture("show_port_channel_summary")["TABLE_channel"]["ROW_channel"][
                "TABLE_member"
            ]["ROW_member"]
        }
        found = []
        for number, members in sorted(self.channels.items()):
            rows = [
                {"port": port, "port-status": recorded.get(port, "D") if number == 43 else "D"}
                for port in sorted(members, key=_port_key)
            ]
            row: dict[str, Any] = {
                "group": str(number),
                "port-channel": f"port-channel{number}",
                "layer": "S",
                "status": "U" if any(r["port-status"] == "P" for r in rows) else "D",
                "type": "Eth",
                "prtcl": "LACP" if any(m != "on" for m in members.values()) else "NONE",
            }
            if rows:
                row["TABLE_member"] = {"ROW_member": rows[0] if len(rows) == 1 else rows}
            found.append(row)
        if not found:
            return {}
        return {"TABLE_channel": {"ROW_channel": found[0] if len(found) == 1 else found}}

    def channel_database(self) -> dict[str, Any]:
        found = []
        for number, members in sorted(self.channels.items()):
            rows = [
                {"port": p, "mode": m, "port-status": "down"} for p, m in sorted(members.items())
            ]
            row: dict[str, Any] = {
                "interface": f"port-channel{number}",
                "total-ports": str(len(rows)),
            }
            if rows:
                row["TABLE_member"] = {"ROW_member": rows[0] if len(rows) == 1 else rows}
            found.append(row)
        if not found:
            return {}
        return {"TABLE_interface": {"ROW_interface": found[0] if len(found) == 1 else found}}

    def descriptions(self) -> dict[str, Any]:
        """``show interface description``: the recorded ports, then the port-channels."""
        rows = [
            dict(row)
            for row in load_fixture("show_interface_description")["TABLE_interface"][
                "ROW_interface"
            ]
            if not row["interface"].startswith("port-channel")
        ]
        for row in rows:
            desc = self.port_state.get(row["interface"], {}).get("desc")
            if desc is not None:
                row.pop("desc", None)
                if desc:
                    row["desc"] = desc
        for number in sorted(self.channels):
            name = f"port-channel{number}"
            row = {"interface": name}
            desc = self.port_state.get(name, {}).get(
                "desc", "storage-server" if number == 43 else ""
            )
            if desc:
                row["desc"] = desc
            rows.append(row)
        return {"TABLE_interface": {"ROW_interface": rows}}

    def lacp_interfaces(self) -> dict[str, Any]:
        body = load_fixture("show_lacp_interface")
        for row in body["TABLE_lacp_intf"]["ROW_lacp_intf"]:
            state = self.port_state.get(row["interface"], {})
            if "lacp_rate" in state:
                row["localport"]["local-timeout"] = (
                    "Short" if state["lacp_rate"] == "fast" else "Long"
                )
            if "lacp_priority" in state:
                row["localport"]["local-port-priority"] = hex(state["lacp_priority"])
        return body

    def lacp_neighbors(self) -> dict[str, Any]:
        """The recorded neighbor of port-channel43's ports, while they are still in it."""
        body = load_fixture("show_lacp_neighbor")
        channel = body["TABLE_interface"]["ROW_interface"]
        members = channel["TABLE_member"]["ROW_member"]
        kept = [m for m in members if m["port"] in self.channels.get(43, {})]
        if not kept:
            return {}
        channel["TABLE_member"]["ROW_member"] = kept[0] if len(kept) == 1 else kept
        return body

    def macs(self) -> list[dict[str, Any]]:
        """The MAC address table's rows, starting from the recorded ones."""
        if self.mac_rows is None:
            self.mac_rows = list(
                load_fixture("show_mac_address_table")["TABLE_mac_address"]["ROW_mac_address"]
            )
        return self.mac_rows

    def _static_mac(
        self, ident: int, undo: bool, mac: str, vlan_text: str, port: str | None
    ) -> dict[str, Any]:
        vlan = int(vlan_text)
        if vlan not in self.vlans:
            return _error(ident, f"ERROR: vlan {vlan} not configured\n")
        rows = self.macs()
        found = [
            row
            for row in rows
            if row["disp_mac_addr"] == mac
            and row["disp_vlan"] == str(vlan)
            and row["disp_type"] == "static"
        ]
        if undo:
            if not found:
                return _error(ident, "ERROR: Entry does not exist\n")
            rows.remove(found[0])
            return _ok(ident, None)
        if port is not None and port not in self.port_names():
            return _error(ident, "% Invalid interface\n")
        # A static entry replaces what was learned for the address in that VLAN.
        self.mac_rows = [
            row
            for row in rows
            if not (row["disp_mac_addr"] == mac and row["disp_vlan"] == str(vlan))
        ]
        self.mac_rows.append(
            {
                "disp_mac_addr": mac,
                "disp_type": "static",
                "disp_vlan": str(vlan),
                "disp_age": "-",
                "disp_is_secure": "F",
                "disp_is_ntfy": "F",
                # How a dropped entry shows is a guess: never seen on cisco-25gb.
                "disp_port": port.replace("Ethernet", "Eth") if port else "Drop",
            }
        )
        return _ok(ident, None)

    def _clear_macs(self, port: str | None, mac: str | None, vlan: str | None) -> None:
        short = port.replace("Ethernet", "Eth") if port else None

        def cleared(row: dict[str, Any]) -> bool:
            if row["disp_type"] != "dynamic":
                return False
            if short is not None and row["disp_port"] != short:
                return False
            if mac is not None and row["disp_mac_addr"] != mac:
                return False
            return vlan is None or row["disp_vlan"] == vlan

        self.mac_rows = [row for row in self.macs() if not cleared(row)]

    def discovery(self, name: str, protocol: str) -> dict[str, Any]:
        """``show cdp interface <port>`` (as recorded) or ``show lldp interface <port>``
        (shaped after Cisco's guides, never seen on cisco-25gb)."""
        state = self.port_state.get(name, {})
        if protocol == "cdp":
            row = dict(load_fixture("show_cdp_interface")["TABLE_cdp_all"]["ROW_cdp_all"])
            row["intf_id"] = name
            row["cdp_intf_enabled"] = "enabled" if state.get("cdp", True) else "disabled"
            return {"TABLE_cdp_all": {"ROW_cdp_all": row}}
        return {
            "TABLE_interface": {
                "ROW_interface": {
                    "interface": name,
                    "tx_enabled": "TRUE" if state.get("lldp_transmit", True) else "FALSE",
                    "rx_enabled": "TRUE" if state.get("lldp_receive", True) else "FALSE",
                }
            }
        }

    def port_names(self) -> list[str]:
        """Every Ethernet port, with split ports listed as their four parts."""
        names = [row["interface"] for row in self._expand(load_fixture("show_interface_status"))]
        return [name for name in names if name.startswith("Ethernet")]

    def _expand(self, body: dict[str, Any]) -> list[dict[str, Any]]:
        """A body's rows, a split port's row replaced by four renamed copies."""
        found = []
        for row in body["TABLE_interface"]["ROW_interface"]:
            mapping = self.breakouts.get(row.get("interface", ""))
            if mapping is None:
                found.append(row)
                continue
            for part in range(1, 5):
                copy = dict(row, interface=f"{row['interface']}/{part}")
                if "speed" in copy:
                    copy["speed"] = "25G" if mapping == "25g-4x" else "10G"
                if "eth_bw" in copy:
                    copy["eth_bw"] = 25_000_000 if mapping == "25g-4x" else 10_000_000
                found.append(copy)
        body["TABLE_interface"]["ROW_interface"] = found
        return found

    def _row_for(self, fixture: str, name: str, template: str) -> dict[str, Any]:
        """One port's row from a recorded all-ports body; a split port's from its parent."""
        rows = load_fixture(fixture)["TABLE_interface"]["ROW_interface"]
        by_name = {row["interface"]: row for row in rows}
        row = by_name.get(name) or by_name.get(name.rsplit("/", 1)[0]) or by_name[template]
        return dict(row, interface=name)

    def capabilities(self, name: str) -> dict[str, Any]:
        """``show interface <port> capabilities``, from the two recorded kinds."""
        base = name.rsplit("/", 1)[0] if name.count("/") == 2 else name
        fixture = (
            "show_interface_capabilities_qsfp"
            if base in ("Ethernet1/50", "Ethernet1/52") and base == name
            else "show_interface_capabilities_sfp"
        )
        row = dict(load_fixture(fixture)["TABLE_interface"]["ROW_interface"], interface=name)
        if name.count("/") == 2:
            row["speed"] = "10000,25000"
        return {"TABLE_interface": {"ROW_interface": row}}

    def flowcontrol(self, name: str) -> dict[str, Any]:
        row = self._row_for("show_interface_flowcontrol", name, "Ethernet1/1")
        state = self.port_state.get(name, {})
        if "flow_receive" in state:
            row["recv_admin"] = row["recv_oper"] = state["flow_receive"]
        if "flow_send" in state:
            row["send_admin"] = row["send_oper"] = state["flow_send"]
        return {"TABLE_interface": {"ROW_interface": row}}

    def storm_control(self, name: str) -> dict[str, Any]:
        row = self._row_for("show_interface_counters_storm_control", name, "Ethernet1/1")
        state = self.port_state.get(name, {})
        for key, field_name in (
            ("storm_broadcast", "eth_bcast_supp"),
            ("storm_multicast", "eth_mcast_supp"),
            ("storm_unicast", "eth_ucast_supp"),
        ):
            if key in state:
                row[field_name] = state[key]
        if "storm_action" in state:
            row["supp_action"] = f"[{state['storm_action']}]"
        return {"TABLE_interface": {"ROW_interface": row}}

    def ip_interfaces(self) -> dict[str, Any]:
        """``show ip interface vrf all``: mgmt0 as recorded, plus routed ports with an address."""
        body = load_fixture("show_ip_interface_vrf_all")
        rows = [body["TABLE_intf"]["ROW_intf"]]
        for name, state in sorted(self.port_state.items()):
            if state.get("routed") and state.get("ip"):
                address, _, masklen = state["ip"].partition("/")
                rows.append(
                    {
                        "vrf-name-out": "default",
                        # Written short, as NX-OS writes port names here.
                        "intf-name": name.replace("Ethernet", "Eth"),
                        "prefix": address,
                        "masklen": int(masklen),
                    }
                )
        return {"TABLE_intf": {"ROW_intf": rows[0] if len(rows) == 1 else rows}}

    def switchports(self) -> dict[str, Any]:
        """``show interface switchport`` with the VLAN settings changed so far."""
        body = load_fixture("show_interface_switchport")
        for row in self._expand(body):
            state = self.port_state.get(row["interface"], {})
            if state.get("routed"):
                row["switchport"] = "Disabled"
            if "mode" in state:
                row["oper_mode"] = state["mode"]
            if "access" in state:
                row["access_vlan"] = state["access"]
            if "native" in state:
                row["native_vlan"] = state["native"]
            if "allowed" in state:
                row["trunk_vlans"] = state["allowed"]
        return body

    def vlan_brief(self) -> dict[str, Any]:
        """``show vlan brief`` for ``vlans``; ports listed as the switch lists them."""
        ports = self.switchports()["TABLE_interface"]["ROW_interface"]
        rows = []
        for number, name in sorted(self.vlans.items()):
            members = []
            for port in ports:
                if port["oper_mode"] == "access" and int(port["access_vlan"]) == number:
                    members.append(port["interface"])
                elif port["oper_mode"] == "trunk" and number in _vlan_numbers(port["trunk_vlans"]):
                    members.append(port["interface"])
            row = {
                "vlanshowbr-vlanid": str(number),
                "vlanshowbr-vlanid-utf": str(number),
                "vlanshowbr-vlanname": name,
                "vlanshowbr-vlanstate": "active",
                "vlanshowbr-shutstate": "noshutdown",
            }
            if members:
                row["vlanshowplist-ifidx"] = ",".join(members)
            rows.append(row)
        return {
            "TABLE_vlanbriefxbrief": {"ROW_vlanbriefxbrief": rows[0] if len(rows) == 1 else rows}
        }

    def features(self) -> dict[str, Any]:
        """``show feature`` as recorded, with lldp on or off as ``lldp`` says and the
        others as ``feature_state`` says."""
        body = load_fixture("show_feature_full")
        for row in body["TABLE_cfcFeatureCtrlTable"]["ROW_cfcFeatureCtrlTable"]:
            name = row["cfcFeatureCtrlName2"]
            on = self.lldp if name == "lldp" else self.feature_state.get(name)
            if on is not None:
                row["cfcFeatureCtrlOpStatus2"] = "enabled" if on else "disabled"
        return body

    def _show(self, cmd: str, ident: int) -> dict[str, Any]:
        if cmd == "show feature":
            return _ok(ident, self.features())
        if cmd == "show port-channel summary":
            return _ok(ident, self.channel_summary())
        if cmd == "show port-channel database":
            return _ok(ident, self.channel_database())
        if cmd == "show interface description":
            return _ok(ident, self.descriptions())
        if cmd.startswith("show lacp"):
            if not self.lacp_on():
                return _error(ident, "% Invalid command\n")
            if cmd == "show lacp system-identifier":
                return _ok(
                    ident,
                    {"system-priority": str(self.lacp_priority), "system-mac": "70-79-b3-00-00-01"},
                )
            if cmd == "show lacp interface":
                return _ok(ident, self.lacp_interfaces())
            if cmd == "show lacp neighbor":
                return _ok(ident, self.lacp_neighbors())
        if cmd.startswith("show lldp"):
            if not self.lldp:
                return _error(ident, "% Invalid command\n")
            if cmd == "show lldp neighbors detail":
                return _ok(ident, load_fixture("show_lldp_neighbors_detail"))
        if match := re.fullmatch(r"show (cdp|lldp) interface (Ethernet\S+)", cmd):
            protocol, name = match.groups()
            if name not in self.port_names():
                return _error(ident, "% Invalid interface format\n")
            return _ok(ident, self.discovery(name, protocol))
        if cmd == "show mac address-table":
            rows = self.macs()
            body = {"TABLE_mac_address": {"ROW_mac_address": rows[0] if len(rows) == 1 else rows}}
            return _ok(ident, body if rows else {})
        if cmd == "show mac address-table aging-time":
            return _ok(ident, {"age_str": "Aging Time\n----------\n", "age": str(self.mac_aging)})
        port_show = re.fullmatch(
            r"show interface (Ethernet\S+) (capabilities|flowcontrol|counters storm-control)", cmd
        )
        if port_show:
            name, what = port_show.groups()
            if name not in self.port_names():
                return _error(ident, "% Invalid interface format\n")
            if what == "capabilities":
                return _ok(ident, self.capabilities(name))
            if what == "flowcontrol":
                return _ok(ident, self.flowcontrol(name))
            return _ok(ident, self.storm_control(name))
        if cmd == "show ip interface vrf all":
            return _ok(ident, self.ip_interfaces())
        if cmd == "show interface brief":
            body = load_fixture("show_interface_brief")
            for row in self._expand(body):
                if self.port_state.get(row["interface"], {}).get("admin_up") is False:
                    row.update(state="down", state_rsn_desc="Administratively down")
            return _ok(ident, body)
        if cmd == "show interface status":
            body = load_fixture("show_interface_status")
            for row in self._expand(body):
                speed = self.port_state.get(row["interface"], {}).get("speed")
                if speed is not None:
                    row["speed"] = _STATUS_SPEED.get(speed, f"{int(speed) // 1000}G")
            return _ok(ident, body)
        if cmd in _RECORDED:
            return _ok(ident, load_fixture(_RECORDED[cmd]))
        if cmd == "show interface":
            body = load_fixture("show_interface")
            for row in self._expand(body):
                state = self.port_state.get(row["interface"], {})
                if "mtu" in state:
                    row["eth_mtu"] = state["mtu"]
                if "fec" in state:
                    row["eth_admin_fec_state"] = state["fec"]
                if "desc" in state:
                    if state["desc"]:
                        row["desc"] = state["desc"]
                    else:
                        row.pop("desc", None)
                if state.get("admin_up") is False:
                    row.update(
                        admin_state="down", state="down", state_rsn_desc="Administratively down"
                    )
                elif state.get("admin_up") is True:
                    row["admin_state"] = "up"
            return _ok(ident, body)
        if cmd == "show interface switchport":
            return _ok(ident, self.switchports())
        if cmd == "show vlan brief":
            return _ok(ident, self.vlan_brief())
        if cmd == "show hostname":
            return _ok(ident, {"hostname": "nexus-lab"})
        if cmd == "show nxapi":
            return _ok(ident, {"nxapi_status": "nxapi enabled", "timeout": "10"})
        if cmd == "show role":
            names = [*BUILTIN_ROLES, *sorted(self.roles)]
            table = [{"role_name": name, "role_description": ""} for name in names]
            return _ok(ident, {"TABLE_role": {"ROW_role": table}})
        if cmd == "show user-account":
            rows = []
            for name in self.users:
                roles = [{"role": role} for role in sorted(self.roles_of(name))]
                rows.append(
                    {
                        "usr_name": name,
                        # One row is an object, several a list, as on the switch.
                        "TABLE_role": {"ROW_role": roles[0] if len(roles) == 1 else roles},
                    }
                )
            return _ok(
                ident, {"TABLE_template": {"ROW_template": rows[0] if len(rows) == 1 else rows}}
            )
        return _error(ident, "% Invalid command\n")

    # ---- SSH ----------------------------------------------------------------

    def ssh_opener(self):
        """An opener for app.state.ssh_opener (see app/switch_ssh.py)."""

        def opener(host: str, port: int, username: str, password: str, timeout: float):
            if not self.ssh_reachable:
                raise SshUnreachable(f"could not open SSH to {host}:{port}: refused")
            known = self.users.get(username)
            if not known or known[0] != password:
                raise SshAuthError("the switch refused the SSH username or password")
            return FakeShell(self)

        return opener


class FakeShell:
    """The pretend switch's command line, for the lines NXray types over SSH."""

    def __init__(self, switch: FakeSwitch) -> None:
        self.switch = switch
        self.mode: list[str] = []  # e.g. ["config", "role", "role-interface"]
        self.role: Role | None = None
        self.closed = False

    def run(self, line: str) -> str:
        self.switch.ssh_lines.append(line)
        invalid = "% Invalid command at '^' marker."
        if any(line.startswith(prefix) for prefix in self.switch.ssh_reject):
            return invalid
        if line == "configure terminal":
            self.mode = ["config"]
            return "Enter configuration commands, one per line.  End with CNTL/Z."
        if line == "end":
            self.mode = []
            return ""
        if not self.mode and (match := re.fullmatch(r"show user-account (\S+)", line)):
            name = match.group(1)
            if name not in self.switch.users:
                return ""
            roles = " ".join(sorted(self.switch.roles_of(name)))
            return f"user:{name}\n\tthis user account has no expiry date\n\troles:{roles}"
        if not self.mode and line == "copy running-config startup-config":
            if self.switch.save_text is not None:
                return self.switch.save_text.strip()
            self.switch.saved = True
            return "Copy complete, now saving to disk (please wait)...\nCopy complete."
        if line == "exit":
            if self.mode:
                self.mode.pop()
            return ""
        current = self.mode[-1] if self.mode else ""
        if current == "config":
            if match := re.fullmatch(r"role name (\S+)", line):
                self.role = self.switch.roles.setdefault(match.group(1), Role())
                self.mode.append("role")
                return ""
            if match := re.fullmatch(r"username (\S+) role (\S+)", line):
                name, role = match.groups()
                if name not in self.switch.users:
                    return f"% User {name} does not exist"
                if role not in self.switch.roles:
                    return "% Role does not exist"
                self.switch.extra_roles.setdefault(name, set()).add(role)
                return ""
        if current == "role" and self.role is not None:
            if line.startswith("description "):
                return ""
            if match := re.fullmatch(r"rule \d+ permit command (.+)", line):
                self.role.entities.add(match.group(1))
                return ""
            if line == "interface policy deny":
                self.role.interface_policy_deny = True
                self.mode.append("role-interface")
                return ""
        if current == "role-interface" and self.role is not None:
            if match := re.fullmatch(r"permit interface (\S+)", line):
                name = match.group(1).lower()
                if (
                    self.switch.freeze_on_channel_permit
                    and name.startswith("port-channel")
                    and name not in self.role.interfaces
                ):
                    self.switch.nxapi_frozen = True
                self.role.interfaces.add(name)
                return ""
        return invalid

    def close(self) -> None:
        self.closed = True


def _port_key(name: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", name))


def _vlan_numbers(text: str) -> set[int]:
    if text == "none":
        return set()
    found: set[int] = set()
    for item in text.split(","):
        first, _, last = item.partition("-")
        found.update(range(int(first), int(last or first) + 1))
    return found


def _ok(ident: int, body: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "result": None if body is None else {"body": body}, "id": ident}


def _error(ident: int, msg: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "error": {"code": -32602, "message": "Invalid params", "data": {"msg": msg}},
        "id": ident,
    }
