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
interface switchport`` answer with what the commands set.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.switch_ssh import SshAuthError, SshUnreachable
from tests.conftest import load_fixture

ADMIN_PASSWORD = "Adm1n-switch-pw"

_RECORDED = {
    "show version": "show_version",
    "show environment": "show_environment",
    "show system resources": "show_system_resources",
    "show interface brief": "show_interface_brief",
    "show interface status": "show_interface_status",
    "show interface transceiver": "show_interface_transceiver",
}

_INTERFACE_COMMANDS = ("shutdown", "no shutdown", "no description")

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

# VLANs NX-OS keeps for itself (show system vlan reserved).
RESERVED_VLANS = range(3968, 4096)


@dataclass
class Role:
    entities: set[str] = field(default_factory=set)  # what each "permit command" rule names
    interface_policy_deny: bool = False
    interfaces: set[str] = field(default_factory=set)  # lower-cased port names


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
    # Show commands answered from these bodies instead of the recorded ones.
    bodies: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Port settings changed through NX-API: name -> {"desc": str, "admin_up": bool,
    # "mode": str, "access": str, "native": str, "allowed": str}.
    port_state: dict[str, dict[str, Any]] = field(default_factory=dict)
    vlans: dict[int, str] = field(default_factory=lambda: {1: "default"})

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def roles_of(self, user: str) -> set[str]:
        return {self.users[user][1], *self.extra_roles.get(user, set())}

    def handle(self, request: httpx.Request) -> httpx.Response:
        if not self.reachable:
            raise httpx.ConnectError("connection refused", request=request)
        user = self._authenticate(request)
        if user is None:
            return httpx.Response(401, text="Unauthorized")
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
                if interface.lower() not in role.interfaces:
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
            if not (is_admin or self._role_allows(user, "interface", name)):
                return denied, None
            return _ok(ident, None), ("interface", name)
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
        if cmd == "copy running-config startup-config":
            if not (is_admin or self._role_allows(user, cmd, None)):
                return denied, context
            if self.save_text is not None:
                return _ok(ident, self.save_text), context
            self.saved = True
            return _ok(ident, None), context
        if not is_admin:
            return denied, context
        if match := re.fullmatch(r"username (\S+) password (\S+) role (\S+)", cmd):
            name, password, role = match.groups()
            self.users[name] = (password, role)
            return _ok(ident, None), context
        if match := re.fullmatch(r"no username (\S+)", cmd):
            self.users.pop(match.group(1), None)
            self.extra_roles.pop(match.group(1), None)
            return _ok(ident, None), context
        return _error(ident, f"% Invalid command: {cmd.split()[0]}\n"), context

    def switchports(self) -> dict[str, Any]:
        """``show interface switchport`` with the VLAN settings changed so far."""
        body = load_fixture("show_interface_switchport")
        for row in body["TABLE_interface"]["ROW_interface"]:
            state = self.port_state.get(row["interface"], {})
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

    def _show(self, cmd: str, ident: int) -> dict[str, Any]:
        if cmd in _RECORDED:
            return _ok(ident, load_fixture(_RECORDED[cmd]))
        if cmd == "show interface":
            body = load_fixture("show_interface")
            for row in body["TABLE_interface"]["ROW_interface"]:
                state = self.port_state.get(row["interface"], {})
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
                self.role.interfaces.add(match.group(1).lower())
                return ""
        return invalid

    def close(self) -> None:
        self.closed = True


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
