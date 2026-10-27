"""A pretend NX-API switch for tests, served through httpx.MockTransport.

It keeps local accounts, checks Basic auth on every request, answers the show
commands NXray uses from recorded output, and applies the configuration
commands NXray sends, so setup can be tested end to end without a switch.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from tests.conftest import load_fixture

ADMIN_PASSWORD = "Adm1n-switch-pw"


@dataclass
class FakeSwitch:
    users: dict[str, tuple[str, str]] = field(
        default_factory=lambda: {"admin": (ADMIN_PASSWORD, "network-admin")}
    )
    saved: bool = False
    reachable: bool = True
    # Command prefixes the switch rejects with an NX-API error.
    reject: set[str] = field(default_factory=set)
    save_text: str | None = None
    requests: list[list[str]] = field(default_factory=list)
    # Show commands answered from these bodies instead of the recorded ones.
    bodies: dict[str, dict[str, Any]] = field(default_factory=dict)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        if not self.reachable:
            raise httpx.ConnectError("connection refused", request=request)
        user = self._authenticate(request)
        if user is None:
            return httpx.Response(401, text="Unauthorized")
        entries = json.loads(request.content)
        self.requests.append([entry["params"]["cmd"] for entry in entries])
        replies = [self._run(user, entry["params"]["cmd"], entry["id"]) for entry in entries]
        status = 500 if any("error" in reply for reply in replies) else 200
        return httpx.Response(status, json=replies[0] if len(replies) == 1 else replies)

    def _authenticate(self, request: httpx.Request) -> str | None:
        header = request.headers.get("authorization", "")
        if not header.startswith("Basic "):
            return None
        name, _, password = base64.b64decode(header[6:]).decode().partition(":")
        known = self.users.get(name)
        return name if known and known[0] == password else None

    def _run(self, user: str, cmd: str, ident: int) -> dict[str, Any]:
        def ok(body: Any) -> dict[str, Any]:
            return {
                "jsonrpc": "2.0",
                "result": None if body is None else {"body": body},
                "id": ident,
            }

        def error(msg: str) -> dict[str, Any]:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32602, "message": "Invalid params", "data": {"msg": msg}},
                "id": ident,
            }

        if any(cmd.startswith(prefix) for prefix in self.reject):
            # Echoes the whole command, password included, so tests can check
            # NXray never passes a switch error on unscrubbed.
            return error(f"% Rejected by the fake switch: {cmd}\n")
        is_admin = self.users[user][1] == "network-admin"

        if cmd in self.bodies:
            return ok(self.bodies[cmd])
        recorded = {
            "show version": "show_version",
            "show environment": "show_environment",
            "show system resources": "show_system_resources",
            "show interface brief": "show_interface_brief",
            "show interface": "show_interface",
            "show interface status": "show_interface_status",
            "show interface transceiver": "show_interface_transceiver",
        }
        if cmd in recorded:
            return ok(load_fixture(recorded[cmd]))
        if cmd == "show hostname":
            return ok({"hostname": "nexus-lab"})
        if cmd == "show user-account":
            rows = [
                {"usr_name": name, "TABLE_role": {"ROW_role": {"role": role}}}
                for name, (_, role) in self.users.items()
            ]
            return ok({"TABLE_template": {"ROW_template": rows[0] if len(rows) == 1 else rows}})
        if not is_admin:
            return error("% Permission denied for the role\n")
        if match := re.fullmatch(r"username (\S+) password (\S+) role (\S+)", cmd):
            name, password, role = match.groups()
            self.users[name] = (password, role)
            return ok(None)
        if match := re.fullmatch(r"no username (\S+)", cmd):
            self.users.pop(match.group(1), None)
            return ok(None)
        if cmd == "copy running-config startup-config":
            if self.save_text is not None:
                return ok(self.save_text)
            self.saved = True
            return ok(None)
        return error(f"% Invalid command: {cmd.split()[0]}\n")
