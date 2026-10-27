"""Client for Cisco NX-API (JSON-RPC over HTTPS).

This is the only module that talks to the switch. Everything else asks it to
run commands and receives parsed JSON bodies back.

NX-API is turned on with ``feature nxapi`` on the switch. It accepts CLI
commands at ``https://<switch>/ins`` as JSON-RPC 2.0 requests and answers
with the same structured data that ``<command> | json`` prints in an SSH
session.

The switch's HTTPS certificate is not checked. NX-API ships with a
self-signed certificate it generates itself, and NXray deliberately accepts
it: the traffic is still encrypted, but the switch's identity is not
verified. This is a project decision, not an oversight.

Read-only ``show`` commands go through ``show()``. The few configuration
commands NXray needs have their own methods (``create_user``,
``delete_user``, ``save_config``), each building its one command from
checked values, so nothing that renders a page can change the switch by
accident and no caller can pass free text to the switch's configuration.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

import httpx

# A hostname (RFC 1123 labels) or an IPv4/IPv6 literal. Anything else, such
# as a value with a path, scheme or credentials in it, is refused so the
# setting can never point the client at a URL other than the switch's /ins.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)

# NX-API runs several commands in one "cli" call when they are separated by
# " ;". Refusing ";" and line breaks keeps one request entry equal to exactly
# one command, so a value that reaches show() cannot smuggle a second one in.
_FORBIDDEN_IN_COMMAND = re.compile(r"[;\r\n]")

# NX-OS user names: up to 28 characters. Stricter than NX-OS itself (which
# also allows + and =) so a name is always safe inside a command line.
_ACCOUNT_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,27}$")

# Only letters and digits: no character the NX-OS command line could read as
# a separator, a quote or a request for help ("?").
_SAFE_PASSWORD = re.compile(r"^[A-Za-z0-9]{8,64}$")

# The only roles NXray ever gives its own account.
ALLOWED_ROLES = frozenset({"network-operator"})

# Names NX-OS keeps for itself, plus the switch's own admin account.
RESERVED_ACCOUNT_NAMES = frozenset(
    {
        "admin", "adm", "bin", "daemon", "ftp", "ftpuser", "games", "gdm", "gopher",
        "halt", "lp", "mail", "mailnull", "man", "mtsuser", "news", "nobody", "nscd",
        "operator", "root", "rpc", "rpcuser", "shutdown", "sync", "sys", "uucp", "xfs",
    }
)  # fmt: skip

# Saving the configuration can take a while on a busy switch.
SAVE_CONFIG_TIMEOUT = 120.0


class NxapiError(Exception):
    """Base class: the switch could not give an answer."""


class NxapiUnreachable(NxapiError):
    """No HTTP answer at all: wrong address, NX-API off, firewall, timeout."""


class NxapiAuthError(NxapiError):
    """The switch refused the username or password."""


class NxapiCommandError(NxapiError):
    """The switch answered, but rejected a command."""


class NxapiProtocolError(NxapiError):
    """The switch answered with something that is not a usable NX-API reply."""


@dataclass(frozen=True)
class SwitchTarget:
    """Where the switch's NX-API is and how to log in to it."""

    host: str
    port: int
    username: str
    password: str
    timeout: float

    def __repr__(self) -> str:
        # Never let the password reach a log line or a traceback.
        return f"SwitchTarget(host={self.host!r}, port={self.port}, username={self.username!r})"

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"https://{host}:{self.port}/ins"


def is_valid_host(value: str) -> bool:
    """True for a bare hostname or IP address, with nothing else attached."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(_HOSTNAME.match(value))


def validate_account_name(name: str) -> str:
    """Return the name, or raise ValueError if NXray would not use it on a switch."""
    if not _ACCOUNT_NAME.match(name):
        raise ValueError(
            "an account name is 1-28 characters: a letter first, then letters, "
            "digits, dots, dashes or underscores"
        )
    if name.lower() in RESERVED_ACCOUNT_NAMES:
        raise ValueError(f"{name!r} is reserved on the switch; pick another name")
    return name


def validate_show_command(command: str) -> str:
    """Return the command stripped, or raise ValueError if it is not a lone show."""
    cleaned = command.strip()
    if not cleaned.lower().startswith("show "):
        raise ValueError(f"only show commands are allowed here, got {cleaned!r}")
    if _FORBIDDEN_IN_COMMAND.search(cleaned):
        raise ValueError(f"a command must not contain ';' or a line break: {cleaned!r}")
    return cleaned


def build_payload(commands: list[str]) -> list[dict[str, Any]]:
    """The JSON-RPC request body for running ``commands`` in order."""
    return [
        {
            "jsonrpc": "2.0",
            "method": "cli",
            "params": {"cmd": command, "version": 1},
            "id": index,
        }
        for index, command in enumerate(commands, start=1)
    ]


def parse_response(
    payload: Any,
    commands: list[str],
    labels: list[str] | None = None,
    allow_text: bool = False,
) -> list[dict[str, Any]]:
    """Turn a JSON-RPC reply into one body per command, in request order.

    NX-API answers a one-command request with a single object rather than a
    one-element list, so both shapes are accepted. A command that prints
    nothing comes back with a null body, returned here as an empty dict.

    ``labels`` replace the commands in error messages, for commands that
    carry a secret (a password) that must never reach a log or a page.
    ``allow_text`` accepts a plain-text answer (configuration commands have
    no structured output) and returns it as ``{"text": ...}``.
    """
    names = labels if labels is not None else commands
    entries = payload if isinstance(payload, list) else [payload]
    if len(entries) != len(commands):
        raise NxapiProtocolError(
            f"asked for {len(commands)} command(s), the switch answered {len(entries)}"
        )

    by_id: dict[int, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), int):
            raise NxapiProtocolError("the switch sent a reply entry without an id")
        by_id[entry["id"]] = entry

    bodies: list[dict[str, Any]] = []
    for index, command in enumerate(names, start=1):
        entry = by_id.get(index)
        if entry is None:
            raise NxapiProtocolError(f"no answer for {command!r}")
        if "error" in entry:
            raise NxapiCommandError(f"{command!r}: {error_message(entry['error'])}")
        result = entry.get("result")
        if result is None:
            bodies.append({})
            continue
        body = result.get("body") if isinstance(result, dict) else None
        if body is None:
            bodies.append({})
        elif isinstance(body, dict):
            bodies.append(body)
        elif allow_text and isinstance(body, str):
            bodies.append({"text": body})
        else:
            raise NxapiProtocolError(f"{command!r} returned text, not structured data")
    return bodies


def error_message(error: Any) -> str:
    """The most specific message in a JSON-RPC error object."""
    if not isinstance(error, dict):
        return "unknown error"
    data = error.get("data")
    if isinstance(data, dict) and isinstance(data.get("msg"), str) and data["msg"].strip():
        return data["msg"].strip()
    message = error.get("message")
    return message.strip() if isinstance(message, str) and message.strip() else "unknown error"


class NxapiClient:
    """A connection to one switch's NX-API.

    ``transport`` exists for tests, which pass an ``httpx.MockTransport`` that
    answers from recorded switch output instead of opening a socket.
    """

    def __init__(self, target: SwitchTarget, transport: httpx.BaseTransport | None = None):
        self._target = target
        self._http = httpx.Client(
            auth=(target.username, target.password),
            # The switch's self-signed certificate is accepted on purpose;
            # see the module docstring.
            verify=False,
            timeout=target.timeout,
            transport=transport,
            headers={"Content-Type": "application/json-rpc"},
        )

    def __enter__(self) -> NxapiClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    def show(self, *commands: str) -> list[dict[str, Any]]:
        """Run show commands in one request; one parsed body per command."""
        if not commands:
            raise ValueError("no commands given")
        cleaned = [validate_show_command(command) for command in commands]
        return self._send(cleaned, cleaned, self._target.timeout)

    def create_user(self, name: str, password: str, role: str) -> None:
        """Create a local switch account. Needs an admin login.

        Every value is checked before anything is sent, so the one command
        built here can only ever be ``username <name> password <pw> role <r>``.
        The password never appears in an error message.
        """
        validate_account_name(name)
        if not _SAFE_PASSWORD.match(password):
            raise ValueError("the password must be 8-64 letters and digits")
        if role not in ALLOWED_ROLES:
            raise ValueError(f"role {role!r} is not one NXray gives its account")
        command = f"username {name} password {password} role {role}"
        label = f"username {name} password ... role {role}"
        self._send([command], [label], self._target.timeout, allow_text=True)

    def delete_user(self, name: str) -> None:
        """Remove a local switch account. Needs an admin login.

        Only used to undo an account NXray created moments earlier when the
        rest of setup failed, so a retry is not blocked by a leftover.
        """
        validate_account_name(name)
        command = f"no username {name}"
        self._send([command], [command], self._target.timeout, allow_text=True)

    def save_config(self) -> None:
        """``copy running-config startup-config``: keep changes over a reboot."""
        command = "copy running-config startup-config"
        timeout = max(self._target.timeout, SAVE_CONFIG_TIMEOUT)
        (body,) = self._send([command], [command], timeout, allow_text=True)
        # The switch reports a failed copy as text, not as an error.
        text = str(body.get("text", ""))
        if "fail" in text.lower() or "error" in text.lower():
            raise NxapiCommandError(f"{command!r}: {text.strip()}")

    def _send(
        self,
        commands: list[str],
        labels: list[str],
        timeout: float,
        allow_text: bool = False,
    ) -> list[dict[str, Any]]:
        """POST commands as one JSON-RPC request and parse the answer."""
        try:
            response = self._http.post(
                self._target.url, json=build_payload(commands), timeout=timeout
            )
        except httpx.TimeoutException as exc:
            raise NxapiUnreachable(
                f"no answer from {self._target.host}:{self._target.port} within {timeout:g} seconds"
            ) from exc
        except httpx.HTTPError as exc:
            raise NxapiUnreachable(
                f"could not connect to {self._target.host}:{self._target.port}: {exc}"
            ) from exc

        if response.status_code in (401, 403):
            raise NxapiAuthError("the switch refused the NX-API username or password")

        # A rejected command comes back as HTTP 500 with a JSON-RPC error
        # body, so the body is read before the status decides anything.
        try:
            payload = response.json()
        except ValueError as exc:
            raise NxapiProtocolError(
                f"the switch answered HTTP {response.status_code} without JSON "
                "(is this address really NX-API?)"
            ) from exc

        return parse_response(payload, commands, labels, allow_text)
