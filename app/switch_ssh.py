"""An SSH session to the switch, for the few configuration lines NX-API refuses.

NX-API rejects any command containing ";". The rules of the role that lets
NXray change ports need one (``conf t ; interface * ; shutdown`` is how NX-OS
names a command inside interface configuration), so those lines are typed
into an SSH shell instead, signed in with the admin login the person enters
on the Switch page. Nothing else uses SSH, and no SSH login is stored.

Like the NX-API client, this accepts the switch's SSH host key without
checking it: the switch generates its own key, NXray has no copy to compare
with, and the same trade-off was made for the NX-API certificate.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Protocol

import paramiko

# The end of an NX-OS prompt: "<hostname># " or "<hostname>(config-role)# ".
_PROMPT = re.compile(r"(?:^|[\r\n])[A-Za-z0-9._-]+(?:\([A-Za-z0-9._-]+\))?# ?$")

# Markers NX-OS puts at the start of a line when it refuses a command.
_ERROR_STARTS = ("%", "ERROR", "Error", "Syntax error", "Invalid")

# A pseudo-terminal this wide never wraps a command line NXray sends.
_TERMINAL_WIDTH = 511

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


class SshError(Exception):
    """Base class: the SSH step did not complete."""


class SshUnreachable(SshError):
    """No SSH answer: wrong address or port, SSH off, firewall, timeout."""


class SshAuthError(SshError):
    """The switch refused the SSH username or password."""


class SshCommandError(SshError):
    """The switch refused a configuration line."""


class Shell(Protocol):
    """An open command line on the switch. Tests provide a pretend one."""

    def run(self, line: str) -> str:
        """Type one line, wait for the next prompt, return what was printed."""
        ...

    def close(self) -> None: ...


# (host, port, username, password, timeout) -> Shell
ShellOpener = Callable[[str, int, str, str, float], Shell]


class _AcceptHostKey(paramiko.MissingHostKeyPolicy):
    """Accept the switch's host key without checking it (see the module docstring)."""

    def missing_host_key(self, client, hostname, key) -> None:  # noqa: ANN001
        return None


class ParamikoShell:
    """An interactive NX-OS shell over a paramiko SSH connection."""

    def __init__(self, client: paramiko.SSHClient, timeout: float) -> None:
        self._client = client
        self._timeout = timeout
        self._channel = client.invoke_shell(term="vt100", width=_TERMINAL_WIDTH, height=200)
        self._channel.settimeout(timeout)
        self._read_until_prompt()
        self.run("terminal length 0")

    def _read_until_prompt(self) -> str:
        deadline = time.monotonic() + self._timeout
        received = ""
        while True:
            if _PROMPT.search(received):
                return received
            if time.monotonic() > deadline:
                raise SshUnreachable(
                    f"the switch stopped answering over SSH within {self._timeout:g} seconds"
                )
            try:
                chunk = self._channel.recv(65536)
            except TimeoutError as exc:
                raise SshUnreachable(
                    f"the switch stopped answering over SSH within {self._timeout:g} seconds"
                ) from exc
            if not chunk:
                raise SshUnreachable("the switch closed the SSH session")
            received += _ANSI.sub("", chunk.decode("utf-8", errors="replace"))

    def run(self, line: str) -> str:
        self._channel.sendall((line + "\n").encode())
        output = self._read_until_prompt()
        # Drop the echoed command (first line) and the prompt (last line).
        lines = output.replace("\r", "").split("\n")
        return "\n".join(lines[1:-1]).strip()

    def close(self) -> None:
        try:
            self._channel.close()
        finally:
            self._client.close()


def open_paramiko_shell(
    host: str, port: int, username: str, password: str, timeout: float
) -> ParamikoShell:
    """Sign in over SSH with a password and open a shell. The default opener."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(_AcceptHostKey())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            # Only the password typed on the page: never this machine's own
            # keys or an SSH agent that happens to be running.
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.AuthenticationException as exc:
        client.close()
        raise SshAuthError("the switch refused the SSH username or password") from exc
    except (OSError, paramiko.SSHException) as exc:
        client.close()
        raise SshUnreachable(f"could not open SSH to {host}:{port}: {exc}") from exc
    try:
        return ParamikoShell(client, timeout)
    except paramiko.SSHException as exc:
        client.close()
        raise SshUnreachable(f"the switch did not open an SSH shell: {exc}") from exc
    except SshError:
        client.close()
        raise


def refused(output: str) -> str | None:
    """The switch's complaint in a command's output, or None if it accepted it."""
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(_ERROR_STARTS):
            return stripped
    return None


def run_config(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    lines: list[str],
    timeout: float,
    opener: ShellOpener | None = None,
) -> None:
    """Sign in over SSH and type ``lines`` in configuration mode, stopping at a refusal.

    The lines are built by the caller from checked values; this function adds
    ``configure terminal`` before them and ``end`` after, and raises
    SshCommandError naming the first line the switch refused.
    """
    shell = (opener or open_paramiko_shell)(host, port, username, password, timeout)
    try:
        for line in ["configure terminal", *lines]:
            complaint = refused(shell.run(line))
            if complaint:
                shell.run("end")
                raise SshCommandError(f"{line!r}: {complaint}")
        shell.run("end")
    finally:
        shell.close()
