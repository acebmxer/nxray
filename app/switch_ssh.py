"""An SSH session to the switch, for the few configuration lines NX-API refuses.

NX-API rejects any command containing ";". The rules of the role that lets
NXray change ports need one (``conf t ; interface * ; shutdown`` is how NX-OS
names a command inside interface configuration), so those lines are typed
into an SSH shell instead, signed in with the admin login the person enters
on the Switch page. Restarting the switch (``reload_switch``, from the Config
page) also goes over SSH with an admin login typed for it: ``reload`` asks a
question, which NX-API cannot answer.

The switch file pages use SSH too, with the stored admin login: ``Session`` runs one
command and streams what it prints (``show tech-support``, the install check, the
install itself, which take minutes and print far more than NX-API answers with), and
copies files to and from bootflash with SCP. The switch's SFTP server closes every
session at once (seen on cisco-25gb, NX-OS 9.3(16), with ``feature sftp-server`` on),
so the copies use the older SCP protocol, which needs ``feature scp-server``. Pasting
a CA certificate (``crypto ca authenticate``) answers the switch's questions in a shell
(``authenticate_ca``).

Like the NX-API client, this accepts the switch's SSH host key without
checking it: the switch generates its own key, NXray has no copy to compare
with, and the same trade-off was made for the NX-API certificate.
"""

from __future__ import annotations

import contextlib
import re
import time
from collections.abc import Callable, Iterator
from typing import BinaryIO, Protocol

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

    def converse(self, line: str, expect: re.Pattern[str]) -> str:
        """Type one line and wait for ``expect`` (a question the switch asks) or the
        next prompt, whichever comes first; return what was printed."""
        ...

    def type_lines(self, lines: list[str]) -> None:
        """Type lines the switch reads as input to a question, waiting for nothing."""
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

    def _read_until_prompt(self, expect: re.Pattern[str] | None = None) -> str:
        deadline = time.monotonic() + self._timeout
        received = ""
        while True:
            if _PROMPT.search(received) or (expect is not None and expect.search(received)):
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

    def converse(self, line: str, expect: re.Pattern[str]) -> str:
        self._channel.sendall((line + "\n").encode())
        output = self._read_until_prompt(expect)
        # Drop the echoed command (first line); a question has no prompt after it.
        return "\n".join(output.replace("\r", "").split("\n")[1:]).strip()

    def type_lines(self, lines: list[str]) -> None:
        for line in lines:
            self._channel.sendall((line + "\n").encode())

    def close(self) -> None:
        try:
            self._channel.close()
        finally:
            self._client.close()


def _connect(
    host: str, port: int, username: str, password: str, timeout: float
) -> paramiko.SSHClient:
    """A signed-in paramiko SSHClient; SshAuthError or SshUnreachable when not."""
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
    return client


def open_paramiko_shell(
    host: str, port: int, username: str, password: str, timeout: float
) -> ParamikoShell:
    """Sign in over SSH with a password and open a shell. The default opener."""
    client = _connect(host, port, username, password, timeout)
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
    then: tuple[str, ...] = (),
) -> list[str]:
    """Sign in over SSH and type ``lines`` in configuration mode, stopping at a refusal.

    The lines are built by the caller from checked values; this function adds
    ``configure terminal`` before them and ``end`` after, and raises
    SshCommandError naming the first line the switch refused. The fixed
    ``then`` commands are typed after ``end``, in the same session; their
    output is returned for the caller to check.
    """
    shell = (opener or open_paramiko_shell)(host, port, username, password, timeout)
    try:
        for line in ["configure terminal", *lines]:
            complaint = refused(shell.run(line))
            if complaint:
                shell.run("end")
                raise SshCommandError(f"{line!r}: {complaint}")
        shell.run("end")
        return [shell.run(line) for line in then]
    finally:
        shell.close()


def run_commands(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    lines: tuple[str, ...],
    timeout: float,
    opener: ShellOpener | None = None,
) -> list[str]:
    """Sign in over SSH and type fixed commands outside configuration mode.

    Returns each command's output for the caller to check.
    """
    shell = (opener or open_paramiko_shell)(host, port, username, password, timeout)
    try:
        return [shell.run(line) for line in lines]
    finally:
        shell.close()


def reload_switch(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: float,
    opener: ShellOpener | None = None,
) -> None:
    """Sign in over SSH and restart the switch: ``terminal dont-ask``, so ``reload``
    asks nothing, then ``reload``.

    The switch drops the session as it goes down, so SshUnreachable after
    ``reload`` is the answer that means it is restarting. A prompt coming back
    means it did not: SshCommandError with what it printed. Signing in raises
    SshAuthError or SshUnreachable as ``run_config`` does.
    """
    shell = (opener or open_paramiko_shell)(host, port, username, password, timeout)
    try:
        complaint = refused(shell.run("terminal dont-ask"))
        if complaint:
            raise SshCommandError(f"'terminal dont-ask': {complaint}")
        try:
            output = shell.run("reload")
        except SshUnreachable:
            return
        raise SshCommandError(
            f"'reload': {refused(output) or output.strip() or 'the switch did not restart'}"
        )
    finally:
        # The session is usually gone already; closing it may fail in any way.
        with contextlib.suppress(Exception):
            shell.close()


# ---- one command, file copies ---------------------------------------------------------

# How much of a file is read or sent at a time.
_CHUNK = 256 * 1024


class Session(Protocol):
    """A signed-in SSH connection for one long command or one file copy at a time.
    Tests provide a pretend one."""

    def stream(self, command: str, timeout: float) -> Iterator[bytes]:
        """Run ``command`` (a fixed command NXray builds) and yield what it prints as it
        comes. SshCommandError when it ends with an error status and printed nothing."""
        ...

    def download(self, remote: str) -> tuple[int, Iterator[bytes]]:
        """Copy ``remote`` (``bootflash:name``) off the switch with SCP: its size, and
        its bytes as they come. SshCommandError when the switch refuses."""
        ...

    def upload(
        self, source: BinaryIO, size: int, remote: str, progress: Callable[[int], None]
    ) -> None:
        """Copy ``size`` bytes from ``source`` to ``remote`` with SCP, calling
        ``progress`` with the bytes sent so far. SshCommandError when refused."""
        ...

    def close(self) -> None: ...


# (host, port, username, password, timeout) -> Session
SessionOpener = Callable[[str, int, str, str, float], Session]


def _scp_answer(channel: paramiko.Channel, step: str) -> None:
    """Read SCP's one-byte answer: 0 is yes, 1 or 2 come with the switch's reason."""
    code = channel.recv(1)
    if code == b"\0":
        return
    if not code:
        raise SshCommandError(f"{step}: the switch closed the copy")
    reason = b""
    while not reason.endswith(b"\n"):
        more = channel.recv(1)
        if not more:
            break
        reason += more
    message = reason.decode("utf-8", errors="replace").strip() or "refused"
    raise SshCommandError(f"{step}: {message}")


class ParamikoSession:
    """``Session`` over paramiko: one exec channel per command or copy."""

    def __init__(self, client: paramiko.SSHClient, timeout: float) -> None:
        self._client = client
        self._timeout = timeout

    def _channel(self, command: str, timeout: float) -> paramiko.Channel:
        transport = self._client.get_transport()
        if transport is None or not transport.is_active():
            raise SshUnreachable("the switch closed the SSH session")
        channel = transport.open_session(timeout=self._timeout)
        channel.settimeout(timeout)
        channel.exec_command(command)
        return channel

    def stream(self, command: str, timeout: float) -> Iterator[bytes]:
        channel = self._channel(command, timeout)
        printed = False
        try:
            while True:
                try:
                    chunk = channel.recv(_CHUNK)
                except TimeoutError as exc:
                    raise SshUnreachable(
                        f"the switch stopped answering over SSH within {timeout:g} seconds"
                    ) from exc
                if not chunk:
                    break
                printed = True
                yield chunk
            status = channel.recv_exit_status()
            if status and not printed:
                complaint = channel.recv_stderr(65536).decode("utf-8", errors="replace").strip()
                raise SshCommandError(f"{command!r}: {complaint or f'error status {status}'}")
        finally:
            channel.close()

    def download(self, remote: str) -> tuple[int, Iterator[bytes]]:
        channel = self._channel(f"scp -f {remote}", self._timeout)
        try:
            channel.sendall(b"\0")
            header = b""
            while not header.endswith(b"\n"):
                more = channel.recv(1)
                if not more:
                    raise SshCommandError(f"copying {remote}: the switch closed the copy")
                header += more
                if header[:1] in (b"\1", b"\2") and header.endswith(b"\n"):
                    reason = header[1:].decode("utf-8", errors="replace").strip()
                    raise SshCommandError(f"copying {remote}: {reason}")
            match = re.fullmatch(rb"C[0-7]{4} ([0-9]+) [^\n]*\n", header)
            if match is None:
                raise SshCommandError(f"copying {remote}: the switch sent no file")
            size = int(match.group(1))
            channel.sendall(b"\0")
        except BaseException:
            channel.close()
            raise

        def body() -> Iterator[bytes]:
            try:
                left = size
                while left:
                    chunk = channel.recv(min(_CHUNK, left))
                    if not chunk:
                        raise SshCommandError(f"copying {remote}: the copy stopped early")
                    left -= len(chunk)
                    yield chunk
                _scp_answer(channel, f"copying {remote}")
                channel.sendall(b"\0")
            finally:
                channel.close()

        return size, body()

    def upload(
        self, source: BinaryIO, size: int, remote: str, progress: Callable[[int], None]
    ) -> None:
        name = remote.split(":", 1)[-1].rsplit("/", 1)[-1]
        channel = self._channel(f"scp -t {remote}", self._timeout)
        try:
            _scp_answer(channel, f"copying to {remote}")
            channel.sendall(f"C0644 {size} {name}\n".encode())
            _scp_answer(channel, f"copying to {remote}")
            sent = 0
            while sent < size:
                chunk = source.read(min(_CHUNK, size - sent))
                if not chunk:
                    raise SshCommandError(f"copying to {remote}: the file ended early")
                channel.sendall(chunk)
                sent += len(chunk)
                progress(sent)
            channel.sendall(b"\0")
            _scp_answer(channel, f"copying to {remote}")
        finally:
            channel.close()

    def close(self) -> None:
        self._client.close()


def open_paramiko_session(
    host: str, port: int, username: str, password: str, timeout: float
) -> ParamikoSession:
    """Sign in over SSH with a password for commands and copies. The default opener."""
    return ParamikoSession(_connect(host, port, username, password, timeout), timeout)


# ---- pasting a CA certificate -------------------------------------------------------------

_PASTE_QUESTION = re.compile(r"END OF INPUT\s*:\s*$")
_ACCEPT_QUESTION = re.compile(r"\[yes/no\]:?\s*$")
_FINGERPRINT = re.compile(r"Fingerprint=([0-9A-Fa-f:]+)")


def authenticate_ca(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    trustpoint: str,
    pem_lines: list[str],
    fingerprints: frozenset[str],
    timeout: float,
    opener: ShellOpener | None = None,
) -> None:
    """Give trustpoint ``trustpoint`` its CA certificate: ``crypto ca authenticate``,
    the PEM lines, ``END OF INPUT``, then yes to the switch's question, but only when
    every SHA1 fingerprint it shows is one of ``fingerprints`` (the certificates NXray
    read); otherwise no.

    The trustpoint name and the PEM lines are checked by the caller. SshCommandError
    with the switch's words when it refuses the certificate.
    """
    shell = (opener or open_paramiko_shell)(host, port, username, password, timeout)
    try:
        shell.run("configure terminal")
        asked = shell.converse(f"crypto ca authenticate {trustpoint}", _PASTE_QUESTION)
        if not _PASTE_QUESTION.search(asked):
            raise SshCommandError(
                f"crypto ca authenticate {trustpoint}: {refused(asked) or asked or 'no question'}"
            )
        shell.type_lines(pem_lines)
        answer = shell.converse("END OF INPUT", _ACCEPT_QUESTION)
        if not _ACCEPT_QUESTION.search(answer):
            lines = [line.strip() for line in answer.splitlines() if line.strip()]
            shell.run("end")
            raise SshCommandError(
                f"crypto ca authenticate {trustpoint}: {'; '.join(lines) or 'refused'}"
            )
        shown = {found.upper() for found in _FINGERPRINT.findall(answer)}
        if not shown or not shown <= {f.upper() for f in fingerprints}:
            shell.run("no")
            shell.run("end")
            raise SshCommandError(
                f"crypto ca authenticate {trustpoint}: the switch showed a different "
                "certificate, so NXray answered no"
            )
        complaint = refused(shell.run("yes"))
        shell.run("end")
        if complaint:
            raise SshCommandError(f"crypto ca authenticate {trustpoint}: {complaint}")
    finally:
        with contextlib.suppress(Exception):
            shell.close()
