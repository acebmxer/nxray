"""app/switch_ssh.py: reading the NX-OS command line, and stopping at a refusal."""

from __future__ import annotations

import pytest

from app import switch_ssh
from app.switch_ssh import (
    ParamikoShell,
    SshCommandError,
    SshUnreachable,
    refused,
    run_config,
)


class FakeChannel:
    """Stands in for a paramiko channel: hands out prepared chunks of output."""

    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = list(chunks)
        self.sent: list[bytes] = []

    def recv(self, size: int) -> bytes:
        if not self.chunks:
            raise TimeoutError
        return self.chunks.pop(0)

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)


def _shell(chunks: list[bytes], timeout: float = 2.0) -> ParamikoShell:
    shell = ParamikoShell.__new__(ParamikoShell)
    shell._channel = FakeChannel(chunks)  # type: ignore[attr-defined]
    shell._timeout = timeout  # type: ignore[attr-defined]
    return shell


# ---- the prompt -----------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "\r\ncisco-25gb# ",
        "\r\ncisco-25gb(config)# ",
        "\r\ncisco-25gb(config-role-interface)# ",
        "nexus-lab#",
    ],
)
def test_prompts_are_recognised(text: str) -> None:
    assert switch_ssh._PROMPT.search(text)


@pytest.mark.parametrize(
    "text",
    [
        "\r\nrule 3 permit command conf t ; interface * ; description *",
        "\r\nEnter configuration commands, one per line.",
        "\r\ncisco-25gb(config)# role name x",  # the echo, not yet the next prompt
    ],
)
def test_output_is_not_mistaken_for_a_prompt(text: str) -> None:
    assert not switch_ssh._PROMPT.search(text)


def test_run_returns_the_output_without_echo_prompt_or_colours() -> None:
    shell = _shell(
        [
            b"show role name x\r\n\x1b[1mRole: x\x1b[0m\r\n",
            b"  Description: test\r\ncisco-25gb# ",
        ]
    )
    assert shell.run("show role name x") == "Role: x\n  Description: test"
    assert shell._channel.sent == [b"show role name x\n"]  # type: ignore[attr-defined]


def test_output_split_mid_prompt_is_read_to_the_end() -> None:
    shell = _shell([b"end\r\ncisco-", b"25gb# "])
    assert shell.run("end") == ""


def test_silence_counts_as_unreachable() -> None:
    shell = _shell([b"copy running-config startup-config\r\n[####  ] 40%"], timeout=0.2)
    with pytest.raises(SshUnreachable, match="stopped answering"):
        shell.run("copy running-config startup-config")


def test_a_closed_session_counts_as_unreachable() -> None:
    shell = _shell([b""])
    with pytest.raises(SshUnreachable, match="closed"):
        shell.run("end")


# ---- refusals -------------------------------------------------------------


@pytest.mark.parametrize(
    ("output", "complaint"),
    [
        ("", None),
        ("Enter configuration commands, one per line.  End with CNTL/Z.", None),
        ("% Incomplete command at '^' marker.", "% Incomplete command at '^' marker."),
        ("            ^\n% Invalid command at '^' marker.", "% Invalid command at '^' marker."),
        ("ERROR: role limit reached", "ERROR: role limit reached"),
        ("Syntax error while parsing 'x'", "Syntax error while parsing 'x'"),
    ],
)
def test_refused(output: str, complaint: str | None) -> None:
    assert refused(output) == complaint


class RecordingShell:
    def __init__(self, answers: dict[str, str] | None = None) -> None:
        self.answers = answers or {}
        self.lines: list[str] = []
        self.closed = False

    def run(self, line: str) -> str:
        self.lines.append(line)
        return self.answers.get(line, "")

    def close(self) -> None:
        self.closed = True


def _opener(shell: RecordingShell):
    def opener(host, port, username, password, timeout):  # noqa: ANN001
        assert (host, port, username, password) == ("192.0.2.10", 22, "admin", "pw")
        return shell

    return opener


def test_run_config_wraps_the_lines_in_configuration_mode() -> None:
    shell = RecordingShell()
    run_config(
        host="192.0.2.10",
        port=22,
        username="admin",
        password="pw",
        lines=["role name a", "exit"],
        timeout=5,
        opener=_opener(shell),
    )
    assert shell.lines == ["configure terminal", "role name a", "exit", "end"]
    assert shell.closed


def test_run_config_stops_at_the_first_refused_line() -> None:
    shell = RecordingShell({"bad": "% Invalid command at '^' marker."})
    with pytest.raises(SshCommandError, match="'bad': % Invalid command"):
        run_config(
            host="192.0.2.10",
            port=22,
            username="admin",
            password="pw",
            lines=["good", "bad", "never"],
            timeout=5,
            opener=_opener(shell),
        )
    assert shell.lines == ["configure terminal", "good", "bad", "end"]
    assert shell.closed
