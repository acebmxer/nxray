"""The password hash helper used to fill in NXRAY_ADMIN_PASSWORD_HASH."""

from __future__ import annotations

import io

import pytest

from app import hashpw
from app.security import verify_password


def _run(monkeypatch: pytest.MonkeyPatch, stdin_text: str) -> int:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
    return hashpw.main()


def test_piped_password_prints_a_working_hash(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run(monkeypatch, "a-long-password\n") == 0
    lines = [line for line in capsys.readouterr().out.splitlines() if "=" in line]
    assert len(lines) == 1
    name, value = lines[0].split("=", 1)
    assert name == "NXRAY_ADMIN_PASSWORD_HASH"
    assert value.startswith("$argon2id$")
    assert verify_password("a-long-password", value)


@pytest.mark.parametrize("password", ["", "short"])
def test_empty_or_short_password_is_refused(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], password: str
) -> None:
    assert _run(monkeypatch, password + "\n") == 1
    assert "NXRAY_ADMIN_PASSWORD_HASH" not in capsys.readouterr().out
