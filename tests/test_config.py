"""Configuration validation: the app must not start misconfigured."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from app.config import ConfigError, load_settings

FAKE_HASH = "$argon2id$v=19$m=65536,t=3,p=4$fake"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in (
        "NXRAY_ADMIN_USER",
        "NXRAY_ADMIN_PASSWORD_HASH",
        "NXRAY_SECRET_KEY",
        "NXRAY_HTTPS",
        "NXRAY_SESSION_HOURS",
        "NXRAY_LOGIN_MAX_ATTEMPTS",
        "NXRAY_LOGIN_LOCKOUT_MINUTES",
        "NXRAY_LOG_LEVEL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NXRAY_DATA_DIR", str(tmp_path))


def test_missing_password_hash_refuses_to_start() -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_settings()
    # The error has to say how to fix it, not just what is wrong.
    assert "app.hashpw" in str(excinfo.value)


def test_plaintext_password_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NXRAY_ADMIN_PASSWORD_HASH", "hunter2")
    with pytest.raises(ConfigError) as excinfo:
        load_settings()
    assert "Argon2" in str(excinfo.value)


def test_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NXRAY_ADMIN_PASSWORD_HASH", FAKE_HASH)
    settings = load_settings()
    assert settings.admin_user == "admin"
    assert settings.https_only is False
    assert settings.session_hours == 12
    assert settings.login_max_attempts == 5
    assert settings.login_lockout_minutes == 15
    assert settings.log_level == "INFO"
    assert settings.db_path == tmp_path / "nxray.db"


def test_secret_key_is_generated_private_and_reused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("NXRAY_ADMIN_PASSWORD_HASH", FAKE_HASH)

    first = load_settings()
    key_file = tmp_path / "secret_key"
    assert first.secret_key
    assert key_file.exists()
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600

    # A restart must reuse the stored key, or every restart logs everyone out.
    assert load_settings().secret_key == first.secret_key


def test_explicit_secret_key_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("NXRAY_ADMIN_PASSWORD_HASH", FAKE_HASH)
    monkeypatch.setenv("NXRAY_SECRET_KEY", "operator-chosen")
    assert load_settings().secret_key == "operator-chosen"
    assert not (tmp_path / "secret_key").exists()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("NXRAY_SESSION_HOURS", "twelve"),
        ("NXRAY_SESSION_HOURS", "0"),
        ("NXRAY_LOGIN_MAX_ATTEMPTS", "1000"),
        ("NXRAY_HTTPS", "maybe"),
        ("NXRAY_LOG_LEVEL", "LOUD"),
    ],
)
def test_bad_setting_is_reported_by_name(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv("NXRAY_ADMIN_PASSWORD_HASH", FAKE_HASH)
    monkeypatch.setenv(name, value)
    with pytest.raises(ConfigError) as excinfo:
        load_settings()
    assert name in str(excinfo.value)


def test_https_setting_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NXRAY_ADMIN_PASSWORD_HASH", FAKE_HASH)
    monkeypatch.setenv("NXRAY_HTTPS", "true")
    assert load_settings().https_only is True
