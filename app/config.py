"""Configuration, read once from the environment.

This is the ONLY module that reads os.environ. Everything else receives the
``Settings`` object built here, so there is exactly one place to look for what
a setting is called, what it defaults to, and what validates it.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(RuntimeError):
    """A setting is missing or unusable, and the app must not start."""


def _env_str(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be true or false, got {raw.strip()!r}")


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = _env_str(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a whole number, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}, got {value}")
    return value


@dataclass(frozen=True)
class Settings:
    """Everything the app needs to run, resolved and validated."""

    data_dir: Path
    admin_user: str
    admin_password_hash: str
    secret_key: str
    https_only: bool
    session_hours: int
    login_max_attempts: int
    login_lockout_minutes: int
    log_level: str
    # Built-in HTTPS (docker/entrypoint.sh starts nginx in front of the app).
    enable_https: bool = False
    # The port browsers reach HTTPS on: the left number of the 8443 mapping in
    # docker-compose.yml. Plain-HTTP visits are redirected there.
    https_port: int = 8443
    # Self-update (app/update.py): checks GHCR for a newer image and, on an
    # admin's say-so, has the Docker socket recreate this container. Off
    # unless the operator has mounted the socket; see docs/installation.md.
    enable_self_update: bool = False
    # True only on an image built from source (docker-compose.dev.yml sets
    # the build argument): its digest is never the published one.
    dev_build: bool = False
    # Seconds between history samples (app/history.py); 0 turns history off.
    history_interval: int = 60

    # Derived paths. Kept here so no other module builds a path by hand.
    db_path: Path = field(init=False)
    tls_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "db_path", self.data_dir / "nxray.db")
        object.__setattr__(self, "tls_dir", self.data_dir / "tls")


def _load_or_create_secret_key(data_dir: Path) -> str:
    """Return the session signing key, generating one on first boot.

    An explicit NXRAY_SECRET_KEY lets the operator control it. Otherwise a
    generated key is kept on the data volume, so sessions survive a restart
    without the secret ever being baked into the image.
    """
    explicit = _env_str("NXRAY_SECRET_KEY")
    if explicit:
        return explicit

    key_file = data_dir / "secret_key"
    if key_file.exists():
        stored = key_file.read_text(encoding="utf-8").strip()
        if stored:
            return stored

    generated = secrets.token_urlsafe(48)
    key_file.write_text(generated, encoding="utf-8")
    key_file.chmod(0o600)
    return generated


def load_settings() -> Settings:
    """Build the settings object, or raise ConfigError with a fix to apply."""
    data_dir = Path(_env_str("NXRAY_DATA_DIR", "/data"))
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigError(f"cannot create data directory {data_dir}: {exc}") from exc

    password_hash = _env_str("NXRAY_ADMIN_PASSWORD_HASH")
    if not password_hash:
        raise ConfigError(
            "NXRAY_ADMIN_PASSWORD_HASH is not set, so there is no way to log in.\n"
            "\n"
            "Generate one with:\n"
            "    docker compose run --rm nxray python -m app.hashpw\n"
            "\n"
            "then paste the printed line into nxray.env.\n"
            "\n"
            "NXray will not start with a default password."
        )
    if not password_hash.startswith("$argon2"):
        raise ConfigError(
            "NXRAY_ADMIN_PASSWORD_HASH does not look like an Argon2 hash "
            "(it should begin with '$argon2id$'). It must be a hash, not a "
            "plaintext password. Generate one with: python -m app.hashpw"
        )

    log_level = _env_str("NXRAY_LOG_LEVEL", "INFO").upper()
    if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        raise ConfigError(
            f"NXRAY_LOG_LEVEL must be DEBUG, INFO, WARNING or ERROR, got {log_level!r}"
        )

    # Built-in HTTPS means the browser is always on HTTPS (NXray's own nginx
    # terminates it), so it implies the Secure cookie flag. NXRAY_HTTPS stays
    # for the other case: a reverse proxy of your own, which NXray can't see.
    enable_https = _env_bool("NXRAY_ENABLE_HTTPS", False)

    history_interval = _env_int("NXRAY_HISTORY_INTERVAL", 60, 0, 3600)
    if 0 < history_interval < 10:
        raise ConfigError(
            "NXRAY_HISTORY_INTERVAL must be 0 (history off) or at least 10 seconds, "
            f"got {history_interval}"
        )

    return Settings(
        data_dir=data_dir,
        admin_user=_env_str("NXRAY_ADMIN_USER", "admin") or "admin",
        admin_password_hash=password_hash,
        secret_key=_load_or_create_secret_key(data_dir),
        https_only=_env_bool("NXRAY_HTTPS", enable_https),
        session_hours=_env_int("NXRAY_SESSION_HOURS", 12, 1, 720),
        login_max_attempts=_env_int("NXRAY_LOGIN_MAX_ATTEMPTS", 5, 1, 100),
        login_lockout_minutes=_env_int("NXRAY_LOGIN_LOCKOUT_MINUTES", 15, 1, 1440),
        log_level=log_level,
        enable_https=enable_https,
        https_port=_env_int("NXRAY_HTTPS_PORT", 8443, 1, 65535),
        enable_self_update=_env_bool("NXRAY_ENABLE_SELF_UPDATE", False),
        dev_build=_env_bool("NXRAY_DEV_BUILD", False),
        history_interval=history_interval,
    )
