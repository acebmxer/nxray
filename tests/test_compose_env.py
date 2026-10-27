"""Compose must deliver an Argon2 hash to the container unmangled.

An Argon2 hash is full of `$` ($argon2id$v=19$m=65536,...), and Compose treats
`$` as variable interpolation in two independent places. Getting either wrong
sends the container a hash with pieces missing and it refuses to start.

These are static checks on the compose file rather than a docker run, so they
work in CI without a daemon. The CI docker job runs the image for real.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE = REPO_ROOT / "docker-compose.yml.example"


def _compose_text() -> str:
    return COMPOSE.read_text(encoding="utf-8")


def test_env_file_uses_raw_format() -> None:
    """Without `format: raw`, Compose interpolates values out of the env file."""
    assert "format: raw" in _compose_text(), (
        "docker-compose.yml.example must load the env file with `format: raw`, "
        "or the $ characters in the Argon2 password hash are eaten as variables."
    )


def test_env_file_is_not_called_dot_env() -> None:
    """Compose auto-loads ./.env to interpolate the compose file itself.

    That happens whatever env_file says, so the config file has to be named
    something else or the mangling comes back.
    """
    text = _compose_text()
    assert re.search(r"path:\s*nxray\.env\b", text), (
        "the env file must be named nxray.env, not .env"
    )
    assert not re.search(r"^\s*-\s*\.env\s*$", text, re.MULTILINE)


def test_example_env_file_is_committed() -> None:
    """The sample must survive; the filled-in copy is gitignored."""
    assert (REPO_ROOT / "nxray.env.example").exists()


def test_real_env_file_is_gitignored() -> None:
    ignored = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").split()
    assert "nxray.env" in ignored, "nxray.env holds the password hash"
    assert ".env" in ignored, "a stray .env must not become committable"
    assert "data/" in ignored, "the data folder holds sessions and the secret key"


def test_example_names_every_setting_the_app_reads() -> None:
    """Each NXRAY_* name config.py reads appears in nxray.env.example."""
    config = (REPO_ROOT / "app" / "config.py").read_text(encoding="utf-8")
    example = (REPO_ROOT / "nxray.env.example").read_text(encoding="utf-8")
    names = set(re.findall(r'"(NXRAY_[A-Z_]+)"', config))
    assert names, "found no settings in app/config.py; the check is not working"
    missing = sorted(name for name in names if name not in example)
    assert not missing, f"nxray.env.example does not mention: {missing}"
