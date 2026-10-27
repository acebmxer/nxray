"""Shared test fixtures.

Every test gets its own temporary data directory and database, so tests never
share state and never touch a real deployment.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.security import hash_password

TEST_USER = "admin"
TEST_PASSWORD = "correct-horse-battery"
FIXTURES = Path(__file__).parent / "fixtures"

# Hashed once: Argon2 is slow on purpose, and every test needs the same hash.
_TEST_HASH = hash_password(TEST_PASSWORD)


def load_fixture(name: str) -> dict[str, Any]:
    """A recorded `show ... | json` body (scrubbed of serials, hostname, IPs)."""
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        admin_user=TEST_USER,
        admin_password_hash=_TEST_HASH,
        secret_key="test-secret-key-not-for-production",
        https_only=False,
        session_hours=12,
        login_max_attempts=5,
        login_lockout_minutes=15,
        log_level="WARNING",
    )


@pytest.fixture
def make_client() -> Iterator[Callable[[Settings], TestClient]]:
    """Build a started test client for given settings; all are closed after."""
    opened: list[TestClient] = []

    def _make(custom: Settings) -> TestClient:
        # Redirects are part of what these tests assert (anonymous callers are
        # sent to /login), so following them silently would hide the behaviour.
        test_client = TestClient(create_app(custom), follow_redirects=False)
        test_client.__enter__()
        opened.append(test_client)
        return test_client

    yield _make
    for test_client in opened:
        test_client.__exit__(None, None, None)


@pytest.fixture
def client(settings: Settings, make_client: Callable[[Settings], TestClient]) -> TestClient:
    return make_client(settings)


@pytest.fixture
def logged_in(client: TestClient) -> TestClient:
    response = client.post(
        "/login",
        data={"username": TEST_USER, "password": TEST_PASSWORD, "next": "/"},
    )
    assert response.status_code == 303, "fixture could not log in"
    return client


def with_settings(settings: Settings, **changes: Any) -> Settings:
    """A copy of the settings with some fields changed."""
    return dataclasses.replace(settings, **changes)
