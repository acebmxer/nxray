"""Shared set-up for the AAA, SSH and certificates, Files, Software and Tech support page
tests: a switch set up against the fake one, with changes turned on in a given role mode."""

from __future__ import annotations

import html
import re
import sqlite3
import time

from fastapi.testclient import TestClient

from app.config import Settings
from app.switch_jobs import Jobs
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


def csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(c.startswith(("show ", "dir ")) for c in r)]


def set_up(client: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
    state = client.app.state  # type: ignore[attr-defined]
    state.nxapi_transport = fake.transport()
    state.ssh_opener = fake.ssh_opener()
    state.ssh_session_opener = fake.session_opener()
    state.jobs = Jobs(background=False)
    client.post(
        "/switch/setup",
        data={
            "csrf": csrf(client, "/switch"),
            "host": "192.0.2.10",
            "port": "443",
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "account_name": "nxray",
            "confirm_save": "yes",
        },
    )
    fake.requests.clear()
    return fake


def enable(client: TestClient, settings: Settings, fake: FakeSwitch, mode: str) -> FakeSwitch:
    response = client.post(
        "/switch/enable-changes",
        data={
            "csrf": csrf(client, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "role_mode": mode,
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    conn = sqlite3.connect(settings.db_path)
    conn.execute(f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    conn.commit()
    conn.close()
    fake.requests.clear()
    fake.signed_in.clear()
    return fake


def sign_in_as(client: TestClient, name: str, role: str) -> TestClient:
    """A second browser, signed in as a new NXray account with ``role``."""
    password = "another-long-password"
    client.post(
        "/users/create",
        data={
            "csrf": csrf(client, "/users"),
            "new_username": name,
            "password": password,
            "confirm_password": password,
            "role": role,
        },
    )
    other = TestClient(client.app, follow_redirects=False)
    response = other.post("/login", data={"username": name, "password": password, "next": "/"})
    assert response.status_code == 303
    return other
