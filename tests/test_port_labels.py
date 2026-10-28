"""Port labels: storing them, the label form, and where they show."""

from __future__ import annotations

import html
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.db import init_db, open_db
from app.port_labels import LABEL_MAX, get_labels, set_label, validate_label
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": _csrf(logged_in, "/switch"),
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


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _save(client: TestClient, name: str, label: str):
    return client.post("/ports/label", data={"csrf": _csrf(client), "name": name, "label": label})


# ---- storage ----


def test_validate_label() -> None:
    assert validate_label("  Proxmox node 2, NIC 1  ") == "Proxmox node 2, NIC 1"
    assert validate_label("") == ""
    # Characters a switch description refuses are fine: the switch never sees a label.
    assert validate_label("NAS; disk ?") == "NAS; disk ?"
    assert validate_label("Büro-Drucker") == "Büro-Drucker"
    assert validate_label("x" * LABEL_MAX) == "x" * LABEL_MAX
    with pytest.raises(ValueError, match="at most 64"):
        validate_label("x" * (LABEL_MAX + 1))
    for bad in ("one\ntwo", "tab\there", "nul\x00"):
        with pytest.raises(ValueError, match="one line"):
            validate_label(bad)


def test_set_get_and_remove(tmp_path: Path) -> None:
    db = tmp_path / "nxray.db"
    init_db(db)
    with open_db(db) as conn:
        assert get_labels(conn) == {}
        assert set_label(conn, "Ethernet1/3", " NAS ", "admin") == "NAS"
        set_label(conn, "Ethernet1/4", "printer", "admin")
        set_label(conn, "Ethernet1/3", "NAS 2", "otto")
        assert get_labels(conn) == {"Ethernet1/3": "NAS 2", "Ethernet1/4": "printer"}
        query = "SELECT updated_by FROM port_labels WHERE port = ?"
        row = conn.execute(query, ("Ethernet1/3",)).fetchone()
        assert row["updated_by"] == "otto"
        set_label(conn, "Ethernet1/4", "", "admin")
        assert get_labels(conn) == {"Ethernet1/3": "NAS 2"}
        with pytest.raises(ValueError):
            set_label(conn, "mgmt0", "no", "admin")


# ---- pages ----


def test_a_label_is_saved_without_touching_the_switch(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    response = _save(logged_in, "Ethernet1/3", "Proxmox node 2, NIC 1")
    assert response.status_code == 200
    text = _text(response.text)
    assert 'Ethernet1/3 now has the label "Proxmox node 2, NIC 1"' in text
    assert "Label Proxmox node 2, NIC 1" in text
    # Only reads: no configuration command went to the switch.
    assert all(cmd.startswith("show ") for request in switch.requests for cmd in request)

    ports = logged_in.get("/ports").text
    assert '<span class="port-label">Proxmox node 2, NIC 1</span>' in ports
    assert "Ethernet1/3 — Proxmox node 2, NIC 1" in ports
    assert "Has a label" in ports


def test_an_empty_label_removes_it(logged_in: TestClient, switch: FakeSwitch) -> None:
    _save(logged_in, "Ethernet1/3", "NAS")
    text = _text(_save(logged_in, "Ethernet1/3", "  ").text)
    assert "Ethernet1/3 no longer has a label." in text
    assert "port-label" not in logged_in.get("/ports").text


def test_a_refused_label_keeps_what_was_typed(logged_in: TestClient, switch: FakeSwitch) -> None:
    long = "y" * (LABEL_MAX + 5)
    response = _save(logged_in, "Ethernet1/3", long)
    assert response.status_code == 400
    assert "Label not saved: a label is at most 64 characters." in _text(response.text)
    assert f'value="{long}"' in response.text


def test_labels_are_escaped(logged_in: TestClient, switch: FakeSwitch) -> None:
    _save(logged_in, "Ethernet1/3", '<img src=x onerror="alert(1)">')
    for page in (
        logged_in.get("/ports").text,
        logged_in.get("/ports/detail?name=Ethernet1/3").text,
    ):
        assert "<img src=x" not in page
        assert "&lt;img src=x" in page


def test_unknown_port_gets_no_label(logged_in: TestClient, switch: FakeSwitch) -> None:
    response = _save(logged_in, "Ethernet9/99", "ghost")
    assert response.status_code == 404
    with open_db(logged_in.app.state.settings.db_path) as conn:  # type: ignore[attr-defined]
        assert get_labels(conn) == {}


def test_the_label_form_needs_the_csrf_token(logged_in: TestClient, switch: FakeSwitch) -> None:
    response = logged_in.post(
        "/ports/label", data={"csrf": "0" * 64, "name": "Ethernet1/3", "label": "x"}
    )
    assert response.status_code in (400, 403)
    with open_db(logged_in.app.state.settings.db_path) as conn:  # type: ignore[attr-defined]
        assert get_labels(conn) == {}


def test_labels_work_while_port_changes_are_off(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/ports/detail?name=Ethernet1/3").text
    assert "Port changes are off" in page
    assert "Save label" in page
    assert _save(logged_in, "Ethernet1/3", "NAS").status_code == 200


def _sign_in_as(client: TestClient, name: str, role: str) -> TestClient:
    password = "another-long-password"
    client.post(
        "/users/create",
        data={
            "csrf": _csrf(client, "/users"),
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


def test_viewers_see_labels_but_get_no_form(logged_in: TestClient, switch: FakeSwitch) -> None:
    _save(logged_in, "Ethernet1/3", "NAS")
    vera = _sign_in_as(logged_in, "vera", "viewer")
    page = vera.get("/ports/detail?name=Ethernet1/3").text
    assert "Label NAS" in _text(page)
    assert "Save label" not in page
    assert "Your role (viewer) can look at labels but not change them" in _text(page)
    assert (
        vera.post(
            "/ports/label", data={"csrf": _csrf(vera), "name": "Ethernet1/3", "label": "x"}
        ).status_code
        == 403
    )


def test_operators_can_label(logged_in: TestClient, switch: FakeSwitch) -> None:
    otto = _sign_in_as(logged_in, "otto", "operator")
    assert _save(otto, "Ethernet1/3", "NAS").status_code == 200
    with open_db(logged_in.app.state.settings.db_path) as conn:  # type: ignore[attr-defined]
        assert get_labels(conn) == {"Ethernet1/3": "NAS"}
