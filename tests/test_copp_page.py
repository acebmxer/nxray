"""The Control-plane policing page, end to end against the fake switch: reading it, and that
it offers no changes."""

from __future__ import annotations

import html
import re

import pytest
from fastapi.testclient import TestClient

from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    """A switch that has been set up (read-only account nxray); the control-plane policy is
    the one recorded on cisco-25gb."""
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
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


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/copp", follow_redirects=False).status_code == 303


def test_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/copp").text)


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/copp"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/copp")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "Policy on the control plane: copp-system-p-policy-strict" in text
    assert "copp-system-p-class-important" in text and "2500 kbps" in text
    assert "Dropped (5 min)" in text
    assert switch.requests == [["show policy-map interface control-plane"]]


def test_page_offers_no_changes(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/copp")
    text = _text(page.text)
    assert "/copp/change" not in page.text
    assert "changes are off" not in text and "Each change asks" not in text
    assert logged_in.post("/copp/change", data={"csrf": _csrf(logged_in)}).status_code in (
        404,
        405,
    )


def test_no_policy_on_the_control_plane(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.bodies["show policy-map interface control-plane"] = {}
    text = _text(logged_in.get("/copp").text)
    assert "No CoPP policy is applied to the control plane." in text


def test_save_config_from_the_page_stays_there(logged_in: TestClient, switch: FakeSwitch) -> None:
    response = logged_in.post(
        "/switch/save", data={"csrf": _csrf(logged_in, "/copp"), "back": "copp"}
    )
    assert "Policy on the control plane:" in _text(response.text)


def test_only_the_matches_column_wraps(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/copp").text
    row = re.search(r"<tr><td[^>]*>copp-system-p-class-critical</td>.*?</tr>", page)
    assert row, "no row for the critical class"
    classes = re.findall(r'<td class="([^"]+)">', row.group(0))
    assert classes == ["one-line", "wrap", *["one-line"] * 7]
