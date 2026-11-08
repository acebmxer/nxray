"""The theme buttons in the top bar and the menu-width button (app/preferences.py)."""

from __future__ import annotations

import re

from fastapi.testclient import TestClient


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def test_the_theme_follows_the_system_until_one_is_picked(logged_in: TestClient) -> None:
    page = logged_in.get("/account").text
    assert '<html lang="en" data-theme="system">' in page
    assert 'value="system" class="on" aria-pressed="true"' in page
    assert 'class="shell"' in page


def test_picking_a_theme_keeps_it_and_goes_back(logged_in: TestClient) -> None:
    response = logged_in.post(
        "/preferences",
        data={"csrf": _csrf(logged_in), "theme": "dark", "next": "/account"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/account"
    cookie = response.headers["set-cookie"]
    assert "nxray_theme=dark" in cookie and "HttpOnly" in cookie
    page = logged_in.get("/account").text
    assert '<html lang="en" data-theme="dark">' in page
    assert 'value="dark" class="on" aria-pressed="true"' in page


def test_the_menu_can_be_narrowed_and_widened(logged_in: TestClient) -> None:
    logged_in.post("/preferences", data={"csrf": _csrf(logged_in), "menu": "narrow"})
    page = logged_in.get("/account").text
    assert 'class="shell shell-narrow"' in page
    assert 'name="menu" value="wide"' in page
    logged_in.post("/preferences", data={"csrf": _csrf(logged_in), "menu": "wide"})
    assert 'class="shell"' in logged_in.get("/account").text


def test_unknown_values_and_addresses_are_ignored(logged_in: TestClient) -> None:
    response = logged_in.post(
        "/preferences",
        data={"csrf": _csrf(logged_in), "theme": "<b>", "menu": "huge", "next": "//evil.example"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert "set-cookie" not in response.headers
    logged_in.cookies.set("nxray_theme", "<b>")
    assert 'data-theme="system"' in logged_in.get("/account").text


def test_the_form_needs_its_token(logged_in: TestClient) -> None:
    response = logged_in.post("/preferences", data={"theme": "dark"}, follow_redirects=False)
    assert response.status_code == 403


def test_signed_out_visitors_are_sent_to_sign_in(client: TestClient) -> None:
    response = client.post("/preferences", data={"theme": "dark"}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")
