"""The left menu's groups fold shut and open from their heading (#94)."""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

GROUPS = ("Monitor", "Configure", "Switch", "Admin")


def _groups(page: str) -> dict[str, str]:
    """Each menu group's opening tag, by its name."""
    return dict(
        (name, tag)
        for tag, name in re.findall(r'(<div class="nav-group[^"]*" data-nav-group="(\w+)">)', page)
    )


def test_each_heading_is_a_button_for_its_own_group(logged_in: TestClient) -> None:
    page = logged_in.get("/account").text
    assert list(_groups(page)) == list(GROUPS)
    for name in GROUPS:
        low = name.lower()
        assert (
            f'<button type="button" class="nav-heading" data-nav-toggle aria-expanded="true" '
            f'aria-controls="nav-{low}"'
        ) in page
        assert f'<div class="nav-items" id="nav-{low}">' in page
    assert '<span class="nav-heading">' not in page


def test_the_group_holding_the_open_page_is_marked(logged_in: TestClient) -> None:
    on_users = _groups(logged_in.get("/users").text)
    assert "nav-group-here" in on_users["Admin"]
    assert all("nav-group-here" not in on_users[name] for name in GROUPS if name != "Admin")
    # A page outside the menu (the account page) marks none.
    on_account = _groups(logged_in.get("/account").text)
    assert all("nav-group-here" not in tag for tag in on_account.values())


def test_the_script_runs_right_after_the_menu(logged_in: TestClient) -> None:
    """Not deferred, and straight after the menu, so a shut group is never drawn open."""
    page = logged_in.get("/account").text
    assert re.search(r'</nav>\s*<script src="/static/nav\.js"></script>', page)
    script = logged_in.get("/static/nav.js")
    assert script.status_code == 200
    assert "javascript" in script.headers["content-type"]
    assert "nxray-nav-shut" in script.text
    assert 'classList.contains("nav-group-here")' in script.text


def test_shut_groups_hide_their_pages_except_in_the_narrow_menu(logged_in: TestClient) -> None:
    css = logged_in.get("/static/style.css").text
    assert ".nav-group-shut .nav-items { display: none; }" in css
    # The narrow menu hides the headings, so it must show every group.
    assert ".shell-narrow .nav-group-shut .nav-items { display: block; }" in css
    assert css.index(".nav-group-shut .nav-items { display: none; }") < css.index(
        ".shell-narrow .nav-group-shut .nav-items"
    )


def test_the_login_page_has_no_menu_script(client: TestClient) -> None:
    assert "/static/nav.js" not in client.get("/login").text
