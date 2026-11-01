"""The port side panel on the Ports page: every change a port's own page offers,
answered back on the Ports page with the same panel open (#14)."""

from __future__ import annotations

import html
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

PANEL = "/ports?show=up&color=speed&port=Ethernet1/3"
BACK = {"back": "ports", "show": "up", "color": "speed"}


def _csrf(client: TestClient, path: str = "/switch") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": _csrf(logged_in),
            "host": "192.0.2.10",
            "port": "443",
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "account_name": "nxray",
            "confirm_save": "yes",
        },
    )
    return fake


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    """Every kind of change on, the wait over."""
    response = logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE switch_connection SET paused_until = ?", (time.time() - 1,))
    conn.commit()
    conn.close()
    switch.requests.clear()
    switch.saved = False
    return switch


def _post(client: TestClient, path: str, confirm: str = "", **fields: str):
    data = {"csrf": _csrf(client, PANEL), **BACK, **fields}
    if confirm:
        data["confirm"] = confirm
    return client.post(path, data=data)


def _panel_of(page: str) -> str:
    match = re.search(r'<aside class="drawer" aria-label="([^"]+)">', page)
    return match.group(1) if match else ""


def test_panel_offers_every_change(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get(PANEL).text
    assert _panel_of(page) == "Ethernet1/3"
    panel = page[page.index('<aside class="drawer"') :]
    for action in (
        "/ports/change",
        "/ports/label",
        "/ports/vlans",
        "/ports/settings",
        "/ports/discovery",
    ):
        assert f'action="{action}"' in panel, action
    for words in ("Change description", "Save label", "Change VLANs", "Change settings"):
        assert words in panel, words
    assert "Change CDP and LLDP" in panel and "Turn off" in panel
    # Every form says it came from the Ports page, with its filter and colours.
    forms = panel.count('<form method="post"')
    assert panel.count('name="back" value="ports"') == forms
    assert panel.count('name="show" value="up"') == forms
    assert panel.count('name="color" value="speed"') == forms
    # The panel's ids never clash with the bulk form's.
    assert 'id="drawer_description"' in panel and 'id="drawer_speed"' in panel
    assert "All of this port →" in panel


def test_panel_offers_the_split_on_a_100g_port(logged_in: TestClient, enabled: FakeSwitch) -> None:
    panel = logged_in.get("/ports?port=Ethernet1/50").text
    assert 'action="/ports/breakout"' in panel and "Split this port" in panel


def test_viewer_panel_has_no_change_forms(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE users SET role = 'viewer'")
    conn.commit()
    conn.close()
    page = logged_in.get(PANEL).text
    assert _panel_of(page) == "Ethernet1/3"
    assert 'method="post" action="/ports/' not in page
    assert "can look at labels but not change them" in _text(page)


def test_panel_says_which_changes_are_off(logged_in: TestClient, switch: FakeSwitch) -> None:
    text = _text(logged_in.get(PANEL).text)
    assert "Port changes are off." in text
    assert "Change VLANs" not in text and "Change settings" not in text


def test_description_change_comes_back_to_the_panel(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    asked = _post(
        logged_in, "/ports/change", name="Ethernet1/3", action="description", description="lab"
    )
    assert "Confirm the change" in asked.text
    # Cancel and the breadcrumb go back to the panel; the origin rides along.
    assert asked.text.count('href="/ports?show=up&amp;color=speed&amp;port=Ethernet1/3"') == 2
    assert 'name="back" value="ports"' in asked.text
    assert _config_requests(enabled) == []

    done = _post(
        logged_in,
        "/ports/change",
        confirm="yes",
        name="Ethernet1/3",
        action="description",
        description="lab",
    )
    assert _config_requests(enabled) == [["interface Ethernet1/3", "description lab"]]
    assert _panel_of(done.text) == "Ethernet1/3"
    assert '<h1 class="page-title">Ports</h1>' in done.text
    assert 'class="filter filter-on" href="/ports?show=up&amp;color=speed"' in done.text
    panel = _text(done.text[done.text.index('<aside class="drawer"') :])
    assert 'Done: Ethernet1/3 now has the description "lab".' in panel
    # The panel offers to save, keeping the panel open.
    assert re.search(r'name="port" value="Ethernet1/3">\s*<button[^>]*>Save config', done.text)


def test_a_refusal_keeps_the_panel_and_what_was_typed(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    response = _post(
        logged_in,
        "/ports/settings",
        confirm="yes",
        name="Ethernet1/3",
        speed="auto",
        mtu="9000",
    )
    assert response.status_code == 400
    assert _panel_of(response.text) == "Ethernet1/3"
    assert "Not changed: a switched port&#39;s MTU is 1500" in response.text
    assert (
        'id="drawer_mtu" name="mtu" type="text" inputmode="numeric" value="9000"' in response.text
    )
    assert _config_requests(enabled) == []


def test_vlan_change_from_the_panel(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.vlans[20] = "lab"
    form = {"mode": "access", "access_vlan": "20", "native_vlan": "1", "allowed": "1-4094"}
    asked = _post(logged_in, "/ports/vlans", name="Ethernet1/3", **form)
    assert "Access VLAN: 1 → 20." in _text(asked.text)
    assert 'href="/ports?show=up&amp;color=speed&amp;port=Ethernet1/3"' in asked.text
    assert 'name="show" value="up"' in asked.text
    done = _post(logged_in, "/ports/vlans", confirm="yes", name="Ethernet1/3", **form)
    assert _config_requests(enabled) == [["interface Ethernet1/3", "switchport access vlan 20"]]
    assert _panel_of(done.text) == "Ethernet1/3"
    assert "Done: Access VLAN: 1 → 20." in _text(done.text)


def test_label_from_the_panel(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _post(logged_in, "/ports/label", name="Ethernet1/3", label="printer")
    assert _panel_of(done.text) == "Ethernet1/3"
    assert 'Done: Ethernet1/3 now has the label "printer".' in _text(done.text)
    assert 'id="drawer_label" name="label" type="text" value="printer"' in done.text


def test_cdp_change_from_the_panel(logged_in: TestClient, enabled: FakeSwitch) -> None:
    asked = _post(logged_in, "/ports/discovery", name="Ethernet1/3")
    assert 'href="/ports?show=up&amp;color=speed&amp;port=Ethernet1/3"' in asked.text
    done = _post(logged_in, "/ports/discovery", confirm="yes", name="Ethernet1/3")
    assert _config_requests(enabled) == [["interface Ethernet1/3", "no cdp enable"]]
    assert _panel_of(done.text) == "Ethernet1/3"


def test_split_from_the_panel_opens_the_first_new_port(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    fields = {"name": "Ethernet1/50", "action": "split", "mapping": "25g-4x"}
    done = _post(logged_in, "/ports/breakout", confirm="yes", **fields)
    assert _config_requests(enabled) == [["interface breakout module 1 port 50 map 25g-4x"]]
    assert _panel_of(done.text) == "Ethernet1/50/1"


def test_clearing_addresses_from_the_panel(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/ports?port=Ethernet1/47").text
    assert 'action="/neighbors/clear"' in page[page.index('<aside class="drawer"') :]
    asked = _post(logged_in, "/neighbors/clear", scope="port", port="Ethernet1/47")
    assert 'href="/ports?show=up&amp;color=speed&amp;port=Ethernet1/47"' in asked.text
    assert 'name="back" value="ports"' in asked.text
    done = _post(logged_in, "/neighbors/clear", confirm="yes", scope="port", port="Ethernet1/47")
    assert _panel_of(done.text) == "Ethernet1/47"
    assert "Done: The switch forgot the addresses learned on Ethernet1/47" in _text(done.text)


def test_save_from_the_panel_keeps_it_open(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = logged_in.post(
        "/switch/save",
        data={"csrf": _csrf(logged_in, PANEL), "port": "Ethernet1/3", **BACK},
    )
    assert enabled.saved
    assert _panel_of(response.text) == "Ethernet1/3"
    assert 'class="filter filter-on" href="/ports?show=up&amp;color=speed"' in response.text


def test_odd_origin_fields_fall_back_to_the_defaults(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    done = logged_in.post(
        "/ports/label",
        data={
            "csrf": _csrf(logged_in, PANEL),
            "name": "Ethernet1/3",
            "label": "x",
            "back": "ports",
            "show": "https://example.com/",
            "color": "<script>",
        },
    )
    assert _panel_of(done.text) == "Ethernet1/3"
    assert 'class="filter filter-on" href="/ports?show=all&amp;color=state"' in done.text


def test_without_the_origin_the_port_page_answers(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    done = logged_in.post(
        "/ports/label",
        data={"csrf": _csrf(logged_in, PANEL), "name": "Ethernet1/3", "label": "x"},
    )
    assert '<h1 class="page-title">Ethernet1/3</h1>' in done.text
    assert 'class="drawer"' not in done.text
