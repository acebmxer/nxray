"""The Spanning tree page, end to end against the fake switch: reading it, the
role version it needs, and a change from asking to sent."""

from __future__ import annotations

import html
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _db(settings: Settings, sql: str) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(sql)
    conn.commit()
    conn.close()


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    """A switch that has been set up (read-only account nxray), with VLAN 10."""
    fake = FakeSwitch()
    fake.vlans[10] = "Servers"
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


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    """All changes on (role version 11) and the wait over."""
    response = logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    switch.requests.clear()
    switch.saved = False
    return switch


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/spanning-tree/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/spanning-tree", follow_redirects=False).status_code == 303


def test_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/spanning-tree").text)


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/spanning-tree"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/spanning-tree")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "Spanning tree" in text and "Mode rapid-pvst" in text
    assert "Trees" in text and "VLAN 1" in text and "VLAN 10" in text
    assert "port-channel43" in text
    # The role at setup (read-only) may not read the configuration text.
    assert "does not let it read the spanning tree settings" in text
    assert switch.requests[0] == [
        "show spanning-tree summary",
        "show spanning-tree detail",
        "show spanning-tree mst configuration",
        "show vlan brief",
        "show interface brief",
    ]
    assert switch.requests[1] == ["show running-config spanning-tree"]
    assert "/spanning-tree/change" not in page.text  # changes are off


def test_changes_off_before_role_version_11(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 10")
    page = logged_in.get("/spanning-tree").text
    assert "Spanning tree changes are off" in _text(page)
    assert "Turn on spanning tree, switch admin and security and config changes" in _text(
        logged_in.get("/switch").text
    )
    refused = _change(logged_in, scope="vlan", setting="priority", action="set",
                      id_vlan="10", v_priority="4096")  # fmt: skip
    assert refused.status_code == 400
    assert "Spanning tree changes are off" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_enabled_page_offers_every_setting(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/spanning-tree")
    text = _text(page.text)
    assert "does not let it read" not in text
    for setting in ("mode", "priority", "port_type", "bpduguard", "guard", "name", "instance"):
        assert f'name="setting" value="{setting}"' in page.text
    # The port form offers the switched ports, never mgmt0.
    assert '<option value="Ethernet1/54"' in page.text
    assert '<option value="mgmt0"' not in page.text


def test_vlan_priority_asks_first_then_sends(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {"scope": "vlan", "setting": "priority", "action": "set", "id_vlan": "10",
              "v_priority": "4096"}  # fmt: skip
    asked = _change(logged_in, confirm=False, **fields)
    assert asked.status_code == 200
    text = _text(asked.text)
    assert "Spanning tree, VLAN (VLAN 10): set Bridge priority (4096)." in text
    assert "spanning-tree vlan 10 priority 4096" in text
    assert "traffic in it can stop for a moment" in text
    assert _config_requests(enabled) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert "Done: Spanning tree, VLAN (VLAN 10): set Bridge priority" in _text(done.text)
    assert _config_requests(enabled) == [["spanning-tree vlan 10 priority 4096"]]
    assert "spanning-tree vlan 10 priority 4096" in enabled.stp_lines
    # The page reads it back from the configuration text.
    page = _text(logged_in.get("/spanning-tree").text)
    assert "NXray changed the switch since its configuration was last saved" in page


def test_any_port_can_be_picked_before_the_listed_ones(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    page = logged_in.get("/spanning-tree").text
    section = page[page.index('id="port"') :]
    picker = section.index("Change any port, also one not listed below: pick it, then the setting")
    assert picker < section.index("<h3>port-channel43</h3>")
    assert section.index('name="setting" value="port_type"') > picker


def test_every_port_has_its_forms_cable_or_not(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/spanning-tree").text
    for name in ("Ethernet1/1", "Ethernet1/49", "Ethernet1/54"):
        assert f"<h3>{name}</h3>" in page
        assert f'name="id_port" value="{name}"' in page


def test_port_setting_shows_on_a_down_port(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(logged_in, scope="port", setting="port_type", action="set",
                   id_port="Ethernet1/54", v_type="edge")  # fmt: skip
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["interface Ethernet1/54", "spanning-tree port type edge"]]
    page = logged_in.get("/spanning-tree").text
    start = page.index("<h3>Ethernet1/54</h3>")
    section = page[start : page.index("<h3>", start + 1)]
    assert '<option value="edge" selected>' in section


def test_mst_region_line(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(logged_in, scope="mst", setting="name", action="set", v_name="campus")
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["spanning-tree mst configuration", "name campus"]]
    assert "spanning-tree mst configuration ; name campus" in enabled.stp_lines


def test_remove_a_switch_wide_setting(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(logged_in, scope="switch", setting="bridge_assurance", action="remove")
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["no spanning-tree bridge assurance"]]


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"scope": "vlan", "setting": "priority", "id_vlan": "20", "v_priority": "4096"},
         "the switch has no VLAN 20"),
        ({"scope": "port", "setting": "cost", "id_port": "mgmt0", "v_cost": "5"}, "front port"),
        ({"scope": "port", "setting": "cost", "id_port": "Ethernet1/99", "v_cost": "5"},
         "not a front port or port-channel carrying VLANs"),
        ({"scope": "vlan", "setting": "priority", "id_vlan": "10", "v_priority": "100"},
         "Priority is one of"),
    ],
)  # fmt: skip
def test_refused_before_anything_is_sent(
    logged_in: TestClient, enabled: FakeSwitch, fields: dict, message: str
) -> None:
    response = _change(logged_in, action="set", **fields)
    assert response.status_code == 400
    assert message in _text(response.text)
    assert _config_requests(enabled) == []


def test_viewer_sees_no_forms_and_cannot_post(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE users SET role = 'viewer'")
    page = logged_in.get("/spanning-tree").text
    assert "/spanning-tree/change" not in page
    assert "can look at spanning tree but not change it" in _text(page)
    response = _change(logged_in, scope="switch", setting="bridge_assurance", action="remove")
    assert response.status_code == 403
    assert _config_requests(enabled) == []


def test_change_needs_csrf(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = logged_in.post(
        "/spanning-tree/change",
        data={"csrf": "0" * 32, "scope": "switch", "setting": "bridge_assurance",
              "action": "remove", "confirm": "yes"},
    )  # fmt: skip
    assert response.status_code == 403
    assert _config_requests(enabled) == []


def test_switch_error_is_shown(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.reject.add("spanning-tree mode")
    response = _change(logged_in, scope="switch", setting="mode", action="set", v_mode="mst")
    assert response.status_code == 400
    assert "Rejected by the fake switch" in _text(response.text)


def test_save_config_returns_to_the_page(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _change(logged_in, scope="switch", setting="bridge_assurance", action="remove")
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "spanning-tree"})
    assert saved.status_code == 200
    assert "Trees" in _text(saved.text)
    assert enabled.saved
