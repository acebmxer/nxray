"""The Port-channels page: reading port-channels and LACP, and their changes, end to
end against the fake switch."""

from __future__ import annotations

import html
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.port_changes import CHANNEL_PERMIT
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


def _enable_changes(client: TestClient):
    return client.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(client, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    """A switch that has been set up (read-only account nxray)."""
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


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    """All changes on, and the wait already over."""
    assert _enable_changes(logged_in).status_code == 200
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    switch.requests.clear()
    switch.saved = False
    return switch


def _post(client: TestClient, path: str, confirm: bool = False, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post(path, data=data)


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


# ---- looking -------------------------------------------------------------------------------


def test_page_shows_the_recorded_port_channel_with_its_partner(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    page = logged_in.get("/port-channels")
    assert page.status_code == 200
    text = _text(page.text)
    assert 'id="port-channel43"' in page.text
    assert "port-channel43 storage-server" in text
    assert "LACP, active" in text and "up in the port-channel" in text
    assert "b8:59:9f:00:00:0e (Mellanox Technologies, Inc.), active, fast rate" in text
    assert "The switch's LACP priority 32768 (the default)" in text
    assert "Make port-channel" in text and "Take out" in text
    assert '<a class="navlink" href="/port-channels">Port-channels</a>' in page.text


def test_viewer_looks_but_gets_no_forms(logged_in: TestClient, enabled: FakeSwitch) -> None:
    viewer = _sign_in_as(logged_in, "watcher", "viewer")
    text = _text(viewer.get("/port-channels").text)
    assert "port-channel43" in text and "Mellanox" in text
    assert "Make port-channel" not in text and "Take out" not in text
    assert "Change LACP priority" not in text


def test_ports_page_and_port_page_link_to_the_port_channel(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    ports = logged_in.get("/ports").text
    assert '<a class="reason" href="/port-channels#port-channel43">in port-channel43</a>' in ports
    port = logged_in.get("/ports/detail", params={"name": "Ethernet1/43"}).text
    assert '<a href="/port-channels#port-channel43">port-channel43</a>' in port


def test_lacp_off_allows_static_only(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.feature_state["lacp"] = False
    enabled.channels.clear()
    text = _text(logged_in.get("/port-channels").text)
    assert "LACP is off on the switch, so only static port-channels can be made" in text
    assert "The switch has no port-channels." in text
    response = _post(
        logged_in, "/port-channels/create", number="5", ports="Ethernet1/5", mode="active"
    )
    assert response.status_code == 400
    assert "Not made: LACP is off on the switch" in _text(response.text)
    assert _config_requests(enabled) == []


# ---- turning the changes on ---------------------------------------------------------------


def test_role_version_5_offers_port_channel_changes_without_a_wait(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 5")
    page = _text(logged_in.get("/port-channels").text)
    assert "Port-channel changes are off." in page and "Make port-channel" not in page
    switch_page = _text(logged_in.get("/switch").text)
    assert (
        "Turn on port-channel, VLAN interface, VRF, static route and routing protocol changes"
        in switch_page
    )
    assert "make, change and delete port-channels" in switch_page
    enabled.ssh_lines.clear()
    text = _text(_enable_changes(logged_in).text)
    assert (
        "Port-channel, VLAN interface, VRF, static route and routing protocol changes are on: "
        "nxray may now also "
        "make, "
        "change and delete" in text
    )
    assert "there is no wait" in text
    assert "rule 47 permit command conf t ; lacp system-priority *" in enabled.ssh_lines
    assert CHANNEL_PERMIT in enabled.ssh_lines
    assert "Make port-channel" in logged_in.get("/port-channels").text


def test_changes_refused_while_off(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 5")
    response = _post(logged_in, "/port-channels/delete", confirm=True, number="43")
    assert response.status_code == 400
    assert "Port-channel changes are off" in _text(response.text)
    assert _config_requests(enabled) == []


# ---- making, filling and deleting --------------------------------------------------------


def test_create_asks_first_then_makes_it(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    fields = {
        "number": "54",
        "ports": ["Ethernet1/53", "Ethernet1/54"],
        "mode": "active",
        "fast_rate": "yes",
        "description": "lab",
    }
    confirm = _post(logged_in, "/port-channels/create", **fields)
    text = _text(confirm.text)
    assert "Make port-channel54 (LACP, active) from Ethernet1/53, Ethernet1/54." in text
    assert "must have the same settings" in text
    assert confirm.text.count('name="ports"') == 2
    assert _config_requests(enabled) == []

    done = _post(logged_in, "/port-channels/create", confirm=True, **fields)
    assert done.status_code == 200
    assert _config_requests(enabled) == [
        [
            "interface Ethernet1/53",
            "lacp rate fast",
            "channel-group 54 mode active",
            "interface Ethernet1/54",
            "lacp rate fast",
            "channel-group 54 mode active",
            "interface port-channel54",
            "description lab",
        ]
    ]
    text = _text(done.text)
    assert "Done: Make port-channel54" in text and "Not saved yet" in text
    assert "port-channel54 lab" in text
    row = sqlite3.connect(settings.db_path).execute("SELECT unsaved_changes FROM switch_connection")
    assert row.fetchone()[0] == 1

    saved = _post(logged_in, "/switch/save", back="port-channels")
    assert "Saved:" in _text(saved.text) and 'id="port-channel54"' in saved.text


def test_create_refuses_a_port_already_in_a_channel(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    response = _post(
        logged_in,
        "/port-channels/create",
        number="5",
        ports=["Ethernet1/5", "Ethernet1/43"],
        mode="active",
        description="kept",
    )
    assert response.status_code == 400
    text = _text(response.text)
    assert "Not made: Ethernet1/43 is already in port-channel43" in text
    assert 'value="kept"' in response.text  # the form keeps what was typed
    assert _config_requests(enabled) == []


def test_add_remove_and_delete(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _post(
        logged_in, "/port-channels/add", confirm=True, number="43", port="Ethernet1/45",
        mode="active",
    )  # fmt: skip
    assert done.status_code == 200
    assert _config_requests(enabled)[-1] == [
        "interface Ethernet1/45",
        "channel-group 43 mode active",
    ]

    refused = _post(logged_in, "/port-channels/delete", number="43")
    assert refused.status_code == 400
    assert (
        "Not deleted: port-channel43 still has Ethernet1/43, Ethernet1/44, Ethernet1/45; "
        "take them out first" in _text(refused.text)
    )

    for port in ("Ethernet1/43", "Ethernet1/44", "Ethernet1/45"):
        response = _post(logged_in, "/port-channels/remove", confirm=True, port=port)
        assert response.status_code == 200, _text(response.text)
    assert enabled.channels[43] == {}
    confirm = _post(logged_in, "/port-channels/delete", number="43")
    assert "Delete port-channel43." in _text(confirm.text)
    done = _post(logged_in, "/port-channels/delete", confirm=True, number="43")
    assert _config_requests(enabled)[-1] == ["no interface port-channel43"]
    assert 43 not in enabled.channels
    assert "The switch has no port-channels." in _text(done.text)


def test_remove_warns_that_the_port_carries_traffic(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    text = _text(_post(logged_in, "/port-channels/remove", port="Ethernet1/43").text)
    assert "Take Ethernet1/43 out of port-channel43." in text and "carries traffic" in text


def test_channel_settings(logged_in: TestClient, enabled: FakeSwitch) -> None:
    confirm = _post(
        logged_in, "/port-channels/settings", number="43", description="nas", min_links="2"
    )
    text = _text(confirm.text)
    assert 'from "storage-server" to "nas"' in text and "at least 2 of its ports" in text
    _post(
        logged_in, "/port-channels/settings", confirm=True, number="43", description="nas",
        min_links="2",
    )  # fmt: skip
    assert _config_requests(enabled)[-1] == [
        "interface port-channel43",
        "description nas",
        "lacp min-links 2",
    ]
    assert "port-channel43 nas" in _text(logged_in.get("/port-channels").text)


def test_member_lacp_rate_needs_the_port_off(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _post(logged_in, "/port-channels/port-lacp", port="Ethernet1/43", rate="fast")
    assert refused.status_code == 400
    assert "turn Ethernet1/43 off on its page" in _text(refused.text)
    enabled.port_state["Ethernet1/43"] = {"admin_up": False}
    _post(
        logged_in, "/port-channels/port-lacp", confirm=True, port="Ethernet1/43", rate="fast",
        priority="100",
    )  # fmt: skip
    assert _config_requests(enabled)[-1] == [
        "interface Ethernet1/43",
        "lacp rate fast",
        "lacp port-priority 100",
    ]
    page = logged_in.get("/port-channels").text
    assert "<td>fast</td>" in page and '<td class="num">100</td>' in page


def test_system_priority(logged_in: TestClient, enabled: FakeSwitch) -> None:
    confirm = _text(_post(logged_in, "/port-channels/system-priority", priority="4096").text)
    assert "Set the switch's LACP priority to 4096 (now 32768" in confirm
    assert "Every LACP port-channel (port-channel43)" in confirm
    done = _post(logged_in, "/port-channels/system-priority", confirm=True, priority="4096")
    assert _config_requests(enabled)[-1] == ["lacp system-priority 4096"]
    assert "The switch's LACP priority 4096" in _text(done.text)


def test_switch_refusal_is_shown(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.reject.add("channel-group")
    response = _post(
        logged_in, "/port-channels/create", confirm=True, number="9", ports="Ethernet1/9",
        mode="active",
    )  # fmt: skip
    assert response.status_code == 400
    assert "Rejected by the fake switch" in _text(response.text)
