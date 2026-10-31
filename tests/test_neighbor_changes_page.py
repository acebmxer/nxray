"""Neighbor changes in the pages: CDP and LLDP on a port's page, and the MAC
address table's aging time, static entries and clearing on the Neighbors page."""

from __future__ import annotations

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


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).replace("&#39;", "'")


def _db(settings: Settings, sql: str) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(sql)
    conn.commit()
    conn.close()


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


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


def _post(client: TestClient, path: str, confirm: bool = False, **fields: str):
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


# ---- the Switch page names the new changes -------------------------------------


def test_role_version_4_offers_neighbor_changes_without_a_wait(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 4")
    text = _text(logged_in.get("/switch").text)
    assert "Turn on neighbor, port-channel, VLAN interface and VRF changes" in text
    assert "turn CDP and LLDP on or off on the front ports" in text
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
    text = _text(response.text)
    assert (
        "Neighbor, port-channel, VLAN interface and VRF changes are on: nxray may now also turn "
        "CDP and LLDP on or off" in text
    )
    assert "there is no wait" in text
    assert "rule 40 permit command clear mac address-table dynamic *" in enabled.ssh_lines


def test_port_page_and_neighbors_page_say_neighbor_changes_are_off(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 4")
    port = _text(logged_in.get("/ports/detail?name=Ethernet1/5").text)
    assert "Neighbor changes are off." in port
    assert "Change CDP and LLDP" not in port
    page = _text(logged_in.get("/neighbors").text)
    assert "Neighbor changes are off." in page
    assert "Add static address" not in page
    response = _post(logged_in, "/neighbors/aging", aging="600")
    assert response.status_code == 400
    assert "Neighbor changes are off" in _text(response.text)
    response = _post(logged_in, "/ports/discovery", name="Ethernet1/5", lldp_shown="")
    assert response.status_code == 400
    assert _config_requests(enabled) == []


# ---- CDP and LLDP on a port -------------------------------------------------------


def test_port_page_shows_cdp_and_that_lldp_is_off(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    text = _text(logged_in.get("/ports/detail?name=Ethernet1/5").text)
    assert "CDP on" in text
    assert "LLDP off for the whole switch" in text
    assert "CDP: send and listen" in text
    assert "LLDP: send" not in text
    assert "LLDP can be set per port once it is on for the whole switch" in text
    assert ["show cdp interface Ethernet1/5"] in enabled.requests


def test_turning_cdp_off_on_a_port_asks_then_changes(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    # No cdp field: the box was unticked.
    asked = _post(logged_in, "/ports/discovery", name="Ethernet1/5")
    text = _text(asked.text)
    assert "Confirm the change" in text
    assert "Turn CDP off on Ethernet1/5." in text
    assert "no longer hears this switch" in text
    assert _config_requests(enabled) == []

    done = _post(logged_in, "/ports/discovery", confirm=True, name="Ethernet1/5")
    assert done.status_code == 200
    assert "Done: Turn CDP off on Ethernet1/5." in _text(done.text)
    assert _config_requests(enabled) == [["interface Ethernet1/5", "no cdp enable"]]
    assert enabled.port_state["Ethernet1/5"]["cdp"] is False
    assert "CDP off" in _text(done.text)
    conn = sqlite3.connect(settings.db_path)
    assert conn.execute("SELECT unsaved_changes FROM switch_connection").fetchone()[0] == 1
    conn.close()


def test_lldp_boxes_with_lldp_on(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.lldp = True
    text = _text(logged_in.get("/ports/detail?name=Ethernet1/5").text)
    assert "sending on, listening on" in text
    assert "LLDP: send" in text and "LLDP: listen" in text
    asked = _post(
        logged_in,
        "/ports/discovery",
        name="Ethernet1/5",
        cdp="on",
        lldp_transmit="on",
        lldp_shown="yes",
    )
    text = _text(asked.text)
    assert "Stop listening for LLDP on Ethernet1/5." in text
    assert "Turn CDP" not in text and "sending LLDP" not in text
    # The confirm page sends back exactly the ticked boxes.
    assert 'name="cdp" value="on"' in asked.text
    assert 'name="lldp_receive"' not in asked.text
    _post(
        logged_in,
        "/ports/discovery",
        confirm=True,
        name="Ethernet1/5",
        cdp="on",
        lldp_transmit="on",
        lldp_shown="yes",
    )
    assert _config_requests(enabled) == [["interface Ethernet1/5", "no lldp receive"]]


def test_nothing_to_change_on_a_port(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = _post(logged_in, "/ports/discovery", name="Ethernet1/5", cdp="on")
    assert "Nothing to change" in _text(response.text)
    assert _config_requests(enabled) == []


def test_a_refused_port_change_shows_the_switch_answer(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.reject.add("no cdp enable")
    response = _post(logged_in, "/ports/discovery", confirm=True, name="Ethernet1/5")
    assert response.status_code == 400
    assert "Rejected by the fake switch" in response.text


def test_viewer_sees_no_change_forms(logged_in: TestClient, enabled: FakeSwitch) -> None:
    viewer = _sign_in_as(logged_in, "vera", "viewer")
    port = _text(viewer.get("/ports/detail?name=Ethernet1/5").text)
    assert "CDP on" in port
    assert "Change CDP and LLDP" not in port
    assert "Clear the addresses learned on this port" not in port
    page = _text(viewer.get("/neighbors").text)
    assert "Static addresses" in page
    assert "Add static address" not in page and "Change aging time" not in page
    assert (
        viewer.post("/neighbors/aging", data={"csrf": _csrf(viewer), "aging": "600"}).status_code
        == 403
    )


def test_operator_can_make_neighbor_changes(logged_in: TestClient, enabled: FakeSwitch) -> None:
    operator = _sign_in_as(logged_in, "otto", "operator")
    page = _text(operator.get("/neighbors").text)
    assert "Add static address" in page
    _post(operator, "/neighbors/aging", confirm=True, aging="600")
    assert enabled.mac_aging == 600


# ---- the aging time ----------------------------------------------------------------


def test_aging_time_asks_then_changes(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/neighbors")
    assert 'id="aging" name="aging" type="text" inputmode="numeric" value="1800"' in page.text
    asked = _text(_post(logged_in, "/neighbors/aging", aging="600").text)
    assert "Forget a learned address after 600 seconds (10 minutes) without traffic" in asked
    assert _config_requests(enabled) == []
    done = _text(_post(logged_in, "/neighbors/aging", confirm=True, aging="600").text)
    assert "Done: Forget a learned address after 600 seconds" in done
    assert "An address is forgotten after 10 minutes without traffic." in done
    assert "NXray changed the switch since its configuration was last saved." in done
    assert _config_requests(enabled) == [["mac address-table aging-time 600"]]


def test_a_bad_aging_time_is_refused_and_kept_in_the_box(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    response = _post(logged_in, "/neighbors/aging", aging="1799")
    assert response.status_code == 400
    assert "Not changed: the switch takes the aging time in steps of 5 seconds" in _text(
        response.text
    )
    assert 'name="aging" type="text" inputmode="numeric" value="1799"' in response.text
    assert _config_requests(enabled) == []


# ---- static addresses ------------------------------------------------------------------


def test_static_address_add_and_remove(logged_in: TestClient, enabled: FakeSwitch) -> None:
    asked = _text(
        _post(
            logged_in, "/neighbors/static", mac="02-00-00-00-00-01", vlan="1", where="Ethernet1/54"
        ).text
    )
    assert "Always send traffic for 02:00:00:00:00:01 in VLAN 1 to Ethernet1/54." in asked
    done = _text(
        _post(
            logged_in,
            "/neighbors/static",
            confirm=True,
            mac="0200.0000.0001",
            vlan="1",
            where="Ethernet1/54",
        ).text
    )
    assert "Done: Always send traffic for 02:00:00:00:00:01" in done
    assert "02:00:00:00:00:01" in done and "Remove" in done
    assert _config_requests(enabled) == [
        ["mac address-table static 0200.0000.0001 vlan 1 interface Ethernet1/54"]
    ]

    enabled.requests.clear()
    asked = _text(
        _post(logged_in, "/neighbors/static/remove", mac="02:00:00:00:00:01", vlan="1").text
    )
    assert "Remove the static entry for 02:00:00:00:00:01 in VLAN 1 (on Ethernet1/54)." in asked
    done = _text(
        _post(
            logged_in, "/neighbors/static/remove", confirm=True, mac="0200.0000.0001", vlan="1"
        ).text
    )
    assert "Done: the static entry for 02:00:00:00:00:01 in VLAN 1 is removed." in done
    assert _config_requests(enabled) == [
        ["no mac address-table static 0200.0000.0001 vlan 1 interface Ethernet1/54"]
    ]
    assert "There are no static addresses." in done


def test_static_address_dropped(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _post(
        logged_in,
        "/neighbors/static",
        confirm=True,
        mac="02:00:00:00:00:02",
        vlan="1",
        where="drop",
    )
    assert _config_requests(enabled) == [["mac address-table static 0200.0000.0002 vlan 1 drop"]]
    page = _text(logged_in.get("/neighbors").text)
    assert "02:00:00:00:00:02" in page and "dropped" in page


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"vlan": "77"}, "VLAN 77 does not exist on the switch"),
        ({"where": "mgmt0"}, "not one of the switch's front ports"),
        ({"mac": "ff:ff:ff:ff:ff:ff"}, "multicast"),
    ],
)
def test_static_address_refusals(
    logged_in: TestClient, enabled: FakeSwitch, fields: dict[str, str], message: str
) -> None:
    form = {"mac": "02:00:00:00:00:01", "vlan": "1", "where": "Ethernet1/54", **fields}
    response = _post(logged_in, "/neighbors/static", confirm=True, **form)
    assert response.status_code == 400
    assert message in _text(response.text)
    assert _config_requests(enabled) == []


def test_removing_a_static_entry_that_is_not_there(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    response = _post(
        logged_in, "/neighbors/static/remove", confirm=True, mac="02:00:00:00:00:09", vlan="1"
    )
    assert response.status_code == 400
    assert "no static entry" in _text(response.text)
    assert _config_requests(enabled) == []


# ---- clearing learned addresses ---------------------------------------------------------


def test_clear_everything_asks_then_clears(logged_in: TestClient, enabled: FakeSwitch) -> None:
    asked = _text(_post(logged_in, "/neighbors/clear", scope="all").text)
    assert "Forget every learned address" in asked
    assert "learned again as soon as they send something" in asked
    assert "nothing to save afterwards" in asked
    done = _text(_post(logged_in, "/neighbors/clear", confirm=True, scope="all").text)
    assert "Done: The switch forgot every learned address" in done
    assert "there is nothing to save." in done
    assert _config_requests(enabled) == [["clear mac address-table dynamic"]]
    assert all(row["disp_type"] != "dynamic" for row in enabled.macs())
    assert "0c:ea:14:00:00:01" not in done
    # Clearing changes no configuration.
    assert "NXray changed the switch since" not in done


@pytest.mark.parametrize(
    ("fields", "command"),
    [
        ({"scope": "vlan", "vlan": "1"}, "clear mac address-table dynamic vlan 1"),
        (
            {"scope": "address", "mac": "0cea.1400.0001", "vlan": "1"},
            "clear mac address-table dynamic address 0cea.1400.0001 vlan 1",
        ),
        (
            {"scope": "port", "port": "Ethernet1/47"},
            "clear mac address-table dynamic interface Ethernet1/47",
        ),
    ],
)
def test_clear_one_part(
    logged_in: TestClient, enabled: FakeSwitch, fields: dict[str, str], command: str
) -> None:
    _post(logged_in, "/neighbors/clear", confirm=True, **fields)
    assert _config_requests(enabled) == [[command]]


def test_clear_from_a_port_page_answers_there(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/ports/detail?name=Ethernet1/47").text
    assert "Clear the addresses learned on this port" in page
    asked = _post(logged_in, "/neighbors/clear", scope="port", port="Ethernet1/47", back="port")
    assert 'href="/ports/detail?name=Ethernet1%2F47"' in asked.text
    assert 'name="back" value="port"' in asked.text
    done = _post(
        logged_in, "/neighbors/clear", confirm=True, scope="port", port="Ethernet1/47", back="port"
    )
    text = _text(done.text)
    assert "Done: The switch forgot the addresses learned on Ethernet1/47" in text
    assert "The switch has learned no MAC addresses on this port." in text
    assert '<h1 class="page-title">Ethernet1/47</h1>' in done.text


@pytest.mark.parametrize("back", ["https://example.com/", "PORT", "neighbors"])
def test_clear_back_field_only_knows_the_port_page(
    logged_in: TestClient, enabled: FakeSwitch, back: str
) -> None:
    done = _post(
        logged_in, "/neighbors/clear", confirm=True, scope="port", port="Ethernet1/47", back=back
    )
    assert '<h1 class="page-title">Neighbors</h1>' in done.text


def test_clear_refusals(logged_in: TestClient, enabled: FakeSwitch) -> None:
    for fields in (
        {"scope": "everything"},
        {"scope": "port", "port": "mgmt0"},
        {"scope": "vlan", "vlan": "5000"},
        {"scope": "address", "mac": "nonsense"},
    ):
        response = _post(logged_in, "/neighbors/clear", confirm=True, **fields)
        assert response.status_code == 400, fields
        assert "Not cleared" in _text(response.text)
    assert _config_requests(enabled) == []


# ---- Save config from the Neighbors page ---------------------------------------------------


def test_save_config_answers_on_the_neighbors_page(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    _post(logged_in, "/neighbors/aging", confirm=True, aging="600")
    response = _post(logged_in, "/switch/save", back="neighbors")
    text = _text(response.text)
    assert "Saved: the switch keeps its current configuration on restart." in text
    assert '<h1 class="page-title">Neighbors</h1>' in response.text
    assert enabled.saved
