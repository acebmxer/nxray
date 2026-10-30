"""Port settings and breakout through the pages, against the fake switch."""

from __future__ import annotations

import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.port_changes import ROLE_NAME, ROLE_VERSION, SETTINGS_RULES
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


def _csrf(client: TestClient, path: str = "/switch") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def _db(settings: Settings, sql: str, *args) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(sql, args)
    conn.commit()
    conn.close()


def _enable(client: TestClient):
    return client.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(client),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )


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
    """Port, VLAN and port settings changes on, the wait over."""
    assert _enable(logged_in).status_code == 200
    _db(settings, "UPDATE switch_connection SET paused_until = ?", time.time() - 1)
    switch.requests.clear()
    switch.saved = False
    return switch


def _page(client: TestClient, name: str = "Ethernet1/3") -> str:
    return client.get("/ports/detail", params={"name": name}).text


def _settings_post(client: TestClient, name: str = "Ethernet1/3", confirm: str = "", **form):
    data = {"csrf": _csrf(client, f"/ports/detail?name={name}"), "name": name, "confirm": confirm}
    data.update(form)
    return client.post("/ports/settings", data=data)


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


# ---- the role ---------------------------------------------------------------


def test_turning_on_types_the_settings_rules(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    text = _text(_enable(logged_in).text)
    assert "Port, VLAN, port settings, feature, neighbor and port-channel changes are on" in text
    assert "split or join the 100G ports" in text
    for rule in SETTINGS_RULES:
        assert rule in switch.ssh_lines
    role = switch.roles[ROLE_NAME]
    assert "conf t ; interface * ; mtu *" in role.entities
    assert "conf t ; interface breakout module * port * map *" in role.entities


def test_old_role_offers_port_settings_with_one_wait(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 2")
    page = _text(logged_in.get("/switch").text)
    assert (
        "Turn on port settings, feature, neighbor and port-channel changes" in page
        and "alone for about 20 minutes" in page
    )
    port = _text(_page(logged_in))
    assert "Port settings changes are off" in port and "Change settings" not in port

    text = _text(_enable(logged_in).text)
    assert (
        "Port settings, feature, neighbor and port-channel changes are on: nxray may now also "
        "set the speed, MTU" in text
    )
    assert "NXray now waits about 20 minutes" in text
    conn = sqlite3.connect(settings.db_path)
    (version,) = conn.execute("SELECT role_version FROM switch_connection").fetchone()
    conn.close()
    assert version == ROLE_VERSION
    assert "Update the port list" in logged_in.get("/switch").text


def test_update_the_port_list_names_the_split_ports(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.breakouts["Ethernet1/50"] = "25g-4x"
    text = _text(_enable(logged_in).text)
    assert "The port list is updated" in text and "57 front ports" in text
    assert "ethernet1/50/2" in enabled.roles[ROLE_NAME].interfaces


# ---- reading ----------------------------------------------------------------


def test_port_page_shows_the_settings(logged_in: TestClient, enabled: FakeSwitch) -> None:
    text = _text(_page(logged_in))
    assert "Port settings" in text
    assert "switched (layer 2)" in text
    assert "Duplex full" in text
    assert "receive off, send off" in text
    assert "broadcast none, multicast none, unicast none; action none" in text
    assert "Change settings" in text
    # The QSFP port offers a split; an SFP port does not.
    assert "Split port" not in text
    assert "Split this port" in _text(_page(logged_in, "Ethernet1/50"))


def test_settings_form_hidden_from_viewers_and_when_off(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    text = _text(_page(logged_in))
    assert "Port settings" in text and "Change settings" not in text


# ---- changing ---------------------------------------------------------------


def test_settings_change_asks_then_sends_only_what_changed(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    form = {"speed": "10000", "mtu": "9216", "fec": "auto", "storm_broadcast": "10"}
    asked = _text(_settings_post(logged_in, **form).text)
    assert "Confirm the change" in asked
    assert "Speed: Auto → 10 Gb/s." in asked and "MTU: 1500 → 9216." in asked
    assert "Storm control, broadcast: no limit → 10.00%." in asked
    assert _config_requests(enabled) == []

    done = _text(_settings_post(logged_in, confirm="yes", **form).text)
    assert "Done: Speed: Auto → 10 Gb/s." in done
    assert _config_requests(enabled) == [
        [
            "interface Ethernet1/3",
            "speed 10000",
            "mtu 9216",
            "storm-control broadcast level 10.00",
        ]
    ]
    page = _text(_page(logged_in))
    assert "9216 (jumbo frames)" in page and "broadcast 10.00%" in page


def test_unchanged_form_sends_nothing(logged_in: TestClient, enabled: FakeSwitch) -> None:
    text = _text(_settings_post(logged_in, speed="auto", mtu="1500", confirm="yes").text)
    assert "Nothing to change" in text
    assert _config_requests(enabled) == []


def test_bad_value_keeps_the_form(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = _settings_post(logged_in, mtu="9000", confirm="yes")
    assert response.status_code == 400
    assert "Not changed: a switched port&#39;s MTU is 1500" in response.text
    assert 'value="9000"' in response.text
    assert _config_requests(enabled) == []


def test_routed_with_address_and_back(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _settings_post(logged_in, layer="routed", ip_address="192.0.2.1/24", confirm="yes")
    assert _config_requests(enabled)[-1] == [
        "interface Ethernet1/3",
        "no switchport",
        "ip address 192.0.2.1/24",
    ]
    page = _text(_page(logged_in))
    assert "routed (layer 3)" in page and "IPv4 address 192.0.2.1/24" in page
    assert "This is a routed port, so it has no VLANs" in page

    _settings_post(logged_in, layer="switched", confirm="yes")
    assert _config_requests(enabled)[-1] == [
        "interface Ethernet1/3",
        "no ip address 192.0.2.1/24",
        "switchport",
    ]
    assert "switched (layer 2)" in _text(_page(logged_in))


def test_flow_control_and_storm_action(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _settings_post(logged_in, flow_receive="on", flow_send="on", storm_action="trap", confirm="yes")
    assert _config_requests(enabled)[-1] == [
        "interface Ethernet1/3",
        "flowcontrol receive on",
        "flowcontrol send on",
        "storm-control action trap",
    ]
    assert "action trap" in _text(_page(logged_in))
    _settings_post(logged_in, storm_action="none", confirm="yes")
    assert _config_requests(enabled)[-1] == [
        "interface Ethernet1/3",
        "no storm-control action trap",
    ]


def test_switch_refusal_is_shown(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.reject.add("fec ")
    response = _settings_post(logged_in, fec="rs-fec", confirm="yes")
    assert response.status_code == 400
    assert "Rejected by the fake switch: fec rs-fec" in response.text


def test_settings_refused_while_off(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 2")
    response = _settings_post(logged_in, speed="10000", confirm="yes")
    assert response.status_code == 400
    assert "Port settings changes are off" in response.text
    assert _config_requests(enabled) == []


def test_role_without_rules_is_refused_by_the_switch(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.roles[ROLE_NAME].entities.discard("conf t ; interface * ; mtu *")
    response = _settings_post(logged_in, mtu="9216", confirm="yes")
    assert response.status_code == 400
    assert "may not make this change yet" in response.text


# ---- breakout ---------------------------------------------------------------


def _breakout(client: TestClient, name: str, action: str, mapping: str, confirm: str = ""):
    return client.post(
        "/ports/breakout",
        data={
            "csrf": _csrf(client, f"/ports/detail?name={name}"),
            "name": name,
            "action": action,
            "mapping": mapping,
            "confirm": confirm,
        },
    )


def test_split_asks_then_shows_the_first_new_port(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    asked = _text(_breakout(logged_in, "Ethernet1/50", "split", "25g-4x").text)
    assert "Split Ethernet1/50 into four ports (4 x 25G)" in asked
    assert "Update the port list" in asked
    assert _config_requests(enabled) == []

    done = _breakout(logged_in, "Ethernet1/50", "split", "25g-4x", confirm="yes")
    assert _config_requests(enabled) == [["interface breakout module 1 port 50 map 25g-4x"]]
    text = _text(done.text)
    assert "Ethernet1/50/1" in text and "Join the four ports" in text
    assert "Update the port list" in text

    # The role does not name the new ports yet, and the page says what to do.
    response = _settings_post(logged_in, name="Ethernet1/50/2", mtu="9216", confirm="yes")
    assert response.status_code == 400
    assert "does not name this port" in response.text

    _enable(logged_in)  # Update the port list
    _settings_post(logged_in, name="Ethernet1/50/2", mtu="9216", confirm="yes")
    assert _config_requests(enabled)[-1] == ["interface Ethernet1/50/2", "mtu 9216"]


def test_join_guesses_the_split_and_restores_the_port(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.breakouts["Ethernet1/50"] = "10g-4x"
    page = _page(logged_in, "Ethernet1/50/3")
    assert re.search(r'<option value="10g-4x" selected>', page)
    _breakout(logged_in, "Ethernet1/50/3", "join", "10g-4x", confirm="yes")
    assert _config_requests(enabled) == [["no interface breakout module 1 port 50 map 10g-4x"]]
    assert "Split this port" in _text(_page(logged_in, "Ethernet1/50"))


@pytest.mark.parametrize(
    ("name", "action", "mapping"),
    [
        ("Ethernet1/3", "split", "25g-4x"),
        ("Ethernet1/50", "split", "40g-2x"),
        ("Ethernet1/50", "join", "25g-4x"),
    ],
)
def test_breakout_refusals_change_nothing(
    logged_in: TestClient, enabled: FakeSwitch, name: str, action: str, mapping: str
) -> None:
    response = _breakout(logged_in, name, action, mapping, confirm="yes")
    assert response.status_code == 400
    assert "Not changed" in response.text
    assert _config_requests(enabled) == []


def test_viewer_cannot_change_settings(logged_in: TestClient, enabled: FakeSwitch) -> None:
    password = "another-long-password"
    logged_in.post(
        "/users/create",
        data={
            "csrf": _csrf(logged_in, "/users"),
            "new_username": "vera",
            "password": password,
            "confirm_password": password,
            "role": "viewer",
        },
    )
    vera = TestClient(logged_in.app, follow_redirects=False)
    vera.post("/login", data={"username": "vera", "password": password, "next": "/"})
    text = _text(_page(vera))
    assert "Port settings" in text and "Change settings" not in text
    assert "Split this port" not in _text(_page(vera, "Ethernet1/50"))
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', vera.get("/account").text)
    assert csrf
    response = vera.post(
        "/ports/settings", data={"csrf": csrf.group(1), "name": "Ethernet1/3", "mtu": "9216"}
    )
    assert response.status_code == 403
