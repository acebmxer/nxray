"""One shared configuration for several ports (#16), through the Ports page."""

from __future__ import annotations

import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


def _csrf(client: TestClient, path: str = "/switch") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(html: str) -> str:
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))
    return text.replace("&#34;", '"').replace("&#39;", "'")


def _db(settings: Settings, sql: str, *args) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(sql, args)
    conn.commit()
    conn.close()


@pytest.fixture
def enabled(logged_in: TestClient, settings: Settings) -> FakeSwitch:
    """A set-up switch with every kind of change on and the wait over."""
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    login = {"admin_user": "admin", "admin_password": ADMIN_PASSWORD, "confirm_save": "yes"}
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": _csrf(logged_in),
            "host": "192.0.2.10",
            "port": "443",
            "account_name": "nxray",
            **login,
        },
    )
    response = logged_in.post(
        "/switch/enable-changes", data={"csrf": _csrf(logged_in), "ssh_port": "22", **login}
    )
    assert response.status_code == 200
    _db(settings, "UPDATE switch_connection SET paused_until = ?", time.time() - 1)
    fake.requests.clear()
    fake.saved = False
    return fake


def _bulk(client: TestClient, names: list[str], **form):
    return client.post("/ports/bulk", data={"csrf": _csrf(client), "names": names, **form})


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


# Ports that are not next to each other, as in the issue.
SPREAD = ["Ethernet1/3", "Ethernet1/7", "Ethernet1/12", "Ethernet1/40"]


def test_the_card_offers_every_shared_setting(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/ports").text
    for field in (
        "power",
        "set_description",
        "description",
        "mode",
        "access_vlan",
        "native_vlan",
        "allowed",
        "layer",
        "speed",
        "mtu",
        "fec",
        "flow_receive",
        "flow_send",
        "storm_broadcast",
        "storm_multicast",
        "storm_unicast",
        "storm_action",
        "cdp",
        "lldp_transmit",
        "lldp_receive",
        "clear_macs",
        "start",
    ):
        assert f'name="{field}"' in page, field
    # Every setting starts at "leave as it is", and no address is offered.
    assert 'name="ip_address"' not in page
    card = page.split('id="bulk-title"')[1].split('class="drawer-foot bulk-bar"')[0]
    assert " checked" not in card
    assert card.count("Leave as it is</option>") == card.count("<select")


def test_sections_follow_their_switch_page_switches(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 1")
    page = logged_in.get("/ports").text
    assert 'name="power"' in page
    assert 'name="mode"' not in page and 'name="mtu"' not in page and 'name="cdp"' not in page


def test_one_vlan_for_ports_that_are_not_neighbours(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.vlans[20] = "lab"
    ask = _bulk(logged_in, SPREAD, access_vlan="20")
    text = _text(ask.text)
    for name in SPREAD:
        assert f"{name}: Access VLAN: 1 → 20." in text
    # One warning naming every port it is about.
    assert (
        "Ethernet1/3, Ethernet1/7, Ethernet1/12, Ethernet1/40: The device on this port moves "
        "from VLAN 1 to VLAN 20" in text
    )
    assert _config_requests(enabled) == []

    done = _text(_bulk(logged_in, SPREAD, access_vlan="20", confirm="yes").text)
    assert "Done: changed Ethernet1/3, Ethernet1/7, Ethernet1/12, Ethernet1/40." in done
    assert _config_requests(enabled) == [
        [f"interface {name}", "switchport access vlan 20"] for name in SPREAD
    ]


def test_only_what_is_filled_in_is_sent(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.vlans[20] = "lab"
    _bulk(logged_in, ["Ethernet1/3"], access_vlan="20", confirm="yes")
    enabled.requests.clear()
    # Changing the MTU leaves the VLANs, speed and everything else alone.
    _bulk(logged_in, ["Ethernet1/3", "Ethernet1/5"], mtu="9216", confirm="yes")
    assert _config_requests(enabled) == [
        ["interface Ethernet1/3", "mtu 9216"],
        ["interface Ethernet1/5", "mtu 9216"],
    ]
    page = _text(logged_in.get("/ports/detail", params={"name": "Ethernet1/3"}).text)
    assert "Access VLAN 20 (lab)" in page and "9216 (jumbo frames)" in page


def test_a_full_configuration_in_one_go(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.vlans.update({10: "users", 20: "voice"})
    form = {
        "power": "on",
        "set_description": "yes",
        "description": "desk",
        "mode": "trunk",
        "native_vlan": "10",
        "allowed": "20",
        "speed": "10000",
        "mtu": "9216",
        "fec": "off",
        "flow_receive": "on",
        "flow_send": "off",
        "storm_broadcast": "5",
        "storm_multicast": "none",
        "storm_unicast": "2.5",
        "storm_action": "trap",
        "cdp": "off",
    }
    ask = _text(_bulk(logged_in, ["Ethernet1/5", "Ethernet1/9"], **form).text)
    assert "VLAN 10 is the native VLAN, so it is added to the VLANs carried" in ask
    _bulk(logged_in, ["Ethernet1/5", "Ethernet1/9"], confirm="yes", **form)
    requests = _config_requests(enabled)
    # Per port: settings, VLANs, CDP/LLDP, then description and on/off.
    assert requests[:4] == [
        [
            "interface Ethernet1/5",
            "speed 10000",
            "mtu 9216",
            "fec off",
            "flowcontrol receive on",
            "storm-control broadcast level 5.00",
            "storm-control unicast level 2.50",
            "storm-control action trap",
        ],
        [
            "interface Ethernet1/5",
            "switchport mode trunk",
            "switchport trunk native vlan 10",
            "switchport trunk allowed vlan 10,20",
        ],
        ["interface Ethernet1/5", "no cdp enable"],
        ["interface Ethernet1/5", "description desk"],
    ]
    assert requests[4][0] == "interface Ethernet1/9" and len(requests) == 8


def test_ports_already_as_asked_are_left_out(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _bulk(logged_in, ["Ethernet1/3"], mtu="9216", confirm="yes")
    ask = _bulk(logged_in, ["Ethernet1/3", "Ethernet1/4"], mtu="9216")
    text = _text(ask.text)
    assert "Ethernet1/4: MTU: 1500 → 9216." in text
    assert "Unchanged: Ethernet1/3 is already set as asked." in text
    assert 'name="names" value="Ethernet1/3"' not in ask.text


def test_trunk_settings_leave_access_ports_alone(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.vlans[10] = "users"
    response = _bulk(logged_in, ["Ethernet1/3"], native_vlan="10", confirm="yes")
    text = _text(response.text)
    assert "Nothing to change: Ethernet1/3 is already set as asked." in text
    assert "Ethernet1/3 is an access port, so the native VLAN and VLANs carried" in text
    assert _config_requests(enabled) == []


@pytest.mark.parametrize(
    ("names", "form", "message"),
    [
        (
            ["Ethernet1/3", "Ethernet1/50"],
            {"speed": "100000"},
            "Ethernet1/3: Ethernet1/3 runs at 1 Gb/s, 10 Gb/s, 25 Gb/s or auto",
        ),
        (["Ethernet1/3"], {"access_vlan": "999"}, "VLAN 999 does not exist on the switch"),
        (["Ethernet1/3"], {"access_vlan": "5000"}, "a VLAN is a number from 1 to 4094"),
        (["Ethernet1/3"], {"allowed": "10 20"}, "is not a VLAN or range"),
        (["Ethernet1/3"], {"mtu": "9000"}, "a switched port's MTU is 1500"),
        (["Ethernet1/3"], {"layer": "routed", "mode": "access"}, "a routed port carries no VLANs"),
        (["Ethernet1/3"], {"storm_broadcast": "101"}, "a storm-control level is a percentage"),
        (["Ethernet1/3"], {"speed": "7"}, "pick a speed from the list"),
        (["Ethernet1/3"], {"fec": "magic"}, "pick a FEC mode from the list"),
        (["Ethernet1/3"], {"cdp": "maybe"}, "CDP and LLDP are on or off"),
        (["Ethernet1/3"], {"lldp_transmit": "on"}, "LLDP is off for the whole switch"),
        (["Ethernet1/3"], {"ip_address": "192.0.2.1/24"}, "fill in at least one setting"),
    ],
)
def test_bad_shared_settings_send_nothing(
    logged_in: TestClient,
    enabled: FakeSwitch,
    names: list[str],
    form: dict[str, str],
    message: str,
) -> None:
    for confirm in ("", "yes"):
        response = _bulk(logged_in, names, confirm=confirm, **form)
        assert response.status_code == 400
        assert message in _text(response.text)
    assert _config_requests(enabled) == []


def test_a_port_that_cannot_take_it_is_named_and_nothing_is_sent(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.vlans[20] = "lab"
    _bulk(logged_in, ["Ethernet1/7"], layer="routed", confirm="yes")
    enabled.requests.clear()
    response = _bulk(logged_in, SPREAD, access_vlan="20", confirm="yes")
    text = _text(response.text)
    assert response.status_code == 400
    assert "these ports cannot take this configuration" in text
    assert "Ethernet1/7: Ethernet1/7 is a routed port, which has no VLANs" in text
    assert "Ethernet1/3:" not in text.split("cannot take")[1].split("Tick")[0]
    assert _config_requests(enabled) == []
    # Making it switched in the same go gives it the VLAN.
    _bulk(logged_in, SPREAD, layer="switched", access_vlan="20", confirm="yes")
    requests = _config_requests(enabled)
    assert ["interface Ethernet1/7", "switchport"] in requests
    assert ["interface Ethernet1/7", "switchport access vlan 20"] in requests
    assert requests.index(["interface Ethernet1/7", "switchport"]) < requests.index(
        ["interface Ethernet1/7", "switchport access vlan 20"]
    )


def test_layer_change_warns_and_never_shares_an_address(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    ask = _text(_bulk(logged_in, ["Ethernet1/3", "Ethernet1/4"], layer="routed").text)
    assert "Layer: switched (layer 2) → routed (layer 3)." in ask
    assert "Ethernet1/3, Ethernet1/4: A routed port carries no VLANs" in ask
    _bulk(logged_in, ["Ethernet1/3", "Ethernet1/4"], layer="routed", confirm="yes")
    assert _config_requests(enabled) == [
        ["interface Ethernet1/3", "no switchport"],
        ["interface Ethernet1/4", "no switchport"],
    ]


def test_routed_ports_keep_their_own_addresses(logged_in: TestClient, enabled: FakeSwitch) -> None:
    for name, address in (("Ethernet1/3", "192.0.2.1/24"), ("Ethernet1/4", "198.51.100.1/24")):
        logged_in.post(
            "/ports/settings",
            data={
                "csrf": _csrf(logged_in),
                "name": name,
                "layer": "routed",
                "ip_address": address,
                "confirm": "yes",
            },
        )
    enabled.requests.clear()
    _bulk(logged_in, ["Ethernet1/3", "Ethernet1/4"], mtu="9000", confirm="yes")
    assert _config_requests(enabled) == [
        ["interface Ethernet1/3", "mtu 9000"],
        ["interface Ethernet1/4", "mtu 9000"],
    ]


def test_cdp_and_clearing_addresses_on_several_ports(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    names = ["Ethernet1/5", "Ethernet1/47"]
    ask = _text(_bulk(logged_in, names, cdp="off", clear_macs="yes").text)
    assert "Ethernet1/5: Turn CDP off on Ethernet1/5." in ask
    assert "Forget the addresses learned on Ethernet1/47" in ask
    done = _bulk(logged_in, names, cdp="off", clear_macs="yes", confirm="yes")
    assert done.status_code == 200
    assert _config_requests(enabled) == [
        ["interface Ethernet1/5", "no cdp enable"],
        ["clear mac address-table dynamic interface Ethernet1/5"],
        ["interface Ethernet1/47", "no cdp enable"],
        ["clear mac address-table dynamic interface Ethernet1/47"],
    ]


def test_clearing_addresses_alone_needs_no_save(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _text(_bulk(logged_in, ["Ethernet1/47"], clear_macs="yes", confirm="yes").text)
    assert "Done: changed Ethernet1/47." in done
    assert "Not saved yet" not in done


def test_each_kind_needs_its_switch(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 2")
    response = _bulk(logged_in, ["Ethernet1/3"], mtu="9216", confirm="yes")
    assert response.status_code == 400
    assert "Port settings changes are off" in response.text
    response = _bulk(logged_in, ["Ethernet1/3"], cdp="off", confirm="yes")
    assert "Neighbor changes are off" in response.text
    _db(settings, "UPDATE switch_connection SET role_version = 1")
    response = _bulk(logged_in, ["Ethernet1/3"], access_vlan="1", confirm="yes")
    assert "VLAN changes are off" in response.text
    assert _config_requests(enabled) == []


def test_a_refusal_partway_through_a_port_says_what_was_made(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.vlans[20] = "lab"
    enabled.reject.add("switchport access vlan")
    names = ["Ethernet1/3", "Ethernet1/4"]
    response = _bulk(logged_in, names, mtu="9216", access_vlan="20", confirm="yes")
    text = _text(response.text)
    assert response.status_code == 400
    assert "Changed:" not in text
    assert (
        "Ethernet1/3 was changed only in part: MTU: 1500 → 9216. Then the switch refused the "
        "next part (VLANs)." in text
    )
    assert "Not tried: Ethernet1/4." in text
    assert "Not saved yet" in text
    assert _config_requests(enabled) == [
        ["interface Ethernet1/3", "mtu 9216"],
        ["interface Ethernet1/3", "switchport access vlan 20"],
    ]
    activity = _text(logged_in.get("/activity").text)
    assert "Ethernet1/3 (in part): MTU: 1500 → 9216." in activity


def test_start_from_a_port_fills_the_form(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.vlans.update({10: "users", 20: "voice"})
    _bulk(
        logged_in,
        ["Ethernet1/9"],
        mode="trunk",
        native_vlan="10",
        allowed="10,20",
        mtu="9216",
        cdp="off",
        confirm="yes",
    )
    enabled.requests.clear()
    page = _bulk(logged_in, ["Ethernet1/3", "Ethernet1/4"], start="Ethernet1/9", fill="yes")
    assert page.status_code == 200
    assert _config_requests(enabled) == []
    text = _text(page.text)
    assert "The form now holds the VLANs, port settings and CDP/LLDP of Ethernet1/9" in text
    html = page.text
    assert '<option value="trunk" selected>' in html
    assert 'name="native_vlan" type="text" inputmode="numeric" value="10"' in html
    assert 'name="allowed" type="text" value="10,20"' in html
    assert 'name="mtu" type="text" inputmode="numeric" value="9216"' in html
    assert '<option value="Ethernet1/9" selected>' in html
    for name in ("Ethernet1/3", "Ethernet1/4"):
        assert f'value="{name}" aria-label="Tick {name}" checked' in html
    # On/off and the description are never copied.
    assert '<option value="" selected>Leave as it is</option>' in html.split('id="bulk_power"')[1]


def test_start_from_an_unknown_port(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = _bulk(logged_in, ["Ethernet1/3"], start="Ethernet9/9", fill="yes")
    assert page.status_code == 400
    assert "Pick a port to start from." in page.text


def test_viewer_cannot_change_several_ports(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    csrf = _csrf(logged_in)
    _db(settings, "UPDATE users SET role = 'viewer'")
    response = logged_in.post(
        "/ports/bulk", data={"csrf": csrf, "names": ["Ethernet1/3"], "mtu": "9216"}
    )
    assert response.status_code == 403
    assert _config_requests(enabled) == []
