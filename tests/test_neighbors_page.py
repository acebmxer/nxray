"""The Neighbors page, a port's Connected devices card and the front panel's
tooltips, against a pretend switch."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from app.face import device_lines, tooltip
from app.neighbors import NeighborView, parse_neighbor_view
from app.ports import parse_ports
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', logged_in.get("/switch").text)
    assert csrf
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": csrf.group(1),
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


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def _view(lldp: bool = False) -> NeighborView:
    return parse_neighbor_view(
        load_fixture("show_feature"),
        load_fixture("show_cdp_global"),
        load_fixture("show_mac_address_table"),
        load_fixture("show_mac_address_table_aging_time"),
        load_fixture("show_ip_arp_detail_vrf_all"),
        load_fixture("show_port_channel_summary"),
        load_fixture("show_cdp_neighbors_detail"),
        load_fixture("show_lldp_neighbors_detail") if lldp else None,
    )


def test_neighbors_page_needs_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in logged_in.get("/neighbors").text


def test_neighbors_page_is_in_the_menu(logged_in: TestClient) -> None:
    assert '<a class="navlink" href="/neighbors">Neighbors</a>' in logged_in.get("/").text


def test_neighbors_page_shows_the_three_tables(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/neighbors")
    assert page.status_code == 200
    text = _text(page.text)
    assert "CDP is on and LLDP is off on the switch." in text
    assert "LLDP is off on the switch, so only devices that speak CDP" in text
    # The CDP neighbor on a front port links to that port; mgmt0 has no page.
    assert '<a href="/ports/detail?name=Ethernet1/47">Ethernet1/47</a>' in page.text
    assert "CDP nexus-lab mgmt0 N9K-C92160YC-X 192.0.2.10" in text
    assert "An address is forgotten after 30 minutes without traffic." in text
    assert "42 entries." in text
    assert "0c:ea:14:00:00:01 Ubiquiti" in text
    assert "Locally administered (often a VM" in text
    assert "the switch itself" in text
    # The ARP entry, and its IPv4 address next to the same MAC address in the MAC table.
    assert "192.0.2.1 60:22:32:00:00:05 mgmt0" in text
    assert re.search(r"60:22:32:00:00:05 .*? 1 Ethernet1/47 192\.0\.2\.1 dynamic", text)
    assert re.search(
        r"port-channel43 is <a [^>]+>Ethernet1/43</a> and <a [^>]+>Ethernet1/44</a>\.", page.text
    )


def test_neighbors_page_lists_lldp_neighbors_once_it_is_on(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    switch.lldp = True
    text = _text(logged_in.get("/neighbors").text)
    assert "CDP is on and LLDP is on on the switch." in text
    assert "LLDP is off" not in text
    assert "Ethernet1/37 LLDP pve-node-1 enp65s0f0np0" in text
    assert "station" in text


def test_searching_the_mac_table(logged_in: TestClient, switch: FakeSwitch) -> None:
    text = _text(logged_in.get("/neighbors", params={"q": "1/39"}).text)
    assert "2 of 42 entries match." in text
    assert "50:6b:4b:00:00:0b" in text and "0c:ea:14:00:00:01" not in text
    assert 'value="1/39"' in logged_in.get("/neighbors", params={"q": "1/39"}).text
    nothing = _text(logged_in.get("/neighbors", params={"q": "<b>x</b>"}).text)
    assert (
        'No entry matches "&lt;b&gt;x&lt;/b&gt;".'
        in logged_in.get("/neighbors", params={"q": "<b>x</b>"}).text
    )
    assert "Show all" in nothing


def test_an_overlong_search_is_cut_short(logged_in: TestClient, switch: FakeSwitch) -> None:
    html = logged_in.get("/neighbors", params={"q": "a" * 500}).text
    assert 'value="' + "a" * 64 + '"' in html
    assert "a" * 65 not in html


def test_the_search_never_reaches_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    logged_in.get("/neighbors", params={"q": "Ethernet1/1; reload"})
    assert all("reload" not in cmd for request in switch.requests for cmd in request)


def test_a_viewer_sees_the_neighbors_page(logged_in: TestClient, switch: FakeSwitch) -> None:
    password = "another-long-password"
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', logged_in.get("/users").text)
    assert csrf
    logged_in.post(
        "/users/create",
        data={
            "csrf": csrf.group(1),
            "new_username": "vera",
            "password": password,
            "confirm_password": password,
            "role": "viewer",
        },
    )
    vera = TestClient(logged_in.app, follow_redirects=False)
    signed_in = vera.post("/login", data={"username": "vera", "password": password, "next": "/"})
    assert signed_in.status_code == 303
    page = vera.get("/neighbors")
    assert page.status_code == 200 and "MAC address table" in page.text


def test_unreachable_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.reachable = False
    assert "could not reach the switch" in _text(logged_in.get("/neighbors").text)


def test_port_page_shows_what_is_plugged_in(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.lldp = True
    text = _text(logged_in.get("/ports/detail", params={"name": "Ethernet1/37"}).text)
    assert "Connected devices" in text
    assert "LLDP pve-node-1 enp65s0f0np0" in text
    assert "0a:00:00:00:00:0d" in text and "b8:59:9f:00:00:0f" in text
    assert "is part of" not in text


def test_port_page_of_a_port_channel_member(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/ports/detail", params={"name": "Ethernet1/43"})
    text = _text(page.text)
    assert (
        'Ethernet1/43 is part of port-channel43, with <a href="/ports/detail?name=Ethernet1/44">'
        "Ethernet1/44</a>. The switch learns" in page.text
    )
    assert "b8:59:9f:00:00:0e" in text
    assert "No device on this port has announced itself." in text
    assert "LLDP is off on the switch" in text


def test_port_page_of_an_empty_port(logged_in: TestClient, switch: FakeSwitch) -> None:
    text = _text(logged_in.get("/ports/detail", params={"name": "Ethernet1/1"}).text)
    assert "The switch has learned no MAC addresses on this port." in text


def test_port_page_keeps_working_when_the_tables_are_refused(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    switch.reject = {"show mac address-table"}
    page = logged_in.get("/ports/detail", params={"name": "Ethernet1/37"})
    assert page.status_code == 200
    text = _text(page.text)
    assert "The switch did not report its neighbors or its MAC address table." in text
    assert "Transceiver" in text and "Port settings" in text


def test_ports_page_keeps_working_when_the_tables_are_refused(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    switch.reject = {"show mac address-table"}
    html = logged_in.get("/ports").text
    assert html.count('<a class="face-port"') == 54
    assert "Devices learned" not in html


def test_front_panel_tooltips_say_what_is_plugged_in(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    html = logged_in.get("/ports").text
    assert "Devices learned on port-channel43: 1" in html
    assert "CDP neighbor: nexus-lab, its port mgmt0" in html


def test_tooltip_names_three_devices_and_counts_the_rest() -> None:
    view = _view()
    lines = device_lines(view.for_port("Ethernet1/47"))
    assert lines[0] == "CDP neighbor: nexus-lab, its port mgmt0"
    # Each address once, however many VLANs it was learned in.
    assert lines[1] == "Devices learned: 24"
    assert len([line for line in lines if line.startswith("  ") and ":" in line]) == 3
    assert lines[-1] == "  and 21 more"
    # In port order, then VLAN: the first is the switch's own mgmt0 (scrubbed to a private address).
    assert lines[2] == "  02:00:00:00:bb:de (locally administered)"
    assert "Ubiquiti" in lines[3]


def test_tooltip_of_a_port_channel_member_and_a_private_address() -> None:
    view = _view()
    assert device_lines(view.for_port("Ethernet1/44")) == [
        "Part of port-channel43",
        "Devices learned on port-channel43: 1",
        "  b8:59:9f:00:00:0e (Mellanox Technologies, Inc.)",
    ]
    lines = device_lines(view.for_port("Ethernet1/38"))
    assert "  0a:00:00:00:00:0a (locally administered)" in lines


def test_tooltip_without_neighbor_data_is_unchanged() -> None:
    ports = parse_ports(
        load_fixture("show_interface"),
        load_fixture("show_interface_status"),
        load_fixture("show_interface_transceiver"),
    )
    port = next(p for p in ports if p.name == "Ethernet1/1")
    empty = _view().for_port("Ethernet1/1")
    assert tooltip(port) == tooltip(port, devices=empty)
