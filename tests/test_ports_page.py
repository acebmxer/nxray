"""The Ports page and a port's own page, against a pretend switch."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

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


def _table(html: str) -> str:
    """The filters and the table, as text: the front panel above them always shows every port."""
    return _text(html.split('<nav class="filters" aria-label="Show ports">')[1])


def _one_port_up(switch: FakeSwitch) -> None:
    interfaces = load_fixture("show_interface")
    for row in interfaces["TABLE_interface"]["ROW_interface"]:
        if row["interface"] == "Ethernet1/3":
            row.update(
                {
                    "state": "up",
                    "eth_speed": "25 Gb/s",
                    "desc": "xcp-host-1 <storage>",
                    "eth_inrate1_bits": "12500000",
                    "eth_inerr": "4",
                }
            )
    switch.bodies["show interface"] = interfaces


def test_ports_page_needs_a_switch(logged_in: TestClient) -> None:
    body = logged_in.get("/ports").text
    assert "No switch connected yet" in body


def test_ports_page_lists_every_port_from_one_request(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    text = _text(logged_in.get("/ports").text)
    assert switch.requests == [
        ["show interface", "show interface status", "show interface transceiver"]
    ]
    assert "All (54)" in text and "Up (0)" in text and "Down (54)" in text
    assert "Ethernet1/1 Down XCVR not inserted auto 1 none 0 b/s 0 b/s 0" in text
    assert "Ethernet1/54" in text


def test_filters(logged_in: TestClient, switch: FakeSwitch) -> None:
    _one_port_up(switch)
    up = _table(logged_in.get("/ports?show=up").text)
    assert "Up (1)" in up and "Down (53)" in up and "With errors (1)" in up
    assert "Ethernet1/3 xcp-host-1 &lt;storage&gt; Up 25 Gb/s" in up
    assert "Ethernet1/1 " not in up
    assert "Ethernet1/3" in _table(logged_in.get("/ports?show=errors").text)
    assert "Ethernet1/3 " not in _table(logged_in.get("/ports?show=down").text)
    # An unknown filter shows everything.
    assert "Ethernet1/54" in _table(logged_in.get("/ports?show=nonsense").text)


def test_descriptions_are_escaped(logged_in: TestClient, switch: FakeSwitch) -> None:
    _one_port_up(switch)
    html = logged_in.get("/ports").text
    assert "xcp-host-1 &lt;storage&gt;" in html
    assert "<storage>" not in html


def test_port_detail(logged_in: TestClient, switch: FakeSwitch) -> None:
    _one_port_up(switch)
    page = logged_in.get("/ports/detail", params={"name": "Ethernet1/3"})
    assert page.status_code == 200
    text = _text(page.text)
    assert "Speed 25 Gb/s" in text
    assert "In now 12.5 Mb/s" in text
    assert "Input errors 4" in text
    assert "MAC address 0200.0000." in text
    assert "Nothing plugged in." in text


def test_ports_link_to_their_detail_page(logged_in: TestClient, switch: FakeSwitch) -> None:
    assert 'href="/ports/detail?name=Ethernet1/1"' in logged_in.get("/ports").text


def test_unknown_port_is_a_404(logged_in: TestClient, switch: FakeSwitch) -> None:
    for name in ("Ethernet9/99", "", "mgmt0", "Ethernet1/1; reload"):
        page = logged_in.get("/ports/detail", params={"name": name})
        assert page.status_code == 404, name
        assert "has no port called" in page.text
    # Port names never reach the switch as part of a command.
    assert all(cmd[0] == "show interface" for cmd in switch.requests)


def test_unreachable_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.reachable = False
    for path in ("/ports", "/ports/detail?name=Ethernet1/1"):
        text = _text(logged_in.get(path).text)
        assert "could not reach the switch" in text, path


def test_ports_page_draws_the_front_panel(logged_in: TestClient, switch: FakeSwitch) -> None:
    _one_port_up(switch)
    html = logged_in.get("/ports").text
    assert '<svg class="face"' in html
    assert html.count('<a class="face-port"') == 54
    assert 'class="face-cell f-up"' in html
    # The legend counts the ports in each colour.
    assert 'Up <span class="legend-values">1</span>' in html
    assert 'Empty: nothing plugged in <span class="legend-values">53</span>' in html


@pytest.mark.parametrize("mode", ["state", "traffic", "errors"])
def test_colour_modes_read_the_switch_once(
    logged_in: TestClient, switch: FakeSwitch, mode: str
) -> None:
    html = logged_in.get(f"/ports?color={mode}").text
    assert switch.requests == [
        ["show interface", "show interface status", "show interface transceiver"]
    ]
    assert f'filter filter-on" href="/ports?show=all&amp;color={mode}"' in html


def test_vlan_mode_names_the_vlans_from_the_same_request(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    html = logged_in.get("/ports?color=vlan").text
    assert len(switch.requests) == 1
    assert "show vlan brief" in switch.requests[0]
    assert "VLAN 1 default" in _text(html)
    assert "f-vlan s0" in html


def test_filters_keep_the_colour_mode(logged_in: TestClient, switch: FakeSwitch) -> None:
    html = logged_in.get("/ports?color=errors&show=down").text
    assert 'href="/ports?show=up&amp;color=errors"' in html
    assert 'href="/ports?show=down&amp;color=traffic"' in html


def test_unknown_colour_mode_is_state(logged_in: TestClient, switch: FakeSwitch) -> None:
    html = logged_in.get("/ports?color=<b>").text
    assert 'filter filter-on" href="/ports?show=all&amp;color=state"' in html
    assert "<b>" not in html


def test_face_links_open_the_port_page(logged_in: TestClient, switch: FakeSwitch) -> None:
    html = logged_in.get("/ports").text
    assert '<a class="face-port" href="/ports/detail?name=Ethernet1/54">' in html
