"""Traffic per device and per VLAN, estimated from the ports' own figures."""

from __future__ import annotations

import json
from typing import Any

import httpx

from app import traffic
from app.neighbors import NeighborView, parse_neighbor_view
from app.nxapi import NxapiClient, SwitchTarget
from app.ports import Port, parse_ports
from tests.conftest import load_fixture

TARGET = SwitchTarget(host="192.0.2.10", port=443, username="nxray", password="pw", timeout=5.0)


def _ports(
    up: dict[str, tuple[int, int]],
    modes: dict[str, str] | None = None,
    vlans: dict[str, str] | None = None,
) -> list[Port]:
    """The recorded ports, with some up at (in, out) bits per second."""
    interfaces = load_fixture("show_interface")
    for row in interfaces["TABLE_interface"]["ROW_interface"]:
        name = row["interface"]
        if name in up:
            row.update(
                state="up",
                eth_inrate1_bits=str(up[name][0]),
                eth_outrate1_bits=str(up[name][1]),
            )
        if modes and name in modes:
            row["eth_mode"] = modes[name]
    statuses = load_fixture("show_interface_status")
    for row in statuses["TABLE_interface"]["ROW_interface"]:
        if vlans and row["interface"] in vlans:
            row["vlan"] = vlans[row["interface"]]
    return parse_ports(interfaces, statuses, {})


def _view() -> NeighborView:
    return parse_neighbor_view(
        load_fixture("show_feature"),
        load_fixture("show_cdp_global"),
        load_fixture("show_mac_address_table"),
        load_fixture("show_mac_address_table_aging_time"),
        load_fixture("show_ip_arp_detail_vrf_all"),
        load_fixture("show_port_channel_summary"),
    )


def _port(ports: list[Port], name: str) -> Port:
    return next(port for port in ports if port.name == name)


# ---- per device ----


def test_a_device_alone_on_an_access_port_gets_the_ports_traffic() -> None:
    # Ethernet1/46 has one address learned on it: 98:03:9b:00:00:0c.
    found = traffic.device_traffic(_ports({"Ethernet1/46": (8_000_000, 2_000_000)}), _view())
    item = found["98:03:9b:00:00:0c"]
    assert (item.port, item.vlan) == ("Ethernet1/46", "2")
    # Named from the device's side: what comes in on the port, it sent.
    assert (item.sends_bits, item.receives_bits, item.total_bits) == (
        8_000_000,
        2_000_000,
        10_000_000,
    )


def test_a_port_that_is_down_gives_no_figure() -> None:
    assert traffic.device_traffic(_ports({}), _view()) == {}


def test_a_port_with_several_devices_cannot_be_split() -> None:
    ports = _ports({"Ethernet1/37": (1, 1), "Ethernet1/47": (1, 1)})
    found = traffic.device_traffic(ports, _view())
    assert all(item.port not in ("Ethernet1/37", "Ethernet1/47") for item in found.values())
    _, why = traffic.port_device(_port(ports, "Ethernet1/37"), _view().for_port("Ethernet1/37"))
    assert why.startswith("2 devices are behind this port")


def test_one_address_in_several_vlans_is_one_device() -> None:
    # Ethernet1/39 has 50:6b:4b:00:00:0b in VLANs 2 and 253.
    ports = _ports({"Ethernet1/39": (5, 7)})
    entry, why = traffic.port_device(_port(ports, "Ethernet1/39"), _view().for_port("Ethernet1/39"))
    assert entry is not None and entry.mac == "50:6b:4b:00:00:0b" and why == ""


def test_a_trunk_gives_no_figure() -> None:
    ports = _ports({"Ethernet1/46": (1, 1)}, modes={"Ethernet1/46": "trunk"})
    assert traffic.device_traffic(ports, _view()) == {}
    _, why = traffic.port_device(_port(ports, "Ethernet1/46"), _view().for_port("Ethernet1/46"))
    assert "trunk carries several VLANs" in why


def test_a_port_channel_member_gives_no_figure() -> None:
    # Ethernet1/43 is in port-channel43, which has one address learned on it.
    ports = _ports({"Ethernet1/43": (1, 1)})
    assert traffic.device_traffic(ports, _view()) == {}
    _, why = traffic.port_device(_port(ports, "Ethernet1/43"), _view().for_port("Ethernet1/43"))
    assert "port-channel" in why


def test_an_empty_port_has_nothing_to_say() -> None:
    ports = _ports({"Ethernet1/1": (1, 1)})
    assert traffic.port_device(_port(ports, "Ethernet1/1"), _view().for_port("Ethernet1/1")) == (
        None,
        "",
    )


def test_busiest_devices_come_first_and_idle_ones_are_left_out() -> None:
    def item(mac: str, sends: int, receives: int) -> traffic.DeviceTraffic:
        return traffic.DeviceTraffic(mac, "Ethernet1/1", "1", sends, receives)

    found = {
        "a": item("a", 1, 1),
        "b": item("b", 10, 0),
        "c": item("c", 0, 0),
        "d": item("d", 5, 5),
    }
    assert [x.mac for x in traffic.busiest_devices(found)] == ["b", "d", "a"]
    assert [x.mac for x in traffic.busiest_devices(found, limit=1)] == ["b"]


def test_load_device_traffic_reads_show_interface_alone() -> None:
    sent: list[Any] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        sent.append([entry["params"]["cmd"] for entry in payload])
        body = load_fixture("show_interface")
        for row in body["TABLE_interface"]["ROW_interface"]:
            if row["interface"] == "Ethernet1/46":
                row.update(state="up", eth_inrate1_bits="3000", eth_outrate1_bits="4000")
        return httpx.Response(200, json=[{"jsonrpc": "2.0", "id": 1, "result": {"body": body}}])

    target = TARGET
    with NxapiClient(target, transport=httpx.MockTransport(handler)) as client:
        found = traffic.load_device_traffic(client, _view())
    assert sent == [["show interface"]]
    assert found["98:03:9b:00:00:0c"].sends_bits == 3000


def test_load_device_traffic_is_empty_when_refused() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=[
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": -32602, "message": "Invalid params", "data": {"msg": "no"}},
                }
            ],
        )

    target = TARGET
    with NxapiClient(target, transport=httpx.MockTransport(handler)) as client:
        assert traffic.load_device_traffic(client, _view()) == {}


# ---- per VLAN ----


def test_a_vlans_access_ports_are_added_up() -> None:
    ports = _ports(
        {"Ethernet1/1": (100, 10), "Ethernet1/2": (200, 20), "Ethernet1/3": (400, 40)},
        vlans={"Ethernet1/1": "10", "Ethernet1/2": "10", "Ethernet1/3": "20"},
    )
    found = traffic.vlan_traffic(ports)
    assert found == {
        10: traffic.VlanTraffic(10, 300, 30, 2),
        20: traffic.VlanTraffic(20, 400, 40, 1),
    }


def test_trunks_routed_and_down_ports_are_left_out() -> None:
    ports = _ports(
        {"Ethernet1/1": (100, 10), "Ethernet1/2": (200, 20), "Ethernet1/3": (400, 40)},
        modes={"Ethernet1/1": "trunk", "Ethernet1/2": "routed"},
        vlans={"Ethernet1/1": "trunk", "Ethernet1/2": "routed", "Ethernet1/4": "30"},
    )
    # Ethernet1/3 is in VLAN 1 as recorded; Ethernet1/4 is down.
    assert traffic.vlan_traffic(ports) == {1: traffic.VlanTraffic(1, 400, 40, 1)}
