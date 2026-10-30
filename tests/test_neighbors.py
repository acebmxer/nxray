"""Neighbors, the MAC address table and ARP (app/neighbors.py).

The CDP, MAC, ARP, port-channel and feature bodies were recorded from
cisco-25gb through NX-API (scrubbed: the switch's own name, serial and
addresses, and the device-specific half of every MAC address). LLDP was off
there, so the LLDP body is shaped after Cisco's NX-API reference for NX-OS
9.3, not recorded.
"""

from __future__ import annotations

from app.neighbors import (
    CDP_NEIGHBORS,
    LLDP_NEIGHBORS,
    NEIGHBOR_COMMANDS,
    NeighborView,
    cdp_enabled,
    feature_enabled,
    filter_macs,
    load_neighbors,
    long_port_name,
    parse_arp,
    parse_cdp_neighbors,
    parse_lldp_neighbors,
    parse_mac_table,
    parse_neighbor_view,
    parse_port_channels,
    readable_duration,
    try_load_neighbors,
)
from app.nxapi import NxapiClient, SwitchTarget
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


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


def _client(switch: FakeSwitch) -> NxapiClient:
    target = SwitchTarget(
        host="192.0.2.10", port=443, username="admin", password=ADMIN_PASSWORD, timeout=10
    )
    return NxapiClient(target, transport=switch.transport())


def test_short_port_names_are_written_out() -> None:
    assert long_port_name("Eth1/47") == "Ethernet1/47"
    assert long_port_name("Eth1/50/2") == "Ethernet1/50/2"
    assert long_port_name("Po43") == "port-channel43"
    for name in ("Ethernet1/3", "mgmt0", "port-channel43", "sup-eth1(R)", "Vlan10"):
        assert long_port_name(name) == name


def test_durations_are_shown_in_plain_units() -> None:
    assert readable_duration("PT1M41S") == "1m 41s"
    assert readable_duration("PT23S") == "23s"
    assert readable_duration("P1DT2H") == "1d 2h"
    assert readable_duration("00:01:41") == "00:01:41"
    assert readable_duration(None) == ""


def test_cdp_neighbors_as_recorded() -> None:
    found = parse_cdp_neighbors(load_fixture("show_cdp_neighbors_detail"))
    assert [(n.local_port, n.name, n.remote_port) for n in found] == [
        ("mgmt0", "nexus-lab", "Ethernet1/47"),
        ("Ethernet1/47", "nexus-lab", "mgmt0"),
    ]
    first = found[0]
    assert first.protocol == "CDP"
    assert first.platform == "N9K-C92160YC-X"
    assert first.address == "192.0.2.10"
    assert first.capabilities.startswith("router, switch")
    # NX-API sends nativevlan as a number and ttl as text: both are read.
    assert first.vlan == "1"
    assert first.hold_seconds == 137
    assert "9.3(16)" in first.software


def test_lldp_neighbors_with_letters_turned_into_words() -> None:
    found = parse_lldp_neighbors(load_fixture("show_lldp_neighbors_detail"))
    server, switch = found
    assert server.local_port == "Ethernet1/37"
    assert server.name == "pve-node-1"
    assert server.remote_port == "enp65s0f0np0"
    assert server.capabilities == "station"
    assert server.address == "192.0.2.21"
    assert server.vlan == ""  # "not advertised"
    assert switch.capabilities == "bridge, router"
    assert switch.platform == "Cisco Nexus Operating System (NX-OS) Software 7.0(3)I7(5)"
    assert switch.vlan == "10"
    assert switch.hold_seconds == 106


def test_an_lldp_neighbor_without_a_name_is_known_by_its_chassis_id() -> None:
    body = {
        "TABLE_nbor_detail": {
            "ROW_nbor_detail": {
                "chassis_id": "b859.9f00.0010",
                "port_id": "b859.9f00.0011",
                "l_port_id": "Eth1/9",
                "sys_name": "not advertised",
                "port_desc": "not advertised",
                "sys_desc": "not advertised",
                "system_capability": "",
                "enabled_capability": "",
            }
        }
    }
    (neighbor,) = parse_lldp_neighbors(body)
    assert neighbor.name == "b859.9f00.0010"
    assert neighbor.remote_port == "b859.9f00.0011"
    assert neighbor.platform == "" and neighbor.capabilities == ""


def test_the_mac_table_as_recorded() -> None:
    macs = parse_mac_table(load_fixture("show_mac_address_table"))
    assert len(macs) == 42
    first = macs[0]
    # Sorted by port, then VLAN; the switch's own address last.
    assert first.port == "Ethernet1/37" and first.vlan == "2"
    assert macs[-1].switch_own and macs[-1].vlan == "" and macs[-1].kind == "static"
    ubiquiti = next(m for m in macs if m.mac == "0c:ea:14:00:00:01")
    assert "Ubiquiti" in ubiquiti.maker and not ubiquiti.local
    private = next(m for m in macs if m.mac == "0a:00:00:00:00:0a")
    assert private.local and private.maker == ""
    assert "VM" in private.maker_text
    assert {m.port for m in macs if m.mac == "b8:59:9f:00:00:0e"} == {"port-channel43"}


def test_arp_port_channels_and_features_as_recorded() -> None:
    (arp,) = parse_arp(load_fixture("show_ip_arp_detail_vrf_all"))
    assert (arp.ip, arp.mac, arp.interface, arp.vrf, arp.age) == (
        "192.0.2.1",
        "60:22:32:00:00:05",
        "mgmt0",
        "management",
        "1m 41s",
    )
    (channel,) = parse_port_channels(load_fixture("show_port_channel_summary"))
    assert channel.name == "port-channel43"
    assert channel.members == ("Ethernet1/43", "Ethernet1/44")
    assert channel.protocol == "LACP" and channel.up
    features = load_fixture("show_feature")
    assert feature_enabled(features, "lacp")
    assert not feature_enabled(features, "lldp")
    assert not feature_enabled(features, "no-such-feature")
    assert cdp_enabled(load_fixture("show_cdp_global"))
    assert not cdp_enabled({"cdp_global_enabled": "disabled"})


def test_empty_tables_give_empty_lists() -> None:
    assert parse_mac_table({}) == []
    assert parse_arp({}) == []
    assert parse_port_channels({}) == []
    assert parse_cdp_neighbors({}) == []
    view = parse_neighbor_view({}, {}, {}, {}, {}, {})
    assert view.neighbors == [] and not view.cdp_enabled and not view.lldp_enabled
    assert view.aging_text == ""


def test_aging_time_in_words() -> None:
    assert _view().aging_text == "An address is forgotten after 30 minutes without traffic."
    assert NeighborView(aging_seconds=60).aging_text.endswith("1 minute without traffic.")
    assert "45 seconds" in NeighborView(aging_seconds=45).aging_text
    assert "aging is off" in NeighborView(aging_seconds=0).aging_text


def test_a_port_channel_member_shows_what_the_channel_learned() -> None:
    view = _view()
    devices = view.for_port("Ethernet1/43")
    assert devices.channel is not None and devices.channel.name == "port-channel43"
    assert {m.mac for m in devices.macs} == {"b8:59:9f:00:00:0e"}
    assert {m.vlan for m in devices.macs} == {"2", "10", "79", "253"}
    assert view.for_port("Ethernet1/44").macs == devices.macs


def test_a_plain_port_shows_its_own_neighbors_and_addresses() -> None:
    view = _view(lldp=True)
    devices = view.for_port("Ethernet1/37")
    assert devices.channel is None
    assert [n.name for n in devices.neighbors] == ["pve-node-1"]
    assert {m.mac for m in devices.macs} == {"0a:00:00:00:00:0d", "b8:59:9f:00:00:0f"}
    assert [n.name for n in view.for_port("Ethernet1/47").neighbors] == ["nexus-lab"]
    empty = view.for_port("Ethernet1/1")
    assert empty.neighbors == [] and empty.macs == []


def test_neighbors_are_listed_in_port_order() -> None:
    view = _view(lldp=True)
    assert [(n.local_port, n.protocol) for n in view.neighbors] == [
        ("Ethernet1/37", "LLDP"),
        ("Ethernet1/40", "LLDP"),
        ("Ethernet1/47", "CDP"),
        ("mgmt0", "CDP"),
    ]


def test_ip_addresses_come_from_the_arp_table() -> None:
    view = _view()
    assert view.ips_of("6022.3200.0005") == ["192.0.2.1"]
    assert view.ips_of("0c:ea:14:00:00:01") == []


def test_searching_the_mac_table() -> None:
    macs = _view().macs
    assert filter_macs(macs, "") == macs
    assert filter_macs(macs, "  ") == macs
    # A VLAN number.
    assert {m.vlan for m in filter_macs(macs, "253")} == {"253"}
    assert len(filter_macs(macs, "253")) == 2
    # Part of a MAC address, in any form.
    for query in ("0cea14", "0c:ea:14", "0CEA.14", "0c-ea-14"):
        assert {m.mac for m in filter_macs(macs, query)} == {
            "0c:ea:14:00:00:01",
            "0c:ea:14:00:00:02",
        }
    # A port, written any way; 1/4 is not 1/43 or 1/47.
    for query in ("Ethernet1/39", "Eth1/39", "1/39", "ethernet1/39"):
        assert {m.port for m in filter_macs(macs, query)} == {"Ethernet1/39"}
    assert filter_macs(macs, "1/4") == []
    assert {m.port for m in filter_macs(macs, "Po43")} == {"port-channel43"}
    # Part of a maker's name.
    assert filter_macs(macs, "ubiquiti") and all(
        "Ubiquiti" in m.maker for m in filter_macs(macs, "ubiquiti")
    )
    assert filter_macs(macs, "no maker is called this") == []


def test_lldp_is_not_asked_for_while_it_is_off() -> None:
    switch = FakeSwitch()
    with _client(switch) as client:
        view = load_neighbors(client)
    assert switch.requests == [list(NEIGHBOR_COMMANDS), [CDP_NEIGHBORS]]
    assert not view.lldp_enabled and view.cdp_enabled
    assert [n.protocol for n in view.neighbors] == ["CDP", "CDP"]


def test_lldp_neighbors_are_read_once_it_is_on() -> None:
    switch = FakeSwitch(lldp=True)
    with _client(switch) as client:
        view = load_neighbors(client)
    assert switch.requests == [list(NEIGHBOR_COMMANDS), [CDP_NEIGHBORS, LLDP_NEIGHBORS]]
    assert view.lldp_enabled
    assert {n.protocol for n in view.neighbors} == {"CDP", "LLDP"}


def test_no_neighbor_request_when_both_protocols_are_off() -> None:
    switch = FakeSwitch(bodies={"show cdp global": {"cdp_global_enabled": "disabled"}})
    with _client(switch) as client:
        view = load_neighbors(client)
    assert switch.requests == [list(NEIGHBOR_COMMANDS)]
    assert view.neighbors == [] and view.macs


def test_a_refused_command_gives_no_view_instead_of_an_error() -> None:
    switch = FakeSwitch(reject={"show mac address-table"})
    with _client(switch) as client:
        assert try_load_neighbors(client) is None
