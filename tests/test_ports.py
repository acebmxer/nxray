"""Port parsing, against output recorded from a real switch."""

from __future__ import annotations

from typing import Any

import pytest

from app.ports import (
    COUNTER_LABELS,
    ERROR_COUNTERS,
    human_bytes,
    human_rate,
    parse_ports,
    parse_transceivers,
    port_sort_key,
)
from tests.conftest import load_fixture


def recorded() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    return (
        load_fixture("show_interface"),
        load_fixture("show_interface_status"),
        load_fixture("show_interface_transceiver"),
    )


def with_port(
    name: str,
    interface: dict[str, Any],
    status: dict[str, Any] | None = None,
    transceiver: dict[str, Any] | None = None,
):
    """The recorded output with one port's rows changed."""
    bodies = recorded()
    for body, changes in zip(bodies, (interface, status or {}, transceiver or {}), strict=True):
        for row in body["TABLE_interface"]["ROW_interface"]:
            if row["interface"] == name:
                row.update(changes)
    return bodies


def test_recorded_switch_has_54_ethernet_ports_in_order() -> None:
    ports = parse_ports(*recorded())
    assert len(ports) == 54
    assert ports[0].name == "Ethernet1/1"
    assert ports[9].name == "Ethernet1/10"  # numeric, not text, order
    assert ports[-1].name == "Ethernet1/54"
    assert all(not port.name.startswith("mgmt") for port in ports)


def test_recorded_port_reads_correctly() -> None:
    port = parse_ports(*recorded())[0]
    assert port.up is False and port.admin_up is True
    assert port.state_label == "Down"
    assert port.reason == "XCVR not inserted"
    assert port.speed == "auto"
    assert port.vlan == "1"
    assert port.mode == "access"
    assert port.mtu == "1500"
    assert port.hardware == "1000/10000/25000 Ethernet"
    assert port.last_flap == "never"
    assert port.transceiver.present is False
    assert port.errors == 0
    assert port.description == ""


def test_an_up_port_with_traffic_and_a_transceiver() -> None:
    bodies = with_port(
        "Ethernet1/5",
        {
            "state": "up",
            "state_rsn_desc": "none",
            "eth_speed": "25 Gb/s",
            "desc": "uplink to xcp-host-1",
            "eth_inrate1_bits": "12500000",
            "eth_outrate1_bits": "900",
            "eth_inbytes": "1610612736",
            "eth_inerr": "3",
            "eth_outdiscard": "2",
            "eth_crc": "3",
        },
        {"state": "connected", "vlan": "trunk", "speed": "25G"},
        {
            "sfp": "present",
            "type": "SFP-H25GB-CU1M",
            "name": "CISCO-AMPHENOL",
            "partnum": "NDCCGJ-C402",
            "serialnum": "APF000000",
        },
    )
    port = next(p for p in parse_ports(*bodies) if p.name == "Ethernet1/5")
    assert port.up and port.state_label == "Up" and port.reason == ""
    assert port.speed == "25 Gb/s"
    assert port.vlan == "trunk"
    assert port.description == "uplink to xcp-host-1"
    assert port.transceiver.present
    assert port.transceiver.type == "SFP-H25GB-CU1M"
    assert port.transceiver.vendor == "CISCO-AMPHENOL"
    assert port.in_bits_per_second == 12_500_000
    assert port.in_bytes == 1_610_612_736
    assert port.errors == 5  # 3 input errors + 2 output discards; CRC is inside input errors


def test_a_disabled_port() -> None:
    bodies = with_port(
        "Ethernet1/7", {"admin_state": "down", "state_rsn_desc": "Administratively down"}
    )
    port = next(p for p in parse_ports(*bodies) if p.name == "Ethernet1/7")
    assert port.state_label == "Disabled"
    assert port.reason == "Administratively down"


def test_description_falls_back_to_interface_status() -> None:
    bodies = with_port("Ethernet1/2", {}, {"name": "spare"})
    assert parse_ports(*bodies)[1].description == "spare"


def test_missing_status_and_transceiver_tables() -> None:
    ports = parse_ports(load_fixture("show_interface"), {}, {})
    assert len(ports) == 54
    assert ports[0].vlan == "" and not ports[0].transceiver.present


def test_parse_transceivers_ignores_details_of_an_absent_one() -> None:
    row = {"interface": "Ethernet1/1", "sfp": "not present", "type": "junk"}
    body = {"TABLE_interface": {"ROW_interface": row}}
    assert parse_transceivers(body)["Ethernet1/1"].type == ""


def test_port_sort_key() -> None:
    names = ["Ethernet1/10", "Ethernet1/2", "Ethernet1/2/1", "Ethernet1/1", "weird"]
    assert sorted(names, key=port_sort_key) == [
        "Ethernet1/1",
        "Ethernet1/2",
        "Ethernet1/2/1",
        "Ethernet1/10",
        "weird",
    ]


def test_error_counters_are_shown_on_the_port_page() -> None:
    assert set(ERROR_COUNTERS) <= set(COUNTER_LABELS)


@pytest.mark.parametrize(
    ("count", "text"),
    [(0, "0 B"), (1023, "1023 B"), (1536, "1.5 KB"), (1610612736, "1.5 GB"), (2**60, "1024.0 PB")],
)
def test_human_bytes(count: int, text: str) -> None:
    assert human_bytes(count) == text


@pytest.mark.parametrize(
    ("bits", "text"),
    [
        (0, "0 b/s"),
        (900, "900 b/s"),
        (12_500_000, "12.5 Mb/s"),
        (25 * 10**9, "25.0 Gb/s"),
        (5 * 10**15, "5000.0 Tb/s"),
    ],
)
def test_human_rate(bits: int, text: str) -> None:
    assert human_rate(bits) == text
