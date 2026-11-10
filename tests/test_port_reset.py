"""Resetting a port or a port-channel to its defaults (app/port_reset.py, #21):
the confirm text, the plan for several ports, the client's commands and the role rule.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.nxapi import NxapiClient, SwitchTarget
from app.port_changes import RESET_RULES, ROLE_VERSION, role_lines
from app.port_channels import Channel, Member
from app.port_reset import channel_reset_summary, plan_bulk_reset, port_reset_summary
from app.port_settings import PortSettings
from app.ports import Port, Transceiver
from app.vlans import PortVlans, Vlan, VlanView


def _port(**changes) -> Port:
    values = {
        "name": "Ethernet1/3",
        "description": "",
        "up": False,
        "admin_up": True,
        "reason": "",
        "speed": "auto",
        "vlan": "1",
        "mode": "access",
        "mtu": "1500",
        "hardware": "",
        "mac": "",
        "last_flap": "",
        "transceiver": Transceiver(present=False),
        "in_bits_per_second": 0,
        "out_bits_per_second": 0,
        "in_bytes": 0,
        "out_bytes": 0,
        "in_packets": 0,
        "out_packets": 0,
    }
    values.update(changes)
    return Port(**values)


def _settings(**changes) -> PortSettings:
    values = {
        "name": "Ethernet1/3",
        "speeds": ("1000", "10000", "25000"),
        "speed": "auto",
        "duplex": "full",
        "mtu": 1500,
        "fec": "auto",
        "fec_oper": "",
        "flow_receive": "off",
        "flow_send": "off",
        "storm": {"broadcast": "100.00", "multicast": "100.00", "unicast": "100.00"},
    }
    values.update(changes)
    return PortSettings(**values)


def _vlans(**changes) -> PortVlans:
    values = {"name": "Ethernet1/3", "switchport": True, "mode": "access", "access_vlan": 1}
    values["native_vlan"] = values.get("native_vlan", values["access_vlan"])
    values.update(changes)
    return PortVlans(**values)


# ---- port_reset_summary -----------------------------------------------------


def test_a_plain_port_has_nothing_to_remove() -> None:
    line, warnings = port_reset_summary(_port(), _settings(), _vlans())
    assert line == (
        "Ethernet1/3: nothing to remove; it is already a plain, unconfigured access port."
    )
    assert warnings == []


def test_lists_everything_a_reset_removes() -> None:
    port = _port(description="storage-server")
    settings = _settings(
        speed="10000",
        mtu=9216,
        fec="rs-fec",
        flow_receive="on",
        storm={"broadcast": "10.00", "multicast": "100.00", "unicast": "100.00"},
        storm_action="shutdown",
    )
    vlans = _vlans(mode="trunk", native_vlan=1, allowed=frozenset({1, 10, 20}))
    line, warnings = port_reset_summary(port, settings, vlans)
    assert line == (
        'Ethernet1/3 loses its description, "storage-server"; its trunk (native VLAN 1, '
        "carrying 1,10,20); its speed, set to 10000; its MTU, set to 9216; its FEC, set to "
        "rs-fec; its flow control (receive on, send off); its storm control (broadcast "
        "10.00%, multicast none, unicast none, action shutdown)."
    )
    assert warnings == []


def test_access_vlan_1_is_not_listed_but_another_one_is() -> None:
    line, _ = port_reset_summary(_port(), _settings(), _vlans(access_vlan=1))
    assert "access VLAN" not in line
    line, _ = port_reset_summary(_port(), _settings(), _vlans(access_vlan=10))
    assert line == "Ethernet1/3 loses its access VLAN, 10."


def test_routed_port_names_its_ip_address() -> None:
    settings = _settings(routed=True, routed_capable=True, ip_address="192.0.2.1/24")
    line, _ = port_reset_summary(_port(), settings, None)
    assert line == ("Ethernet1/3 loses its routed (layer 3) setting and IPv4 address 192.0.2.1/24.")
    line, _ = port_reset_summary(_port(), _settings(routed=True), None)
    assert line == "Ethernet1/3 loses its routed (layer 3) setting."


def test_a_down_port_has_no_warning_but_an_up_one_does() -> None:
    _, warnings = port_reset_summary(_port(up=False), _settings(), _vlans())
    assert warnings == []
    _, warnings = port_reset_summary(_port(up=True), _settings(), _vlans())
    assert len(warnings) == 1 and "loses its connection while it resets" in warnings[0]


def test_missing_settings_or_vlans_are_skipped_not_guessed() -> None:
    line, _ = port_reset_summary(_port(description="x"), None, None)
    assert line == 'Ethernet1/3 loses its description, "x".'


# ---- plan_bulk_reset ---------------------------------------------------------


def _view() -> VlanView:
    ports = {
        "Ethernet1/1": _vlans(name="Ethernet1/1"),
        "Ethernet1/2": _vlans(name="Ethernet1/2", access_vlan=10, native_vlan=10),
    }
    return VlanView([Vlan(1, "default", "active"), Vlan(10, "users", "active")], ports)


def test_plan_bulk_reset_keeps_front_panel_order_and_collects_lines() -> None:
    ports = [_port(name="Ethernet1/2"), _port(name="Ethernet1/1")]
    chosen, lines, warnings = plan_bulk_reset(ports, ["Ethernet1/1", "Ethernet1/2"], _view(), {})
    assert [p.name for p in chosen] == ["Ethernet1/2", "Ethernet1/1"]
    assert lines == [
        "Ethernet1/2 loses its access VLAN, 10.",
        "Ethernet1/1: nothing to remove; it is already a plain, unconfigured access port.",
    ]
    assert warnings == []


def test_plan_bulk_reset_needs_at_least_one_name() -> None:
    with pytest.raises(ValueError, match="tick at least one port"):
        plan_bulk_reset([_port()], [], _view(), {})


def test_plan_bulk_reset_refuses_an_unknown_port() -> None:
    with pytest.raises(ValueError, match="no port called Ethernet1/9"):
        plan_bulk_reset([_port()], ["Ethernet1/9"], _view(), {})


def test_plan_bulk_reset_warns_once_per_up_port() -> None:
    ports = [_port(name="Ethernet1/1", up=True), _port(name="Ethernet1/2", up=True)]
    _, _, warnings = plan_bulk_reset(ports, ["Ethernet1/1", "Ethernet1/2"], None, {})
    assert len(warnings) == 2


# ---- channel_reset_summary ---------------------------------------------------


def _channel(**changes) -> Channel:
    values = {
        "number": 43,
        "protocol": "LACP",
        "up": True,
        "routed": False,
        "description": "",
        "members": (),
    }
    values.update(changes)
    return Channel(**values)


def test_empty_channel_has_nothing_to_remove() -> None:
    line, warnings = channel_reset_summary(_channel(up=False))
    assert line == "port-channel43: nothing to remove; it already has none of its own settings."
    assert warnings == []


def test_channel_with_a_description_and_members_warns() -> None:
    members = (Member("Ethernet1/43", "P", "active"), Member("Ethernet1/44", "P", "active"))
    channel = _channel(description="storage-server", members=members)
    line, warnings = channel_reset_summary(channel)
    assert line == 'port-channel43 loses its description, "storage-server".'
    assert any("Ethernet1/43, Ethernet1/44" in w and "stays in the" in w for w in warnings)
    assert any("may be interrupted while it resets" in w for w in warnings)


# ---- NxapiClient.reset_ports / reset_port_channel ----------------------------


def _recording() -> tuple[list[list[str]], NxapiClient]:
    sent: list[list[str]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        entries = json.loads(request.content)
        sent.append([entry["params"]["cmd"] for entry in entries])
        replies = [{"jsonrpc": "2.0", "result": None, "id": entry["id"]} for entry in entries]
        return httpx.Response(200, json=replies[0] if len(replies) == 1 else replies)

    target = SwitchTarget("192.0.2.10", 443, "nxray", "pw", 5.0)
    return sent, NxapiClient(target, transport=httpx.MockTransport(handle))


def test_reset_ports_sends_one_command_per_port() -> None:
    sent, client = _recording()
    with client:
        client.reset_ports(["Ethernet1/1", "Ethernet1/2"])
    assert sent == [["default interface Ethernet1/1", "default interface Ethernet1/2"]]


def test_reset_port_channel_sends_one_command() -> None:
    sent, client = _recording()
    with client:
        client.reset_port_channel(43)
    assert sent == [["default interface port-channel43"]]


def test_reset_ports_refuses_before_sending() -> None:
    sent, client = _recording()
    with client, pytest.raises(ValueError):
        client.reset_ports([])
    with client, pytest.raises(ValueError):
        client.reset_ports(["mgmt0"])
    assert sent == []


def test_reset_port_channel_refuses_a_bad_number() -> None:
    sent, client = _recording()
    with client, pytest.raises(ValueError):
        client.reset_port_channel(0)
    assert sent == []


# ---- the role -----------------------------------------------------------------


def test_role_has_the_reset_rule() -> None:
    lines = role_lines(["Ethernet1/1"], "nxray")
    for rule in RESET_RULES:
        assert rule in lines
    assert ROLE_VERSION == 20
    description = next(line for line in lines if line.startswith("description "))
    assert len(description.removeprefix("description ")) <= 128
