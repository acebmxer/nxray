"""Layer 3 parsing and planning (app/routing.py) against output recorded on
cisco-25gb, and the client methods that build the VLAN interface and address
commands."""

from __future__ import annotations

import httpx
import pytest

from app.nxapi import (
    NxapiClient,
    SwitchTarget,
    address_line,
    validate_interface_address,
    validate_ipv6_interface,
    validate_routed_interface,
)
from app.port_changes import LAYER3_RULES, VLAN_INTERFACE_PERMIT, role_lines
from app.routing import (
    Address,
    L3Interface,
    RoutingView,
    parse_brief,
    parse_ipv4,
    parse_ipv6,
    parse_vlan_interface,
    plan_add_address,
    plan_create_vlan_interface,
    plan_delete_vlan_interface,
    plan_remove_address,
    plan_vlan_interface_settings,
)
from app.vlans import Vlan, vlan_interface_ids
from tests.conftest import load_fixture

# ---- reading -----------------------------------------------------------------


def test_brief_lists_vlan_interfaces_and_routed_ports() -> None:
    svis, routed = parse_brief(load_fixture("show_interface_brief_l3"))
    assert svis == ["Vlan1", "Vlan3900"]
    assert [row["interface"] for row in routed] == ["Ethernet1/54"]
    assert vlan_interface_ids(load_fixture("show_interface_brief_l3")) == {1, 3900}
    # The recorded brief from before VLAN interfaces existed has none.
    assert vlan_interface_ids(load_fixture("show_interface_brief")) == frozenset()


def test_ipv4_reads_primary_secondary_and_vrf() -> None:
    found = parse_ipv4(load_fixture("show_ip_interface_vrf_all_l3"))
    vrf, addresses, _ = found["Vlan3900"]
    assert (vrf, addresses) == ("default", [Address("192.0.2.1/24")])
    vrf, addresses, _ = found["Ethernet1/54"]
    assert vrf == "tenant-a"
    assert addresses == [Address("198.51.100.1/24"), Address("198.51.100.2/24", secondary=True)]
    assert found["mgmt0"][0] == "management"


def test_ipv6_reads_addresses_and_link_local() -> None:
    found = parse_ipv6(load_fixture("show_ipv6_interface_vrf_all"))
    assert found["Vlan3900"] == (
        "default",
        [Address("2001:db8:5::1/64")],
        "fe80::7279:b3ff:fe00:1",
    )
    assert found["Ethernet1/54"][1] == [Address("2001:db8:1::1/64")]
    assert parse_ipv6({}) == {}


def test_vlan_interface_from_its_own_show() -> None:
    ipv4 = parse_ipv4(load_fixture("show_ip_interface_vrf_all_l3"))
    ipv6 = parse_ipv6(load_fixture("show_ipv6_interface_vrf_all"))
    svi = parse_vlan_interface("Vlan3900", load_fixture("show_interface_vlan"), ipv4, ipv6, {})
    assert (svi.vlan, svi.kind, svi.admin_up, svi.up, svi.mtu) == (3900, "vlan", True, True, 9000)
    assert svi.description == "probe"
    assert [a.text for a in svi.addresses] == ["192.0.2.1/24", "2001:db8:5::1/64"]
    assert svi.primary == Address("192.0.2.1/24") and svi.secondaries == []


# ---- planning ----------------------------------------------------------------


def _view(**kwargs) -> RoutingView:
    defaults = {
        "interface_vlan_on": True,
        "vlans": [Vlan(1, "default", "active"), Vlan(10, "Servers", "active"),
                  Vlan(20, "Lab", "active")],
        "vlan_interfaces": [
            L3Interface("Vlan1", admin_up=False),
            L3Interface(
                "Vlan10", admin_up=True, up=True, mtu=1500,
                addresses=(Address("192.0.2.1/24"), Address("2001:db8:a::1/64")),
            ),
        ],
        "routed_ports": [
            L3Interface(
                "Ethernet1/54", vrf="tenant-a",
                addresses=(Address("198.51.100.1/24"), Address("198.51.100.2/24", True)),
            )
        ],
    }  # fmt: skip
    defaults.update(kwargs)
    return RoutingView(**defaults)


def test_create_needs_the_feature_and_an_existing_vlan_without_one() -> None:
    with pytest.raises(ValueError, match="interface-vlan on the Features page"):
        plan_create_vlan_interface(
            _view(interface_vlan_on=False), vlan="20", ipv4="", ipv6="", description="",
            mtu="", enabled=True,
        )  # fmt: skip
    with pytest.raises(ValueError, match="create it on the VLANs page"):
        plan_create_vlan_interface(
            _view(), vlan="30", ipv4="", ipv6="", description="", mtu="", enabled=True
        )
    with pytest.raises(ValueError, match="has a VLAN interface already"):
        plan_create_vlan_interface(
            _view(), vlan="10", ipv4="", ipv6="", description="", mtu="", enabled=True
        )


def test_only_vlans_up_to_254_can_get_a_vlan_interface() -> None:
    """Issue #11: the role names Vlan1-254 only, one line each on the switch."""
    view = _view(vlans=[Vlan(1, "default", "active"), Vlan(254, "a", "active"),
                        Vlan(300, "b", "active")])  # fmt: skip
    assert [v.id for v in view.free_vlans] == [254]
    with pytest.raises(ValueError, match="VLANs 1 to 254 only"):
        plan_create_vlan_interface(
            view, vlan="300", ipv4="", ipv6="", description="", mtu="", enabled=True
        )
    with pytest.raises(ValueError, match="change Vlan300 on the switch itself"):
        plan_add_address(view, name="Vlan300", address="203.0.113.1/24")
    assert VLAN_INTERFACE_PERMIT == "permit interface Vlan1-254"


def test_create_with_both_addresses() -> None:
    change, lines, warnings = plan_create_vlan_interface(
        _view(), vlan="20", ipv4="203.0.113.129/25", ipv6="2001:db8:14::1/64",
        description="lab gateway", mtu="9000", enabled=True,
    )  # fmt: skip
    assert change.vlan == 20 and change.enabled is True and change.mtu == 9000
    assert change.add == (("203.0.113.129/25", False), ("2001:db8:14::1/64", False))
    assert lines[0] == "Make a VLAN interface for VLAN 20 (Vlan20)."
    assert "routes between VLAN 20" in warnings[0]


def test_create_refuses_a_network_another_interface_has_in_the_vrf() -> None:
    with pytest.raises(ValueError, match="same network as 192.0.2.1/24 on Vlan10"):
        plan_create_vlan_interface(
            _view(), vlan="20", ipv4="192.0.2.5/24", ipv6="", description="", mtu="",
            enabled=True,
        )  # fmt: skip
    # Ethernet1/54's network is in another VRF, so it does not count.
    change, _, _ = plan_create_vlan_interface(
        _view(), vlan="20", ipv4="198.51.100.9/24", ipv6="", description="", mtu="",
        enabled=False,
    )  # fmt: skip
    assert change.enabled is None and change.add == (("198.51.100.9/24", False),)


def test_settings_sends_only_what_differs() -> None:
    change, lines, _ = plan_vlan_interface_settings(
        _view(), vlan="10", ipv4="192.0.2.1/24", description="core", mtu="1500", enabled=True
    )
    assert (change.description, change.mtu, change.enabled, change.add) == ("core", None, None, ())
    with pytest.raises(ValueError, match="nothing to change"):
        plan_vlan_interface_settings(
            _view(), vlan="10", ipv4="192.0.2.1/24", description="", mtu="", enabled=True
        )
    change, lines, warnings = plan_vlan_interface_settings(
        _view(), vlan="10", ipv4="192.0.2.65/26", description="", mtu="", enabled=False
    )
    assert change.remove == (("192.0.2.1/24", False),)
    assert change.add == (("192.0.2.65/26", False),) and change.enabled is False
    assert "IPv4 address: 192.0.2.1/24 → 192.0.2.65/26." in lines and warnings


def test_delete_keeps_vlan_1_and_names_the_addresses() -> None:
    with pytest.raises(ValueError, match="keeps the VLAN 1 interface"):
        plan_delete_vlan_interface(_view(), vlan="1")
    number, lines, warnings = plan_delete_vlan_interface(_view(), vlan="10")
    assert number == 10 and "192.0.2.1/24, 2001:db8:a::1/64" in lines[1] and warnings


def test_adding_ipv4_becomes_secondary_when_there_is_a_primary() -> None:
    change, _, _ = plan_add_address(_view(), name="Vlan10", address="203.0.113.1/24")
    assert change.add == (("203.0.113.1/24", True),)
    # An extra address may share the main one's network, as the switch takes it.
    change, _, _ = plan_add_address(_view(), name="Vlan10", address="192.0.2.2/24")
    assert change.add == (("192.0.2.2/24", True),)
    change, _, _ = plan_add_address(_view(), name="Vlan1", address="203.0.113.1/24")
    assert change.add == (("203.0.113.1/24", False),)
    change, _, _ = plan_add_address(_view(), name="Ethernet1/54", address="2001:db8:9::1/64")
    assert change.add == (("2001:db8:9::1/64", False),)
    with pytest.raises(ValueError, match="has 192.0.2.1/24 already"):
        plan_add_address(_view(), name="Vlan10", address="192.0.2.1/24")
    with pytest.raises(ValueError, match="address box of Vlan10 was empty"):
        plan_add_address(_view(), name="Vlan10", address="  ")
    with pytest.raises(ValueError, match="not a VLAN interface or routed port"):
        plan_add_address(_view(), name="Ethernet1/3", address="203.0.113.1/24")
    with pytest.raises(ValueError):
        plan_add_address(_view(), name="mgmt0", address="203.0.113.1/24")


def test_removing_the_main_ipv4_waits_for_the_extra_ones() -> None:
    with pytest.raises(ValueError, match="remove its extra IPv4 addresses first"):
        plan_remove_address(_view(), name="Ethernet1/54", address="198.51.100.1/24")
    change, _, _ = plan_remove_address(_view(), name="Ethernet1/54", address="198.51.100.2/24")
    assert change.remove == (("198.51.100.2/24", True),)


# ---- checked values and commands -----------------------------------------------


def test_address_checks() -> None:
    assert validate_ipv6_interface(" 2001:DB8::1/64 ") == "2001:db8::1/64"
    for bad in ("2001:db8::1", "fe80::1/64", "ff02::1/64", "::1/128", "::/0", "nonsense"):
        with pytest.raises(ValueError):
            validate_ipv6_interface(bad)
    assert validate_interface_address("192.0.2.1/24") == "192.0.2.1/24"
    assert address_line("192.0.2.1/24", True) == "ip address 192.0.2.1/24 secondary"
    assert address_line("2001:db8::1/64") == "ipv6 address 2001:db8::1/64"
    with pytest.raises(ValueError):
        address_line("2001:db8::1/64", True)
    assert validate_routed_interface("vlan10") == "Vlan10"
    assert validate_routed_interface("port-channel5") == "port-channel5"
    for bad in ("mgmt0", "Vlan0", "Vlan4095", "loopback0", "Ethernet1/1 ; reload"):
        with pytest.raises(ValueError):
            validate_routed_interface(bad)


def _client(sent: list[list[str]]) -> NxapiClient:
    def handle(request: httpx.Request) -> httpx.Response:
        import json

        entries = json.loads(request.content)
        sent.append([e["params"]["cmd"] for e in entries])
        reply = [{"jsonrpc": "2.0", "result": None, "id": e["id"]} for e in entries]
        return httpx.Response(200, json=reply[0] if len(reply) == 1 else reply)

    target = SwitchTarget("192.0.2.10", 443, "nxray", "pw", 5.0)
    return NxapiClient(target, transport=httpx.MockTransport(handle))


def test_vlan_interface_commands_in_order() -> None:
    sent: list[list[str]] = []
    with _client(sent) as client:
        client.configure_vlan_interface(
            20, description="lab", mtu=9000, enabled=True,
            remove=[("192.0.2.1/24", False)], add=[("192.0.2.65/26", False)],
        )  # fmt: skip
        client.delete_vlan_interface(20)
        client.set_interface_addresses(
            "Ethernet1/54", remove=[("198.51.100.2/24", True)], add=[("2001:db8::1/64", False)]
        )
        with pytest.raises(ValueError):
            client.delete_vlan_interface(1)
        with pytest.raises(ValueError):
            client.configure_vlan_interface(20)
        with pytest.raises(ValueError):
            client.set_interface_addresses("mgmt0", add=[("192.0.2.5/24", False)])
    assert sent == [
        [
            "interface vlan20",
            "no ip address 192.0.2.1/24",
            "ip address 192.0.2.65/26",
            "description lab",
            "mtu 9000",
            "no shutdown",
        ],
        ["no interface vlan20"],
        [
            "interface Ethernet1/54",
            "no ip address 198.51.100.2/24 secondary",
            "ipv6 address 2001:db8::1/64",
        ],
    ]


def test_role_names_the_vlan_interfaces_and_has_the_layer3_rules() -> None:
    lines = role_lines(["Ethernet1/1"], "nxray")
    for rule in LAYER3_RULES:
        assert rule in lines
    # The delete rule as proven on the switch: other spellings never matched.
    assert "rule 50 permit command conf t ; no interface Vlan *" in lines
    policy = lines.index("interface policy deny")
    assert lines.index(VLAN_INTERFACE_PERMIT) > policy
