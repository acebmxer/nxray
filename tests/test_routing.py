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
    static_route_line,
    validate_interface_address,
    validate_ipv6_interface,
    validate_next_hop,
    validate_route_prefix,
    validate_routed_interface,
    validate_vrf_name,
)
from app.port_changes import (
    LAYER3_RULES,
    ROUTE_RULES,
    VLAN_INTERFACE_PERMIT,
    VRF_RULES,
    role_lines,
)
from app.routing import (
    Address,
    L3Interface,
    RoutingView,
    StaticRoute,
    Vrf,
    parse_brief,
    parse_ipv4,
    parse_ipv4_static,
    parse_ipv6,
    parse_ipv6_static,
    parse_vlan_interface,
    parse_vrf_members,
    parse_vrfs,
    plan_add_address,
    plan_add_static_route,
    plan_create_vlan_interface,
    plan_create_vrf,
    plan_delete_vlan_interface,
    plan_delete_vrf,
    plan_interface_vrf,
    plan_remove_address,
    plan_remove_static_route,
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


# ---- VRFs ----------------------------------------------------------------------


def test_vrfs_and_their_interfaces_from_the_recorded_output() -> None:
    members = parse_vrf_members(load_fixture("show_vrf_interface"))
    assert members == {
        "Vlan1": "default",
        "Vlan3900": "default",
        "mgmt0": "management",
        "Ethernet1/54": "tenant-a",
    }
    vrfs = parse_vrfs(load_fixture("show_vrf"), members)
    assert [(v.name, v.up, v.reason, v.kept) for v in vrfs] == [
        ("default", True, "", True),
        ("management", True, "", True),
        ("tenant-a", True, "", False),
    ]
    assert vrfs[0].interfaces == ("Vlan1", "Vlan3900")
    assert vrfs[2].interfaces == ("Ethernet1/54",)
    assert parse_vrfs({}, {}) == [] and parse_vrf_members({}) == {}


def _vrf_view(**kwargs) -> RoutingView:
    return _view(
        vrfs=[
            Vrf("default", interfaces=("Vlan1", "Vlan10")),
            Vrf("management", interfaces=("mgmt0",)),
            Vrf("tenant-a", interfaces=("Ethernet1/54",)),
            Vrf("lab"),
        ],
        **kwargs,
    )


def test_vrf_names() -> None:
    assert validate_vrf_name(" tenant-a ") == "tenant-a"
    assert validate_vrf_name("Lab_2") == "Lab_2"
    for bad in ("default", "Management", "all", "", "-a", "a b", "a;b", "x" * 33):
        with pytest.raises(ValueError):
            validate_vrf_name(bad)
    assert _vrf_view().vrf_choices == ["default", "tenant-a", "lab"]


def test_create_and_delete_a_vrf() -> None:
    name, lines, warnings = plan_create_vrf(_vrf_view(), name="blue")
    assert name == "blue" and lines[0].startswith("Make the VRF blue.") and warnings == []
    with pytest.raises(ValueError, match="has a VRF lab already"):
        plan_create_vrf(_vrf_view(), name="LAB")
    with pytest.raises(ValueError, match="keeps the VRF name"):
        plan_create_vrf(_vrf_view(), name="management")
    assert plan_delete_vrf(_vrf_view(), name="lab")[1] == ["Delete the VRF lab."]
    with pytest.raises(ValueError, match="Ethernet1/54 is in VRF tenant-a; move it"):
        plan_delete_vrf(_vrf_view(), name="tenant-a")
    with pytest.raises(ValueError, match="has no VRF blue"):
        plan_delete_vrf(_vrf_view(), name="blue")
    with pytest.raises(ValueError, match="keeps the VRF name"):
        plan_delete_vrf(_vrf_view(), name="default")


def test_moving_an_interface_names_the_addresses_the_switch_deletes() -> None:
    move, lines, warnings = plan_interface_vrf(_vrf_view(), name="Vlan10", vrf="lab")
    assert (move.name, move.vrf, move.current) == ("Vlan10", "lab", "default")
    assert lines[0] == "Move Vlan10 from VRF default to VRF lab."
    assert len(lines) == 1 and "changes: 192.0.2.1/24, 2001:db8:a::1/64." in warnings[0]
    assert "Add them again afterwards" in warnings[0] and len(warnings) == 2  # it is on
    move, lines, warnings = plan_interface_vrf(_vrf_view(), name="Vlan1", vrf="tenant-a")
    assert move.vrf == "tenant-a" and len(lines) == 1 and warnings == []
    move, _, _ = plan_interface_vrf(_vrf_view(), name="Ethernet1/54", vrf="default")
    assert (move.vrf, move.current) == ("default", "tenant-a")
    with pytest.raises(ValueError, match="in VRF default already"):
        plan_interface_vrf(_vrf_view(), name="Vlan10", vrf="default")
    with pytest.raises(ValueError, match="has no VRF blue; make it first"):
        plan_interface_vrf(_vrf_view(), name="Vlan10", vrf="blue")
    with pytest.raises(ValueError, match="keeps the VRF name"):
        plan_interface_vrf(_vrf_view(), name="Vlan10", vrf="management")
    with pytest.raises(ValueError):
        plan_interface_vrf(_vrf_view(), name="mgmt0", vrf="lab")


def test_a_new_vlan_interface_in_a_vrf() -> None:
    # 192.0.2.1/24 is Vlan10's in default; in VRF lab the same network is free.
    change, lines, _ = plan_create_vlan_interface(
        _vrf_view(), vlan="20", ipv4="192.0.2.5/24", ipv6="", description="", mtu="",
        enabled=True, vrf="lab",
    )  # fmt: skip
    assert change.vrf == "lab" and "VRF: lab." in lines
    # tenant-a has Ethernet1/54's network.
    with pytest.raises(ValueError, match="same network as 198.51.100.1/24 on Ethernet1/54"):
        plan_create_vlan_interface(
            _vrf_view(), vlan="20", ipv4="198.51.100.9/24", ipv6="", description="", mtu="",
            enabled=True, vrf="tenant-a",
        )  # fmt: skip
    change, _, _ = plan_create_vlan_interface(
        _vrf_view(), vlan="20", ipv4="", ipv6="", description="", mtu="", enabled=True
    )
    assert change.vrf is None


def test_vrf_commands() -> None:
    sent: list[list[str]] = []
    with _client(sent) as client:
        client.create_vrf("lab")
        client.delete_vrf("lab")
        client.set_interface_vrf("Vlan10", "lab", current="default")
        client.set_interface_vrf("Ethernet1/54", "default", current="tenant-a")
        client.set_interface_vrf("Ethernet1/54", "lab", current="tenant-a")
        client.configure_vlan_interface(20, vrf="lab", add=[("192.0.2.1/24", False)])
        for bad in (
            lambda: client.create_vrf("management"),
            lambda: client.delete_vrf("default"),
            lambda: client.set_interface_vrf("Vlan10", "default", current="default"),
            lambda: client.set_interface_vrf("mgmt0", "lab", current="management"),
            lambda: client.set_interface_vrf("Vlan10", "a b", current="default"),
        ):
            with pytest.raises(ValueError):
                bad()
    assert sent == [
        ["vrf context lab"],
        ["no vrf context lab"],
        ["interface Vlan10", "vrf member lab"],
        ["interface Ethernet1/54", "no vrf member tenant-a"],
        ["interface Ethernet1/54", "no vrf member tenant-a", "vrf member lab"],
        ["interface vlan20", "vrf member lab", "ip address 192.0.2.1/24"],
    ]


def test_role_has_the_vrf_rules() -> None:
    lines = role_lines(["Ethernet1/1"], "nxray")
    for rule in VRF_RULES:
        assert rule in lines
    # The forms proven on the switch.
    assert "rule 52 permit command conf t ; no vrf context *" in lines
    assert "rule 53 permit command conf t ; interface * ; vrf member *" in lines
    assert lines.index(VRF_RULES[-1]) < lines.index("interface policy deny")


# ---- static routes -----------------------------------------------------------------


def test_static_routes_from_the_recorded_output() -> None:
    assert parse_ipv4_static(load_fixture("show_ip_static_route_vrf_all")) == [
        StaticRoute("tenant-a", "203.0.113.0/24", "198.51.100.254", False),
        StaticRoute("default", "198.51.100.128/25", "192.0.2.254", True),
        StaticRoute("management", "0.0.0.0/0", "203.0.113.254", True),
    ]
    assert parse_ipv6_static(load_fixture("show_ipv6_static_route_vrf_all")) == [
        StaticRoute("tenant-a", "2001:db8:2::/64", "2001:db8:1::fe"),
        StaticRoute("default", "2001:db8:3::/64", "2001:db8:4::fe"),
    ]
    assert parse_ipv4_static({}) == [] and parse_ipv6_static({"TABLE_vrf": []}) == []
    assert StaticRoute("management", "0.0.0.0/0", "203.0.113.254").kept
    assert not StaticRoute("default", "0.0.0.0/0", "192.0.2.254").kept


def test_route_values_are_checked() -> None:
    assert validate_route_prefix(" 203.0.113.0/24 ") == "203.0.113.0/24"
    assert validate_route_prefix("0.0.0.0/0") == "0.0.0.0/0"
    assert validate_route_prefix("2001:DB8:2::/48") == "2001:db8:2::/48"
    with pytest.raises(ValueError, match="did you mean 203.0.113.0/24"):
        validate_route_prefix("203.0.113.5/24")
    for bad in ("203.0.113.0", "224.0.0.0/4", "nonsense/8", "0.0.0.0/8"):
        with pytest.raises(ValueError):
            validate_route_prefix(bad)
    assert validate_next_hop("2001:DB8::FE") == "2001:db8::fe"
    for bad in ("fe80::1", "0.0.0.0", "127.0.0.1", "224.0.0.1", "192.0.2.0/24", "x"):
        with pytest.raises(ValueError):
            validate_next_hop(bad)
    assert static_route_line("2001:db8:2::/48", "2001:db8::fe") == (
        "ipv6 route 2001:db8:2::/48 2001:db8::fe"
    )
    with pytest.raises(ValueError, match="both be IPv4 or both IPv6"):
        static_route_line("203.0.113.0/24", "2001:db8::fe")


def _route_view() -> RoutingView:
    return _vrf_view(
        static_routes=[
            StaticRoute("default", "203.0.113.0/24", "192.0.2.254", True),
            StaticRoute("management", "0.0.0.0/0", "203.0.113.254", True),
            StaticRoute("lab", "198.18.0.0/15", "198.51.100.9", False),
        ]
    )


def test_adding_a_route() -> None:
    change, lines, warnings = plan_add_static_route(
        _route_view(), vrf="default", prefix="0.0.0.0/0", next_hop="192.0.2.254"
    )
    assert (change.vrf, change.prefix, change.next_hop) == ("default", "0.0.0.0/0", "192.0.2.254")
    assert lines == [
        "Add a static route in VRF default: traffic for 0.0.0.0/0 goes to 192.0.2.254."
    ]
    assert len(warnings) == 1 and "default route" in warnings[0]  # 192.0.2.0/24 is Vlan10's
    _, _, warnings = plan_add_static_route(
        _route_view(), vrf="tenant-a", prefix="2001:db8:9::/48", next_hop="2001:db8:a::fe"
    )
    # 2001:db8:a::/64 is on Vlan10, in default, not in tenant-a.
    assert "No interface in VRF tenant-a" in warnings[0]
    with pytest.raises(ValueError, match="has the route 203.0.113.0/24 via 192.0.2.254 already"):
        plan_add_static_route(
            _route_view(), vrf="default", prefix="203.0.113.0/24", next_hop="192.0.2.254"
        )
    with pytest.raises(ValueError, match="keeps the VRF name"):
        plan_add_static_route(
            _route_view(), vrf="management", prefix="198.18.0.0/15", next_hop="203.0.113.1"
        )
    with pytest.raises(ValueError, match="has no VRF blue"):
        plan_add_static_route(
            _route_view(), vrf="blue", prefix="198.18.0.0/15", next_hop="192.0.2.9"
        )
    with pytest.raises(ValueError, match="type the next hop"):
        plan_add_static_route(_route_view(), vrf="default", prefix="198.18.0.0/15", next_hop="")


def test_removing_a_route_and_deleting_a_vrf_that_has_routes() -> None:
    change, lines, warnings = plan_remove_static_route(
        _route_view(), vrf="lab", prefix="198.18.0.0/15", next_hop="198.51.100.9"
    )
    assert change.vrf == "lab" and lines[0].startswith("Remove the static route") and warnings
    with pytest.raises(ValueError, match="has no route"):
        plan_remove_static_route(
            _route_view(), vrf="default", prefix="198.18.0.0/15", next_hop="192.0.2.254"
        )
    with pytest.raises(ValueError, match="keeps the VRF name"):
        plan_remove_static_route(
            _route_view(), vrf="management", prefix="0.0.0.0/0", next_hop="203.0.113.254"
        )
    with pytest.raises(ValueError, match=r"has static routes \(198.18.0.0/15 via 198.51.100.9\)"):
        plan_delete_vrf(_route_view(), name="lab")


def test_route_commands() -> None:
    sent: list[list[str]] = []
    with _client(sent) as client:
        client.set_static_route("default", "0.0.0.0/0", "192.0.2.254", add=True)
        client.set_static_route("lab", "2001:db8:2::/48", "2001:db8::fe", add=True)
        client.set_static_route("lab", "198.18.0.0/15", "198.51.100.9", add=False)
        with pytest.raises(ValueError):
            client.set_static_route("management", "0.0.0.0/0", "203.0.113.1", add=True)
    assert sent == [
        ["ip route 0.0.0.0/0 192.0.2.254"],
        ["vrf context lab", "ipv6 route 2001:db8:2::/48 2001:db8::fe"],
        ["vrf context lab", "no ip route 198.18.0.0/15 198.51.100.9"],
    ]


def test_role_has_the_route_rules() -> None:
    lines = role_lines(["Ethernet1/1"], "nxray")
    for rule in ROUTE_RULES:
        assert rule in lines
    assert "rule 59 permit command conf t ; vrf context * ; ip route *" in lines
    assert lines.index(ROUTE_RULES[-1]) < lines.index("interface policy deny")
