"""EIGRP, RIP and IS-IS (app/protocols_igp.py): parsing output recorded on
cisco-25gb (NX-OS 9.3(16)), and the exact lines every setting builds.

Fixtures ending in ``_doc`` are hand-made: nothing was plugged into the probe
port, so the switch never showed a neighbor or an EIGRP interface. They are
shaped after Cisco's documented NX-API field names for the same commands, not
recorded.
"""

from __future__ import annotations

import pytest

from app.protocols import Protocol, build_change
from app.protocols_igp import EIGRP, ISIS, PROTOCOLS, RIP, parse_eigrp, parse_isis, parse_rip
from tests.conftest import load_fixture

# ---- reading -----------------------------------------------------------------


def _eigrp(interfaces: str = "", neighbors: str = "") -> list[dict]:
    return [
        load_fixture("show_ip_eigrp_vrf_all"),
        load_fixture(interfaces or "show_ip_eigrp_interfaces_vrf_all"),
        load_fixture(neighbors or "show_ip_eigrp_neighbors_vrf_all"),
        load_fixture("show_ipv6_eigrp_vrf_all"),
        load_fixture("show_ipv6_eigrp_interfaces_vrf_all"),
    ]


def _rip(neighbors: str = "") -> list[dict]:
    return [
        load_fixture("show_ip_rip_vrf_all"),
        load_fixture("show_ip_rip_interface_vrf_all"),
        load_fixture(neighbors or "show_ip_rip_neighbor_vrf_all"),
        load_fixture("show_ipv6_rip_vrf_all"),
        load_fixture("show_ipv6_rip_interface_vrf_all"),
    ]


def _isis(adjacency: str = "") -> list[dict]:
    return [
        load_fixture("show_isis_vrf_all"),
        load_fixture("show_isis_interface_vrf_all"),
        load_fixture(adjacency or "show_isis_adjacency_vrf_all"),
    ]


def test_protocols_are_eigrp_rip_and_isis() -> None:
    assert [p.key for p in PROTOCOLS] == ["eigrp", "rip", "isis"]
    assert [p.features for p in PROTOCOLS] == [("eigrp",), ("rip",), ("isis",)]
    assert EIGRP.commands[0] == "show ip eigrp vrf all"
    assert len(EIGRP.commands) == 5 and len(RIP.commands) == 5 and len(ISIS.commands) == 3
    for protocol in PROTOCOLS:
        assert [s.key for s in protocol.scopes] == ["process", "vrf", "af", "interface"]


def test_eigrp_process_from_recorded_output() -> None:
    view = parse_eigrp(_eigrp())
    [process] = view.of("process")
    assert process.ident == {"tag": "nxprobe"}
    assert process.title == "EIGRP nxprobe"
    assert process.values["autonomous_system"] == {"asn": "100"}
    assert process.values["router_id"] == {"router_id": "192.0.2.1"}
    assert process.values["maximum_paths"] == {"paths": "4"}
    assert process.values["distance"] == {"internal": "90", "external": "170"}
    assert process.values["redistribute"] == {"source": "static", "route_map": "nxprobe-rm"}
    assert process.values["metric_weights"] == {
        "k1": "1",
        "k2": "0",
        "k3": "1",
        "k4": "0",
        "k5": "0",
        "k6": "",
    }
    assert process.values["timers_active"] == {"minutes": "3"}
    assert process.values["nsf_converge"] == {"seconds": "120"}
    assert process.values["graceful_restart"] == {}
    assert "bfd" not in process.values
    assert "authentication_key_chain" not in process.values
    facts = dict(process.facts)
    assert facts["AS"] == "100"
    assert facts["Redistributes"] == "static (route-map nxprobe-rm)"
    assert facts["Passive interfaces"] == "1"
    assert view.of("vrf") == []


def test_eigrp_ipv6_address_family_from_recorded_output() -> None:
    [af] = parse_eigrp(_eigrp()).of("af")
    assert af.ident == {"tag": "nxprobe", "vrf": "", "af": "ipv6"}
    assert af.title == "EIGRP nxprobe, IPv6"
    assert "autonomous_system" not in af.values  # the IPv6 family has no AS of its own yet
    assert af.values["maximum_paths"] == {"paths": "8"}
    assert af.values["redistribute"] == {"source": "static", "route_map": "nxprobe-rm"}
    assert dict(af.facts)["AS"] == "not set"


def test_eigrp_with_nothing_plugged_in_has_empty_tables() -> None:
    view = parse_eigrp(_eigrp())
    neighbors, interfaces = view.tables
    assert neighbors.rows == () and interfaces.rows == ()
    assert view.of("interface") == []


def test_eigrp_neighbors_and_interfaces_shaped_after_cisco_docs() -> None:
    view = parse_eigrp(
        _eigrp(
            interfaces="show_ip_eigrp_interfaces_vrf_all_doc",
            neighbors="show_ip_eigrp_neighbors_vrf_all_doc",
        )
    )
    neighbors, interfaces = view.tables
    assert neighbors.rows == (
        ("nxprobe", "default", "192.0.2.2", "Ethernet1/54", "13", "46m 49s", "6", "0"),
        ("nxprobe", "default", "192.0.2.3", "Vlan10", "11", "1d 2h 3m 4s", "7", "0"),
        ("AS 200", "lab", "198.51.100.2", "Ethernet1/53", "14", "10s", "1", "0"),
    )
    assert interfaces.rows == (
        ("IPv4", "nxprobe", "default", "Ethernet1/54", "1", "6", "0"),
        ("IPv4", "nxprobe", "default", "Vlan10", "1", "7", "0"),
    )
    by_name = {i.ident["interface"]: i for i in view.of("interface")}
    assert set(by_name) == {"Ethernet1/54", "Vlan10"}
    assert by_name["Vlan10"].values == {"ip_router": {"tag": "nxprobe"}}


def test_eigrp_parser_survives_empty_replies() -> None:
    view = parse_eigrp([{}, {}, {}, {}, {}])
    assert view.instances == ()
    assert parse_eigrp([]).instances == ()


def test_rip_processes_and_families_from_recorded_output() -> None:
    view = parse_rip(_rip())
    [process] = view.of("process")
    assert process.ident == {"tag": "nxprobe"}  # shown by the switch as "rip-nxprobe"
    assert view.of("vrf") == []
    ipv4, ipv6 = view.of("af")
    assert ipv4.ident == {"tag": "nxprobe", "vrf": "", "af": "ipv4"}
    assert ipv4.values["maximum_paths"] == {"paths": "4"}
    assert ipv4.values["distance"] == {"distance": "120"}
    assert ipv4.values["default_metric"] == {"metric": "1"}
    assert ipv4.values["default_information"] == {"always": "", "route_map": ""}
    assert ipv4.values["redistribute"] == {"source": "static", "route_map": "nxprobe-rm"}
    facts = dict(ipv4.facts)
    assert facts["Timers"] == "update 30 s, invalid 180 s, flush 240 s"
    assert facts["Default route"] == "sent"
    assert facts["Interfaces"] == "Ethernet1/54"
    assert ipv6.ident == {"tag": "nxprobe", "vrf": "", "af": "ipv6"}
    assert ipv6.values["maximum_paths"] == {"paths": "16"}
    assert "default_information" not in ipv6.values


def test_rip_interface_settings_from_recorded_output() -> None:
    view = parse_rip(_rip())
    [interface] = view.of("interface")
    assert interface.ident == {"interface": "Ethernet1/54"}
    assert interface.values == {
        "ip_router": {"tag": "nxprobe"},
        "passive": {},
        "metric_offset": {"offset": "2"},
        "auth_mode": {"mode": "md5"},
        "auth_key_chain": {"key_chain": "nxprobe-kc"},
        "ip_router6": {"tag": "nxprobe"},
        "passive6": {},
        "metric_offset6": {"offset": "1"},
    }
    neighbors, interfaces = view.tables
    assert neighbors.rows == ()
    assert interfaces.rows == (
        (
            "IPv4",
            "nxprobe",
            "default",
            "Ethernet1/54",
            "protocol-down/link-down/admin-up",
            "yes",
            "2",
            "no",
            "md5, key chain nxprobe-kc",
        ),
        (
            "IPv6",
            "nxprobe",
            "default",
            "Ethernet1/54",
            "protocol-down/link-down/admin-up",
            "yes",
            "1",
            "no",
            "none",
        ),
    )


def test_rip_neighbors_shaped_after_cisco_docs() -> None:
    neighbors, _ = parse_rip(_rip(neighbors="show_ip_rip_neighbor_vrf_all_doc")).tables
    assert neighbors.rows == (("nxprobe", "default", "192.0.2.2", "Ethernet1/54", "0", "0"),)


def test_isis_process_from_recorded_output() -> None:
    view = parse_isis(_isis())
    [process] = view.of("process")
    assert process.ident == {"tag": "nxprobe"}
    assert process.values["net"] == {"net": "49.0001.1920.0000.2001.00"}
    assert process.values["is_type"] == {"is_type": "level-2"}
    assert process.values["lsp_mtu"] == {"mtu": "1492"}
    assert process.values["graceful_restart"] == {}
    assert process.values["auth_type_l2"] == {"auth_type": "md5"}
    assert process.values["auth_key_chain_l2"] == {"key_chain": "nxprobe-kc"}
    assert process.values["auth_check_l1"] == {} and process.values["auth_check_l2"] == {}
    assert "auth_type_l1" not in process.values
    facts = dict(process.facts)
    assert facts["System ID"] == "1920.0000.2001"
    assert facts["Authentication"] == "level 1: none; level 2: md5, key chain nxprobe-kc"
    assert facts["Interfaces"] == "Ethernet1/54"
    assert [i.ident for i in view.of("af")] == [
        {"tag": "nxprobe", "vrf": "", "af": "ipv4"},
        {"tag": "nxprobe", "vrf": "", "af": "ipv6"},
    ]
    assert dict(view.of("af")[0].facts) == {"BFD": "off"}


def test_isis_interface_from_recorded_output() -> None:
    view = parse_isis(_isis())
    [interface] = view.of("interface")
    assert interface.ident == {"interface": "Ethernet1/54"}
    assert interface.values == {
        "circuit_type": {"circuit_type": "level-2"},
        "passive": {"level": "level-1-2"},
        "network_p2p": {},
        "metric_l1": {"metric": "1"},
        "metric_l2": {"metric": "20"},
        "hello_interval": {"seconds": "5", "level": ""},
        "hello_multiplier": {"multiplier": "3", "level": ""},
        "lsp_interval": {"ms": "33"},
        "retransmit_interval": {"seconds": "5"},
    }
    adjacencies, interfaces = view.tables
    assert adjacencies.rows == ()
    assert interfaces.rows == (
        (
            "nxprobe",
            "default",
            "Ethernet1/54",
            "Down",
            "level-2",
            "point-to-point",
            "level-1-2",
            "1",
            "20",
        ),
    )


def test_isis_adjacencies_shaped_after_cisco_docs() -> None:
    adjacencies, _ = parse_isis(_isis(adjacency="show_isis_adjacency_vrf_all_doc")).tables
    assert adjacencies.rows == (
        (
            "nxprobe",
            "default",
            "nexus-peer",
            "1920.0000.2002",
            "Ethernet1/54",
            "2",
            "UP",
            "00:00:25",
        ),
        (
            "nxprobe",
            "default",
            "1920.0000.2003",
            "1920.0000.2003",
            "Vlan10",
            "1-2",
            "INIT",
            "00:00:08",
        ),
    )


@pytest.mark.parametrize(
    ("protocol", "bodies"),
    [
        (EIGRP, _eigrp("show_ip_eigrp_interfaces_vrf_all_doc")),
        (RIP, _rip()),
        (ISIS, _isis()),
    ],
)
def test_every_prefilled_value_sends_back_as_a_valid_line(
    protocol: Protocol, bodies: list[dict]
) -> None:
    """What the page prefills from the switch's output passes the same checks."""
    view = protocol.parse(bodies)
    assert view.instances
    for instance in view.instances:
        scope = protocol.scope(instance.scope)
        assert scope is not None
        for key, values in instance.values.items():
            setting = scope.setting(key)
            assert setting is not None, (instance.scope, key)
            assert set(values) == {f.name for f in setting.fields}, key
            change = build_change(protocol, scope.key, key, "set", instance.ident, values)
            assert change.lines


# ---- changing: every setting builds its exact line ---------------------------

IDENT = {
    "process": {"tag": "core"},
    "vrf": {"tag": "core", "vrf": "lab"},
    "af": {"tag": "core", "vrf": "", "af": "ipv6"},
    "interface": {"interface": "Vlan10"},
}

ENTER = {
    protocol.key: {
        "process": (f"router {protocol.key} core",),
        "vrf": (f"router {protocol.key} core", "vrf lab"),
        "af": (f"router {protocol.key} core", "address-family ipv6 unicast"),
        "interface": ("interface Vlan10",),
    }
    for protocol in PROTOCOLS
}

_ROUTER = ("process", "vrf", "af")


def _both(key: str, values: dict[str, str], line: str) -> list[tuple]:
    """An interface setting and its IPv6 twin ("ip ..." -> "ipv6 ...")."""
    return [
        ("interface", key, values, line),
        ("interface", key + "6", values, "ipv6 " + line[3:]),
    ]


_REDISTRIBUTION = [
    (
        "redistribute",
        {"source": "static", "route_map": "rm-static"},
        "redistribute static route-map rm-static",
    ),
    (
        "redistribute_protocol",
        {"protocol": "bgp", "source_tag": "65001", "route_map": "rm-bgp"},
        "redistribute bgp 65001 route-map rm-bgp",
    ),
]

_EIGRP_ROUTER_CASES = [
    *_REDISTRIBUTION,
    ("autonomous_system", {"asn": "100"}, "autonomous-system 100"),
    ("router_id", {"router_id": "192.0.2.1"}, "router-id 192.0.2.1"),
    (
        "redistribute_limit",
        {"maximum": "1000", "threshold": "75", "limit_action": "warning-only"},
        "redistribute maximum-prefix 1000 75 warning-only",
    ),
    (
        "default_information",
        {"always": "on", "route_map": "rm-default"},
        "default-information originate always route-map rm-default",
    ),
    (
        "default_metric",
        {"bandwidth": "100000", "delay": "100", "reliability": "255", "load": "1", "mtu": "1492"},
        "default-metric 100000 100 255 1 1492",
    ),
    ("distance", {"internal": "90", "external": "170"}, "distance 90 170"),
    ("maximum_paths", {"paths": "8"}, "maximum-paths 8"),
    (
        "metric_weights",
        {"k1": "1", "k2": "0", "k3": "1", "k4": "0", "k5": "0"},
        "metric weights 0 1 0 1 0 0",
    ),
    ("metric_max_hops", {"hops": "100"}, "metric maximum-hops 100"),
    ("metric_version", {}, "metric version 64bit"),
    ("metric_rib_scale", {"scale": "128"}, "metric rib-scale 128"),
    ("stub", {"stub_routes": "connected summary"}, "stub connected summary"),
    ("timers_active", {"minutes": "3"}, "timers active-time 3"),
    ("timers_active_disabled", {}, "timers active-time disabled"),
    ("nsf_converge", {"seconds": "120"}, "timers nsf converge 120"),
    ("nsf_route_hold", {"seconds": "240"}, "timers nsf route-hold 240"),
    ("nsf_signal", {"seconds": "20"}, "timers nsf signal 20"),
    ("authentication_key_chain", {"key_chain": "keys"}, "authentication key-chain keys"),
    ("authentication_mode", {}, "authentication mode md5"),
    ("graceful_restart", {}, "graceful-restart"),
    ("nsf_await", {}, "nsf await-redist-proto-convergence"),
    ("bfd", {}, "bfd"),
    ("log_neighbor_changes", {}, "log-neighbor-changes"),
    ("log_neighbor_warnings", {"seconds": "10"}, "log-neighbor-warnings 10"),
    ("shutdown", {}, "shutdown"),
]

_EIGRP_CASES = [
    *[(scope, *case) for scope in _ROUTER for case in _EIGRP_ROUTER_CASES],
    *_both("ip_router", {"tag": "core"}, "ip router eigrp core"),
    *_both("passive", {"tag": "core"}, "ip passive-interface eigrp core"),
    *_both("hello_interval", {"tag": "core", "seconds": "10"}, "ip hello-interval eigrp core 10"),
    *_both("hold_time", {"tag": "core", "seconds": "30"}, "ip hold-time eigrp core 30"),
    *_both("authentication_mode", {"tag": "core"}, "ip authentication mode eigrp core md5"),
    *_both(
        "authentication_key_chain",
        {"tag": "core", "key_chain": "keys"},
        "ip authentication key-chain eigrp core keys",
    ),
    (
        "interface",
        "summary",
        {"tag": "core", "prefix": "192.0.2.0/23", "distance": "10"},
        "ip summary-address eigrp core 192.0.2.0/23 10",
    ),
    (
        "interface",
        "summary6",
        {"tag": "core", "prefix": "2001:db8::/48"},
        "ipv6 summary-address eigrp core 2001:db8::/48",
    ),
    *_both(
        "distribute_list",
        {"tag": "core", "list_kind": "route-map", "list_name": "rm-in", "direction": "in"},
        "ip distribute-list eigrp core route-map rm-in in",
    ),
    *_both("bandwidth", {"tag": "core", "kbps": "10000000"}, "ip bandwidth eigrp core 10000000"),
    *_both("delay", {"tag": "core", "delay": "10"}, "ip delay eigrp core 10"),
    *_both(
        "bandwidth_percent", {"tag": "core", "percent": "50"}, "ip bandwidth-percent eigrp core 50"
    ),
    *_both("split_horizon", {"tag": "core"}, "ip split-horizon eigrp core"),
    *_both("next_hop_self", {"tag": "core"}, "ip next-hop-self eigrp core"),
]

_RIP_CASES = [
    ("process", "metric_direct_zero", {}, "metric direct 0"),
    ("process", "shutdown", {}, "shutdown"),
    ("vrf", "shutdown", {}, "shutdown"),
    *[("af", *case) for case in _REDISTRIBUTION],
    ("af", "default_information", {}, "default-information originate"),
    ("af", "default_metric", {"metric": "2"}, "default-metric 2"),
    ("af", "distance", {"distance": "120"}, "distance 120"),
    ("af", "maximum_paths", {"paths": "16"}, "maximum-paths 16"),
    (
        "af",
        "timers",
        {"update": "30", "invalid": "180", "holddown": "180", "garbage": "240"},
        "timers basic 30 180 180 240",
    ),
    *_both("ip_router", {"tag": "core"}, "ip router rip core"),
    *_both("passive", {}, "ip rip passive-interface"),
    ("interface", "auth_mode", {"mode": "md5"}, "ip rip authentication mode md5"),
    ("interface", "auth_key_chain", {"key_chain": "keys"}, "ip rip authentication key-chain keys"),
    *_both("metric_offset", {"offset": "2"}, "ip rip metric-offset 2"),
    *_both("poison_reverse", {}, "ip rip poison-reverse"),
    ("interface", "summary", {"prefix": "192.0.2.0/23"}, "ip rip summary-address 192.0.2.0/23"),
    (
        "interface",
        "summary6",
        {"prefix": "2001:db8::/48"},
        "ipv6 rip summary-address 2001:db8::/48",
    ),
    *_both(
        "route_filter",
        {"list_kind": "prefix-list", "list_name": "pl-in", "direction": "in"},
        "ip rip route-filter prefix-list pl-in in",
    ),
]

_ISIS_ROUTER_CASES = [
    *_REDISTRIBUTION,
    ("net", {"net": "49.0001.1920.0000.2001.00"}, "net 49.0001.1920.0000.2001.00"),
    ("is_type", {"is_type": "level-2"}, "is-type level-2"),
    ("hostname_dynamic", {}, "hostname dynamic"),
    ("auth_type_l1", {"auth_type": "md5"}, "authentication-type md5 level-1"),
    ("auth_type_l2", {"auth_type": "cleartext"}, "authentication-type cleartext level-2"),
    ("auth_key_chain_l1", {"key_chain": "keys"}, "authentication key-chain keys level-1"),
    ("auth_key_chain_l2", {"key_chain": "keys"}, "authentication key-chain keys level-2"),
    ("auth_check_l1", {}, "authentication-check level-1"),
    ("auth_check_l2", {}, "authentication-check level-2"),
    ("distance", {"distance": "115"}, "distance 115"),
    ("maximum_paths", {"paths": "8"}, "maximum-paths 8"),
    ("default_information", {"always": "yes"}, "default-information originate always"),
    ("redistribute_limit", {"maximum": "500"}, "redistribute maximum-prefix 500"),
    (
        "reference_bandwidth",
        {"bandwidth": "100", "unit": "Gbps"},
        "reference-bandwidth 100 Gbps",
    ),
    (
        "overload_always",
        {"suppress": "external"},
        "set-overload-bit always suppress external",
    ),
    ("overload_startup", {"seconds": "300"}, "set-overload-bit on-startup 300"),
    ("overload_bgp", {"asn": "65001"}, "set-overload-bit on-startup wait-for bgp 65001"),
    ("attached_bit", {}, "set-attached-bit"),
    (
        "lsp_gen_interval",
        {"level": "level-1", "max_wait": "500", "initial_wait": "50", "second_wait": "50"},
        "lsp-gen-interval level-1 500 50 50",
    ),
    ("spf_interval", {"level": "level-2", "max_wait": "1000"}, "spf-interval level-2 1000"),
    ("lsp_mtu", {"mtu": "1492"}, "lsp-mtu 1492"),
    ("max_lsp_lifetime", {"seconds": "1200"}, "max-lsp-lifetime 1200"),
    ("graceful_restart", {}, "graceful-restart"),
    ("graceful_restart_t3", {"seconds": "60"}, "graceful-restart t3 manual 60"),
    ("bfd", {}, "bfd"),
    ("log_adjacency_changes", {}, "log-adjacency-changes"),
    ("shutdown", {}, "shutdown"),
]

_ISIS_CASES = [
    *[(scope, *case) for scope in ("process", "vrf") for case in _ISIS_ROUTER_CASES],
    *[("af", *case) for case in _REDISTRIBUTION],
    (
        "af",
        "redistribute_limit",
        {"maximum": "500", "limit_action": "withdraw"},
        "redistribute maximum-prefix 500 withdraw",
    ),
    (
        "af",
        "default_information",
        {"route_map": "rm-default"},
        "default-information originate route-map rm-default",
    ),
    (
        "af",
        "summary",
        {"prefix": "2001:db8::/48", "level": "level-1-2"},
        "summary-address 2001:db8::/48 level-1-2",
    ),
    (
        "af",
        "distribute_all",
        {"from_level": "level-1", "to_level": "level-2"},
        "distribute level-1 into level-2 all",
    ),
    (
        "af",
        "distribute_route_map",
        {"from_level": "level-2", "to_level": "level-1", "route_map": "rm-leak"},
        "distribute level-2 into level-1 route-map rm-leak",
    ),
    ("af", "distance", {"distance": "115"}, "distance 115"),
    ("af", "maximum_paths", {"paths": "8"}, "maximum-paths 8"),
    ("af", "adjacency_check", {}, "adjacency-check"),
    ("af", "bfd", {}, "bfd"),
    ("interface", "ip_router", {"tag": "core"}, "ip router isis core"),
    ("interface", "ip_router6", {"tag": "core"}, "ipv6 router isis core"),
    ("interface", "circuit_type", {"circuit_type": "level-2"}, "isis circuit-type level-2"),
    ("interface", "passive", {"level": "level-1-2"}, "isis passive-interface level-1-2"),
    ("interface", "network_p2p", {}, "isis network point-to-point"),
    ("interface", "metric_l1", {"metric": "20"}, "isis metric 20 level-1"),
    ("interface", "metric_l2", {"metric": "20"}, "isis metric 20 level-2"),
    ("interface", "metric6_l1", {"metric": "30"}, "isis ipv6 metric 30 level-1"),
    ("interface", "metric6_l2", {"metric": "30"}, "isis ipv6 metric 30 level-2"),
    ("interface", "priority", {"priority": "70", "level": "level-2"}, "isis priority 70 level-2"),
    (
        "interface",
        "hello_interval",
        {"seconds": "5", "level": "level-2"},
        "isis hello-interval 5 level-2",
    ),
    ("interface", "hello_multiplier", {"multiplier": "3"}, "isis hello-multiplier 3"),
    (
        "interface",
        "csnp_interval",
        {"seconds": "10", "level": "level-1"},
        "isis csnp-interval 10 level-1",
    ),
    ("interface", "lsp_interval", {"ms": "33"}, "isis lsp-interval 33"),
    ("interface", "retransmit_interval", {"seconds": "5"}, "isis retransmit-interval 5"),
    ("interface", "hello_padding", {}, "isis hello-padding"),
    (
        "interface",
        "auth_type",
        {"auth_type": "md5", "level": "level-2"},
        "isis authentication-type md5 level-2",
    ),
    ("interface", "auth_key_chain", {"key_chain": "keys"}, "isis authentication key-chain keys"),
    ("interface", "auth_check", {"level": "level-1"}, "isis authentication-check level-1"),
    ("interface", "mesh_group", {"mesh_id": "1"}, "isis mesh-group 1"),
    ("interface", "mesh_blocked", {}, "isis mesh-group blocked"),
    ("interface", "bfd", {}, "isis bfd"),
    ("interface", "bfd6", {}, "isis ipv6 bfd"),
    ("interface", "shutdown", {}, "isis shutdown"),
]

CASES = [
    *[(EIGRP, *case) for case in _EIGRP_CASES],
    *[(RIP, *case) for case in _RIP_CASES],
    *[(ISIS, *case) for case in _ISIS_CASES],
]


def test_every_setting_has_a_case() -> None:
    covered = {(p.key, scope, setting) for p, scope, setting, _, _ in CASES}
    every = {
        (p.key, scope.key, setting.key)
        for p in PROTOCOLS
        for scope in p.scopes
        for setting in scope.settings
    }
    assert every - covered == set()
    assert covered - every == set()


@pytest.mark.parametrize(
    ("protocol", "scope", "setting", "values", "line"),
    CASES,
    ids=[f"{p.key}-{scope}-{setting}" for p, scope, setting, _, _ in CASES],
)
def test_setting_builds_its_line_and_its_no_form(
    protocol: Protocol, scope: str, setting: str, values: dict[str, str], line: str
) -> None:
    enter = ENTER[protocol.key][scope]
    change = build_change(protocol, scope, setting, "set", IDENT[scope], values)
    assert change.lines == (*enter, line)
    removed = build_change(protocol, scope, setting, "remove", IDENT[scope], values)
    assert removed.lines == (*enter, "no " + line)


@pytest.mark.parametrize("protocol", PROTOCOLS, ids=[p.key for p in PROTOCOLS])
def test_making_and_deleting_a_process(protocol: Protocol) -> None:
    router = f"router {protocol.key} core"
    made = build_change(protocol, "process", "", "create", {"tag": "core"}, {})
    assert made.lines == (router,)
    deleted = build_change(protocol, "process", "", "delete", {"tag": "core"}, {})
    assert deleted.lines == ("no " + router,)
    assert deleted.warning


@pytest.mark.parametrize("protocol", PROTOCOLS, ids=[p.key for p in PROTOCOLS])
def test_making_and_deleting_a_vrf_part(protocol: Protocol) -> None:
    router = f"router {protocol.key} core"
    ident = {"tag": "core", "vrf": "lab"}
    assert build_change(protocol, "vrf", "", "create", ident, {}).lines == (router, "vrf lab")
    assert build_change(protocol, "vrf", "", "delete", ident, {}).lines == (router, "no vrf lab")


@pytest.mark.parametrize("protocol", PROTOCOLS, ids=[p.key for p in PROTOCOLS])
def test_making_and_deleting_an_address_family(protocol: Protocol) -> None:
    router = f"router {protocol.key} core"
    in_vrf = {"tag": "core", "vrf": "lab", "af": "ipv4"}
    assert build_change(protocol, "af", "", "create", in_vrf, {}).lines == (
        router,
        "vrf lab",
        "address-family ipv4 unicast",
    )
    default = {"tag": "core", "vrf": "default", "af": "ipv6"}
    assert build_change(protocol, "af", "", "delete", default, {}).lines == (
        router,
        "no address-family ipv6 unicast",
    )


@pytest.mark.parametrize("protocol", PROTOCOLS, ids=[p.key for p in PROTOCOLS])
def test_interfaces_are_not_made_or_deleted_here(protocol: Protocol) -> None:
    for action in ("create", "delete"):
        with pytest.raises(ValueError, match="not"):
            build_change(protocol, "interface", "", action, {"interface": "Vlan10"}, {})


# ---- refusals -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("protocol", "scope", "ident", "setting", "values", "message"),
    [
        # wrong address family
        (
            EIGRP,
            "interface",
            IDENT["interface"],
            "summary",
            {"tag": "core", "prefix": "2001:db8::/48"},
            "IPv4",
        ),
        (
            EIGRP,
            "interface",
            IDENT["interface"],
            "summary6",
            {"tag": "core", "prefix": "192.0.2.0/24"},
            "IPv6",
        ),
        (RIP, "interface", IDENT["interface"], "summary", {"prefix": "2001:db8::/48"}, "IPv4"),
        (EIGRP, "process", IDENT["process"], "router_id", {"router_id": "2001:db8::1"}, "IPv4"),
        (
            ISIS,
            "af",
            IDENT["af"],
            "summary",
            {"prefix": "192.0.2.1/24", "level": "level-1"},
            "did you mean",
        ),
        # out of range
        (
            EIGRP,
            "interface",
            IDENT["interface"],
            "hello_interval",
            {"tag": "core", "seconds": "0"},
            "1 to 65535",
        ),
        (EIGRP, "process", IDENT["process"], "autonomous_system", {"asn": "65536"}, "65535"),
        (EIGRP, "process", IDENT["process"], "maximum_paths", {"paths": "33"}, "1 to 32"),
        (RIP, "interface", IDENT["interface"], "metric_offset", {"offset": "16"}, "1 to 15"),
        (
            RIP,
            "af",
            IDENT["af"],
            "timers",
            {"update": "4", "invalid": "180", "holddown": "180", "garbage": "240"},
            "from 5",
        ),
        (
            ISIS,
            "interface",
            IDENT["interface"],
            "priority",
            {"priority": "128", "level": "level-1"},
            "0 to 127",
        ),
        (ISIS, "process", IDENT["process"], "overload_startup", {"seconds": "4"}, "5 to 86400"),
        (ISIS, "process", IDENT["process"], "lsp_mtu", {"mtu": "4353"}, "128 to 4352"),
        (ISIS, "interface", IDENT["interface"], "passive", {"level": "level-3"}, "one of"),
        (ISIS, "process", IDENT["process"], "net", {"net": "49.0001.1920.0000.2001"}, "NET"),
        # ";" in a name
        (
            EIGRP,
            "process",
            IDENT["process"],
            "redistribute",
            {"source": "static", "route_map": "rm;reload"},
            ";",
        ),
        (RIP, "interface", IDENT["interface"], "ip_router", {"tag": "core;reload"}, ";"),
        (ISIS, "interface", IDENT["interface"], "auth_key_chain", {"key_chain": "a;b"}, ";"),
        # the management VRF and interface
        (EIGRP, "vrf", {"tag": "core", "vrf": "management"}, "shutdown", {}, "management"),
        (
            RIP,
            "af",
            {"tag": "core", "vrf": "management", "af": "ipv4"},
            "distance",
            {"distance": "120"},
            "management",
        ),
        (ISIS, "interface", {"interface": "mgmt0"}, "shutdown", {}, "Interface"),
        (ISIS, "interface", {"interface": "Vlan300"}, "shutdown", {}, "254"),
        # a process name the switch would split
        (ISIS, "process", {"tag": "core 2"}, "shutdown", {}, "Process"),
    ],
)
def test_bad_values_are_refused(
    protocol: Protocol,
    scope: str,
    ident: dict[str, str],
    setting: str,
    values: dict[str, str],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        build_change(protocol, scope, setting, "set", ident, values)


def test_deleting_a_vrf_part_of_the_management_vrf_is_refused() -> None:
    with pytest.raises(ValueError, match="management"):
        build_change(EIGRP, "vrf", "", "delete", {"tag": "core", "vrf": "management"}, {})


def test_an_unknown_setting_is_refused() -> None:
    with pytest.raises(ValueError, match="no setting"):
        build_change(RIP, "interface", "ip_router7", "set", IDENT["interface"], {"tag": "x"})
