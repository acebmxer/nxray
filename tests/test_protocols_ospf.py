"""OSPF and OSPFv3 (app/protocols_ospf.py): parsing output recorded on
cisco-25gb (NX-OS 9.3(16)) and the exact lines every setting builds.

The two neighbor fixtures (``*_neighbors_vrf_all_doc.json``) are hand-made,
shaped after Cisco's NX-API reference for those commands, not recorded: the
probe switch had nothing plugged in, so it had no neighbors.
"""

from __future__ import annotations

import pytest

from app.protocols import Protocol, build_change
from app.protocols_ospf import OSPF, OSPFV3, PROTOCOLS, parse_ospf, parse_ospfv3
from tests.conftest import load_fixture


def _ospf_bodies() -> list[dict]:
    return [
        load_fixture("show_ip_ospf_vrf_all"),
        load_fixture("show_ip_ospf_interface_vrf_all"),
        load_fixture("show_ip_ospf_neighbors_vrf_all_doc"),
        load_fixture("show_ip_ospf_summary-address_vrf_all"),
    ]


def _ospfv3_bodies() -> list[dict]:
    return [
        load_fixture("show_ospfv3_vrf_all"),
        load_fixture("show_ospfv3_interface_vrf_all"),
        load_fixture("show_ospfv3_neighbors_vrf_all_doc"),
    ]


def _table(view, title: str):
    return next(t for t in view.tables if t.title == title)


# ---- the protocols --------------------------------------------------------------


def test_protocols_are_ospf_and_ospfv3() -> None:
    assert [p.key for p in PROTOCOLS] == ["ospf", "ospfv3"]
    assert OSPF.features == ("ospf",)
    assert OSPFV3.features == ("ospfv3",)
    assert OSPF.commands == (
        "show ip ospf vrf all",
        "show ip ospf interface vrf all",
        "show ip ospf neighbors vrf all",
        "show ip ospf summary-address vrf all",
    )
    assert OSPFV3.commands == (
        "show ospfv3 vrf all",
        "show ospfv3 interface vrf all",
        "show ospfv3 neighbors vrf all",
    )
    assert OSPF.parse is parse_ospf
    assert OSPFV3.parse is parse_ospfv3
    assert [s.key for s in OSPF.scopes] == ["process", "vrf", "interface"]
    assert [s.key for s in OSPFV3.scopes] == ["process", "vrf", "af", "interface"]


# ---- reading OSPF ---------------------------------------------------------------


def test_ospf_process_from_recorded_output() -> None:
    view = parse_ospf(_ospf_bodies())
    [process] = view.of("process")
    assert process.ident == {"tag": "nxprobe"}
    assert process.title == "nxprobe"
    facts = dict(process.facts)
    assert facts["Router ID"] == "192.0.2.1"
    assert facts["VRF"] == "default"
    assert facts["State"] == "0 of 3 areas active"
    assert facts["Areas"] == "0.0.0.0 (backbone), 0.0.0.1 (stub), 0.0.0.2 (NSSA)"
    assert facts["Reference bandwidth"] == "100000 Mbps"
    assert facts["SPF timers"] == "start 0s, hold 1s, max 5s"
    assert facts["Redistributes"] == "static, direct"
    assert facts["Role"] == "AS boundary router (brings in outside routes)"
    assert facts["Graceful restart"] == "on (planned restarts only), grace period 60s"
    assert process.values == {
        "router_id": {"router_id": "192.0.2.1"},
        "auto_cost": {"bandwidth": "100", "unit": "Gbps"},
        "passive_default": {},
        "graceful_restart": {"planned_only": "planned-only"},
        "grace_period": {"grace": "60"},
        "distance": {"distance": "115"},
        "maximum_paths": {"paths": "4"},
    }


def test_ospf_vrf_part_from_recorded_output() -> None:
    view = parse_ospf(_ospf_bodies())
    [part] = view.of("vrf")
    assert part.ident == {"tag": "nxprobe", "vrf": "nxprobe-v"}
    assert part.title == "nxprobe, VRF nxprobe-v"
    assert dict(part.facts)["Areas"] == "0.0.0.3 (stub)"
    assert part.values["router_id"] == {"router_id": "192.0.2.2"}
    assert part.values["auto_cost"] == {"bandwidth": "40", "unit": "Gbps"}
    assert part.values["maximum_paths"] == {"paths": "8"}
    assert part.values["distance"] == {"distance": "110"}
    assert "passive_default" not in part.values


def test_ospf_interface_from_recorded_output() -> None:
    view = parse_ospf(_ospf_bodies())
    [interface] = view.of("interface")
    assert interface.ident == {"interface": "Ethernet1/54"}
    assert interface.values == {
        "router": {"process": "nxprobe", "area": "0.0.0.0", "secondaries": ""},
        "cost": {"cost": "10"},
        "network": {"network": "point-to-point"},
        "passive": {},
    }
    assert _table(view, "Interfaces").rows == (
        ("Ethernet1/54", "nxprobe", "default", "0.0.0.0", "10", "down", "point-to-point", "yes"),
    )


def test_ospf_areas_and_summaries_tables() -> None:
    view = parse_ospf(_ospf_bodies())
    assert _table(view, "Areas").rows == (
        ("nxprobe", "default", "0.0.0.0", "backbone", "MD5", "1", "192.0.2.0/24"),
        ("nxprobe", "default", "0.0.0.1", "stub", "none", "0", "-"),
        ("nxprobe", "default", "0.0.0.2", "NSSA", "none", "0", "-"),
        ("nxprobe", "nxprobe-v", "0.0.0.3", "stub", "none", "0", "-"),
    )
    assert _table(view, "Summary addresses").rows == (
        ("nxprobe", "default", "203.0.113.0/24", "waiting for routes"),
    )


def test_ospf_neighbors_shaped_after_cisco_documentation() -> None:
    # Hand-made fixture (see the module docstring): never seen live.
    view = parse_ospf(_ospf_bodies())
    assert _table(view, "Neighbors").rows == (
        (
            "192.0.2.2",
            "192.0.2.2",
            "Ethernet1/54",
            "FULL/BDR",
            "7d 11h 59m 45s",
            "default",
            "nxprobe",
        ),
        ("198.51.100.2", "198.51.100.2", "Vlan20", "FULL", "30s", "default", "nxprobe"),
        (
            "203.0.113.2",
            "203.0.113.2",
            "Ethernet1/53",
            "INIT/DROTHER",
            "1h 2m",
            "nxprobe-v",
            "nxprobe",
        ),
    )


def test_ospf_no_neighbors_reads_as_an_empty_table() -> None:
    # The switch answers "result": null when there are none; the client makes it {}.
    bodies = _ospf_bodies()
    bodies[2] = {}
    view = parse_ospf(bodies)
    assert _table(view, "Neighbors").rows == ()


def test_ospf_without_a_process_says_so() -> None:
    view = parse_ospf([{}, {}, {}, {}])
    assert view.instances == ()
    assert view.notes == ("No OSPF process yet. Make one below.",)
    assert parse_ospf([]).instances == ()


def test_area_types_with_options() -> None:
    body = {
        "TABLE_ctx": {
            "ROW_ctx": {
                "ptag": "1",
                "cname": "default",
                "TABLE_area": {
                    "ROW_area": [
                        {"aname": "0.0.0.4", "stub": "true", "no_summary": "true"},
                        {
                            "aname": "0.0.0.5",
                            "nssa": "true",
                            "no_summary": "true",
                            "no_redist": "true",
                        },
                        {"aname": "0.0.0.6", "stub": "false", "nssa": "false"},
                    ]
                },
            }
        }
    }
    view = parse_ospf([body])
    assert [row[3] for row in _table(view, "Areas").rows] == [
        "stub, no summaries",
        "NSSA, no summaries, no redistribution",
        "normal",
    ]


def test_values_read_from_the_switch_build_valid_lines() -> None:
    """Every value the page prefills passes its own field checks."""
    for protocol, bodies in ((OSPF, _ospf_bodies()), (OSPFV3, _ospfv3_bodies())):
        view = protocol.parse(bodies)
        for instance in view.instances:
            for key, values in instance.values.items():
                change = build_change(protocol, instance.scope, key, "set", instance.ident, values)
                assert change.lines


# ---- reading OSPFv3 ---------------------------------------------------------------


def test_ospfv3_process_and_address_family_from_recorded_output() -> None:
    view = parse_ospfv3(_ospfv3_bodies())
    [process] = view.of("process")
    assert process.ident == {"tag": "nxprobe"}
    assert dict(process.facts)["Areas"] == "0.0.0.0 (backbone), 0.0.0.1 (stub)"
    assert dict(process.facts)["Redistributes"] == "static"
    assert process.values == {
        "router_id": {"router_id": "192.0.2.1"},
        "auto_cost": {"bandwidth": "40", "unit": "Gbps"},
        "graceful_restart": {"planned_only": "planned-only"},
        "grace_period": {"grace": "60"},
    }
    [family] = view.of("af")
    assert family.ident == {"tag": "nxprobe", "vrf": "default"}
    assert family.values == {"distance": {"distance": "110"}, "maximum_paths": {"paths": "4"}}
    assert view.of("vrf") == []
    assert _table(view, "Areas").rows[0] == (
        "nxprobe",
        "default",
        "0.0.0.0",
        "backbone",
        "-",
        "1",
        "2001:db8:1::/48",
    )


def test_ospfv3_interface_and_neighbors() -> None:
    view = parse_ospfv3(_ospfv3_bodies())
    [interface] = view.of("interface")
    assert interface.ident == {"interface": "Ethernet1/54"}
    assert interface.values["router"] == {
        "process": "nxprobe",
        "area": "0.0.0.0",
        "secondaries": "",
    }
    assert interface.values["passive"] == {}
    # Hand-made neighbor fixture, shaped after Cisco's documentation.
    assert _table(view, "Neighbors").rows == (
        ("192.0.2.2", "fe80::2", "Ethernet1/54", "FULL/DR", "30s", "default", "nxprobe"),
        ("203.0.113.2", "fe80::3", "Ethernet1/53", "FULL/DR", "18s", "nxprobe-v", "nxprobe"),
    )


def test_ospfv3_without_a_process_says_so() -> None:
    assert parse_ospfv3([{}, {}, {}]).notes == ("No OSPFv3 process yet. Make one below.",)


# ---- building changes: every setting -------------------------------------------------

# key -> (values, the line set sends, the line remove sends)
_ROUTER_COMMON = {
    "router_id": ({"router_id": "192.0.2.1"}, "router-id 192.0.2.1", "no router-id 192.0.2.1"),
    "auto_cost": (
        {"bandwidth": "100", "unit": "Gbps"},
        "auto-cost reference-bandwidth 100 Gbps",
        "no auto-cost reference-bandwidth",
    ),
    "passive_default": ({}, "passive-interface default", "no passive-interface default"),
    "log_adjacency": (
        {"detail": "on"},
        "log-adjacency-changes detail",
        "no log-adjacency-changes",
    ),
    "bfd": ({}, "bfd", "no bfd"),
    "name_lookup": ({}, "name-lookup", "no name-lookup"),
    "shutdown": ({}, "shutdown", "no shutdown"),
    "area_stub": (
        {"area": "1", "no_summary": "on"},
        "area 0.0.0.1 stub no-summary",
        "no area 0.0.0.1 stub",
    ),
    "area_nssa": (
        {"area": "2", "no_summary": "on", "no_redistribution": "on", "originate": "on"},
        "area 0.0.0.2 nssa no-summary no-redistribution default-information-originate",
        "no area 0.0.0.2 nssa",
    ),
    "area_nssa_translate": (
        {"area": "0.0.0.2", "translate": "always"},
        "area 0.0.0.2 nssa translate type7 always",
        "no area 0.0.0.2 nssa translate type7",
    ),
    "area_virtual_link": (
        {"area": "1", "peer": "198.51.100.9"},
        "area 0.0.0.1 virtual-link 198.51.100.9",
        "no area 0.0.0.1 virtual-link 198.51.100.9",
    ),
    "timers_lsa": (
        {"lsa_start": "0", "lsa_hold": "5000", "lsa_max": "5000"},
        "timers throttle lsa 0 5000 5000",
        "no timers throttle lsa 0 5000 5000",
    ),
    "lsa_arrival": ({"arrival": "1000"}, "timers lsa-arrival 1000", "no timers lsa-arrival 1000"),
    "lsa_pacing": (
        {"pacing": "240"},
        "timers lsa-group-pacing 240",
        "no timers lsa-group-pacing 240",
    ),
    "graceful_restart": (
        {"planned_only": "on"},
        "graceful-restart planned-only",
        "no graceful-restart",
    ),
    "grace_period": (
        {"grace": "120"},
        "graceful-restart grace-period 120",
        "no graceful-restart grace-period 120",
    ),
    "helper_disable": ({}, "graceful-restart helper-disable", "no graceful-restart helper-disable"),
    "max_lsa": (
        {"max_lsa": "12000", "lsa_threshold": "80", "lsa_warning": "on"},
        "max-lsa 12000 80 warning-only",
        "no max-lsa 12000 80 warning-only",
    ),
}

# Lines OSPF has at the router level and OSPFv3 in its address family.
_ROUTES = {
    "redistribute_bgp": (
        {"asn": "65001", "route_map": "nxprobe-rm"},
        "redistribute bgp 65001 route-map nxprobe-rm",
        "no redistribute bgp 65001 route-map nxprobe-rm",
    ),
    "redistribute_direct": (
        {"route_map": "nxprobe-rm"},
        "redistribute direct route-map nxprobe-rm",
        "no redistribute direct route-map nxprobe-rm",
    ),
    "redistribute_static": (
        {"route_map": "nxprobe-rm"},
        "redistribute static route-map nxprobe-rm",
        "no redistribute static route-map nxprobe-rm",
    ),
    "redistribute_eigrp": (
        {"source_tag": "100", "route_map": "rm"},
        "redistribute eigrp 100 route-map rm",
        "no redistribute eigrp 100 route-map rm",
    ),
    "redistribute_isis": (
        {"source_tag": "core", "route_map": "rm"},
        "redistribute isis core route-map rm",
        "no redistribute isis core route-map rm",
    ),
    "redistribute_rip": (
        {"source_tag": "edge", "route_map": "rm"},
        "redistribute rip edge route-map rm",
        "no redistribute rip edge route-map rm",
    ),
    "default_information": (
        {"always": "on", "route_map": "rm"},
        "default-information originate always route-map rm",
        "no default-information originate",
    ),
    "default_metric": ({"metric": "25"}, "default-metric 25", "no default-metric 25"),
    "distance": ({"distance": "115"}, "distance 115", "no distance 115"),
    "maximum_paths": ({"paths": "4"}, "maximum-paths 4", "no maximum-paths 4"),
    "table_map": (
        {"route_map": "rm", "filter": "on"},
        "table-map rm filter",
        "no table-map rm filter",
    ),
    "timers_spf": (
        {"spf_start": "200", "spf_hold": "1000", "spf_max": "5000"},
        "timers throttle spf 200 1000 5000",
        "no timers throttle spf 200 1000 5000",
    ),
    "area_default_cost": (
        {"area": "1", "cost": "25"},
        "area 0.0.0.1 default-cost 25",
        "no area 0.0.0.1 default-cost",
    ),
    "area_filter": (
        {"area": "1", "route_map": "rm-in", "direction": "in"},
        "area 0.0.0.1 filter-list route-map rm-in in",
        "no area 0.0.0.1 filter-list route-map rm-in in",
    ),
}

OSPF_ROUTER = {
    **_ROUTER_COMMON,
    **_ROUTES,
    "rfc1583": ({}, "rfc1583compatibility", "no rfc1583compatibility"),
    "area_range": (
        {"area": "0", "prefix": "192.0.2.0/24", "not_advertise": "on", "range_cost": "20"},
        "area 0.0.0.0 range 192.0.2.0/24 not-advertise cost 20",
        "no area 0.0.0.0 range 192.0.2.0/24",
    ),
    "area_authentication": (
        {"area": "0", "message_digest": "on"},
        "area 0.0.0.0 authentication message-digest",
        "no area 0.0.0.0 authentication",
    ),
    "redistribute_ospf": (
        {"source_tag": "edge", "route_map": "rm"},
        "redistribute ospf edge route-map rm",
        "no redistribute ospf edge route-map rm",
    ),
    "redistribute_maximum": (
        {"maximum": "1000", "threshold": "75", "limit_action": "warning-only"},
        "redistribute maximum-prefix 1000 75 warning-only",
        "no redistribute maximum-prefix 1000 75 warning-only",
    ),
    "summary_address": (
        {"prefix": "203.0.113.0/24", "summary_tag": "2"},
        "summary-address 203.0.113.0/24 tag 2",
        "no summary-address 203.0.113.0/24",
    ),
    "summary_hidden": (
        {"prefix": "203.0.113.0/24"},
        "summary-address 203.0.113.0/24 not-advertise",
        "no summary-address 203.0.113.0/24",
    ),
    "max_metric": (
        {"external": "on", "include_stub": "on", "startup": "600", "summary": "on"},
        "max-metric router-lsa external-lsa include-stub on-startup 600 summary-lsa",
        "no max-metric router-lsa",
    ),
}

OSPFV3_ROUTER = {
    **_ROUTER_COMMON,
    "max_metric": (
        {"external": "on", "stub_prefix": "on", "startup": "600", "inter_area": "on"},
        "max-metric router-lsa external-lsa stub-prefix-lsa on-startup 600 inter-area-prefix-lsa",
        "no max-metric router-lsa",
    ),
}

OSPFV3_AF = {
    **_ROUTES,
    "redistribute_ospfv3": (
        {"source_tag": "edge", "route_map": "rm"},
        "redistribute ospfv3 edge route-map rm",
        "no redistribute ospfv3 edge route-map rm",
    ),
    "redistribute_maximum": (
        {"maximum": "1000", "threshold": "75", "limit_action": "withdraw"},
        "redistribute maximum-prefix 1000 75 withdraw",
        "no redistribute maximum-prefix",
    ),
    "area_range": (
        {"area": "0", "prefix": "2001:db8:1::/48"},
        "area 0.0.0.0 range 2001:db8:1::/48",
        "no area 0.0.0.0 range 2001:db8:1::/48",
    ),
    "summary_address": (
        {"prefix": "2001:db8:2::/48"},
        "summary-address 2001:db8:2::/48",
        "no summary-address 2001:db8:2::/48",
    ),
    "summary_hidden": (
        {"prefix": "2001:db8:2::/48"},
        "summary-address 2001:db8:2::/48 not-advertise",
        "no summary-address 2001:db8:2::/48",
    ),
}


def _interface_cases(word: str, join: str) -> dict[str, tuple[dict[str, str], str, str]]:
    return {
        "router": (
            {"process": "core", "area": "0", "secondaries": "on"},
            f"{join} core area 0.0.0.0 secondaries none",
            f"no {join} core area 0.0.0.0",
        ),
        "multi_area": (
            {"process": "core", "area": "3"},
            f"{join} core multi-area 0.0.0.3",
            f"no {join} core multi-area 0.0.0.3",
        ),
        "cost": ({"cost": "10"}, f"{word} cost 10", f"no {word} cost 10"),
        "priority": ({"priority": "5"}, f"{word} priority 5", f"no {word} priority 5"),
        "network": (
            {"network": "point-to-point"},
            f"{word} network point-to-point",
            f"no {word} network",
        ),
        "passive": ({}, f"{word} passive-interface", f"no {word} passive-interface"),
        "mtu_ignore": ({}, f"{word} mtu-ignore", f"no {word} mtu-ignore"),
        "hello": ({"hello": "5"}, f"{word} hello-interval 5", f"no {word} hello-interval 5"),
        "dead": ({"dead": "20"}, f"{word} dead-interval 20", f"no {word} dead-interval 20"),
        "retransmit": (
            {"retransmit": "5"},
            f"{word} retransmit-interval 5",
            f"no {word} retransmit-interval 5",
        ),
        "transmit_delay": (
            {"delay": "1"},
            f"{word} transmit-delay 1",
            f"no {word} transmit-delay 1",
        ),
        "bfd": ({}, f"{word} bfd", f"no {word} bfd"),
        "bfd_disable": ({}, f"{word} bfd disable", f"no {word} bfd disable"),
        "shutdown": ({}, f"{word} shutdown", f"no {word} shutdown"),
    }


OSPF_INTERFACE = {
    **_interface_cases("ip ospf", "ip router ospf"),
    "authentication": (
        {"auth_mode": "message-digest"},
        "ip ospf authentication message-digest",
        "no ip ospf authentication",
    ),
    "key_chain": (
        {"key_chain": "nxprobe-kc"},
        "ip ospf authentication key-chain nxprobe-kc",
        "no ip ospf authentication key-chain nxprobe-kc",
    ),
    "password": (
        {"password": "s3cret!"},
        "ip ospf authentication-key s3cret!",
        "no ip ospf authentication-key",
    ),
    "md5_key": (
        {"key_id": "1", "md5_key": "m5-key"},
        "ip ospf message-digest-key 1 md5 m5-key",
        "no ip ospf message-digest-key 1",
    ),
}

OSPFV3_INTERFACE = {
    **_interface_cases("ospfv3", "ipv6 router ospfv3"),
    "instance": ({"instance": "1"}, "ospfv3 instance 1", "no ospfv3 instance 1"),
}

# (protocol, scope, identity, lines that enter it, cases)
_PLACES = [
    (OSPF, "process", {"tag": "core"}, ["router ospf core"], OSPF_ROUTER),
    (OSPF, "vrf", {"tag": "core", "vrf": "lab"}, ["router ospf core", "vrf lab"], OSPF_ROUTER),
    (OSPF, "interface", {"interface": "Ethernet1/54"}, ["interface Ethernet1/54"], OSPF_INTERFACE),
    (OSPFV3, "process", {"tag": "core"}, ["router ospfv3 core"], OSPFV3_ROUTER),
    (
        OSPFV3,
        "vrf",
        {"tag": "core", "vrf": "lab"},
        ["router ospfv3 core", "vrf lab"],
        OSPFV3_ROUTER,
    ),
    (
        OSPFV3,
        "af",
        {"tag": "core", "vrf": "default"},
        ["router ospfv3 core", "address-family ipv6 unicast"],
        OSPFV3_AF,
    ),
    (
        OSPFV3,
        "af",
        {"tag": "core", "vrf": "lab"},
        ["router ospfv3 core", "vrf lab", "address-family ipv6 unicast"],
        OSPFV3_AF,
    ),
    (OSPFV3, "interface", {"interface": "Vlan10"}, ["interface Vlan10"], OSPFV3_INTERFACE),
]

_CASES = [
    pytest.param(protocol, scope, ident, enter, key, *case, id=f"{protocol.key}-{scope}-{key}")
    for protocol, scope, ident, enter, cases in _PLACES
    for key, case in cases.items()
]


def test_every_setting_has_a_case() -> None:
    for protocol, scope_key, _ident, _enter, cases in _PLACES:
        scope = protocol.scope(scope_key)
        assert scope is not None
        assert sorted(s.key for s in scope.settings) == sorted(cases), (protocol.key, scope_key)


@pytest.mark.parametrize(
    ("protocol", "scope", "ident", "enter", "key", "values", "on", "off"), _CASES
)
def test_setting_lines(
    protocol: Protocol,
    scope: str,
    ident: dict[str, str],
    enter: list[str],
    key: str,
    values: dict[str, str],
    on: str,
    off: str,
) -> None:
    assert build_change(protocol, scope, key, "set", ident, values).lines == (*enter, on)
    assert build_change(protocol, scope, key, "remove", ident, values).lines == (*enter, off)


def test_lines_stay_inside_what_the_role_allows() -> None:
    interface_starts = ("ip router ", "ipv6 router ", "ip ospf ", "ospfv3 ")
    for protocol, scope, ident, _enter, cases in _PLACES:
        for key, (values, _on, _off) in cases.items():
            for action in ("set", "remove"):
                lines = build_change(protocol, scope, key, action, ident, values).lines
                first, last = lines[0], lines[-1].removeprefix("no ")
                if scope == "interface":
                    assert first.startswith("interface ")
                    assert last.startswith(interface_starts), last
                else:
                    assert first.startswith(("router ospf ", "router ospfv3 "))


def test_secrets_are_masked_in_labels() -> None:
    change = build_change(
        OSPF,
        "interface",
        "md5_key",
        "set",
        {"interface": "Vlan10"},
        {"key_id": "3", "md5_key": "topsecret"},
    )
    assert change.lines[-1] == "ip ospf message-digest-key 3 md5 topsecret"
    assert change.labels[-1] == "ip ospf message-digest-key 3 md5 ***"
    assert "topsecret" not in change.describe
    password = build_change(
        OSPF, "interface", "password", "set", {"interface": "Vlan10"}, {"password": "plainpw"}
    )
    assert password.labels[-1] == "ip ospf authentication-key ***"


def test_optional_parts_drop_out() -> None:
    ident = {"tag": "core"}
    assert build_change(OSPF, "process", "area_stub", "set", ident, {"area": "1"}).lines[-1] == (
        "area 0.0.0.1 stub"
    )
    assert build_change(OSPF, "process", "area_nssa", "set", ident, {"area": "2"}).lines[-1] == (
        "area 0.0.0.2 nssa"
    )
    assert build_change(OSPF, "process", "default_information", "set", ident, {}).lines[-1] == (
        "default-information originate"
    )
    assert build_change(OSPF, "process", "max_metric", "set", ident, {}).lines[-1] == (
        "max-metric router-lsa"
    )
    assert (
        build_change(OSPF, "process", "auto_cost", "set", ident, {"bandwidth": "40000"}).lines[-1]
        == "auto-cost reference-bandwidth 40000"
    )
    assert build_change(OSPF, "process", "log_adjacency", "set", ident, {}).lines[-1] == (
        "log-adjacency-changes"
    )
    interface = {"interface": "Vlan10"}
    assert build_change(
        OSPF, "interface", "router", "set", interface, {"process": "1", "area": "0.0.0.0"}
    ).lines == ("interface Vlan10", "ip router ospf 1 area 0.0.0.0")
    assert build_change(OSPF, "interface", "authentication", "set", interface, {}).lines[-1] == (
        "ip ospf authentication"
    )


# ---- making and deleting -------------------------------------------------------------


def test_create_and_delete_processes() -> None:
    for protocol, word in ((OSPF, "ospf"), (OSPFV3, "ospfv3")):
        ident = {"tag": "core"}
        assert build_change(protocol, "process", "", "create", ident, {}).lines == (
            f"router {word} core",
        )
        delete = build_change(protocol, "process", "", "delete", ident, {})
        assert delete.lines == (f"no router {word} core",)
        assert delete.warning
        part = {"tag": "core", "vrf": "lab"}
        assert build_change(protocol, "vrf", "", "create", part, {}).lines == (
            f"router {word} core",
            "vrf lab",
        )
        assert build_change(protocol, "vrf", "", "delete", part, {}).lines == (
            f"router {word} core",
            "no vrf lab",
        )


def test_address_family_and_interfaces_are_not_made_or_deleted_here() -> None:
    with pytest.raises(ValueError):
        build_change(OSPFV3, "af", "", "create", {"tag": "core"}, {})
    with pytest.raises(ValueError):
        build_change(OSPF, "interface", "", "delete", {"interface": "Vlan10"}, {})


# ---- refusals --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("protocol", "scope", "key", "ident", "values"),
    [
        # wrong address family
        (OSPF, "process", "router_id", {"tag": "core"}, {"router_id": "2001:db8::1"}),
        (OSPFV3, "process", "router_id", {"tag": "core"}, {"router_id": "2001:db8::1"}),
        (OSPF, "process", "area_range", {"tag": "core"}, {"area": "0", "prefix": "2001:db8::/32"}),
        (OSPFV3, "af", "area_range", {"tag": "core"}, {"area": "0", "prefix": "192.0.2.0/24"}),
        (OSPF, "process", "summary_address", {"tag": "core"}, {"prefix": "2001:db8::/32"}),
        (OSPFV3, "af", "summary_hidden", {"tag": "core"}, {"prefix": "203.0.113.0/24"}),
        (
            OSPF,
            "process",
            "area_virtual_link",
            {"tag": "core"},
            {"area": "1", "peer": "2001:db8::9"},
        ),
        # not the start of its network
        (OSPF, "process", "area_range", {"tag": "core"}, {"area": "0", "prefix": "192.0.2.1/24"}),
        # out of range
        (OSPF, "process", "distance", {"tag": "core"}, {"distance": "0"}),
        (OSPF, "process", "distance", {"tag": "core"}, {"distance": "256"}),
        (OSPF, "process", "maximum_paths", {"tag": "core"}, {"paths": "17"}),
        (OSPF, "process", "auto_cost", {"tag": "core"}, {"bandwidth": "4000001"}),
        (OSPF, "process", "area_stub", {"tag": "core"}, {"area": "4294967296"}),
        (
            OSPF,
            "process",
            "timers_lsa",
            {"tag": "core"},
            {"lsa_start": "0", "lsa_hold": "10", "lsa_max": "5000"},
        ),
        (OSPF, "process", "grace_period", {"tag": "core"}, {"grace": "4"}),
        (OSPF, "interface", "cost", {"interface": "Vlan10"}, {"cost": "65536"}),
        (OSPF, "interface", "priority", {"interface": "Vlan10"}, {"priority": "256"}),
        (OSPF, "interface", "transmit_delay", {"interface": "Vlan10"}, {"delay": "451"}),
        (OSPF, "interface", "md5_key", {"interface": "Vlan10"}, {"key_id": "0", "md5_key": "k"}),
        (OSPFV3, "interface", "hello", {"interface": "Vlan10"}, {"hello": "0"}),
        (OSPFV3, "interface", "instance", {"interface": "Vlan10"}, {"instance": "256"}),
        # not one of the choices
        (OSPF, "interface", "network", {"interface": "Vlan10"}, {"network": "nbma"}),
        (
            OSPF,
            "process",
            "area_filter",
            {"tag": "core"},
            {"area": "1", "route_map": "rm", "direction": "both"},
        ),
        # ";" or a space in a name or secret
        (OSPF, "process", "redistribute_static", {"tag": "core"}, {"route_map": "rm;reload"}),
        (OSPF, "process", "router_id", {"tag": "core;reload"}, {"router_id": "192.0.2.1"}),
        (OSPF, "interface", "key_chain", {"interface": "Vlan10"}, {"key_chain": "kc 1"}),
        (OSPF, "interface", "password", {"interface": "Vlan10"}, {"password": "a b"}),
        (OSPF, "interface", "md5_key", {"interface": "Vlan10"}, {"key_id": "1", "md5_key": "a;b"}),
        (OSPF, "interface", "router", {"interface": "Vlan10"}, {"process": "a;b", "area": "0"}),
        # missing values
        (OSPF, "process", "redistribute_bgp", {"tag": "core"}, {"route_map": "rm"}),
        (OSPF, "process", "redistribute_bgp", {"tag": "core"}, {"asn": "0", "route_map": "rm"}),
        # interfaces NXray never changes
        (OSPF, "interface", "cost", {"interface": "mgmt0"}, {"cost": "10"}),
        (OSPF, "interface", "cost", {"interface": "Vlan300"}, {"cost": "10"}),
        # the management VRF
        (
            OSPF,
            "vrf",
            "router_id",
            {"tag": "core", "vrf": "management"},
            {"router_id": "192.0.2.1"},
        ),
        (OSPFV3, "af", "distance", {"tag": "core", "vrf": "management"}, {"distance": "110"}),
    ],
)
def test_bad_values_are_refused(
    protocol: Protocol, scope: str, key: str, ident: dict[str, str], values: dict[str, str]
) -> None:
    with pytest.raises(ValueError):
        build_change(protocol, scope, key, "set", ident, values)


def test_management_vrf_cannot_be_made_or_deleted() -> None:
    for protocol in PROTOCOLS:
        for action in ("create", "delete"):
            with pytest.raises(ValueError):
                build_change(protocol, "vrf", "", action, {"tag": "core", "vrf": "management"}, {})


def test_a_vrf_part_needs_a_vrf() -> None:
    with pytest.raises(ValueError):
        build_change(OSPF, "vrf", "", "create", {"tag": "core"}, {})


def test_a_vrf_part_is_never_the_default_vrf() -> None:
    with pytest.raises(ValueError):
        build_change(OSPF, "vrf", "", "delete", {"tag": "core", "vrf": "default"}, {})
