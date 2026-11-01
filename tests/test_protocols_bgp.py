"""BGP (app/protocols_bgp.py): parsing against output recorded on the probe switch
(NX-OS 9.3(16)), and the exact lines every setting sends.

The probe's neighbors never came up (nothing was plugged in). The two
``..._neighbors_doc.json`` fixtures, with an established neighbor in a VRF and
its outbound policy, are hand-made, shaped after Cisco's documentation and the
field names of the idle rows; they were not recorded.
"""

from __future__ import annotations

import pytest

from app.protocols import build_change
from app.protocols_bgp import BGP, PROTOCOLS, parse_bgp
from tests.conftest import load_fixture

ASN = {"asn": "65001"}
IN_VRF = {"asn": "65001", "vrf": "lab"}
AF = {"asn": "65001", "vrf": "default", "af": "ipv4 unicast"}
NEIGHBOR = {"asn": "65001", "vrf": "", "address": "192.0.2.2"}
NEIGHBOR_AF = {**NEIGHBOR, "af": "ipv4 unicast"}

ENTER = {
    "process": ["router bgp 65001"],
    "vrf": ["router bgp 65001", "vrf lab"],
    "af": ["router bgp 65001", "address-family ipv4 unicast"],
    "neighbor": ["router bgp 65001", "neighbor 192.0.2.2"],
    "neighbor_af": ["router bgp 65001", "neighbor 192.0.2.2", "address-family ipv4 unicast"],
}
IDENT = {"process": ASN, "vrf": IN_VRF, "af": AF, "neighbor": NEIGHBOR, "neighbor_af": NEIGHBOR_AF}


def _view():
    return parse_bgp(
        [
            load_fixture("show_bgp_process"),
            load_fixture("show_bgp_all_summary_vrf_all"),
            load_fixture("show_bgp_vrf_all_all_neighbors"),
            load_fixture("show_bgp_sessions_vrf_all"),
            load_fixture("show_bgp_ipv6_unicast_vrf_all"),
        ]
    )


def _table(view, title):
    return next(t for t in view.tables if t.title == title)


# ---- the protocol --------------------------------------------------------------


def test_protocol_reads_in_one_request_with_the_bgp_feature():
    assert PROTOCOLS == (BGP,)
    assert BGP.key == "bgp"
    assert BGP.features == ("bgp",)
    assert BGP.commands == (
        "show bgp process",
        "show bgp all summary vrf all",
        "show bgp vrf all all neighbors",
        "show bgp sessions vrf all",
        "show bgp ipv6 unicast vrf all",
    )
    assert "show ip bgp vrf all" not in BGP.commands  # no JSON on NX-OS 9.3
    assert [s.key for s in BGP.scopes] == ["process", "vrf", "af", "neighbor", "neighbor_af"]


# ---- parsing -------------------------------------------------------------------


def test_process_with_its_facts_and_router_id():
    view = _view()
    (process,) = view.of("process")
    assert process.ident == {"asn": "65001"}
    assert process.title == "BGP AS 65001"
    facts = dict(process.facts)
    assert facts["AS number"] == "65001"
    assert facts["Router ID"] == "192.0.2.1"
    assert facts["State"] == "Running"
    assert facts["Neighbors"] == "0 of 2 established"
    assert facts["VRFs"] == "default, nxprobe-v"
    assert process.values == {"router_id": {"router_id": "192.0.2.1"}}


def test_vrf_part_from_summary_and_sessions():
    view = _view()
    (vrf,) = view.of("vrf")
    assert vrf.ident == {"asn": "65001", "vrf": "nxprobe-v"}
    assert dict(vrf.facts) == {"Router ID": "192.0.2.3", "Neighbors": "0 of 0 established"}
    assert any("VRF nxprobe-v" in note for note in view.notes)


def test_address_families_with_redistribution():
    view = _view()
    afs = {(i.ident["vrf"], i.ident["af"]): i for i in view.of("af")}
    assert set(afs) == {("default", "ipv4 unicast"), ("default", "ipv6 unicast")}
    ipv4 = afs["default", "ipv4 unicast"]
    assert ipv4.ident == {"asn": "65001", "vrf": "default", "af": "ipv4 unicast"}
    assert ipv4.title == "IPv4 unicast in VRF default"
    facts = dict(ipv4.facts)
    assert facts["Networks"] == "1"
    assert facts["Aggregates"] == "1"
    assert facts["Redistributes"] == "static (route-map nxprobe-rm)"
    assert ipv4.values == {"redistribute": {"source": "static", "route_map": "nxprobe-rm"}}
    assert dict(afs["default", "ipv6 unicast"].facts)["Redistributes"] == "nothing"
    assert afs["default", "ipv6 unicast"].values == {}


def test_neighbors_with_their_settings():
    view = _view()
    neighbors = {i.ident["address"]: i for i in view.of("neighbor")}
    assert set(neighbors) == {"192.0.2.2", "2001:db8:1::2"}
    v4 = neighbors["192.0.2.2"]
    assert v4.ident == {"asn": "65001", "vrf": "default", "address": "192.0.2.2"}
    assert v4.title == "Neighbor 192.0.2.2"
    assert v4.values == {
        "remote_as": {"remote_as": "65002"},
        "description": {"description": "probe-peer"},
        "update_source": {"source": "Ethernet1/54"},
        "bfd": {},
    }
    facts = dict(v4.facts)
    assert facts["Remote AS"] == "65002"
    assert facts["Kind"] == "outside (eBGP)"
    assert facts["State"] == "Idle for 11s"
    assert facts["Neighbor's router ID"] == "not known yet"
    assert neighbors["2001:db8:1::2"].values == {"remote_as": {"remote_as": "65002"}}


def test_neighbor_address_families_with_policies():
    view = _view()
    families = {(i.ident["address"], i.ident["af"]): i for i in view.of("neighbor_af")}
    assert set(families) == {("192.0.2.2", "ipv4 unicast"), ("2001:db8:1::2", "ipv6 unicast")}
    v4 = families["192.0.2.2", "ipv4 unicast"]
    assert v4.ident == {
        "asn": "65001",
        "vrf": "default",
        "address": "192.0.2.2",
        "af": "ipv4 unicast",
    }
    assert v4.values == {
        "route_map_in": {"route_map": "nxprobe-rm"},
        "soft_reconfiguration": {"always": ""},
        "send_community": {},
    }
    assert dict(v4.facts) == {"Prefixes received": "0", "Prefixes sent": "0"}
    assert families["2001:db8:1::2", "ipv6 unicast"].values == {}


def test_neighbor_session_and_ipv6_tables():
    view = _view()
    neighbors = _table(view, "Neighbors")
    assert neighbors.rows == (
        ("192.0.2.2", "default", "ipv4 unicast", "65002", "Idle", "11s", ""),
        ("2001:db8:1::2", "default", "ipv6 unicast", "65002", "Idle", "10s", ""),
    )
    sessions = _table(view, "Sessions")
    assert sessions.rows[0] == ("192.0.2.2", "default", "65002", "Idle", "11s", "", "0", "0 / 0")
    assert len(sessions.rows) == 2
    ipv6 = _table(view, "IPv6 BGP table")
    assert ipv6.rows == (
        ("default", "2001:db8:1::/64", "this switch", "", "invalid", "100", "32768", "", "i"),
    )
    assert "IPv4 BGP table" in ipv6.note


def test_established_neighbor_in_a_vrf_doc_shaped():
    # Hand-made after Cisco's documentation: never seen live.
    view = parse_bgp(
        [
            load_fixture("show_bgp_process"),
            load_fixture("show_bgp_all_summary_vrf_all_neighbors_doc"),
            load_fixture("show_bgp_vrf_all_all_neighbors_doc"),
            {},
            {},
        ]
    )
    (neighbor,) = view.of("neighbor")
    assert neighbor.ident == {"asn": "65001", "vrf": "nxprobe-v", "address": "198.51.100.2"}
    assert neighbor.title == "Neighbor 198.51.100.2 in VRF nxprobe-v"
    assert neighbor.values == {
        "remote_as": {"remote_as": "65010"},
        "description": {"description": "lab-peer"},
        "update_source": {"source": "Ethernet1/54"},
        "transport_passive": {},
        "remove_private_as": {"mode": ""},
    }
    facts = dict(neighbor.facts)
    assert facts["State"] == "Established for 1d 2h 3m"
    assert facts["Neighbor's router ID"] == "198.51.100.2"
    (family,) = view.of("neighbor_af")
    assert family.values == {
        "filter_list_in": {"filter_list": "lab-aspath"},
        "route_map_in": {"route_map": "lab-in"},
        "prefix_list_out": {"prefix_list": "lab-out"},
        "soft_reconfiguration": {"always": "always"},
        "send_community": {},
        "send_community_extended": {},
        "as_override": {},
        "disable_peer_as_check": {},
        "route_reflector_client": {},
        "default_originate": {"route_map": ""},
    }
    assert dict(family.facts) == {"Prefixes received": "12", "Prefixes sent": "3"}
    # The VRF's IPv4 family has a table version, so it counts as set up.
    afs = {(i.ident["vrf"], i.ident["af"]) for i in view.of("af")}
    assert ("nxprobe-v", "ipv4 unicast") in afs
    assert _table(view, "Neighbors").rows == (
        ("198.51.100.2", "nxprobe-v", "ipv4 unicast", "65010", "Established", "1d 2h 3m", "12"),
    )
    assert view.notes == ()


def test_no_process_yet_and_empty_output():
    view = parse_bgp([{}, {}, {}, {}, {}])
    assert view.instances == ()
    assert "no BGP process yet" in view.notes[0]
    assert [t.rows for t in view.tables] == [(), (), ()]
    assert parse_bgp([]).instances == ()


# ---- changes: create and delete ---------------------------------------------------


def _lines(scope, setting, action, ident, values=None):
    return list(build_change(BGP, scope, setting, action, ident, values or {}).lines)


def test_create_and_delete_the_process():
    assert _lines("process", "", "create", ASN) == ["router bgp 65001"]
    change = build_change(BGP, "process", "", "delete", ASN, {})
    assert list(change.lines) == ["no router bgp 65001"]
    assert "every BGP setting" in change.warning
    assert _lines("process", "", "create", {"asn": "1.10"}) == ["router bgp 1.10"]


def test_create_and_delete_a_vrf_part():
    assert _lines("vrf", "", "create", IN_VRF) == ["router bgp 65001", "vrf lab"]
    assert _lines("vrf", "", "delete", IN_VRF) == ["router bgp 65001", "no vrf lab"]


def test_create_and_delete_an_address_family():
    assert _lines("af", "", "create", AF) == ENTER["af"]
    assert _lines("af", "", "delete", AF) == ["router bgp 65001", "no address-family ipv4 unicast"]
    in_vrf = {"asn": "65001", "vrf": "lab", "af": "ipv6 multicast"}
    assert _lines("af", "", "create", in_vrf) == [
        "router bgp 65001",
        "vrf lab",
        "address-family ipv6 multicast",
    ]
    assert _lines("af", "", "delete", in_vrf) == [
        "router bgp 65001",
        "vrf lab",
        "no address-family ipv6 multicast",
    ]


def test_create_and_delete_a_neighbor():
    assert _lines("neighbor", "", "create", NEIGHBOR) == ENTER["neighbor"]
    assert _lines("neighbor", "", "delete", NEIGHBOR) == [
        "router bgp 65001",
        "no neighbor 192.0.2.2",
    ]
    v6 = {"asn": "65001", "vrf": "lab", "address": "2001:db8:1::2"}
    assert _lines("neighbor", "", "delete", v6) == [
        "router bgp 65001",
        "vrf lab",
        "no neighbor 2001:db8:1::2",
    ]


def test_create_and_delete_a_neighbor_address_family():
    assert _lines("neighbor_af", "", "create", NEIGHBOR_AF) == ENTER["neighbor_af"]
    assert _lines("neighbor_af", "", "delete", NEIGHBOR_AF) == [
        "router bgp 65001",
        "neighbor 192.0.2.2",
        "no address-family ipv4 unicast",
    ]


# ---- changes: every setting -----------------------------------------------------

_COMMON = [
    ("router_id", {"router_id": "192.0.2.1"}, "router-id 192.0.2.1"),
    ("log_neighbor_changes", {}, "log-neighbor-changes"),
    ("bestpath_multipath_relax", {}, "bestpath as-path multipath-relax"),
    ("bestpath_as_path_ignore", {}, "bestpath as-path ignore"),
    ("bestpath_compare_routerid", {}, "bestpath compare-routerid"),
    ("bestpath_compare_neighborid", {}, "bestpath compare-neighborid"),
    ("bestpath_always_compare_med", {}, "bestpath always-compare-med"),
    ("bestpath_med_missing_as_worst", {}, "bestpath med missing-as-worst"),
    ("bestpath_med_confed", {}, "bestpath med confed"),
    ("bestpath_med_non_deterministic", {}, "bestpath med non-deterministic"),
    ("bestpath_cost_community_ignore", {}, "bestpath cost-community ignore"),
    ("bestpath_igp_metric_ignore", {}, "bestpath igp-metric ignore"),
    ("timers", {"keepalive": "10", "hold": "30"}, "timers bgp 10 30"),
    ("graceful_restart", {}, "graceful-restart"),
    ("graceful_restart_time", {"restart_time": "300"}, "graceful-restart restart-time 300"),
    (
        "graceful_restart_stalepath",
        {"stalepath_time": "600"},
        "graceful-restart stalepath-time 600",
    ),
    ("graceful_restart_helper", {}, "graceful-restart-helper"),
    ("cluster_id", {"cluster_id": "192.0.2.1"}, "cluster-id 192.0.2.1"),
    ("maxas_limit", {"as_limit": "50"}, "maxas-limit 50"),
]

CASES = [
    *(("process", *case) for case in _COMMON),
    ("process", "confederation_id", {"confed_id": "4000"}, "confederation identifier 4000"),
    (
        "process",
        "confederation_peers",
        {"peer1": "65010", "peer2": "65020", "peer4": "65040"},
        "confederation peers 65010 65020 65040",
    ),
    ("process", "enforce_first_as", {}, "enforce-first-as"),
    ("process", "fast_external_fallover", {}, "fast-external-fallover"),
    ("process", "shutdown", {}, "shutdown"),
    *(("vrf", *case) for case in _COMMON),
    ("vrf", "local_as", {"local_as": "65100"}, "local-as 65100"),
    ("af", "network", {"prefix": "192.0.2.0/24"}, "network 192.0.2.0/24"),
    (
        "af",
        "network",
        {"prefix": "2001:db8:1::/64", "route_map": "set-comm"},
        "network 2001:db8:1::/64 route-map set-comm",
    ),
    (
        "af",
        "aggregate",
        {"prefix": "192.0.2.0/23", "summary_only": "on"},
        "aggregate-address 192.0.2.0/23 summary-only",
    ),
    (
        "af",
        "aggregate",
        {
            "prefix": "192.0.2.0/23",
            "as_set": "on",
            "summary_only": "on",
            "advertise_map": "adv",
            "attribute_map": "attr",
            "suppress_map": "supp",
        },
        "aggregate-address 192.0.2.0/23 as-set summary-only advertise-map adv "
        "attribute-map attr suppress-map supp",
    ),
    (
        "af",
        "redistribute",
        {"source": "static", "route_map": "nxprobe-rm"},
        "redistribute static route-map nxprobe-rm",
    ),
    (
        "af",
        "redistribute",
        {"source": "direct", "route_map": "conn"},
        "redistribute direct route-map conn",
    ),
    (
        "af",
        "redistribute_protocol",
        {"protocol": "ospf", "tag": "core", "route_map": "ospf-in"},
        "redistribute ospf core route-map ospf-in",
    ),
    ("af", "default_information", {}, "default-information originate"),
    ("af", "maximum_paths", {"paths": "4"}, "maximum-paths 4"),
    ("af", "maximum_paths_ibgp", {"paths": "8"}, "maximum-paths ibgp 8"),
    (
        "af",
        "distance",
        {"external": "20", "internal": "200", "local": "220"},
        "distance 20 200 220",
    ),
    ("af", "dampening", {}, "dampening"),
    (
        "af",
        "dampening",
        {"half_life": "15", "reuse": "750", "suppress": "2000", "max_suppress": "60"},
        "dampening 15 750 2000 60",
    ),
    ("af", "dampening_route_map", {"route_map": "damp"}, "dampening route-map damp"),
    ("af", "additional_paths_send", {}, "additional-paths send"),
    ("af", "additional_paths_receive", {}, "additional-paths receive"),
    (
        "af",
        "additional_paths_selection",
        {"route_map": "paths"},
        "additional-paths selection route-map paths",
    ),
    ("af", "nexthop_route_map", {"route_map": "hops"}, "nexthop route-map hops"),
    ("af", "table_map", {"route_map": "tmap"}, "table-map tmap"),
    ("af", "table_map", {"route_map": "tmap", "filter": "on"}, "table-map tmap filter"),
    ("neighbor", "remote_as", {"remote_as": "65002"}, "remote-as 65002"),
    ("neighbor", "description", {"description": "probe-peer"}, "description probe-peer"),
    ("neighbor", "update_source", {"source": "Ethernet1/54"}, "update-source Ethernet1/54"),
    ("neighbor", "update_source", {"source": "port-channel5"}, "update-source port-channel5"),
    ("neighbor", "ebgp_multihop", {"ttl": "5"}, "ebgp-multihop 5"),
    ("neighbor", "ttl_security", {"hops": "2"}, "ttl-security hops 2"),
    ("neighbor", "timers", {"keepalive": "10", "hold": "30"}, "timers 10 30"),
    ("neighbor", "password", {"password": "s3cret!"}, "password 0 s3cret!"),
    ("neighbor", "bfd", {}, "bfd"),
    ("neighbor", "shutdown", {}, "shutdown"),
    ("neighbor", "transport_passive", {}, "transport connection-mode passive"),
    ("neighbor", "local_as", {"local_as": "65100"}, "local-as 65100"),
    (
        "neighbor",
        "local_as",
        {"local_as": "65100", "mode": "no-prepend replace-as dual-as"},
        "local-as 65100 no-prepend replace-as dual-as",
    ),
    ("neighbor", "remove_private_as", {}, "remove-private-as"),
    ("neighbor", "remove_private_as", {"mode": "all"}, "remove-private-as all"),
    ("neighbor", "disable_connected_check", {}, "disable-connected-check"),
    ("neighbor", "dynamic_capability", {}, "dynamic-capability"),
    ("neighbor", "suppress_4byte_as", {}, "capability suppress 4-byte-as"),
    ("neighbor_af", "route_map_in", {"route_map": "nxprobe-rm"}, "route-map nxprobe-rm in"),
    ("neighbor_af", "route_map_out", {"route_map": "out-rm"}, "route-map out-rm out"),
    ("neighbor_af", "prefix_list_in", {"prefix_list": "pl-in"}, "prefix-list pl-in in"),
    ("neighbor_af", "prefix_list_out", {"prefix_list": "pl-out"}, "prefix-list pl-out out"),
    ("neighbor_af", "filter_list_in", {"filter_list": "as-in"}, "filter-list as-in in"),
    ("neighbor_af", "filter_list_out", {"filter_list": "as-out"}, "filter-list as-out out"),
    ("neighbor_af", "unsuppress_map", {"route_map": "unsup"}, "unsuppress-map unsup"),
    ("neighbor_af", "soft_reconfiguration", {}, "soft-reconfiguration inbound"),
    (
        "neighbor_af",
        "soft_reconfiguration",
        {"always": "on"},
        "soft-reconfiguration inbound always",
    ),
    ("neighbor_af", "next_hop_self", {}, "next-hop-self"),
    ("neighbor_af", "next_hop_self", {"all": "on"}, "next-hop-self all"),
    ("neighbor_af", "send_community", {}, "send-community"),
    ("neighbor_af", "send_community_extended", {}, "send-community extended"),
    ("neighbor_af", "route_reflector_client", {}, "route-reflector-client"),
    ("neighbor_af", "default_originate", {}, "default-originate"),
    (
        "neighbor_af",
        "default_originate",
        {"route_map": "dflt"},
        "default-originate route-map dflt",
    ),
    ("neighbor_af", "weight", {"weight": "100"}, "weight 100"),
    ("neighbor_af", "maximum_prefix", {"limit": "1000"}, "maximum-prefix 1000"),
    (
        "neighbor_af",
        "maximum_prefix",
        {"limit": "1000", "threshold": "80", "warning_only": "on"},
        "maximum-prefix 1000 80 warning-only",
    ),
    (
        "neighbor_af",
        "maximum_prefix_restart",
        {"limit": "1000", "restart": "30"},
        "maximum-prefix 1000 restart 30",
    ),
    ("neighbor_af", "allowas_in", {}, "allowas-in"),
    ("neighbor_af", "allowas_in", {"count": "2"}, "allowas-in 2"),
    ("neighbor_af", "as_override", {}, "as-override"),
    ("neighbor_af", "disable_peer_as_check", {}, "disable-peer-as-check"),
    ("neighbor_af", "suppress_inactive", {}, "suppress-inactive"),
]

# Settings whose "remove" line is not "no " + the set line.
NO_LINES = {
    ("neighbor", "password"): "no password",
    ("neighbor_af", "soft_reconfiguration"): "no soft-reconfiguration inbound",
}


@pytest.mark.parametrize(("scope", "setting", "values", "line"), CASES)
def test_every_setting_sets_and_removes_its_line(scope, setting, values, line):
    assert _lines(scope, setting, "set", IDENT[scope], values) == [*ENTER[scope], line]
    found = BGP.scope(scope)
    spec = found.setting(setting) if found else None
    assert spec is not None
    if not spec.removable:
        with pytest.raises(ValueError, match="cannot be removed"):
            _lines(scope, setting, "remove", IDENT[scope], values)
        return
    removed = NO_LINES.get((scope, setting), f"no {line}")
    assert _lines(scope, setting, "remove", IDENT[scope], values) == [*ENTER[scope], removed]


def test_every_setting_has_a_case():
    covered = {(scope, setting) for scope, setting, _, _ in CASES}
    every = {(scope.key, s.key) for scope in BGP.scopes for s in scope.settings}
    assert every == covered


def test_settings_inside_a_vrf_neighbor_enter_the_vrf():
    ident = {"asn": "65001", "vrf": "lab", "address": "2001:db8:1::2", "af": "ipv6 unicast"}
    assert _lines("neighbor_af", "next_hop_self", "set", ident) == [
        "router bgp 65001",
        "vrf lab",
        "neighbor 2001:db8:1::2",
        "address-family ipv6 unicast",
        "next-hop-self",
    ]
    default = {"asn": "65001", "vrf": "default", "af": "ipv4 unicast"}
    assert _lines("af", "default_information", "set", default) == [
        "router bgp 65001",
        "address-family ipv4 unicast",
        "default-information originate",
    ]


def test_password_is_masked_in_labels_and_notice():
    change = build_change(BGP, "neighbor", "password", "set", NEIGHBOR, {"password": "s3cret!"})
    assert change.lines[-1] == "password 0 s3cret!"
    assert change.labels[-1] == "password 0 ***"
    assert "s3cret" not in change.describe
    assert change.warning


def test_vrf_part_of_the_default_vrf_is_refused():
    ident = {"asn": "65001", "vrf": "default"}
    with pytest.raises(ValueError, match="other than default"):
        _lines("vrf", "", "delete", ident)
    with pytest.raises(ValueError, match="other than default"):
        _lines("vrf", "router_id", "set", ident, {"router_id": "192.0.2.9"})


# ---- refusals ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scope", "setting", "ident", "values", "message"),
    [
        ("process", "router_id", ASN, {"router_id": "2001:db8::1"}, "IPv4 address"),
        ("process", "router_id", ASN, {"router_id": "192.0.2.1;exit"}, '";"'),
        ("process", "timers", ASN, {"keepalive": "4000", "hold": "30"}, "0 to 3600"),
        ("process", "confederation_id", ASN, {"confed_id": "0"}, "AS number"),
        ("process", "router_id", {"asn": "4294967296"}, {"router_id": "192.0.2.1"}, "AS"),
        ("vrf", "router_id", {"asn": "65001", "vrf": "management"}, {"router_id": "192.0.2.1"},
         "keeps the VRF name"),
        ("af", "network", AF, {"prefix": "192.0.2.1/24"}, "not the start"),
        ("af", "network", AF, {"prefix": "192.0.2.0"}, "prefix length"),
        ("af", "network", {**AF, "af": "ipv4 anycast"}, {"prefix": "192.0.2.0/24"},
         "Address family is one of"),
        ("af", "redistribute", AF, {"source": "bgp", "route_map": "rm"}, "one of"),
        ("af", "redistribute", AF, {"source": "static", "route_map": "rm;reload"}, '";"'),
        ("af", "redistribute", AF, {"source": "static"}, "Route-map is needed"),
        ("af", "redistribute_protocol", AF, {"protocol": "ospf", "tag": "a b",
                                              "route_map": "rm"}, "Process tag"),
        ("af", "maximum_paths", AF, {"paths": "65"}, "1 to 64"),
        ("af", "distance", AF, {"external": "0", "internal": "200", "local": "220"},
         "1 to 255"),
        ("af", "dampening", AF, {"half_life": "46"}, "1 to 45"),
        ("neighbor", "remote_as", {**NEIGHBOR, "address": "224.0.0.5"}, {"remote_as": "1"},
         "not an address"),
        ("neighbor", "remote_as", {**NEIGHBOR, "vrf": "management"}, {"remote_as": "1"},
         "keeps the VRF name"),
        ("neighbor", "remote_as", NEIGHBOR, {"remote_as": "65536.1"}, "AS number"),
        ("neighbor", "update_source", NEIGHBOR, {"source": "mgmt0"}, "Interface"),
        ("neighbor", "update_source", NEIGHBOR, {"source": "Vlan300"}, "1 to 254"),
        ("neighbor", "ebgp_multihop", NEIGHBOR, {"ttl": "1"}, "2 to 255"),
        ("neighbor", "description", NEIGHBOR, {"description": "a;b"}, '";"'),
        ("neighbor", "description", NEIGHBOR, {"description": "x" * 81}, "80"),
        ("neighbor", "password", NEIGHBOR, {"password": "two words"}, "without spaces"),
        ("neighbor", "password", NEIGHBOR, {"password": "pw;exit"}, '";"'),
        ("neighbor", "local_as", NEIGHBOR, {"local_as": "1", "mode": "dual-as"}, "one of"),
        ("neighbor_af", "weight", NEIGHBOR_AF, {"weight": "65536"}, "0 to 65535"),
        ("neighbor_af", "maximum_prefix", NEIGHBOR_AF, {"limit": "1000", "threshold": "101"},
         "1 to 100"),
        ("neighbor_af", "allowas_in", NEIGHBOR_AF, {"count": "11"}, "1 to 10"),
        ("neighbor_af", "route_map_in", NEIGHBOR_AF, {"route_map": "-bad"}, "Route-map"),
    ],
)  # fmt: skip
def test_bad_values_are_refused(scope, setting, ident, values, message):
    with pytest.raises(ValueError, match=message):
        build_change(BGP, scope, setting, "set", ident, values)


def test_remote_as_is_only_changed_and_unknown_settings_refused():
    with pytest.raises(ValueError, match="cannot be removed"):
        build_change(BGP, "neighbor", "remote_as", "remove", NEIGHBOR, {"remote_as": "65002"})
    with pytest.raises(ValueError, match="no setting"):
        build_change(BGP, "process", "redistribute", "set", ASN, {})
    with pytest.raises(ValueError, match="no 'interface' settings"):
        build_change(BGP, "interface", "x", "set", ASN, {})
