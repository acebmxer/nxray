"""PIM, PIM6, IGMP, MSDP and BFD (app/protocols_multicast.py): the parsers
against output recorded on cisco-25gb (NX-OS 9.3(16)), and the exact lines
every setting sends.

Two fixtures are not recorded: ``show_ip_pim_neighbor_vrf_all_doc`` and
``show_bfd_neighbors_doc`` are shaped after Cisco's documented NX-API output
for those commands (the switch had no PIM neighbor and no BFD session, and
then prints an empty table or nothing at all).
"""

from __future__ import annotations

import pytest

from app.protocols import Protocol, build_change
from app.protocols_multicast import (
    BFD,
    IGMP,
    MSDP,
    PIM,
    PIM6,
    PROTOCOLS,
    parse_bfd,
    parse_igmp,
    parse_msdp,
    parse_pim,
    parse_pim6,
)
from tests.conftest import load_fixture

_BY_KEY = {p.key: p for p in PROTOCOLS}


def _pim_bodies(neighbors: str = "show_ip_pim_neighbor_vrf_all") -> list[dict]:
    return [
        load_fixture("show_ip_pim_interface_vrf_all"),
        load_fixture(neighbors),
        load_fixture("show_ip_pim_rp_vrf_all"),
        load_fixture("show_ip_pim_group-range_vrf_all"),
        load_fixture("show_ip_mroute_vrf_all"),
    ]


def _table(view, title: str):
    return next(t for t in view.tables if t.title == title)


# ---- the protocols ----------------------------------------------------------------


def test_protocols_are_the_five_with_their_features_and_commands() -> None:
    assert [p.key for p in PROTOCOLS] == ["pim", "pim6", "igmp", "msdp", "bfd"]
    assert [p.features for p in PROTOCOLS] == [
        ("pim",),
        ("pim6",),
        ("pim",),
        ("msdp",),
        ("bfd",),
    ]
    assert PIM.commands == (
        "show ip pim interface vrf all",
        "show ip pim neighbor vrf all",
        "show ip pim rp vrf all",
        "show ip pim group-range vrf all",
        "show ip mroute vrf all",
    )
    assert PIM6.commands == ("show ipv6 pim interface vrf all", "show ipv6 pim rp vrf all")
    assert IGMP.commands == ("show ip igmp interface vrf all",)
    assert MSDP.commands == ("show ip msdp peer vrf all", "show ip msdp summary vrf all")
    assert BFD.commands == ("show bfd neighbors",)
    assert PIM.parse is parse_pim and BFD.parse is parse_bfd


# ---- reading ------------------------------------------------------------------------


def test_pim_reads_the_vrf_rp_ssm_range_and_interface() -> None:
    view = parse_pim(_pim_bodies())
    (vrf,) = view.of("vrf")
    assert vrf.ident == {"vrf": "default"}
    assert ("Static RPs", "1") in vrf.facts and ("SSM range", "232.0.0.0/8") in vrf.facts
    assert vrf.values == {
        "rp_group": {"address": "192.0.2.10", "group": "224.0.0.0/4", "bidir": "", "override": ""},
        "ssm_range": {"group": "232.0.0.0/8"},
    }
    (interface,) = view.of("interface")
    assert interface.ident == {"interface": "Ethernet1/54"}
    assert ("Address", "192.0.2.1/24") in interface.facts
    assert interface.values == {
        "sparse_mode": {},
        "dr_priority": {"priority": "10"},
        "hello_interval": {"milliseconds": "30000"},
    }


def test_pim_tables_from_recorded_output() -> None:
    view = parse_pim(_pim_bodies())
    assert _table(view, "PIM interfaces").rows == (
        (
            "Ethernet1/54",
            "default",
            "protocol-down/link-down/admin-up",
            "192.0.2.1/24",
            "",
            "10",
            "0",
            "30",
            "no",
            "no",
        ),
    )
    assert _table(view, "PIM neighbors").rows == ()
    assert _table(view, "Rendezvous points").rows == (
        ("192.0.2.10", "224.0.0.0/4", "default", "set here", "255", "00:00:02", "no"),
    )
    assert _table(view, "Group ranges").rows == (
        ("232.0.0.0/8", "SSM", "", "default", "Local", "Accept"),
        ("224.0.0.0/4", "ASM", "192.0.2.10", "default", "Static", ""),
    )
    assert _table(view, "Multicast routes").rows == (
        ("*", "232.0.0.0/8", "default", "", "", "0", "00:00:26"),
    )


def test_pim_neighbors_from_documented_output() -> None:
    # Shaped after Cisco's documentation, not recorded: one VRF with a list of
    # neighbors, one with a single neighbor.
    view = parse_pim(_pim_bodies("show_ip_pim_neighbor_vrf_all_doc"))
    assert _table(view, "PIM neighbors").rows == (
        ("192.0.2.2", "Vlan10", "default", "1w0d", "00:01:25", "1", "n/a"),
        ("198.51.100.2", "Ethernet1/54", "default", "02:10:44", "00:01:19", "10", "Up"),
        ("203.0.113.2", "Vlan20", "tenant-a", "00:05:12", "00:01:30", "1", "n/a"),
    )
    assert [i.ident["vrf"] for i in view.of("vrf")] == ["default", "tenant-a"]


def test_pim_with_nothing_printed() -> None:
    view = parse_pim([{}, {}, {}, {}, {}])
    assert [i.ident for i in view.instances] == [{"vrf": "default"}]
    assert all(t.rows == () for t in view.tables)
    assert parse_pim([]).instances[0].ident == {"vrf": "default"}


def test_pim6_reads_rp_and_interface() -> None:
    view = parse_pim6(
        [load_fixture("show_ipv6_pim_interface_vrf_all"), load_fixture("show_ipv6_pim_rp_vrf_all")]
    )
    (vrf,) = view.of("vrf")
    assert vrf.facts == (("Static RPs", "1"),)
    assert vrf.values == {
        "rp_group": {"address": "2001:db8:1::10", "group": "ff00::/8", "override": ""}
    }
    (interface,) = view.of("interface")
    assert interface.values == {
        "sparse_mode": {},
        "dr_priority": {"priority": "1"},
        "hello_interval": {"milliseconds": "30000"},
    }
    state = "protocol-down/link-down/admin-up"
    assert _table(view, "PIM6 interfaces").rows == (
        ("Ethernet1/54", "default", state, "", "1", "0", "30", "no", "no"),
    )
    assert _table(view, "Rendezvous points").rows == (
        ("2001:db8:1::10", "ff00::/8", "default", "set here", "255", "00:00:03", "no"),
    )


def test_igmp_reads_the_interface_and_its_timers() -> None:
    view = parse_igmp([load_fixture("show_ip_igmp_interface_vrf_all")])
    (interface,) = view.instances
    assert interface.scope == "interface" and interface.ident == {"interface": "Ethernet1/54"}
    assert ("Version", "3") in interface.facts and ("Querier", "none yet") in interface.facts
    assert interface.values == {
        "version": {"version": "3"},
        "query_interval": {"seconds": "125"},
        "query_max_response_time": {"seconds": "10"},
        "startup_query_interval": {"seconds": "31"},
        "startup_query_count": {"count": "2"},
        "robustness_variable": {"count": "2"},
        "querier_timeout": {"seconds": "255"},
        "last_member_query_response_time": {"seconds": "1"},
        "last_member_query_count": {"count": "2"},
        "group_timeout": {"seconds": "260"},
    }
    assert view.tables[0].rows == (
        (
            "Ethernet1/54",
            "default",
            "protocol-down/link-down/admin-up",
            "192.0.2.1/24",
            "",
            "3",
            "0",
            "125",
        ),
    )
    assert parse_igmp([{}]).instances == ()


def test_msdp_reads_the_vrf_and_the_peer() -> None:
    view = parse_msdp(
        [load_fixture("show_ip_msdp_peer_vrf_all"), load_fixture("show_ip_msdp_summary_vrf_all")]
    )
    (vrf,) = view.of("vrf")
    assert ("Local AS", "65001") in vrf.facts and ("Originator ID", "192.0.2.1") in vrf.facts
    assert vrf.values == {"reconnect_interval": {"seconds": "10"}}
    (peer,) = view.of("peer")
    assert peer.ident == {"vrf": "default", "address": "198.51.100.9"}
    assert ("State", "Connecting") in peer.facts
    assert ("In this state for", "2d 13h 19m 57s") in peer.facts
    assert peer.values == {
        "connect_source": {"peer": "198.51.100.9", "source": "Ethernet1/54", "remote_as": ""},
        "description": {"peer": "198.51.100.9", "text": "probe-msdp"},
        "keepalive": {"peer": "198.51.100.9", "interval": "60", "timeout": "90"},
    }
    assert view.tables[0].rows == (
        (
            "198.51.100.9",
            "default",
            "Connecting",
            "",
            "Ethernet1/54",
            "2d 13h 19m 57s",
            "0",
            "0",
            "probe-msdp",
        ),
    )


def test_bfd_sessions_from_documented_output() -> None:
    # Shaped after Cisco's documentation, not recorded: the switch had no BFD
    # session. Each session comes as two rows with the same local_disc.
    view = parse_bfd([load_fixture("show_bfd_neighbors_doc")])
    assert view.tables[0].rows == (
        ("192.0.2.2", "192.0.2.1", "Ethernet1/54", "default", "Up", "Up", "3", "642", "one hop",
         "bgp, pim"),
        ("2001:db8:1::2", "2001:db8:1::1", "Vlan20", "tenant-a", "Down", "Down", "3", "0",
         "one hop", "ospfv3"),
    )  # fmt: skip
    assert [i.ident for i in view.instances] == [
        {},
        {"interface": "Ethernet1/54"},
        {"interface": "Vlan20"},
    ]


def test_bfd_with_no_sessions_prints_nothing() -> None:
    # Recorded: with no session the switch's reply has "result": null.
    for bodies in ([None], [{}], []):
        view = parse_bfd(bodies)  # type: ignore[arg-type]
        assert [i.scope for i in view.instances] == ["global"]
        assert view.tables[0].rows == ()


# ---- every setting's lines -----------------------------------------------------------

_IDENT = {
    "vrf": {"vrf": "default"},
    "interface": {"interface": "Vlan10"},
    "peer": {"vrf": "default", "address": "198.51.100.9"},
    "global": {},
}
_ENTER = {
    "vrf": (),
    "interface": ("interface Vlan10",),
    "peer": (),
    "global": (),
}
_PEER = "198.51.100.9"

# (protocol, scope, setting, values, line set, line removed or None when it
# cannot be removed)
_CASES: list[tuple[str, str, str, dict[str, str], str, str | None]] = [
    # PIM, per VRF
    ("pim", "vrf", "rp_group", {"address": "192.0.2.10", "group": "224.0.0.0/4"},
     "ip pim rp-address 192.0.2.10 group-list 224.0.0.0/4",
     "no ip pim rp-address 192.0.2.10 group-list 224.0.0.0/4"),
    ("pim", "vrf", "rp_route_map", {"address": "192.0.2.10", "route_map": "rp-groups"},
     "ip pim rp-address 192.0.2.10 route-map rp-groups",
     "no ip pim rp-address 192.0.2.10 route-map rp-groups"),
    ("pim", "vrf", "rp_prefix_list",
     {"address": "192.0.2.10", "prefix_list": "rp-pl", "override": "on"},
     "ip pim rp-address 192.0.2.10 prefix-list rp-pl override",
     "no ip pim rp-address 192.0.2.10 prefix-list rp-pl override"),
    ("pim", "vrf", "anycast_rp", {"anycast": "192.0.2.100", "member": "192.0.2.1"},
     "ip pim anycast-rp 192.0.2.100 192.0.2.1", "no ip pim anycast-rp 192.0.2.100 192.0.2.1"),
    ("pim", "vrf", "ssm_range", {"group": "232.0.0.0/8"},
     "ip pim ssm range 232.0.0.0/8", "no ip pim ssm range 232.0.0.0/8"),
    ("pim", "vrf", "ssm_route_map", {"route_map": "ssm-groups"},
     "ip pim ssm route-map ssm-groups", "no ip pim ssm route-map ssm-groups"),
    ("pim", "vrf", "ssm_prefix_list", {"prefix_list": "ssm-pl"},
     "ip pim ssm prefix-list ssm-pl", "no ip pim ssm prefix-list ssm-pl"),
    ("pim", "vrf", "ssm_none", {}, "ip pim ssm range none", "no ip pim ssm range none"),
    ("pim", "vrf", "bsr_listen", {"mode": "listen forward"},
     "ip pim bsr listen forward", "no ip pim bsr listen forward"),
    ("pim", "vrf", "bsr_candidate", {"source": "Vlan10", "hash_len": "30", "priority": "100"},
     "ip pim bsr bsr-candidate Vlan10 hash-len 30 priority 100",
     "no ip pim bsr bsr-candidate Vlan10"),
    ("pim", "vrf", "bsr_rp_candidate",
     {"source": "Vlan10", "group": "239.0.0.0/8", "priority": "10", "interval": "30"},
     "ip pim bsr rp-candidate Vlan10 group-list 239.0.0.0/8 priority 10 interval 30",
     "no ip pim bsr rp-candidate Vlan10 group-list 239.0.0.0/8"),
    ("pim", "vrf", "bsr_policy", {"route_map": "bsr-ok"},
     "ip pim bsr bsr-policy bsr-ok", "no ip pim bsr bsr-policy bsr-ok"),
    ("pim", "vrf", "bsr_rp_candidate_policy", {"route_map": "crp-ok"},
     "ip pim bsr rp-candidate-policy crp-ok", "no ip pim bsr rp-candidate-policy crp-ok"),
    ("pim", "vrf", "auto_rp_listen", {"mode": "listen"},
     "ip pim auto-rp listen", "no ip pim auto-rp listen"),
    ("pim", "vrf", "auto_rp_mapping_agent", {"source": "Ethernet1/54", "scope": "16"},
     "ip pim auto-rp mapping-agent Ethernet1/54 scope 16",
     "no ip pim auto-rp mapping-agent Ethernet1/54"),
    ("pim", "vrf", "auto_rp_candidate",
     {"source": "Vlan10", "group": "239.0.0.0/8", "scope": "16", "interval": "30"},
     "ip pim auto-rp rp-candidate Vlan10 group-list 239.0.0.0/8 scope 16 interval 30",
     "no ip pim auto-rp rp-candidate Vlan10 group-list 239.0.0.0/8"),
    ("pim", "vrf", "auto_rp_candidate_policy", {"route_map": "announce-ok"},
     "ip pim auto-rp rp-candidate-policy announce-ok",
     "no ip pim auto-rp rp-candidate-policy announce-ok"),
    ("pim", "vrf", "auto_rp_mapping_agent_policy", {"route_map": "agents-ok"},
     "ip pim auto-rp mapping-agent-policy agents-ok",
     "no ip pim auto-rp mapping-agent-policy agents-ok"),
    ("pim", "vrf", "register_source", {"source": "Vlan10"},
     "ip pim register-source Vlan10", "no ip pim register-source Vlan10"),
    ("pim", "vrf", "register_rate_limit", {"rate": "1000"},
     "ip pim register-rate-limit 1000", "no ip pim register-rate-limit 1000"),
    ("pim", "vrf", "register_policy", {"route_map": "reg-ok"},
     "ip pim register-policy reg-ok", "no ip pim register-policy reg-ok"),
    ("pim", "vrf", "spt_infinity", {"route_map": "shared-only"},
     "ip pim spt-threshold infinity group-list shared-only",
     "no ip pim spt-threshold infinity group-list shared-only"),
    ("pim", "vrf", "log_neighbor_changes", {},
     "ip pim log-neighbor-changes", "no ip pim log-neighbor-changes"),
    ("pim", "vrf", "bfd", {}, "ip pim bfd", "no ip pim bfd"),
    # PIM, per interface
    ("pim", "interface", "sparse_mode", {}, "ip pim sparse-mode", "no ip pim sparse-mode"),
    ("pim", "interface", "dr_priority", {"priority": "10"},
     "ip pim dr-priority 10", "no ip pim dr-priority 10"),
    ("pim", "interface", "dr_delay", {"seconds": "3"}, "ip pim dr-delay 3", "no ip pim dr-delay 3"),
    ("pim", "interface", "hello_interval", {"milliseconds": "30000"},
     "ip pim hello-interval 30000", "no ip pim hello-interval 30000"),
    ("pim", "interface", "hello_authentication", {"key": "pimkey1"},
     "ip pim hello-authentication ah-md5 pimkey1",
     "no ip pim hello-authentication ah-md5 pimkey1"),
    ("pim", "interface", "border", {}, "ip pim border", "no ip pim border"),
    ("pim", "interface", "passive", {}, "ip pim passive", "no ip pim passive"),
    ("pim", "interface", "neighbor_policy", {"prefix_list": "pim-nbrs"},
     "ip pim neighbor-policy prefix-list pim-nbrs",
     "no ip pim neighbor-policy prefix-list pim-nbrs"),
    ("pim", "interface", "jp_policy", {"route_map": "jp-ok", "direction": "in"},
     "ip pim jp-policy jp-ok in", "no ip pim jp-policy jp-ok in"),
    ("pim", "interface", "bfd_instance", {}, "ip pim bfd-instance", "no ip pim bfd-instance"),
    # PIM6, per VRF
    ("pim6", "vrf", "rp_group", {"address": "2001:db8:1::10", "group": "ff00::/8"},
     "ipv6 pim rp-address 2001:db8:1::10 group-list ff00::/8",
     "no ipv6 pim rp-address 2001:db8:1::10 group-list ff00::/8"),
    ("pim6", "vrf", "rp_route_map", {"address": "2001:db8:1::10", "route_map": "rp6"},
     "ipv6 pim rp-address 2001:db8:1::10 route-map rp6",
     "no ipv6 pim rp-address 2001:db8:1::10 route-map rp6"),
    ("pim6", "vrf", "rp_prefix_list", {"address": "2001:db8:1::10", "prefix_list": "rp6-pl"},
     "ipv6 pim rp-address 2001:db8:1::10 prefix-list rp6-pl",
     "no ipv6 pim rp-address 2001:db8:1::10 prefix-list rp6-pl"),
    ("pim6", "vrf", "anycast_rp", {"anycast": "2001:db8:1::100", "member": "2001:db8:1::1"},
     "ipv6 pim anycast-rp 2001:db8:1::100 2001:db8:1::1",
     "no ipv6 pim anycast-rp 2001:db8:1::100 2001:db8:1::1"),
    ("pim6", "vrf", "register_rate_limit", {"rate": "500"},
     "ipv6 pim register-rate-limit 500", "no ipv6 pim register-rate-limit 500"),
    ("pim6", "vrf", "register_policy", {"route_map": "reg6"},
     "ipv6 pim register-policy reg6", "no ipv6 pim register-policy reg6"),
    ("pim6", "vrf", "spt_infinity", {"route_map": "shared6"},
     "ipv6 pim spt-threshold infinity group-list shared6",
     "no ipv6 pim spt-threshold infinity group-list shared6"),
    ("pim6", "vrf", "log_neighbor_changes", {},
     "ipv6 pim log-neighbor-changes", "no ipv6 pim log-neighbor-changes"),
    # PIM6, per interface
    ("pim6", "interface", "sparse_mode", {}, "ipv6 pim sparse-mode", "no ipv6 pim sparse-mode"),
    ("pim6", "interface", "dr_priority", {"priority": "192"},
     "ipv6 pim dr-priority 192", "no ipv6 pim dr-priority 192"),
    ("pim6", "interface", "hello_interval", {"milliseconds": "25000"},
     "ipv6 pim hello-interval 25000", "no ipv6 pim hello-interval 25000"),
    ("pim6", "interface", "border", {}, "ipv6 pim border", "no ipv6 pim border"),
    ("pim6", "interface", "passive", {}, "ipv6 pim passive", "no ipv6 pim passive"),
    ("pim6", "interface", "neighbor_policy", {"route_map": "nbrs6"},
     "ipv6 pim neighbor-policy nbrs6", "no ipv6 pim neighbor-policy nbrs6"),
    ("pim6", "interface", "jp_policy", {"route_map": "jp6"},
     "ipv6 pim jp-policy jp6", "no ipv6 pim jp-policy jp6"),
    # IGMP, per interface
    ("igmp", "interface", "version", {"version": "3"}, "ip igmp version 3", "no ip igmp version 3"),
    ("igmp", "interface", "query_interval", {"seconds": "100"},
     "ip igmp query-interval 100", "no ip igmp query-interval 100"),
    ("igmp", "interface", "query_max_response_time", {"seconds": "15"},
     "ip igmp query-max-response-time 15", "no ip igmp query-max-response-time 15"),
    ("igmp", "interface", "startup_query_interval", {"seconds": "25"},
     "ip igmp startup-query-interval 25", "no ip igmp startup-query-interval 25"),
    ("igmp", "interface", "startup_query_count", {"count": "3"},
     "ip igmp startup-query-count 3", "no ip igmp startup-query-count 3"),
    ("igmp", "interface", "robustness_variable", {"count": "3"},
     "ip igmp robustness-variable 3", "no ip igmp robustness-variable 3"),
    ("igmp", "interface", "querier_timeout", {"seconds": "300"},
     "ip igmp querier-timeout 300", "no ip igmp querier-timeout 300"),
    ("igmp", "interface", "last_member_query_response_time", {"seconds": "3"},
     "ip igmp last-member-query-response-time 3",
     "no ip igmp last-member-query-response-time 3"),
    ("igmp", "interface", "last_member_query_count", {"count": "3"},
     "ip igmp last-member-query-count 3", "no ip igmp last-member-query-count 3"),
    ("igmp", "interface", "group_timeout", {"seconds": "300"},
     "ip igmp group-timeout 300", "no ip igmp group-timeout 300"),
    ("igmp", "interface", "immediate_leave", {},
     "ip igmp immediate-leave", "no ip igmp immediate-leave"),
    ("igmp", "interface", "report_link_local_groups", {},
     "ip igmp report-link-local-groups", "no ip igmp report-link-local-groups"),
    ("igmp", "interface", "report_policy", {"route_map": "reports-ok"},
     "ip igmp report-policy reports-ok", "no ip igmp report-policy reports-ok"),
    ("igmp", "interface", "access_group", {"route_map": "groups-ok"},
     "ip igmp access-group groups-ok", "no ip igmp access-group groups-ok"),
    ("igmp", "interface", "join_group", {"route_map": "joins"},
     "ip igmp join-group route-map joins", "no ip igmp join-group route-map joins"),
    ("igmp", "interface", "static_oif", {"route_map": "static-groups"},
     "ip igmp static-oif route-map static-groups",
     "no ip igmp static-oif route-map static-groups"),
    ("igmp", "interface", "join_group_address", {"group": "239.1.1.1", "sender": ""},
     "ip igmp join-group 239.1.1.1", "no ip igmp join-group 239.1.1.1"),
    ("igmp", "interface", "static_oif_address", {"group": "239.1.1.1", "sender": "192.0.2.10"},
     "ip igmp static-oif 239.1.1.1 source 192.0.2.10",
     "no ip igmp static-oif 239.1.1.1 source 192.0.2.10"),
    # MSDP, per VRF
    ("msdp", "vrf", "peer", {"peer": _PEER, "source": "Ethernet1/54", "remote_as": "65002"},
     "ip msdp peer 198.51.100.9 connect-source Ethernet1/54 remote-as 65002", None),
    ("msdp", "vrf", "originator_id", {"source": "Ethernet1/54"},
     "ip msdp originator-id Ethernet1/54", "no ip msdp originator-id Ethernet1/54"),
    ("msdp", "vrf", "reconnect_interval", {"seconds": "20"},
     "ip msdp reconnect-interval 20", "no ip msdp reconnect-interval 20"),
    ("msdp", "vrf", "sa_interval", {"seconds": "80"},
     "ip msdp sa-interval 80", "no ip msdp sa-interval 80"),
    ("msdp", "vrf", "group_limit", {"limit": "1000", "source": "192.0.2.0/24"},
     "ip msdp group-limit 1000 source 192.0.2.0/24",
     "no ip msdp group-limit 1000 source 192.0.2.0/24"),
    ("msdp", "vrf", "flush_routes", {}, "ip msdp flush-routes", "no ip msdp flush-routes"),
    # MSDP, per peer
    ("msdp", "peer", "connect_source", {"peer": _PEER, "source": "Vlan10"},
     "ip msdp peer 198.51.100.9 connect-source Vlan10", None),
    ("msdp", "peer", "description", {"peer": _PEER, "text": "peer in the lab"},
     "ip msdp description 198.51.100.9 peer in the lab",
     "no ip msdp description 198.51.100.9 peer in the lab"),
    ("msdp", "peer", "password", {"peer": _PEER, "password": "msdp-pw1"},
     "ip msdp password 198.51.100.9 msdp-pw1", "no ip msdp password 198.51.100.9"),
    ("msdp", "peer", "keepalive", {"peer": _PEER, "interval": "30", "timeout": "75"},
     "ip msdp keepalive 198.51.100.9 30 75", "no ip msdp keepalive 198.51.100.9"),
    ("msdp", "peer", "mesh_group", {"peer": _PEER, "name": "mesh1"},
     "ip msdp mesh-group 198.51.100.9 mesh1", "no ip msdp mesh-group 198.51.100.9 mesh1"),
    ("msdp", "peer", "sa_limit", {"peer": _PEER, "limit": "5000"},
     "ip msdp sa-limit 198.51.100.9 5000", "no ip msdp sa-limit 198.51.100.9"),
    ("msdp", "peer", "sa_policy_in", {"peer": _PEER, "route_map": "sa-in"},
     "ip msdp sa-policy 198.51.100.9 sa-in in", "no ip msdp sa-policy 198.51.100.9 sa-in in"),
    ("msdp", "peer", "sa_policy_out", {"peer": _PEER, "route_map": "sa-out"},
     "ip msdp sa-policy 198.51.100.9 sa-out out",
     "no ip msdp sa-policy 198.51.100.9 sa-out out"),
    ("msdp", "peer", "shutdown", {"peer": _PEER},
     "ip msdp shutdown 198.51.100.9", "no ip msdp shutdown 198.51.100.9"),
    # BFD
    ("bfd", "global", "interval", {"tx": "250", "rx": "250", "multiplier": "3"},
     "bfd interval 250 min_rx 250 multiplier 3", "no bfd interval 250 min_rx 250 multiplier 3"),
    ("bfd", "global", "slow_timer", {"milliseconds": "2000"},
     "bfd slow-timer 2000", "no bfd slow-timer 2000"),
    ("bfd", "global", "startup_timer", {"seconds": "10"},
     "bfd startup-timer 10", "no bfd startup-timer"),
    ("bfd", "interface", "interval", {"tx": "300", "rx": "300", "multiplier": "3"},
     "bfd interval 300 min_rx 300 multiplier 3", "no bfd interval 300 min_rx 300 multiplier 3"),
    ("bfd", "interface", "echo", {}, "bfd echo", "no bfd echo"),
    ("bfd", "interface", "authentication", {"key_id": "1", "key": "bfdkey1"},
     "bfd authentication keyed-sha1 key-id 1 key bfdkey1", "no bfd authentication"),
]  # fmt: skip


def test_every_setting_has_a_case() -> None:
    defined = {
        (protocol.key, scope.key, setting.key)
        for protocol in PROTOCOLS
        for scope in protocol.scopes
        for setting in scope.settings
    }
    covered = {(p, s, k) for p, s, k, *_ in _CASES}
    assert covered == defined


@pytest.mark.parametrize(
    ("protocol", "scope", "setting", "values", "line", "removed"),
    _CASES,
    ids=[f"{p}-{s}-{k}" for p, s, k, *_ in _CASES],
)
def test_setting_lines(
    protocol: str,
    scope: str,
    setting: str,
    values: dict[str, str],
    line: str,
    removed: str | None,
) -> None:
    proto: Protocol = _BY_KEY[protocol]
    change = build_change(proto, scope, setting, "set", _IDENT[scope], values)
    assert change.lines == (*_ENTER[scope], line)
    if removed is None:
        with pytest.raises(ValueError, match="cannot be removed"):
            build_change(proto, scope, setting, "remove", _IDENT[scope], values)
    else:
        change = build_change(proto, scope, setting, "remove", _IDENT[scope], values)
        assert change.lines == (*_ENTER[scope], removed)


def test_a_vrf_is_entered_first() -> None:
    change = build_change(
        PIM, "vrf", "rp_group", "set", {"vrf": "tenant-a"}, {"address": "192.0.2.10"}
    )
    assert change.lines == ("vrf context tenant-a", "ip pim rp-address 192.0.2.10")
    change = build_change(
        MSDP, "peer", "shutdown", "set", {"vrf": "tenant-a", "address": _PEER}, {"peer": _PEER}
    )
    assert change.lines == ("vrf context tenant-a", "ip msdp shutdown 198.51.100.9")


def test_rp_with_bidir_and_override() -> None:
    change = build_change(
        PIM,
        "vrf",
        "rp_group",
        "set",
        _IDENT["vrf"],
        {"address": "192.0.2.10", "group": "239.0.0.0/8", "bidir": "on", "override": "on"},
    )
    assert change.lines == ("ip pim rp-address 192.0.2.10 group-list 239.0.0.0/8 bidir override",)


def test_bfd_for_pim_turned_off_on_one_interface() -> None:
    change = build_change(
        PIM, "interface", "bfd_instance", "set", _IDENT["interface"], {"disable": "on"}
    )
    assert change.lines == ("interface Vlan10", "ip pim bfd-instance disable")


def test_secrets_are_masked() -> None:
    cases = [
        (PIM, "interface", "hello_authentication", {"key": "pimkey1"}, "pimkey1"),
        (MSDP, "peer", "password", {"peer": _PEER, "password": "msdp-pw1"}, "msdp-pw1"),
        (BFD, "interface", "authentication", {"key_id": "1", "key": "bfdkey1"}, "bfdkey1"),
    ]
    for protocol, scope, setting, values, secret in cases:
        change = build_change(protocol, scope, setting, "set", _IDENT[scope], values)
        assert secret in change.lines[-1]
        assert secret not in " ".join(change.labels) and "***" in change.labels[-1]
        assert secret not in change.describe
        assert change.warning


def test_msdp_peer_is_deleted_and_nothing_is_created() -> None:
    change = build_change(MSDP, "peer", "", "delete", {"vrf": "tenant-a", "address": _PEER}, {})
    assert change.lines == ("vrf context tenant-a", "no ip msdp peer 198.51.100.9")
    assert change.warning
    change = build_change(MSDP, "peer", "", "delete", {"vrf": "default", "address": _PEER}, {})
    assert change.lines == ("no ip msdp peer 198.51.100.9",)
    for protocol in PROTOCOLS:
        for scope in protocol.scopes:
            assert not scope.create
            if not (protocol is MSDP and scope.key == "peer"):
                assert scope.delete is None
    with pytest.raises(ValueError, match="not made from here"):
        build_change(MSDP, "peer", "", "create", {"vrf": "default", "address": _PEER}, {})
    with pytest.raises(ValueError, match="not deleted from here"):
        build_change(PIM, "interface", "", "delete", _IDENT["interface"], {})


# ---- refusals ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("protocol", "scope", "ident", "setting", "values", "message"),
    [
        # wrong address family
        (PIM, "vrf", {}, "rp_group", {"address": "2001:db8:1::10"}, "IPv4 address"),
        (PIM6, "vrf", {}, "rp_group", {"address": "192.0.2.10"}, "IPv6 address"),
        (PIM6, "vrf", {}, "rp_group", {"address": "2001:db8:1::10", "group": "224.0.0.0/4"},
         "IPv6 network"),
        (MSDP, "peer", {"address": _PEER}, "shutdown", {"peer": "2001:db8:1::2"}, "IPv4 address"),
        (MSDP, "peer", {"address": "2001:db8:1::2"}, "shutdown", {"peer": _PEER}, "IPv4 address"),
        # not a multicast group, or a multicast address where a router address goes
        (PIM, "vrf", {}, "ssm_range", {"group": "192.0.2.0/24"}, "not a multicast group"),
        (PIM, "vrf", {}, "rp_group", {"address": "239.1.1.1"}, "not an address a router"),
        # out of range
        (PIM, "interface", {"interface": "Vlan10"}, "dr_priority", {"priority": "0"},
         "from 1 to 4294967295"),
        (PIM, "interface", {"interface": "Vlan10"}, "hello_interval", {"milliseconds": "999"},
         "from 1000 to 18724286"),
        (PIM, "vrf", {}, "bsr_candidate", {"source": "Vlan10", "hash_len": "33"}, "from 0 to 32"),
        (PIM, "vrf", {}, "register_rate_limit", {"rate": "65536"}, "from 1 to 65535"),
        (IGMP, "interface", {"interface": "Vlan10"}, "version", {"version": "1"}, "one of 2, 3"),
        (IGMP, "interface", {"interface": "Vlan10"}, "query_max_response_time",
         {"seconds": "26"}, "from 1 to 25"),
        (MSDP, "peer", {"address": _PEER}, "keepalive",
         {"peer": _PEER, "interval": "61", "timeout": "90"}, "from 1 to 60"),
        (MSDP, "vrf", {}, "sa_interval", {"seconds": "59"}, "from 60 to 65535"),
        (BFD, "global", {}, "interval", {"tx": "49", "rx": "50", "multiplier": "3"},
         "from 50 to 999"),
        (BFD, "global", {}, "startup_timer", {"seconds": "31"}, "from 0 to 30"),
        (BFD, "interface", {"interface": "Vlan10"}, "authentication",
         {"key_id": "256", "key": "k"}, "from 0 to 255"),
        # names and text
        (PIM, "vrf", {}, "register_policy", {"route_map": "rm;reload"}, "cannot contain"),
        (IGMP, "interface", {"interface": "Vlan10"}, "static_oif", {"route_map": "a b"},
         "letters, digits"),
        (IGMP, "interface", {"interface": "Vlan10"}, "static_oif_address",
         {"group": "192.0.2.1", "sender": ""}, "not a multicast group"),
        (IGMP, "interface", {"interface": "Vlan10"}, "join_group_address",
         {"group": "224.0.0.5", "sender": ""}, "kept for routers"),
        (MSDP, "peer", {"address": _PEER}, "description", {"peer": _PEER, "text": "x;y"},
         "cannot contain"),
        (MSDP, "peer", {"address": _PEER}, "password", {"peer": _PEER, "password": "pw;1"},
         "without spaces"),
        # management VRF and interfaces NXray never changes
        (PIM, "vrf", {"vrf": "management"}, "bfd", {}, "keeps the VRF name"),
        (MSDP, "vrf", {"vrf": "management"}, "flush_routes", {}, "keeps the VRF name"),
        (PIM, "interface", {"interface": "mgmt0"}, "sparse_mode", {}, "front-panel port"),
        (IGMP, "interface", {"interface": "Vlan300"}, "version", {"version": "3"},
         "VLANs 1 to 254"),
        (PIM, "vrf", {}, "register_source", {"source": "mgmt0"}, "front-panel port"),
        # an MSDP peer is removed by deleting it
        (MSDP, "vrf", {}, "peer", {"peer": _PEER, "source": "Vlan10"}, "cannot be removed"),
    ],
)  # fmt: skip
def test_refusals(
    protocol: Protocol,
    scope: str,
    ident: dict[str, str],
    setting: str,
    values: dict[str, str],
    message: str,
) -> None:
    action = "remove" if message == "cannot be removed" else "set"
    with pytest.raises(ValueError, match=message):
        build_change(protocol, scope, setting, action, ident, values)
