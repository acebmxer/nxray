"""The Routing policy page (app/protocols_policy.py): route-maps, prefix lists
and key chains, parsed from output recorded on cisco-25gb (NX-OS 9.3(16)),
and the exact lines every change sends."""

from __future__ import annotations

import pytest

from app.protocols import ProtocolChange, build_change
from app.protocols_policy import (
    POLICY,
    POLICY_COMMANDS,
    PROTOCOLS,
    check_prefix_entry,
    parse_policy,
)
from tests.conftest import load_fixture


def _recorded() -> list[dict]:
    return [
        load_fixture("show_route-map"),
        load_fixture("show_ip_prefix-list"),
        load_fixture("show_ipv6_prefix-list"),
        load_fixture("show_key_chain"),
    ]


def _change(
    scope: str,
    setting: str,
    action: str,
    ident: dict[str, str],
    values: dict[str, str] | None = None,
) -> ProtocolChange:
    return build_change(POLICY, scope, setting, action, ident, values or {})


ENTRY = {"name": "lab-rm", "seq": "10", "action": "permit"}
ENTER = "route-map lab-rm permit 10"
KEY = {"chain": "lab-kc", "key": "1"}

# ---- the protocol ----------------------------------------------------------------


def test_policy_is_the_only_protocol_and_needs_no_feature() -> None:
    assert PROTOCOLS == (POLICY,)
    assert POLICY.key == "policy"
    assert POLICY.name == "Routing policy"
    assert POLICY.features == ()
    assert (
        POLICY.commands
        == POLICY_COMMANDS
        == (
            "show route-map",
            "show ip prefix-list",
            "show ipv6 prefix-list",
            "show key chain",
        )
    )
    assert POLICY.parse is parse_policy


# ---- reading -----------------------------------------------------------------


def test_route_map_entry_from_recorded_output() -> None:
    view = parse_policy(_recorded())
    (entry,) = view.of("route_map_entry")
    assert entry.ident == {"name": "nxprobe-rm", "seq": "10", "action": "permit"}
    assert entry.title == "nxprobe-rm permit 10"
    assert dict(entry.facts) == {
        "Match": "ip address prefix-lists nxprobe-pl",
        "Set": "metric 100",
    }
    assert entry.values["match_ip_prefix"] == {"ip_prefix_list": "nxprobe-pl"}
    assert entry.values["set_metric"] == {
        "metric": "100",
        "delay": "",
        "reliability": "",
        "load": "",
        "mtu": "",
    }
    (whole,) = view.of("route_map")
    assert whole.ident == {"name": "nxprobe-rm"}
    assert dict(whole.facts) == {"Entries": "1"}


def test_prefix_lists_from_recorded_output() -> None:
    view = parse_policy(_recorded())
    assert [i.ident for i in view.of("ipv4_prefix_list")] == [{"name": "nxprobe-pl"}]
    assert [i.ident for i in view.of("ipv6_prefix_list")] == [{"name": "nxprobe-pl6"}]
    # The lists' forms are always offered, one place for each family.
    assert [i.ident for i in view.of("ipv4_prefix_lists")] == [{}]
    assert [i.ident for i in view.of("ipv6_prefix_lists")] == [{}]
    prefix_table = next(t for t in view.tables if t.title == "Prefix lists")
    assert prefix_table.rows == (
        ("IPv4", "nxprobe-pl", "5", "permit", "192.0.2.0/24 le 32"),
        ("IPv6", "nxprobe-pl6", "5", "permit", "2001:db8::/32 le 128"),
    )


def test_key_chain_from_recorded_output_never_shows_the_key() -> None:
    view = parse_policy(_recorded())
    (chain,) = view.of("key_chain")
    assert chain.ident == {"chain": "nxprobe-kc"}
    assert dict(chain.facts) == {"Keys": "1"}
    (key,) = view.of("key")
    assert key.ident == {"chain": "nxprobe-kc", "key": "1"}
    assert dict(key.facts) == {"Accepted now": "yes", "Sent now": "yes"}
    key_table = next(t for t in view.tables if t.title == "Key chains")
    assert key_table.columns == ("Key chain", "Key", "Accepted now", "Sent now")
    assert key_table.rows == (("nxprobe-kc", "1", "yes", "yes"),)
    secret = load_fixture("show_key_chain")["TABLE_keychain"]["ROW_keychain"]["TABLE_key"][
        "ROW_key"
    ]["key_string"]
    assert secret not in repr(view)


def test_route_map_table_from_recorded_output() -> None:
    view = parse_policy(_recorded())
    table = next(t for t in view.tables if t.title == "Route-maps")
    assert table.rows == (
        ("nxprobe-rm", "10", "permit", "ip address prefix-lists nxprobe-pl", "metric 100"),
    )


def test_nothing_configured_reads_as_empty() -> None:
    # "show key chain" answers {} when there is none; the others print nothing.
    view = parse_policy([{}, {}, {}, {}])
    assert view.of("route_map_entry") == []
    assert view.of("key_chain") == []
    assert [t.rows for t in view.tables] == [(), (), ()]
    assert parse_policy([]).tables == view.tables


def test_many_entries_and_every_clause_prefill_their_settings() -> None:
    # Shaped after the text "show route-map" prints; only the first two
    # clauses of entry 10 were seen live.
    body = {
        "TABLE_rmap": {
            "ROW_rmap": [
                {
                    "name": "lab-rm",
                    "action": "permit",
                    "seq": 10,
                    "TABLE_rmap_match": {
                        "ROW_rmap_match": [
                            {"match_type": "ip address prefix-lists", "match_stmt": "pl4"},
                            {"match_type": "ipv6 address prefix-lists", "match_stmt": "pl6"},
                            {"match_type": "ip next-hop prefix-lists", "match_stmt": "nh4"},
                            {"match_type": "ipv6 next-hop prefix-lists", "match_stmt": "nh6"},
                            {"match_type": "interface", "match_stmt": "Eth1/54"},
                            {"match_type": "tag", "match_stmt": "7"},
                            {"match_type": "metric", "match_stmt": "20 +- 5"},
                            {"match_type": "route-type", "match_stmt": "external"},
                            {"match_type": "as-path (as-path filter):", "match_stmt": "ap1"},
                            {
                                "match_type": "community (community-list filter):",
                                "match_stmt": "c1 exact-match",
                            },
                        ]
                    },
                    "TABLE_rmap_set": {
                        "ROW_rmap_set": [
                            {"set_type": "metric", "set_stmt": "100 10 255 1 1500"},
                            {"set_type": "metric-type", "set_stmt": "type-1"},
                            {"set_type": "tag", "set_stmt": "33"},
                            {"set_type": "local-preference", "set_stmt": "200"},
                            {"set_type": "weight", "set_stmt": "50"},
                            {"set_type": "origin", "set_stmt": "incomplete"},
                            {"set_type": "as-path prepend", "set_stmt": "65001 65001"},
                            {"set_type": "community", "set_stmt": "65001:100 additive"},
                            {"set_type": "ip next-hop", "set_stmt": "192.0.2.9"},
                            {"set_type": "ipv6 next-hop", "set_stmt": "2001:db8::9"},
                            {"set_type": "distance", "set_stmt": "20 200 220"},
                            {"set_type": "level", "set_stmt": "level-2"},
                        ]
                    },
                },
                {
                    "name": "lab-rm",
                    "action": "deny",
                    "seq": 20,
                    "TABLE_rmap_set": {
                        "ROW_rmap_set": [
                            {"set_type": "as-path prepend last-as", "set_stmt": "3"},
                            {"set_type": "community", "set_stmt": "no-export"},
                            {"set_type": "distance", "set_stmt": "150"},
                        ]
                    },
                },
                {"name": "other-rm", "action": "permit", "seq": 5},
            ]
        }
    }
    view = parse_policy([body, {}, {}, {}])
    first, second, third = view.of("route_map_entry")
    assert first.values == {
        "match_ip_prefix": {"ip_prefix_list": "pl4"},
        "match_ipv6_prefix": {"ipv6_prefix_list": "pl6"},
        "match_ip_next_hop": {"ip_next_hop_list": "nh4"},
        "match_ipv6_next_hop": {"ipv6_next_hop_list": "nh6"},
        "match_interface": {"match_interface": "Ethernet1/54"},
        "match_tag": {"match_tag": "7"},
        "match_metric": {"match_metric": "20", "match_deviation": "5"},
        "match_route_type": {"route_type": "external"},
        "match_as_path": {"as_path_list": "ap1"},
        "match_community": {"community_list": "c1", "exact_match": "exact-match"},
        "set_metric": {
            "metric": "100",
            "delay": "10",
            "reliability": "255",
            "load": "1",
            "mtu": "1500",
        },
        "set_metric_type": {"metric_type": "type-1"},
        "set_tag": {"tag": "33"},
        "set_local_preference": {"local_preference": "200"},
        "set_weight": {"weight": "50"},
        "set_origin": {"origin": "incomplete"},
        "set_as_path_prepend": {
            "prepend_1": "65001",
            "prepend_2": "65001",
            "prepend_3": "",
            "prepend_4": "",
        },
        "set_community": {
            "community_as": "65001",
            "community_value": "100",
            "additive": "additive",
        },
        "set_ip_next_hop": {"ip_next_hop": "192.0.2.9"},
        "set_ipv6_next_hop": {"ipv6_next_hop": "2001:db8::9"},
        "set_distance_bgp": {
            "distance_external": "20",
            "distance_internal": "200",
            "distance_local": "220",
        },
        "set_level": {"level": "level-2"},
    }
    assert second.ident == {"name": "lab-rm", "seq": "20", "action": "deny"}
    assert second.values == {
        "set_as_path_prepend_last_as": {"last_as": "3"},
        "set_community_well_known": {"well_known": "no-export", "additive": ""},
        "set_distance": {"distance": "150"},
    }
    assert third.values == {}
    assert dict(third.facts) == {"Match": "every route", "Set": "nothing"}
    assert [(i.ident["name"], dict(i.facts)) for i in view.of("route_map")] == [
        ("lab-rm", {"Entries": "2"}),
        ("other-rm", {"Entries": "1"}),
    ]


def test_many_prefix_list_entries_and_keys() -> None:
    ipv4 = {
        "TABLE_ip_pfl": {
            "ROW_ip_pfl": [
                {"name": "a", "seq": 5, "action": "permit", "rule": "192.0.2.0/24"},
                {"name": "a", "seq": 10, "action": "deny", "rule": "0.0.0.0/0 le 32"},
                {"name": "b", "seq": 5, "action": "permit", "rule": "198.51.100.0/24 ge 25"},
            ]
        }
    }
    keys = {
        "TABLE_keychain": {
            "ROW_keychain": [
                {
                    "chain_name": "kc1",
                    "TABLE_key": {
                        "ROW_key": [
                            {"key_id": 1, "accept_valid": "true", "send_valid": "false"},
                            {"key_id": 2, "accept_valid": "false", "send_valid": "false"},
                        ]
                    },
                },
                {"chain_name": "empty-kc"},
            ]
        }
    }
    view = parse_policy([{}, ipv4, {}, keys])
    assert [i.ident["name"] for i in view.of("ipv4_prefix_list")] == ["a", "b"]
    assert view.of("ipv6_prefix_list") == []
    assert [i.ident for i in view.of("key")] == [
        {"chain": "kc1", "key": "1"},
        {"chain": "kc1", "key": "2"},
    ]
    key_table = next(t for t in view.tables if t.title == "Key chains")
    assert key_table.rows == (
        ("kc1", "1", "yes", "no"),
        ("kc1", "2", "no", "no"),
        ("empty-kc", "", "", ""),
    )


# ---- route-map entries -----------------------------------------------------------


def test_route_map_entry_create_and_delete() -> None:
    made = _change("route_map_entry", "", "create", ENTRY)
    assert made.lines == (ENTER,)
    gone = _change("route_map_entry", "", "delete", {**ENTRY, "action": "deny"})
    assert gone.lines == ("no route-map lab-rm deny 10",)
    assert gone.warning


def test_whole_route_map_delete_and_it_is_not_made_from_here() -> None:
    assert _change("route_map", "", "delete", {"name": "lab-rm"}).lines == ("no route-map lab-rm",)
    with pytest.raises(ValueError, match="not made from here"):
        _change("route_map", "", "create", {"name": "lab-rm"})


ENTRY_SETTINGS = [
    ("description", {"description": "lab redistribution"}, "description lab redistribution",
     "no description"),
    ("match_ip_prefix", {"ip_prefix_list": "pl4"}, "match ip address prefix-list pl4", None),
    ("match_ipv6_prefix", {"ipv6_prefix_list": "pl6"}, "match ipv6 address prefix-list pl6",
     None),
    ("match_ip_next_hop", {"ip_next_hop_list": "nh4"}, "match ip next-hop prefix-list nh4",
     None),
    ("match_ipv6_next_hop", {"ipv6_next_hop_list": "nh6"},
     "match ipv6 next-hop prefix-list nh6", None),
    ("match_interface", {"match_interface": "Vlan10"}, "match interface Vlan10", None),
    ("match_tag", {"match_tag": "7"}, "match tag 7", None),
    ("match_metric", {"match_metric": "20"}, "match metric 20", None),
    ("match_route_type", {"route_type": "nssa-external"}, "match route-type nssa-external",
     None),
    ("match_as_path", {"as_path_list": "ap1"}, "match as-path ap1", None),
    ("match_community", {"community_list": "c1"}, "match community c1", None),
    ("set_metric", {"metric": "100"}, "set metric 100", None),
    ("set_metric_type", {"metric_type": "type-1"}, "set metric-type type-1", None),
    ("set_tag", {"tag": "33"}, "set tag 33", None),
    ("set_local_preference", {"local_preference": "200"}, "set local-preference 200", None),
    ("set_weight", {"weight": "65535"}, "set weight 65535", None),
    ("set_origin", {"origin": "igp"}, "set origin igp", None),
    ("set_as_path_prepend", {"prepend_1": "65001"}, "set as-path prepend 65001",
     "no set as-path prepend"),
    ("set_as_path_prepend_last_as", {"last_as": "2"}, "set as-path prepend last-as 2",
     "no set as-path prepend last-as"),
    ("set_community", {"community_as": "65001", "community_value": "100"},
     "set community 65001:100", "no set community"),
    ("set_community_well_known", {"well_known": "no-export"}, "set community no-export",
     "no set community"),
    ("set_community_none", {}, "set community none", "no set community"),
    ("set_ip_next_hop", {"ip_next_hop": "192.0.2.9"}, "set ip next-hop 192.0.2.9", None),
    ("set_ipv6_next_hop", {"ipv6_next_hop": "2001:db8::9"}, "set ipv6 next-hop 2001:db8::9",
     None),
    ("set_distance", {"distance": "150"}, "set distance 150", "no set distance"),
    ("set_distance_bgp",
     {"distance_external": "20", "distance_internal": "200", "distance_local": "220"},
     "set distance 20 200 220", "no set distance"),
    ("set_level", {"level": "level-1-2"}, "set level level-1-2", None),
    ("continue", {"continue_seq": "30"}, "continue 30", "no continue"),
]  # fmt: skip


@pytest.mark.parametrize(("setting", "values", "line", "removal"), ENTRY_SETTINGS)
def test_every_route_map_setting_sets_and_removes(
    setting: str, values: dict[str, str], line: str, removal: str | None
) -> None:
    assert _change("route_map_entry", setting, "set", ENTRY, values).lines == (ENTER, line)
    removed = _change("route_map_entry", setting, "remove", ENTRY, values)
    assert removed.lines == (ENTER, removal or f"no {line}")


def test_every_route_map_setting_is_tested() -> None:
    scope = POLICY.scope("route_map_entry")
    assert scope is not None
    assert {s.key for s in scope.settings} == {row[0] for row in ENTRY_SETTINGS}


def test_route_map_settings_optional_parts() -> None:
    def line(setting: str, values: dict[str, str]) -> str:
        return _change("route_map_entry", setting, "set", ENTRY, values).lines[-1]

    assert line("match_metric", {"match_metric": "20", "match_deviation": "5"}) == (
        "match metric 20 +- 5"
    )
    assert line("match_community", {"community_list": "c1", "exact_match": "on"}) == (
        "match community c1 exact-match"
    )
    assert line(
        "set_metric",
        {"metric": "100000", "delay": "10", "reliability": "255", "load": "1", "mtu": "1500"},
    ) == ("set metric 100000 10 255 1 1500")
    # The EIGRP parts go in all together or not at all.
    assert line("set_metric", {"metric": "100", "delay": "10"}) == "set metric 100"
    assert line(
        "set_as_path_prepend",
        {"prepend_1": "65001", "prepend_2": "65001", "prepend_3": "65001", "prepend_4": "1.10"},
    ) == ("set as-path prepend 65001 65001 65001 1.10")
    assert line(
        "set_community", {"community_as": "0", "community_value": "65535", "additive": "on"}
    ) == ("set community 0:65535 additive")
    assert line("set_community_well_known", {"well_known": "local-AS", "additive": "on"}) == (
        "set community local-AS additive"
    )
    assert line("match_interface", {"match_interface": "port-channel5"}) == (
        "match interface port-channel5"
    )


@pytest.mark.parametrize(
    ("setting", "values", "message"),
    [
        ("set_ip_next_hop", {"ip_next_hop": "2001:db8::9"}, "IPv4"),
        ("set_ipv6_next_hop", {"ipv6_next_hop": "192.0.2.9"}, "IPv6"),
        ("set_ip_next_hop", {"ip_next_hop": "224.0.0.5"}, "not an address"),
        ("set_weight", {"weight": "65536"}, "0 to 65535"),
        ("set_distance", {"distance": "0"}, "1 to 255"),
        ("set_distance", {"distance": "256"}, "1 to 255"),
        ("set_tag", {"tag": "4294967296"}, "0 to 4294967295"),
        ("set_tag", {"tag": "-1"}, "whole number"),
        ("set_as_path_prepend_last_as", {"last_as": "11"}, "1 to 10"),
        ("set_community", {"community_as": "65536", "community_value": "1"}, "0 to 65535"),
        ("set_as_path_prepend", {"prepend_1": "0"}, "AS number"),
        ("set_metric_type", {"metric_type": "type-3"}, "one of"),
        ("match_route_type", {"route_type": "static"}, "one of"),
        ("match_ip_prefix", {"ip_prefix_list": "pl;reload"}, "cannot contain"),
        ("match_ip_prefix", {"ip_prefix_list": "pl 4"}, "letters, digits"),
        ("match_ip_prefix", {"ip_prefix_list": ""}, "needed"),
        ("match_interface", {"match_interface": "mgmt0"}, "Interface"),
        ("match_interface", {"match_interface": "Vlan300"}, "1 to 254"),
        ("description", {"description": "x" * 91}, "at most 90"),
        ("description", {"description": "why?"}, "cannot contain"),
        ("continue", {"continue_seq": "65536"}, "1 to 65535"),
    ],
)
def test_route_map_settings_refuse_bad_values(
    setting: str, values: dict[str, str], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _change("route_map_entry", setting, "set", ENTRY, values)


@pytest.mark.parametrize(
    ("ident", "message"),
    [
        ({**ENTRY, "seq": "0"}, "1 to 65535"),
        ({**ENTRY, "seq": "65536"}, "1 to 65535"),
        ({**ENTRY, "action": "allow"}, "one of permit, deny"),
        ({**ENTRY, "name": "rm;no feature bgp"}, "cannot contain"),
        ({**ENTRY, "name": "-rm"}, "starting with a letter"),
        ({**ENTRY, "name": "r" * 64}, "1 to 63"),
    ],
)
def test_route_map_entry_refuses_bad_identity(ident: dict[str, str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _change("route_map_entry", "", "create", ident)


# ---- prefix lists --------------------------------------------------------------


def test_ipv4_prefix_list_entry_exactly_as_the_probe_sent_it() -> None:
    values = {
        "list": "nxprobe-pl",
        "seq": "5",
        "action": "permit",
        "prefix": "192.0.2.0/24",
        "le": "32",
    }
    made = _change("ipv4_prefix_lists", "entry", "set", {}, values)
    assert made.lines == ("ip prefix-list nxprobe-pl seq 5 permit 192.0.2.0/24 le 32",)
    removed = _change("ipv4_prefix_lists", "entry", "remove", {}, values)
    assert removed.lines == ("no ip prefix-list nxprobe-pl seq 5 permit 192.0.2.0/24 le 32",)


def test_ipv6_prefix_list_entry_exactly_as_the_probe_sent_it() -> None:
    values = {
        "list": "nxprobe-pl6",
        "seq": "5",
        "action": "permit",
        "prefix": "2001:db8::/32",
        "le": "128",
    }
    made = _change("ipv6_prefix_lists", "entry", "set", {}, values)
    assert made.lines == ("ipv6 prefix-list nxprobe-pl6 seq 5 permit 2001:db8::/32 le 128",)
    removed = _change("ipv6_prefix_lists", "entry", "remove", {}, values)
    assert removed.lines == ("no ipv6 prefix-list nxprobe-pl6 seq 5 permit 2001:db8::/32 le 128",)


def test_prefix_list_entry_lengths_are_optional() -> None:
    base = {"list": "a", "seq": "10", "action": "deny", "prefix": "198.51.100.0/24"}
    assert _change("ipv4_prefix_lists", "entry", "set", {}, base).lines == (
        "ip prefix-list a seq 10 deny 198.51.100.0/24",
    )
    both = {**base, "ge": "25", "le": "30"}
    assert _change("ipv4_prefix_lists", "entry", "set", {}, both).lines == (
        "ip prefix-list a seq 10 deny 198.51.100.0/24 ge 25 le 30",
    )


def test_prefix_list_descriptions() -> None:
    values = {"list": "a", "description": "lab networks"}
    assert _change("ipv4_prefix_lists", "description", "set", {}, values).lines == (
        "ip prefix-list a description lab networks",
    )
    assert _change("ipv4_prefix_lists", "description", "remove", {}, values).lines == (
        "no ip prefix-list a description",
    )
    assert _change("ipv6_prefix_lists", "description", "set", {}, values).lines == (
        "ipv6 prefix-list a description lab networks",
    )
    assert _change("ipv6_prefix_lists", "description", "remove", {}, values).lines == (
        "no ipv6 prefix-list a description",
    )


def test_whole_prefix_list_delete() -> None:
    assert _change("ipv4_prefix_list", "", "delete", {"name": "nxprobe-pl"}).lines == (
        "no ip prefix-list nxprobe-pl",
    )
    assert _change("ipv6_prefix_list", "", "delete", {"name": "nxprobe-pl6"}).lines == (
        "no ipv6 prefix-list nxprobe-pl6",
    )
    with pytest.raises(ValueError, match="not made from here"):
        _change("ipv4_prefix_list", "", "create", {"name": "a"})


@pytest.mark.parametrize(
    ("scope", "values", "message"),
    [
        ("ipv4_prefix_lists", {"prefix": "2001:db8::/32"}, "IPv4 network"),
        ("ipv6_prefix_lists", {"prefix": "192.0.2.0/24"}, "IPv6 network"),
        ("ipv4_prefix_lists", {"prefix": "192.0.2.1/24"}, "did you mean 192.0.2.0/24"),
        ("ipv4_prefix_lists", {"prefix": "192.0.2.0"}, "prefix length"),
        ("ipv4_prefix_lists", {"le": "33"}, "1 to 32"),
        ("ipv6_prefix_lists", {"prefix": "2001:db8::/32", "le": "129"}, "1 to 128"),
        ("ipv4_prefix_lists", {"seq": "0"}, "1 to 4294967294"),
        ("ipv4_prefix_lists", {"action": "allow"}, "one of permit, deny"),
        ("ipv4_prefix_lists", {"list": "a;b"}, "cannot contain"),
    ],
)
def test_prefix_list_entry_refuses_bad_values(
    scope: str, values: dict[str, str], message: str
) -> None:
    base = {"list": "a", "seq": "5", "action": "permit", "prefix": "192.0.2.0/24"}
    with pytest.raises(ValueError, match=message):
        _change(scope, "entry", "set", {}, {**base, **values})


def test_check_prefix_entry_accepts_lengths_in_order() -> None:
    assert check_prefix_entry("192.0.2.0/24") == ("192.0.2.0/24", "", "")
    assert check_prefix_entry("192.0.2.0/24", "", "32") == ("192.0.2.0/24", "", "32")
    assert check_prefix_entry("192.0.2.0/24", "25", "") == ("192.0.2.0/24", "25", "")
    assert check_prefix_entry(" 192.0.2.0/24 ", "26", "26") == ("192.0.2.0/24", "26", "26")
    assert check_prefix_entry("2001:db8::/32", "48", "128") == ("2001:db8::/32", "48", "128")
    assert check_prefix_entry("0.0.0.0/0", "1", "32") == ("0.0.0.0/0", "1", "32")


@pytest.mark.parametrize(
    ("prefix", "ge", "le", "message"),
    [
        ("192.0.2.0/24", "24", "", "25 to 32"),
        ("192.0.2.0/24", "", "24", "25 to 32"),
        ("192.0.2.0/24", "", "33", "25 to 32"),
        ("2001:db8::/32", "", "129", "33 to 128"),
        ("192.0.2.0/24", "30", "28", "cannot be more than"),
        ("192.0.2.0/24", "x", "", "whole number"),
        ("192.0.2.1/24", "", "", "not a network"),
        ("nowhere", "", "", "not a network"),
    ],
)
def test_check_prefix_entry_refuses(prefix: str, ge: str, le: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        check_prefix_entry(prefix, ge, le)


# ---- key chains --------------------------------------------------------------------


def test_key_chain_create_and_delete() -> None:
    assert _change("key_chain", "", "create", {"chain": "lab-kc"}).lines == ("key chain lab-kc",)
    assert _change("key_chain", "", "delete", {"chain": "lab-kc"}).lines == ("no key chain lab-kc",)


def test_key_create_and_delete() -> None:
    assert _change("key", "", "create", KEY).lines == ("key chain lab-kc", "key 1")
    assert _change("key", "", "delete", KEY).lines == ("key chain lab-kc", "no key 1")


def test_key_string_as_the_probe_sent_it_and_masked() -> None:
    change = _change("key", "key_string", "set", KEY, {"key_string": "nxprobekey1"})
    assert change.lines == ("key chain lab-kc", "key 1", "key-string 0 nxprobekey1")
    assert change.labels == ("key chain lab-kc", "key 1", "key-string 0 ***")
    assert "nxprobekey1" not in change.describe
    # Removing needs no key typed in: it is a setting of its own.
    removed = _change("key", "remove_key_string", "remove", KEY, {})
    assert removed.lines == ("key chain lab-kc", "key 1", "no key-string")
    with pytest.raises(ValueError, match="only removed"):
        _change("key", "remove_key_string", "set", KEY, {})
    with pytest.raises(ValueError, match="cannot be removed"):
        _change("key", "key_string", "remove", KEY, {"key_string": "nxprobekey1"})


def test_cryptographic_algorithm() -> None:
    values = {"algorithm": "HMAC-SHA-256"}
    assert _change("key", "cryptographic_algorithm", "set", KEY, values).lines[-1] == (
        "cryptographic-algorithm HMAC-SHA-256"
    )
    assert _change("key", "cryptographic_algorithm", "remove", KEY, values).lines[-1] == (
        "no cryptographic-algorithm HMAC-SHA-256"
    )
    with pytest.raises(ValueError, match="one of"):
        _change("key", "cryptographic_algorithm", "set", KEY, {"algorithm": "SHA-1"})


START = {
    "start_hour": "00",
    "start_minute": "00",
    "start_second": "00",
    "start_month": "Jan",
    "start_day": "1",
    "start_year": "2026",
}
END = {
    "end_hour": "23",
    "end_minute": "59",
    "end_second": "59",
    "end_month": "Dec",
    "end_day": "31",
    "end_year": "2026",
}


@pytest.mark.parametrize("word", ["accept", "send"])
def test_lifetimes(word: str) -> None:
    def line(setting: str, values: dict[str, str]) -> str:
        return _change("key", f"{word}_lifetime_{setting}", "set", KEY, values).lines[-1]

    assert line("infinite", START) == f"{word}-lifetime 00:00:00 Jan 1 2026 infinite"
    assert line("until", {**START, **END}) == (
        f"{word}-lifetime 00:00:00 Jan 1 2026 23:59:59 Dec 31 2026"
    )
    assert line("duration", {**START, "duration": "86400"}) == (
        f"{word}-lifetime 00:00:00 Jan 1 2026 duration 86400"
    )
    assert line("infinite", {**START, "local": "on"}) == (
        f"{word}-lifetime local 00:00:00 Jan 1 2026 infinite"
    )
    removed = _change("key", f"{word}_lifetime", "remove", KEY, {})
    assert removed.lines == ("key chain lab-kc", "key 1", f"no {word}-lifetime")
    with pytest.raises(ValueError, match="only removed"):
        _change("key", f"{word}_lifetime", "set", KEY, {})
    for setting in ("infinite", "until", "duration"):
        with pytest.raises(ValueError, match="cannot be removed"):
            _change("key", f"{word}_lifetime_{setting}", "remove", KEY, {**START, **END})


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"start_hour": "24"}, "one of"),
        ({"start_hour": "0"}, "one of"),
        ({"start_minute": "60"}, "one of"),
        ({"start_second": "7"}, "one of"),
        ({"start_month": "January"}, "one of"),
        ({"start_day": "32"}, "1 to 31"),
        ({"start_year": "1999"}, "2000 to 2035"),
        ({"start_year": "26"}, "2000 to 2035"),
        ({"start_day": ""}, "needed"),
        ({"duration": "0"}, "1 to 2147483646"),
        ({"duration": "2147483647"}, "1 to 2147483646"),
    ],
)
def test_lifetimes_refuse_bad_times(values: dict[str, str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _change(
            "key", "accept_lifetime_duration", "set", KEY, {**START, "duration": "60", **values}
        )


@pytest.mark.parametrize(
    ("ident", "values", "message"),
    [
        ({**KEY, "key": "65536"}, {}, "0 to 65535"),
        ({**KEY, "chain": "kc;reload"}, {}, "cannot contain"),
        (KEY, {"key_string": "two words"}, "without spaces"),
        (KEY, {"key_string": "x" * 64}, "1 to 63"),
        (KEY, {"key_string": ""}, "needed"),
    ],
)
def test_keys_refuse_bad_values(
    ident: dict[str, str], values: dict[str, str], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _change("key", "key_string", "set", ident, values)


def test_every_key_setting_is_tested() -> None:
    scope = POLICY.scope("key")
    assert scope is not None
    lifetimes = {
        f"{word}_lifetime{kind}"
        for word in ("accept", "send")
        for kind in ("", "_infinite", "_until", "_duration")
    }
    assert {s.key for s in scope.settings} == {
        "key_string",
        "remove_key_string",
        "cryptographic_algorithm",
        *lifetimes,
    }


def test_unknown_scope_and_setting_are_refused() -> None:
    with pytest.raises(ValueError, match="no 'vrf' settings"):
        _change("vrf", "", "create", {})
    with pytest.raises(ValueError, match="no setting"):
        _change("route_map_entry", "set_vrf", "set", ENTRY, {})
