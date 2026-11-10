"""VXLAN (app/vxlan.py): reading ``show nve`` and the configuration text, the lines
every setting sends, and the values NXray refuses."""

from __future__ import annotations

import pytest

from app.port_changes import (
    LIMITED_RULES,
    NVE_PERMIT,
    ROLE_VERSION,
    VXLAN_RULES,
    role_lines,
)
from app.vxlan import (
    VXLAN,
    build_vxlan_change,
    parse_vxlan,
    parse_vxlan_config,
)
from tests.conftest import load_fixture

CONFIG = """\
feature nv overlay
feature vn-segment-vlan-based
nv overlay evpn
fabric forwarding anycast-gateway-mac 2020.0000.00aa

vlan 10
  vn-segment 10010
vlan 20

vrf context tenant
  vni 50000
  address-family ipv4 unicast
    route-target both auto evpn

interface nve1
  no shutdown
  host-reachability protocol bgp
  source-interface loopback1
  member vni 10010
    suppress-arp
    mcast-group 239.1.1.1
  member vni 50000 associate-vrf

evpn
  vni 10010 l2
    rd auto
    route-target import 65000:10010
    route-target export auto
"""


def _bodies() -> list[dict]:
    return [
        load_fixture("show_nve_interface_doc"),
        load_fixture("show_nve_peers_doc"),
        load_fixture("show_nve_vni_doc"),
    ]


def _lines(scope: str, setting: str, action: str, ident: dict, values: dict) -> tuple[str, ...]:
    return build_vxlan_change(scope, setting, action, ident, values).lines


# ---- reading ---------------------------------------------------------------------


def test_parse_vxlan_config_as_a_tree() -> None:
    config = parse_vxlan_config(CONFIG)
    assert config.has("nv overlay evpn")
    assert config.children("vlan 10") == ["vn-segment 10010"]
    assert config.children("interface nve1", "member vni 10010") == [
        "suppress-arp",
        "mcast-group 239.1.1.1",
    ]
    assert config.children("evpn", "vni 10010 l2")[0] == "rd auto"
    assert not config.has("interface nve2")


def test_parse_vxlan_from_the_switch_and_the_configuration() -> None:
    view = parse_vxlan(_bodies(), parse_vxlan_config(CONFIG))
    nve = view.of("nve")
    assert [i.ident for i in nve] == [{"nve": "1"}]
    facts = dict(nve[0].facts)
    assert facts["State"] == "Up" and facts["Source address"] == "192.0.2.1"
    assert facts["Admin state"] == "on"
    assert "Host reachability through BGP" in facts["Turned on"]
    assert nve[0].values["source_interface"] == {"source": "loopback1"}

    assert [(i.ident["vlan"], i.values["vni"]) for i in view.of("vlan")] == [
        ("10", {"vni": "10010"})
    ]
    l2 = view.of("l2vni")
    assert [i.ident for i in l2] == [{"nve": "1", "vni": "10010"}]
    assert l2[0].values["mcast_group"] == {"group": "239.1.1.1"}
    assert "Suppress ARP" in dict(l2[0].facts)["Turned on"]
    assert dict(l2[0].facts)["State"] == "Up"
    assert [i.ident for i in view.of("l3vni")] == [{"nve": "1", "vni": "50000"}]

    evpn = view.of("evpn")[0]
    assert evpn.ident == {"vni": "10010"}
    assert evpn.values["rd"] == {"target": "auto"}
    assert evpn.values["rt_import"] == {"target": "65000:10010"}
    assert evpn.values["rt_export"] == {"target": "auto"}
    assert [i.ident for i in view.of("vrf")] == [{"vrf": "tenant"}]
    assert view.of("vrf")[0].values["vni"] == {"vni": "50000"}
    assert [i.ident for i in view.of("vrf_af")] == [{"vrf": "tenant", "af": "ipv4"}]
    assert view.notes == ("The EVPN control plane is on.",)

    peers, vnis = view.tables
    assert peers.rows[0] == ("nve1", "192.0.2.2", "Up", "CP", "01:12:44", "5254.0012.3456")
    assert peers.rows[1][2] == "Down"
    assert vnis.rows[0][:3] == ("nve1", "10010", "L2 [10]")


def test_parse_vxlan_without_config_says_so() -> None:
    view = parse_vxlan(_bodies(), None)
    assert view.notes and "does not let it read the VXLAN settings" in view.notes[0]
    assert [i.ident["nve"] for i in view.of("nve")] == ["1"]
    # The VNIs the switch lists are shown by type even without the configuration.
    assert [i.ident["vni"] for i in view.of("l2vni")] == ["10010"]
    assert [i.ident["vni"] for i in view.of("l3vni")] == ["50000"]
    assert view.of("vlan") == [] and view.of("evpn") == []


def test_parse_vxlan_tolerates_an_empty_answer() -> None:
    view = parse_vxlan([{}, {}, {}], parse_vxlan_config(""))
    assert view.instances == ()
    assert [len(t.rows) for t in view.tables] == [0, 0]
    assert view.notes == ("The EVPN control plane is off.",)
    assert parse_vxlan([], None).instances == ()


def test_a_single_interface_answer_without_a_table_is_read() -> None:
    view = parse_vxlan([{"interface": "nve1", "state": "Up"}, {}, {}], None)
    assert dict(view.of("nve")[0].facts)["State"] == "Up"


# ---- the lines -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("scope", "setting", "ident", "values", "lines"),
    [
        ("switch", "evpn", {}, {}, ("nv overlay evpn",)),
        (
            "switch",
            "anycast_mac",
            {},
            {"mac": "2020.0000.00AA"},
            ("fabric forwarding anycast-gateway-mac 2020.0000.00aa",),
        ),
        ("vlan", "vni", {"vlan": "10"}, {"vni": "10010"}, ("vlan 10", "vn-segment 10010")),
        (
            "nve",
            "source_interface",
            {"nve": "1"},
            {"source": "lo1"},
            ("interface nve1", "source-interface loopback1"),
        ),
        (
            "nve",
            "host_reachability",
            {"nve": "1"},
            {},
            ("interface nve1", "host-reachability protocol bgp"),
        ),
        ("nve", "advertise_vmac", {"nve": "1"}, {}, ("interface nve1", "advertise virtual-rmac")),
        ("nve", "admin_up", {"nve": "1"}, {}, ("interface nve1", "no shutdown")),
        ("nve", "admin_down", {"nve": "1"}, {}, ("interface nve1", "shutdown")),
        ("nve", "global_suppress_arp", {"nve": "1"}, {}, ("interface nve1", "global suppress-arp")),
        (
            "nve",
            "global_mcast",
            {"nve": "1"},
            {"group": "239.1.1.1", "layer": "L2"},
            ("interface nve1", "global mcast-group 239.1.1.1 L2"),
        ),
        (
            "l2vni",
            "suppress_arp",
            {"nve": "1", "vni": "10010"},
            {},
            ("interface nve1", "member vni 10010", "suppress-arp"),
        ),
        (
            "l2vni",
            "mcast_group",
            {"nve": "1", "vni": "10010"},
            {"group": "239.1.1.1"},
            ("interface nve1", "member vni 10010", "mcast-group 239.1.1.1"),
        ),
        (
            "l2vni",
            "ingress",
            {"nve": "1", "vni": "10010"},
            {},
            ("interface nve1", "member vni 10010", "ingress-replication protocol bgp"),
        ),
        (
            "evpn",
            "rd",
            {"vni": "10010"},
            {"target": "auto"},
            ("evpn", "vni 10010 l2", "rd auto"),
        ),
        (
            "evpn",
            "rt_import",
            {"vni": "10010"},
            {"target": "65000:10010"},
            ("evpn", "vni 10010 l2", "route-target import 65000:10010"),
        ),
        (
            "evpn",
            "rt_export",
            {"vni": "10010"},
            {"target": "192.0.2.1:10"},
            ("evpn", "vni 10010 l2", "route-target export 192.0.2.1:10"),
        ),
        ("vrf", "vni", {"vrf": "tenant"}, {"vni": "50000"}, ("vrf context tenant", "vni 50000")),
        (
            "vrf_af",
            "rt_both_auto",
            {"vrf": "tenant", "af": "ipv4"},
            {},
            ("vrf context tenant", "address-family ipv4 unicast", "route-target both auto evpn"),
        ),
        (
            "vrf_af",
            "rt_import",
            {"vrf": "tenant", "af": "ipv6"},
            {"target": "65000:50000"},
            (
                "vrf context tenant",
                "address-family ipv6 unicast",
                "route-target import 65000:50000 evpn",
            ),
        ),
    ],
)
def test_set_sends_one_line(scope, setting, ident, values, lines) -> None:  # type: ignore[no-untyped-def]
    assert _lines(scope, setting, "set", ident, values) == lines


def test_make_and_delete_places() -> None:
    assert _lines("nve", "", "create", {"nve": "1"}, {}) == ("interface nve1",)
    deleted = build_vxlan_change("nve", "", "delete", {"nve": "1"}, {})
    assert deleted.lines == ("no interface nve1",)
    assert "ends every VXLAN tunnel" in deleted.warning
    assert _lines("l2vni", "", "create", {"nve": "1", "vni": "10010"}, {}) == (
        "interface nve1",
        "member vni 10010",
    )
    assert _lines("l3vni", "", "create", {"nve": "1", "vni": "50000"}, {}) == (
        "interface nve1",
        "member vni 50000 associate-vrf",
    )
    assert _lines("l2vni", "", "delete", {"nve": "1", "vni": "10010"}, {}) == (
        "interface nve1",
        "no member vni 10010",
    )
    assert _lines("l3vni", "", "delete", {"nve": "1", "vni": "50000"}, {}) == (
        "interface nve1",
        "no member vni 50000 associate-vrf",
    )
    assert _lines("evpn", "", "create", {"vni": "10010"}, {}) == ("evpn", "vni 10010 l2")
    assert _lines("evpn", "", "delete", {"vni": "10010"}, {}) == ("evpn", "no vni 10010 l2")


def test_removing_a_setting_sends_its_no_form() -> None:
    assert _lines("switch", "evpn", "remove", {}, {}) == ("no nv overlay evpn",)
    assert _lines("vlan", "vni", "remove", {"vlan": "10"}, {"vni": "10010"}) == (
        "vlan 10",
        "no vn-segment 10010",
    )
    assert _lines("nve", "source_interface", "remove", {"nve": "1"}, {"source": "lo1"}) == (
        "interface nve1",
        "no source-interface loopback1",
    )
    assert _lines("evpn", "rd", "remove", {"vni": "10"}, {"target": "auto"}) == (
        "evpn",
        "vni 10 l2",
        "no rd auto",
    )


def test_turn_on_and_off_are_not_removed() -> None:
    with pytest.raises(ValueError, match="cannot be removed"):
        _lines("nve", "admin_up", "remove", {"nve": "1"}, {})


# ---- what is refused ---------------------------------------------------------------------


@pytest.mark.parametrize("vni", ["0", "16777216", "x", "", "10; reload", "-1"])
def test_bad_vnis_are_refused(vni: str) -> None:
    with pytest.raises(ValueError):
        _lines("vlan", "vni", "set", {"vlan": "10"}, {"vni": vni})
    with pytest.raises(ValueError):
        _lines("l2vni", "", "create", {"nve": "1", "vni": vni}, {})


@pytest.mark.parametrize("nve", ["0", "2", "x", ""])
def test_only_nve1_exists(nve: str) -> None:
    with pytest.raises(ValueError):
        _lines("nve", "", "create", {"nve": nve}, {})


@pytest.mark.parametrize(
    "target", ["", "bad", "65000", "65000:", "auto evpn", "1.2.3:4", "65000:10;reload"]
)
def test_bad_route_targets_are_refused(target: str) -> None:
    with pytest.raises(ValueError):
        _lines("evpn", "rt_import", "set", {"vni": "10010"}, {"target": target})


def test_other_bad_values_are_refused() -> None:
    for scope, setting, ident, values in (
        ("vlan", "vni", {"vlan": "4000"}, {"vni": "10"}),
        ("vlan", "vni", {"vlan": "abc"}, {"vni": "10"}),
        ("nve", "source_interface", {"nve": "1"}, {"source": "nonsense"}),
        ("nve", "global_mcast", {"nve": "1"}, {"group": "192.0.2.1", "layer": "L2"}),
        ("nve", "global_mcast", {"nve": "1"}, {"group": "239.1.1.1", "layer": "L9"}),
        ("l2vni", "mcast_group", {"nve": "1", "vni": "10"}, {"group": "10.0.0.1"}),
        ("switch", "anycast_mac", {}, {"mac": "not-a-mac"}),
        ("vrf", "vni", {"vrf": "default"}, {"vni": "50000"}),
        ("vrf", "vni", {"vrf": "bad vrf"}, {"vni": "50000"}),
        ("vrf_af", "rt_both_auto", {"vrf": "tenant", "af": "ipx"}, {}),
    ):
        with pytest.raises(ValueError):
            _lines(scope, setting, "set", ident, values)


def test_unknown_scope_setting_or_action_is_refused() -> None:
    with pytest.raises(ValueError):
        _lines("nothing", "x", "set", {}, {})
    with pytest.raises(ValueError):
        _lines("nve", "nothing", "set", {"nve": "1"}, {})
    with pytest.raises(ValueError):
        _lines("vlan", "vni", "create", {"vlan": "10"}, {})
    with pytest.raises(ValueError):
        _lines("vrf", "", "delete", {"vrf": "tenant"}, {})


# ---- the role ---------------------------------------------------------------------------


def test_every_setting_has_a_role_rule() -> None:
    assert ROLE_VERSION >= 20
    assert all(rule in LIMITED_RULES for rule in VXLAN_RULES)
    assert all(rule in role_lines(["Ethernet1/1"], "nxray") for rule in VXLAN_RULES)
    rules = " ".join(VXLAN_RULES)
    for part in (
        "conf t ; interface nve*",
        "conf t ; evpn*",
        "conf t ; vlan * ; vn-segment *",
        "conf t ; vrf context * ; vni *",
        "conf t ; nv overlay evpn",
        "show running-config vxlan",
    ):
        assert part in rules


def test_the_port_list_names_nve_only_when_asked() -> None:
    assert NVE_PERMIT not in role_lines(["Ethernet1/1"], "nxray")
    assert NVE_PERMIT in role_lines(["Ethernet1/1"], "nxray", nve=True)
    assert NVE_PERMIT == "permit interface nve1"


def test_the_page_needs_both_features() -> None:
    assert VXLAN.features == ("nve", "vnseg_vlan")
