"""Spanning tree (app/spanning_tree.py): parsing recorded switch output, the lines
every setting sends, and the values NXray refuses."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.port_changes import STP_RULES
from app.protocols import Field, Scope, Setting, check_value
from app.spanning_tree import (
    SPANNING_TREE,
    build_stp_change,
    expand_vlans,
    parse_spanning_tree,
    parse_stp_config,
    switch_port_names,
)
from tests.conftest import FIXTURES, load_fixture


def _config() -> str:
    # Hand-assembled from the lines the switch stored during the stage 16 probe
    # (Ethernet1/54, VLAN 250, the MST region); Ethernet1/53's lines are the same
    # shapes with other values, not recorded.
    return (FIXTURES / "show_running-config_spanning-tree.txt").read_text()


def _bodies() -> list[dict]:
    return [
        load_fixture("show_spanning-tree_summary"),
        load_fixture("show_spanning-tree_detail"),
        load_fixture("show_spanning-tree_mst_configuration"),
        load_fixture("show_vlan_brief"),
        load_fixture("show_interface_brief"),
    ]


# ---- reading ---------------------------------------------------------------------


def test_expand_vlans() -> None:
    assert expand_vlans("1-2,10,69") == [1, 2, 10, 69]
    assert expand_vlans("250") == [250]
    assert expand_vlans("all") == []


def test_parse_stp_config_sorts_the_lines() -> None:
    config = parse_stp_config(_config())
    assert config.vlans[250] == {
        "priority": "4096",
        "hello": "3",
        "forward": "20",
        "max_age": "30",
    }
    assert config.region == ["name lab-region", "revision 5", "instance 1 vlan 250"]
    assert config.ports["Ethernet1/54"][0] == "spanning-tree port-priority 64"
    assert set(config.ports) == {"Ethernet1/53", "Ethernet1/54"}
    assert config.switch == []


def test_parse_stp_config_switch_lines_and_off_vlans() -> None:
    config = parse_stp_config(
        "spanning-tree mode mst\n"
        "spanning-tree port type edge default\n"
        "no spanning-tree vlan 30-31\n"
        "spanning-tree mst 1 priority 8192\n"
        "spanning-tree vlan 1-2 priority 4096\n"
        "interface mgmt0\n"
        "  spanning-tree cost 5\n"
    )
    assert config.switch == ["spanning-tree mode mst", "spanning-tree port type edge default"]
    assert config.off_vlans == {30, 31}
    assert config.instances == {1: {"priority": "8192"}}
    assert config.vlans == {1: {"priority": "4096"}, 2: {"priority": "4096"}}
    assert config.ports == {}  # mgmt0 is never a spanning tree port


def test_switch_port_names_skips_routed_and_management() -> None:
    names = switch_port_names(load_fixture("show_interface_brief"))
    assert "Ethernet1/1" in names and "mgmt0" not in names
    routed = {"TABLE_interface": {"ROW_interface": [
        {"interface": "Ethernet1/54", "portmode": "routed"},
        {"interface": "port-channel43", "portmode": "trunk"},
        {"interface": "Vlan10"},
    ]}}  # fmt: skip
    assert switch_port_names(routed) == ["port-channel43"]


def test_parse_recorded_output_without_the_config() -> None:
    view = parse_spanning_tree(_bodies(), None)
    switch = view.of("switch")[0]
    facts = dict(switch.facts)
    assert facts["Mode"] == "rapid-pvst"
    assert facts["Root bridge for"] == "1-2,10,69,79,253-254"
    assert facts["Path cost method"] == "short"
    assert facts["Bridge Assurance"] == "on"
    assert switch.values["mode"] == {"mode": "rapid-pvst"}
    assert switch.values["pathcost"] == {"method": "short"}
    assert "bridge_assurance" in switch.values and "pvst_simulate" in switch.values
    assert "loopguard_default" not in switch.values
    # The note says why down ports are missing.
    assert any("does not let it read" in n for n in view.notes)
    assert any("only in mst mode" in n for n in view.notes)


def test_vlan_instances_from_the_trees() -> None:
    view = parse_spanning_tree(_bodies(), None)
    vlan1 = next(i for i in view.of("vlan") if i.ident == {"vlan": "1"})
    facts = dict(vlan1.facts)
    assert facts["This switch"] == "32769 0200.0000.0001"
    assert facts["Root port"] == "this switch is the root"
    assert facts["Hello / forward / max age"] == "2 / 15 / 20"
    assert vlan1.values == {}  # all defaults: nothing marked as set


def test_vlan_with_non_default_settings_is_prefilled() -> None:
    bodies = _bodies()
    bodies[1] = load_fixture("show_spanning-tree_vlan_250_detail")  # recorded in the probe
    bodies[3] = {"TABLE_vlanbriefxbrief": {"ROW_vlanbriefxbrief": {"vlanshowbr-vlanid": "250"}}}
    view = parse_spanning_tree(bodies, None)
    (vlan,) = view.of("vlan")
    assert vlan.values == {
        "priority": {"priority": "4096"},
        "hello": {"seconds": "3"},
        "forward": {"seconds": "20"},
        "max_age": {"seconds": "30"},
    }


def test_vlan_without_a_tree_says_so() -> None:
    bodies = _bodies()
    bodies[3] = {"TABLE_vlanbriefxbrief": {"ROW_vlanbriefxbrief": {"vlanshowbr-vlanid": "300"}}}
    (vlan,) = parse_spanning_tree(bodies, None).of("vlan")
    assert dict(vlan.facts)["Tree"].startswith("none")


def test_trees_and_ports_tables() -> None:
    view = parse_spanning_tree(_bodies(), None)
    trees, ports, _settings, problems = view.tables
    assert [row[0] for row in trees.rows] == ["VLAN 1", "VLAN 2"]
    assert trees.rows[0][3] == "this switch is the root"
    first = ports.rows[0]
    assert first[:4] == ("port-channel43", "VLAN 1", "designated", "forwarding")
    assert problems.rows == ()


def test_ports_in_trees_are_instances() -> None:
    view = parse_spanning_tree(_bodies(), None)
    names = [i.ident["port"] for i in view.of("port")]
    assert "port-channel43" in names and "Ethernet1/37" in names
    # Ports with nothing plugged in are listed too, so their settings can be changed.
    assert "Ethernet1/1" in names and "Ethernet1/54" in names
    down = next(i for i in view.of("port") if i.ident["port"] == "Ethernet1/54")
    assert down.facts == (("In", "no tree: the port is down or carries no VLAN"),)
    po = next(i for i in view.of("port") if i.ident["port"] == "port-channel43")
    assert ("In", "VLAN 1: designated forwarding") in po.facts


def test_config_prefills_ports_vlans_and_region() -> None:
    view = parse_spanning_tree(_bodies(), _config())
    assert not any("does not let it read" in n for n in view.notes)
    port = next(i for i in view.of("port") if i.ident["port"] == "Ethernet1/54")
    assert port.values == {
        "priority": {"priority": "64"},
        "cost": {"cost": "100"},
        "link_type": {"type": "point-to-point"},
        "port_type": {"type": "normal"},
        "bpduguard": {"state": "enable"},
        "guard": {"guard": "root"},
        "bpdufilter": {"state": "enable"},
    }
    other = next(i for i in view.of("port") if i.ident["port"] == "Ethernet1/53")
    assert other.values["port_type"] == {"type": "edge trunk"}
    assert other.values["guard"] == {"guard": "loop"}
    assert dict(other.facts)["In"].startswith("no tree")


def test_port_settings_table_lists_every_switched_port() -> None:
    view = parse_spanning_tree(_bodies(), _config())
    table = next(t for t in view.tables if t.title == "Port settings")
    rows = {row[0]: row for row in table.rows}
    assert "Ethernet1/1" in rows and "Ethernet1/54" in rows and "Ethernet1/49" in rows
    assert rows["Ethernet1/1"][1:8] == ("default",) * 7
    assert rows["Ethernet1/54"][1:9] == (
        "normal",
        "enable",
        "enable",
        "root",
        "100",
        "64",
        "point-to-point",
        "vlan 250 port-priority 32; vlan 250 cost 200",
    )


def test_problem_ports() -> None:
    bodies = _bodies()
    # Never seen live: a blocked port in a dispute, shaped after the recorded rows.
    tree = dict(bodies[1]["TABLE_tree"]["ROW_tree"][0])
    port = dict(tree["TABLE_port"]["ROW_port"][0], state="blocking", dispute="true")
    tree["TABLE_port"] = {"ROW_port": [port]}
    bodies[1] = {"TABLE_tree": {"ROW_tree": [tree]}}
    _, _, _, problems = parse_spanning_tree(bodies, None).tables
    assert problems.rows == (("port-channel43", "VLAN 1", "dispute, blocking"),)


def test_region_from_the_switch() -> None:
    bodies = _bodies()
    bodies[2] = {
        "stp-mode": "rapid-pvst",
        "name": "lab-region",
        "rev-id": 5,
        "TABLE_instance_to_vlan_map": {
            "ROW_instance_to_vlan_map": [
                {"mst_id": 0, "vlan_bit_map": "1-249,251-4094"},
                {"mst_id": 1, "vlan_bit_map": "250"},
            ]
        },
    }  # shaped as recorded during the probe (probe_mst_config)
    view = parse_spanning_tree(bodies, "spanning-tree mst 1 priority 8192\n")
    (region,) = view.of("mst")
    assert region.values == {"name": {"name": "lab-region"}, "revision": {"revision": "5"}}
    assert ("Instance 1", "250") in region.facts
    instances = {i.ident["instance"]: i for i in view.of("mst_instance")}
    assert set(instances) == {"0", "1"}
    assert instances["1"].values == {"priority": {"priority": "8192"}}


# ---- every setting's lines ----------------------------------------------------------

V = {"vlan": "250"}
P = {"port": "Ethernet1/54"}
I = {"instance": "1"}  # noqa: E741

_CASES = [
    # scope, setting, ident, values, set lines, remove lines (None: cannot remove)
    ("switch", "mode", {}, {"mode": "mst"}, ["spanning-tree mode mst"], None),
    ("switch", "pathcost", {}, {"method": "long"},
     ["spanning-tree pathcost method long"], ["no spanning-tree pathcost method"]),
    ("switch", "bridge_assurance", {}, {},
     ["spanning-tree bridge assurance"], ["no spanning-tree bridge assurance"]),
    ("switch", "edge_default", {}, {},
     ["spanning-tree port type edge default"], ["no spanning-tree port type edge default"]),
    ("switch", "network_default", {}, {},
     ["spanning-tree port type network default"],
     ["no spanning-tree port type network default"]),
    ("switch", "bpduguard_default", {}, {},
     ["spanning-tree port type edge bpduguard default"],
     ["no spanning-tree port type edge bpduguard default"]),
    ("switch", "bpdufilter_default", {}, {},
     ["spanning-tree port type edge bpdufilter default"],
     ["no spanning-tree port type edge bpdufilter default"]),
    ("switch", "loopguard_default", {}, {},
     ["spanning-tree loopguard default"], ["no spanning-tree loopguard default"]),
    ("switch", "pvst_simulate", {}, {},
     ["spanning-tree mst simulate pvst global"], ["no spanning-tree mst simulate pvst global"]),
    ("switch", "mst_hello", {}, {"seconds": "3"},
     ["spanning-tree mst hello-time 3"], ["no spanning-tree mst hello-time"]),
    ("switch", "mst_forward", {}, {"seconds": "20"},
     ["spanning-tree mst forward-time 20"], ["no spanning-tree mst forward-time"]),
    ("switch", "mst_max_age", {}, {"seconds": "30"},
     ["spanning-tree mst max-age 30"], ["no spanning-tree mst max-age"]),
    ("switch", "mst_max_hops", {}, {"hops": "30"},
     ["spanning-tree mst max-hops 30"], ["no spanning-tree mst max-hops"]),
    ("vlan", "priority", V, {"priority": "4096"},
     ["spanning-tree vlan 250 priority 4096"], ["no spanning-tree vlan 250 priority"]),
    ("vlan", "root", V, {"role": "primary", "diameter": "", "hello": ""},
     ["spanning-tree vlan 250 root primary"], None),
    ("vlan", "hello", V, {"seconds": "3"},
     ["spanning-tree vlan 250 hello-time 3"], ["no spanning-tree vlan 250 hello-time"]),
    ("vlan", "forward", V, {"seconds": "20"},
     ["spanning-tree vlan 250 forward-time 20"], ["no spanning-tree vlan 250 forward-time"]),
    ("vlan", "max_age", V, {"seconds": "30"},
     ["spanning-tree vlan 250 max-age 30"], ["no spanning-tree vlan 250 max-age"]),
    ("vlan", "off", V, {}, ["no spanning-tree vlan 250"], ["spanning-tree vlan 250"]),
    ("mst", "name", {}, {"name": "lab-region"},
     ["spanning-tree mst configuration", "name lab-region"],
     ["spanning-tree mst configuration", "no name"]),
    ("mst", "revision", {}, {"revision": "5"},
     ["spanning-tree mst configuration", "revision 5"],
     ["spanning-tree mst configuration", "no revision"]),
    ("mst", "instance", {}, {"instance": "1", "vlans": "250, 260-270"},
     ["spanning-tree mst configuration", "instance 1 vlan 250,260-270"],
     ["spanning-tree mst configuration", "no instance 1 vlan 250,260-270"]),
    ("mst", "remove_instance", {}, {"instance": "1"}, None,
     ["spanning-tree mst configuration", "no instance 1"]),
    ("mst_instance", "priority", I, {"priority": "8192"},
     ["spanning-tree mst 1 priority 8192"], ["no spanning-tree mst 1 priority"]),
    ("mst_instance", "root", I, {"role": "secondary", "diameter": "4", "hello": "2"},
     ["spanning-tree mst 1 root secondary diameter 4 hello-time 2"], None),
    ("port", "port_type", P, {"type": "edge trunk"},
     ["interface Ethernet1/54", "spanning-tree port type edge trunk"],
     ["interface Ethernet1/54", "no spanning-tree port type"]),
    ("port", "bpduguard", P, {"state": "enable"},
     ["interface Ethernet1/54", "spanning-tree bpduguard enable"],
     ["interface Ethernet1/54", "no spanning-tree bpduguard"]),
    ("port", "bpdufilter", P, {"state": "disable"},
     ["interface Ethernet1/54", "spanning-tree bpdufilter disable"],
     ["interface Ethernet1/54", "no spanning-tree bpdufilter"]),
    ("port", "guard", P, {"guard": "loop"},
     ["interface Ethernet1/54", "spanning-tree guard loop"],
     ["interface Ethernet1/54", "no spanning-tree guard"]),
    ("port", "cost", P, {"cost": "100"},
     ["interface Ethernet1/54", "spanning-tree cost 100"],
     ["interface Ethernet1/54", "no spanning-tree cost"]),
    ("port", "priority", P, {"priority": "64"},
     ["interface Ethernet1/54", "spanning-tree port-priority 64"],
     ["interface Ethernet1/54", "no spanning-tree port-priority"]),
    ("port", "vlan_cost", P, {"vlans": "250", "cost": "200"},
     ["interface Ethernet1/54", "spanning-tree vlan 250 cost 200"],
     ["interface Ethernet1/54", "no spanning-tree vlan 250 cost"]),
    ("port", "vlan_priority", P, {"vlans": "10-20", "priority": "32"},
     ["interface Ethernet1/54", "spanning-tree vlan 10-20 port-priority 32"],
     ["interface Ethernet1/54", "no spanning-tree vlan 10-20 port-priority"]),
    ("port", "mst_cost", P, {"instance": "1", "cost": "2000"},
     ["interface Ethernet1/54", "spanning-tree mst 1 cost 2000"],
     ["interface Ethernet1/54", "no spanning-tree mst 1 cost"]),
    ("port", "mst_priority", P, {"instance": "0", "priority": "96"},
     ["interface Ethernet1/54", "spanning-tree mst 0 port-priority 96"],
     ["interface Ethernet1/54", "no spanning-tree mst 0 port-priority"]),
    ("port", "link_type", P, {"type": "shared"},
     ["interface Ethernet1/54", "spanning-tree link-type shared"],
     ["interface Ethernet1/54", "no spanning-tree link-type"]),
]  # fmt: skip


def test_every_setting_has_a_case() -> None:
    defined = {(s.key, t.key) for s in SPANNING_TREE.scopes for t in s.settings}
    assert {(c[0], c[1]) for c in _CASES} == defined


@pytest.mark.parametrize(("scope", "setting", "ident", "values", "on", "off"), _CASES)
def test_setting_lines(scope, setting, ident, values, on, off) -> None:
    if on is not None:
        assert list(build_stp_change(scope, setting, "set", ident, values).lines) == on
    else:
        with pytest.raises(ValueError, match="only removed"):
            build_stp_change(scope, setting, "set", ident, values)
    if off is not None:
        assert list(build_stp_change(scope, setting, "remove", ident, values).lines) == off
    else:
        with pytest.raises(ValueError, match="cannot be removed"):
            build_stp_change(scope, setting, "remove", ident, values)


def test_removing_needs_only_what_the_no_line_names() -> None:
    change = build_stp_change("vlan", "priority", "remove", V, {})
    assert change.lines == ("no spanning-tree vlan 250 priority",)


def test_the_mode_change_warns() -> None:
    change = build_stp_change("switch", "mode", "set", {}, {"mode": "mst"})
    assert "restarts spanning tree on every VLAN" in change.warning
    assert change.describe == "Spanning tree, Whole switch: set Mode (mst)."


def test_port_names_are_written_as_the_switch_writes_them() -> None:
    for typed, written in (
        ("eth1/5", "Ethernet1/5"),
        ("Ethernet1/50/2", "Ethernet1/50/2"),
        ("po43", "port-channel43"),
        ("Port-Channel 7", "port-channel7"),
    ):
        lines = build_stp_change("port", "cost", "set", {"port": typed}, {"cost": "5"}).lines
        assert lines[0] == f"interface {written}"


@pytest.mark.parametrize(
    ("scope", "setting", "ident", "values", "message"),
    [
        ("vlan", "priority", V, {"priority": "1000"}, "Priority is one of"),
        ("vlan", "priority", {"vlan": "4000"}, {"priority": "4096"}, "the switch's own"),
        ("vlan", "priority", {"vlan": "0"}, {"priority": "4096"}, "from 1 to 4094"),
        ("vlan", "hello", V, {"seconds": "11"}, "from 1 to 10"),
        ("vlan", "forward", V, {"seconds": "3"}, "from 4 to 30"),
        ("vlan", "max_age", V, {"seconds": "41"}, "from 6 to 40"),
        ("vlan", "root", V, {"role": "primary", "diameter": "", "hello": "2"}, "diameter"),
        ("vlan", "root", V, {"role": "tertiary", "diameter": "", "hello": ""}, "one of"),
        ("vlan", "root", V, {"role": "primary", "diameter": "8", "hello": ""}, "from 2 to 7"),
        ("switch", "mode", {}, {"mode": "pvst"}, "one of rapid-pvst, mst"),
        ("switch", "mst_max_hops", {}, {"hops": "256"}, "from 1 to 255"),
        ("mst", "name", {}, {"name": "a;b"}, "cannot contain"),
        ("mst", "name", {}, {"name": "x" * 33}, "1 to 32"),
        ("mst", "revision", {}, {"revision": "65536"}, "from 0 to 65535"),
        ("mst", "instance", {}, {"instance": "0", "vlans": "10"}, "from 1 to 4094"),
        ("mst", "instance", {}, {"instance": "1", "vlans": "20-10"}, "higher one"),
        ("mst", "instance", {}, {"instance": "1", "vlans": "all"}, "VLAN numbers"),
        ("mst", "instance", {}, {"instance": "1", "vlans": "10,4000"}, "the switch's own"),
        ("port", "cost", P, {"cost": "0"}, "from 1 to 200000000"),
        ("port", "priority", P, {"priority": "100"}, "one of"),
        ("port", "port_type", P, {"type": "trunk"}, "one of"),
        ("port", "cost", {"port": "mgmt0"}, {"cost": "5"}, "front port"),
        ("port", "cost", {"port": "Vlan10"}, {"cost": "5"}, "front port"),
        ("port", "cost", {"port": "Ethernet1/54; reload"}, {"cost": "5"}, "cannot contain"),
        ("port", "cost", {"port": "port-channel5000"}, {"cost": "5"}, "1 to 4096"),
        ("port", "vlan_cost", P, {"vlans": "10 20", "cost": "5"}, "VLAN numbers"),
    ],
)
def test_refusals(scope, setting, ident, values, message) -> None:
    with pytest.raises(ValueError, match=message):
        build_stp_change(scope, setting, "set", ident, values)


def test_unknown_scope_and_setting() -> None:
    with pytest.raises(ValueError, match="no 'nosuch' settings"):
        build_stp_change("nosuch", "x", "set", {}, {})
    with pytest.raises(ValueError, match="no setting 'nosuch'"):
        build_stp_change("vlan", "nosuch", "set", V, {})
    with pytest.raises(ValueError, match="not made from here"):
        build_stp_change("vlan", "", "create", V, {})


# ---- the role ------------------------------------------------------------------------


def _allowed(path: str) -> bool:
    for rule in STP_RULES:
        entity = rule.split(" permit command ", 1)[1]
        if re.fullmatch(re.escape(entity).replace(r"\*", ".*"), path):
            return True
    return False


def test_every_line_stays_inside_the_role() -> None:
    for scope, setting, _ident, _values, on, off in _CASES:
        for lines in (on, off):
            if lines is None:
                continue
            for index in range(len(lines)):
                if index == 0 and lines[0].startswith("interface "):
                    continue  # entering a port: the port list allows it
                path = "conf t ; " + " ; ".join(lines[: index + 1])
                assert _allowed(path), f"{scope}/{setting}: {path!r} is not in the role"
    assert _allowed("show running-config spanning-tree")


def test_framework_ident_in_setting_lines() -> None:
    """A setting may name the scope's identity fields its line carries."""
    with pytest.raises(ValueError, match="no field"):
        Setting("x", "X", "spanning-tree vlan {vlan} cost {cost}", (Field("cost", "C", "int"),))
    with pytest.raises(ValueError, match="no identity field"):
        Scope("s", "S", (), (), (Setting("x", "X", "a {vlan}", ident=("vlan",)),))
    assert check_value(Field("v", "VLANs", "vlans"), " 10 , 20-30 ") == "10,20-30"


def test_fixtures_are_scrubbed() -> None:
    for name in ("summary", "detail", "mst_configuration", "vlan_250_detail"):
        text = Path(FIXTURES / f"show_spanning-tree_{name}.json").read_text()
        assert "7079.b3bd" not in text and "10.100." not in text and "cisco-25gb" not in text
