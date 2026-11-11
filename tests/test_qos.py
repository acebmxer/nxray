"""QoS (app/qos.py): reading the class-maps, policy-maps and counters, the lines every
setting sends, and the values NXray refuses."""

from __future__ import annotations

import pytest

from app.nxapi import NxapiCommandError
from app.qos import (
    QOS,
    build_qos_change,
    is_built_in,
    load_qos_page,
    parse_applied,
    parse_counters,
    parse_qos,
    parse_system,
)
from tests.conftest import load_fixture


def _lines(scope: str, setting: str, action: str, ident: dict, values: dict) -> tuple[str, ...]:
    return build_qos_change(scope, setting, action, ident, values).lines


def _view():
    return parse_qos(
        [
            load_fixture("show_class_map_type_qos"),
            load_fixture("show_policy_map_type_qos"),
            load_fixture("show_class_map_type_network_qos"),
            load_fixture("show_policy_map_type_network_qos"),
            load_fixture("show_policy_map_type_queuing"),
            load_fixture("show_policy_map_interface_brief"),
            load_fixture("show_policy_map_system"),
        ],
        load_fixture("show_queuing_interface"),
    )


# ---- reading ---------------------------------------------------------------------


def test_the_switchs_own_names_are_recognised() -> None:
    for name in (
        "class-default",
        "c-nq1",
        "c-8q-nq-default",
        "c-out-8q-q7",
        "c-out-q-default",
        "default-8q-out-policy",
        "default-nq-policy",
        "default-in-policy",
    ):
        assert is_built_in(name), name
    for name in ("voice", "c-voice", "default", "my-default-policy"):
        assert not is_built_in(name), name


def test_class_maps_become_places_without_the_defaults() -> None:
    view = _view()
    places = view.of("cmap")
    assert [i.ident for i in places] == [
        {"cmap": "nxprobe-voice", "mode": "match-any"},
        {"cmap": "nxprobe-data", "mode": "match-all"},
        {"cmap": "nxprobe-empty", "mode": "match-all"},
    ]
    facts = dict(places[0].facts)
    assert facts["Matches"] == (
        "dscp 46; access-group nxprobe-acl; precedence 5; cos 0-3; ip rtp 2000-3000"
    )
    assert places[0].values["description"] == {"text": "voice traffic"}
    assert dict(places[1].facts)["Matches"] == "dscp 10,12"  # one row, not a list
    assert dict(places[2].facts)["Matches"] == "nothing yet"


def test_a_policy_map_and_its_classes_are_places() -> None:
    view = _view()
    assert [i.ident for i in view.of("policy")] == [{"policy": "nxprobe-pm"}]
    policy = dict(view.of("policy")[0].facts)
    assert policy["Applied to"] == "Ethernet1/53"
    assert "nxprobe-voice: set qos-group 7, set dscp 46" in policy["Classes"]
    voice, default = view.of("pclass")
    assert voice.ident == {"policy": "nxprobe-pm", "class": "nxprobe-voice"}
    assert voice.values["set_qos_group"] == {"group": "7"}
    assert voice.values["set_dscp"] == {"dscp": "46"}
    assert voice.values["set_cos"] == {"cos": "5"}
    assert voice.values["set_precedence"] == {"precedence": "3"}
    assert voice.values["police"] == {"rate": "2", "unit": "gbps"}
    assert default.ident["class"] == "class-default"


def test_a_port_with_a_policy_is_a_place() -> None:
    ports = _view().of("qos_port")
    assert [i.ident for i in ports] == [{"port": "Ethernet1/53"}]
    assert ports[0].values == {"service_policy": {"policy": "nxprobe-pm"}}


def test_network_qos_and_queuing_policies_are_places() -> None:
    view = _view()
    assert [i.ident for i in view.of("nqmap")] == [{"nqmap": "nxprobe-nq"}]
    assert [i.ident for i in view.of("nqpolicy")] == [{"nqpolicy": "nxprobe-npm"}]
    (nq,) = view.of("nqclass")
    assert nq.values["mtu"] == {"mtu": "9216"}
    assert nq.values["pause"] == {"cos": "3"}
    assert [i.ident for i in view.of("qpolicy")] == [{"qpolicy": "nxprobe-qpm"}]
    q2, q3 = view.of("qclass")
    assert q2.values["queue_limit"] == {"size": "50000"}
    assert q2.values["shape"] == {"minimum": "100", "maximum": "500", "unit": "mbps"}
    assert q3.values["bandwidth"] == {"percent": "20"}


def test_applied_and_system_policies() -> None:
    assert parse_applied(load_fixture("show_policy_map_interface_brief")) == {
        "Ethernet1/53": {"qos": "nxprobe-pm"}
    }
    assert parse_system(load_fixture("show_policy_map_system")) == [
        ("network-qos", "default-8q-nq-policy"),
        ("queuing output", "default-8q-out-policy"),
    ]


def test_tables_show_what_is_applied_the_defaults_and_the_counters() -> None:
    applied, built_in, counters = _view().tables
    assert applied.rows == (("Ethernet1/53", "nxprobe-pm", "-"),)
    assert ("queuing", "default-8q-out-policy") in built_in.rows
    assert ("network-qos", "default-8q-nq-policy") in built_in.rows
    assert counters.rows == (("Ethernet1/1", "0", "1200", "3", "0"),)


def test_counters_count_unicast_and_multicast_and_skip_idle_queues() -> None:
    body = load_fixture("show_queuing_interface")
    rows = body["TABLE_module"]["ROW_module"]["TABLE_queuing_interface"]["ROW_queuing_interface"]
    rows[0]["TABLE_qosgrp_egress_stats"]["ROW_qosgrp_egress_stats"][0][
        "TABLE_qosgrp_egress_stats_entry"
    ]["ROW_qosgrp_egress_stats_entry"][0]["eq-mc-stat-value"] = "30"
    assert parse_counters(body) == [("Ethernet1/1", "0", "1230", "3", "0")]


def test_nothing_made_is_an_empty_page() -> None:
    view = parse_qos([{}, {}, {}, {}, {}, {}, {}])
    assert [i.scope for i in view.instances] == ["system"]
    assert view.tables[0].rows == ()


# ---- the lines each setting sends ------------------------------------------------


def test_make_and_delete_a_class_map() -> None:
    ident = {"cmap": "voice", "mode": "match-any"}
    assert _lines("cmap", "", "create", ident, {}) == ("class-map type qos match-any voice",)
    assert _lines("cmap", "", "delete", ident, {}) == ("no class-map type qos voice",)


def test_class_map_matches() -> None:
    ident = {"cmap": "voice", "mode": "match-all"}
    enter = "class-map type qos match-all voice"
    for setting, values, line in (
        ("match_dscp", {"values": "46"}, "match dscp 46"),
        ("match_dscp", {"values": "10, 12"}, "match dscp 10,12"),
        ("match_cos", {"values": "0-3"}, "match cos 0-3"),
        ("match_precedence", {"values": "5"}, "match precedence 5"),
        ("match_acl", {"acl": "web"}, "match access-group name web"),
        ("match_rtp", {"ports": "16384-32767"}, "match ip rtp 16384-32767"),
        ("description", {"text": "voice"}, "description voice"),
    ):
        assert _lines("cmap", setting, "set", ident, values) == (enter, line)
    assert _lines("cmap", "match_cos", "remove", ident, {"values": "5"})[1] == "no match cos 5"
    assert _lines("cmap", "description", "remove", ident, {})[1] == "no description"


def test_policy_map_and_its_classes() -> None:
    assert _lines("policy", "", "create", {"policy": "p"}, {}) == ("policy-map type qos p",)
    assert _lines("policy", "", "delete", {"policy": "p"}, {}) == ("no policy-map type qos p",)
    ident = {"policy": "p", "class": "voice"}
    assert _lines("pclass", "", "create", ident, {}) == ("policy-map type qos p", "class voice")
    assert _lines("pclass", "", "delete", ident, {}) == ("policy-map type qos p", "no class voice")
    enter = ("policy-map type qos p", "class voice")
    for setting, values, line in (
        ("set_qos_group", {"group": "3"}, "set qos-group 3"),
        ("set_dscp", {"dscp": "46"}, "set dscp 46"),
        ("set_cos", {"cos": "5"}, "set cos 5"),
        ("set_precedence", {"precedence": "3"}, "set precedence 3"),
        (
            "police",
            {"rate": "1", "unit": "mbps", "burst": "200"},
            "police cir 1 mbps bc 200 ms conform transmit violate drop",
        ),
        (
            "police",
            {"rate": "100", "unit": "kbps", "burst": ""},
            "police cir 100 kbps conform transmit violate drop",
        ),
        (
            "police_percent",
            {"percent": "10"},
            "police cir percent 10 conform transmit violate drop",
        ),
    ):
        assert _lines("pclass", setting, "set", ident, values) == (*enter, line)


def test_removing_a_mark_or_limit_sends_the_whole_line() -> None:
    # The switch refuses "no set cos" and "no police" alone (cisco-25gb, 2026-11-10).
    ident = {"policy": "p", "class": "voice"}
    assert _lines("pclass", "set_cos", "remove", ident, {"cos": "5"})[2] == "no set cos 5"
    assert _lines("pclass", "police", "remove", ident, {"rate": "5", "unit": "mbps"})[2] == (
        "no police cir 5 mbps conform transmit violate drop"
    )


def test_a_port_takes_a_policy_as_input() -> None:
    ident = {"port": "Ethernet1/54"}
    assert _lines("qos_port", "service_policy", "set", ident, {"policy": "p"}) == (
        "interface Ethernet1/54",
        "service-policy type qos input p",
    )
    assert _lines("qos_port", "service_policy", "remove", ident, {"policy": "p"})[1] == (
        "no service-policy type qos input p"
    )


def test_network_qos_lines() -> None:
    assert _lines("nqmap", "", "create", {"nqmap": "nq3"}, {}) == (
        "class-map type network-qos match-any nq3",
    )
    assert _lines("nqmap", "match_group", "set", {"nqmap": "nq3"}, {"groups": "3"})[1] == (
        "match qos-group 3"
    )
    assert _lines("nqpolicy", "", "create", {"nqpolicy": "np"}, {}) == (
        "policy-map type network-qos np",
    )
    ident = {"nqpolicy": "np", "nqclass": "nq3"}
    enter = ("policy-map type network-qos np", "class type network-qos nq3")
    assert _lines("nqclass", "mtu", "set", ident, {"mtu": "9216"}) == (*enter, "mtu 9216")
    assert _lines("nqclass", "pause", "set", ident, {"cos": "3"}) == (*enter, "pause pfc-cos 3")
    assert _lines("nqclass", "", "delete", ident, {}) == (
        "policy-map type network-qos np",
        "no class type network-qos nq3",
    )


def test_queuing_lines() -> None:
    assert _lines("qpolicy", "", "create", {"qpolicy": "qp"}, {}) == ("policy-map type queuing qp",)
    ident = {"qpolicy": "qp", "qclass": "c-out-8q-q3"}
    enter = ("policy-map type queuing qp", "class type queuing c-out-8q-q3")
    for setting, values, line in (
        ("bandwidth", {"percent": "20"}, "bandwidth remaining percent 20"),
        ("priority", {"level": "1"}, "priority level 1"),
        (
            "shape",
            {"minimum": "100", "maximum": "500", "unit": "mbps"},
            "shape min 100 mbps max 500 mbps",
        ),
        ("queue_limit", {"size": "50000"}, "queue-limit 50000 bytes"),
    ):
        assert _lines("qclass", setting, "set", ident, values) == (*enter, line)
    assert _lines("qclass", "", "delete", ident, {}) == (
        "policy-map type queuing qp",
        "no class type queuing c-out-8q-q3",
    )


def test_system_policies() -> None:
    for setting, line in (
        ("network_qos", "service-policy type network-qos np"),
        ("queuing_output", "service-policy type queuing output qp"),
        ("qos_input", "service-policy type qos input p"),
    ):
        change = build_qos_change("system", setting, "set", {}, {"policy": line.split()[-1]})
        assert change.lines == ("system qos", line)
        assert "whole switch" in change.warning


# ---- what is refused -------------------------------------------------------------


@pytest.mark.parametrize(
    ("scope", "setting", "values"),
    [
        ("cmap", "match_dscp", {"values": "64"}),
        ("cmap", "match_dscp", {"values": "af11"}),
        ("cmap", "match_dscp", {"values": "10;20"}),
        ("cmap", "match_dscp", {"values": "12-10"}),
        ("cmap", "match_cos", {"values": "8"}),
        ("cmap", "match_rtp", {"ports": "100-200"}),
        ("cmap", "description", {"text": "a ; b"}),
        ("pclass", "set_qos_group", {"group": "8"}),
        ("pclass", "set_dscp", {"dscp": "64"}),
        ("pclass", "police", {"rate": "0", "unit": "mbps", "burst": ""}),
        ("pclass", "police", {"rate": "1", "unit": "tbps", "burst": ""}),
        ("pclass", "police_percent", {"percent": "101"}),
        ("nqclass", "mtu", {"mtu": "100"}),
        ("qclass", "bandwidth", {"percent": "101"}),
        ("qclass", "priority", {"level": "2"}),
    ],
)
def test_bad_values_are_refused(scope: str, setting: str, values: dict) -> None:
    ident = {
        "cmap": {"cmap": "c", "mode": "match-any"},
        "pclass": {"policy": "p", "class": "c"},
        "nqclass": {"nqpolicy": "p", "nqclass": "c"},
        "qclass": {"qpolicy": "p", "qclass": "c-out-8q-q3"},
    }[scope]
    with pytest.raises(ValueError):
        build_qos_change(scope, setting, "set", ident, values)


@pytest.mark.parametrize(
    ("scope", "ident"),
    [
        ("cmap", {"cmap": "bad name", "mode": "match-any"}),
        ("cmap", {"cmap": "x" * 41, "mode": "match-any"}),
        ("cmap", {"cmap": "ok", "mode": "match-none"}),
        ("policy", {"policy": ""}),
        ("qclass", {"qpolicy": "qp", "qclass": "c-voice"}),
    ],
)
def test_bad_names_are_refused(scope: str, ident: dict) -> None:
    with pytest.raises(ValueError):
        build_qos_change(scope, "", "create", ident, {})


def test_the_page_is_described_by_the_shared_parts() -> None:
    assert [s.key for s in QOS.scopes] == [
        "cmap",
        "policy",
        "pclass",
        "qos_port",
        "nqmap",
        "nqpolicy",
        "nqclass",
        "qpolicy",
        "qclass",
        "system",
    ]


class _Client:
    """A client whose `show class-map type qos` fails with ``message``."""

    def __init__(self, message: str) -> None:
        self.message = message

    def show(self, *commands: str):
        if commands == ("show class-map type qos",):
            raise NxapiCommandError(self.message)
        if len(commands) == 1:
            return [{}]
        return [
            load_fixture("show_interface_brief"),
            load_fixture("show_class_map_type_network_qos"),
            load_fixture("show_policy_map_type_network_qos"),
            load_fixture("show_policy_map_type_queuing"),
            load_fixture("show_policy_map_interface_brief"),
            load_fixture("show_policy_map_system"),
        ]


def test_nothing_made_is_not_a_warning() -> None:
    # cisco-25gb prints nothing while no class-map or policy-map was made.
    for message in ("'show class-map type qos': CLI output cannot be parsed by the server", ""):
        page = load_qos_page(_Client(message))  # type: ignore[arg-type]
        assert page.problem == "" and page.classes == ()


def test_any_other_refusal_is_shown() -> None:
    page = load_qos_page(_Client("% Permission denied for the role"))  # type: ignore[arg-type]
    assert "did not answer" in page.problem and "Permission denied" in page.problem
