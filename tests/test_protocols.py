"""The shared routing protocol framework (app/protocols.py) and the registry
(app/routing_protocols.py): field checks, templates, building a change, the
route table, and that every protocol's lines stay inside NXray's role."""

from __future__ import annotations

import re

import pytest

from app.port_changes import PROTOCOL_RULES
from app.protocols import (
    Field,
    Protocol,
    ProtocolView,
    Scope,
    Setting,
    build_change,
    check_value,
    render,
    route_age,
)
from app.routing_protocols import ALL_PROTOCOLS, build_protocol_change, parse_routes, protocol
from tests.conftest import load_fixture

# ---- fields ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "raw", "expected"),
    [
        ("int", "10", "10"),
        ("ipv4", "192.0.2.1", "192.0.2.1"),
        ("ipv6", "2001:db8::1", "2001:db8::1"),
        ("prefix4", "192.0.2.0/24", "192.0.2.0/24"),
        ("prefix6", "2001:db8::/32", "2001:db8::/32"),
        ("group4", "239.0.0.0/8", "239.0.0.0/8"),
        ("area", "0", "0.0.0.0"),
        ("area", "4294967295", "255.255.255.255"),
        ("area", "0.0.0.1", "0.0.0.1"),
        ("asn", "65001", "65001"),
        ("asn", "1.10", "1.10"),
        ("name", "core-1", "core-1"),
        ("secret", "Sekr1t!", "Sekr1t!"),
        ("text", "to the core", "to the core"),
        ("interface", "vlan10", "Vlan10"),
        ("source", "loopback0", "loopback0"),
        ("source", "lo 7", "loopback7"),
        ("source", "Vlan10", "Vlan10"),
        ("vrf", "lab", "lab"),
        ("net", "49.0001.1920.0000.2001.00", "49.0001.1920.0000.2001.00"),
        ("mac", "02:00:00:00:00:01", "0200.0000.0001"),
        ("mac", "0200.0000.0001", "0200.0000.0001"),
        ("maddr4", "239.1.1.1", "239.1.1.1"),
    ],
)
def test_check_value_takes(kind: str, raw: str, expected: str) -> None:
    assert check_value(Field("x", "X", kind, minimum=1, maximum=100), raw) == expected


@pytest.mark.parametrize(
    ("kind", "raw"),
    [
        ("int", "0"),
        ("int", "101"),
        ("int", "1e3"),
        ("ipv4", "2001:db8::1"),
        ("ipv4", "224.0.0.5"),
        ("ipv4", "127.0.0.1"),
        ("ipv6", "192.0.2.1"),
        ("prefix4", "192.0.2.1/24"),
        ("prefix4", "192.0.2.0"),
        ("group4", "192.0.2.0/24"),
        ("area", "4294967296"),
        ("asn", "0"),
        ("asn", "4294967296"),
        ("name", "has space"),
        ("name", "x;reload"),
        ("name", "-x"),
        ("secret", "has space"),
        ("secret", "a;b"),
        ("secret", '"quoted'),
        ("secret", "|pipe"),
        ("interface", "mgmt0"),
        ("interface", "Vlan300"),
        ("interface", "loopback0"),
        ("source", "loopback1024"),
        ("source", "mgmt0"),
        ("vrf", "management"),
        ("net", "49.0001"),
        ("mac", "0100.5e00.0001"),
        ("mac", "0000.0000.0000"),
        ("mac", "zz00.0000.0001"),
        ("maddr4", "192.0.2.1"),
        ("maddr4", "224.0.0.5"),
    ],
)
def test_check_value_refuses(kind: str, raw: str) -> None:
    with pytest.raises(ValueError):
        check_value(Field("x", "X", kind, minimum=1, maximum=100), raw)


def test_optional_field_may_be_empty_and_required_may_not() -> None:
    assert check_value(Field("x", "X", "int", optional=True), "") == ""
    with pytest.raises(ValueError, match="X is needed"):
        check_value(Field("x", "X", "int"), " ")


def test_default_vrf_is_empty_when_optional_and_refused_when_required() -> None:
    assert check_value(Field("vrf", "VRF", "vrf", optional=True), "default") == ""
    with pytest.raises(ValueError, match="other than default"):
        check_value(Field("vrf", "VRF", "vrf"), "default")


def test_name_and_secret_honour_a_maximum() -> None:
    assert check_value(Field("x", "X", "name", maximum=5), "abcde") == "abcde"
    with pytest.raises(ValueError, match="1 to 5"):
        check_value(Field("x", "X", "name", maximum=5), "abcdef")
    with pytest.raises(ValueError, match="1 to 8"):
        check_value(Field("x", "X", "secret", maximum=8), "123456789")


def test_flag_is_its_word_or_nothing() -> None:
    flag = Field("x", "X", "flag", choices=("passive",))
    assert check_value(flag, "yes") == "passive"
    assert check_value(flag, "") == ""


def test_unknown_kind_and_choice_without_choices_are_programming_errors() -> None:
    with pytest.raises(ValueError):
        Field("x", "X", "colour")
    with pytest.raises(ValueError):
        Field("x", "X", "choice")


# ---- templates --------------------------------------------------------------------------


def test_render_drops_bracketed_parts_with_an_empty_value() -> None:
    template = "area {area} range {prefix}[ cost {cost}][ {hide}]"
    values = {"area": "0.0.0.0", "prefix": "192.0.2.0/24", "cost": "", "hide": "not-advertise"}
    assert render(template, values) == "area 0.0.0.0 range 192.0.2.0/24 not-advertise"


def test_render_needs_every_blank() -> None:
    with pytest.raises(KeyError):
        render("router-id {router_id}", {})


def test_setting_and_scope_catch_drift() -> None:
    with pytest.raises(ValueError, match="no field"):
        Setting("x", "X", "cost {cost}")
    with pytest.raises(ValueError, match="no identity field"):
        Scope("s", "S", (), ("router ospf {tag}",))
    with pytest.raises(ValueError, match="reuse identity"):
        Scope(
            "s",
            "S",
            (Field("tag", "Tag", "name"),),
            ("router ospf {tag}",),
            (Setting("x", "X", "x {tag}", (Field("tag", "Tag", "name"),)),),
        )


# ---- building a change ---------------------------------------------------------------------

_PROTO = Protocol(
    key="test",
    name="Test",
    summary="",
    features=(),
    commands=(),
    parse=lambda bodies: ProtocolView(),
    scopes=(
        Scope(
            "process",
            "Process",
            (Field("tag", "Process", "name"),),
            ("router ospf {tag}",),
            (
                Setting(
                    "password",
                    "Password",
                    "authentication-key {password}",
                    (Field("password", "Password", "secret"),),
                    no_line="no authentication-key",
                ),
                Setting(
                    "range",
                    "Range",
                    "area {area} range {prefix}",
                    (Field("area", "Area", "area"), Field("prefix", "Network", "prefix4")),
                    check=lambda v: _refuse_area_one(v),
                    warning="Routes change.",
                ),
            ),
            create=True,
            delete=("no router ospf {tag}",),
            delete_warning="Gone.",
        ),
    ),
)


def _refuse_area_one(values: dict[str, str]) -> None:
    if values["area"] == "0.0.0.1":
        raise ValueError("not area 1")


def test_build_create_and_delete() -> None:
    made = build_change(_PROTO, "process", "", "create", {"tag": "core"}, {})
    assert made.lines == ("router ospf core",)
    assert made.describe == "Test: make Process (Process core)."
    gone = build_change(_PROTO, "process", "", "delete", {"tag": "core"}, {})
    assert gone.lines == ("no router ospf core",)
    assert gone.warning == "Gone."


def test_build_set_masks_secrets_in_labels_and_words() -> None:
    change = build_change(
        _PROTO, "process", "password", "set", {"tag": "core"}, {"password": "Sekr1t"}
    )
    assert change.lines == ("router ospf core", "authentication-key Sekr1t")
    assert change.labels == ("router ospf core", "authentication-key ***")
    assert "Sekr1t" not in change.describe


def test_remove_checks_only_what_the_no_line_uses() -> None:
    change = build_change(_PROTO, "process", "password", "remove", {"tag": "core"}, {})
    assert change.lines == ("router ospf core", "no authentication-key")


def test_setting_check_refuses_a_combination() -> None:
    values = {"area": "1", "prefix": "192.0.2.0/24"}
    with pytest.raises(ValueError, match="not area 1"):
        build_change(_PROTO, "process", "range", "set", {"tag": "core"}, values)
    ok = build_change(_PROTO, "process", "range", "set", {"tag": "core"}, {**values, "area": "0"})
    assert ok.lines[-1] == "area 0.0.0.0 range 192.0.2.0/24"
    assert ok.warning == "Routes change."


@pytest.mark.parametrize(
    ("scope", "setting", "action", "message"),
    [
        ("nosuch", "", "set", "has no 'nosuch' settings"),
        ("process", "nosuch", "set", "has no setting 'nosuch'"),
        ("process", "", "launch", "unknown action"),
    ],
)
def test_build_refuses_unknown_parts(scope: str, setting: str, action: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        build_change(_PROTO, scope, setting, action, {"tag": "core"}, {})


def test_build_protocol_change_by_key() -> None:
    change = build_protocol_change("ospf", "process", "", "create", {"tag": "core"}, {})
    assert change.lines == ("router ospf core",)
    with pytest.raises(ValueError, match="no routing protocol page"):
        build_protocol_change("nosuch", "process", "", "create", {}, {})


# ---- the registry -------------------------------------------------------------------------


def test_protocol_keys_are_unique_and_found() -> None:
    keys = [p.key for p in ALL_PROTOCOLS]
    assert len(keys) == len(set(keys))
    assert {
        "ospf",
        "ospfv3",
        "bgp",
        "eigrp",
        "rip",
        "isis",
        "hsrp",
        "vrrp",
        "vrrpv3",
        "pim",
        "pim6",
        "igmp",
        "msdp",
        "bfd",
        "policy",
    } <= set(keys)
    assert protocol("ospf") is not None and protocol("nosuch") is None


def _allowed(path: str) -> bool:
    """Whether one of NXray's protocol role rules covers ``path``, as the switch
    matches them: "*" is anything, and a mode rule covers every line inside it."""
    for rule in PROTOCOL_RULES:
        entity = rule.split(" permit command ", 1)[1]
        if re.fullmatch(re.escape(entity).replace(r"\*", ".*"), path):
            return True
    return False


def _sample(spec: Field) -> str:
    samples = {
        "int": str(spec.minimum if spec.minimum is not None else 1),
        "ipv4": "192.0.2.1",
        "ipv6": "2001:db8::1",
        "ip": "192.0.2.1",
        "prefix4": "192.0.2.0/24",
        "prefix6": "2001:db8::/32",
        "prefix": "192.0.2.0/24",
        "group4": "239.0.0.0/8",
        "group6": "ff3e::/32",
        "area": "0",
        "asn": "65001",
        "name": "lab",
        "secret": "Sekr1t",
        "text": "note",
        "interface": "Vlan10",
        "source": "loopback0",
        "vrf": "lab",
        "net": "49.0001.1920.0000.2001.00",
        "mac": "0200.0000.0001",
        "maddr4": "239.1.1.1",
        "flag": "yes",
    }
    if spec.kind == "choice":
        return spec.choices[0]
    return samples[spec.kind]


def _paths(lines: tuple[str, ...]) -> list[str]:
    """Each line as the mode path the switch checks against the role."""
    paths = []
    for index in range(len(lines)):
        paths.append("conf t ; " + " ; ".join(lines[: index + 1]))
    return paths


@pytest.mark.parametrize("proto", ALL_PROTOCOLS, ids=lambda p: p.key)
def test_every_line_stays_inside_the_role(proto: Protocol) -> None:
    """Build every create, delete, set and remove a page offers, with sample
    values, and check the role allows each line: NXray never offers a change
    the switch would refuse as denied."""
    for scope in proto.scopes:
        ident = {f.name: _sample(f) for f in scope.ident}
        changes = []
        if scope.create:
            changes.append(build_change(proto, scope.key, "", "create", ident, {}))
        if scope.delete is not None:
            changes.append(build_change(proto, scope.key, "", "delete", ident, {}))
        for setting in scope.settings:
            values = {f.name: _sample(f) for f in setting.fields}
            for action, allowed in (("set", setting.settable), ("remove", setting.removable)):
                if not allowed:
                    continue
                try:
                    changes.append(
                        build_change(proto, scope.key, setting.key, action, ident, values)
                    )
                except ValueError:
                    # A sample that does not fit this setting (a combination
                    # check); the module's own tests send real values.
                    continue
        for change in changes:
            paths = _paths(change.lines)
            if change.lines[0].startswith(("interface ", "vrf context ")):
                # Entering the interface or VRF: the port and VRF rules allow it.
                paths = paths[1:]
            for path in paths:
                assert _allowed(path), f"{proto.key}/{scope.key}: {path!r} is not in the role"


# ---- the route table ------------------------------------------------------------------------


def test_route_age() -> None:
    assert route_age("P1DT13H30M23S") == "1d 13h 30m"
    assert route_age("PT11S") == "11s"
    assert route_age("PT5M") == "5m"
    assert route_age("never") == "never"


def test_parse_routes_ipv4() -> None:
    # Recorded with nothing routed: the default VRF is listed but has no routes.
    routes = parse_routes(load_fixture("show_ip_route_vrf_all"))
    assert all(r.prefix and r.source for r in routes)
    assert {r.vrf for r in routes} == {"management"}
    assert [(r.prefix, r.source) for r in routes] == [
        ("0.0.0.0/0", "static"),
        ("203.0.113.0/24", "direct"),
        ("203.0.113.10/32", "local"),
    ]
    gateway = next(r for r in routes if r.vrf == "management" and r.prefix == "0.0.0.0/0")
    assert any("203.0.113.254" in hop for hop in gateway.next_hops)
    assert not any(r.ipv6 for r in routes)


def test_parse_routes_ipv6() -> None:
    routes = parse_routes(load_fixture("show_ipv6_route_vrf_all"))
    assert all(r.ipv6 for r in routes)


def test_parse_routes_of_nothing() -> None:
    assert parse_routes({}) == []
