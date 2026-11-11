"""UDLD (app/udld.py): reading the switch's text, the lines every setting sends, and the
values NXray refuses."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.udld import UDLD, build_udld_change, parse_udld, parse_udld_global, parse_udld_ports

FIXTURES = Path(__file__).parent / "fixtures"
GLOBAL = (FIXTURES / "show_udld_global_doc.txt").read_text()
PORTS = (FIXTURES / "show_udld_doc.txt").read_text()


def _lines(scope: str, setting: str, action: str, ident: dict, values: dict) -> tuple[str, ...]:
    return build_udld_change(scope, setting, action, ident, values).lines


def test_the_switch_wide_mode_and_interval() -> None:
    assert parse_udld_global(GLOBAL) == {"mode": "enabled-aggressive", "interval": "15"}
    assert parse_udld_global("") == {}


def test_every_port_block_is_read() -> None:
    ports = {p.name: p for p in parse_udld_ports(PORTS)}
    assert list(ports) == ["Ethernet1/1", "Ethernet1/2", "Ethernet1/3"]
    one = ports["Ethernet1/1"]
    assert (one.setting, one.state, one.link) == (
        "device-default",
        "enabled-aggressive",
        "bidirectional",
    )
    assert one.detail == "advertisement - Single neighbor detected"
    assert one.neighbors == (("core-1", "Ethernet1/49", "bidirectional"),)
    assert ports["Ethernet1/2"].neighbors == ()


def test_a_neighbour_line_does_not_overwrite_the_ports_own() -> None:
    # "Message interval" is printed for the port and again for its neighbour.
    view = parse_udld(GLOBAL, PORTS)
    assert view.tables[0].rows[0] == (
        "Ethernet1/1",
        "device-default",
        "enabled-aggressive",
        "bidirectional",
        "advertisement - Single neighbor detected",
    )
    assert view.tables[1].rows == (("Ethernet1/1", "core-1", "Ethernet1/49", "bidirectional"),)


def test_only_ports_not_on_their_default_are_places() -> None:
    view = parse_udld(GLOBAL, PORTS)
    assert [(i.ident["port"], i.values) for i in view.of("udld_port")] == [
        ("Ethernet1/2", {"state": {"state": "disable"}}),
        ("Ethernet1/3", {"state": {"state": "enable"}, "aggressive": {}}),
    ]
    (switch,) = view.of("udld_switch")
    assert switch.facts == (("Mode", "enabled-aggressive"), ("Message interval", "15 s"))
    assert switch.values["message_time"] == {"seconds": "15"}


def test_nothing_read_is_an_empty_page() -> None:
    view = parse_udld("", "")
    assert view.instances == () and view.tables[0].rows == () and view.tables[1].rows == ()


def test_text_worded_differently_does_not_break_the_page() -> None:
    view = parse_udld("something else\n", "Interface Ethernet1/9\nno colon here\nOdd: thing\n")
    assert view.tables[0].rows == (("Ethernet1/9", "-", "-", "-", "-"),)


@pytest.mark.parametrize("state", ["enable", "disable"])
def test_port_state_set_and_removed(state: str) -> None:
    ident = {"port": "Ethernet1/5"}
    assert _lines("udld_port", "state", "set", ident, {"state": state}) == (
        "interface Ethernet1/5",
        f"udld {state}",
    )
    assert _lines("udld_port", "state", "remove", ident, {"state": state})[-1] == (
        f"no udld {state}"
    )


def test_aggressive_on_a_port_and_on_the_switch() -> None:
    assert _lines("udld_port", "aggressive", "set", {"port": "Ethernet1/5"}, {}) == (
        "interface Ethernet1/5",
        "udld aggressive",
    )
    assert _lines("udld_switch", "aggressive", "remove", {}, {}) == ("no udld aggressive",)


def test_message_interval() -> None:
    assert _lines("udld_switch", "message_time", "set", {}, {"seconds": "30"}) == (
        "udld message-time 30",
    )
    with pytest.raises(ValueError):
        _lines("udld_switch", "message_time", "remove", {}, {})


@pytest.mark.parametrize("bad", ["6", "91", "", "15 ; reload", "abc"])
def test_a_bad_interval_is_refused(bad: str) -> None:
    with pytest.raises(ValueError):
        _lines("udld_switch", "message_time", "set", {}, {"seconds": bad})


@pytest.mark.parametrize("bad", ["maybe", "", "enable; shut"])
def test_a_bad_state_is_refused(bad: str) -> None:
    with pytest.raises(ValueError):
        _lines("udld_port", "state", "set", {"port": "Ethernet1/5"}, {"state": bad})


def test_the_protocol_has_both_places_and_needs_the_feature() -> None:
    assert [s.key for s in UDLD.scopes] == ["udld_port", "udld_switch"]
    assert UDLD.features == ("udld",)
