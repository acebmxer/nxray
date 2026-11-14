"""VTP (app/vtp.py): reading the switch's text, the lines every setting sends, and the
values NXray refuses."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.vtp import VTP, build_vtp_change, parse_pairs, parse_vtp, parse_vtp_ports

FIXTURES = Path(__file__).parent / "fixtures"
STATUS = (FIXTURES / "show_vtp_status_doc.txt").read_text()
INTERFACES = (FIXTURES / "show_vtp_interface_doc.txt").read_text()
COUNTERS = (FIXTURES / "show_vtp_counters_doc.txt").read_text()


def _change(scope: str, setting: str, action: str, ident: dict, values: dict):
    return build_vtp_change(scope, setting, action, ident, values)


def test_status_lines_are_kept_as_the_switch_prints_them() -> None:
    pairs = dict(parse_pairs(STATUS))
    assert pairs["VTP Operating Mode"] == "Transparent"
    assert pairs["VTP Pruning Mode"] == "Disabled (Operationally Disabled)"
    # A time of day is not split at its colons, and a heading is not a setting.
    assert not any("last modified" in label for label in pairs)
    assert "VTP Status Information" not in pairs


def test_the_switch_place_has_mode_domain_and_version() -> None:
    (switch,) = parse_vtp(STATUS, INTERFACES, COUNTERS).of("vtp_switch")
    assert switch.facts == (("Mode", "Transparent"), ("Domain", "campus"), ("Version", "1"))
    assert switch.values == {
        "mode": {"mode": "transparent"},
        "domain": {"name": "campus"},
        "version": {"version": "1"},
    }


def test_a_domain_not_set_yet() -> None:
    text = "VTP Operating Mode : Transparent\nVTP Domain Name : <VTP domain not acquired>\n"
    (switch,) = parse_vtp(text).of("vtp_switch")
    assert "domain" not in switch.values


def test_ports_and_the_ones_turned_off() -> None:
    assert parse_vtp_ports(INTERFACES) == [
        ("Ethernet1/1", "Enabled"),
        ("Ethernet1/2", "Disabled"),
        ("port-channel20", "Enabled"),
    ]
    assert parse_vtp_ports("Eth1/7   Disabled\nPo3  Enabled\n") == [
        ("Ethernet1/7", "Disabled"),
        ("port-channel3", "Enabled"),
    ]
    view = parse_vtp(STATUS, INTERFACES, COUNTERS)
    assert [i.ident["port"] for i in view.of("vtp_port")] == ["Ethernet1/2"]
    assert view.tables[1].rows[1] == ("Ethernet1/2", "Disabled")


def test_counters_table() -> None:
    view = parse_vtp(STATUS, INTERFACES, COUNTERS)
    assert view.tables[2].rows[0] == ("Summary advertisements received", "4")
    assert len(view.tables[2].rows) == 8


def test_nothing_read_is_an_empty_page() -> None:
    view = parse_vtp("")
    assert view.instances == () and all(t.rows == () for t in view.tables)


@pytest.mark.parametrize("mode", ["transparent", "off"])
def test_mode(mode: str) -> None:
    assert _change("vtp_switch", "mode", "set", {}, {"mode": mode}).lines == (f"vtp mode {mode}",)


@pytest.mark.parametrize("mode", ["server", "client", "", "off ; reload"])
def test_a_mode_the_switch_does_not_have_is_refused(mode: str) -> None:
    with pytest.raises(ValueError):
        _change("vtp_switch", "mode", "set", {}, {"mode": mode})


def test_domain_and_version() -> None:
    assert _change("vtp_switch", "domain", "set", {}, {"name": "campus"}).lines == (
        "vtp domain campus",
    )
    assert _change("vtp_switch", "version", "set", {}, {"version": "2"}).lines == ("vtp version 2",)
    for bad in ("two words", "x" * 33, "a;b", ""):
        with pytest.raises(ValueError):
            _change("vtp_switch", "domain", "set", {}, {"name": bad})
    with pytest.raises(ValueError):
        _change("vtp_switch", "version", "set", {}, {"version": "3"})


def test_the_password_is_sent_but_never_shown() -> None:
    change = _change("vtp_switch", "password", "set", {}, {"password": "s3cret!"})
    assert change.lines == ("vtp password s3cret!",)
    assert "s3cret!" not in " ".join(change.labels) and "s3cret!" not in change.describe
    assert _change("vtp_switch", "password", "remove", {}, {}).lines == ("no vtp password",)


def test_vtp_on_a_port() -> None:
    ident = {"port": "Ethernet1/5"}
    assert _change("vtp_port", "vtp", "set", ident, {}).lines == ("interface Ethernet1/5", "vtp")
    assert _change("vtp_port", "vtp", "remove", ident, {}).lines == (
        "interface Ethernet1/5",
        "no vtp",
    )


def test_the_protocol_needs_the_feature() -> None:
    assert VTP.features == ("vtp",) and [s.key for s in VTP.scopes] == ["vtp_switch", "vtp_port"]
