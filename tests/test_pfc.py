"""Priority flow control (app/pfc.py): reading the pause counters, the lines every setting
sends, and the values NXray refuses."""

from __future__ import annotations

import pytest

from app.pfc import PFC, build_pfc_change, parse_pfc
from tests.conftest import load_fixture

BODY = load_fixture("show_interface_priority-flow-control_detail")


def _lines(scope: str, setting: str, action: str, ident: dict, values: dict) -> tuple[str, ...]:
    return build_pfc_change(scope, setting, action, ident, values).lines


def test_every_port_is_in_the_table_with_its_counters() -> None:
    view = parse_pfc([BODY])
    ports = {row[0]: row for row in view.tables[0].rows}
    assert len(ports) == 5
    assert ports["Ethernet1/2"] == ("Ethernet1/2", "On", "On", "12", "7")
    assert ports["Ethernet1/1"][1:3] == ("Auto", "Off")


def test_pause_by_priority_lists_only_ports_with_counts() -> None:
    view = parse_pfc([BODY])
    assert view.tables[1].rows == (
        ("Ethernet1/2", "0 / 0", "0 / 0", "0 / 0", "12 / 7", "0 / 0", "0 / 0", "0 / 0", "0 / 0"),
    )


def test_only_ports_not_on_auto_are_places() -> None:
    view = parse_pfc([BODY])
    assert [(i.ident["port"], i.values["mode"]["mode"]) for i in view.of("pfc_port")] == [
        ("Ethernet1/2", "on"),
        ("Ethernet1/3", "off"),
    ]


def test_one_port_is_a_dict_not_a_list() -> None:
    one = {
        "TABLE_module": {
            "ROW_module": {
                "TABLE_pfc_interface": {
                    "ROW_pfc_interface": {
                        "if_name_str": "Ethernet1/54",
                        "admin": "Auto",
                        "oper": "Off",
                        "rx-stats": 0,
                        "tx-stats": 0,
                    }
                }
            }
        }
    }
    assert parse_pfc([one]).tables[0].rows == (("Ethernet1/54", "Auto", "Off", "0", "0"),)


def test_nothing_read_is_an_empty_page() -> None:
    view = parse_pfc([{}])
    assert view.instances == () and view.tables[0].rows == ()


@pytest.mark.parametrize("mode", ["on", "off", "auto"])
def test_port_mode(mode: str) -> None:
    assert _lines("pfc_port", "mode", "set", {"port": "Ethernet1/5"}, {"mode": mode}) == (
        "interface Ethernet1/5",
        f"priority-flow-control mode {mode}",
    )


def test_port_mode_removed_and_watchdog() -> None:
    assert _lines("pfc_port", "mode", "remove", {"port": "Ethernet1/5"}, {})[-1] == (
        "no priority-flow-control mode"
    )
    assert _lines("pfc_port", "watchdog", "set", {"port": "Ethernet1/5"}, {"state": "on"})[-1] == (
        "priority-flow-control watch-dog-interval on"
    )


def test_switch_wide_lines() -> None:
    assert _lines("pfc_switch", "watchdog", "set", {}, {"state": "off"}) == (
        "priority-flow-control watch-dog-interval off",
    )
    assert _lines("pfc_switch", "override", "set", {}, {}) == (
        "priority-flow-control override-interface mode off",
    )


@pytest.mark.parametrize("bad", ["maybe", "", "ON; shut"])
def test_a_bad_mode_is_refused(bad: str) -> None:
    with pytest.raises(ValueError):
        _lines("pfc_port", "mode", "set", {"port": "Ethernet1/5"}, {"mode": bad})


def test_the_protocol_has_both_places() -> None:
    assert [s.key for s in PFC.scopes] == ["pfc_port", "pfc_switch"]
