"""Monitor sessions (app/monitor.py): reading ``show monitor session all``, the lines
every setting sends, and the values NXray refuses."""

from __future__ import annotations

import pytest

from app.monitor import (
    MONITOR,
    SESSION_MAX,
    build_monitor_change,
    load_monitor_page,
    parse_monitor,
    parse_origin,
)
from app.nxapi import NxapiCommandError
from tests.conftest import load_fixture


def _lines(scope: str, setting: str, action: str, ident: dict, values: dict) -> tuple[str, ...]:
    return build_monitor_change(scope, setting, action, ident, values).lines


# ---- reading ---------------------------------------------------------------------


def test_parse_origin() -> None:
    config = (
        "version 9.3(16)\nmonitor session 30 \n\n"
        "monitor erspan origin ip-address 192.0.2.1 global\n"
    )
    assert parse_origin(config) == "192.0.2.1"
    assert parse_origin("version 9.3(16)\n") == ""


def test_the_sessions_become_places_and_a_table() -> None:
    view = parse_monitor([load_fixture("show_monitor_session_all")], "192.0.2.1")
    local = view.of("span")
    assert [i.ident for i in local] == [{"session": "30"}]
    facts = dict(local[0].facts)
    assert facts["State"] == "down (Session admin shut)"
    assert facts["Source ports"] == "Ethernet1/54 (rx)"
    assert facts["Source VLANs"] == "250 (rx)"
    assert facts["Only VLANs"] == "1-10"
    assert facts["Destination port"] == "Ethernet1/53"
    assert local[0].values["description"] == {"text": "uplink to analyzer"}

    erspan = view.of("erspan")
    assert [i.ident for i in erspan] == [{"session": "31"}]
    facts = dict(erspan[0].facts)
    assert facts["Destination address"] == "10.250.250.1" and facts["ERSPAN ID"] == "7"
    assert erspan[0].values["ttl"] == {"ttl": "32"}
    assert erspan[0].values["destination_ip"] == {"address": "10.250.250.1"}
    assert erspan[0].values["mtu"] == {"mtu": "1400"}

    assert view.of("erspan_dst") == []
    assert view.of("origin")[0].values == {"origin": {"address": "192.0.2.1"}}
    table = view.tables[0]
    assert [row[0] for row in table.rows] == ["30", "31"]
    assert table.rows[0][3] == "Ethernet1/54 (rx); VLAN 250 (rx)"


def test_no_session_is_an_empty_page() -> None:
    view = parse_monitor([{}])
    assert view.instances == () and view.tables[0].rows == ()


def test_one_session_is_a_row_not_a_list() -> None:
    body = {"TABLE_session": {"ROW_session": {"session_number": "5", "type": "local"}}}
    view = parse_monitor([body])
    assert [i.title for i in view.instances] == ["Session 5"]


def test_an_erspan_destination_session_is_a_place() -> None:
    body = {"TABLE_session": {"ROW_session": {"session_number": "6", "type": "erspan-destination"}}}
    view = parse_monitor([body])
    assert [i.ident for i in view.of("erspan_dst")] == [{"session": "6"}]
    assert view.tables[0].rows[0][:2] == ("6", "erspan-destination")


def test_a_session_type_without_a_form_is_only_in_the_table() -> None:
    body = {"TABLE_session": {"ROW_session": {"session_number": "6", "type": "something-new"}}}
    view = parse_monitor([body])
    assert view.instances == () and view.tables[0].rows[0][:2] == ("6", "something-new")


# ---- the lines each setting sends ------------------------------------------------


def test_make_and_delete_a_local_session() -> None:
    assert _lines("span", "", "create", {"session": "30"}, {}) == ("monitor session 30",)
    assert _lines("span", "", "delete", {"session": "30"}, {}) == ("no monitor session 30",)


def test_an_erspan_session_is_always_entered_with_its_type() -> None:
    # Entered plainly it is a local session and the switch refuses ERSPAN lines in it.
    for setting, values, line in (
        ("erspan_id", {"id": "7"}, "erspan-id 7"),
        ("destination_ip", {"address": "10.250.250.1"}, "destination ip 10.250.250.1"),
        ("ttl", {"ttl": "32"}, "ip ttl 32"),
        ("dscp", {"dscp": "10"}, "ip dscp 10"),
        ("vrf", {"vrf_name": "default"}, "vrf default"),
    ):
        assert _lines("erspan", setting, "set", {"session": "31"}, values) == (
            "monitor session 31 type erspan-source",
            line,
        )


def test_an_erspan_destination_session_is_entered_with_its_type() -> None:
    # Written from Cisco's guide: the switch refused these lines while nve was on, so
    # they were not tried on cisco-25gb.
    enter = "monitor session 8 type erspan-destination"
    for setting, values, line in (
        ("source_ip", {"address": "192.0.2.1"}, "source ip 192.0.2.1"),
        ("erspan_id", {"id": "7"}, "erspan-id 7"),
        ("destination_interface", {"port": "Ethernet1/53"}, "destination interface Ethernet1/53"),
        ("admin_up", {}, "no shut"),
    ):
        assert _lines("erspan_dst", setting, "set", {"session": "8"}, values) == (enter, line)
    assert _lines("erspan_dst", "", "delete", {"session": "8"}, {}) == ("no monitor session 8",)


def test_sources_destination_and_state() -> None:
    ident = {"session": "30"}
    enter = "monitor session 30"
    assert _lines(
        "span", "source_interface", "set", ident, {"port": "Ethernet1/54", "direction": "rx"}
    ) == (
        enter,
        "source interface Ethernet1/54 rx",
    )
    assert _lines("span", "source_interface", "remove", ident, {"port": "Ethernet1/54"}) == (
        enter,
        "no source interface Ethernet1/54",
    )
    assert (
        _lines("span", "source_vlan", "set", ident, {"vlans": "10, 20-30", "direction": "rx"})[1]
        == "source vlan 10,20-30 rx"
    )
    assert _lines("span", "filter_vlan", "set", ident, {"vlans": "1-10"})[1] == "filter vlan 1-10"
    assert _lines("span", "destination_interface", "set", ident, {"port": "Ethernet1/53"})[1] == (
        "destination interface Ethernet1/53"
    )
    assert _lines("span", "admin_up", "set", ident, {})[1] == "no shut"
    assert _lines("span", "admin_down", "set", ident, {})[1] == "shut"
    assert _lines("span", "description", "set", ident, {"text": "analyzer"})[1] == (
        "description analyzer"
    )
    assert _lines("span", "description", "remove", ident, {})[1] == "no description"


def test_destination_port_and_origin_address() -> None:
    assert _lines("dest_port", "monitor", "set", {"port": "Ethernet1/53"}, {}) == (
        "interface Ethernet1/53",
        "switchport monitor",
    )
    assert _lines("dest_port", "monitor", "remove", {"port": "Ethernet1/53"}, {}) == (
        "interface Ethernet1/53",
        "no switchport monitor",
    )
    assert _lines("origin", "origin", "set", {}, {"address": "192.0.2.1"}) == (
        "monitor erspan origin ip-address 192.0.2.1 global",
    )
    assert _lines("origin", "origin", "remove", {}, {"address": "192.0.2.1"}) == (
        "no monitor erspan origin ip-address 192.0.2.1 global",
    )


# ---- what is refused -------------------------------------------------------------


@pytest.mark.parametrize("session", ["0", str(SESSION_MAX + 1), "x", ""])
def test_session_numbers_outside_1_to_32_are_refused(session: str) -> None:
    with pytest.raises(ValueError):
        build_monitor_change("span", "", "create", {"session": session}, {})


@pytest.mark.parametrize(
    ("setting", "values"),
    [
        ("source_interface", {"port": "Ethernet1/54", "direction": "sideways"}),
        ("source_vlan", {"vlans": "0", "direction": "rx"}),
        ("source_vlan", {"vlans": "10;20", "direction": "rx"}),
        ("description", {"text": "x" * 33}),
        ("description", {"text": "a ; b"}),
        ("mtu", {"mtu": "63"}),
    ],
)
def test_bad_values_are_refused(setting: str, values: dict) -> None:
    with pytest.raises(ValueError):
        build_monitor_change("span", setting, "set", {"session": "30"}, values)


@pytest.mark.parametrize(
    ("setting", "values"),
    [
        ("erspan_id", {"id": "1024"}),
        ("ttl", {"ttl": "0"}),
        ("dscp", {"dscp": "64"}),
        ("destination_ip", {"address": "not-an-address"}),
        ("vrf", {"vrf_name": "bad name"}),
    ],
)
def test_bad_erspan_values_are_refused(setting: str, values: dict) -> None:
    with pytest.raises(ValueError):
        build_monitor_change("erspan", setting, "set", {"session": "31"}, values)


def test_the_page_is_described_by_the_shared_parts() -> None:
    assert [s.key for s in MONITOR.scopes] == [
        "span",
        "erspan",
        "erspan_dst",
        "dest_port",
        "origin",
    ]


class _Client:
    """A client whose `show monitor session all` fails with ``message``."""

    def __init__(self, message: str) -> None:
        self.message = message

    def show(self, *commands: str):
        if commands == ("show monitor session all",):
            raise NxapiCommandError(self.message)
        return [load_fixture("show_interface_brief"), load_fixture("show_feature")]

    def show_text(self, command: str) -> str:
        return ""


def test_the_note_for_no_sessions_is_not_a_warning() -> None:
    # cisco-25gb answers "CLI output cannot be parsed by the server" when there is none.
    for message in (
        "'show monitor session all': CLI output cannot be parsed by the server",
        "Note: There are no sessions configured",
    ):
        page = load_monitor_page(_Client(message))  # type: ignore[arg-type]
        assert page.problem == "" and page.view.tables[0].rows == ()


def test_any_other_refusal_is_shown() -> None:
    page = load_monitor_page(_Client("% Permission denied for the role"))  # type: ignore[arg-type]
    assert "did not report its monitor sessions" in page.problem
