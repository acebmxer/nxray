"""IP SLA (app/ip_sla.py): reading the entries, results, schedules and reactions, the
lines every setting sends, and the values NXray refuses.

The show output and the lines were recorded on cisco-25gb (NX-OS 9.3(16)) with throwaway
entries 9000-9009; the switch's own addresses are replaced by documentation ones. The two
results in ``show_ip_sla_statistics_details_results`` were printed by the switch a minute
apart (9000 pinging a router that answered, 9001 an address that did not)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.ip_sla import (
    IP_SLA,
    build_ip_sla_change,
    entry_values,
    parse_ip_sla,
    parse_sla_config,
    schedule_values,
)
from app.protocols import Field, check_value
from tests.conftest import load_fixture

CONFIG = load_fixture("show_ip_sla_configuration")
STATS = load_fixture("show_ip_sla_statistics_details")
RESULTS = load_fixture("show_ip_sla_statistics_details_results")
TEXT = (Path(__file__).parent / "fixtures" / "show_running-config_sla_sender.txt").read_text()


def _view(stats=STATS, text: str | None = TEXT):
    return parse_ip_sla([CONFIG, stats], text)


def _lines(scope: str, setting: str, action: str, ident: dict, values: dict) -> tuple[str, ...]:
    return build_ip_sla_change(scope, setting, action, ident, values).lines


def test_every_entry_is_a_row_with_what_it_measures() -> None:
    rows = {row[0]: row for row in _view().tables[0].rows}
    assert sorted(rows) == [str(n) for n in range(9001, 9010)]
    assert rows["9001"][1:5] == ("icmp-echo 192.0.2.1", "default", "30 s", "Inactive")
    assert rows["9002"][1] == "udp-jitter 192.0.2.1 port 5000"
    assert rows["9003"][2] == "management"
    assert rows["9005"][1] == "dns www.example.com via 192.0.2.1"
    assert rows["9006"][1] == "http get http://192.0.2.1/"
    # Never run: no result and no counts.
    assert rows["9002"][5:] == ("-", "- / -", "-")


def test_the_latest_result_in_words() -> None:
    rows = {row[0]: row for row in _view(RESULTS).tables[0].rows}
    assert rows["9001"][5:] == ("Timeout", "0 / 1", "10:57:36.929 UTC Wed Nov 11 2026")
    assert rows["9001"][4] == "Active"
    ok = parse_ip_sla(
        [
            {
                "TABLE_configuration": {
                    "ROW_configuration": {
                        "index": 9000,
                        "oper-type": "icmp-echo",
                        "dest-ip": "198.51.100.1",
                        "vrf-name": "management",
                        "frequency": 10,
                    }
                }
            },
            RESULTS,
        ]
    )
    assert ok.tables[0].rows[0][5:7] == ("OK, 1 ms", "3 / 0")


def test_the_configuration_text_by_entry() -> None:
    found = parse_sla_config(TEXT)
    assert found[9002].measure == "udp-jitter 192.0.2.1 5000 num-packets 5"
    assert found[9002].lines == ["tos 46", "frequency 30"]
    assert found[9008].schedule == "life forever start-time after 00:30:00 ageout 7200"
    assert ("timeout", "") in found[9001].reactions
    assert found[9005].triggers == ["9006"]


def test_an_entry_shows_its_current_settings() -> None:
    found = parse_sla_config(TEXT)
    assert entry_values(found[9002]) == {
        "udp_jitter": {"target": "192.0.2.1", "port": "5000", "packets": "5"},
        "tos": {"tos": "46"},
        "frequency": {"seconds": "30"},
    }
    assert entry_values(found[9009])["udp_jitter"] == {
        "target": "192.0.2.1",
        "port": "5003",
        "source": "198.51.100.2",
        "source_port": "6000",
        "interval": "30",
    }
    assert entry_values(found[9003])["vrf"] == {"vrf": "management"}
    assert entry_values(found[9006]) == {"http": {"url": "http://192.0.2.1/"}}


def test_schedules_and_reactions_are_places() -> None:
    view = _view()
    schedules = {i.ident["sla"]: i for i in view.of("schedule")}
    assert sorted(schedules) == ["9007", "9008", "9009"]
    assert schedules["9009"].values["schedule"] == {"life": "60", "start": "01:00:00 Nov 12"}
    assert schedules["9007"].values["schedule"] == {
        "start": "01:00:00",
        "ageout": "86400",
        "recurring": "recurring",
    }
    reactions = {i.ident["sla"]: i for i in view.of("reaction")}
    assert sorted(reactions) == ["9001", "9002", "9005", "9006"]
    assert ("Starts entry", "9006") in reactions["9005"].facts
    assert reactions["9005"].values == {"trigger": {"target": "9006"}}


def test_without_the_configuration_text_the_page_says_so() -> None:
    view = _view(text=None)
    assert len(view.tables[0].rows) == 9 and view.of("schedule") == []
    assert "did not show its IP SLA configuration" in view.notes[0]


def test_schedule_values() -> None:
    assert schedule_values("life 300 start-time now") == {"life": "300", "start": "now"}
    assert schedule_values("") == {}


def test_making_an_entry_sends_its_measuring_line() -> None:
    assert _lines("entry", "icmp_echo", "set", {"entry": "10"}, {"target": "192.0.2.1"}) == (
        "ip sla 10",
        "icmp-echo 192.0.2.1",
    )
    assert _lines(
        "entry",
        "udp_jitter",
        "set",
        {"entry": "11"},
        {"target": "192.0.2.1", "port": "5000", "source": "198.51.100.2", "packets": "5"},
    ) == ("ip sla 11", "udp-jitter 192.0.2.1 5000 source-ip 198.51.100.2 num-packets 5")
    assert _lines(
        "entry", "dns", "set", {"entry": "12"}, {"name": "www.example.com", "server": "192.0.2.1"}
    ) == ("ip sla 12", "dns www.example.com name-server 192.0.2.1")
    assert _lines("entry", "http", "set", {"entry": "13"}, {"url": "http://192.0.2.1"}) == (
        "ip sla 13",
        "http get http://192.0.2.1/",
    )


def test_what_an_entry_measures_cannot_be_removed() -> None:
    with pytest.raises(ValueError, match="cannot be removed"):
        build_ip_sla_change("entry", "icmp_echo", "remove", {"entry": "10"}, {})


def test_entry_settings_and_their_no_forms() -> None:
    assert _lines("entry", "frequency", "set", {"entry": "10"}, {"seconds": "30"}) == (
        "ip sla 10",
        "frequency 30",
    )
    assert _lines("entry", "verify_data", "remove", {"entry": "10"}, {}) == (
        "ip sla 10",
        "no verify-data",
    )
    assert _lines("entry", "vrf", "set", {"entry": "10"}, {"vrf": "management"})[-1] == (
        "vrf management"
    )
    assert (
        _lines("entry", "enhanced", "set", {"entry": "10"}, {"interval": "900", "buckets": "10"})[
            -1
        ]
        == "history enhanced interval 900 buckets 10"
    )
    assert _lines("entry", "tag", "remove", {"entry": "10"}, {})[-1] == "no tag"


def test_the_default_vrf_is_set_by_removing() -> None:
    with pytest.raises(ValueError, match="Remove goes back"):
        build_ip_sla_change("entry", "vrf", "set", {"entry": "10"}, {"vrf": "default"})


def test_deleting_an_entry() -> None:
    assert _lines("entry", "", "delete", {"entry": "10"}, {}) == ("no ip sla 10",)


def test_schedules() -> None:
    assert _lines(
        "schedule", "schedule", "set", {"sla": "10"}, {"life": "forever", "start": "now"}
    ) == ("ip sla schedule 10 life forever start-time now",)
    assert _lines(
        "schedule",
        "schedule",
        "set",
        {"sla": "10"},
        {"life": "3600", "start": "01:00", "ageout": "86400", "recurring": "yes"},
    ) == ("ip sla schedule 10 life 3600 start-time 01:00 ageout 86400 recurring",)
    assert _lines("schedule", "schedule", "set", {"sla": "10"}, {"start": "after 0:30:00"}) == (
        "ip sla schedule 10 start-time after 00:30:00",
    )
    assert _lines("schedule", "schedule", "set", {"sla": "10"}, {"start": "1:00:00 nov 12"}) == (
        "ip sla schedule 10 start-time 01:00:00 Nov 12",
    )
    assert _lines("schedule", "schedule", "remove", {"sla": "10"}, {}) == ("no ip sla schedule 10",)


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"start": "now", "recurring": "yes"}, "time of day"),
        ({"start": "01:00", "life": "90000", "recurring": "yes"}, "less than a day"),
        ({"start": "01:00", "life": "3600", "recurring": "yes"}, "more than a day"),
        ({"start": "tomorrow"}, "now, pending"),
        ({"start": "25:00"}, "00:00 to 23:59"),
        ({"start": "01:00:00 Foo 12"}, "month and a day"),
        ({"life": "0"}, "seconds, or forever"),
    ],
)
def test_schedules_the_switch_would_refuse(values: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        build_ip_sla_change("schedule", "schedule", "set", {"sla": "10"}, values)


def test_reactions() -> None:
    assert _lines(
        "reaction",
        "reaction",
        "set",
        {"sla": "10"},
        {
            "event": "rtt",
            "upper": "400",
            "lower": "200",
            "when": "consecutive",
            "count": "3",
            "action": "trapOnly",
        },
    ) == (
        "ip sla reaction-configuration 10 react rtt threshold-value 400 200 threshold-type "
        "consecutive 3 action-type trapOnly",
    )
    assert _lines(
        "reaction",
        "reaction",
        "set",
        {"sla": "10"},
        {
            "event": "jitterAvg",
            "upper": "10",
            "lower": "5",
            "when": "xofy",
            "count": "3",
            "of": "5",
        },
    ) == (
        "ip sla reaction-configuration 10 react jitterAvg threshold-value 10 5 threshold-type "
        "xofy 3 5",
    )
    assert _lines("reaction", "reaction", "remove", {"sla": "10"}, {"event": "timeout"}) == (
        "no ip sla reaction-configuration 10 react timeout",
    )
    assert _lines("reaction", "trigger", "set", {"sla": "10"}, {"target": "11"}) == (
        "ip sla reaction-trigger 10 11",
    )
    assert _lines("reaction", "trigger", "remove", {"sla": "10"}, {"target": "11"}) == (
        "no ip sla reaction-trigger 10 11",
    )


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"event": "rtt", "when": "consecutive"}, "how many times"),
        ({"event": "rtt", "when": "xofy", "count": "3"}, "out of how many"),
        ({"event": "rtt", "when": "xofy", "count": "6", "of": "5"}, "x cannot be more than y"),
        ({"event": "rtt", "when": "immediate", "count": "2"}, "takes no count"),
        ({"event": "rtt", "when": "immediate", "upper": "5", "lower": "10"}, "falling threshold"),
        ({"event": "nope", "when": "immediate"}, "Event is one of"),
    ],
)
def test_reactions_the_switch_would_refuse(values: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        build_ip_sla_change("reaction", "reaction", "set", {"sla": "10"}, values)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("ftp://192.0.2.1/", "web address"),
        ("http://192.0.2.1/a b", "web address"),
        ("http://192.0.2.1/?x=1", "cannot contain"),
        ("http://192.0.2.1:70000/", "1 to 65535"),
    ],
)
def test_web_addresses_refused(raw: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        check_value(Field("url", "Web address", "url"), raw)


def test_entry_numbers_and_ports_are_checked() -> None:
    with pytest.raises(ValueError, match="Entry is a number"):
        build_ip_sla_change("entry", "frequency", "set", {"entry": "0"}, {"seconds": "30"})
    with pytest.raises(ValueError, match="Target port is a number"):
        build_ip_sla_change(
            "entry", "udp_echo", "set", {"entry": "10"}, {"target": "192.0.2.1", "port": "70000"}
        )


def test_every_scope_is_on_the_page() -> None:
    assert [s.key for s in IP_SLA.scopes] == ["entry", "schedule", "reaction"]
    assert IP_SLA.features == ("sla_sender",)
