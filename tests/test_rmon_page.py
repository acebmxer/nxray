"""The RMON page (#95), end to end against the fake switch, and its parsers."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.rmon import build_rmon_change, parse_alarms, parse_events, parse_rmon
from tests.fake_switch import FakeSwitch
from tests.stage_d_helpers import config_requests, csrf, enable, set_up, text

FIXTURES = Path(__file__).parent / "fixtures"
# Recorded on cisco-25gb (NX-OS 9.3(16), 2026-11-13).
EVENTS = (FIXTURES / "show_rmon_events.txt").read_text()
ALARMS = (FIXTURES / "show_rmon_alarms.txt").read_text()
HCALARMS = (FIXTURES / "show_rmon_hcalarms.txt").read_text()
OID = "1.3.6.1.2.1.2.2.1.10.436234240"


def _lines(scope, action="create", **ident):
    return list(build_rmon_change(scope, "", action, ident, {}).lines)


def test_the_lines() -> None:
    assert _lines("event", id="250") == ["rmon event 250"]
    assert _lines("event", id="251", log="yes", trap="public", description="x", owner="me") == [
        "rmon event 251 log trap public description x owner me"
    ]
    assert _lines("event", "delete", id="251") == ["no rmon event 251"]
    alarm = {
        "id": "250", "oid": OID, "interval": "30", "sample": "delta",
        "rising": "100", "falling": "10",
    }  # fmt: skip
    assert _lines("alarm", **alarm) == [
        f"rmon alarm 250 {OID} 30 delta rising-threshold 100 falling-threshold 10"
    ]
    assert _lines("alarm", **alarm, rising_event="250", falling_event="251", owner="me") == [
        f"rmon alarm 250 {OID} 30 delta rising-threshold 100 250 falling-threshold 10 251 owner me"
    ]
    assert _lines("alarm", "delete", **alarm) == ["no rmon alarm 250"]
    assert _lines(
        "hcalarm", **alarm, startup="1", rising_event="250", falling_event="251", owner="me"
    ) == [
        f"rmon hcalarm 250 {OID} 30 delta startupalarm 1 rising-threshold 100 250 "
        "falling-threshold 10 251 owner me"
    ]


@pytest.mark.parametrize(
    ("scope", "ident"),
    [
        ("event", {"id": "0"}),
        ("event", {"id": "65536"}),
        ("event", {"id": "1", "trap": "a" * 33}),
        ("event", {"id": "1", "description": "two words"}),
        (
            "alarm",
            {
                "id": "1",
                "oid": "ifInOctets.1",
                "interval": "30",
                "sample": "delta",
                "rising": "10",
                "falling": "1",
            },
        ),  # fmt: skip
        (
            "alarm",
            {
                "id": "1",
                "oid": OID,
                "interval": "700001",
                "sample": "delta",
                "rising": "10",
                "falling": "1",
            },
        ),  # fmt: skip
        (
            "alarm",
            {
                "id": "1",
                "oid": OID,
                "interval": "30",
                "sample": "delta",
                "rising": "10",
                "falling": "10",
            },
        ),  # the switch: falling must be lesser
        (
            "alarm",
            {
                "id": "1",
                "oid": OID,
                "interval": "30",
                "sample": "up",
                "rising": "10",
                "falling": "1",
            },
        ),  # fmt: skip
    ],
)
def test_the_checks(scope: str, ident: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        build_rmon_change(scope, "", "create", ident, {})


def test_events_are_read() -> None:
    events = parse_events(EVENTS)
    assert [e.number for e in events] == ["1", "2", "5", "250", "251", "253"]
    first = events[0]
    assert (first.log, first.trap, first.owner) == (True, "public", "PMON@FATAL")
    assert first.description == "FATAL(1)"
    empty, trap_only, log_only = events[3], events[4], events[5]
    assert (empty.log, empty.trap, empty.owner, empty.description) == (False, "", "", "")
    assert (trap_only.log, trap_only.trap, trap_only.description) == (False, "public", "newdesc")
    assert (log_only.log, log_only.trap, log_only.owner) == (True, "", "nxprobe")


def test_alarms_are_read() -> None:
    alarms = parse_alarms(ALARMS)
    assert [a.number for a in alarms] == ["250", "253"]
    first = alarms[0]
    assert (first.oid, first.interval, first.sample) == (OID, "40", "delta")
    assert (first.rising, first.rising_event) == ("200", "250")
    assert (first.falling, first.falling_event, first.owner) == ("20", "251", "nxprobe2")
    (high,) = parse_alarms(HCALARMS)
    assert high.high_capacity and high.startup == "rising alarm" and high.owner == "nxprobe"
    assert parse_alarms(None) == [] and parse_events("") == []


def test_the_view_has_a_place_for_each() -> None:
    view = parse_rmon(EVENTS, ALARMS, HCALARMS, "Number of 32 bit alarms configured : 2\n")
    assert [i.scope for i in view.instances] == ["event"] * 6 + ["alarm"] * 2 + ["hcalarm"]
    event = view.instances[0]
    assert event.ident == {
        "id": "1", "log": "log", "trap": "public", "description": "FATAL(1)",
        "owner": "PMON@FATAL",
    }  # fmt: skip
    assert dict(event.facts)["When it fires"] == "log and trap to public"
    assert view.instances[-1].ident["startup"] == "1"
    assert view.tables[0].rows == (("Number of 32 bit alarms configured", "2"),)
    assert any("did not show" in n for n in parse_rmon(None, ALARMS, HCALARMS, None).notes)


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    return set_up(logged_in)


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/rmon/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/rmon", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/rmon"' in logged_in.get("/").text


def test_the_page_reads_what_the_switch_has(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.rmon_events[7] = {"log": True, "trap": "public", "description": "d", "owner": "o"}
    switch.rmon_alarms[9] = {
        "hc": False, "oid": OID, "interval": "30", "sample": "delta", "rising": "10",
        "rising_event": "7", "falling": "1", "falling_event": "7", "owner": "o",
    }  # fmt: skip
    page = logged_in.get("/rmon")
    assert page.status_code == 200, text(page.text)
    shown = text(page.text)
    assert "Event 7" in shown and "log and trap to public" in shown and "Alarm 9" in shown
    assert OID in shown
    assert switch.requests == [
        ["show rmon events"],
        ["show rmon alarms"],
        ["show rmon hcalarms"],
        ["show rmon info"],
    ]


def test_an_event_and_an_alarm_are_made_and_deleted(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    asked = _change(
        logged_in,
        confirm=False,
        scope="event",
        action="create",
        id_id="250",
        id_log="yes",
        id_trap="public",
    )
    assert "rmon event 250 log trap public" in text(asked.text)
    assert config_requests(switch) == []
    done = _change(
        logged_in, scope="event", action="create", id_id="250", id_log="yes", id_trap="public"
    )
    assert done.status_code == 200, text(done.text)
    assert switch.rmon_events[250]["log"] and switch.rmon_events[250]["trap"] == "public"
    assert "Event 250" in text(logged_in.get("/rmon").text)
    alarm = {
        "scope": "alarm", "action": "create", "id_id": "250", "id_oid": OID,
        "id_interval": "30", "id_sample": "delta", "id_rising": "100",
        "id_rising_event": "250", "id_falling": "10", "id_falling_event": "250",
    }  # fmt: skip
    made = _change(logged_in, **alarm)
    assert made.status_code == 200, text(made.text)
    assert switch.rmon_alarms[250]["rising_event"] == "250"
    gone = _change(logged_in, scope="alarm", action="delete", **{
        k: v for k, v in alarm.items() if k.startswith("id_")
    })  # fmt: skip
    assert gone.status_code == 200, text(gone.text)
    assert 250 not in switch.rmon_alarms
    removed = _change(logged_in, scope="event", action="delete", id_id="250", id_log="yes")
    assert removed.status_code == 200, text(removed.text)
    assert 250 not in switch.rmon_events


def test_a_description_is_kept_when_an_event_is_entered_again(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    switch.rmon_events[5] = {"log": True, "trap": "", "description": "keep", "owner": "me"}
    done = _change(logged_in, scope="event", action="create", id_id="5", id_trap="public")
    assert done.status_code == 200, text(done.text)
    assert switch.rmon_events[5] == {
        "log": False, "trap": "public", "description": "keep", "owner": "me"
    }  # fmt: skip


def test_the_switchs_refusals_are_shown(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    refused = _change(
        logged_in, scope="alarm", action="create", id_id="3", id_oid="1.3.6.1.2.1.2.2.1.10.1",
        id_interval="30", id_sample="delta", id_rising="10", id_falling="1",
    )  # fmt: skip
    assert refused.status_code == 400 and "No such entry" in text(refused.text)
    backwards = _change(
        logged_in, scope="alarm", action="create", id_id="3", id_oid=OID, id_interval="30",
        id_sample="delta", id_rising="10", id_falling="10",
    )  # fmt: skip
    assert backwards.status_code == 400 and "falling threshold is below" in text(backwards.text)
    assert switch.rmon_alarms == {}


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "limited")
    refused = _change(logged_in, scope="event", action="create", id_id="250")
    assert refused.status_code == 400 and "RMON changes are off" in text(refused.text)
    assert config_requests(switch) == []


def test_save_config_comes_back_here(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    saved = logged_in.post("/switch/save", data={"csrf": csrf(logged_in), "back": "rmon"})
    assert saved.status_code == 200 and "RMON" in text(saved.text) and switch.saved
