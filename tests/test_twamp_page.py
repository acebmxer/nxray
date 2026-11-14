"""The TWAMP server page (#95), end to end against the fake switch, and its parsers."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.twamp import build_twamp_change, parse_standards, parse_twamp, parse_twamp_config
from tests.fake_switch import FakeSwitch
from tests.stage_d_helpers import config_requests, csrf, enable, set_up, text

FIXTURES = Path(__file__).parent / "fixtures"
# Recorded on cisco-25gb (NX-OS 9.3(16), 2026-11-13).
CONFIG = (FIXTURES / "show_running_config_section_twamp.txt").read_text()
STANDARDS = (
    "\nFeature                   Organization    Standard\n"
    "TWAMP Server              IETF            RFC5357\n"
    "TWAMP Reflector           IETF            RFC5357\n"
)


def _lines(scope, setting, action="set", **values):
    return list(build_twamp_change(scope, setting, action, {}, values).lines)


def test_the_lines() -> None:
    assert _lines("server", "port", port="1000") == ["ip sla server twamp", "port 1000"]
    assert _lines("server", "port", "remove") == ["ip sla server twamp", "no port"]
    assert _lines("server", "inactivity", seconds="300") == [
        "ip sla server twamp",
        "timer inactivity 300",
    ]
    assert _lines("server", "inactivity", "remove") == [
        "ip sla server twamp",
        "no timer inactivity",
    ]
    assert _lines("responder", "enabled") == ["ip sla responder twamp"]
    assert _lines("responder", "enabled", "remove") == ["no ip sla responder twamp"]


@pytest.mark.parametrize(
    ("setting", "values"),
    [
        ("port", {"port": "0"}),
        ("port", {"port": "65536"}),
        ("inactivity", {"seconds": "6001"}),
        ("inactivity", {"seconds": "0"}),
    ],  # fmt: skip
)
def test_the_ranges_are_the_switchs(setting: str, values: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        build_twamp_change("server", setting, "set", {}, values)


def test_the_configuration_is_read() -> None:
    assert parse_twamp_config(CONFIG) == {
        "server": {"port": {"port": "65535"}, "inactivity": {"seconds": "6000"}},
        "responder": {"enabled": {}},
    }
    assert parse_twamp_config("feature sla twamp-server\n") == {"server": {}, "responder": {}}
    assert parse_standards(STANDARDS) == (
        ("TWAMP Server", "IETF", "RFC5357"),
        ("TWAMP Reflector", "IETF", "RFC5357"),
    )
    view = parse_twamp(CONFIG, "\nIP SLAs Responder TWAMP is: Disabled\n", STANDARDS)
    assert dict(view.instances[0].facts) == {"State": "IP SLAs Responder TWAMP is: Disabled"}
    assert dict(view.instances[1].facts)["Responder line"] == "in the configuration"
    assert any("did not show" in n for n in parse_twamp(None).notes)


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    return set_up(logged_in)


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/twamp/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/twamp", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/twamp"' in logged_in.get("/").text


def test_with_the_feature_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["sla_twamp"] = False
    page = logged_in.get("/twamp")
    assert page.status_code == 200, text(page.text)
    assert "is off on the switch" in text(page.text)
    assert switch.requests == [["show feature"]]


def test_page_reads_the_server(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    switch.feature_state["sla_twamp"] = True
    switch.mon_lines += ["ip sla server twamp", "ip sla server twamp ; port 1000"]
    page = logged_in.get("/twamp")
    assert page.status_code == 200, text(page.text)
    shown = text(page.text)
    assert "IP SLAs Responder TWAMP is: Disabled" in shown and "RFC5357" in shown
    assert 'value="1000"' in page.text  # the port form shows it set


def test_settings_are_sent_and_read_back(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    switch.feature_state["sla_twamp"] = True
    asked = _change(
        logged_in, confirm=False, scope="server", setting="port", action="set", v_port="1000"
    )
    assert "port 1000" in text(asked.text) and config_requests(switch) == []
    done = _change(logged_in, scope="server", setting="port", action="set", v_port="1000")
    assert done.status_code == 200, text(done.text)
    assert "ip sla server twamp ; port 1000" in switch.mon_lines
    again = _change(logged_in, scope="server", setting="port", action="set", v_port="2000")
    assert again.status_code == 200 and "ip sla server twamp ; port 1000" not in switch.mon_lines
    idle = _change(logged_in, scope="server", setting="inactivity", action="set", v_seconds="300")
    assert idle.status_code == 200, text(idle.text)
    back = _change(logged_in, scope="server", setting="port", action="remove")
    assert back.status_code == 200, text(back.text)
    assert not any("port" in line for line in switch.mon_lines)
    on = _change(logged_in, scope="responder", setting="enabled", action="set")
    assert on.status_code == 200 and "ip sla responder twamp" in switch.mon_lines
    off = _change(logged_in, scope="responder", setting="enabled", action="remove")
    assert off.status_code == 200 and "ip sla responder twamp" not in switch.mon_lines


def test_the_switchs_refusal_is_shown(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    switch.feature_state["sla_twamp"] = True
    refused = _change(logged_in, scope="server", setting="port", action="set", v_port="70000")
    assert refused.status_code == 400 and "Not changed" in text(refused.text)
    assert config_requests(switch) == []


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "limited")
    switch.feature_state["sla_twamp"] = True
    refused = _change(logged_in, scope="server", setting="port", action="set", v_port="1000")
    assert refused.status_code == 400 and "TWAMP server changes are off" in text(refused.text)
    assert config_requests(switch) == []


def test_save_config_comes_back_here(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    saved = logged_in.post("/switch/save", data={"csrf": csrf(logged_in), "back": "twamp"})
    assert saved.status_code == 200 and "TWAMP" in text(saved.text) and switch.saved
