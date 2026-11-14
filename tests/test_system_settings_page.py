"""The Switch-wide settings page (#102), end to end against the fake switch, and its parser."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.system_settings import (
    build_system_settings_change,
    parse_system_config,
    parse_system_settings,
)
from tests.fake_switch import FakeSwitch
from tests.stage_d_helpers import config_requests, csrf, enable, set_up, text

CONFIG = """!Command: show running-config
hostname cisco-25gb
ip domain-lookup
ip http source-interface mgmt0
ip dns source-interface mgmt0
ip tcp path-mtu-discovery
ip tcp mss 1400
ip tcp synwait-time 20
xml server max-session 4
xml server validate all
acllog match-log-level 5
logging source-interface mgmt0
interface Ethernet1/1
  ip tcp mss 9
"""


def _lines(setting, action="set", **values):
    return list(build_system_settings_change("system", setting, action, {}, values).lines)


def test_the_lines() -> None:
    assert _lines("log_source", interface="mgmt0") == ["logging source-interface mgmt0"]
    assert _lines("log_source", "remove") == ["no logging source-interface"]
    assert _lines("dns_source", "remove", interface="mgmt0") == ["no ip dns source-interface mgmt0"]
    assert _lines("tcp_pmtud") == ["ip tcp path-mtu-discovery"]
    assert _lines("tcp_mss", bytes="1400") == ["ip tcp mss 1400"]
    assert _lines("tcp_mss", "remove") == ["no ip tcp mss"]
    assert _lines("tcp_syn", seconds="20") == ["ip tcp synwait-time 20"]
    assert _lines("xml_sessions", sessions="4") == ["xml server max-session 4"]
    assert _lines("xml_sessions", "remove", sessions="4") == ["no xml server max-session 4"]
    assert _lines("xml_validate") == ["xml server validate all"]
    assert _lines("acllog_level", level="5") == ["acllog match-log-level 5"]
    assert _lines("acllog_level", "remove", level="5") == ["no acllog match-log-level 5"]


@pytest.mark.parametrize(
    ("setting", "values"),
    [
        ("tcp_mss", {"bytes": "87"}),
        ("tcp_mss", {"bytes": "10001"}),
        ("tcp_syn", {"seconds": "4"}),
        ("tcp_syn", {"seconds": "301"}),
        ("xml_sessions", {"sessions": "9"}),
        ("acllog_level", {"level": "8"}),
        ("log_source", {"interface": "mgmt0 ; reload"}),
    ],  # fmt: skip
)
def test_the_ranges_are_the_switchs(setting: str, values: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        build_system_settings_change("system", setting, "set", {}, values)


def test_the_configuration_is_read() -> None:
    values = parse_system_config(CONFIG)
    assert values["log_source"] == {"interface": "mgmt0"}
    assert values["tcp_mss"] == {"bytes": "1400"}  # not the interface's line
    assert values["tcp_pmtud"] == {} and values["xml_validate"] == {}
    assert values["acllog_level"] == {"level": "5"}
    assert parse_system_config("hostname x\n") == {}
    assert any("did not show" in n for n in parse_system_settings(None).notes)


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    return set_up(logged_in)


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": csrf(client), "scope": "system", **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/system-settings/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/system-settings", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/system-settings"' in logged_in.get("/").text


def test_page_reads_what_is_set(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    switch.sys_lines += ["ip tcp mss 1400"]
    page = logged_in.get("/system-settings")
    assert page.status_code == 200, text(page.text)
    assert 'value="1400"' in page.text


def test_settings_are_sent_and_read_back(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    asked = _change(logged_in, confirm=False, setting="tcp_mss", action="set", v_bytes="1400")
    assert "ip tcp mss 1400" in text(asked.text) and config_requests(switch) == []
    done = _change(logged_in, setting="tcp_mss", action="set", v_bytes="1400")
    assert done.status_code == 200, text(done.text)
    assert "ip tcp mss 1400" in switch.sys_lines
    again = _change(logged_in, setting="tcp_mss", action="set", v_bytes="1200")
    assert again.status_code == 200 and "ip tcp mss 1400" not in switch.sys_lines
    back = _change(logged_in, setting="tcp_mss", action="remove")
    assert back.status_code == 200, text(back.text)
    assert switch.sys_lines == []
    dns = _change(logged_in, setting="dns_source", action="set", v_interface="mgmt0")
    assert dns.status_code == 200, text(dns.text)
    assert "ip dns source-interface mgmt0" in switch.sys_lines
    gone = _change(logged_in, setting="dns_source", action="remove", v_interface="mgmt0")
    assert gone.status_code == 200 and switch.sys_lines == []
    on = _change(logged_in, setting="xml_validate", action="set")
    assert on.status_code == 200 and "xml server validate all" in switch.sys_lines


def test_a_value_out_of_range_is_refused_before_the_switch(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    refused = _change(logged_in, setting="tcp_syn", action="set", v_seconds="301")
    assert refused.status_code == 400 and "Not changed" in text(refused.text)
    assert config_requests(switch) == []


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "limited")
    refused = _change(logged_in, setting="tcp_mss", action="set", v_bytes="1400")
    assert refused.status_code == 400 and "changes are off" in text(refused.text)
    assert config_requests(switch) == []


def test_save_config_comes_back_here(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    data = {"csrf": csrf(logged_in), "back": "system-settings"}
    saved = logged_in.post("/switch/save", data=data)
    assert saved.status_code == 200 and "Switch-wide settings" in text(saved.text)
    assert switch.saved
