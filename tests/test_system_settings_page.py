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


def _scoped(setting, scope="system", action="set", ident=None, **values):
    return list(build_system_settings_change(scope, setting, action, ident or {}, values).lines)


def test_the_other_lines() -> None:
    assert _scoped("ifalias_long") == ["snmp ifmib ifalias long"]
    assert _scoped("cpu_rate_limit", direction="input", pps="1000") == [
        "rate-limit cpu direction input pps 1000 action log"
    ]
    assert _scoped("cpu_rate_limit", action="remove", direction="input", pps="1000") == [
        "no rate-limit cpu direction input pps 1000 action log"
    ]
    assert _scoped("onboard_logging") == ["hw-module logging onboard"]
    assert _scoped("onboard_logging", kind="cpuhog") == ["hw-module logging onboard cpuhog"]
    assert _scoped("load_sharing", rotate="5") == [
        "ip load-sharing address source-destination port source-destination rotate 5"
    ]
    assert _scoped("routing_mode", mode="host") == ["system routing max-mode host"]
    assert _scoped("default_switchport") == ["system default switchport"]
    assert _scoped("switching_mode", mode="store-forward") == ["switching-mode store-forward"]
    assert _scoped("afd_profile", profile="burst") == ["hardware qos afd profile burst"]
    assert _scoped("llfc_watchdog", state="on") == ["link-level-flow-control watch-dog-interval on"]
    assert _scoped("sockets_range", low="15001", high="22001") == [
        "sockets local-port-range 15001 22001"
    ]
    assert _scoped("fips") == ["fips mode enable"]
    assert _scoped("periodic", "time_range", ident={"name": "work"}, days="weekdays",
                   start="08:00", end="17:00") == [
        "time-range work",
        "periodic weekdays 08:00 to 17:00",
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("setting", "values"),
    [
        ("cpu_rate_limit", {"direction": "sideways", "pps": "1"}),
        ("cpu_rate_limit", {"direction": "input", "pps": "100001"}),
        ("routing_mode", {"mode": "l3 ; reload"}),
        ("switching_mode", {"mode": "cut-through"}),
        ("l2pt_cos", {"cos": "8"}),
        ("buffer_threshold", {"percent": "96"}),
        ("sockets_range", {"low": "15000", "high": "22001"}),
    ],  # fmt: skip
)
def test_the_other_ranges_and_choices(setting: str, values: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        build_system_settings_change("system", setting, "set", {}, values)


def test_time_ranges_are_read() -> None:
    config = (
        "hostname x\ntime-range work\n  10 periodic weekdays 08:00:00 to 17:00:00\n"
        "  20 absolute start 08:00:00 1 January 2027 end 17:00:00 31 December 2027\n"
        "time-range empty\nrate-limit cpu direction input pps 1000 action log\n"
    )
    view = parse_system_settings(config)
    titles = [i.title for i in view.instances]
    assert titles == ["Switch-wide settings", "Time range work", "Time range empty"]
    work = view.instances[1]
    assert work.ident == {"name": "work"}
    assert work.values == {"periodic": {"days": "weekdays", "start": "08:00", "end": "17:00"}}
    assert dict(work.facts)["Entries"].startswith("periodic weekdays")
    assert dict(view.instances[2].facts)["Entries"] == "none"
    assert view.instances[0].values["cpu_rate_limit"] == {"direction": "input", "pps": "1000"}


def test_the_other_settings_are_sent_and_read_back(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    rate = _change(
        logged_in, setting="cpu_rate_limit", action="set", v_direction="input", v_pps="1000"
    )
    assert rate.status_code == 200, text(rate.text)
    assert "rate-limit cpu direction input pps 1000 action log" in switch.sys_lines
    other = _change(
        logged_in, setting="cpu_rate_limit", action="set", v_direction="output", v_pps="5"
    )
    assert other.status_code == 200 and len(switch.sys_lines) == 2
    gone = _change(
        logged_in, setting="cpu_rate_limit", action="remove", v_direction="input", v_pps="1000"
    )
    assert gone.status_code == 200 and switch.sys_lines == [
        "rate-limit cpu direction output pps 5 action log"
    ]
    plain = _change(logged_in, setting="default_switchport", action="set")
    assert plain.status_code == 200 and "system default switchport" in switch.sys_lines
    shut = _change(logged_in, setting="default_switchport_shutdown", action="set")
    assert shut.status_code == 200
    off = _change(logged_in, setting="default_switchport_shutdown", action="remove")
    assert off.status_code == 200 and "system default switchport" in switch.sys_lines
    warned = _change(logged_in, confirm=False, setting="routing_mode", action="set", v_mode="host")
    assert (
        "restarted" in text(warned.text) and "system routing max-mode host" not in switch.sys_lines
    )


def test_a_time_range_is_made_filled_and_deleted(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    fields = {"scope": "time_range", "id_name": "work"}
    made = logged_in.post(
        "/system-settings/change",
        data={
            "csrf": csrf(logged_in), "confirm": "yes", "setting": "periodic", "action": "set",
            "v_days": "weekdays", "v_start": "08:00", "v_end": "17:00", **fields,
        },
    )  # fmt: skip
    assert made.status_code == 200, text(made.text)
    assert switch.time_ranges == {"work": ["periodic weekdays 08:00:00 to 17:00:00"]}
    page = logged_in.get("/system-settings")
    assert "Time range work" in text(page.text)
    removed = logged_in.post(
        "/system-settings/change",
        data={
            "csrf": csrf(logged_in), "confirm": "yes", "setting": "periodic", "action": "remove",
            "v_days": "weekdays", "v_start": "08:00", "v_end": "17:00", **fields,
        },
    )  # fmt: skip
    assert removed.status_code == 200 and switch.time_ranges == {"work": []}
