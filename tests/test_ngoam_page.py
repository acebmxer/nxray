"""The VXLAN OAM page (#95), end to end against the fake switch, and its parsers."""

from __future__ import annotations

import html
import json
import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.ngoam import (
    PAGE_COMMANDS,
    STATS_COMMANDS,
    build_ngoam_change,
    loop_refused,
    parse_acl_status,
    parse_counters,
    parse_ngoam,
    parse_ngoam_config,
    tool_wait,
)
from app.port_changes import BROAD_RULES, NGOAM_RULES, ROLE_NAME
from app.switch_connection import BROAD_NGOAM_VERSION
from tests.conftest import inventory_body
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"

# Recorded on cisco-25gb (NX-OS 9.3(16), 2026-11-13) with a throwaway profile; that switch
# has VXLAN on but no NVE interface, so the tools' messages were not sent.
CONFIG = (FIXTURES / "show_running_config_ngoam.txt").read_text()
PING = (FIXTURES / "ngoam_ping_nve.txt").read_text()
COUNTERS = [
    json.loads((FIXTURES / f"show_ngoam_{word}_statistics_summary.json").read_text())
    for word in ("loopback", "traceroute", "pathtrace")
]
ACL = (FIXTURES / "show_ngoam_acl_status.txt").read_text()


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _db(settings: Settings, sql: str) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(sql)
    conn.commit()
    conn.close()


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


def _lines(scope, setting, action, ident=None, values=None):
    return list(build_ngoam_change(scope, setting, action, ident or {}, values or {}).lines)


# ---- parsing and lines ----------------------------------------------------------------------


def test_the_configuration_is_read():
    found = parse_ngoam_config(CONFIG)
    assert found.profiles["250"] == {
        "description": {"text": "nxprobe test profile"},
        "hop": {"hops": "255"},
        "oam_channel": {},
        "dot1q": {"vlan": "250", "port": "Ethernet1/54"},
        "sport": {"port_number": "1024, 2048"},
    }
    assert found.flows[("250", "forward")] == {
        "dot1q": {"vlan": "250", "cos": ""},
        "ip_destination": {"address": "192.0.2.1"},
        "mac_source": {"address": "0200.0000.0002"},
        "mac_destination": {"address": "0200.0000.0001"},
        "port_source": {"number": "65535"},
        "port_destination": {"number": "80"},
        "protocol": {"number": "17"},
    }
    assert found.loop is None and not found.install_acl and not found.key_set


def test_the_counters_and_acl_are_read():
    rows = parse_counters(COUNTERS)
    assert [r[0] for r in rows] == ["Ping", "Traceroute", "Pathtrace"]
    assert rows[0] == ("Ping", "0", "0", "0", "1213", "0", "0", "Fri Nov 13 12:11:01.371 UTC")
    assert parse_counters([]) == ()
    assert parse_acl_status(ACL) == "1"
    assert parse_acl_status("") == ""


def test_loop_detection_is_refused_on_a_nexus_9200_only():
    assert loop_refused(inventory_body("Nexus9000 C92160YC-X chassis", "N9K-C92160YC-X"))
    assert not loop_refused(inventory_body("Nexus9000 C93180YC-EX chassis", "N9K-C93180YC-EX"))
    assert not loop_refused(None)
    assert not loop_refused({})


def test_the_page_view():
    view = parse_ngoam(CONFIG, COUNTERS, ACL, loop_refused=True)
    (profile,) = view.of("profile")
    facts = dict(profile.facts)
    assert facts["Hops"] == "255" and facts["NVO3 channel"] == "yes"
    assert facts["Flows"] == "forward"
    assert [i.title for i in view.of("flow")] == ["Profile 250, flow forward"]
    assert dict(view.of("global")[0].facts)["Access list on VLANs"] == "1"
    assert view.of("loop") == [] and view.of("loop_now") == []
    assert [i.scope for i in view.instances[:3]] == ["ping", "traceroute", "pathtrace"]
    assert "Loop detection not supported on this hardware" in view.notes[0]
    assert "did not show its configuration" in parse_ngoam(None).notes[-1]


def test_a_secret_key_is_never_shown():
    config = CONFIG + "ngoam authentication-key S3cretKey\n"
    view = parse_ngoam(config)
    assert dict(view.of("global")[0].facts)["Authentication key"] == "set"
    assert "S3cretKey" not in repr(view)
    made = build_ngoam_change("global", "authentication_key", "set", {}, {"key": "S3cretKey"})
    assert made.lines == ("ngoam authentication-key S3cretKey",)
    assert "S3cretKey" not in " ".join(made.labels) and "S3cretKey" not in made.describe


def test_the_tool_lines_follow_the_order_the_switch_takes():
    assert _lines(
        "ping",
        "by_vni",
        "set",
        values={
            "address": "192.0.2.1",
            "vni": "5000",
            "profile": "250",
            "sport": "5000",
            "source": "192.0.2.9",
            "count": "2",
            "size": "100",
            "interval": "1",
            "timeout": "1",
            "egress": "Ethernet1/54",
            "verbose": "yes",
        },
    ) == [
        "ping nve ip 192.0.2.1 profile 250 vni 5000 sport 5000 source 192.0.2.9 count 2 "
        "packet-size 100 interval 1 timeout 1 egress Ethernet1/54 verbose"
    ]
    assert _lines(
        "ping", "by_vrf", "set", values={"address": "192.0.2.1", "vrf": "default", "profile": "250"}
    ) == ["ping nve ip 192.0.2.1 vrf default profile 250"]
    assert _lines(
        "ping",
        "by_flow",
        "set",
        values={
            "vrf": "default",
            "dip": "192.0.2.2",
            "sip": "192.0.2.1",
            "psport": "1000",
            "pdport": "2000",
            "proto": "17",
            "verify": "yes",
            "verbose": "yes",
        },
    ) == [
        "ping nve ip unknown vrf default payload ip 192.0.2.2 192.0.2.1 port 1000 2000 "
        "proto 17 payload-end verify-host verbose"
    ]
    assert _lines(
        "ping",
        "by_mac",
        "set",
        values={"mac": "0200.0000.0001", "vlan": "250", "port": "Ethernet1/54", "count": "2"},
    ) == ["ping nve mac 0200.0000.0001 250 Ethernet1/54 count 2"]
    assert _lines(
        "traceroute",
        "by_vni",
        "set",
        values={"address": "192.0.2.1", "vni": "5000", "ttl": "10", "timeout": "30"},
    ) == ["traceroute nve ip 192.0.2.1 vni 5000 max-ttl 10 timeout 30"]
    assert _lines(
        "pathtrace",
        "by_flow",
        "set",
        values={
            "vrf": "default",
            "profile": "250",
            "dmac": "0200.0000.0001",
            "smac": "0200.0000.0002",
            "req_stats": "yes",
        },
    ) == [
        "pathtrace nve ip unknown vrf default profile 250 payload mac-addr 0200.0000.0001 "
        "0200.0000.0002 payload-end req-stats"
    ]
    assert _lines(
        "pathtrace",
        "by_mac",
        "set",
        values={"mac": "0200.0000.0001", "vlan": "250", "profile": "3", "verbose": "yes"},
    ) == ["pathtrace nve mac 0200.0000.0001 250 profile 3 verbose"]
    made = build_ngoam_change("ping", "by_vni", "set", {}, {"address": "192.0.2.1", "vni": "5"})
    assert not made.config and made.describe.startswith("VXLAN OAM: Ping an address in a VNI:")


def test_tool_values_are_refused_before_anything_is_sent():
    with pytest.raises(ValueError, match="from 1 to 100"):
        build_ngoam_change(
            "ping", "by_vni", "set", {}, {"address": "192.0.2.1", "vni": "5", "count": "101"}
        )
    with pytest.raises(ValueError, match="300 seconds at most"):
        build_ngoam_change(
            "ping",
            "by_vni",
            "set",
            {},
            {"address": "192.0.2.1", "vni": "5", "count": "100", "timeout": "5"},
        )
    with pytest.raises(ValueError, match="IPv4 address"):
        build_ngoam_change(
            "ping",
            "by_vni",
            "set",
            {},
            {"address": "192.0.2.1", "vni": "5", "source": "2001:db8::1"},
        )
    with pytest.raises(ValueError, match="both addresses"):
        build_ngoam_change("ping", "by_flow", "set", {}, {"vrf": "red", "dip": "192.0.2.2"})
    with pytest.raises(ValueError, match="host's MAC address or its address"):
        build_ngoam_change("traceroute", "by_flow", "set", {}, {"vrf": "red", "proto": "6"})
    with pytest.raises(ValueError, match="cannot contain"):
        build_ngoam_change("ping", "by_vrf", "set", {}, {"address": "192.0.2.1", "vrf": "a;b"})
    with pytest.raises(ValueError, match="1 to 30"):
        build_ngoam_change(
            "traceroute", "by_vni", "set", {}, {"address": "192.0.2.1", "vni": "5", "timeout": "0"}
        )
    with pytest.raises(ValueError, match="cannot be removed"):
        build_ngoam_change("ping", "by_vni", "remove", {}, {})


def test_how_long_a_tool_may_take():
    assert tool_wait("ping nve ip 192.0.2.1 vni 5") == 5 * 2 + 30
    assert tool_wait("ping nve ip 192.0.2.1 vni 5 count 10 interval 2 timeout 3") == 50 + 30
    assert tool_wait("pathtrace nve ip 192.0.2.1 vni 5 max-ttl 10 timeout 4") == 40 + 30
    assert tool_wait("traceroute nve ip 192.0.2.1 vni 5") == 60 + 30


def test_the_profile_and_flow_lines():
    ident = {"profile": "7"}
    assert _lines("profile", "", "create", ident) == ["ngoam profile 7"]
    assert _lines("profile", "", "delete", ident) == ["no ngoam profile 7"]
    assert _lines("profile", "hop", "remove", ident) == ["ngoam profile 7", "no hop"]
    assert _lines("profile", "oam_channel", "set", ident) == ["ngoam profile 7", "oam-channel 2"]
    assert _lines("profile", "payload_pad", "set", ident, {"pad": "0x2"})[-1] == "payload pad 0x2"
    with pytest.raises(ValueError, match="hexadecimal"):
        build_ngoam_change("profile", "payload_pad", "set", ident, {"pad": "12"})
    with pytest.raises(ValueError, match="front port"):
        build_ngoam_change("profile", "interface", "set", ident, {"port": "port-channel10"})
    with pytest.raises(ValueError, match="cannot be removed"):
        build_ngoam_change("profile", "description", "remove", ident, {})
    flow = {"profile": "7", "direction": "reverse"}
    assert _lines("flow", "", "create", flow) == ["ngoam profile 7", "flow reverse"]
    assert _lines("flow", "", "delete", flow) == ["ngoam profile 7", "no flow reverse"]
    assert _lines("flow", "dot1q", "set", flow, {"vlan": "250", "cos": "3"})[-1] == (
        "dot1q 250 cos 3"
    )
    assert _lines("flow", "ip_source", "remove", flow)[-1] == "no ip source"
    assert _lines("loop", "", "create") == ["ngoam loop-detection"]
    assert _lines("loop_now", "probe", "set", values={"vlan": "250", "port": "Ethernet1/5"}) == [
        "ngoam loop-detection probe vlan 250 port Ethernet1/5"
    ]
    assert _lines("counters", "loopback", "set") == ["clear ngoam loopback statistics summary"]


# ---- the page ---------------------------------------------------------------------------------


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "host": "192.0.2.10",
            "port": "443",
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "account_name": "nxray",
            "confirm_save": "yes",
        },
    )
    fake.feature_state["ngoam"] = True
    fake.feature_state["nve"] = True
    fake.ngoam_lines += ["ngoam profile 250", "ngoam profile 250 ; hop 9"]
    fake.requests.clear()
    return fake


def _enable(client: TestClient, settings: Settings, fake: FakeSwitch, mode: str) -> FakeSwitch:
    response = client.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(client, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "role_mode": mode,
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    fake.requests.clear()
    fake.signed_in.clear()
    return fake


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    return _enable(logged_in, settings, switch, "broad")


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/ngoam/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/ngoam", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/ngoam"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/ngoam")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "Profile 250" in text and "Ping across the fabric" in text
    assert "Run" in text and "Loop detection not supported" in text
    assert enabled.requests == [
        list(PAGE_COMMANDS),
        list(STATS_COMMANDS),
        ["show ngoam acl status"],
        ["show running-config"],
    ]


def test_with_the_feature_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["ngoam"] = False
    switch.feature_state["nve"] = False
    text = _text(logged_in.get("/ngoam").text)
    assert "ngoam is off on the switch" in text and "VXLAN (feature nv overlay) is off" in text


def test_a_ping_shows_what_the_switch_printed(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = dict(
        scope="ping",
        setting="by_vni",
        action="set",
        v_address="192.0.2.1",
        v_vni="5000",
        v_count="3",
        v_verbose="yes",
    )
    asked = _change(logged_in, confirm=False, **fields)
    assert "ping nve ip 192.0.2.1 vni 5000 count 3 verbose" in _text(asked.text)
    assert "changes no configuration" in _text(asked.text)
    assert enabled.ngoam_ran == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert enabled.ngoam_ran == ["ping nve ip 192.0.2.1 vni 5000 count 3 verbose"]
    text = _text(done.text)
    assert "What the switch printed" in text and "Success rate is 0 percent" in text
    assert "Not saved yet" not in text
    assert "Sent 3, Received 0" in done.text  # kept as printed, line breaks too
    assert "Q Reason: Failed to get vni data from nve, vni = 5000\nQ Reason" in html.unescape(
        done.text
    )


def test_a_tool_the_switch_refuses_says_why(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _change(
        logged_in,
        scope="pathtrace",
        setting="by_vni",
        action="set",
        v_address="192.0.2.1",
        v_vni="5000",
        v_profile="99",
    )
    assert refused.status_code == 400
    assert "Failed to find profile id 99" in _text(refused.text)
    assert "What the switch printed" not in _text(refused.text)


def test_profiles_flows_and_counters(logged_in: TestClient, enabled: FakeSwitch) -> None:
    made = _change(logged_in, scope="profile", action="create", id_profile="7")
    assert made.status_code == 200, _text(made.text)
    hop = _change(
        logged_in, scope="profile", setting="hop", action="set", id_profile="7", v_hops="12"
    )
    assert hop.status_code == 200 and "ngoam profile 7 ; hop 12" in enabled.ngoam_lines
    flow = _change(logged_in, scope="flow", action="create", id_profile="7", id_direction="forward")
    assert flow.status_code == 200, _text(flow.text)
    v4 = _change(
        logged_in,
        scope="flow",
        setting="ip_destination",
        action="set",
        id_profile="7",
        id_direction="forward",
        v_address="192.0.2.1",
    )
    assert v4.status_code == 200, _text(v4.text)
    v6 = _change(
        logged_in,
        scope="flow",
        setting="ipv6_source",
        action="set",
        id_profile="7",
        id_direction="forward",
        v_address="2001:db8::1",
    )
    assert v6.status_code == 400 and "v6 and v4" in _text(v6.text)
    assert "Profile 7, flow forward" in _text(v4.text)
    cleared = _change(logged_in, scope="counters", setting="loopback", action="set")
    assert cleared.status_code == 200, _text(cleared.text)
    assert enabled.ngoam_ran == ["clear ngoam loopback statistics summary"]


def test_loop_detection_is_refused_on_this_model(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    refused = _change(logged_in, scope="loop", action="create")
    assert refused.status_code == 400 and "not supported on this hardware" in _text(refused.text)
    enabled.loop_detection_supported = True
    done = _change(logged_in, scope="loop", action="create")
    assert done.status_code == 200, _text(done.text)
    probe = _change(
        logged_in,
        scope="loop_now",
        setting="probe",
        action="set",
        v_vlan="250",
        v_port="Ethernet1/5",
    )
    assert probe.status_code == 200, _text(probe.text)
    assert enabled.ngoam_ran == ["ngoam loop-detection probe vlan 250 port Ethernet1/5"]


def test_the_broad_role_allows_the_tools() -> None:
    assert set(NGOAM_RULES) <= set(BROAD_RULES)


def test_a_broad_role_written_before_the_tools_is_refused_until_updated(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    for rule in NGOAM_RULES:
        enabled.roles[ROLE_NAME].entities.discard(rule.split(" command ", 1)[1])
    _db(settings, f"UPDATE switch_connection SET role_version = {BROAD_NGOAM_VERSION - 1}")
    refused = _change(
        logged_in, scope="ping", setting="by_vni", action="set", v_address="192.0.2.1", v_vni="5000"
    )
    assert refused.status_code == 400 and "Update the port list" in _text(refused.text)
    assert enabled.ngoam_ran == []
    assert "allowed VXLAN OAM's ping" in _text(logged_in.get("/switch").text)
    done = _change(logged_in, scope="profile", action="create", id_profile="8")
    assert done.status_code == 200, _text(done.text)


def test_the_switch_refuses_a_tool_without_the_rule(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    for rule in NGOAM_RULES:
        enabled.roles[ROLE_NAME].entities.discard(rule.split(" command ", 1)[1])
    refused = _change(
        logged_in, scope="ping", setting="by_vni", action="set", v_address="192.0.2.1", v_vni="5000"
    )
    assert refused.status_code == 400 and "may not make this change yet" in _text(refused.text)
    assert enabled.ngoam_ran == []


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    refused = _change(
        logged_in, scope="ping", setting="by_vni", action="set", v_address="192.0.2.1", v_vni="5000"
    )
    assert refused.status_code == 400 and "VXLAN OAM changes and tools are off" in _text(
        refused.text
    )
    assert _config_requests(switch) == [] and switch.ngoam_ran == []


def test_with_the_admin_login_stored_the_tool_runs_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "stored")
    done = _change(
        logged_in,
        scope="traceroute",
        setting="by_vni",
        action="set",
        v_address="192.0.2.1",
        v_vni="5000",
    )
    assert done.status_code == 200, _text(done.text)
    assert "admin" in switch.signed_in and "Route not found" in _text(done.text)


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "ngoam"})
    assert saved.status_code == 200
    assert "Make a profile" in _text(saved.text) and enabled.saved
