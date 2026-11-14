"""The Programmability page (#95), end to end against the fake switch, and its parsers."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.programmability import (
    build_programmability_change,
    parse_facts,
    parse_programmability,
    parse_programmability_config,
)
from tests.fake_switch import FakeSwitch
from tests.stage_d_helpers import config_requests, csrf, enable, set_up, text

FIXTURES = Path(__file__).parent / "fixtures"
# Recorded on cisco-25gb (NX-OS 9.3(16), 2026-11-13), gRPC on with its defaults.
GRPC = (FIXTURES / "show_grpc_gnmi_service_statistics.txt").read_text()
NXSDK = (
    "NXSDK Started/Temp unavailabe/Max services : 0/0/32\n"
    "NXSDK Default App Path         : /isan/bin/nxsdk\n"
    "NXSDK Supported Versions       : 1.0 1.5 1.7.5 2.0 2.5\n"
)
ALL_ON = {"grpc": True, "netconf": True, "restconf": True, "nxsdk_mgr": True,
          "container-tracker": True, "openflow": True}  # fmt: skip


def _lines(scope, setting, action="set", **values):
    return list(build_programmability_change(scope, setting, action, {}, values).lines)


def test_the_lines() -> None:
    assert _lines("grpc", "port", port="50052") == ["grpc port 50052"]
    assert _lines("grpc", "port", "remove", port="50052") == ["no grpc port 50052"]
    assert _lines("grpc", "max_calls", calls="16") == ["grpc gnmi max-concurrent-calls 16"]
    assert _lines("grpc", "certificate", name="tp1") == ["grpc certificate tp1"]
    assert _lines("netconf", "sessions", sessions="10") == ["netconf sessions 10"]
    assert _lines("netconf", "idle_timeout", minutes="0") == ["netconf idle-timeout 0"]
    assert _lines("nxsdk", "service", name="myapp") == ["nxsdk service-name myapp"]
    for scope, setting, values in (
        ("grpc", "port", {"port": "1023"}),  # the switch: range is (1024:65535)
        ("grpc", "max_calls", {"calls": "17"}),
        ("netconf", "sessions", {"sessions": "11"}),
        ("netconf", "idle_timeout", {"minutes": "1441"}),
        ("nxsdk", "service", {"name": "a" * 21}),
    ):
        with pytest.raises(ValueError):
            build_programmability_change(scope, setting, "set", {}, values)


def test_the_facts_and_the_configuration_are_read() -> None:
    facts = dict(parse_facts(GRPC))
    assert facts["Vrf"] == "management" and facts["Server address"] == "[::]:50051"
    assert facts["Max concurrent calls"] == "8"
    assert parse_programmability_config(
        "feature grpc\ngrpc port 50052\ngrpc gnmi max-concurrent-calls 5\ngrpc certificate tp1\n"
        "netconf sessions 3\nnetconf idle-timeout 600\nnxsdk service-name app1\n"
        "interface Ethernet1/1\n  grpc port 1\n"
    ) == {
        "grpc": {
            "port": {"port": "50052"},
            "max_calls": {"calls": "5"},
            "certificate": {"name": "tp1"},
        },
        "netconf": {"sessions": {"sessions": "3"}, "idle_timeout": {"minutes": "600"}},
        "nxsdk": {"service": {"name": "app1"}},
    }


def test_the_view_shows_only_the_interfaces_that_are_on() -> None:
    view = parse_programmability({"grpc": True, "netconf": False}, "grpc port 50052\n", GRPC)
    assert [i.scope for i in view.instances] == ["grpc"]
    assert view.instances[0].values["port"] == {"port": "50052"}
    assert any("Off on the switch: NETCONF, RESTCONF" in note for note in view.notes)
    on = parse_programmability(ALL_ON, "", GRPC, NXSDK, "The switch is not configured\n")
    assert [i.scope for i in on.instances] == [
        "grpc", "netconf", "restconf", "nxsdk", "container_tracker", "openflow"
    ]  # fmt: skip
    assert dict(on.instances[5].facts) == {"State": "The switch is not configured"}
    assert dict(on.instances[3].facts)["NXSDK Default App Path"] == "/isan/bin/nxsdk"


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = set_up(logged_in)
    fake.texts.update(
        {
            "show grpc gnmi service statistics": GRPC,
            "show nxsdk internal service": NXSDK,
            "show openflow switch 1": "The switch is not configured\n",
        }
    )
    return fake


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/programmability/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/programmability", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/programmability"' in logged_in.get("/").text


def test_with_every_feature_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/programmability")
    assert page.status_code == 200, text(page.text)
    assert "Off on the switch: gRPC, NETCONF, RESTCONF, NX-SDK, Container Tracker" in text(
        page.text
    )
    assert switch.requests == [["show feature"]]
    assert "Change the" not in text(page.text)  # no form for a feature that is off


def test_a_form_is_offered_only_for_what_is_on(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    off = text(logged_in.get("/programmability").text)
    assert "Calls at once" not in off and "Sessions at once" not in off
    switch.feature_state["grpc"] = True
    on = text(logged_in.get("/programmability").text)
    assert "Calls at once" in on and "Sessions at once" not in on


def test_page_reads_what_is_on(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state.update(ALL_ON)
    page = logged_in.get("/programmability")
    assert page.status_code == 200, text(page.text)
    shown = text(page.text)
    assert "management" in shown and "[::]:50051" in shown
    assert "/isan/bin/nxsdk" in shown and "The switch is not configured" in shown
    assert "RESTCONF" in shown and "Container Tracker" in shown
    # NXray's own account may not read the configuration: the page says so.
    assert "did not show its configuration" in shown
    assert [r[0] for r in switch.requests][:2] == ["show feature", "show running-config"]


def test_settings_are_sent_and_read_back(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    switch.feature_state.update({"grpc": True, "netconf": True, "nxsdk_mgr": True})
    asked = _change(
        logged_in, confirm=False, scope="grpc", setting="port", action="set", v_port="50052"
    )
    assert "grpc port 50052" in text(asked.text)
    assert config_requests(switch) == []
    done = _change(logged_in, scope="grpc", setting="port", action="set", v_port="50052")
    assert done.status_code == 200, text(done.text)
    assert "grpc port 50052" in switch.mgmt_lines
    assert 'value="50052"' in logged_in.get("/programmability").text  # the form shows it set
    sessions = _change(logged_in, scope="netconf", setting="sessions", action="set", v_sessions="4")
    assert sessions.status_code == 200, text(sessions.text)
    assert "netconf sessions 4" in switch.mgmt_lines
    back = _change(logged_in, scope="grpc", setting="port", action="remove", v_port="50052")
    assert back.status_code == 200, text(back.text)
    assert "grpc port 50052" not in switch.mgmt_lines


def test_the_switchs_refusals_are_shown(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    switch.feature_state["nxsdk_mgr"] = True
    refused = _change(logged_in, scope="nxsdk", setting="service", action="set", v_name="nope")
    assert refused.status_code == 400 and "Service nope not found" in text(refused.text)
    switch.nxsdk_apps.add("myapp")
    ok = _change(logged_in, scope="nxsdk", setting="service", action="set", v_name="myapp")
    assert ok.status_code == 200, text(ok.text)
    assert "nxsdk service-name myapp" in switch.mgmt_lines


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "limited")
    switch.feature_state["grpc"] = True
    refused = _change(logged_in, scope="grpc", setting="port", action="set", v_port="50052")
    assert refused.status_code == 400
    assert "Programmability changes are off" in text(refused.text)
    assert config_requests(switch) == []


def test_save_config_comes_back_here(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    saved = logged_in.post(
        "/switch/save", data={"csrf": csrf(logged_in), "back": "programmability"}
    )
    assert saved.status_code == 200
    assert "Programmability" in text(saved.text) and switch.saved
