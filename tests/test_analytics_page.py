"""The Flow analytics page (#95), end to end against the fake switch, and its parsers."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.analytics import build_analytics_change, parse_analytics, parse_analytics_config
from app.config import Settings
from tests.fake_switch import FakeSwitch
from tests.stage_d_helpers import config_requests, csrf, enable, set_up, text

FIXTURES = Path(__file__).parent / "fixtures"
# Recorded on cisco-25gb (NX-OS 9.3(16), 2026-11-13), objects made for the probe.
CONFIG = (FIXTURES / "show_running_config_analytics.txt").read_text()


def _lines(scope, setting="", action="set", ident=None, **values):
    return list(build_analytics_change(scope, setting, action, ident or {}, values).lines)


def test_the_lines() -> None:
    assert _lines("exporter", action="create", ident={"name": "e1"}) == ["flow exporter e1"]
    assert _lines("exporter", action="delete", ident={"name": "e1"}) == ["no flow exporter e1"]
    one = {"name": "e1"}
    assert _lines("exporter", "destination", ident=one, address="192.0.2.9", vrf="management") == [
        "flow exporter e1",
        "destination 192.0.2.9 use-vrf management",
    ]
    assert _lines("exporter", "destination", ident=one, address="192.0.2.9", vrf="default") == [
        "flow exporter e1",
        "destination 192.0.2.9",
    ]
    assert _lines("exporter", "dscp", "remove", one) == ["flow exporter e1", "no dscp"]
    assert _lines("exporter", "transport", ident=one, port="9995") == [
        "flow exporter e1",
        "transport udp 9995",
    ]
    assert _lines("record", "match_tos", ident={"name": "r1"}) == [
        "flow record r1",
        "match ip tos",
    ]
    assert _lines("record", "count_bytes", "remove", {"name": "r1"}) == [
        "flow record r1",
        "no collect counter bytes",
    ]
    assert _lines("profile", "interval", ident={"name": "p1"}, interval="1000") == [
        "flow profile p1",
        "collect interval 1000",
    ]
    assert _lines("filter", "ipv4", ident={"name": "f1"}, acl="web") == [
        "flow filter f1",
        "ipv4 web",
    ]
    assert _lines("event", "drops", ident={"name": "v1"}) == ["flow event v1", "group drop-events"]
    assert _lines("system", "exporter_id", id="7") == ["flow system config", "exporter-id 7"]
    assert _lines("system", "exporter_id", "remove", id="7") == [
        "flow system config",
        "no exporter-id 7",
    ]
    assert _lines("monitor", "bucket", ident={"name": "m1"}, bucket="1", low="0", high="100") == [
        "flow monitor m1",
        "exporter-bucket-id 1 0 100",
    ]


@pytest.mark.parametrize(
    ("scope", "setting", "ident", "values"),
    [
        ("exporter", "dscp", {"name": "e"}, {"dscp": "64"}),
        ("exporter", "transport", {"name": "e"}, {"port": "0"}),
        ("exporter", "destination", {"name": "e"}, {"address": "x", "vrf": "default"}),
        ("profile", "interval", {"name": "p"}, {"interval": "500"}),
        ("profile", "port", {"name": "p"}, {"port": "65536"}),
        ("system", "exporter_id", {}, {"id": "4096"}),
        ("exporter", "dscp", {"name": "bad name"}, {"dscp": "1"}),
    ],
)
def test_the_checks(scope: str, setting: str, ident: dict, values: dict) -> None:
    with pytest.raises(ValueError):
        build_analytics_change(scope, setting, "set", ident, values)


def test_the_configuration_is_read() -> None:
    found = parse_analytics_config(CONFIG)
    assert found["exporter"] == [
        ("nxe1", {"destination": {"address": "0.0.0.0", "vrf": ""}, "dscp": {"dscp": "0"}})
    ]
    ((name, record),) = found["record"]
    assert name == "nxr1" and record["match_tos"] == {} and record["count_bytes"] == {}
    assert record["description"] == {"text": "rec"} and "match_src" in record
    assert found["profile"] == [
        ("nxp1", {"interval": {"interval": "100"}, "port": {"port": "5000"}})
    ]
    assert found["filter"] == [("nxf1", {"ipv4": {"acl": "nxprobeacl"}})]
    assert found["event"] == [("nxev1", {"description": {"text": "x"}})]
    assert found["monitor"] == [("nxmon1", {"description": {"text": "mon"}})]
    assert found["system"] == [("", {"exporter_id": {"id": "0"}})]
    view = parse_analytics(CONFIG)
    assert [i.title for i in view.instances if i.scope in ("exporter", "system")] == [
        "Exporter nxe1",
        "System",
    ]
    assert any("did not show" in n for n in parse_analytics(None).notes)


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    return set_up(logged_in)


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/analytics/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/analytics", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/analytics"' in logged_in.get("/").text


def test_with_the_feature_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["analytics"] = False
    page = logged_in.get("/analytics")
    assert page.status_code == 200, text(page.text)
    assert "is off on the switch" in text(page.text)
    assert switch.requests == [["show feature", "show vrf"]]


def test_page_reads_the_objects(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["analytics"] = True
    switch.mon_lines += ["flow exporter e1", "flow exporter e1 ; dscp 46"]
    page = logged_in.get("/analytics")
    assert page.status_code == 200, text(page.text)
    assert "Exporter e1" in text(page.text)
    assert [r[0] for r in switch.requests][-1] == "show running-config analytics all"


def test_objects_are_made_changed_and_deleted(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    switch.feature_state["analytics"] = True
    made = _change(logged_in, scope="exporter", action="create", id_name="e1")
    assert made.status_code == 200, text(made.text)
    assert "flow exporter e1" in switch.mon_lines
    asked = _change(
        logged_in,
        confirm=False,
        scope="exporter",
        setting="dscp",
        action="set",
        id_name="e1",
        v_dscp="46",
    )
    assert "dscp 46" in text(asked.text)
    for setting, values in (
        ("dscp", {"v_dscp": "46"}),
        ("destination", {"v_address": "192.0.2.9", "v_vrf": "management"}),
        ("transport", {"v_port": "9995"}),
    ):
        done = _change(
            logged_in, scope="exporter", setting=setting, action="set", id_name="e1", **values
        )
        assert done.status_code == 200, text(done.text)
    assert "flow exporter e1 ; dscp 46" in switch.mon_lines
    assert "flow exporter e1 ; destination 192.0.2.9 use-vrf management" in switch.mon_lines
    shown = text(logged_in.get("/analytics").text)
    assert "Exporter e1" in shown
    removed = _change(
        logged_in, scope="exporter", setting="dscp", action="remove", id_name="e1", v_dscp="46"
    )
    assert removed.status_code == 200 and "flow exporter e1 ; dscp 46" not in switch.mon_lines
    gone = _change(logged_in, scope="exporter", action="delete", id_name="e1")
    assert gone.status_code == 200, text(gone.text)
    assert not [line for line in switch.mon_lines if line.startswith("flow exporter e1")]


def test_a_record_keeps_only_what_the_switch_keeps(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    switch.feature_state["analytics"] = True
    assert _change(logged_in, scope="record", action="create", id_name="r1").status_code == 200
    for setting in ("match_tos", "count_bytes"):
        done = _change(logged_in, scope="record", setting=setting, action="set", id_name="r1")
        assert done.status_code == 200, text(done.text)
    assert "flow record r1 ; match ip tos" in switch.mon_lines
    assert "flow record r1 ; collect counter bytes" in switch.mon_lines


def test_the_system_settings_and_the_switchs_refusal(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    switch.feature_state["analytics"] = True
    done = _change(logged_in, scope="system", setting="exporter_id", action="set", v_id="7")
    assert done.status_code == 200, text(done.text)
    assert "flow system config ; exporter-id 7" in switch.mon_lines
    bare = _change(logged_in, scope="system", setting="exporter_id", action="remove", v_id="7")
    assert bare.status_code == 200, text(bare.text)
    refused = _change(
        logged_in, scope="profile", setting="interval", action="set", id_name="p1", v_interval="500"
    )
    assert refused.status_code == 400 and "Not changed" in text(refused.text)


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "limited")
    switch.feature_state["analytics"] = True
    refused = _change(logged_in, scope="exporter", action="create", id_name="e1")
    assert refused.status_code == 400 and "Flow analytics changes are off" in text(refused.text)
    assert config_requests(switch) == []


def test_save_config_comes_back_here(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    saved = logged_in.post("/switch/save", data={"csrf": csrf(logged_in), "back": "analytics"})
    assert saved.status_code == 200 and "Flow analytics" in text(saved.text) and switch.saved
