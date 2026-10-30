"""Parsing the feature list (app/features.py) and the feature command (NxapiClient)."""

from __future__ import annotations

import httpx
import pytest

from app.features import (
    CATALOG,
    GROUPS,
    KEEP_ON,
    NXSDK_APPS_NAME,
    feature_states,
    lacp_channels,
    parse_features,
    vlan_interfaces,
)
from app.nxapi import FEATURE_COMMANDS, NxapiClient, SwitchTarget
from app.port_changes import FEATURE_RULES, ROLE_VERSION, missing_changes, role_lines
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


def _view(channels=None, brief=None):
    return parse_features(
        load_fixture("show_feature_full"),
        load_fixture("show_port_channel_summary") if channels is None else channels,
        load_fixture("show_interface_brief") if brief is None else brief,
    )


def test_every_recorded_feature_is_listed_once() -> None:
    states = feature_states(load_fixture("show_feature_full"))
    assert len(states) == 130  # 193 rows: ospf, eigrp and others once per instance
    view = _view()
    names = [f.name for f in view.features]
    assert len(names) == len(set(names))
    # The 32 NX-SDK app slots are one line.
    assert NXSDK_APPS_NAME in names
    assert not any(name.startswith("nxsdk_app") and name != NXSDK_APPS_NAME for name in names)
    assert len(names) == 130 - 32 + 1


def test_enabled_features_match_the_switch() -> None:
    assert [f.name for f in _view().enabled] == ["icam", "lacp", "nxapi", "sshServer"]


def test_switch_names_become_the_commands_people_type() -> None:
    view = _view()
    assert view.get("sshServer").label == "ssh"  # type: ignore[union-attr]
    assert view.get("hsrp_engine").label == "hsrp"  # type: ignore[union-attr]
    assert view.get("nve").label == "nv overlay"  # type: ignore[union-attr]
    # No feature command on this switch: shown under its own name, not changed.
    icam = view.get("icam")
    assert icam is not None and icam.command is None and icam.label == "icam"
    assert icam.refusal(turn_on=False) is not None


def test_every_catalog_command_is_one_the_switch_offers() -> None:
    for name, info in CATALOG.items():
        assert info.group in GROUPS, name
        if info.command is not None:
            assert info.command in FEATURE_COMMANDS, name


def test_every_offered_command_has_a_feature() -> None:
    commands = {info.command for info in CATALOG.values()}
    assert FEATURE_COMMANDS <= commands


def test_groups_follow_the_page_order() -> None:
    groups = [group for group, _ in _view().grouped()]
    assert groups == [g for g in GROUPS if g in groups]
    assert groups[-1] == "Other"


def test_unknown_feature_lands_in_other() -> None:
    body = {
        "TABLE_cfcFeatureCtrlTable": {
            "ROW_cfcFeatureCtrlTable": {
                "cfcFeatureCtrlName2": "brand-new",
                "cfcFeatureCtrlOpStatus2": "enabled",
            }
        }
    }
    (feature,) = parse_features(body, {}, {}).features
    assert feature.group == "Other" and feature.command is None and feature.enabled


def test_lacp_in_use_by_port_channel43_cannot_be_turned_off() -> None:
    lacp = _view().get("lacp")
    assert lacp is not None
    assert lacp.used_by == ("port-channel43 (Ethernet1/43, Ethernet1/44)",)
    refusal = lacp.refusal(turn_on=False)
    assert refusal is not None and "port-channel43" in refusal and "remove it first" in refusal


def test_lacp_without_lacp_port_channels_may_be_turned_off() -> None:
    lacp = _view(channels={}).get("lacp")
    assert lacp is not None and lacp.used_by == () and lacp.refusal(turn_on=False) is None


def test_static_port_channel_does_not_count_as_lacp() -> None:
    body = load_fixture("show_port_channel_summary")
    body["TABLE_channel"]["ROW_channel"]["prtcl"] = "NONE"
    assert lacp_channels(body) == []


def test_vlan_interfaces_block_turning_off_interface_vlan() -> None:
    brief = {
        "TABLE_interface": {"ROW_interface": [{"interface": "Vlan10"}, {"interface": "mgmt0"}]}
    }
    assert vlan_interfaces(brief) == ["Vlan10"]
    body = load_fixture("show_feature_full")
    for row in body["TABLE_cfcFeatureCtrlTable"]["ROW_cfcFeatureCtrlTable"]:
        if row["cfcFeatureCtrlName2"] == "interface-vlan":
            row["cfcFeatureCtrlOpStatus2"] = "enabled"
    feature = parse_features(body, {}, brief).get("interface-vlan")
    assert feature is not None and feature.used_by == ("Vlan10",)
    assert feature.refusal(turn_on=False) is not None


def test_nxray_never_turns_off_nxapi_or_ssh() -> None:
    view = _view()
    for name in KEEP_ON:
        feature = view.get(name)
        assert feature is not None and feature.refusal(turn_on=False) == KEEP_ON[name]


def test_turning_on_an_unused_feature_is_allowed() -> None:
    lldp = _view().get("lldp")
    assert lldp is not None and not lldp.enabled and lldp.refusal(turn_on=True) is None


# ---- the role and the command ----------------------------------------------


def test_role_has_the_feature_rules() -> None:
    lines = role_lines(["Ethernet1/1"], "nxray")
    for rule in FEATURE_RULES:
        assert rule in lines
    assert ROLE_VERSION == 5


@pytest.mark.parametrize(
    ("version", "words"),
    [
        (1, "VLAN, port settings, feature and neighbor changes"),
        (2, "port settings, feature and neighbor changes"),
        (3, "feature and neighbor changes"),
        (4, "neighbor changes"),
        (5, ""),
    ],
)
def test_missing_changes(version: int, words: str) -> None:
    assert missing_changes(version) == words


def _client(switch: FakeSwitch) -> NxapiClient:
    target = SwitchTarget("192.0.2.10", 443, "admin", ADMIN_PASSWORD, 5.0)
    return NxapiClient(target, transport=switch.transport())


def test_set_feature_sends_one_command() -> None:
    switch = FakeSwitch()
    with _client(switch) as client:
        client.set_feature("lldp", True)
        client.set_feature("sla sender", True)
        client.set_feature("sla sender", False)
    assert switch.requests == [["feature lldp"], ["feature sla sender"], ["no feature sla sender"]]
    assert switch.lldp and switch.feature_state["sla_sender"] is False


@pytest.mark.parametrize("command", ["lldp ; reload", "feature-set fex", "password", "ntp", ""])
def test_set_feature_refuses_anything_else(command: str) -> None:
    switch = FakeSwitch()
    with _client(switch) as client, pytest.raises(ValueError):
        client.set_feature(command, True)
    assert switch.requests == []


@pytest.mark.parametrize("command", ["nxapi", "ssh"])
def test_set_feature_never_turns_off_what_nxray_needs(command: str) -> None:
    switch = FakeSwitch()
    with _client(switch) as client, pytest.raises(ValueError):
        client.set_feature(command, False)
    assert switch.requests == []


def test_set_feature_waits_longer_than_a_show() -> None:
    seen: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.extensions["timeout"]["read"])
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": None, "id": 1})

    target = SwitchTarget("192.0.2.10", 443, "admin", ADMIN_PASSWORD, 5.0)
    with NxapiClient(target, transport=httpx.MockTransport(handler)) as client:
        client.set_feature("lldp", True)
    assert seen == [120.0]
