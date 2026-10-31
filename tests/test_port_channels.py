"""Port-channels and LACP: parsing recorded output, checked values, the client's
commands, the role rules and the plans."""

from __future__ import annotations

import json

import httpx
import pytest

from app.nxapi import (
    NxapiClient,
    NxapiCommandError,
    SwitchTarget,
    validate_channel_number,
    validate_lacp_priority,
    validate_min_links,
)
from app.port_changes import (
    CHANNEL_PERMIT,
    CHANNEL_RULES,
    ROLE_VERSION,
    VLAN_INTERFACE_PERMIT,
    missing_changes,
    role_lines,
)
from app.port_channels import (
    CONFIG_MUST_MATCH,
    Channel,
    ChannelView,
    Member,
    load_channels,
    parse_brief,
    parse_channels,
    parse_descriptions,
    parse_lacp_ports,
    parse_modes,
    parse_partners,
    plan_add,
    plan_channel_settings,
    plan_create,
    plan_delete,
    plan_port_lacp,
    plan_remove,
    plan_system_priority,
)
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch, Role

PORTS = ["Ethernet1/1", "Ethernet1/2", "Ethernet1/43", "Ethernet1/44", "Ethernet1/53"]


def _client(fake: FakeSwitch, user: str = "admin", password: str = ADMIN_PASSWORD) -> NxapiClient:
    return NxapiClient(SwitchTarget("192.0.2.10", 443, user, password, 5.0), fake.transport())


def _recording() -> tuple[list[list[str]], NxapiClient]:
    """A client whose requests are only recorded, each answered with null results."""
    sent: list[list[str]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        entries = json.loads(request.content)
        sent.append([entry["params"]["cmd"] for entry in entries])
        replies = [{"jsonrpc": "2.0", "result": None, "id": entry["id"]} for entry in entries]
        return httpx.Response(200, json=replies[0] if len(replies) == 1 else replies)

    target = SwitchTarget("192.0.2.10", 443, "nxray", "pw", 5.0)
    return sent, NxapiClient(target, transport=httpx.MockTransport(handle))


def _po43(**changes) -> Channel:
    members = (
        Member("Ethernet1/43", "P", "active", "normal", 32768),
        Member("Ethernet1/44", "P", "active", "normal", 32768),
    )
    values = {
        "number": 43,
        "protocol": "LACP",
        "up": True,
        "routed": False,
        "description": "storage-server",
        "members": members,
    }
    values.update(changes)
    return Channel(**values)


def _view(**changes) -> ChannelView:
    values = {
        "channels": [_po43()],
        "lacp_enabled": True,
        "system_priority": 32768,
        "front_ports": PORTS,
        "turned_off": frozenset(),
        "up_ports": frozenset({"Ethernet1/43", "Ethernet1/44"}),
    }
    values.update(changes)
    return ChannelView(**values)


# ---- parsing recorded output ------------------------------------------------------


def test_modes_from_the_recorded_database() -> None:
    modes = parse_modes(load_fixture("show_port_channel_database"))
    assert modes == {"Ethernet1/43": "active", "Ethernet1/44": "active", "Ethernet1/53": "active",
                     "Ethernet1/54": "on"}  # fmt: skip


def test_descriptions_include_port_channels() -> None:
    found = parse_descriptions(load_fixture("show_interface_description"))
    assert found["port-channel43"] == "storage-server"
    assert found["port-channel55"] == "lab-bundle"
    assert "port-channel54" not in found  # no description


def test_lacp_rate_and_priority_from_the_recorded_interfaces() -> None:
    ports = parse_lacp_ports(load_fixture("show_lacp_interface"))
    assert ports["Ethernet1/43"] == ("normal", 32768)  # local-timeout Long, 0x8000
    assert len(ports) == 54


def test_partner_from_the_recorded_neighbor() -> None:
    partners = parse_partners(load_fixture("show_lacp_neighbor"))
    partner = partners["Ethernet1/43"]
    assert partner.mac == "b8:59:9f:00:00:0e"
    assert partner.system_priority == 65535
    assert partner.maker == "Mellanox Technologies, Inc."
    assert partner.words == "active, fast rate"  # flags FA
    assert set(partners) == {"Ethernet1/43", "Ethernet1/44"}


def test_channels_from_the_recorded_summary_of_three() -> None:
    channels = parse_channels(
        load_fixture("show_port_channel_summary_three"),
        parse_modes(load_fixture("show_port_channel_database")),
        parse_descriptions(load_fixture("show_interface_description")),
        set(),
    )
    assert [c.name for c in channels] == ["port-channel43", "port-channel54", "port-channel55"]
    po43, po54, po55 = channels
    assert po43.up and po43.lacp and po43.mode == "active"
    assert po43.member_names == ["Ethernet1/43", "Ethernet1/44"]
    assert all(m.bundled for m in po43.members)
    assert not po54.up and po54.members[0].state_words == "down"
    assert po55.protocol == "NONE" and po55.mode == "on" and not po55.lacp
    assert po55.description == "lab-bundle"


def test_brief_gives_front_ports_turned_off_and_up() -> None:
    body = {
        "TABLE_interface": {
            "ROW_interface": [
                {"interface": "mgmt0", "state": "up"},
                {"interface": "Ethernet1/10", "state": "up", "state_rsn_desc": "none"},
                {
                    "interface": "Ethernet1/2",
                    "state": "down",
                    "state_rsn_desc": "Administratively down",
                },
                {"interface": "port-channel7", "state": "up", "portmode": "routed"},
            ]
        }
    }
    ports, off, up, routed = parse_brief(body)
    assert ports == ["Ethernet1/2", "Ethernet1/10"]
    assert off == {"Ethernet1/2"} and up == {"Ethernet1/10"} and routed == {"port-channel7"}


def test_load_channels_reads_lacp_only_while_it_is_on() -> None:
    fake = FakeSwitch()
    with _client(fake) as client:
        view = load_channels(client)
    assert view.lacp_enabled and view.system_priority == 32768
    assert view.channels[0].members[0].partner is not None
    assert len(fake.requests) == 2

    fake = FakeSwitch(feature_state={"lacp": False}, channels={})
    with _client(fake) as client:
        view = load_channels(client)
    assert not view.lacp_enabled and view.channels == [] and view.system_priority is None
    assert len(fake.requests) == 1  # no "show lacp": they are invalid with LACP off
    assert "Ethernet1/43" in view.free_ports


# ---- checked values and the client's commands ------------------------------------------


@pytest.mark.parametrize("value", ["0", "4097", "x", "1.5", "-1", "٣"])
def test_channel_number_refuses(value: str) -> None:
    with pytest.raises(ValueError):
        validate_channel_number(value)


def test_ranges_from_the_switch_help() -> None:
    assert validate_channel_number(" 4096 ") == 4096
    assert validate_lacp_priority("1") == 1 and validate_lacp_priority(65535) == 65535
    assert validate_min_links("32") == 32
    for bad in ("0", "65536"):
        with pytest.raises(ValueError):
            validate_lacp_priority(bad)
    for bad in ("0", "33"):
        with pytest.raises(ValueError):
            validate_min_links(bad)


def test_join_sends_rate_before_the_channel_group_then_the_description() -> None:
    sent, client = _recording()
    with client:
        client.join_port_channel(
            54, ["Ethernet1/53", "Ethernet1/54"], "active", fast_rate=True, description="lab"
        )
        client.join_port_channel(55, ["Ethernet1/1"], "on")
    assert sent == [
        [
            "interface Ethernet1/53",
            "lacp rate fast",
            "channel-group 54 mode active",
            "interface Ethernet1/54",
            "lacp rate fast",
            "channel-group 54 mode active",
            "interface port-channel54",
            "description lab",
        ],
        ["interface Ethernet1/1", "channel-group 55"],
    ]


def test_client_port_channel_commands() -> None:
    sent, client = _recording()
    with client:
        client.leave_port_channel("Ethernet1/53")
        client.delete_port_channel(54)
        client.configure_port_channel(54, description="", min_links=2)
        client.set_port_lacp("Ethernet1/53", rate="normal", priority=100)
        client.set_lacp_system_priority(4096)
    assert sent == [
        ["interface Ethernet1/53", "no channel-group"],
        ["no interface port-channel54"],
        ["interface port-channel54", "no description", "lacp min-links 2"],
        ["interface Ethernet1/53", "lacp rate normal", "lacp port-priority 100"],
        ["lacp system-priority 4096"],
    ]


@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.join_port_channel(54, ["mgmt0"], "active"),
        lambda c: c.join_port_channel(54, ["Ethernet1/1"], "desirable"),
        lambda c: c.join_port_channel(54, ["Ethernet1/1"], "on", fast_rate=True),
        lambda c: c.join_port_channel(54, [], "active"),
        lambda c: c.join_port_channel(54, ["Ethernet1/1"], "active", description="a;b"),
        lambda c: c.leave_port_channel("port-channel43"),
        lambda c: c.delete_port_channel(0),
        lambda c: c.configure_port_channel(54),
        lambda c: c.set_port_lacp("Ethernet1/1", rate="slow"),
        lambda c: c.set_port_lacp("Ethernet1/1"),
        lambda c: c.set_lacp_system_priority(0),
    ],
)
def test_client_refuses_before_sending(call) -> None:
    sent, client = _recording()
    with client, pytest.raises(ValueError):
        call(client)
    assert sent == []


# ---- the role ------------------------------------------------------------------------


def test_role_has_the_port_channel_rules_and_names_every_port_channel() -> None:
    lines = role_lines(["Ethernet1/1"], "nxray")
    for rule in CHANNEL_RULES:
        assert rule in lines
    assert ROLE_VERSION == 7
    # Inside "interface policy deny", after the front ports: outside it the switch refuses it.
    policy = lines.index("interface policy deny")
    assert lines.index(CHANNEL_PERMIT) > lines.index("permit interface Ethernet1/1") > policy
    assert lines[lines.index(CHANNEL_PERMIT) + 1] == VLAN_INTERFACE_PERMIT
    assert lines[lines.index(CHANNEL_PERMIT) + 2] == "exit"
    numbers = [int(line.split()[1]) for line in lines if line.startswith("rule ")]
    assert numbers == list(range(1, 51))


def test_missing_changes_names_port_channel_changes() -> None:
    assert missing_changes(5) == "port-channel and VLAN interface changes"
    assert missing_changes(6) == "VLAN interface changes"
    assert missing_changes(7) == ""


def _restricted(fake: FakeSwitch, permits: set[str]) -> NxapiClient:
    """An account like NXray's, with the port-channel rules and the given port list."""
    entities = {rule.split(" permit command ", 1)[1] for rule in CHANNEL_RULES}
    entities.add("conf t ; interface * ; description *")
    fake.roles["probe"] = Role(entities=entities, interface_policy_deny=True, interfaces=permits)
    fake.users["probe"] = ("Probe-pw-1", "network-operator")
    fake.extra_roles["probe"] = {"probe"}
    return _client(fake, "probe", "Probe-pw-1")


def test_fake_switch_needs_the_port_channels_in_the_port_list() -> None:
    """As on cisco-25gb: channel-group works on a listed port and creates the
    port-channel, but the port-channel itself is refused until the list names it."""
    fake = FakeSwitch()
    with _restricted(fake, {"ethernet1/53"}) as client:
        client.join_port_channel(54, ["Ethernet1/53"], "active")
        assert fake.channels[54] == {"Ethernet1/53": "active"}
        with pytest.raises(NxapiCommandError, match="Interface permission denied"):
            client.configure_port_channel(54, description="lab")
        with pytest.raises(NxapiCommandError, match="Interface permission denied"):
            client.delete_port_channel(54)
    fake = FakeSwitch()
    with _restricted(fake, {"ethernet1/53", "port-channel1-4096"}) as client:
        client.join_port_channel(54, ["Ethernet1/53"], "active")
        client.configure_port_channel(54, description="lab", min_links=1)
        client.leave_port_channel("Ethernet1/53")
        client.delete_port_channel(54)
    assert 54 not in fake.channels


def test_fake_switch_refuses_a_rate_change_on_an_active_member() -> None:
    fake = FakeSwitch()
    with _client(fake) as client:
        with pytest.raises(NxapiCommandError, match="not admin down"):
            client.set_port_lacp("Ethernet1/43", rate="fast")
        client.configure_port("Ethernet1/43", enabled=False)
        client.set_port_lacp("Ethernet1/43", rate="fast")
    assert fake.port_state["Ethernet1/43"]["lacp_rate"] == "fast"


# ---- plans ----------------------------------------------------------------------------


def test_create_checks_and_describes() -> None:
    join, lines, warnings = plan_create(
        _view(),
        number=" 1 ",
        ports=["Ethernet1/2", "Ethernet1/1", "Ethernet1/2"],
        mode="active",
        fast_rate=True,
        description="lab",
    )
    assert (join.number, join.ports, join.mode, join.fast_rate, join.description) == (
        1,
        ("Ethernet1/1", "Ethernet1/2"),
        "active",
        True,
        "lab",
    )
    assert lines[0] == "Make port-channel1 (LACP, active) from Ethernet1/1, Ethernet1/2."
    assert warnings == [CONFIG_MUST_MATCH]  # neither port is up


def test_create_warns_for_up_ports_and_static() -> None:
    view = _view(up_ports=frozenset({"Ethernet1/1"}))
    _, _, warnings = plan_create(
        view, number="2", ports=["Ethernet1/1"], mode="on", fast_rate=False, description=""
    )
    assert any("Ethernet1/1 is up now" in w for w in warnings)
    assert any("does not check the other end" in w for w in warnings)


@pytest.mark.parametrize(
    ("changes", "fields", "message"),
    [
        ({}, {"number": "43"}, "exists already"),
        ({}, {"ports": ["Ethernet1/43"]}, "already in port-channel43"),
        ({}, {"ports": ["mgmt0"]}, "not one of the switch's front ports"),
        ({}, {"ports": []}, "at least one port"),
        ({}, {"mode": "desirable"}, "choose LACP"),
        ({"lacp_enabled": False}, {}, "LACP is off"),
        ({}, {"mode": "on", "fast_rate": True}, "no LACP rate"),
        ({}, {"number": "4097"}, "1 to 4096"),
        ({}, {"description": "café"}, "plain letters"),
    ],
)
def test_create_refuses(changes, fields, message) -> None:
    values = {
        "number": "1",
        "ports": ["Ethernet1/1"],
        "mode": "active",
        "fast_rate": False,
        "description": "",
    }
    values.update(fields)
    with pytest.raises(ValueError, match=message):
        plan_create(_view(**changes), **values)


def test_static_channel_can_be_made_with_lacp_off() -> None:
    join, _, _ = plan_create(
        _view(lacp_enabled=False),
        number="2",
        ports=["Ethernet1/1"],
        mode="on",
        fast_rate=False,
        description="",
    )
    assert join.mode == "on"


def test_add_takes_the_channels_own_mode() -> None:
    join, lines, _ = plan_add(
        _view(), number="port-channel43", port="Ethernet1/1", mode="active", fast_rate=False
    )
    assert join.ports == ("Ethernet1/1",) and lines == [
        "Add Ethernet1/1 to port-channel43 (LACP, active)."
    ]
    with pytest.raises(ValueError, match="must join the same way"):
        plan_add(_view(), number="43", port="Ethernet1/1", mode="passive", fast_rate=False)
    with pytest.raises(ValueError, match="no port-channel7"):
        plan_add(_view(), number="7", port="Ethernet1/1", mode="active", fast_rate=False)


def test_remove_warns_for_a_bundled_port_and_the_last_one() -> None:
    name, lines, warnings = plan_remove(_view(), port="Ethernet1/43")
    assert name == "Ethernet1/43" and lines[0] == "Take Ethernet1/43 out of port-channel43."
    assert len(warnings) == 1 and "carries traffic" in warnings[0]
    lone = _po43(members=(Member("Ethernet1/43", "D", "active"),))
    _, _, warnings = plan_remove(_view(channels=[lone]), port="Ethernet1/43")
    assert len(warnings) == 1 and "last port" in warnings[0]
    with pytest.raises(ValueError, match="in no port-channel"):
        plan_remove(_view(), port="Ethernet1/1")


def test_delete_is_refused_while_the_channel_has_ports() -> None:
    with pytest.raises(ValueError, match="still has Ethernet1/43, Ethernet1/44; take them out"):
        plan_delete(_view(), number="43")
    empty = _po43(members=(), up=False)
    number, lines, _ = plan_delete(_view(channels=[empty]), number="43")
    assert number == 43 and lines == ["Delete port-channel43."]


def test_channel_settings_send_only_what_changes() -> None:
    change, lines, warnings = plan_channel_settings(
        _view(), number="43", description="storage-server", min_links="3"
    )
    assert change.description is None and change.min_links == 3
    assert lines == ["Keep port-channel43 up only while at least 3 of its ports are up."]
    assert "goes down until 3 are" in warnings[0]
    change, _, warnings = plan_channel_settings(_view(), number="43", description="", min_links="")
    assert change.description == "" and change.min_links is None and warnings == []
    with pytest.raises(ValueError, match="nothing to change"):
        plan_channel_settings(_view(), number="43", description="storage-server", min_links="")
    static = _po43(protocol="NONE", members=(Member("Ethernet1/43", "P", "on"),))
    with pytest.raises(ValueError, match="needs LACP"):
        plan_channel_settings(_view(channels=[static]), number="43", description="", min_links="2")


def test_port_lacp_rate_needs_the_port_off() -> None:
    with pytest.raises(ValueError, match="turn Ethernet1/43 off on its page"):
        plan_port_lacp(_view(), port="Ethernet1/43", rate="fast", priority="")
    view = _view(turned_off=frozenset({"Ethernet1/43"}))
    change, lines, _ = plan_port_lacp(view, port="Ethernet1/43", rate="fast", priority="100")
    assert (change.rate, change.priority) == ("fast", 100)
    assert lines[0] == "Ethernet1/43 sends LACP messages every second (fast rate)."
    # A priority alone works while the port is up.
    change, _, _ = plan_port_lacp(_view(), port="Ethernet1/43", rate="normal", priority="100")
    assert (change.rate, change.priority) == (None, 100)
    with pytest.raises(ValueError, match="nothing to change"):
        plan_port_lacp(_view(), port="Ethernet1/43", rate="normal", priority="32768")
    static = _po43(protocol="NONE", members=(Member("Ethernet1/43", "P", "on"),))
    with pytest.raises(ValueError, match="does not use LACP"):
        plan_port_lacp(_view(channels=[static]), port="Ethernet1/43", rate="fast", priority="")


def test_system_priority_warns_every_lacp_channel() -> None:
    value, lines, warnings = plan_system_priority(_view(), "4096")
    assert value == 4096 and "now 32768" in lines[0]
    assert "port-channel43" in warnings[0]
    with pytest.raises(ValueError, match="32768 already"):
        plan_system_priority(_view(), "32768")
    with pytest.raises(ValueError, match="LACP is off"):
        plan_system_priority(_view(lacp_enabled=False), "4096")
