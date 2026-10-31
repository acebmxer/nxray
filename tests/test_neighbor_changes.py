"""Neighbor changes: checked values, the client's commands, the role rules and the plans."""

from __future__ import annotations

import json

import httpx
import pytest

from app.neighbor_changes import (
    DROP,
    RELEARN_WARNING,
    DiscoveryChange,
    PortDiscovery,
    describe_port_discovery,
    load_port_discovery,
    parse_cdp_interface,
    parse_lldp_interface,
    plan_clear,
    plan_mac_aging,
    plan_port_discovery,
    plan_static_mac,
    plan_static_removal,
    static_entries,
    static_target,
)
from app.neighbors import MacEntry, NeighborView, PortChannel, parse_mac_table
from app.nxapi import (
    NxapiClient,
    SwitchTarget,
    validate_device_mac,
    validate_mac_aging,
)
from app.port_changes import NEIGHBOR_RULES, ROLE_VERSION, missing_changes, role_lines
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

PORTS = ["Ethernet1/1", "Ethernet1/2", "Ethernet1/47", "Ethernet1/54"]


def _client(fake: FakeSwitch) -> NxapiClient:
    target = SwitchTarget("192.0.2.10", 443, "admin", ADMIN_PASSWORD, 5.0)
    return NxapiClient(target, transport=fake.transport())


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


def _view(**changes) -> NeighborView:
    macs = parse_mac_table(load_fixture("show_mac_address_table"))
    return NeighborView(**{"macs": macs, "aging_seconds": 1800, **changes})


def _static(mac: str, vlan: str, port: str) -> MacEntry:
    return MacEntry(mac=mac, vlan=vlan, kind="static", port=port)


# ---- checked values -----------------------------------------------------------


@pytest.mark.parametrize("value", ["0", "120", "1800", "918000", " 300 "])
def test_aging_times_the_switch_takes(value: str) -> None:
    assert validate_mac_aging(value) == int(value)


@pytest.mark.parametrize("value", ["", "-5", "60", "115", "918005", "1e3", "١٢٠", "abc"])
def test_aging_times_out_of_range_are_refused(value: str) -> None:
    with pytest.raises(ValueError, match="0 \\(never forget\\) or 120 to 918000"):
        validate_mac_aging(value)


def test_aging_time_not_a_multiple_of_five_is_refused() -> None:
    # The switch would quietly store 1795 (seen on cisco-25gb).
    with pytest.raises(ValueError, match="steps of 5 seconds, such as 1795"):
        validate_mac_aging("1799")


@pytest.mark.parametrize(
    "text", ["00:11:22:33:44:55", "0011.2233.4455", "00-11-22-33-44-55", "001122334455"]
)
def test_device_mac_in_the_switch_form(text: str) -> None:
    assert validate_device_mac(text) == "0011.2233.4455"


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("01:00:5e:00:00:01", "multicast"),
        ("ff:ff:ff:ff:ff:ff", "multicast"),
        ("00:00:00:00:00:00", "not a device"),
        ("0011.2233.44", "not a MAC address"),
        ("0011.2233.445g", "not a MAC address"),
        ("0011.2233.4455 vlan 1", "not a MAC address"),
    ],
)
def test_bad_device_macs_are_refused(text: str, reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        validate_device_mac(text)


# ---- the client's commands ----------------------------------------------------


def test_port_discovery_sends_only_the_values_given() -> None:
    sent, client = _recording()
    client.set_port_discovery("Ethernet1/5", cdp=False)
    client.set_port_discovery("Ethernet1/5", lldp_transmit=True, lldp_receive=False)
    assert sent == [
        ["interface Ethernet1/5", "no cdp enable"],
        ["interface Ethernet1/5", "lldp transmit", "no lldp receive"],
    ]


def test_port_discovery_refuses_nothing_and_a_bad_port() -> None:
    sent, client = _recording()
    with pytest.raises(ValueError, match="nothing to change"):
        client.set_port_discovery("Ethernet1/5")
    with pytest.raises(ValueError, match="front-panel port"):
        client.set_port_discovery("mgmt0", cdp=False)
    assert sent == []


def test_mac_table_commands() -> None:
    sent, client = _recording()
    client.set_mac_aging(600)
    client.add_static_mac("00:11:22:33:44:55", 10, "Ethernet1/5")
    client.add_static_mac("00:11:22:33:44:56", 10, None)
    client.remove_static_mac("0011.2233.4455", 10, "Ethernet1/5")
    client.remove_static_mac("0011.2233.4456", 10, None)
    client.clear_learned_macs()
    client.clear_learned_macs(port="Ethernet1/5")
    client.clear_learned_macs(vlan=10)
    client.clear_learned_macs(mac="00:11:22:33:44:55")
    client.clear_learned_macs(mac="00:11:22:33:44:55", vlan=10)
    assert sent == [
        ["mac address-table aging-time 600"],
        ["mac address-table static 0011.2233.4455 vlan 10 interface Ethernet1/5"],
        ["mac address-table static 0011.2233.4456 vlan 10 drop"],
        ["no mac address-table static 0011.2233.4455 vlan 10 interface Ethernet1/5"],
        ["no mac address-table static 0011.2233.4456 vlan 10 drop"],
        ["clear mac address-table dynamic"],
        ["clear mac address-table dynamic interface Ethernet1/5"],
        ["clear mac address-table dynamic vlan 10"],
        ["clear mac address-table dynamic address 0011.2233.4455"],
        ["clear mac address-table dynamic address 0011.2233.4455 vlan 10"],
    ]


def test_mac_table_commands_refuse_bad_values() -> None:
    sent, client = _recording()
    with pytest.raises(ValueError):
        client.set_mac_aging(1799)
    with pytest.raises(ValueError):
        client.add_static_mac("01:00:5e:00:00:01", 10, "Ethernet1/5")
    with pytest.raises(ValueError):
        client.add_static_mac("00:11:22:33:44:55", 4095, "Ethernet1/5")
    with pytest.raises(ValueError):
        client.add_static_mac("00:11:22:33:44:55", 10, "port-channel43")
    with pytest.raises(ValueError, match="cannot be combined"):
        client.clear_learned_macs(port="Ethernet1/5", vlan=10)
    with pytest.raises(ValueError):
        client.clear_learned_macs(port="mgmt0")
    assert sent == []


# ---- the role -------------------------------------------------------------------


def test_role_has_the_neighbor_rules() -> None:
    lines = role_lines(["Ethernet1/1"], "nxray")
    for rule in NEIGHBOR_RULES:
        assert rule in lines
    assert ROLE_VERSION == 7
    # Rule numbers carry on from the feature rules and never repeat.
    numbers = [int(line.split()[1]) for line in lines if line.startswith("rule ")]
    assert numbers == list(range(1, 51))


def test_missing_changes_names_neighbor_changes() -> None:
    assert missing_changes(4) == "neighbor, port-channel and VLAN interface changes"
    assert missing_changes(3) == "feature, neighbor, port-channel and VLAN interface changes"
    assert missing_changes(1) == (
        "VLAN, port settings, feature, neighbor, port-channel and VLAN interface changes"
    )
    assert missing_changes(6) == "VLAN interface changes"
    assert missing_changes(7) == ""


def test_the_role_lets_the_account_make_neighbor_changes() -> None:
    """Through the fake switch, with only the role's rules: the same commands
    NXray sends, on a port the role names; another port is refused."""
    fake = FakeSwitch(lldp=True)
    fake.users["nxray"] = ("Passw0rdForTests", "network-operator")
    shell = fake.ssh_opener()("192.0.2.10", 22, "admin", ADMIN_PASSWORD, 5.0)
    shell.run("configure terminal")
    for line in role_lines(["Ethernet1/5"], "nxray", vlan_interfaces=False):
        assert "Invalid" not in shell.run(line), line
    target = SwitchTarget("192.0.2.10", 443, "nxray", "Passw0rdForTests", 5.0)
    with NxapiClient(target, transport=fake.transport()) as client:
        client.set_port_discovery("Ethernet1/5", cdp=False, lldp_transmit=False)
        client.set_mac_aging(600)
        client.add_static_mac("00:11:22:33:44:55", 1, "Ethernet1/5")
        client.remove_static_mac("00:11:22:33:44:55", 1, "Ethernet1/5")
        client.clear_learned_macs()
        with pytest.raises(Exception, match="Interface permission denied"):
            client.set_port_discovery("Ethernet1/6", cdp=False)
    assert fake.port_state["Ethernet1/5"] == {"cdp": False, "lldp_transmit": False}
    assert fake.mac_aging == 600
    assert all(row["disp_type"] != "dynamic" for row in fake.macs())


# ---- reading a port ---------------------------------------------------------------


def test_cdp_interface_from_recorded_output() -> None:
    assert parse_cdp_interface(load_fixture("show_cdp_interface")) is True
    body = load_fixture("show_cdp_interface")
    body["TABLE_cdp_all"]["ROW_cdp_all"]["cdp_intf_enabled"] = "disabled"
    assert parse_cdp_interface(body) is False
    assert parse_cdp_interface({}) is None


def test_lldp_interface_fields_are_found_wherever_they_sit() -> None:
    flat = {"tx_enabled": "TRUE", "rx_enabled": "FALSE"}
    nested = {"TABLE_interface": {"ROW_interface": [{"interface": "Ethernet1/5", **flat}]}}
    assert parse_lldp_interface(flat) == (True, False)
    assert parse_lldp_interface(nested) == (True, False)
    assert parse_lldp_interface({}) == (None, None)


def test_load_port_discovery_reads_lldp_only_while_it_is_on() -> None:
    fake = FakeSwitch()
    with _client(fake) as client:
        assert load_port_discovery(client, "Ethernet1/5", False) == PortDiscovery(cdp=True)
    assert fake.requests == [["show cdp interface Ethernet1/5"]]

    fake = FakeSwitch(lldp=True)
    fake.port_state["Ethernet1/5"] = {"cdp": False, "lldp_receive": False}
    with _client(fake) as client:
        found = load_port_discovery(client, "Ethernet1/5", True)
    assert found == PortDiscovery(cdp=False, lldp_transmit=True, lldp_receive=False)
    assert found is not None and found.lldp_known


def test_load_port_discovery_is_none_when_refused() -> None:
    fake = FakeSwitch(reject={"show cdp interface"})
    with _client(fake) as client:
        assert load_port_discovery(client, "Ethernet1/5", False) is None


# ---- planning a port's CDP and LLDP --------------------------------------------------


def test_plan_sends_only_what_differs() -> None:
    now = PortDiscovery(cdp=True, lldp_transmit=True, lldp_receive=True)
    change = plan_port_discovery(
        now, cdp=True, lldp_transmit=False, lldp_receive=True, lldp_shown=True
    )
    assert (change.cdp, change.lldp_transmit, change.lldp_receive) == (None, False, None)
    same = plan_port_discovery(
        now, cdp=True, lldp_transmit=True, lldp_receive=True, lldp_shown=True
    )
    assert same.empty


def test_plan_leaves_lldp_alone_when_the_page_did_not_show_it() -> None:
    # LLDP off on the switch: its boxes are not on the page, so they arrive unticked.
    now = PortDiscovery(cdp=True)
    change = plan_port_discovery(
        now, cdp=False, lldp_transmit=False, lldp_receive=False, lldp_shown=False
    )
    assert (change.cdp, change.lldp_transmit, change.lldp_receive) == (False, None, None)
    # A form from before LLDP went off still does not touch it.
    change = plan_port_discovery(
        now, cdp=True, lldp_transmit=False, lldp_receive=False, lldp_shown=True
    )
    assert change.empty


def test_describe_warns_only_when_turning_off() -> None:
    lines, warnings = describe_port_discovery(
        "Ethernet1/5", DiscoveryChange(cdp=False, lldp_transmit=False, lldp_receive=False)
    )
    assert lines == [
        "Turn CDP off on Ethernet1/5.",
        "Stop sending LLDP on Ethernet1/5.",
        "Stop listening for LLDP on Ethernet1/5.",
    ]
    assert len(warnings) == 3
    lines, warnings = describe_port_discovery(
        "Ethernet1/5", DiscoveryChange(cdp=True, lldp_transmit=True, lldp_receive=True)
    )
    assert lines[0] == "Turn CDP on on Ethernet1/5."
    assert warnings == []


# ---- planning MAC table changes --------------------------------------------------------


def test_plan_aging() -> None:
    seconds, lines, warnings = plan_mac_aging(_view(), "600")
    assert seconds == 600
    assert lines[0] == (
        "Forget a learned address after 600 seconds (10 minutes) without traffic "
        "(now 1800 seconds (30 minutes))."
    )
    assert warnings == []
    _, _, warnings = plan_mac_aging(_view(), "0")
    assert "only grows" in warnings[0]
    with pytest.raises(ValueError, match="already"):
        plan_mac_aging(_view(), "1800")


def test_static_entries_leave_out_the_switch_itself() -> None:
    own = MacEntry(mac="70:79:b3:bd:bb:e5", vlan="", kind="static", port="sup-eth1(R)")
    added = _static("02:00:00:00:00:01", "1", "Ethernet1/54")
    dropped = _static("02:00:00:00:00:02", "1", "Drop")
    channel = _static("02:00:00:00:00:03", "1", "port-channel43")
    view = _view(macs=[own, added, dropped, channel])
    assert static_entries(view) == [added, dropped, channel]
    assert [static_target(m) for m in static_entries(view)] == ["Ethernet1/54", DROP, None]


def test_plan_static_mac_on_a_port() -> None:
    entry, lines, warnings = plan_static_mac(
        _view(), mac="02:00:00:00:00:01", vlan="1", where="1/54", vlan_ids={1}, ports=PORTS
    )
    assert (entry.mac, entry.vlan, entry.port) == ("0200.0000.0001", 1, "Ethernet1/54")
    assert lines[0] == "Always send traffic for 02:00:00:00:00:01 in VLAN 1 to Ethernet1/54."
    assert warnings == []


def test_plan_static_mac_dropped() -> None:
    entry, lines, _ = plan_static_mac(
        _view(), mac="0200.0000.0001", vlan="1", where="drop", vlan_ids={1}, ports=PORTS
    )
    assert entry.port is None
    assert lines[0] == "Drop all traffic to and from 02:00:00:00:00:01 in VLAN 1."


def test_plan_static_mac_warns_when_the_address_was_learned_elsewhere() -> None:
    learned = parse_mac_table(load_fixture("show_mac_address_table"))[0]
    _, _, warnings = plan_static_mac(
        _view(),
        mac=learned.mac,
        vlan=learned.vlan,
        where="Ethernet1/54",
        vlan_ids={int(learned.vlan)},
        ports=PORTS,
    )
    assert f"was learned on {learned.port}" in warnings[0]


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"vlan": "20"}, "VLAN 20 does not exist"),
        ({"where": "port-channel43"}, "not one of the switch's front ports"),
        ({"where": "Ethernet1/99"}, "not one of the switch's front ports"),
        ({"mac": "01:00:5e:00:00:01"}, "multicast"),
        ({"mac": "02:00:00:00:00:09"}, "already has a static entry"),
    ],
)
def test_plan_static_mac_refusals(changes: dict[str, str], reason: str) -> None:
    view = _view(macs=[_static("02:00:00:00:00:09", "1", "Ethernet1/1")])
    form = {"mac": "02:00:00:00:00:01", "vlan": "1", "where": "Ethernet1/54", **changes}
    with pytest.raises(ValueError, match=reason):
        plan_static_mac(view, vlan_ids={1}, ports=PORTS, **form)


def test_plan_static_removal() -> None:
    view = _view(
        macs=[
            _static("02:00:00:00:00:01", "1", "Ethernet1/54"),
            _static("02:00:00:00:00:02", "1", "Drop"),
            _static("02:00:00:00:00:03", "1", "port-channel43"),
        ]
    )
    entry, lines, _ = plan_static_removal(view, mac="0200.0000.0001", vlan="1")
    assert (entry.mac, entry.vlan, entry.port) == ("0200.0000.0001", 1, "Ethernet1/54")
    assert lines[0] == (
        "Remove the static entry for 02:00:00:00:00:01 in VLAN 1 (on Ethernet1/54)."
    )
    entry, _, _ = plan_static_removal(view, mac="02:00:00:00:00:02", vlan="1")
    assert entry.port is None
    with pytest.raises(ValueError, match="remove it on the switch"):
        plan_static_removal(view, mac="02:00:00:00:00:03", vlan="1")
    with pytest.raises(ValueError, match="no static entry"):
        plan_static_removal(view, mac="02:00:00:00:00:01", vlan="2")


def test_plan_clear_counts_what_goes() -> None:
    view = _view()
    dynamic = [m for m in view.macs if m.kind == "dynamic"]
    clear, lines, warnings = plan_clear(view, scope="all", ports=PORTS)
    assert clear.port is None and clear.vlan is None and clear.mac is None
    assert f"({len(dynamic)} learned addresses in the table now)" in lines[0]
    assert clear.done == (
        f"The switch forgot every learned address ({len(dynamic)} learned addresses "
        "were in the table)."
    )
    assert warnings == [RELEARN_WARNING]

    on_47 = [m for m in dynamic if m.port == "Ethernet1/47"]
    clear, lines, _ = plan_clear(view, scope="port", ports=PORTS, port="Eth1/47")
    assert clear.port == "Ethernet1/47"
    assert lines[0].startswith(f"Forget the addresses learned on Ethernet1/47 ({len(on_47)} ")

    clear, lines, _ = plan_clear(view, scope="vlan", ports=PORTS, vlan="1")
    assert clear.vlan == 1

    one = dynamic[0]
    clear, lines, _ = plan_clear(view, scope="address", ports=PORTS, mac=one.mac)
    assert clear.mac == validate_device_mac(one.mac) and clear.vlan is None
    assert "(1 learned address in the table now)" in lines[0]


def test_plan_clear_refusals_and_a_port_channel_member() -> None:
    view = _view(port_channels=[PortChannel("port-channel43", ("Ethernet1/2",), "LACP", True)])
    with pytest.raises(ValueError, match="choose what to clear"):
        plan_clear(view, scope="everything", ports=PORTS)
    with pytest.raises(ValueError, match="front ports"):
        plan_clear(view, scope="port", ports=PORTS, port="mgmt0")
    with pytest.raises(ValueError):
        plan_clear(view, scope="vlan", ports=PORTS, vlan="")
    with pytest.raises(ValueError):
        plan_clear(view, scope="address", ports=PORTS, mac="nonsense")
    _, _, warnings = plan_clear(view, scope="port", ports=PORTS, port="Ethernet1/2")
    assert "part of port-channel43" in warnings[0]
