"""Port settings: reading them from recorded switch output, and checking a form."""

from __future__ import annotations

import re

import pytest

from app.nxapi import validate_ip_interface, validate_storm_level
from app.port_settings import (
    NO_STORM_LIMIT,
    PortSettings,
    describe_port_settings,
    guess_breakout_map,
    parse_ip_addresses,
    parse_port_settings,
    plan_breakout,
    plan_port_settings,
    settings_commands,
    speed_label,
    speed_mbps,
)
from app.ports import parse_ports
from app.vlans import parse_switchports
from tests.conftest import load_fixture


def _port(name: str):
    ports = parse_ports(
        load_fixture("show_interface"),
        load_fixture("show_interface_status"),
        load_fixture("show_interface_transceiver"),
    )
    return next(port for port in ports if port.name == name)


def _settings(name: str = "Ethernet1/3", caps: str = "show_interface_capabilities_sfp"):
    vlans = parse_switchports(load_fixture("show_interface_switchport"))
    caps_body = load_fixture(caps)
    caps_body["TABLE_interface"]["ROW_interface"]["interface"] = name
    return parse_port_settings(
        _port(name),
        vlans.get(name),
        caps_body,
        load_fixture("show_interface_flowcontrol"),
        load_fixture("show_interface_counters_storm_control"),
        load_fixture("show_ip_interface_vrf_all"),
    )


def _with(settings: PortSettings, **changes) -> PortSettings:
    from dataclasses import replace

    return replace(settings, **changes)


# ---- reading ----------------------------------------------------------------


def test_reads_the_recorded_sfp_port() -> None:
    settings = _settings()
    assert settings.speeds == ("1000", "10000", "25000")
    assert settings.speed == "auto"
    assert settings.duplex == "full"
    assert settings.mtu == 1500
    assert settings.fec == "auto"
    assert (settings.flow_receive, settings.flow_send) == ("off", "off")
    assert settings.storm == dict.fromkeys(("broadcast", "multicast", "unicast"), NO_STORM_LIMIT)
    assert settings.storm_action == "none"
    assert not settings.routed and settings.routed_capable
    assert settings.ip_address == ""
    assert not settings.breakout_capable and not settings.is_breakout_port


def test_reads_the_recorded_qsfp_port_as_splittable() -> None:
    settings = _settings("Ethernet1/50", "show_interface_capabilities_qsfp")
    assert settings.breakout_capable
    assert settings.speeds[-1] == "100000"


def test_breakout_port_knows_its_parent() -> None:
    settings = _with(_settings(), name="Ethernet1/50/3")
    assert settings.is_breakout_port and settings.parent == "Ethernet1/50"


def test_storm_levels_and_action_are_read() -> None:
    storm = {
        "TABLE_interface": {
            "ROW_interface": {
                "interface": "Ethernet1/3",
                "eth_bcast_supp": "10.50",
                "eth_mcast_supp": "100.00",
                "eth_ucast_supp": "2",
                "supp_action": "[shutdown]",
            }
        }
    }
    vlans = parse_switchports(load_fixture("show_interface_switchport"))
    settings = parse_port_settings(
        _port("Ethernet1/3"),
        vlans.get("Ethernet1/3"),
        load_fixture("show_interface_capabilities_sfp"),
        load_fixture("show_interface_flowcontrol"),
        storm,
        {},
    )
    assert settings.storm == {"broadcast": "10.50", "multicast": "100.00", "unicast": "2.00"}
    assert settings.storm_text("broadcast") == "10.50%"
    assert settings.storm_text("multicast") == "none"
    assert settings.storm_field("multicast") == ""
    assert settings.storm_action == "shutdown"


def test_ip_addresses_take_short_and_long_names() -> None:
    body = {
        "TABLE_intf": {
            "ROW_intf": [
                {"vrf-name-out": "default", "intf-name": "Eth1/7", "prefix": "192.0.2.1",
                 "masklen": 24},
                {"vrf-name-out": "management", "intf-name": "mgmt0", "prefix": "192.0.2.10",
                 "masklen": 24},
            ]
        }
    }  # fmt: skip
    found = parse_ip_addresses(body)
    assert found["Ethernet1/7"] == ("192.0.2.1/24", "default")
    assert found["mgmt0"] == ("192.0.2.10/24", "management")
    # The recorded output has mgmt0 only.
    assert set(parse_ip_addresses(load_fixture("show_ip_interface_vrf_all"))) == {"mgmt0"}


def test_settings_commands_refuse_a_bad_port_name() -> None:
    assert settings_commands("Ethernet1/3")[0] == "show interface Ethernet1/3 capabilities"
    with pytest.raises(ValueError):
        settings_commands("mgmt0")


@pytest.mark.parametrize(
    ("text", "mbps"),
    [("10G", "10000"), ("25G", "25000"), ("100G", "100000"), ("1000", "1000"),
     ("auto", "auto"), ("auto-speed", "auto"), ("--", "")],
)  # fmt: skip
def test_speed_words(text: str, mbps: str) -> None:
    assert speed_mbps(text) == mbps


def test_speed_labels() -> None:
    assert speed_label("10000") == "10 Gb/s"
    assert speed_label("100") == "100 Mb/s"
    assert speed_label("auto") == "Auto"


# ---- checking the form ------------------------------------------------------


def test_an_unchanged_form_changes_nothing() -> None:
    settings = _settings()
    assert plan_port_settings(settings, {}).empty
    form = {
        "layer": "switched",
        "speed": "auto",
        "mtu": "1500",
        "fec": "auto",
        "flow_receive": "off",
        "flow_send": "off",
        "storm_broadcast": "",
        "storm_multicast": "",
        "storm_unicast": "",
        "storm_action": "none",
    }
    assert plan_port_settings(settings, form).empty


def test_only_the_changed_settings_are_kept() -> None:
    change = plan_port_settings(
        _settings(), {"speed": "10000", "mtu": "9216", "storm_broadcast": "10"}
    )
    assert change.speed == "10000"
    assert change.mtu == 9216
    assert change.storm_levels == {"broadcast": "10.00"}
    assert change.fec is None and change.layer is None and change.storm_action is None


@pytest.mark.parametrize(
    ("form", "reason"),
    [
        ({"speed": "100000"}, "runs at"),
        ({"speed": "fast"}, "runs at"),
        ({"mtu": "9000"}, "1500 (standard) or 9216"),
        ({"mtu": "abc"}, "MTU is a number"),
        ({"fec": "magic"}, "FEC mode"),
        ({"flow_send": "maybe"}, "on or off"),
        ({"storm_unicast": "120"}, "0 to 100"),
        ({"storm_unicast": "1.234"}, "two decimals"),
        ({"storm_action": "explode"}, "none, shutdown or trap"),
        ({"layer": "both"}, "switched (layer 2) or routed"),
        ({"layer": "routed", "ip_address": "192.0.2.0/24"}, "network's own"),
        ({"layer": "routed", "ip_address": "192.0.2.5"}, "prefix length"),
        ({"layer": "routed", "ip_address": "banana"}, "not an IPv4 address"),
        ({"layer": "routed", "mtu": "100"}, "576 to 9216"),
    ],
)
def test_bad_forms_are_refused(form: dict[str, str], reason: str) -> None:
    with pytest.raises(ValueError, match=re.escape(reason)):
        plan_port_settings(_settings(), form)


def test_routed_port_with_address() -> None:
    change = plan_port_settings(
        _settings(), {"layer": "routed", "ip_address": "192.0.2.1/24", "mtu": "9000"}
    )
    assert change.layer == "routed"
    assert change.ip_address == "192.0.2.1/24"
    assert change.remove_ip is None
    assert change.mtu == 9000
    # Storm control does not apply to a routed port, so its fields are ignored.
    assert change.storm_levels == {}


def test_a_port_that_cannot_route_is_refused() -> None:
    with pytest.raises(ValueError, match="cannot be a routed port"):
        plan_port_settings(_with(_settings(), routed_capable=False), {"layer": "routed"})


def test_changing_and_removing_the_address() -> None:
    routed = _with(_settings(), routed=True, ip_address="192.0.2.1/24", mtu=9000)
    moved = plan_port_settings(routed, {"layer": "routed", "ip_address": "192.0.2.9/24"})
    assert (moved.remove_ip, moved.ip_address) == ("192.0.2.1/24", "192.0.2.9/24")
    cleared = plan_port_settings(routed, {"layer": "routed", "ip_address": ""})
    assert (cleared.remove_ip, cleared.ip_address) == ("192.0.2.1/24", None)


def test_back_to_switched_removes_the_address_and_checks_the_mtu() -> None:
    routed = _with(_settings(), routed=True, ip_address="192.0.2.1/24", mtu=9000)
    with pytest.raises(ValueError, match="1500"):
        plan_port_settings(routed, {"layer": "switched"})
    change = plan_port_settings(routed, {"layer": "switched", "mtu": "1500"})
    assert change.layer == "switched"
    assert change.remove_ip == "192.0.2.1/24"
    assert change.mtu == 1500


def test_storm_limit_removed_and_action_cleared() -> None:
    limited = _with(
        _settings(),
        storm={"broadcast": "5.00", "multicast": NO_STORM_LIMIT, "unicast": NO_STORM_LIMIT},
        storm_action="trap",
    )
    change = plan_port_settings(limited, {"storm_broadcast": "", "storm_action": "none"})
    assert change.storm_levels == {"broadcast": NO_STORM_LIMIT}
    assert change.storm_action == "none"


def test_descriptions_and_warnings() -> None:
    settings = _settings()
    change = plan_port_settings(
        settings, {"speed": "10000", "storm_action": "shutdown", "mtu": "1500"}
    )
    lines, warnings = describe_port_settings(settings, change, up=True)
    assert "Speed: Auto → 10 Gb/s." in lines
    assert "Storm-control action: none → shutdown." in lines
    assert any("link goes down" in w for w in warnings)
    assert any("turns the port off" in w for w in warnings)
    _, quiet = describe_port_settings(settings, change, up=False)
    assert not any("link goes down" in w for w in quiet)


def test_smaller_mtu_warns() -> None:
    jumbo = _with(_settings(), mtu=9216)
    change = plan_port_settings(jumbo, {"mtu": "1500"})
    _, warnings = describe_port_settings(jumbo, change, up=False)
    assert any("larger than 1500 bytes are dropped" in w for w in warnings)


def test_layer_change_warns() -> None:
    settings = _settings()
    change = plan_port_settings(settings, {"layer": "routed"})
    lines, warnings = describe_port_settings(settings, change, up=False)
    assert lines == ["Layer: switched (layer 2) → routed (layer 3)."]
    assert any("VLAN settings are removed" in w for w in warnings)


# ---- breakout ---------------------------------------------------------------


def test_split_and_join_plans() -> None:
    qsfp = _settings("Ethernet1/50", "show_interface_capabilities_qsfp")
    split = plan_breakout(qsfp, "split", "25g-4x")
    assert split.port == "Ethernet1/50"
    assert "Ethernet1/50/1 to Ethernet1/50/4" in split.lines[0]
    assert any("Update the port list" in w for w in split.warnings)
    part = _with(qsfp, name="Ethernet1/50/2")
    join = plan_breakout(part, "join", "10g-4x")
    assert join.port == "Ethernet1/50" and join.action == "join"


@pytest.mark.parametrize(
    ("name", "action", "mapping", "reason"),
    [
        ("Ethernet1/3", "split", "25g-4x", "cannot be split"),
        ("Ethernet1/50", "split", "40g-2x", "4 x 10G or 4 x 25G"),
        ("Ethernet1/50", "join", "25g-4x", "not one of four"),
        ("Ethernet1/50/1", "split", "25g-4x", "cannot be split"),
        ("Ethernet1/50", "melt", "25g-4x", "split or join"),
    ],
)
def test_breakout_refusals(name: str, action: str, mapping: str, reason: str) -> None:
    qsfp = _settings("Ethernet1/50", "show_interface_capabilities_qsfp")
    settings = qsfp if name == "Ethernet1/50" else _with(qsfp, name=name)
    if name == "Ethernet1/3":
        settings = _settings()
    with pytest.raises(ValueError, match=re.escape(reason)):
        plan_breakout(settings, action, mapping)


def test_breakout_map_guess() -> None:
    assert guess_breakout_map(["25G", "25G", "auto", "25G"]) == "25g-4x"
    assert guess_breakout_map(["10G"] * 4) == "10g-4x"
    assert guess_breakout_map(["10G", "25G"]) is None
    assert guess_breakout_map([]) is None


# ---- value checks -----------------------------------------------------------


def test_ip_interface_values() -> None:
    assert validate_ip_interface(" 192.0.2.1/24 ") == "192.0.2.1/24"
    assert validate_ip_interface("192.0.2.0/31") == "192.0.2.0/31"
    with pytest.raises(ValueError):
        validate_ip_interface("192.0.2.255/24")
    with pytest.raises(ValueError):
        validate_ip_interface("2001:db8::1/64")


def test_storm_level_values() -> None:
    assert validate_storm_level("10") == "10.00"
    assert validate_storm_level("0.5") == "0.50"
    assert validate_storm_level(100) == "100.00"
    for bad in ("-1", "100.01", "1e2", "ten", ""):
        with pytest.raises(ValueError):
            validate_storm_level(bad)
