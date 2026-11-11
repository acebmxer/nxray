"""802.1X (app/dot1x.py): reading the switch's text, the lines every setting sends, and
the values NXray refuses."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.dot1x import (
    DOT1X,
    TIMERS,
    build_dot1x_change,
    parse_dot1x,
    parse_dot1x_global,
    parse_dot1x_ports,
)

FIXTURES = Path(__file__).parent / "fixtures"
GLOBAL = (FIXTURES / "show_dot1x_doc.txt").read_text()
DETAILS = (FIXTURES / "show_dot1x_all_details_doc.txt").read_text()
PORT = {"port": "Ethernet1/5"}


def _lines(scope: str, setting: str, action: str, ident: dict, values: dict) -> tuple[str, ...]:
    return build_dot1x_change(scope, setting, action, ident, values).lines


def test_the_switch_wide_lines() -> None:
    assert parse_dot1x_global(GLOBAL) == {
        "sysauthcontrol": "Enabled",
        "dot1x protocol version": "2",
        "mac-move": "Deny",
    }
    # Also found at the top of the details, when `show dot1x` gave nothing.
    assert parse_dot1x_global("", DETAILS)["mac-move"] == "Deny"


def test_ports_and_their_signed_in_devices() -> None:
    ports = {p.name: p for p in parse_dot1x_ports(DETAILS)}
    assert list(ports) == ["Ethernet1/1", "Ethernet1/2"]
    one = ports["Ethernet1/1"]
    assert one.settings["portcontrol"] == "AUTO" and one.settings["hostmode"] == "MULTI AUTH"
    assert [c["supplicant"] for c in one.clients] == ["00:00:5E:00:53:01", "00:00:5E:00:53:02"]
    assert one.clients[1]["authentication method"] == "MAB"


def test_the_ports_own_sign_in_to_another_switch_is_left_out() -> None:
    two = {p.name: p for p in parse_dot1x_ports(DETAILS)}["Ethernet1/2"]
    assert two.settings["pae"] == "AUTHENTICATOR" and "startperiod" not in two.settings
    assert two.clients == []


def test_the_tables() -> None:
    view = parse_dot1x(GLOBAL, DETAILS)
    devices, ports = view.tables
    assert devices.rows == (
        ("Ethernet1/1", "00:00:5E:00:53:01", "DATA", "AUTHORIZED", "EAP", "Remote Server", "110"),
        ("Ethernet1/1", "00:00:5E:00:53:02", "DATA", "AUTHORIZED", "MAB", "Remote Server", "-"),
    )
    assert ports.rows == (
        ("Ethernet1/1", "AUTO", "MULTI AUTH", "Disabled", "on", "2"),
        ("Ethernet1/2", "FORCE_AUTH", "SINGLE HOST", "Enabled", "off", "0"),
    )


def test_the_places_carry_what_is_set() -> None:
    view = parse_dot1x(GLOBAL, DETAILS)
    (switch,) = view.of("dot1x_switch")
    assert switch.values == {"mac_move": {"policy": "deny"}}
    one, two = view.of("dot1x_port")
    assert one.values["port_control"] == {"control": "auto"}
    assert one.values["host_mode"] == {"mode": "multi-auth"}
    assert one.values["max_req"] == {"count": "1"}
    assert two.values["port_control"] == {"control": "force-authorized"}
    assert two.values["host_mode"] == {"mode": "single-host"}
    assert (
        "Timers (seconds)",
        "re-authperiod 3600 (Locally configured), quiet-period 60, "
        "tx-period 1, supp-timeout 30, server-timeout 30, ratelimit-period 0, "
        "inactivity-period 0",
    ) in one.facts


def test_nothing_read_is_an_empty_page() -> None:
    view = parse_dot1x("", "")
    assert view.instances == () and all(t.rows == () for t in view.tables)


def test_a_host_mode_nxray_does_not_set_is_shown_but_not_offered() -> None:
    text = "Dot1x Info for Ethernet1/26\n PAE = AUTHENTICATOR\n HostMode = MULTI-DOMAIN\n"
    (port,) = parse_dot1x("", text).of("dot1x_port")
    assert ("Host mode", "MULTI-DOMAIN") in port.facts and "host_mode" not in port.values


@pytest.mark.parametrize("control", ["auto", "force-authorized", "force-unauthorized"])
def test_port_control(control: str) -> None:
    assert _lines("dot1x_port", "port_control", "set", PORT, {"control": control}) == (
        "interface Ethernet1/5",
        f"dot1x port-control {control}",
    )
    assert _lines("dot1x_port", "port_control", "remove", PORT, {})[-1] == "no dot1x port-control"


def test_port_control_warns_first() -> None:
    change = build_dot1x_change("dot1x_port", "port_control", "set", PORT, {"control": "auto"})
    assert "cut off" in change.warning


@pytest.mark.parametrize("mode", ["single-host", "multi-host", "multi-auth"])
def test_host_mode(mode: str) -> None:
    assert _lines("dot1x_port", "host_mode", "set", PORT, {"mode": mode})[-1] == (
        f"dot1x host-mode {mode}"
    )


def test_mac_authentication_bypass_with_and_without_eap() -> None:
    assert _lines("dot1x_port", "mab", "set", PORT, {})[-1] == "dot1x mac-auth-bypass"
    assert _lines("dot1x_port", "mab", "set", PORT, {"eap": "yes"})[-1] == (
        "dot1x mac-auth-bypass eap"
    )
    assert _lines("dot1x_port", "mab", "remove", PORT, {})[-1] == "no dot1x mac-auth-bypass"


@pytest.mark.parametrize("timer", TIMERS)
def test_every_timer(timer: str) -> None:
    values = {"timer": timer, "seconds": "120"}
    assert _lines("dot1x_port", "timeout", "set", PORT, values)[-1] == (
        f"dot1x timeout {timer} 120"
    )
    assert _lines("dot1x_port", "timeout", "remove", PORT, {"timer": timer})[-1] == (
        f"no dot1x timeout {timer}"
    )


@pytest.mark.parametrize(
    ("setting", "values"),
    [
        ("timeout", {"timer": "quiet-period", "seconds": "0"}),
        ("timeout", {"timer": "quiet-period", "seconds": "65536"}),
        ("timeout", {"timer": "nap-time", "seconds": "5"}),
        ("max_req", {"count": "11"}),
        ("max_reauth_req", {"count": "0"}),
        ("port_control", {"control": "open"}),
        ("host_mode", {"mode": "multi-domain"}),
        ("port_control", {"control": "auto ; shutdown"}),
    ],
)
def test_bad_values_are_refused(setting: str, values: dict) -> None:
    with pytest.raises(ValueError):
        _lines("dot1x_port", setting, "set", PORT, values)


def test_retries_and_the_rest_of_the_port_lines() -> None:
    assert _lines("dot1x_port", "max_req", "set", PORT, {"count": "3"})[-1] == "dot1x max-req 3"
    assert _lines("dot1x_port", "max_reauth_req", "set", PORT, {"count": "4"})[-1] == (
        "dot1x max-reauth-req 4"
    )
    assert _lines("dot1x_port", "reauth", "remove", PORT, {})[-1] == "no dot1x re-authentication"
    assert _lines("dot1x_port", "pae", "set", PORT, {})[-1] == "dot1x pae authenticator"


def test_switch_wide_lines() -> None:
    assert _lines("dot1x_switch", "auth_group", "set", {}, {"group": "radius"}) == (
        "aaa authentication dot1x default group radius",
    )
    assert _lines("dot1x_switch", "accounting_group", "remove", {}, {"group": "rad2"}) == (
        "no aaa accounting dot1x default group rad2",
    )
    assert _lines("dot1x_switch", "system_auth", "remove", {}, {}) == (
        "no dot1x system-auth-control",
    )
    assert _lines("dot1x_switch", "radius_accounting", "set", {}, {}) == (
        "dot1x radius-accounting",
    )
    assert _lines("dot1x_switch", "mac_move", "set", {}, {"policy": "permit"}) == (
        "dot1x mac-move permit",
    )
    with pytest.raises(ValueError):
        _lines("dot1x_switch", "auth_group", "set", {}, {"group": "radius tacacs"})


def test_the_protocol_needs_the_feature() -> None:
    assert DOT1X.features == ("dot1x",)
    assert [s.key for s in DOT1X.scopes] == ["dot1x_switch", "dot1x_port"]
