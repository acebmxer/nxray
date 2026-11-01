"""Switch admin: reading the running configuration, NTP status, the clock and the
log, and the lines each change sends. The configuration text and the show
bodies are shaped after Cisco's NX-OS 9.3 guides and NX-API reference (fixtures
ending in _doc), not recorded on a switch."""

from __future__ import annotations

import pytest

from app.port_changes import ADMIN_RULES, role_lines
from app.protocols import Field, check_value
from app.switch_admin import (
    build_admin_change,
    clock_text,
    log_command,
    parse_admin_config,
    parse_log,
    parse_ntp_status,
    parse_switch_admin,
)
from tests.conftest import FIXTURES, load_fixture


def _config() -> str:
    return (FIXTURES / "show_running-config_admin_doc.txt").read_text()


def _lines(scope: str, setting: str, action: str = "set", ident=None, **values: str):
    return list(build_admin_change(scope, setting, action, ident or {}, values).lines)


def test_parse_admin_config() -> None:
    found = parse_admin_config(_config())
    assert found.hostname == "nexus-lab"
    assert found.banner == "Authorized access only"
    assert found.timezone == ("EST", "-5", "0")
    assert found.summer_time is not None and found.summer_time[0] == "EDT"
    assert found.domain == ("example.net", "management")
    assert found.lookup is False
    assert found.name_servers == [("192.0.2.53", "management"), ("192.0.2.54", "management")]
    assert found.context_name_servers == [("198.51.100.53", "management")]
    assert found.ntp_servers == [
        {"address": "192.0.2.123", "prefer": "prefer", "vrf": "management"},
        {"address": "192.0.2.124", "prefer": "", "vrf": "management"},
    ]
    assert found.logfile == ("6", "4194304")
    assert found.console == "off" and found.monitor == "3"
    assert found.timestamp == "milliseconds"
    assert found.log_servers == [{"address": "192.0.2.50", "level": "5", "vrf": "management"}]
    assert found.contact == "noc@example.net" and found.location == "Rack 4, room 2"
    assert found.communities == [
        ("Scrubbed-Ro-1", "network-operator"),
        ("Scrubbed-Rw-1", "network-admin"),
    ]
    assert found.trap_hosts == {"192.0.2.162": {"kind": "traps, version 2c", "vrf": "management"}}


def test_banner_over_several_lines() -> None:
    found = parse_admin_config("banner motd ^Line one\nLine two\n^\nhostname x\n")
    assert found.banner == "Line one\nLine two"
    assert found.hostname == "x"


def test_defaults_when_nothing_is_set() -> None:
    found = parse_admin_config("hostname x\n")
    assert found.banner is None and found.lookup is True and found.console is None
    view = parse_switch_admin([{"hostname": "x"}, {}], {}, "hostname x\n")
    facts = dict(view.of("system")[0].facts)
    assert facts["Time zone"] == "UTC"
    assert facts["Console logging"] == "level 2 (default)"
    assert facts["Login banner"] == "the switch's own"


def test_ntp_status_and_clock() -> None:
    peers = parse_ntp_status(load_fixture("show_ntp_peer-status_doc"))
    assert [(p.address, p.synced, p.vrf) for p in peers] == [
        ("192.0.2.123", True, "management"),
        ("192.0.2.124", False, "management"),
    ]
    assert clock_text(load_fixture("show_clock_doc")) == (
        "18:42:07.512 UTC Sat Oct 31 2026",
        "NTP",
    )
    assert clock_text({}) == ("unknown", "")


def test_page_masks_communities() -> None:
    view = parse_switch_admin(
        [{"hostname": "nexus-lab"}, load_fixture("show_clock_doc")],
        load_fixture("show_ntp_peer-status_doc"),
        _config(),
    )
    shown = repr(view)
    assert "Scrubbed-Ro-1" not in shown and "Scrubbed-Trap-1" not in shown
    (table,) = view.tables
    assert table.rows == (
        ("*** (hidden)", "read-only (network-operator)"),
        ("*** (hidden)", "read-write (network-admin)"),
    )
    ntp = view.of("ntp")
    assert ntp[0].values == {"server": {"prefer": "prefer", "vrf": "management"}}


def test_page_without_the_configuration() -> None:
    view = parse_switch_admin(
        [{"hostname": "nexus-lab"}, {}], load_fixture("show_ntp_peer-status_doc"), None
    )
    assert [i.title for i in view.of("ntp")] == ["192.0.2.123", "192.0.2.124"]
    assert view.of("dns") == [] and view.tables == ()
    assert any("does not let it read" in n for n in view.notes)


@pytest.mark.parametrize(
    ("scope", "setting", "action", "ident", "values", "lines"),
    [
        ("system", "hostname", "set", {}, {"name": "core-1"}, ["hostname core-1"]),
        ("system", "banner", "remove", {}, {}, ["no banner motd"]),
        (
            "system",
            "timezone",
            "set",
            {},
            {"zone": "EST", "hours": "-5", "minutes": "0"},
            ["clock timezone EST -5 0"],
        ),
        (
            "system",
            "summer_time",
            "set",
            {},
            {
                "zone": "EDT",
                "start_week": "2",
                "start_day": "Sunday",
                "start_month": "March",
                "start_time": "2:00",
                "end_week": "1",
                "end_day": "Sunday",
                "end_month": "November",
                "end_time": "02:00",
                "offset": "60",
            },
            ["clock summer-time EDT 2 Sunday March 02:00 1 Sunday November 02:00 60"],
        ),
        (
            "system",
            "domain",
            "set",
            {},
            {"domain": "Example.NET", "vrf": "management"},
            ["ip domain-name example.net use-vrf management"],
        ),
        ("system", "lookup", "remove", {}, {}, ["no ip domain-lookup"]),
        (
            "system",
            "logfile",
            "set",
            {},
            {"level": "6", "size": ""},
            ["logging logfile messages 6"],
        ),
        ("system", "console", "remove", {}, {}, ["no logging console"]),
        ("system", "contact", "remove", {}, {}, ["no snmp-server contact"]),
        (
            "ntp",
            "server",
            "set",
            {"address": "ntp.example.net"},
            {"prefer": "", "vrf": "default"},
            ["ntp server ntp.example.net"],
        ),
        ("ntp", "", "delete", {"address": "192.0.2.123"}, {}, ["no ntp server 192.0.2.123"]),
        (
            "dns",
            "server",
            "set",
            {"address": "192.0.2.53", "vrf": "management"},
            {},
            ["ip name-server 192.0.2.53 use-vrf management"],
        ),
        (
            "dns",
            "",
            "delete",
            {"address": "192.0.2.53", "vrf": "default"},
            {},
            ["no ip name-server 192.0.2.53"],
        ),
        (
            "logging",
            "server",
            "set",
            {"address": "192.0.2.50"},
            {"level": "4", "vrf": "management"},
            ["logging server 192.0.2.50 4 use-vrf management"],
        ),
        (
            "snmp_host",
            "vrf",
            "set",
            {"address": "192.0.2.162"},
            {"vrf": "management"},
            ["snmp-server host 192.0.2.162 use-vrf management"],
        ),
    ],
)
def test_change_lines(scope, setting, action, ident, values, lines) -> None:
    assert _lines(scope, setting, action, ident, **values) == lines


def test_community_is_masked_in_the_labels() -> None:
    change = build_admin_change("system", "community", "set", {}, {"community": "Secret-1"})
    assert change.lines == ("snmp-server community Secret-1 group network-operator",)
    assert change.labels == ("snmp-server community *** group network-operator",)
    assert "Secret-1" not in change.describe


@pytest.mark.parametrize(
    ("scope", "setting", "values", "message"),
    [
        ("system", "hostname", {"name": "core 1"}, "Hostname is 1 to 63"),
        ("system", "banner", {"text": "a # b"}, 'cannot contain "#"'),
        ("system", "banner", {"text": "a ; b"}, 'cannot contain ";"'),
        ("system", "timezone", {"zone": "EST", "hours": "-24", "minutes": "0"}, "one of"),
        (
            "system",
            "clock_set",
            {"time": "25:00:00", "day": "1", "month": "May", "year": "2026"},
            "a time of day",
        ),  # fmt: skip
        ("system", "domain", {"domain": "not a domain", "vrf": "default"}, "a domain name"),
        ("system", "logfile", {"level": "8", "size": ""}, "one of"),
        ("system", "community", {"community": "has space"}, "without spaces"),
        ("snmp_host", "vrf", {"vrf": "default"}, "pick the VRF"),
    ],
)
def test_bad_values_are_refused(scope, setting, values, message) -> None:
    ident = {"address": "192.0.2.162"} if scope == "snmp_host" else {}
    with pytest.raises(ValueError, match=message):
        build_admin_change(scope, setting, "set", ident, values)


def test_removing_the_hostname_or_log_file_is_refused() -> None:
    for setting in ("hostname", "logfile", "clock_set"):
        with pytest.raises(ValueError, match="cannot be removed"):
            build_admin_change("system", setting, "remove", {}, {})


def test_clock_set_is_not_configuration() -> None:
    change = build_admin_change(
        "system", "clock_set", "set", {},
        {"time": "14:30:00", "day": "31", "month": "October", "year": "2026"},
    )  # fmt: skip
    assert change.lines == ("clock set 14:30:00 31 October 2026",)
    assert change.config is False
    assert build_admin_change("system", "hostname", "set", {}, {"name": "x"}).config is True


@pytest.mark.parametrize(
    ("kind", "raw", "expected"),
    [
        ("host", "192.0.2.1", "192.0.2.1"),
        ("host", "NTP.Example.net", "ntp.example.net"),
        ("usevrf", "default", ""),
        ("usevrf", "management", "management"),
        ("usevrf", "lab", "lab"),
        ("hhmm", "2:00", "02:00"),
        ("hhmmss", "23:59:59", "23:59:59"),
    ],
)
def test_new_field_kinds(kind: str, raw: str, expected: str) -> None:
    assert check_value(Field("f", "F", kind), raw) == expected


@pytest.mark.parametrize(
    ("kind", "raw"),
    [
        ("host", "127.0.0.1"),
        ("host", "-bad.example"),
        ("host", "1.2.3"),
        ("domain", "a..b"),
        ("usevrf", "all"),
        ("hhmm", "24:00"),
        ("hhmmss", "12:00"),
    ],
)
def test_new_field_kinds_refuse(kind: str, raw: str) -> None:
    with pytest.raises(ValueError):
        check_value(Field("f", "F", kind), raw)


def test_role_has_the_admin_rules_and_no_wide_snmp_rule() -> None:
    lines = role_lines(["Ethernet1/1"], "nxray")
    for rule in ADMIN_RULES:
        assert rule in lines
    snmp = [r for r in ADMIN_RULES if "snmp-server" in r]
    # Never a rule that would let the account make SNMP users or read-write communities.
    adding = [r for r in snmp if " ; no " not in r]
    assert not any(r.endswith(("snmp-server *", "snmp-server community *")) for r in adding)
    assert not any("snmp-server user" in r for r in ADMIN_RULES)


def test_log() -> None:
    output = (FIXTURES / "show_logging_last_doc.txt").read_text()
    lines = parse_log(output)
    assert len(lines) == 5 and "Authentication failed" in lines[0].text
    assert [line.severity for line in lines] == [3, 2, 5, 5, 5]
    assert [line.severity for line in parse_log(output, worst=3)] == [3, 2]
    assert len(parse_log(output, search="ETHERNET1/7")) == 2
    assert parse_log("\n2026 header\n", worst=7) == []
    assert log_command(50) == "show logging last 50"
    with pytest.raises(ValueError):
        log_command(5)
