"""Parsers for NX-API show output, against output recorded from a real switch.

The fixtures are `show ... | json` from an N9K-C92160YC-X on NX-OS 9.3(16),
with serial numbers, the hostname and the management address replaced.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from app.nxapi import NxapiClient, SwitchTarget
from app.switch import (
    DASHBOARD_COMMANDS,
    Dashboard,
    TempSensor,
    fan_speed_percent,
    health_problems,
    load_dashboard,
    parse_environment,
    parse_port_summary,
    parse_resources,
    parse_version,
    rows,
    section,
    to_int,
)
from tests.conftest import load_fixture


def test_rows_handles_one_row_many_rows_and_none() -> None:
    one = {"TABLE_x": {"ROW_x": {"a": 1}}}
    many = {"TABLE_x": {"ROW_x": [{"a": 1}, {"a": 2}, "junk"]}}
    assert rows(one, "TABLE_x", "ROW_x") == [{"a": 1}]
    assert rows(many, "TABLE_x", "ROW_x") == [{"a": 1}, {"a": 2}]
    assert rows({}, "TABLE_x", "ROW_x") == []
    assert rows({"TABLE_x": "text"}, "TABLE_x", "ROW_x") == []


def test_section() -> None:
    assert section({"a": {"b": 1}}, "a") == {"b": 1}
    assert section({"a": "text"}, "a") == {}
    assert section({}, "a") == {}


def test_to_int() -> None:
    assert to_int("27") == 27
    assert to_int("650 W") == 650
    assert to_int("126.00 W") == 126
    assert to_int("N/A") is None
    assert to_int(None) is None


def test_fan_speed_percent() -> None:
    assert fan_speed_percent("0x80") == 50
    assert fan_speed_percent("0xff") == 100
    assert fan_speed_percent("fast") is None
    assert fan_speed_percent(None) is None


def test_parse_version() -> None:
    info = parse_version(load_fixture("show_version"))
    assert info.hostname == "nexus-lab"
    assert info.model == "Nexus9000 C92160YC-X chassis"
    assert info.nxos_version == "9.3(16)"
    assert info.uptime == "23 minutes"
    assert info.last_reset_reason == "Module PowerCycled"


def test_uptime_wording() -> None:
    body = {"kern_uptm_days": "1", "kern_uptm_hrs": "0", "kern_uptm_mins": "1"}
    assert parse_version(body).uptime == "1 day, 0 hours, 1 minute"
    body = {"kern_uptm_days": "3", "kern_uptm_hrs": "2", "kern_uptm_mins": "5"}
    assert parse_version(body).uptime == "3 days, 2 hours, 5 minutes"


def test_parse_version_of_an_empty_body() -> None:
    info = parse_version({})
    assert info.hostname == "unknown"
    assert info.uptime == "0 minutes"


def test_parse_environment() -> None:
    env = parse_environment(load_fixture("show_environment"))

    assert [(t.name, t.current_c, t.minor_c, t.major_c) for t in env.temperatures] == [
        ("Intake", 30, 80, 90),
        ("Exhaust", 31, 50, 70),
        ("CPU", 47, 90, 100),
        ("Davos", 57, 90, 110),
    ]
    assert all(t.level == "ok" for t in env.temperatures)

    assert len(env.fans) == 6
    assert all(fan.ok for fan in env.fans)
    assert env.fans[0].direction == "back-to-front"
    # The recorded fan zone table has one row, held as an object: the quirk.
    assert env.fan_speed_percent == 50

    assert [(p.number, p.input_w, p.output_w, p.capacity_w) for p in env.power_supplies] == [
        ("1", 43, 24, 650),
        ("2", 83, 66, 650),
    ]
    assert all(p.ok for p in env.power_supplies)
    assert env.redundancy_mode == "PS-Redundant"
    assert env.total_draw_w == 126


def test_parse_environment_of_an_empty_body() -> None:
    env = parse_environment({})
    assert env.temperatures == [] and env.fans == [] and env.power_supplies == []
    assert env.fan_speed_percent is None
    assert env.total_draw_w is None


def _sensor(current: int | None, status: str = "Ok") -> TempSensor:
    return TempSensor(
        module="1", name="x", current_c=current, minor_c=50, major_c=70, status=status
    )


def test_temperature_levels() -> None:
    assert _sensor(49).level == "ok"
    assert _sensor(50).level == "warn"
    assert _sensor(70).level == "crit"
    assert _sensor(None).level == "unknown"
    # The switch's own alarm wins over the numbers.
    assert _sensor(30, "Minor Alarm").level == "warn"
    assert _sensor(30, "Major Alarm").level == "crit"


def test_parse_resources() -> None:
    res = parse_resources(load_fixture("show_system_resources"))
    assert res.cpu_used_percent == 10.3
    assert res.memory_used_percent == 40.5
    assert res.load_1min == "0.62"
    empty = parse_resources({})
    assert empty.cpu_used_percent is None and empty.memory_used_percent is None


def test_parse_port_summary_counts_front_panel_ports_only() -> None:
    ports = parse_port_summary(load_fixture("show_interface_brief"))
    # 54 Ethernet ports; mgmt0 is left out. Nothing was plugged in when the
    # output was recorded.
    assert ports.total == 54
    assert ports.up == 0
    assert ports.down == 54
    assert ports.no_transceiver == 54


def test_load_dashboard_uses_one_request() -> None:
    fixtures = {
        "show version": load_fixture("show_version"),
        "show environment": load_fixture("show_environment"),
        "show system resources": load_fixture("show_system_resources"),
        "show interface brief": load_fixture("show_interface_brief"),
    }
    requests: list[list[dict[str, Any]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        entries = json.loads(request.content)
        requests.append(entries)
        reply = [
            {"jsonrpc": "2.0", "result": {"body": fixtures[e["params"]["cmd"]]}, "id": e["id"]}
            for e in entries
        ]
        return httpx.Response(200, json=reply)

    target = SwitchTarget(host="192.0.2.10", port=443, username="u", password="p", timeout=5)
    with NxapiClient(target, transport=httpx.MockTransport(handler)) as client:
        dash = load_dashboard(client)

    assert len(requests) == 1
    assert [e["params"]["cmd"] for e in requests[0]] == list(DASHBOARD_COMMANDS)
    assert dash.system.hostname == "nexus-lab"
    assert dash.environment.total_draw_w == 126
    assert dash.ports.total == 54


def _dashboard_with(environment: dict[str, Any]):
    return Dashboard(
        system=parse_version(load_fixture("show_version")),
        environment=parse_environment(environment),
        resources=parse_resources(load_fixture("show_system_resources")),
        ports=parse_port_summary(load_fixture("show_interface_brief")),
    )


def test_health_problems_is_empty_for_the_recorded_switch() -> None:
    assert health_problems(_dashboard_with(load_fixture("show_environment"))) == []


def test_health_problems_names_each_problem() -> None:
    body = load_fixture("show_environment")
    body["TABLE_tempinfo"]["ROW_tempinfo"][0]["curtemp"] = "85"  # Intake, minor 80
    body["TABLE_tempinfo"]["ROW_tempinfo"][1]["curtemp"] = "70"  # Exhaust, major 70
    body["fandetails"]["TABLE_faninfo"]["ROW_faninfo"][0]["fanstatus"] = "Absent"
    body["powersup"]["TABLE_psinfo"]["ROW_psinfo"][0]["ps_status"] = ""
    assert health_problems(_dashboard_with(body)) == [
        "Temperature Intake is 85°C, at or above its minor limit of 80°C.",
        "Temperature Exhaust is 70°C, at or above its major limit of 70°C.",
        "Fan Fan1(sys_fan1) reports Absent.",
        "Power supply 1 reports no status.",
    ]
