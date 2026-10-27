"""The dashboard with a connected switch, against a pretend switch."""

from __future__ import annotations

import copy
import re

import pytest
from fastapi.testclient import TestClient

from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', logged_in.get("/switch").text)
    assert csrf
    response = logged_in.post(
        "/switch/setup",
        data={
            "csrf": csrf.group(1),
            "host": "192.0.2.10",
            "port": "443",
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "account_name": "nxray",
            "confirm_save": "yes",
        },
    )
    assert "NXray created the account" in response.text
    fake.requests.clear()
    return fake


def _environment(**sensor_changes: dict[str, str]) -> dict:
    body = copy.deepcopy(load_fixture("show_environment"))
    for row in body["TABLE_tempinfo"]["ROW_tempinfo"]:
        row.update(sensor_changes.get(row["sensor"], {}))
    return body


def _text(html: str) -> str:
    """The page as visible text, one space between words."""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def test_everything_comes_from_one_request_with_the_nxray_account(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    assert logged_in.get("/").status_code == 200
    assert switch.requests == [
        ["show version", "show environment", "show system resources", "show interface brief"]
    ]


def test_dashboard_shows_the_recorded_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    text = _text(logged_in.get("/").text)
    assert "Connected to nexus-lab as nxray." in text
    assert "Temperatures, fans and power supplies are all OK." in text
    # Switch
    assert "Nexus9000 C92160YC-X chassis" in text
    assert "9.3(16)" in text and "23 minutes" in text
    assert "Module PowerCycled" in text
    # Temperatures: sensor, now, minor, major
    assert "Intake 30°C 80°C 90°C OK" in text
    assert "Davos 57°C 90°C 110°C OK" in text
    # Fans
    assert "Fan speed: 50%" in text
    assert "Fan1(sys_fan1) NXA-FAN-30CFM-F back-to-front OK" in text
    # Power
    assert "1 NXA-PAC-650W-PE 43 W 24 W 650 W OK" in text
    assert "Total draw 126 W" in text
    assert "Mode PS-Redundant" in text
    # CPU, memory, ports
    assert "10.3%" in text and "40.5%" in text
    assert "Ethernet ports 54" in text
    assert "No transceiver 54" in text
    assert "Needs attention" not in text


def test_hot_sensors_are_flagged(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.bodies["show environment"] = _environment(
        Exhaust={"curtemp": "55"},  # minor 50
        CPU={"curtemp": "101", "alarmstatus": "Major Alarm"},  # major 100
    )
    html = logged_in.get("/").text
    text = _text(html)
    assert "Needs attention" in text
    assert "Temperature Exhaust is 55°C, at or above its minor limit of 50°C." in text
    assert "Temperature CPU is 101°C, at or above its major limit of 100°C." in text
    assert "all OK" not in text
    assert 'badge badge-warn">Above minor' in html
    assert 'badge badge-crit">Above major' in html


def test_a_failed_power_supply_and_fan_are_flagged(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    body = load_fixture("show_environment")
    body["powersup"]["TABLE_psinfo"]["ROW_psinfo"][1]["ps_status"] = "Fail/Shutdown"
    body["fandetails"]["TABLE_faninfo"]["ROW_faninfo"][2]["fanstatus"] = "Failure"
    switch.bodies["show environment"] = body
    text = _text(logged_in.get("/").text)
    assert "Power supply 2 reports Fail/Shutdown." in text
    assert "Fan Fan3(sys_fan3) reports Failure." in text
    assert "650 W Fail/Shutdown" in text  # the switch's own word when not OK


def test_missing_sections_do_not_break_the_page(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.bodies["show environment"] = {}
    switch.bodies["show system resources"] = {}
    response = logged_in.get("/")
    assert response.status_code == 200
    text = _text(response.text)
    assert "The switch reported no temperature sensors." in text
    assert "The switch reported no fans." in text
    assert "The switch reported no power supplies." in text
    assert "CPU now unknown" in text


def test_a_rejected_show_command_is_reported(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.reject = {"show environment"}
    text = _text(logged_in.get("/").text)
    assert "The switch refused a command" in text
    assert "Go to the Switch page" in text
