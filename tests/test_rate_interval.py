"""How long a port averages its In and Out over (``load-interval counter 1``):
the checked values, the client's command, the role rules and the port page."""

from __future__ import annotations

import json
import re
import sqlite3
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.nxapi import LOAD_INTERVALS, NxapiClient, SwitchTarget
from app.port_changes import TRAFFIC_RULES, missing_changes, role_lines
from app.port_settings import load_interval_label, plan_load_interval
from app.ports import parse_ports
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

PORT = "Ethernet1/1"


def _recording() -> tuple[list[list[str]], NxapiClient]:
    sent: list[list[str]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        entries = json.loads(request.content)
        sent.append([entry["params"]["cmd"] for entry in entries])
        replies = [{"jsonrpc": "2.0", "result": None, "id": entry["id"]} for entry in entries]
        return httpx.Response(200, json=replies[0] if len(replies) == 1 else replies)

    target = SwitchTarget("192.0.2.10", 443, "nxray", "pw", 5.0)
    return sent, NxapiClient(target, transport=httpx.MockTransport(handle))


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).replace("&#39;", "'")


def _db(settings: Settings, sql: str) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(sql)
    conn.commit()
    conn.close()


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


@pytest.fixture
def enabled(logged_in: TestClient, settings: Settings) -> FakeSwitch:
    """A set-up switch with every change on and the wait over."""
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "host": "192.0.2.10",
            "port": "443",
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "account_name": "nxray",
            "confirm_save": "yes",
        },
    )
    response = logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    fake.requests.clear()
    fake.saved = False
    return fake


def _post(client: TestClient, confirm: bool = False, **fields: str):
    data = {"csrf": _csrf(client), "name": PORT, **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/ports/rate-interval", data=data)


# ---- what the switch reports, and the checked values ---------------------------


def test_ports_carry_the_switchs_rate_average() -> None:
    ports = parse_ports(
        load_fixture("show_interface"),
        load_fixture("show_interface_status"),
        load_fixture("show_interface_transceiver"),
    )
    assert ports and {port.load_interval for port in ports} == {30}


def test_labels() -> None:
    assert load_interval_label(30) == "30 seconds (the switch's default)"
    assert load_interval_label(5) == "5 seconds"
    assert load_interval_label(60) == "1 minute"
    assert load_interval_label(300) == "5 minutes"
    assert load_interval_label(0) == "unknown"


def test_plan_keeps_only_a_change() -> None:
    assert plan_load_interval(PORT, 30, "default").empty
    assert plan_load_interval(PORT, 10, "10").empty
    shorter = plan_load_interval(PORT, 30, "10")
    assert shorter.seconds == 10 and not shorter.empty
    assert shorter.lines == [
        f"Average {PORT}'s In and Out rates over 10 seconds, instead of 30 seconds "
        "(the switch's default)."
    ]
    assert "jump about more" in shorter.warnings[0]
    back = plan_load_interval(PORT, 10, "default")
    assert back.seconds is None and not back.empty and back.warnings == []


@pytest.mark.parametrize("choice", ["", "7", "301", "0", "-5", "30; shutdown", "１０"])
def test_plan_refuses_other_values(choice: str) -> None:
    with pytest.raises(ValueError, match="Pick how long"):
        plan_load_interval(PORT, 30, choice)


def test_client_sends_one_checked_line() -> None:
    sent, client = _recording()
    client.set_load_interval(PORT, 10)
    client.set_load_interval(PORT, None)
    assert sent == [
        [f"interface {PORT}", "load-interval counter 1 10"],
        [f"interface {PORT}", "no load-interval counter 1"],
    ]


@pytest.mark.parametrize("seconds", [0, 7, 301, True])
def test_client_refuses_other_values(seconds: int) -> None:
    sent, client = _recording()
    with pytest.raises(ValueError):
        client.set_load_interval(PORT, seconds)
    assert sent == []


def test_client_refuses_other_ports() -> None:
    sent, client = _recording()
    with pytest.raises(ValueError):
        client.set_load_interval("mgmt0", 10)
    assert sent == []
    assert 30 in LOAD_INTERVALS


# ---- the role ------------------------------------------------------------------


def test_role_has_the_traffic_rules() -> None:
    lines = role_lines([PORT], "nxray")
    for rule in TRAFFIC_RULES:
        assert rule in lines
    assert missing_changes(14) == "traffic measuring changes"


def test_role_version_14_turns_on_traffic_measuring_without_a_wait(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 14")
    page = _text(logged_in.get("/switch").text)
    assert "Turn on traffic measuring changes" in page
    enabled.ssh_lines.clear()
    response = logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )
    text = _text(response.text)
    assert "Traffic measuring changes are on: nxray may now also set how long" in text
    assert "there is no wait" in text
    assert "rule 228 permit command conf t ; interface * ; load-interval *" in enabled.ssh_lines


# ---- the port page -------------------------------------------------------------


def test_port_page_shows_the_average_and_the_form(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    page = logged_in.get(f"/ports/detail?name={PORT}").text
    text = _text(page)
    assert "In and Out averaged over 30 seconds (the switch's default)" in text
    assert 'action="/ports/rate-interval"' in page
    assert "the switch's average over the last 30 seconds" in text


def test_changing_the_average_asks_first_then_sends_it(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    asked = _post(logged_in, seconds="10")
    assert asked.status_code == 200
    assert "instead of 30 seconds" in _text(asked.text)
    assert _config_requests(enabled) == []

    done = _post(logged_in, confirm=True, seconds="10")
    assert done.status_code == 200
    text = _text(done.text)
    assert "Done: Average Ethernet1/1's In and Out rates over 10 seconds" in text
    assert _config_requests(enabled) == [[f"interface {PORT}", "load-interval counter 1 10"]]
    assert "In and Out averaged over 10 seconds" in text
    assert "the switch's average over the last 10 seconds" in text

    enabled.requests.clear()
    _post(logged_in, confirm=True, seconds="default")
    assert _config_requests(enabled) == [[f"interface {PORT}", "no load-interval counter 1"]]


def test_nothing_to_change_sends_nothing(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = _post(logged_in, confirm=True, seconds="default")
    assert "Nothing to change" in _text(response.text)
    assert _config_requests(enabled) == []


def test_a_bad_value_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = _post(logged_in, confirm=True, seconds="7")
    assert response.status_code == 400
    assert "Pick how long to average over" in _text(response.text)
    assert _config_requests(enabled) == []


def test_off_before_role_version_15(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 14")
    page = _text(logged_in.get(f"/ports/detail?name={PORT}").text)
    assert "Traffic measuring changes are off" in page
    response = _post(logged_in, confirm=True, seconds="10")
    assert response.status_code == 400
    assert _config_requests(enabled) == []


def test_needs_a_csrf_token(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = logged_in.post(
        "/ports/rate-interval", data={"csrf": "wrong", "name": PORT, "seconds": "10"}
    )
    assert response.status_code in (400, 403)
    assert _config_requests(enabled) == []


def test_the_side_panel_has_the_form_too(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get(f"/ports?port={PORT}").text
    assert 'action="/ports/rate-interval"' in page
    assert 'id="panel-rate-seconds"' in page or "rate-seconds" in page
