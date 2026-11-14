"""The Telemetry page, end to end against the fake switch: reading it with the feature
off and on, who may change it, changes from asking to sent, and the parsers and checks on
their own."""

from __future__ import annotations

import html
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.protocols import Field, check_value
from app.telemetry import build_telemetry_change, parse_telemetry_config, parse_telemetry_view
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

COMMANDS = (
    "show telemetry transport",
    "show telemetry control database sensor-groups",
    "show telemetry data collector brief",
)


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _db(settings: Settings, sql: str) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(sql)
    conn.commit()
    conn.close()


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


def _setup_form(client: TestClient, **extra: str) -> dict[str, str]:
    return {
        "csrf": _csrf(client, "/switch"),
        "host": "192.0.2.10",
        "port": "443",
        "admin_user": "admin",
        "admin_password": ADMIN_PASSWORD,
        "account_name": "nxray",
        "confirm_save": "yes",
        **extra,
    }


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    """A switch that has been set up (read-only account nxray), telemetry off."""
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post("/switch/setup", data=_setup_form(logged_in))
    fake.requests.clear()
    return fake


@pytest.fixture
def on(switch: FakeSwitch) -> FakeSwitch:
    """telemetry on with one group of each kind, answering as recorded on cisco-25gb."""
    switch.feature_state["telemetry"] = True
    for cmd in COMMANDS:
        switch.bodies[cmd] = load_fixture(cmd.replace(" ", "_").replace("-", "_"))
    switch.telemetry_parts.update(
        {
            "destination-profile": ["use-vrf management", "use-compression gzip"],
            "destination-group 250": [
                "ip address 192.0.2.80 port 50001 protocol gRPC encoding GPB",
                "ip address 192.0.2.81 port 50002 protocol HTTP encoding JSON",
            ],
            "sensor-group 250": ["data-source DME", "path sys/intf depth 0"],
            "subscription 250": ["dst-grp 250", "snsr-grp 250 sample-interval 30000"],
        }
    )
    return switch


@pytest.fixture
def enabled(logged_in: TestClient, on: FakeSwitch, settings: Settings) -> FakeSwitch:
    """Changes on with the broad role, and the wait over."""
    response = logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "role_mode": "broad",
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    on.requests.clear()
    on.saved = False
    return on


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/telemetry/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/telemetry", follow_redirects=False).status_code == 303


def test_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/telemetry").text)


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/telemetry"' in logged_in.get("/").text


def test_with_the_feature_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/telemetry")
    assert page.status_code == 200
    assert "off on the switch, so Telemetry is not running" in _text(page.text)
    assert switch.requests == [["show feature", "show vrf"]]


def test_feature_off_links_to_its_row_on_the_features_page(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    assert 'href="/features#feature-telemetry"' in logged_in.get("/telemetry").text


def test_page_reads_the_switch(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/telemetry")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "Destination group 250" in text and "Sensor group 250" in text
    assert "Connected" in text  # the gRPC collector's state
    assert "250 every 30000 ms" in text
    assert "sys/intf depth 0" in text
    assert enabled.requests == [
        ["show feature", "show vrf"],
        list(COMMANDS),
        ["show running-config"],
    ]


def test_without_the_configuration_text_the_collectors_still_show(
    logged_in: TestClient, on: FakeSwitch
) -> None:
    page = logged_in.get("/telemetry").text
    text = _text(page)
    assert "192.0.2.80" in text and "Connected" in text and "Running" in text
    assert "did not show the telemetry settings" in text
    assert "/telemetry/change" not in page  # changes are off


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "telemetry"})
    assert saved.status_code == 200
    assert "collector" in _text(saved.text) and enabled.saved


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, on: FakeSwitch, settings: Settings
) -> None:
    logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    on.requests.clear()
    assert "Telemetry changes are off" in _text(logged_in.get("/telemetry").text)
    refused = _change(logged_in, scope="subscription", action="create", id_subscription="7")
    assert refused.status_code == 400
    assert _config_requests(on) == []


def test_a_collector_asks_first_then_sends(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {
        "scope": "destination",
        "setting": "ipv4",
        "action": "set",
        "id_group": "250",
        "v_address": "192.0.2.82",
        "v_port": "50003",
        "v_protocol": "UDP",
        "v_encoding": "GPB",
    }
    line = "ip address 192.0.2.82 port 50003 protocol UDP encoding GPB"
    asked = _change(logged_in, confirm=False, **fields)
    assert asked.status_code == 200
    assert line in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["telemetry", "destination-group 250", line]]
    assert line in enabled.telemetry_parts["destination-group 250"]


def test_a_protocol_with_the_wrong_encoding_is_refused(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    refused = _change(
        logged_in,
        scope="destination",
        setting="ipv4",
        action="set",
        id_group="250",
        v_address="192.0.2.82",
        v_port="50003",
        v_protocol="HTTP",
        v_encoding="GPB",
    )
    assert refused.status_code == 400
    assert "HTTP carries JSON only" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_removing_a_collector_needs_only_its_address_and_port(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    done = _change(
        logged_in,
        scope="destination",
        setting="ipv4",
        action="remove",
        id_group="250",
        v_address="192.0.2.81",
        v_port="50002",
    )
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [
        ["telemetry", "destination-group 250", "no ip address 192.0.2.81 port 50002"]
    ]
    assert len(enabled.telemetry_parts["destination-group 250"]) == 1


def test_a_subscription_is_made_and_deleted(logged_in: TestClient, enabled: FakeSwitch) -> None:
    made = _change(logged_in, scope="subscription", action="create", id_subscription="7")
    assert made.status_code == 200, _text(made.text)
    assert "subscription 7" in enabled.telemetry_parts
    gone = _change(logged_in, scope="subscription", action="delete", id_subscription="7")
    assert gone.status_code == 200, _text(gone.text)
    assert _config_requests(enabled)[-1] == ["telemetry", "no subscription 7"]
    assert "subscription 7" not in enabled.telemetry_parts


def test_a_sample_interval_under_a_second_is_refused(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    refused = _change(
        logged_in,
        scope="subscription",
        setting="snsr_grp",
        action="set",
        id_subscription="250",
        v_group="250",
        v_ms="500",
    )
    assert refused.status_code == 400
    assert _config_requests(enabled) == []


def test_a_show_command_path_cannot_redirect_or_pipe(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    for command in ("show version > bootflash:x", "show version | grep x", "conf t"):
        refused = _change(
            logged_in,
            scope="sensor",
            setting="show_path",
            action="set",
            id_group="250",
            v_command=command,
        )
        assert refused.status_code == 400, command
    assert _config_requests(enabled) == []
    done = _change(
        logged_in,
        scope="sensor",
        setting="show_path",
        action="set",
        id_group="251",
        v_command="show version",
    )
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["telemetry", "sensor-group 251", 'path "show version"']]


def test_the_profile_vrf_refuses_default(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _change(logged_in, scope="profile", setting="use_vrf", action="set", v_vrf="default")
    assert refused.status_code == 400
    assert _config_requests(enabled) == []


# ---- the parts on their own ----------------------------------------------------------


CONFIG = """!Command: show running-config
feature telemetry
telemetry
  destination-profile
    use-vrf management
    use-retry size 20
  destination-group 1
    ipv6 address 2001:db8::80 port 50004 protocol gRPC encoding GPB
  sensor-group 2
    data-source NX-API
    path "show version"
  subscription 3
    dst-grp 1
    snsr-grp 2 sample-interval 0
interface Ethernet1/1
  description not telemetry
"""


def test_the_configuration_text_is_split_by_part() -> None:
    found = parse_telemetry_config(CONFIG)
    assert found.profile == ["use-vrf management", "use-retry size 20"]
    assert found.destinations == {
        "1": ["ipv6 address 2001:db8::80 port 50004 protocol gRPC encoding GPB"]
    }
    assert found.sensors == {"2": ["data-source NX-API", 'path "show version"']}
    assert found.subscriptions == {"3": ["dst-grp 1", "snsr-grp 2 sample-interval 0"]}


def test_the_view_fills_the_forms_and_says_on_change() -> None:
    view = parse_telemetry_view({}, {}, {}, CONFIG)
    profile = view.of("profile")[0]
    assert profile.values["use_vrf"] == {"vrf": "management"}
    assert profile.values["retry"] == {"mb": "20"}
    (group,) = view.of("destination")
    assert group.values["ipv6"]["port"] == "50004"
    (subscription,) = view.of("subscription")
    assert ("Sensor groups", "2 on change") in subscription.facts


def test_a_path_with_its_options() -> None:
    change = build_telemetry_change(
        "sensor",
        "path",
        "set",
        {"group": "2"},
        {"path": "sys/ch", "depth": "1", "query": "", "filter": 'eq(eqptCh.operSt,"online")'},
    )
    assert change.lines == (
        "telemetry",
        "sensor-group 2",
        'path sys/ch depth 1 filter-condition eq(eqptCh.operSt,"online")',
    )


def test_a_telemetry_path_has_no_spaces_or_leading_quote() -> None:
    spec = Field("path", "Path", "telpath")
    assert check_value(spec, "sys/intf") == "sys/intf"
    for bad in ("sys/intf depth 0", '"show version"', "sys;intf"):
        with pytest.raises(ValueError):
            check_value(spec, bad)
