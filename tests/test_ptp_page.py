"""The PTP page, end to end against the fake switch: reading it with the feature off and
on, who may change it, changes from asking to sent, and the parsers on their own."""

from __future__ import annotations

import html
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.ptp import build_ptp_change, parse_ptp_config, parse_ptp_view
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

COMMANDS = (
    "show ptp clock",
    "show ptp parent",
    "show ptp time-property",
    "show ptp brief",
    "show ptp counters all",
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
    """A switch that has been set up (read-only account nxray), ptp off."""
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post("/switch/setup", data=_setup_form(logged_in))
    fake.requests.clear()
    return fake


@pytest.fixture
def on(switch: FakeSwitch) -> FakeSwitch:
    """ptp on, with a source address and one port, answering as recorded on cisco-25gb."""
    switch.feature_state["ptp"] = True
    for cmd in COMMANDS:
        switch.bodies[cmd] = load_fixture(cmd.replace(" ", "_").replace("-", "_"))
    switch.ptp_lines[:] = [
        "ptp source 192.0.2.1",
        "ptp domain 5",
        "ptp priority1 100",
        "ptp notification type high-correction interval 30",
        "interface Ethernet1/5 ; ptp",
        "interface Ethernet1/5 ; ptp transmission unicast",
        "interface Ethernet1/5 ; ptp role master",
        "interface Ethernet1/5 ; ptp slave 192.0.2.75",
        "interface Ethernet1/5 ; ptp vlan 250",
    ]
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
    return client.post("/ptp/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/ptp", follow_redirects=False).status_code == 303


def test_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/ptp").text)


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/ptp"' in logged_in.get("/").text


def test_with_the_feature_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/ptp")
    assert page.status_code == 200
    assert "off on the switch, so PTP is not running" in _text(page.text)
    assert switch.requests == [["show feature", "show interface brief", "show vrf"]]


def test_page_reads_the_switch(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/ptp")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "Free-Run" in text and "boundary clock" in text and "this switch" in text
    assert "192.0.2.75" in text  # the port's unicast slave
    assert "12 / 0" in text  # announce messages sent / received
    assert enabled.requests == [
        ["show feature", "show interface brief", "show vrf"],
        list(COMMANDS),
        ["show running-config"],
    ]


def test_without_the_configuration_text_the_clock_still_shows(
    logged_in: TestClient, on: FakeSwitch
) -> None:
    page = logged_in.get("/ptp").text
    text = _text(page)
    assert "Free-Run" in text and "12 / 0" in text
    assert "did not show the PTP settings" in text
    assert "/ptp/change" not in page  # changes are off


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "ptp"})
    assert saved.status_code == 200
    assert "grandmaster" in _text(saved.text) and enabled.saved


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
    assert "PTP changes are off" in _text(logged_in.get("/ptp").text)
    refused = _change(logged_in, scope="ptp_switch", setting="domain", action="set", v_domain="7")
    assert refused.status_code == 400
    assert _config_requests(on) == []


def test_enabled_page_offers_the_settings_with_their_values(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    page = logged_in.get("/ptp").text
    for setting in ("source", "domain", "priority1", "ptp", "role", "sync_interval", "slave"):
        assert f'name="setting" value="{setting}"' in page
    assert 'value="192.0.2.1"' in page  # the source address, filled in
    assert '<option value="Ethernet1/1"' in page
    assert '<option value="port-channel' not in page


def test_the_domain_asks_first_then_replaces(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {"scope": "ptp_switch", "setting": "domain", "action": "set", "v_domain": "7"}
    asked = _change(logged_in, confirm=False, **fields)
    assert asked.status_code == 200
    assert "ptp domain 7" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["ptp domain 7"]]
    assert "ptp domain 7" in enabled.ptp_lines and "ptp domain 5" not in enabled.ptp_lines


def test_a_port_turns_ptp_on(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(logged_in, scope="ptp_port", setting="ptp", action="set", id_port="Ethernet1/6")
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["interface Ethernet1/6", "ptp"]]
    assert "interface Ethernet1/6 ; ptp" in enabled.ptp_lines


def test_a_negative_sync_interval(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(
        logged_in,
        scope="ptp_port",
        setting="sync_interval",
        action="set",
        id_port="Ethernet1/5",
        v_log="-3",
    )
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["interface Ethernet1/5", "ptp sync interval -3"]]


def test_removing_ptp_from_a_port_clears_its_lines(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    done = _change(
        logged_in, scope="ptp_port", setting="ptp", action="remove", id_port="Ethernet1/5"
    )
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["interface Ethernet1/5", "no ptp"]]
    assert not any(line.startswith("interface Ethernet1/5") for line in enabled.ptp_lines)


def test_the_switch_refuses_removing_the_source_while_a_port_runs_ptp(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    refused = _change(
        logged_in, scope="ptp_switch", setting="source", action="remove", v_address="192.0.2.1"
    )
    assert refused.status_code == 400
    assert "There are still interfaces with PTP enabled" in _text(refused.text)
    assert "ptp source 192.0.2.1" in enabled.ptp_lines


def test_a_port_channel_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _change(
        logged_in, scope="ptp_port", setting="ptp", action="set", id_port="port-channel20"
    )
    assert refused.status_code == 400
    assert _config_requests(enabled) == []


def test_out_of_range_values_never_reach_the_switch(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    for fields in (
        {"scope": "ptp_switch", "setting": "domain", "v_domain": "128"},
        {
            "scope": "ptp_port",
            "setting": "announce_timeout",
            "id_port": "Ethernet1/5",
            "v_count": "5",
        },
        {"scope": "ptp_switch", "setting": "source", "v_address": "2001:db8::1"},
    ):
        assert _change(logged_in, action="set", **fields).status_code == 400
    assert _config_requests(enabled) == []


# ---- the parts on their own ----------------------------------------------------------


CONFIG = """!Command: show running-config
feature ptp
ptp source 192.0.2.1 vrf management
ptp domain 5
ptp correction-range 200000
ptp correction-range logging
ptp notification type port-state-change category master-slave-only interval immediate
no ptp management
interface Ethernet1/5
  description to the grandmaster
  ptp
  ptp vlan 250
interface Ethernet1/6
  switchport
"""


def test_the_configuration_text_is_split_by_place() -> None:
    found = parse_ptp_config(CONFIG)
    assert found.switch[0] == "ptp source 192.0.2.1 vrf management"
    assert found.ports == {"Ethernet1/5": ["ptp", "ptp vlan 250"]}


def test_the_forms_start_with_what_is_set() -> None:
    view = parse_ptp_view({}, {}, {}, {}, {}, CONFIG)
    clock = view.of("ptp_switch")[0]
    assert clock.values["source"] == {"address": "192.0.2.1", "vrf": "management"}
    assert clock.values["correction_range"] == {"ns": "200000"}
    assert "correction_logging" in clock.values
    assert "management" not in clock.values  # turned off
    assert clock.values["notify_port_now"] == {"category": "master-slave-only"}
    (port,) = view.of("ptp_port")
    assert port.ident == {"port": "Ethernet1/5"}
    assert port.values["vlan"] == {"vlan": "250"}


def test_a_notification_line_carries_its_timing() -> None:
    now = build_ptp_change("ptp_switch", "notify_correction_now", "set", {}, {})
    assert now.lines == ("ptp notification type high-correction interval immediate",)
    every = build_ptp_change(
        "ptp_switch",
        "notify_port_every",
        "set",
        {},
        {"category": "all", "seconds": "30"},
    )
    assert every.lines == ("ptp notification type port-state-change category all interval 30",)
    gone = build_ptp_change("ptp_switch", "notify_port_every", "remove", {}, {})
    assert gone.lines == ("no ptp notification type port-state-change",)


def test_no_forms_name_their_value() -> None:
    change = build_ptp_change(
        "ptp_port", "vlan", "remove", {"port": "Ethernet1/5"}, {"vlan": "250"}
    )
    assert change.lines == ("interface Ethernet1/5", "no ptp vlan 250")
