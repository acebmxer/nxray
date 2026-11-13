"""The Edge Virtual Bridging page (#95), end to end against the fake switch, and its
parsers."""

from __future__ import annotations

import html
import json
import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.evb import (
    build_evb_change,
    parse_evb,
    parse_evb_config,
    parse_hosts,
    parse_vsis,
    wait_time,
)
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"

# Recorded on cisco-25gb (NX-OS 9.3(16), 2026-11-13), EVB on with its defaults and no host.
STATE = json.loads((FIXTURES / "show_evb.json").read_text())
HOSTS_EMPTY = (FIXTURES / "show_evb_hosts.txt").read_text()
VSI_EMPTY = (FIXTURES / "show_evb_vsi.txt").read_text()
# The recorded headings with rows added (no server announced a VM on the probe switch).
HOSTS = HOSTS_EMPTY.rstrip() + (
    "\nesx-01          30001    100   4196  0050.5601.0001 192.0.2.31        Ethernet1/7\n"
)
VSI = VSI_EMPTY.rstrip() + (
    "\n1        0x1a2b         Eth1/7          4000          ASSOC    A       25/25\n"
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


def _lines(setting, action, values=None):
    return list(build_evb_change("global", setting, action, {}, values or {}).lines)


# ---- parsing and lines ----------------------------------------------------------------------


def test_the_wait_times_are_in_seconds():
    assert wait_time(25) == "25 (about 335 seconds)"
    assert wait_time("20") == "20 (about 10 seconds)"
    assert wait_time(None) == "-"


def test_the_recorded_tables_have_no_rows():
    assert parse_hosts(HOSTS_EMPTY) == [] and parse_vsis(VSI_EMPTY) == []


def test_rows_under_the_headings_are_read():
    assert parse_hosts(HOSTS) == [
        ("esx-01", "30001", "100", "4196", "0050.5601.0001", "192.0.2.31", "Ethernet1/7")
    ]
    assert parse_vsis(VSI) == [("1", "0x1a2b", "Ethernet1/7", "4000", "ASSOC", "A", "25/25")]


def test_the_configuration_is_read():
    assert parse_evb_config(
        "feature evb\nevb mac 0180.c200.0003\nevb resource-wait-delay 22\n"
        "evb batch-response disable\n"
    ) == {
        "mac": {"mac": "0180.c200.0003"},
        "resource_wait_delay": {"exponent": "22"},
        "batch_response_off": {},
    }


def test_the_page_view():
    view = parse_evb(STATE, HOSTS, VSI, "feature evb\n")
    (whole,) = view.of("global")
    facts = dict(whole.facts)
    assert facts["Role"] == "VDP bridge" and facts["VDP address"] == "0180.c200.0000"
    assert facts["Answer wait"] == "25 (about 335 seconds)"
    assert facts["VDP messages received"] == "0"
    assert [t.title for t in view.tables] == ["Hosts", "Virtual station interfaces (VSIs)"]
    # Without the configuration, the current values come from show evb.
    assert parse_evb(STATE).of("global")[0].values["resource_wait_delay"] == {"exponent": "25"}


def test_the_lines():
    assert _lines("mac", "set", {"mac": "0180.c200.0003"}) == ["evb mac 0180.c200.0003"]
    assert _lines("mac", "remove") == ["no evb mac"]
    assert _lines("resource_wait_delay", "set", {"exponent": "22"}) == [
        "evb resource-wait-delay 22"
    ]
    assert _lines("reinit_keep_alive", "remove") == ["no evb reinit-keep-alive"]
    assert _lines("batch_response_off", "set") == ["evb batch-response disable"]
    with pytest.raises(ValueError, match="from 0 to 31"):
        build_evb_change("global", "reinit_keep_alive", "set", {}, {"exponent": "32"})
    with pytest.raises(ValueError):
        build_evb_change("global", "mac", "set", {}, {"mac": "0200.0000.0001"})


# ---- the page ---------------------------------------------------------------------------------


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
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
    fake.feature_state["evb"] = True
    fake.texts.update({"show evb hosts": HOSTS, "show evb vsi": VSI})
    fake.requests.clear()
    return fake


def _enable(client: TestClient, settings: Settings, fake: FakeSwitch, mode: str) -> FakeSwitch:
    response = client.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(client, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "role_mode": mode,
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    fake.requests.clear()
    fake.signed_in.clear()
    return fake


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    return _enable(logged_in, settings, switch, "broad")


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), "scope": "global", **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/evb/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/evb", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/evb"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/evb")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "VDP bridge" in text and "esx-01" in text and "0x1a2b" in text
    assert enabled.requests == [
        ["show feature"],
        ["show evb"],
        ["show evb hosts"],
        ["show evb vsi"],
        ["show running-config"],
    ]


def test_with_the_feature_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["evb"] = False
    assert "evb is off on the switch" in _text(logged_in.get("/evb").text)


def test_settings_are_sent_and_read_back(logged_in: TestClient, enabled: FakeSwitch) -> None:
    asked = _change(logged_in, confirm=False, setting="mac", action="set", v_mac="0180.c200.0003")
    assert "evb mac 0180.c200.0003" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, setting="mac", action="set", v_mac="0180.c200.0003")
    assert done.status_code == 200, _text(done.text)
    assert "evb mac 0180.c200.0003" in enabled.l2_lines
    assert "0180.c200.0003" in _text(done.text)
    wait = _change(logged_in, setting="resource_wait_delay", action="set", v_exponent="22")
    assert wait.status_code == 200, _text(wait.text)
    assert "22 (about 41 seconds)" in _text(wait.text)
    back = _change(logged_in, setting="resource_wait_delay", action="remove")
    assert back.status_code == 200, _text(back.text)
    assert not any("resource-wait-delay" in line for line in enabled.l2_lines)
    batch = _change(logged_in, setting="batch_response_off", action="set")
    assert batch.status_code == 200, _text(batch.text)
    assert "evb batch-response disable" in enabled.l2_lines


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    refused = _change(logged_in, setting="batch_response_off", action="set")
    assert refused.status_code == 400
    assert "Edge Virtual Bridging changes are off" in _text(refused.text)
    assert _config_requests(switch) == []


def test_with_the_admin_login_stored_the_change_is_sent_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "stored")
    done = _change(logged_in, setting="batch_response_off", action="set")
    assert done.status_code == 200, _text(done.text)
    assert "admin" in switch.signed_in and "evb batch-response disable" in switch.l2_lines


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "evb"})
    assert saved.status_code == 200
    assert "VDP address" in _text(saved.text) and enabled.saved
