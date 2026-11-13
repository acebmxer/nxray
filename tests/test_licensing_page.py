"""The Smart Licensing page (#95), end to end against the fake switch, and its parsers."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.licensing import (
    build_licensing_change,
    parse_licensing,
    parse_summary,
    parse_udi,
    parse_usage,
)
from tests.fake_switch import FakeSwitch
from tests.stage_d_helpers import config_requests, csrf, enable, set_up, text

FIXTURES = Path(__file__).parent / "fixtures"
# Recorded on cisco-25gb (NX-OS 9.3(16), 2026-11-13).
SUMMARY = (FIXTURES / "show_license_summary.txt").read_text()
USAGE = (FIXTURES / "show_license_usage.txt").read_text()
UDI = "UDI: PID:N9K-C92160YC-X, SN:FDO221221GZ\n"


def test_the_usage_table_is_read() -> None:
    rows = parse_usage(USAGE)
    assert rows[0] == ("ACI-STRG", "No", "-", "Unused", "-")
    assert rows[-1] == ("LAN_ENTERPRISE_SERVICES_PKG", "Yes", "-", "Unused", "never       -")
    assert len(rows) == 4  # the headings and dashes are left out


def test_the_summary_and_identity_are_read() -> None:
    assert parse_summary(SUMMARY) == (
        ("Smart Licensing", "ENABLED"),
        ("Registration", "UNREGISTERED"),
        ("Export-controlled features", "Not Allowed"),
        ("Licence authorization", "No Licenses in Use"),
    )
    assert parse_udi(UDI) == "PID:N9K-C92160YC-X, SN:FDO221221GZ"
    assert parse_udi(None) == "" and parse_summary(None) == ()


def test_the_view_while_it_is_off_and_on() -> None:
    off = parse_licensing(False, USAGE)
    assert off.instances == () and "Smart Licensing is off" in off.notes[0]
    assert len(off.tables[0].rows) == 4
    on = parse_licensing(
        True, USAGE, SUMMARY, UDI, "feature license smart\nlicense smart reservation\n"
    )
    (smart,) = on.of("smart")
    assert dict(smart.facts)["Registration"] == "UNREGISTERED"
    assert dict(smart.facts)["Identity (UDI)"].startswith("PID:N9K-C92160YC-X")
    assert smart.values == {"reservation": {}}
    assert (
        parse_licensing(True, USAGE, SUMMARY, UDI, "feature license smart\n").of("smart")[0].values
        == {}
    )


def test_the_lines() -> None:
    assert build_licensing_change("smart", "reservation", "set", {}, {}).lines == (
        "license smart reservation",
    )
    assert build_licensing_change("smart", "reservation", "remove", {}, {}).lines == (
        "no license smart reservation",
    )
    with pytest.raises(ValueError):
        build_licensing_change("smart", "enable", "set", {}, {})  # turned on on Features


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = set_up(logged_in)
    fake.texts.update(
        {
            "show license usage": USAGE,
            "show license summary": SUMMARY,
            "show license udi": UDI,
        }
    )
    return fake


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": csrf(client), "scope": "smart", **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/licensing/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/licensing", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/licensing"' in logged_in.get("/").text


def test_with_smart_licensing_off_the_usage_still_shows(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    page = logged_in.get("/licensing")
    assert page.status_code == 200, text(page.text)
    shown = text(page.text)
    assert "Smart Licensing is off" in shown and "LAN_ENTERPRISE_SERVICES_PKG" in shown
    assert switch.requests == [["show feature"], ["show license usage"]]
    assert "Licence reservation" not in shown  # no form while it is off


def test_the_form_is_offered_only_while_it_is_on(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    assert "Licence reservation" not in text(logged_in.get("/licensing").text)
    switch.feature_state["license-smart"] = True
    assert "Licence reservation" in text(logged_in.get("/licensing").text)


def test_page_reads_the_registration(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["license-smart"] = True
    shown = text(logged_in.get("/licensing").text)
    assert "UNREGISTERED" in shown and "PID:N9K-C92160YC-X" in shown
    assert "No Licenses in Use" in shown


def test_the_reservation_is_set_and_removed(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    switch.feature_state["license-smart"] = True
    asked = _change(logged_in, confirm=False, setting="reservation", action="set")
    assert "license smart reservation" in text(asked.text)
    assert config_requests(switch) == []
    done = _change(logged_in, setting="reservation", action="set")
    assert done.status_code == 200, text(done.text)
    assert "license smart reservation" in switch.mgmt_lines
    gone = _change(logged_in, setting="reservation", action="remove")
    assert gone.status_code == 200, text(gone.text)
    assert "license smart reservation" not in switch.mgmt_lines


def test_it_is_refused_while_the_feature_is_off(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    refused = _change(logged_in, setting="reservation", action="set")
    assert refused.status_code == 400 and "Invalid command" in text(refused.text)


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "limited")
    switch.feature_state["license-smart"] = True
    refused = _change(logged_in, setting="reservation", action="set")
    assert refused.status_code == 400 and "Smart Licensing changes are off" in text(refused.text)
    assert config_requests(switch) == []


def test_save_config_comes_back_here(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    saved = logged_in.post("/switch/save", data={"csrf": csrf(logged_in), "back": "licensing"})
    assert saved.status_code == 200
    assert "Smart Licensing" in text(saved.text) and switch.saved
