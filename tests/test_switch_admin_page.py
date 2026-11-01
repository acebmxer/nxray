"""The Switch admin and Switch log pages, end to end against the fake switch:
reading them, the role version they need, and changes from asking to sent."""

from __future__ import annotations

import html
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


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


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    """A switch that has been set up (read-only account nxray)."""
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
    fake.requests.clear()
    return fake


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    """All changes on (role version 12) and the wait over."""
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
    switch.requests.clear()
    switch.saved = False
    return switch


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/switch-admin/change", data=data)


def test_pages_need_login(client: TestClient) -> None:
    assert client.get("/switch-admin", follow_redirects=False).status_code == 303
    assert client.get("/switch-admin/log", follow_redirects=False).status_code == 303


def test_pages_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/switch-admin").text)
    assert "No switch connected yet" in _text(logged_in.get("/switch-admin/log").text)


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/switch-admin"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/switch-admin")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "Switch admin" in text and "Hostname nexus-lab" in text
    assert "18:42:07.512 UTC Sat Oct 31 2026 (from NTP)" in text
    # NTP servers in use, from show ntp peer-status.
    assert "192.0.2.123" in text and "the clock follows it" in text
    assert "not reached yet" in text
    # The role at setup (read-only) may not read the configuration.
    assert "does not let it read the switch's configuration yet" in text
    assert switch.requests[0] == ["show hostname", "show clock", "show vrf"]
    assert switch.requests[1] == ["show ntp peer-status"]
    assert switch.requests[2] == ["show running-config"]
    assert "/switch-admin/change" not in page.text  # changes are off


def test_changes_off_before_role_version_12(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 11")
    page = logged_in.get("/switch-admin").text
    assert "Switch admin changes are off" in _text(page)
    assert "Turn on switch admin, security and config and layer 2 security changes" in _text(
        logged_in.get("/switch").text
    )
    refused = _change(logged_in, scope="system", setting="hostname", action="set",
                      v_name="core-1")  # fmt: skip
    assert refused.status_code == 400
    assert "Switch admin changes are off" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_role_version_11_turns_on_switch_admin_without_a_wait(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 11")
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
    assert (
        "Switch admin, security and config and layer 2 security changes are on: nxray may now also "
        "change the "
        "switch's hostname" in text
    )
    assert "there is no wait" in text
    assert "rule 164 permit command conf t ; snmp-server community * group network-operator" in (
        enabled.ssh_lines
    )


def test_enabled_page_shows_the_configuration(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.admin_lines = [
        "clock timezone EST -5 0",
        "ip domain-name example.net use-vrf management",
        "ip name-server 192.0.2.53 use-vrf management",
        "ntp server 192.0.2.123 prefer use-vrf management",
        "logging server 192.0.2.50 5 use-vrf management",
        "snmp-server community Secret-Ro-1 group network-operator",
        "snmp-server host 192.0.2.162 traps version 2c Secret-Trap-1",
        "banner motd #Authorized access only#",
    ]
    enabled.context_name_servers = [("198.51.100.53", "management")]
    page = logged_in.get("/switch-admin")
    assert page.status_code == 200
    text = _text(page.text)
    assert "Time zone EST, UTC -5:00" in text
    assert "Domain name example.net (VRF management)" in text
    assert "192.0.2.53 (VRF management)" in text
    assert "198.51.100.53 (VRF management)" in text and "vrf context management" in text
    assert "Preferred yes" in text and "the clock follows it" in text
    assert "192.0.2.50" in text
    assert "Login banner Authorized access only" in text
    assert "read-only (network-operator)" in text
    # Communities are never shown, not even in a form.
    assert "Secret-Ro-1" not in page.text and "Secret-Trap-1" not in page.text
    assert "/switch-admin/change" in page.text
    assert 'href="/switch-admin/log"' in page.text
    assert "Change any NTP servers" in text


def test_hostname_asks_first_then_renames_and_stores_it(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    asked = _change(logged_in, confirm=False, scope="system", setting="hostname",
                    action="set", v_name="core-1")  # fmt: skip
    text = _text(asked.text)
    assert "Confirm the change" in text and "hostname core-1" in text
    assert "CDP and LLDP neighbors" in text  # the warning
    assert _config_requests(enabled) == []
    done = _change(logged_in, scope="system", setting="hostname", action="set", v_name="core-1")
    assert done.status_code == 200, _text(done.text)
    assert "Done: Switch admin, Whole switch: set Hostname (core-1)." in _text(done.text)
    assert "Not saved yet" in _text(done.text)
    assert _config_requests(enabled) == [["hostname core-1"]]
    assert enabled.hostname == "core-1"
    conn = sqlite3.connect(settings.db_path)
    (stored,) = conn.execute("SELECT switch_hostname FROM switch_connection").fetchone()
    conn.close()
    assert stored == "core-1"
    assert "Save config" in done.text


def test_clock_set_is_not_configuration(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {
        "scope": "system",
        "setting": "clock_set",
        "action": "set",
        "v_time": "9:05:00",
        "v_day": "31",
        "v_month": "October",
        "v_year": "2026",
    }
    asked = _text(_change(logged_in, confirm=False, **fields).text)
    assert "clock set 09:05:00 31 October 2026" in asked
    assert "changes no configuration" in asked
    done = _text(_change(logged_in, **fields).text)
    assert "Done:" in done and "Not saved yet" not in done
    assert enabled.clock_sets == ["09:05:00 31 October 2026"]


def test_ntp_server_added_and_deleted(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(logged_in, scope="ntp", setting="server", action="set",
                   id_address="192.0.2.123", v_prefer="yes", v_vrf="management")  # fmt: skip
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["ntp server 192.0.2.123 prefer use-vrf management"]]
    page = _text(done.text)
    assert "NTP servers" in page and "Delete 192.0.2.123" in page
    enabled.requests.clear()
    gone = _change(logged_in, scope="ntp", action="delete", id_address="192.0.2.123")
    assert gone.status_code == 200, _text(gone.text)
    assert _config_requests(enabled) == [["no ntp server 192.0.2.123"]]
    assert enabled.admin_lines == []


def test_a_server_in_the_default_vrf_gets_no_use_vrf(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    _change(logged_in, scope="logging", setting="server", action="set",
            id_address="syslog.example.net", v_level="", v_vrf="default")  # fmt: skip
    assert _config_requests(enabled) == [["logging server syslog.example.net"]]


def test_an_unknown_vrf_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _change(logged_in, scope="dns", setting="server", action="set",
                      id_address="192.0.2.53", id_vrf="nowhere")  # fmt: skip
    assert refused.status_code == 400
    assert "the switch has no VRF nowhere" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_name_server_inside_a_vrf_is_deleted_there(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.context_name_servers = [("198.51.100.53", "management")]
    done = _change(logged_in, scope="dns_context", action="delete",
                   id_address="198.51.100.53", id_context="management")  # fmt: skip
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [
        ["vrf context management", "no ip name-server 198.51.100.53"]
    ]
    assert enabled.context_name_servers == []


def test_snmp_community_is_masked_and_read_only(logged_in: TestClient, enabled: FakeSwitch) -> None:
    asked = _change(logged_in, confirm=False, scope="system", setting="community",
                    action="set", v_community="Very-Secret-1")  # fmt: skip
    # Only the confirm form carries it back, as for every secret.
    assert "Very-Secret-1" not in _text(asked.text)
    assert "snmp-server community *** group network-operator" in _text(asked.text)
    done = _change(logged_in, scope="system", setting="community", action="set",
                   v_community="Very-Secret-1")  # fmt: skip
    assert done.status_code == 200 and "Very-Secret-1" not in done.text
    assert enabled.admin_lines == ["snmp-server community Very-Secret-1 group network-operator"]


def test_role_refuses_a_read_write_community(enabled: FakeSwitch) -> None:
    """The switch itself refuses NXray's account the lines NXray never sends."""
    from app.nxapi import NxapiClient, NxapiCommandError, SwitchTarget

    password = enabled.users["nxray"][0]
    target = SwitchTarget(
        host="192.0.2.10", port=443, username="nxray", password=password, timeout=5.0
    )
    with NxapiClient(target, transport=enabled.transport()) as client:
        for line in (
            "snmp-server community Rw-1 group network-admin",
            "snmp-server user evil network-admin auth sha Passw0rd-123",
            "username evil password Passw0rd-123 role network-admin",
        ):
            with pytest.raises(NxapiCommandError, match="Permission denied|Invalid"):
                client._send([line], [line], 5.0, allow_text=True)


def test_snmp_community_error_is_scrubbed(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.reject.add("snmp-server community")
    refused = _change(logged_in, scope="system", setting="community", action="set",
                      v_community="Very-Secret-1")  # fmt: skip
    assert refused.status_code == 400
    assert "Very-Secret-1" not in refused.text


def test_banner_refuses_its_delimiter(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _change(logged_in, scope="system", setting="banner", action="set",
                      v_text="Room #4")  # fmt: skip
    assert refused.status_code == 400 and 'the banner cannot contain "#"' in _text(refused.text)
    done = _change(logged_in, scope="system", setting="banner", action="set",
                   v_text="Authorized access only")  # fmt: skip
    assert done.status_code == 200
    assert enabled.admin_lines == ["banner motd #Authorized access only#"]
    assert "Login banner Authorized access only" in _text(logged_in.get("/switch-admin").text)
    _change(logged_in, scope="system", setting="banner", action="remove")
    assert enabled.admin_lines == []


def test_dns_lookups_off_and_on(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _change(logged_in, scope="system", setting="lookup", action="remove")
    assert enabled.admin_lines == ["no ip domain-lookup"]
    assert "DNS lookups off" in _text(logged_in.get("/switch-admin").text)
    _change(logged_in, scope="system", setting="lookup", action="set")
    assert enabled.admin_lines == []


def test_viewer_sees_no_forms_and_cannot_post(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE users SET role = 'viewer'")
    page = logged_in.get("/switch-admin").text
    assert "/switch-admin/change" not in page
    assert "Hostname nexus-lab" in _text(page)
    assert "can look at the switch's settings but not change them" in _text(page)
    response = _change(logged_in, scope="system", setting="hostname", action="set", v_name="x")
    assert response.status_code == 403
    # The log is for every role.
    assert logged_in.get("/switch-admin/log").status_code == 200
    assert _config_requests(enabled) == []


def test_change_needs_csrf(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = logged_in.post(
        "/switch-admin/change",
        data={"csrf": "0" * 32, "scope": "system", "setting": "hostname",
              "action": "set", "v_name": "x", "confirm": "yes"},
    )  # fmt: skip
    assert response.status_code == 403
    assert _config_requests(enabled) == []


def test_log_page_newest_first(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/switch-admin/log")
    assert page.status_code == 200
    text = _text(page.text)
    assert switch.requests == [["show logging last 200"]]
    assert text.index("Authentication failed") < text.index("IF_DOWN_LINK_FAILURE")
    assert "5 lines" in text


def test_log_page_filters(logged_in: TestClient, switch: FakeSwitch) -> None:
    text = _text(logged_in.get("/switch-admin/log?search=ethernet1/7&lines=50").text)
    assert switch.requests == [["show logging last 50"]]
    assert "2 lines match, of the last 50" in text and "NTP" not in text
    text = _text(logged_in.get("/switch-admin/log?level=3").text)
    assert "NO_RESP_FROM_LS" in text and "Authentication failed" in text
    assert "IF_UP" not in text
    # Anything but the offered counts reads 200; nothing typed reaches the switch.
    switch.requests.clear()
    logged_in.get("/switch-admin/log?lines=5;reload")
    assert switch.requests == [["show logging last 200"]]


def test_save_config_returns_to_the_page(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _change(logged_in, scope="system", setting="contact", action="set", v_text="noc@example.net")
    response = logged_in.post(
        "/switch/save", data={"csrf": _csrf(logged_in), "back": "switch-admin"}
    )
    assert response.status_code == 200
    assert "Switch admin" in _text(response.text) and enabled.saved
