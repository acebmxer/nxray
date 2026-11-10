"""The ACLs and Port security pages, end to end against the fake switch: reading
them, the role version they need, and changes from asking to sent."""

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
    """All changes on (role version 13) and the wait over."""
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


def _change(client: TestClient, url: str, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post(url, data=data)


ACL = "/security/acls/change"
PORTSEC = "/security/port-security/change"


def test_pages_need_login(client: TestClient) -> None:
    assert client.get("/security/acls", follow_redirects=False).status_code == 303
    assert client.get("/security/port-security", follow_redirects=False).status_code == 303


def test_menu_links_to_security(logged_in: TestClient) -> None:
    assert 'href="/security/acls"' in logged_in.get("/").text


def test_pages_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/security/acls").text)
    assert "No switch connected yet" in _text(logged_in.get("/security/port-security").text)


def test_read_only_role_cannot_read_the_configuration(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    text = _text(logged_in.get("/security/acls").text)
    assert "does not let it read the switch's configuration yet" in text
    assert "/security/acls/change" not in logged_in.get("/security/acls").text


def test_changes_off_before_role_version_13(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 12")
    assert "Security and config changes are off" in _text(logged_in.get("/security/acls").text)
    assert (
        "Turn on security and config, layer 2 security, traffic measuring, reset to "
        "defaults, sFlow status, switch restart and vPC changes"
        in _text(logged_in.get("/switch").text)
    )
    refused = _change(logged_in, ACL, scope="ipv4_acl", action="create", id_name="web")
    assert refused.status_code == 400
    assert "Security and config changes are off" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_role_version_12_turns_on_security_without_a_wait(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 12")
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
        "Security and config, layer 2 security, traffic measuring, reset to defaults,"
        " sFlow status, switch restart and vPC changes are on: nxray may now also make and"
        " delete" in text
    )
    assert "there is no wait" in text
    assert "rule 188 permit command checkpoint *" in enabled.ssh_lines
    # Rolling back is never in the role.
    assert not any("rollback" in line for line in enabled.ssh_lines)


def test_make_an_acl_add_entries_and_apply_it(logged_in: TestClient, enabled: FakeSwitch) -> None:
    asked = _change(logged_in, ACL, confirm=False, scope="ipv4_acl", action="create",
                    id_name="mgmt-in")  # fmt: skip
    assert "ip access-list mgmt-in" in _text(asked.text)
    assert _config_requests(enabled) == []

    assert _change(logged_in, ACL, scope="ipv4_acl", action="create",
                   id_name="mgmt-in").status_code == 200  # fmt: skip
    done = _change(
        logged_in,
        ACL,
        scope="ipv4_acl",
        setting="entry",
        action="set",
        id_name="mgmt-in",
        v_seq="10",
        v_action="permit",
        v_protocol="tcp",
        v_source="192.0.2.0/24",
        v_destination="any",
        v_destination_port="22",
    )
    assert done.status_code == 200, _text(done.text)
    assert ["ip access-list mgmt-in", "10 permit tcp 192.0.2.0/24 any eq 22"] in enabled.requests
    applied = _change(logged_in, ACL, scope="switched", setting="ipv4_in", action="set",
                      id_port="Ethernet1/3", v_acl="mgmt-in")  # fmt: skip
    assert applied.status_code == 200, _text(applied.text)
    assert ["interface Ethernet1/3", "ip port access-group mgmt-in in"] in enabled.requests

    text = _text(logged_in.get("/security/acls").text)
    assert "permit tcp 192.0.2.0/24 any eq 22" in text
    assert "Applies on Ethernet1/3 in" in text
    assert "NXray changed the switch since its configuration was last saved" in text

    # A number already in use is refused by the switch.
    again = _change(logged_in, ACL, scope="ipv4_acl", setting="entry", action="set",
                    id_name="mgmt-in", v_seq="10", v_action="deny", v_protocol="ip",
                    v_source="any", v_destination="any")  # fmt: skip
    assert again.status_code == 400
    removed = _change(logged_in, ACL, scope="ipv4_acl", setting="entry", action="remove",
                      id_name="mgmt-in", v_seq="10")  # fmt: skip
    assert removed.status_code == 200
    assert "permit tcp" not in _text(logged_in.get("/security/acls").text)


def test_acl_refuses_a_routed_place_that_is_not_there(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    refused = _change(logged_in, ACL, scope="routed", setting="ipv4_in", action="set",
                      id_interface="Vlan10", v_acl="web")  # fmt: skip
    assert refused.status_code == 400
    assert "is not a VLAN interface" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_port_security_needs_the_feature(logged_in: TestClient, enabled: FakeSwitch) -> None:
    text = _text(logged_in.get("/security/port-security").text)
    assert "port-security is off on the switch" in text
    refused = _change(logged_in, PORTSEC, scope="port", setting="enable", action="set",
                      id_port="Ethernet1/3")  # fmt: skip
    assert refused.status_code == 400
    assert _config_requests(enabled) == []


def test_port_security_changes(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.feature_state["eth-port-sec"] = True
    page = logged_in.get("/security/port-security")
    assert page.status_code == 200
    assert 'name="setting" value="maximum"' in page.text
    asked = _change(logged_in, PORTSEC, confirm=False, scope="port", setting="enable",
                    action="set", id_port="Ethernet1/3")  # fmt: skip
    assert "a second device turns the port off" in _text(asked.text)
    for setting, values in (
        ("maximum", {"v_maximum": "3"}),
        ("violation", {"v_mode": "restrict"}),
        ("mac", {"v_mac": "0200.0000.0001", "v_vlan": "1"}),
        ("enable", {}),
    ):
        done = _change(logged_in, PORTSEC, scope="port", setting=setting, action="set",
                       id_port="Ethernet1/3", **values)  # fmt: skip
        assert done.status_code == 200, _text(done.text)
    text = _text(logged_in.get("/security/port-security").text)
    assert "Port security on" in text and "Most addresses 3" in text
    assert "0200.0000.0001 (VLAN 1)" in text
    # Port-channels and routed ports are not offered.
    refused = _change(logged_in, PORTSEC, scope="port", setting="enable", action="set",
                      id_port="port-channel43")  # fmt: skip
    assert refused.status_code == 400


def test_viewer_sees_no_forms_and_cannot_post(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE users SET role = 'viewer'")
    page = logged_in.get("/security/acls")
    assert page.status_code == 200 and "/security/acls/change" not in page.text
    assert "can look at ACLs but not change them" in _text(page.text)
    assert _change(logged_in, ACL, scope="ipv4_acl", action="create",
                   id_name="web").status_code == 403  # fmt: skip


def test_changes_are_in_the_activity_log(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _change(logged_in, ACL, scope="ipv4_acl", action="create", id_name="web")
    text = _text(logged_in.get("/activity").text)
    assert "ACLs: make IPv4 ACLs (ACL web)." in text
    assert "192.0.2.10" in text
