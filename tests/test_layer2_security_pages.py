"""The DHCP and ARP page, the ACLs page's role version 14 parts and restarting the
switch from the Config page, end to end against the fake switch."""

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


def _enable(client: TestClient) -> str:
    response = client.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(client, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    return _text(response.text)


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    """All changes on (role version 14), the wait over, the dhcp feature on."""
    _enable(logged_in)
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    switch.feature_state["dhcp"] = True
    switch.requests.clear()
    switch.saved = False
    return switch


def _change(client: TestClient, url: str, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post(url, data=data)


ACL = "/security/acls/change"
DHCP = "/security/dhcp/change"


def test_dhcp_page_needs_login(client: TestClient) -> None:
    assert client.get("/security/dhcp", follow_redirects=False).status_code == 303


def test_dhcp_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/security/dhcp").text)


def test_security_pages_link_to_dhcp(logged_in: TestClient, enabled: FakeSwitch) -> None:
    assert 'href="/security/dhcp"' in logged_in.get("/security/acls").text
    assert 'href="/security/dhcp"' in logged_in.get("/security/port-security").text


def test_dhcp_page_needs_the_feature(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.feature_state["dhcp"] = False
    assert "dhcp is off on the switch" in _text(logged_in.get("/security/dhcp").text)
    refused = _change(logged_in, DHCP, scope="switch", setting="snooping", action="set")
    assert refused.status_code == 400
    assert _config_requests(enabled) == []


def test_changes_off_before_role_version_14(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 13")
    assert "Layer 2 security changes are off" in _text(logged_in.get("/security/dhcp").text)
    switch_page = _text(logged_in.get("/switch").text)
    assert (
        "Turn on layer 2 security, traffic measuring and reset to defaults changes" in switch_page
    )
    refused = _change(logged_in, DHCP, scope="switch", setting="snooping", action="set")
    assert refused.status_code == 400
    assert "Layer 2 security changes are off" in _text(refused.text)
    # On the ACLs page the older parts still work; the newer ones say why not.
    newer = _change(logged_in, ACL, scope="mac_acl", action="create", id_name="no-ipx")
    assert newer.status_code == 400
    assert "need NXray's newer role on the switch" in _text(newer.text)
    older = _change(logged_in, ACL, scope="ipv4_acl", action="create", id_name="web")
    assert older.status_code == 200, _text(older.text)
    assert _config_requests(enabled) == [["ip access-list web"]]


def test_role_version_13_turns_on_layer2_without_a_wait(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 13")
    enabled.ssh_lines.clear()
    text = _enable(logged_in)
    assert (
        "Layer 2 security, traffic measuring and reset to defaults changes are on: nxray may "
        "now also set DHCP "
        "snooping" in text
    )
    assert "there is no wait" in text
    assert "rule 227 permit command conf t ; hardware access-list tcam region *" in (
        enabled.ssh_lines
    )
    assert not any("reload" in line for line in enabled.ssh_lines)


def test_dhcp_snooping_arp_inspection_and_source_guard(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    page = logged_in.get("/security/dhcp")
    assert page.status_code == 200
    text = _text(page.text)
    assert "DHCP snooping off" in text and "DHCP relay on" in text
    assert "02:00:00:00:00:21" in text and "192.0.2.21" in text

    asked = _change(logged_in, DHCP, confirm=False, scope="switch", setting="snooping_vlans",
                    action="set", v_vlans="1")  # fmt: skip
    assert "ip dhcp snooping vlan 1" in _text(asked.text)
    assert "dropped at once" in _text(asked.text)
    assert _config_requests(enabled) == []

    for scope, setting, fields in (
        ("switch", "snooping", {}),
        ("switch", "snooping_vlans", {"v_vlans": "1"}),
        ("port", "snooping_trust", {"id_port": "Ethernet1/3"}),
        ("port", "snooping_rate", {"id_port": "Ethernet1/3", "v_rate": "30"}),
        ("port", "arp_trust", {"id_port": "Ethernet1/3"}),
        ("port", "source_guard", {"id_port": "Ethernet1/4"}),
        ("switch", "arp_vlans", {"v_vlans": "1"}),
        ("switch", "arp_validate", {"v_checks": "src-mac ip"}),
        ("switch", "binding", {"v_address": "192.0.2.20", "v_mac": "0200.0000.0020",
                               "v_vlan": "1", "v_port": "Ethernet1/4"}),
        ("switch", "verify_mac", {}),
    ):  # fmt: skip
        action = "remove" if setting == "verify_mac" else "set"
        done = _change(logged_in, DHCP, scope=scope, setting=setting, action=action, **fields)
        assert done.status_code == 200, _text(done.text)
    assert ["interface Ethernet1/3", "ip dhcp snooping limit rate 30"] in enabled.requests
    assert ["no ip dhcp snooping verify mac-address"] in enabled.requests

    text = _text(logged_in.get("/security/dhcp").text)
    assert "DHCP snooping on" in text and "Snooping in VLANs 1" in text
    assert "MAC addresses checked off" in text
    assert "ARP also checks src-mac ip" in text
    assert "Ethernet1/3 yes 30 a second yes off" in text
    assert "0200.0000.0020 192.0.2.20 — static 1 Ethernet1/4" in text
    assert "NXray changed the switch since its configuration was last saved" in text

    # The other kind of place is refused before anything is sent.
    enabled.requests.clear()
    refused = _change(logged_in, DHCP, scope="port", setting="arp_trust", action="set",
                      id_port="Ethernet1/99")  # fmt: skip
    assert refused.status_code == 400
    assert "is not a front port" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_dhcp_relay_and_arp_acls(logged_in: TestClient, enabled: FakeSwitch) -> None:
    # The role names VLAN interfaces once interface-vlan is on: Update the port list.
    enabled.feature_state["interface-vlan"] = True
    enabled.svis.add(10)
    assert "The port list is updated" in _enable(logged_in)
    relay = _change(logged_in, DHCP, scope="relay", setting="server", action="set",
                    id_interface="Vlan10", v_server="192.0.2.53", v_vrf="management")  # fmt: skip
    assert relay.status_code == 200, _text(relay.text)
    assert [
        "interface Vlan10",
        "ip dhcp relay address 192.0.2.53 use-vrf management",
    ] in enabled.requests
    off = _change(logged_in, DHCP, scope="switch", setting="relay6", action="remove")
    assert off.status_code == 200, _text(off.text)

    made = _change(logged_in, DHCP, scope="arp_acl", action="create", id_name="fixed-hosts")
    assert made.status_code == 200, _text(made.text)
    entry = _change(logged_in, DHCP, scope="arp_acl", setting="entry", action="set",
                    id_name="fixed-hosts", v_seq="10", v_action="permit",
                    v_address="192.0.2.20", v_mac="0200.0000.0020")  # fmt: skip
    assert entry.status_code == 200, _text(entry.text)
    applied = _change(logged_in, DHCP, scope="switch", setting="arp_filter", action="set",
                      v_acl="fixed-hosts", v_vlans="1")  # fmt: skip
    assert applied.status_code == 200, _text(applied.text)

    text = _text(logged_in.get("/security/dhcp").text)
    assert "Vlan10 192.0.2.53 (VRF management)" in text
    assert "DHCPv6 relay off" in text
    assert "10 permit ip host 192.0.2.20 mac host 0200.0000.0020" in text
    assert "For VLANs 1" in text


def test_acl_v14_parts(logged_in: TestClient, enabled: FakeSwitch) -> None:
    text = _text(logged_in.get("/security/acls").text)
    assert "Ingress PACL" in text and "ing-ifacl" in text

    steps = (
        {"scope": "mac_acl", "action": "create", "id_name": "no-ipx"},
        {"scope": "mac_acl", "setting": "entry", "action": "set", "id_name": "no-ipx",
         "v_seq": "10", "v_action": "deny", "v_source": "any", "v_destination": "any",
         "v_ethertype": "0x8137"},
        {"scope": "switched", "setting": "mac_in", "action": "set", "id_port": "Ethernet1/3",
         "v_acl": "no-ipx"},
        {"scope": "addr4_group", "action": "create", "id_name": "web-servers"},
        {"scope": "addr4_group", "setting": "entry", "action": "set", "id_name": "web-servers",
         "v_seq": "10", "v_address": "192.0.2.10"},
        {"scope": "ipv4_acl", "action": "create", "id_name": "web-in"},
        {"scope": "ipv4_acl", "setting": "entry", "action": "set", "id_name": "web-in",
         "v_seq": "10", "v_action": "permit", "v_protocol": "tcp", "v_source": "any",
         "v_destination": "addrgroup web-servers", "v_destination_port": "443"},
        {"scope": "access_map", "action": "create", "id_name": "guard", "id_seq": "10"},
        {"scope": "access_map", "setting": "match_ip", "action": "set", "id_name": "guard",
         "id_seq": "10", "v_acl": "web-in"},
        {"scope": "access_map", "setting": "action", "action": "set", "id_name": "guard",
         "id_seq": "10", "v_action": "forward"},
        {"scope": "vlan_filter", "setting": "vlans", "action": "set", "id_name": "guard",
         "v_vlans": "1"},
        {"scope": "tcam", "setting": "region", "action": "set", "v_region": "ing-ifacl",
         "v_size": "256"},
    )  # fmt: skip
    for fields in steps:
        done = _change(logged_in, ACL, **fields)
        assert done.status_code == 200, (fields, _text(done.text))
    assert ["mac access-list no-ipx", "10 deny any any 0x8137"] in enabled.requests
    assert ["vlan filter guard vlan-list 1"] in enabled.requests

    text = _text(logged_in.get("/security/acls").text)
    assert "no-ipx MAC 1 Ethernet1/3 in" in text
    assert "10 permit tcp any addrgroup web-servers eq 443" in text
    assert "Used by web-in" in text
    assert "VLAN access map guard 10 web-in → forward 1" in text
    assert "ing-ifacl Ingress PACL 256 256" in text

    asked = _change(logged_in, ACL, confirm=False, scope="tcam", setting="region",
                    action="set", v_region="vacl", v_size="512")  # fmt: skip
    assert "Nothing changes until the switch restarts" in _text(asked.text)


def test_restart_asks_saves_first_and_reloads(logged_in: TestClient, enabled: FakeSwitch) -> None:
    asked = logged_in.post("/config/reload", data={"csrf": _csrf(logged_in)})
    assert asked.status_code == 200
    text = _text(asked.text)
    assert "every port goes down" in text and "Switch admin username" in text
    assert enabled.reloads == 0

    wrong = logged_in.post(
        "/config/reload",
        data={"csrf": _csrf(logged_in), "confirm": "yes", "save": "yes",
              "admin_user": "admin", "admin_password": "nope", "ssh_port": "22"},
    )  # fmt: skip
    assert wrong.status_code == 400
    assert "refused that admin username or password" in _text(wrong.text)
    assert enabled.reloads == 0

    done = logged_in.post(
        "/config/reload",
        data={"csrf": _csrf(logged_in), "confirm": "yes", "save": "yes",
              "admin_user": "admin", "admin_password": ADMIN_PASSWORD, "ssh_port": "22"},
    )  # fmt: skip
    assert done.status_code == 200, _text(done.text)
    assert "the switch is restarting, with its configuration saved first" in _text(done.text)
    assert enabled.reloads == 1 and enabled.saved_at_reload == [True]
    assert enabled.ssh_lines[-2:] == ["terminal dont-ask", "reload"]
    activity = _text(logged_in.get("/activity").text)
    assert "Restarted the switch, after saving its configuration" in activity


def test_restart_without_saving_and_bad_input(logged_in: TestClient, enabled: FakeSwitch) -> None:
    bad_port = logged_in.post(
        "/config/reload",
        data={"csrf": _csrf(logged_in), "confirm": "yes", "admin_user": "admin",
              "admin_password": ADMIN_PASSWORD, "ssh_port": "70000"},
    )  # fmt: skip
    assert bad_port.status_code == 400 and "SSH port" in _text(bad_port.text)
    empty = logged_in.post("/config/reload", data={"csrf": _csrf(logged_in), "confirm": "yes"})
    assert "Enter the switch's admin username and password" in _text(empty.text)
    done = logged_in.post(
        "/config/reload",
        data={"csrf": _csrf(logged_in), "confirm": "yes", "admin_user": "admin",
              "admin_password": ADMIN_PASSWORD, "ssh_port": "22"},
    )  # fmt: skip
    assert done.status_code == 200
    assert enabled.saved_at_reload == [False]


def test_restart_by_an_account_that_may_not(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = logged_in.post(
        "/config/reload",
        data={"csrf": _csrf(logged_in), "confirm": "yes", "admin_user": "nxray",
              "admin_password": enabled.users["nxray"][0], "ssh_port": "22"},
    )  # fmt: skip
    assert refused.status_code == 400
    assert "Not restarted: the switch refused it" in _text(refused.text)
    assert enabled.reloads == 0


def test_restart_is_for_admins_only(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE users SET role = 'operator'")
    assert logged_in.post("/config/reload", data={"csrf": _csrf(logged_in)}).status_code == 403
    assert enabled.reloads == 0
