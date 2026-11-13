"""The VM Tracker page (#95), end to end against the fake switch, and its parsers."""

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
from app.port_changes import BROAD_RULES, ROLE_NAME, VMTRACKER_REFRESH_RULES
from app.switch_connection import BROAD_VMTRACKER_VERSION
from app.vmtracker import (
    PAGE_COMMANDS,
    build_vmtracker_change,
    parse_status,
    parse_vm_info,
    parse_vmtracker,
    parse_vmtracker_config,
)
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"

# Recorded on cisco-25gb (NX-OS 9.3(16), 2026-11-13) with a throwaway connection.
STATUS = json.loads((FIXTURES / "show_vmtracker_status.json").read_text())
# Lines the same switch wrote during that probe, put together in one text; the stored
# password replaced.
CONFIG = (FIXTURES / "show_running_config_vmtracker.txt").read_text()
# Laid out as in Cisco's NX-OS 9.3 VM Tracker guide (no vCenter on the probe switch).
INFO = """
--------------------------------------------------------------------------------------------
Interface   Host            VMNIC   VM              State   PortGroup       VLAN-Range
--------------------------------------------------------------------------------------------
Eth1/5      192.0.2.21      vmnic1  web 01          on      VM Network      100
Ethernet1/6 192.0.2.22      vmnic0  db01            off     Storage PG      200-201
"""


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


def _lines(scope, setting, action, ident, values=None):
    return list(build_vmtracker_change(scope, setting, action, ident, values or {}).lines)


# ---- parsing and lines ----------------------------------------------------------------------


def test_the_configuration_is_read():
    found = parse_vmtracker_config(CONFIG)
    assert found.auto_config
    assert found.ports_off == ("Ethernet1/53",)
    assert found.passwords == {"nxprobe-vc"}
    assert found.connections["nxprobe-vc"] == {
        "sync_full_info": {"seconds": "1200"},
        "find_new_host": {"seconds": "600"},
        "remote": {"address": "192.0.2.50", "port": "443", "vrf": "management"},
        "login": {"user": "nxprobe-vcuser"},
        "allowed_vlans": {"vlans": "1-251,253-4094"},
    }


def test_the_status_and_vms_are_read():
    assert parse_status(STATUS) == {"nxprobe-vc": ("192.0.2.51", "No Connect")}
    assert parse_status(None) == {}
    assert parse_vm_info(INFO) == [
        ("Ethernet1/5", "192.0.2.21", "vmnic1", "web 01", "on", "VM Network", "100"),
        ("Ethernet1/6", "192.0.2.22", "vmnic0", "db01", "off", "Storage PG", "200-201"),
    ]
    assert parse_vm_info("") == []


def test_the_page_view_never_shows_the_password():
    view = parse_vmtracker(CONFIG, STATUS, INFO)
    (connection,) = view.of("connection")
    facts = dict(connection.facts)
    assert facts["vCenter"] == "192.0.2.50 port 443"
    assert facts["Login"] == "nxprobe-vcuser (password set)"
    assert facts["Makes VLANs"] == "no" and facts["State"] == "No Connect"
    assert "Xxxxxxx00000" not in repr(view)
    assert [i.title for i in view.of("port")] == ["Ethernet1/53"]
    assert [i.title for i in view.of("sync")] == ["nxprobe-vc"]
    assert view.of("global")[0].values == {"auto_config": {}}
    assert "did not show its configuration" in parse_vmtracker(None).notes[0]


def test_the_lines():
    ident = {"name": "vc1"}
    assert _lines("connection", "", "create", ident) == ["vmtracker connection vc1"]
    assert _lines("connection", "", "delete", ident) == ["no vmtracker connection vc1"]
    assert _lines(
        "connection",
        "remote",
        "set",
        ident,
        {"address": "192.0.2.50", "port": "443", "vrf": "management"},
    ) == [  # fmt: skip
        "vmtracker connection vc1",
        "remote ip address 192.0.2.50 port 443 vrf management",
    ]
    assert _lines("connection", "remote", "set", ident, {"address": "192.0.2.50"})[-1] == (
        "remote ip address 192.0.2.50"
    )
    made = build_vmtracker_change(
        "connection", "login", "set", ident,
        {"user": "administrator@vsphere.local", "password": "S3cret!x"},
    )  # fmt: skip
    assert made.lines[-1] == "username administrator@vsphere.local password 0 S3cret!x"
    assert "S3cret!x" not in " ".join(made.labels) and "S3cret!x" not in made.describe
    assert _lines("connection", "login", "remove", ident, {"user": "svc"})[-1] == (
        "no username svc password removed"
    )
    assert _lines("connection", "autovlan", "remove", ident)[-1] == "no autovlan enable"
    assert _lines("connection", "allowed_except", "set", ident, {"vlans": "300"})[-1] == (
        "allowed-vlans except 300"
    )
    assert (
        _lines("connection", "pending_task_polling", "remove", ident, {"seconds": "30"})[-1]
        == "no set interval pending-task-polling 30"
    )
    assert _lines("port", "tracking", "remove", {"port": "Ethernet1/5"}) == [
        "interface Ethernet1/5",
        "no vmtracker enable",
    ]
    assert _lines("sync", "refresh", "set", ident) == ["vmtracker connection vc1 refresh"]
    with pytest.raises(ValueError, match="from 1 to 65355"):
        build_vmtracker_change("connection", "pending_task_polling", "set", ident, {"seconds": "0"})
    with pytest.raises(ValueError, match="cannot be removed"):
        build_vmtracker_change("connection", "remote", "remove", ident, {})


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
    fake.feature_state["vmtracker"] = True
    fake.texts["show vmtracker info detail"] = INFO
    fake.l2_lines += [
        "vmtracker connection vc1",
        "vmtracker connection vc1 ; remote ip address 192.0.2.50 port 443 vrf management",
    ]
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
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/vmtracker/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/vmtracker", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/vmtracker"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/vmtracker")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "192.0.2.50 port 443" in text and "No Connect" in text and "web 01" in text
    assert enabled.requests == [
        list(PAGE_COMMANDS),
        ["show vmtracker status"],
        ["show vmtracker info detail"],
        ["show running-config"],
    ]


def test_with_the_feature_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["vmtracker"] = False
    assert "vmtracker is off on the switch" in _text(logged_in.get("/vmtracker").text)


def test_a_connection_is_set_up_without_showing_the_password(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    asked = _change(logged_in, confirm=False, scope="connection", setting="login", action="set",
                    id_name="vc1", v_user="administrator@vsphere.local",
                    v_password="S3cret!x")  # fmt: skip
    # The confirm page's form carries it back; it is never shown.
    assert "S3cret!x" not in _text(asked.text) and "password 0 ***" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, scope="connection", setting="login", action="set", id_name="vc1",
                   v_user="administrator@vsphere.local", v_password="S3cret!x")  # fmt: skip
    assert done.status_code == 200, _text(done.text)
    assert "S3cret!x" not in done.text
    assert "administrator@vsphere.local (password set)" in _text(done.text)
    vlans = _change(logged_in, scope="connection", setting="allowed_except", action="set",
                    id_name="vc1", v_vlans="300")  # fmt: skip
    assert vlans.status_code == 200, _text(vlans.text)
    assert "1-299,301-4094" in _text(vlans.text)
    off = _change(logged_in, scope="connection", setting="autovlan", action="remove",
                  id_name="vc1")  # fmt: skip
    assert off.status_code == 200, _text(off.text)
    assert "vmtracker connection vc1 ; no autovlan enable" in enabled.l2_lines
    port = _change(logged_in, scope="port", setting="tracking", action="remove",
                   id_port="Ethernet1/5")  # fmt: skip
    assert port.status_code == 200, _text(port.text)
    assert "interface Ethernet1/5 ; no vmtracker enable" in enabled.l2_lines


def test_a_new_connection_and_auto_config(logged_in: TestClient, enabled: FakeSwitch) -> None:
    made = _change(logged_in, scope="connection", action="create", id_name="vc2")
    assert made.status_code == 200, _text(made.text)
    assert "vmtracker connection vc2" in enabled.l2_lines
    refused = _change(logged_in, scope="global", setting="auto_config", action="set")
    assert refused.status_code == 400
    assert "fabric forwarding is enabled" in _text(refused.text)
    enabled.feature_state["hmm"] = True
    done = _change(logged_in, scope="global", setting="auto_config", action="set")
    assert done.status_code == 200, _text(done.text)
    assert "vmtracker fabric auto-config" in enabled.l2_lines


def test_a_fifth_connection_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.l2_lines += [f"vmtracker connection vc{n}" for n in (2, 3, 4)]
    refused = _change(logged_in, scope="connection", action="create", id_name="vc5")
    assert refused.status_code == 400 and "4 vCenter connections at most" in _text(refused.text)


def test_syncing_now_is_typed_outside_configuration_mode(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    done = _change(logged_in, scope="sync", setting="refresh", action="set", id_name="vc1")
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["vmtracker connection vc1 refresh"]]
    assert enabled.l2_ran == ["vmtracker connection vc1 refresh"]
    assert "Not saved yet" not in _text(done.text)


def test_the_broad_role_allows_syncing() -> None:
    assert set(VMTRACKER_REFRESH_RULES) <= set(BROAD_RULES)


def test_a_broad_role_written_before_syncing_is_refused_until_updated(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    for rule in VMTRACKER_REFRESH_RULES:
        enabled.roles[ROLE_NAME].entities.discard(rule.split(" command ", 1)[1])
    _db(settings, f"UPDATE switch_connection SET role_version = {BROAD_VMTRACKER_VERSION - 1}")
    refused = _change(logged_in, scope="sync", setting="refresh", action="set", id_name="vc1")
    assert refused.status_code == 400 and "Update the port list" in _text(refused.text)
    assert "allowed syncing a VM Tracker" in _text(logged_in.get("/switch").text)
    done = _change(logged_in, scope="connection", setting="connect", action="set", id_name="vc1")
    assert done.status_code == 200, _text(done.text)
    assert "Connected" in _text(done.text)


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    refused = _change(logged_in, scope="connection", action="create", id_name="vc2")
    assert refused.status_code == 400 and "VM Tracker changes are off" in _text(refused.text)
    assert _config_requests(switch) == []


def test_with_the_admin_login_stored_the_change_is_sent_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "stored")
    done = _change(logged_in, scope="connection", action="create", id_name="vc2")
    assert done.status_code == 200, _text(done.text)
    assert "admin" in switch.signed_in


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "vmtracker"})
    assert saved.status_code == 200
    assert "Add a vCenter connection" in _text(saved.text) and enabled.saved
