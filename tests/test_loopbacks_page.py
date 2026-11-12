"""The Loopbacks page (#82), end to end against the fake switch, and its parser."""

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
from app.loopbacks import COMMANDS, build_loopback_change, parse_loopback_view, parse_loopbacks
from app.port_changes import LOOPBACK_PERMIT, ROLE_NAME, role_lines
from app.switch_connection import BROAD_LOOPBACK_VERSION, ROLE_BROAD, ROLE_LIMITED
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"


def _body(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def _recorded() -> list[dict]:
    """The page's five bodies as recorded on cisco-25gb with two throwaway loopbacks."""
    return [
        _body("show_interface_brief_loopbacks"),
        _body("show_ip_interface_vrf_all_loopbacks"),
        _body("show_ipv6_interface_vrf_all_loopbacks"),
        _body("show_vrf"),
        _body("show_vrf_interface_loopbacks"),
    ]


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


# ---- parsing and lines --------------------------------------------------------------------


def test_the_recorded_output_gives_each_loopback() -> None:
    first, second = parse_loopbacks(_recorded())
    assert (first.number, first.up, first.description, first.vrf) == (
        250,
        True,
        "nxprobe lo",
        "default",
    )
    assert first.ipv4 == ("198.51.100.250/32", "198.51.100.251/32")
    assert first.ipv6 == ("2001:db8:250::1/128",)
    # Turned off, in a VRF: "down" in show interface brief, as recorded.
    assert (second.number, second.up, second.vrf, second.ipv4) == (
        251,
        False,
        "lab",
        ("198.51.100.252/32",),
    )
    place = parse_loopback_view(_recorded()).of("loopback")[0]
    assert place.ident == {"number": "250"} and place.title == "loopback250"
    assert place.values["ipv4"] == {"address": "198.51.100.250/32"}
    assert dict(place.facts)["IPv4"] == "198.51.100.250/32, 198.51.100.251/32"


def test_no_loopback_gives_an_empty_page() -> None:
    assert parse_loopbacks([_body("show_interface_brief"), {}, {}, {}, {}]) == []
    assert len(COMMANDS) == 5


def test_the_lines() -> None:
    def lines(setting: str, action: str, number: str = "0", **values: str) -> tuple[str, ...]:
        return build_loopback_change("loopback", setting, action, {"number": number}, values).lines

    assert lines("", "create", "7") == ("interface loopback7",)
    assert lines("", "delete", "7") == ("no interface loopback7",)
    assert lines("description", "set", text="router id") == (
        "interface loopback0",
        "description router id",
    )
    assert lines("description", "remove") == ("interface loopback0", "no description")
    assert lines("ipv4", "set", address="192.0.2.1/32") == (
        "interface loopback0",
        "ip address 192.0.2.1/32",
    )
    assert lines("ipv4", "remove", address="192.0.2.1/32")[-1] == "no ip address 192.0.2.1/32"
    assert lines("ipv4_secondary", "set", address="192.0.2.2/32")[-1] == (
        "ip address 192.0.2.2/32 secondary"
    )
    assert lines("ipv4_secondary", "remove", address="192.0.2.2/32")[-1] == (
        "no ip address 192.0.2.2/32 secondary"
    )
    assert lines("ipv6", "set", address="2001:db8::1/128")[-1] == "ipv6 address 2001:db8::1/128"
    assert lines("vrf", "set", vrf="lab")[-1] == "vrf member lab"
    assert lines("vrf", "remove", vrf="lab")[-1] == "no vrf member lab"
    assert lines("admin_down", "set")[-1] == "shutdown"
    assert lines("admin_up", "set")[-1] == "no shutdown"
    assert build_loopback_change(
        "loopback", "vrf", "set", {"number": "0"}, {"vrf": "lab"}
    ).warning.startswith("The switch deletes every address")


@pytest.mark.parametrize(
    ("setting", "number", "values"),
    [
        ("description", "1024", {"text": "x"}),  # loopbacks go to 1023, as on the switch
        ("ipv4", "0", {"address": "198.51.100.0/24"}),  # the network's own address
        ("ipv4", "0", {"address": "192.0.2.1"}),  # no prefix length
        ("ipv6", "0", {"address": "fe80::1/64"}),  # link-local: the switch makes one
        ("ipv4", "0", {"address": "2001:db8::1/128"}),  # IPv6 in the IPv4 form
        ("vrf", "0", {"vrf": "management"}),
        ("vrf", "0", {"vrf": "default"}),
    ],
)
def test_wrong_values_are_refused(setting: str, number: str, values: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        build_loopback_change("loopback", setting, "set", {"number": number}, values)


def test_the_broad_role_names_the_loopbacks_and_leaving_it_takes_them_out() -> None:
    ports = ["Ethernet1/1"]
    assert LOOPBACK_PERMIT in role_lines(ports, "nxray", mode=ROLE_BROAD)
    assert LOOPBACK_PERMIT not in role_lines(ports, "nxray", mode=ROLE_LIMITED)
    leaving = role_lines(ports, "nxray", mode=ROLE_LIMITED, previous_mode=ROLE_BROAD)
    assert f"no {LOOPBACK_PERMIT}" in leaving and LOOPBACK_PERMIT not in leaving
    assert f"no {LOOPBACK_PERMIT}" not in role_lines(
        ports, "nxray", mode=ROLE_BROAD, previous_mode=ROLE_BROAD
    )


# ---- the page -----------------------------------------------------------------------------


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
    fake.port_state["loopback0"] = {
        "routed": True,
        "admin_up": True,
        "loopback": True,
        "desc": "router id",
        "ip": "192.0.2.1/32",
    }
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
    return client.post("/loopbacks/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/loopbacks", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/loopbacks"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/loopbacks")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "loopback0" in text and "router id" in text and "192.0.2.1/32" in text
    assert switch.requests == [list(COMMANDS)]
    assert "/loopbacks/change" not in page.text  # changes are off


def test_the_broad_role_names_the_loopbacks_on_the_switch(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    assert LOOPBACK_PERMIT.removeprefix("permit interface ") in enabled.roles[ROLE_NAME].interfaces


def test_making_a_loopback_asks_first_then_sends(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    fields = {"scope": "loopback", "action": "create", "id_number": "250"}
    asked = _change(logged_in, confirm=False, **fields)
    assert "interface loopback250" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["interface loopback250"]]
    assert "loopback250" in enabled.port_state
    assert "loopback250" in _text(done.text)


def test_addresses_and_deleting(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(
        logged_in,
        scope="loopback",
        setting="ipv4_secondary",
        action="set",
        id_number="0",
        v_address="192.0.2.2/32",
    )
    assert done.status_code == 200, _text(done.text)
    assert enabled.port_state["loopback0"]["secondaries"] == ["192.0.2.2/32"]
    assert "192.0.2.1/32, 192.0.2.2/32" in _text(done.text)
    gone = _change(logged_in, scope="loopback", action="delete", id_number="0")
    assert gone.status_code == 200, _text(gone.text)
    assert "loopback0" not in enabled.port_state
    assert _config_requests(enabled)[-1] == ["no interface loopback0"]


def test_a_switch_error_is_shown(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _change(
        logged_in,
        scope="loopback",
        setting="ipv4_secondary",
        action="set",
        id_number="9",
        v_address="192.0.2.9/32",
    )
    assert refused.status_code == 400
    assert "Configure the primary address first" in _text(refused.text)


def test_a_broad_role_written_before_the_loopbacks_is_refused_until_updated(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    enabled.roles[ROLE_NAME].interfaces.discard("loopback0-1023")
    _db(settings, f"UPDATE switch_connection SET role_version = {BROAD_LOOPBACK_VERSION - 1}")
    refused = _change(logged_in, scope="loopback", action="create", id_number="250")
    assert refused.status_code == 400 and "Update the port list" in _text(refused.text)
    assert _config_requests(enabled) == []
    assert "written before it named the loopbacks" in _text(logged_in.get("/switch").text)
    # Not a security problem, so no warning on the other pages.
    assert "loopbacks" not in _text(logged_in.get("/vlans").text)

    updated = logged_in.post(
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
    assert "The role now also names the loopbacks" in _text(updated.text)
    assert "loopback0-1023" in enabled.roles[ROLE_NAME].interfaces
    done = _change(logged_in, scope="loopback", action="create", id_number="250")
    assert done.status_code == 200, _text(done.text)


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "loopbacks"})
    assert saved.status_code == 200
    assert "Make a loopback" in _text(saved.text) and enabled.saved


def test_with_the_admin_login_stored_the_change_is_sent_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    # The stored mode's own account has only the limited rules, which name no loopback.
    _enable(logged_in, settings, switch, "stored")
    done = _change(logged_in, scope="loopback", setting="admin_down", action="set", id_number="0")
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(switch) == [["interface loopback0", "shutdown"]]
    assert "admin" in switch.signed_in
    assert switch.port_state["loopback0"]["admin_up"] is False


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    refused = _change(logged_in, scope="loopback", action="create", id_number="250")
    assert refused.status_code == 400 and "Loopback changes are off" in _text(refused.text)
    assert _config_requests(switch) == []
