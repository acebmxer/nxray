"""The Call Home page (#77), end to end against the fake switch, and its parsers."""

from __future__ import annotations

import html
import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.callhome import (
    build_callhome_change,
    config_lines,
    parse_callhome,
    parse_label_lines,
    parse_profiles,
)
from app.config import Settings
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"
STATUS = (FIXTURES / "show_callhome.txt").read_text()
PROFILES = (FIXTURES / "show_callhome_destination-profile.txt").read_text()
TRANSPORT = (FIXTURES / "show_callhome_transport.txt").read_text()
CONFIG = (FIXTURES / "show_running-config_callhome.txt").read_text()


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


# ---- parsing ------------------------------------------------------------------------------


def test_profiles_are_read_with_their_lists() -> None:
    profiles = {p.name: p for p in parse_profiles(PROFILES)}
    assert set(profiles) == {"noc", "full_txt", "short_txt", "CiscoTAC-1"}
    noc = profiles["noc"]
    assert noc.emails == ["1: noc@example.net", "2: team@example.net"]
    assert noc.urls == ["1: https://example.net/callhome"]
    assert noc.groups == ["environmental", "syslog-group-port"]
    assert noc.values["message-level"] == "5"
    assert profiles["CiscoTAC-1"].groups == ["cisco-tac"]


def test_the_page_view() -> None:
    view = parse_callhome(STATUS, PROFILES, TRANSPORT, CONFIG)
    (switch,) = view.of("callhome")
    assert switch.title == "Call Home is off"
    assert switch.values["email"] == {"email": "noc@example.net"}
    assert switch.values["phone"] == {"phone": "+15550100"}
    assert "enable" not in switch.values
    (transport,) = view.of("transport")
    assert transport.values["proxy"] == {"server": "192.0.2.11", "port": "8080"}
    assert transport.values["http_vrf"] == {"vrf": "management"}
    noc = next(i for i in view.of("profile") if i.ident == {"profile": "noc"})
    assert noc.values == {
        "format": {"format": "full-txt"},
        "level": {"level": "5"},
        "size": {"size": "100000"},
    }
    assert view.tables[0].rows == (("192.0.2.10", "port 25 priority 60 use-vrf management"),)
    # The switch's own profiles go by their line names and offer no Delete.
    assert [i.ident["profile"] for i in view.of("builtin_profile")] == [
        "full-txt-destination",
        "short-txt-destination",
        "CiscoTAC-1",
    ]
    assert [i.ident["profile"] for i in view.of("profile")] == ["noc"]
    assert ("switch priority", "7") in parse_label_lines(STATUS)
    assert config_lines(CONFIG)[0] == "contract-id K-2002"


def test_the_lines() -> None:
    def lines(scope: str, setting: str, action: str, ident=None, **values: str):
        return build_callhome_change(scope, setting, action, ident or {}, values).lines

    assert lines("callhome", "email", "set", email="noc@example.net") == (
        "callhome",
        "email-contact noc@example.net",
    )
    assert lines("callhome", "email", "remove") == ("callhome", "no email-contact")
    assert lines("callhome", "street", "set", value="1 Example Street") == (
        "callhome",
        "streetaddress 1 Example Street",
    )
    assert lines("profile", "email", "set", {"profile": "noc"}, index="3", email="a@b.net") == (
        "callhome",
        "destination-profile noc index 3 email-addr a@b.net",
    )
    assert (
        lines("profile", "url", "set", {"profile": "noc"}, index="1", url="https://x.net/p")[-1]
        == "destination-profile noc index 1 http https://x.net/p"
    )
    assert (
        lines("transport", "mail_server", "set", server="192.0.2.25", vrf="management")[-1]
        == "transport email mail-server 192.0.2.25 use-vrf management"
    )
    assert lines("transport", "mail_server", "remove", server="192.0.2.25")[-1] == (
        "no transport email mail-server 192.0.2.25"
    )
    assert (
        lines(
            "builtin_profile", "email", "set", {"profile": "CiscoTAC-1"}, index="1", email="a@b.net"
        )[-1]
        == "destination-profile CiscoTAC-1 index 1 email-addr a@b.net"
    )
    with pytest.raises(ValueError):
        build_callhome_change("profile", "", "delete", {"profile": "CiscoTAC-1"}, {})
    with pytest.raises(ValueError):
        build_callhome_change("builtin_profile", "", "delete", {"profile": "CiscoTAC-1"}, {})
    deleted = build_callhome_change("profile", "", "delete", {"profile": "noc"}, {})
    assert deleted.lines == ("callhome", "no destination-profile noc")
    test = build_callhome_change("callhome", "test", "set", {}, {})
    assert test.lines == ("callhome", "callhome test") and not test.config
    for bad in (
        ("callhome", "email", {"email": "not an address"}),
        ("callhome", "phone", {"phone": "555 0100"}),
        ("profile", "url", {"index": "1", "url": "ftp://x.net/"}),
        ("profile", "level", {"level": "10"}),
    ):
        with pytest.raises(ValueError):
            build_callhome_change(bad[0], bad[1], "set", {"profile": "noc"}, bad[2])


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
    fake.texts["show callhome"] = STATUS
    fake.texts["show callhome destination-profile"] = PROFILES
    fake.texts["show callhome transport"] = TRANSPORT
    fake.requests.clear()
    return fake


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
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
    conn = sqlite3.connect(settings.db_path)
    conn.execute(f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    conn.commit()
    conn.close()
    switch.requests.clear()
    return switch


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/callhome/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/callhome", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/callhome"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/callhome")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "Call Home is off" in text and "CiscoTAC-1" in text and "team@example.net" in text
    assert switch.requests == [
        ["show vrf"],
        ["show callhome"],
        ["show callhome destination-profile"],
        ["show callhome transport"],
        ["show running-config callhome"],
    ]


def test_contact_and_profile_changes_are_sent_inside_callhome(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    fields = {"scope": "callhome", "setting": "email", "action": "set", "v_email": "a@b.net"}
    asked = _change(logged_in, confirm=False, **fields)
    assert "email-contact a@b.net" in _text(asked.text)
    assert _config_requests(enabled) == []
    assert _change(logged_in, **fields).status_code == 200
    done = _change(
        logged_in,
        scope="profile",
        setting="make",
        action="set",
        id_profile="team",
    )
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [
        ["callhome", "email-contact a@b.net"],
        ["callhome", "destination-profile team"],
    ]
    assert enabled.callhome_lines == [
        "callhome ; email-contact a@b.net",
        "callhome ; destination-profile team",
    ]


def test_turning_it_on_warns_first(logged_in: TestClient, enabled: FakeSwitch) -> None:
    asked = _change(logged_in, confirm=False, scope="callhome", setting="enable", action="set")
    assert "starts sending messages" in _text(asked.text)
    assert _config_requests(enabled) == []


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "callhome"})
    assert saved.status_code == 200 and "Destination profiles" in _text(saved.text)
