"""The EEM page (#72), end to end against the fake switch, and its parsers. EEM changes
need the stored admin login: an applet's commands run as the switch's admin."""

from __future__ import annotations

import html
import json
import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.command_menu import PORT_OFF, SAVE
from app.config import Settings
from app.eem import build_eem_change, parse_eem, parse_eem_config, parse_history
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"
CONFIG = (FIXTURES / "show_running-config_eem.txt").read_text()


def _body(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


# ---- parsing and lines ---------------------------------------------------------------


def test_applets_and_variables_are_read() -> None:
    applets, variables = parse_eem_config(CONFIG)
    assert [(a.name, a.policy) for a in applets] == [("hello", ""), ("port-watch", "")]
    assert applets[1].lines[0] == 'event syslog pattern "LINK-3-UPDOWN"'
    assert variables == [("notify", "noc@example.net")]
    history = _body("show_event_manager_history_events")["history-events"]
    rows = parse_history(history)
    assert rows[0] == ("10/26/2026 22:14:11", "cli", "__syslog_trigger_default")
    assert rows[-1] == ("05/05/2023 07:51:36", "cli", "write_memory")


def test_the_page_view() -> None:
    bodies = [
        {},
        _body("show_event_manager_system-policy"),
        _body("show_event_manager_history_events"),
    ]
    view = parse_eem(bodies, CONFIG)
    watch = next(i for i in view.of("applet") if i.ident["applet"] == "port-watch")
    facts = dict(watch.facts)
    assert facts["Event"] == 'event syslog pattern "LINK-3-UPDOWN"'
    assert facts["Actions"].startswith("action 1.0 cli conf t; action 2.0 cli interface")
    (variable,) = view.of("environment")
    assert variable.values == {"value": {"value": "noc@example.net"}}
    policies = view.tables[1].rows
    assert policies[0][0] == "__BootupPortLoopback" and policies[0][2] == "Yes"


def test_the_lines() -> None:
    def change(setting: str, action: str = "set", ident=None, **values: str):
        return build_eem_change("applet", setting, action, ident or {"applet": "a"}, values)

    assert change("log", label="1", priority="warnings", msg="port down").lines == (
        "event manager applet a",
        "action 1 syslog priority warnings msg port down",
    )
    assert change("syslog", pattern="LINK-3-UPDOWN").lines[-1] == (
        'event syslog pattern "LINK-3-UPDOWN"'
    )
    assert change("log", "remove", label="1").lines[-1] == "no action 1"
    run = change("run", label="5", command=PORT_OFF, port="Ethernet1/5")
    assert run.lines == (
        "event manager applet a",
        "action 5.1 cli configure terminal",
        "action 5.2 cli interface Ethernet1/5",
        "action 5.3 cli shutdown",
    )
    assert change("run", label="2.0", command=SAVE).lines[-1] == (
        "action 2.0 cli copy running-config startup-config"
    )
    with pytest.raises(ValueError):
        change("run", label="5.1", command=PORT_OFF, port="Ethernet1/5")
    with pytest.raises(ValueError):
        change("run", label="1", command="username x role network-admin")
    with pytest.raises(ValueError):
        change("description", text='say "hi"')
    override = build_eem_change(
        "applet", "", "create", {"applet": "flap", "policy": "__ethpm_link_flap"}, {}
    )
    assert override.lines == ("event manager applet flap override __ethpm_link_flap",)
    variable = build_eem_change("environment", "value", "set", {"name": "to"}, {"value": "a b"})
    assert variable.lines == ('event manager environment to "a b"',)


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
    fake.eem_lines.extend(
        [
            "event manager applet hello",
            "event manager applet hello ; action 1 syslog msg hi",
        ]
    )
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
    conn = sqlite3.connect(settings.db_path)
    conn.execute(f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    conn.commit()
    conn.close()
    fake.requests.clear()
    fake.signed_in.clear()
    return fake


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/eem/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/eem", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/eem"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/eem")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "hello" in text and "action 1 syslog msg hi" in text and "__ethpm_link_flap" in text
    assert switch.requests == [
        [
            "show interface brief",
            "show event manager system-policy",
            "show event manager history events",
        ],
        ["show running-config eem"],
    ]
    assert "/eem/change" not in page.text  # changes are off


def test_the_broad_role_cannot_change_eem(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "broad")
    refused = _change(logged_in, scope="applet", action="create", id_applet="x")
    assert refused.status_code == 400 and "need the stored admin login" in _text(refused.text)
    assert _config_requests(switch) == []


def test_with_the_admin_login_stored_an_action_is_sent_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "stored")
    fields = {
        "scope": "applet",
        "setting": "run",
        "action": "set",
        "id_applet": "hello",
        "v_label": "2",
        "v_command": SAVE,
    }
    asked = _change(logged_in, confirm=False, **fields)
    assert "action 2 cli copy running-config startup-config" in _text(asked.text)
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(switch) == [
        ["event manager applet hello", "action 2 cli copy running-config startup-config"]
    ]
    # NXray's own account has only the limited rules here, which the fake switch holds to:
    # the line went through because it was sent with the admin login.
    assert "admin" in switch.signed_in


def test_save_config_comes_back_here(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "stored")
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "eem"})
    assert saved.status_code == 200 and "System policies" in _text(saved.text)
