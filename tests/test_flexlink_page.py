"""The Flex Links page (#95), end to end against the fake switch, and its parsers.

The switch the fake stands for (a 92160YC-X) refuses Flex Links, as cisco-25gb did; the
tests that make pairs turn ``flexlink_supported`` on, as on a model Cisco's guide lists.
The pairs' text follows the guide's layout (not seen on a switch).
"""

from __future__ import annotations

import html
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.flexlink import (
    NOT_ON_9200,
    PAGE_COMMANDS,
    build_flexlink_change,
    model_note,
    parse_backup_state,
    parse_flexlink,
    parse_flexlink_config,
)
from tests.conftest import inventory_body
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

# Laid out as in Cisco's NX-OS 9.3 Layer 2 Switching guide.
STATE = """
Switch Backup Interface Pairs:

Active Interface        Backup Interface        State
------------------------------------------------------------------------
Ethernet1/1             Ethernet1/2             Active Down/Backup Down
port-channel10          port-channel20          Active Down/Backup Up
Po30                    Eth1/45                 Active Up/Backup Standby
"""
CONFIG = """
interface port-channel10
  switchport backup interface port-channel20 preemption mode forced
  switchport backup interface port-channel20 preemption delay 10
  switchport backup interface port-channel20
interface Ethernet1/1
  switchport backup interface Ethernet1/2
  switchport backup interface Ethernet1/2 multicast fast-convergence
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
    return list(build_flexlink_change(scope, setting, action, ident, values or {}).lines)


# ---- parsing and lines ----------------------------------------------------------------------


def test_the_pairs_are_read_from_the_configuration():
    pairs = {(p.port, p.backup): p.values for p in parse_flexlink_config(CONFIG)}
    assert pairs == {
        ("port-channel10", "port-channel20"): {
            "preemption_mode": {"mode": "forced"},
            "preemption_delay": {"seconds": "10"},
        },
        ("Ethernet1/1", "Ethernet1/2"): {"fast_convergence": {}},
    }


def test_the_state_rows_follow_the_heading():
    assert parse_backup_state(STATE) == [
        ("Ethernet1/1", "Ethernet1/2", "Active Down/Backup Down"),
        ("port-channel10", "port-channel20", "Active Down/Backup Up"),
        ("port-channel30", "Ethernet1/45", "Active Up/Backup Standby"),
    ]


def test_the_page_view():
    view = parse_flexlink(CONFIG, STATE)
    (pair, other) = view.of("pair")
    assert pair.title == "port-channel10 backed up by port-channel20"
    assert dict(pair.facts) == {
        "State": "Active Down/Backup Up",
        "Preemption": "forced",
        "Preemption delay": "10 seconds",
        "Multicast fast convergence": "off",
    }
    assert dict(other.facts)["Preemption delay"] == "not used"
    assert dict(other.facts)["Multicast fast convergence"] == "on"
    assert "did not show its configuration" in parse_flexlink(None, STATE).notes[0]


def test_the_model_note_is_for_a_nexus_9200_only():
    assert (
        model_note(inventory_body("Nexus9000 C92160YC-X chassis", "N9K-C92160YC-X")) == NOT_ON_9200
    )
    assert model_note(inventory_body("Nexus9000 C93180YC-EX chassis", "N9K-C93180YC-EX")) == ""
    assert model_note(None) == ""


def test_the_lines():
    ident = {"port": "Ethernet1/1", "backup": "Ethernet1/2"}
    assert _lines("pair", "", "create", ident) == [
        "interface Ethernet1/1",
        "switchport backup interface Ethernet1/2",
    ]
    assert _lines("pair", "", "delete", ident) == [
        "interface Ethernet1/1",
        "no switchport backup interface Ethernet1/2",
    ]
    assert _lines("pair", "preemption_mode", "set", ident, {"mode": "bandwidth"}) == [
        "interface Ethernet1/1",
        "switchport backup interface Ethernet1/2 preemption mode bandwidth",
    ]
    assert _lines("pair", "preemption_delay", "remove", ident, {"seconds": "10"}) == [
        "interface Ethernet1/1",
        "no switchport backup interface Ethernet1/2 preemption delay 10",
    ]
    assert _lines("pair", "fast_convergence", "set", ident) == [
        "interface Ethernet1/1",
        "switchport backup interface Ethernet1/2 multicast fast-convergence",
    ]
    with pytest.raises(ValueError, match="1 to 300"):
        build_flexlink_change("pair", "preemption_delay", "set", ident, {"seconds": "301"})
    with pytest.raises(ValueError, match="cannot be removed"):
        build_flexlink_change("pair", "preemption_mode", "remove", ident, {"mode": "off"})


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
    """A switch that does Flex Links, with the feature on and the broad role."""
    switch.flexlink_supported = True
    switch.feature_state["Flexlink"] = True
    return _enable(logged_in, settings, switch, "broad")


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/flexlink/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/flexlink", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/flexlink"' in logged_in.get("/").text


def test_on_a_nexus_9200_the_page_says_plainly_it_does_not_do_flex_links(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    # The limited role has the Features page's rules.
    _enable(logged_in, settings, switch, "limited")
    text = _text(logged_in.get("/flexlink").text)
    assert NOT_ON_9200 in text and "flexlink is off on the switch" in text
    assert switch.requests == [list(PAGE_COMMANDS)]
    # And the switch refuses the feature, as cisco-25gb did.
    refused = logged_in.post(
        "/features/set",
        data={"csrf": _csrf(logged_in), "name": "Flexlink", "state": "on", "confirm": "yes"},
    )
    alert = re.search(r'alert-error" role="alert">([^<]*)<', refused.text)
    assert alert and "Feature flexlink is not supported on this platform" in alert.group(1)
    assert not switch.feature_state.get("Flexlink")


def test_a_pair_is_made_set_and_deleted(logged_in: TestClient, enabled: FakeSwitch) -> None:
    asked = _change(logged_in, confirm=False, scope="pair", action="create",
                    id_port="Ethernet1/1", id_backup="Ethernet1/2")  # fmt: skip
    assert "switchport backup interface Ethernet1/2" in _text(asked.text)
    assert _config_requests(enabled) == []
    made = _change(logged_in, scope="pair", action="create", id_port="Ethernet1/1",
                   id_backup="Ethernet1/2")  # fmt: skip
    assert made.status_code == 200, _text(made.text)
    assert "interface Ethernet1/1 ; switchport backup interface Ethernet1/2" in enabled.l2_lines
    text = _text(made.text)
    assert "Ethernet1/1 backed up by Ethernet1/2" in text and "Active Down/Backup Down" in text
    mode = _change(logged_in, scope="pair", setting="preemption_mode", action="set",
                   id_port="Ethernet1/1", id_backup="Ethernet1/2", v_mode="forced")  # fmt: skip
    assert mode.status_code == 200, _text(mode.text)
    line = "switchport backup interface Ethernet1/2 preemption mode forced"
    assert ["interface Ethernet1/1", line] in enabled.requests
    assert "Preemption forced" in _text(mode.text)
    gone = _change(logged_in, scope="pair", action="delete", id_port="Ethernet1/1",
                   id_backup="Ethernet1/2")  # fmt: skip
    assert gone.status_code == 200, _text(gone.text)
    assert not any("switchport backup" in line for line in enabled.l2_lines)


def test_a_port_the_switch_lacks_or_backing_itself_is_refused(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    same = _change(logged_in, scope="pair", action="create", id_port="Ethernet1/1",
                   id_backup="Ethernet1/1")  # fmt: skip
    assert same.status_code == 400 and "its own backup" in _text(same.text)
    missing = _change(logged_in, scope="pair", action="create", id_port="Ethernet1/1",
                      id_backup="port-channel999")  # fmt: skip
    assert missing.status_code == 400 and "no layer 2 port port-channel999" in _text(missing.text)
    assert _config_requests(enabled) == []


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    switch.flexlink_supported = True
    switch.feature_state["Flexlink"] = True
    _enable(logged_in, settings, switch, "limited")
    refused = _change(logged_in, scope="pair", action="create", id_port="Ethernet1/1",
                      id_backup="Ethernet1/2")  # fmt: skip
    assert refused.status_code == 400 and "Flex Links changes are off" in _text(refused.text)
    assert _config_requests(switch) == []


def test_with_the_admin_login_stored_the_change_is_sent_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    switch.flexlink_supported = True
    switch.feature_state["Flexlink"] = True
    _enable(logged_in, settings, switch, "stored")
    done = _change(logged_in, scope="pair", action="create", id_port="Ethernet1/1",
                   id_backup="Ethernet1/2")  # fmt: skip
    assert done.status_code == 200, _text(done.text)
    assert "admin" in switch.signed_in


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "flexlink"})
    assert saved.status_code == 200
    assert "Make a Flex Link pair" in _text(saved.text) and enabled.saved
