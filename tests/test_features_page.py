"""The Features page: listing every feature, and turning one on or off (admins only)."""

from __future__ import annotations

import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


def _csrf(client: TestClient, path: str = "/switch") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).replace("&#39;", "'")


def _db(settings: Settings, sql: str) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(sql)
    conn.commit()
    conn.close()


def _enable(client: TestClient):
    return client.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(client),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    """A switch that has been set up (read-only account nxray)."""
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": _csrf(logged_in),
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
    """All changes on, and the wait already over."""
    assert _enable(logged_in).status_code == 200
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    switch.requests.clear()
    switch.saved = False
    return switch


def _set(client: TestClient, name: str, state: str, confirm: bool = False):
    # The account page always has a form, whatever the role and the switch.
    data = {"csrf": _csrf(client, "/account"), "name": name, "state": state}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/features/set", data=data)


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


def _sign_in_as(client: TestClient, name: str, role: str) -> TestClient:
    password = "another-long-password"
    client.post(
        "/users/create",
        data={
            "csrf": _csrf(client, "/users"),
            "new_username": name,
            "password": password,
            "confirm_password": password,
            "role": role,
        },
    )
    other = TestClient(client.app, follow_redirects=False)
    response = other.post("/login", data={"username": name, "password": password, "next": "/"})
    assert response.status_code == 303
    return other


# ---- looking ----------------------------------------------------------------


def test_features_page_lists_groups_and_states(logged_in: TestClient, switch: FakeSwitch) -> None:
    text = _text(logged_in.get("/features").text)
    assert "On now: icam , lacp , nxapi , ssh ." in text
    for group in ("Routing and layer 3", "Layer 2", "Management and access", "Other"):
        assert group in text
    assert "LLDP: announces the switch" in text
    assert "Used by port-channel43 (Ethernet1/43, Ethernet1/44)." in text
    assert "Feature changes are off" in text
    assert "Turn on" not in text.replace("Turn them on", "")
    assert switch.requests == [
        ["show feature", "show port-channel summary", "show interface brief"]
    ]


def test_features_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in logged_in.get("/features").text


def test_nav_has_features(logged_in: TestClient, switch: FakeSwitch) -> None:
    assert 'href="/features"' in logged_in.get("/").text


def test_viewers_and_operators_look_but_get_no_buttons(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    for name, role in (("vera", "viewer"), ("otto", "operator")):
        other = _sign_in_as(logged_in, name, role)
        page = _text(other.get("/features").text)
        assert "lacp" in page and "Turn off" not in page and "Turn on" not in page
        assert f"Your role ({role}) can look at features but not change them" in page
        response = other.post(
            "/features/set",
            data={"csrf": _csrf(other, "/account"), "name": "lldp", "state": "on"},
        )
        assert response.status_code == 403
    assert _config_requests(enabled) == []


def test_buttons_follow_what_may_change(logged_in: TestClient, enabled: FakeSwitch) -> None:
    html = logged_in.get("/features").text
    text = _text(html)
    # LLDP may be turned on; lacp is used by port-channel43; nxapi and ssh are kept on.
    assert re.search(
        r'name="name" value="lldp">\s*<input type="hidden" name="state" value="on">', html
    )
    assert 'name="name" value="lacp"' not in html
    assert "in use: remove what uses it first" in text
    assert 'name="name" value="nxapi"' not in html and 'name="name" value="sshServer"' not in html
    assert "kept on: NXray needs it" in text
    assert 'name="name" value="icam"' not in html and "not changed from NXray" in text


# ---- changing ---------------------------------------------------------------


def test_turning_on_asks_first_then_turns_it_on(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    asked = _text(_set(logged_in, "lldp", "on").text)
    assert "Confirm the change" in asked and "Turn on lldp." in asked
    assert "announcing itself on every port" in asked
    assert _config_requests(enabled) == []

    done = _text(_set(logged_in, "lldp", "on", confirm=True).text)
    assert "Done: lldp is on. Not saved yet" in done
    assert _config_requests(enabled) == [["feature lldp"]]
    assert enabled.lldp
    assert "On now: icam , lacp , lldp , nxapi , ssh ." in done
    assert "NXray changed the switch since its configuration was last saved" in done
    assert not enabled.saved
    conn = sqlite3.connect(settings.db_path)
    (unsaved,) = conn.execute("SELECT unsaved_changes FROM switch_connection").fetchone()
    conn.close()
    assert unsaved == 1


def test_turning_off_warns_that_settings_go(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.feature_state["scheduler"] = True
    asked = _text(_set(logged_in, "scheduler", "off").text)
    assert "Turn off scheduler." in asked and "deletes all of its settings" in asked
    done = _text(_set(logged_in, "scheduler", "off", confirm=True).text)
    assert "Done: scheduler is off." in done
    assert _config_requests(enabled) == [["no feature scheduler"]]
    assert enabled.feature_state["scheduler"] is False


def test_two_word_feature_command(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _set(logged_in, "sla_sender", "on", confirm=True)
    assert _config_requests(enabled) == [["feature sla sender"]]


def test_lacp_used_by_a_port_channel_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = _set(logged_in, "lacp", "off", confirm=True)
    assert response.status_code == 400
    text = _text(response.text)
    assert "Not turned off: port-channel43 (Ethernet1/43, Ethernet1/44) still uses lacp" in text
    assert _config_requests(enabled) == []


@pytest.mark.parametrize("name", ["nxapi", "sshServer"])
def test_nxapi_and_ssh_are_never_turned_off(
    logged_in: TestClient, enabled: FakeSwitch, name: str
) -> None:
    response = _set(logged_in, name, "off", confirm=True)
    assert response.status_code == 400
    assert _config_requests(enabled) == []


def test_feature_without_a_command_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = _set(logged_in, "icam", "off", confirm=True)
    assert response.status_code == 400
    assert "has no feature command on this switch" in _text(response.text)
    assert _config_requests(enabled) == []


@pytest.mark.parametrize("name", ["made-up", "lldp ; reload", ""])
def test_unknown_names_are_refused(logged_in: TestClient, enabled: FakeSwitch, name: str) -> None:
    response = _set(logged_in, name, "on", confirm=True)
    assert response.status_code == 400
    assert _config_requests(enabled) == []


def test_bad_state_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    assert _set(logged_in, "lldp", "maybe", confirm=True).status_code == 400
    assert _config_requests(enabled) == []


def test_already_on_changes_nothing(logged_in: TestClient, enabled: FakeSwitch) -> None:
    text = _text(_set(logged_in, "lacp", "on", confirm=True).text)
    assert "lacp is already on." in text
    assert _config_requests(enabled) == []


def test_refused_while_feature_changes_are_off(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 3")
    response = _set(logged_in, "lldp", "on", confirm=True)
    assert response.status_code == 400
    assert "Feature changes are off" in _text(response.text)
    assert _config_requests(enabled) == []


def test_switch_refusal_is_shown(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.reject.add("feature lldp")
    response = _set(logged_in, "lldp", "on", confirm=True)
    assert response.status_code == 400
    assert "Not turned on:" in _text(response.text)
    assert not enabled.lldp


def test_save_config_from_the_features_page_stays_there(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    _set(logged_in, "lldp", "on", confirm=True)
    response = logged_in.post(
        "/switch/save", data={"csrf": _csrf(logged_in, "/features"), "back": "features"}
    )
    text = _text(response.text)
    assert "Saved: the switch keeps its current configuration on restart." in text
    assert "On now:" in text  # the Features page, not the Switch page
    assert enabled.saved


# ---- the Switch page --------------------------------------------------------


def test_old_role_offers_feature_changes_without_a_wait(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 3")
    page = _text(logged_in.get("/switch").text)
    assert (
        "Turn on feature, neighbor, port-channel and VLAN interface changes" in page
        and "There is no wait this time" in page
    )
    assert "Off: this version of NXray can also turn switch features on and off" in page
    assert "read, plus port changes, VLANs and port settings" in page

    text = _text(_enable(logged_in).text)
    assert (
        "Feature, neighbor, port-channel and VLAN interface changes are on: nxray may now "
        "also turn switch features on and off on the Features page, turn CDP and LLDP on or off"
        in text
    )
    assert "The switch applies this at once, so there is no wait." in text
    assert "rule 28 permit command conf t ; feature *" in enabled.ssh_lines
    assert "rule 29 permit command conf t ; no feature *" in enabled.ssh_lines
    page = _text(logged_in.get("/switch").text)
    assert (
        "read, plus port changes, VLANs, port settings, features, CDP, LLDP, the MAC "
        "address table, port-channels and VLAN interfaces" in page
    )
    assert "Update the port list" in page
    assert _set(logged_in, "lldp", "on", confirm=True).status_code == 200
    assert enabled.lldp


def test_fresh_account_without_the_feature_rules_is_refused_by_the_switch(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    """The fake switch enforces the role: without rules 28 and 29 it refuses."""
    enabled.roles["nxray-ports"].entities.discard("conf t ; feature *")
    response = _set(logged_in, "lldp", "on", confirm=True)
    assert response.status_code == 400
    assert "NXray's account may not make this change yet" in _text(response.text)
    assert not enabled.lldp
