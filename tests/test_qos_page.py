"""The QoS page, end to end against the fake switch: reading it, who may change it, and a
change from asking to sent."""

from __future__ import annotations

import html
import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from tests.conftest import load_fixture
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


def _setup_form(client: TestClient, **extra: str) -> dict[str, str]:
    return {
        "csrf": _csrf(client, "/switch"),
        "host": "192.0.2.10",
        "port": "443",
        "admin_user": "admin",
        "admin_password": ADMIN_PASSWORD,
        "account_name": "nxray",
        "confirm_save": "yes",
        **extra,
    }


BODIES = {
    "show class-map type qos": "show_class_map_type_qos",
    "show policy-map type qos": "show_policy_map_type_qos",
    "show class-map type network-qos": "show_class_map_type_network_qos",
    "show policy-map type network-qos": "show_policy_map_type_network_qos",
    "show policy-map type queuing": "show_policy_map_type_queuing",
    "show policy-map interface brief": "show_policy_map_interface_brief",
    "show policy-map system": "show_policy_map_system",
    "show queuing interface": "show_queuing_interface",
}


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    """A switch that has been set up (read-only account nxray), with some QoS made."""
    fake = FakeSwitch()
    for command, name in BODIES.items():
        fake.bodies[command] = load_fixture(name)
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post("/switch/setup", data=_setup_form(logged_in))
    fake.requests.clear()
    return fake


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    """Changes on with the broad role, and the wait over."""
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
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    switch.requests.clear()
    switch.saved = False
    return switch


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/qos/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/qos", follow_redirects=False).status_code == 303


def test_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/qos").text)


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/qos"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/qos")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "Class-map nxprobe-voice" in text and "Policy-map nxprobe-pm" in text
    assert "dscp 46" in text and "Ethernet1/53" in text
    assert "Policy-map nxprobe-qpm" in text and "Policy-map nxprobe-npm" in text
    assert "Packets dropped" in text and "1200" in text
    assert "default-8q-out-policy" in text  # in the switch's own policies
    assert switch.requests[0][0] == "show interface brief"
    assert "/qos/change" not in page.text  # changes are off


def test_nothing_made_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    for command in ("show class-map type qos", "show policy-map type qos"):
        switch.bodies[command] = {}
    text = _text(logged_in.get("/qos").text)
    assert "None on the switch." in text and "Class-map nxprobe-voice" not in text


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    switch.requests.clear()
    assert "QoS changes are off" in _text(logged_in.get("/qos").text)
    refused = _change(logged_in, scope="policy", action="create", id_policy="p")
    assert refused.status_code == 400
    assert "QoS changes are off" in _text(refused.text)
    assert _config_requests(switch) == []


def test_enabled_page_offers_the_settings(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/qos")
    for setting in ("match_dscp", "set_qos_group", "police", "service_policy", "queue_limit"):
        assert f'name="setting" value="{setting}"' in page.text
    assert '<option value="Ethernet1/1"' in page.text
    assert '<option value="c-out-8q-q3"' in page.text


def test_make_a_policy_asks_first_then_sends(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {"scope": "policy", "action": "create", "id_policy": "web"}
    asked = _change(logged_in, confirm=False, **fields)
    assert asked.status_code == 200
    assert "policy-map type qos web" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["policy-map type qos web"]]
    assert enabled.qos_lines == ["policy-map type qos web"]


def test_a_class_map_with_a_match_and_a_class_in_a_policy(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    make = _change(logged_in, scope="cmap", action="create", id_cmap="web", id_mode="match-any")
    assert make.status_code == 200, _text(make.text)
    match = _change(
        logged_in,
        scope="cmap",
        setting="match_dscp",
        action="set",
        id_cmap="web",
        id_mode="match-any",
        v_values="46",
    )
    assert match.status_code == 200, _text(match.text)
    added = _change(
        logged_in, scope="pclass", action="create", id_policy="nxprobe-pm", id_class="nxprobe-voice"
    )
    assert added.status_code == 200, _text(added.text)
    mark = _change(
        logged_in,
        scope="pclass",
        setting="set_qos_group",
        action="set",
        id_policy="nxprobe-pm",
        id_class="nxprobe-voice",
        v_group="3",
    )
    assert mark.status_code == 200, _text(mark.text)
    assert _config_requests(enabled) == [
        ["class-map type qos match-any web"],
        ["class-map type qos match-any web", "match dscp 46"],
        ["policy-map type qos nxprobe-pm", "class nxprobe-voice"],
        ["policy-map type qos nxprobe-pm", "class nxprobe-voice", "set qos-group 3"],
    ]
    assert enabled.qos_lines == [
        "class-map type qos web",
        "class-map type qos web ; match dscp 46",
        "policy-map type qos nxprobe-pm",
        "policy-map type qos nxprobe-pm ; class nxprobe-voice",
        "policy-map type qos nxprobe-pm ; class nxprobe-voice ; set qos-group 3",
    ]


def test_apply_a_policy_to_a_port_and_take_it_off(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    fields = {
        "scope": "qos_port",
        "setting": "service_policy",
        "id_port": "Ethernet1/5",
        "v_policy": "nxprobe-pm",
    }
    assert _change(logged_in, action="set", **fields).status_code == 200
    assert enabled.qos_lines == ["interface Ethernet1/5 ; service-policy type qos input nxprobe-pm"]
    assert _change(logged_in, action="remove", **fields).status_code == 200
    assert enabled.qos_lines == []


def test_a_system_policy_warns_it_changes_the_whole_switch(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    asked = _change(
        logged_in,
        confirm=False,
        scope="system",
        setting="queuing_output",
        action="set",
        v_policy="nxprobe-qpm",
    )
    assert "whole switch" in _text(asked.text)
    assert "service-policy type queuing output nxprobe-qpm" in _text(asked.text)
    assert _config_requests(enabled) == []


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        (
            {
                "scope": "qos_port",
                "setting": "service_policy",
                "id_port": "Ethernet1/99",
                "v_policy": "p",
            },
            "no port Ethernet1/99",
        ),
        (
            {"scope": "pclass", "action": "create", "id_policy": "p", "id_class": "missing"},
            "no class-map missing",
        ),
        (
            {"scope": "nqclass", "action": "create", "id_nqpolicy": "p", "id_nqclass": "gone"},
            "no network-qos class-map gone",
        ),
        (
            {"scope": "policy", "action": "create", "id_policy": "default-8q-out-policy"},
            "keeps for its own defaults",
        ),
    ],
)
def test_a_place_the_switch_lacks_is_refused(
    logged_in: TestClient, enabled: FakeSwitch, fields: dict, message: str
) -> None:
    refused = _change(logged_in, **{"action": "set", **fields})
    assert refused.status_code == 400
    assert message in _text(refused.text)
    assert _config_requests(enabled) == []
