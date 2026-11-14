"""The vPC page, end to end against the fake switch: reading it, the role version it
needs, and a change from asking to sent."""

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


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    """A switch that has been set up (read-only account nxray), with vPC turned on."""
    fake = FakeSwitch()
    fake.feature_state["vpc"] = True
    fake.bodies["show vpc"] = load_fixture("show_vpc_doc")
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
    """All changes on and the wait over."""
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
    return client.post("/vpc/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/vpc", follow_redirects=False).status_code == 303


def test_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in _text(logged_in.get("/vpc").text)


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/vpc"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/vpc")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "vPC domain 10" in text and "peer-ok" in text and "primary" in text
    assert "Peer-link" in text and "port-channel1" in text
    assert "port-channel44" in text and "inconsistent" in text
    assert switch.requests[0] == ["show feature", "show port-channel summary", "show vrf"]
    assert switch.requests[1] == ["show vpc"]
    # The role at setup (read-only) may not read the configuration text.
    assert "does not let it read the vPC settings" in text
    assert "/vpc/change" not in page.text  # changes are off


def test_feature_off_says_which(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["vpc"] = False
    text = _text(logged_in.get("/vpc").text)
    assert "vpc is off on the switch, so vPC is not running" in text
    assert 'href="/features"' in logged_in.get("/vpc").text


def test_changes_off_before_role_version_19(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE switch_connection SET role_version = 18")
    assert "vPC changes are off" in _text(logged_in.get("/vpc").text)
    refused = _change(logged_in, scope="domain", action="create", id_domain="10")
    assert refused.status_code == 400
    assert "vPC changes are off" in _text(refused.text)
    assert _config_requests(enabled) == []
    assert "Turn on vPC and VXLAN changes" in _text(logged_in.get("/switch").text)


def test_enabled_page_offers_the_settings(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/vpc")
    assert "does not let it read" not in _text(page.text)
    for setting in ("keepalive", "role_priority", "peer_switch", "peer_link", "number"):
        assert f'name="setting" value="{setting}"' in page.text
    assert enabled.requests[2] == ["show running-config vpc"]
    # Only port-channels are offered for the vPC lines, never a front port.
    assert '<option value="port-channel43"' in page.text
    assert '<option value="Ethernet1/1"' not in page.text
    assert '<option value="management"' in page.text


def test_make_the_domain_asks_first_then_sends(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {"scope": "domain", "action": "create", "id_domain": "10"}
    asked = _change(logged_in, confirm=False, **fields)
    assert asked.status_code == 200
    assert "vpc domain 10" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["vpc domain 10"]]
    assert "vpc domain 10" in enabled.vpc_lines
    assert "NXray changed the switch since its configuration was last saved" in _text(
        logged_in.get("/vpc").text
    )


def test_keepalive_and_the_setting_shows_back(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(
        logged_in,
        scope="domain",
        setting="keepalive",
        action="set",
        id_domain="10",
        v_destination="192.0.2.2",
        v_source="",
        v_vrf="management",
    )
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [
        ["vpc domain 10", "peer-keepalive destination 192.0.2.2 vrf management"]
    ]
    page = logged_in.get("/vpc").text
    assert 'value="192.0.2.2"' in page  # the form is filled from the configuration


def test_peer_link_and_vpc_number(logged_in: TestClient, enabled: FakeSwitch) -> None:
    link = _change(logged_in, scope="channel", setting="peer_link", action="set",
                   id_channel="port-channel43")  # fmt: skip
    assert link.status_code == 200, _text(link.text)
    number = _change(logged_in, scope="channel", setting="number", action="set",
                     id_channel="port-channel43", v_number="43")  # fmt: skip
    assert number.status_code == 200, _text(number.text)
    assert _config_requests(enabled) == [
        ["interface port-channel43", "vpc peer-link"],
        ["interface port-channel43", "vpc 43"],
    ]
    gone = _change(logged_in, scope="channel", setting="number", action="remove",
                   id_channel="port-channel43", v_number="43")  # fmt: skip
    assert gone.status_code == 200
    assert "interface port-channel43 ; vpc 43" not in enabled.vpc_lines


def test_a_port_channel_the_switch_lacks_is_refused(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    refused = _change(logged_in, scope="channel", setting="peer_link", action="set",
                      id_channel="port-channel99")  # fmt: skip
    assert refused.status_code == 400
    assert "not a switched port-channel on the switch" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_a_second_domain_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _change(logged_in, scope="domain", action="create", id_domain="20")
    assert refused.status_code == 400
    assert "already has vPC domain 10" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_bad_values_are_refused_before_anything_is_sent(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    refused = _change(logged_in, scope="domain", setting="role_priority", action="set",
                      id_domain="10", v_priority="0")  # fmt: skip
    assert refused.status_code == 400
    assert _config_requests(enabled) == []


def test_viewer_sees_no_forms_and_cannot_post(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    _db(settings, "UPDATE users SET role = 'viewer'")
    page = logged_in.get("/vpc").text
    assert "/vpc/change" not in page
    assert "can look at vPC but not change it" in _text(page)
    response = _change(logged_in, scope="domain", action="create", id_domain="10")
    assert response.status_code == 403
    assert _config_requests(enabled) == []


def test_change_needs_csrf(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = logged_in.post(
        "/vpc/change",
        data={"csrf": "0" * 32, "scope": "domain", "action": "create", "id_domain": "10",
              "confirm": "yes"},
    )  # fmt: skip
    assert response.status_code == 403
    assert _config_requests(enabled) == []


def test_switch_error_is_shown(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.reject.add("vpc domain")
    response = _change(logged_in, scope="domain", action="create", id_domain="10")
    assert response.status_code == 400
    assert "Rejected by the fake switch" in _text(response.text)


def test_save_config_returns_to_the_page(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _change(logged_in, scope="domain", action="create", id_domain="10")
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "vpc"})
    assert saved.status_code == 200
    assert "Peer-link" in _text(saved.text)
    assert enabled.saved
