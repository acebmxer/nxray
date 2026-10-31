"""VLANs through the pages: the VLANs page, a port's VLANs, and turning VLAN changes on."""

from __future__ import annotations

import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.port_changes import ROLE_NAME
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch


def _csrf(client: TestClient, path: str = "/switch") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def _end_pause(settings: Settings) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE switch_connection SET paused_until = ?", (time.time() - 1,))
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
    """Port and VLAN changes on, and the wait already over."""
    assert _enable(logged_in).status_code == 200
    _end_pause(settings)
    switch.requests.clear()
    switch.saved = False
    return switch


def _post(client: TestClient, path: str, page: str = "/switch", **fields: str):
    return client.post(path, data={"csrf": _csrf(client, page), **fields})


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


# ---- the VLANs page ---------------------------------------------------------


def test_vlans_page_lists_the_switch_vlans(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.vlans[20] = "storage"
    text = _text(logged_in.get("/vlans").text)
    assert "VLANs" in text and "default" in text and "storage" in text
    assert "54 ports" in text  # everything sits in VLAN 1
    assert "VLAN changes are off" in text
    assert "Rename" not in text and "Create VLAN" not in text


def test_vlans_page_without_a_switch(logged_in: TestClient) -> None:
    assert "No switch connected yet" in logged_in.get("/vlans").text


def test_nav_has_vlans(logged_in: TestClient, switch: FakeSwitch) -> None:
    assert 'href="/vlans"' in logged_in.get("/").text


def test_create_rename_delete(logged_in: TestClient, enabled: FakeSwitch) -> None:
    created = _text(_post(logged_in, "/vlans/create", vlan_id="20", name="storage").text)
    assert 'Done: VLAN 20 named "storage" created' in created.replace("&#34;", '"')
    assert enabled.vlans[20] == "storage"
    assert "changed the switch since its configuration was last saved" in created

    renamed = _text(_post(logged_in, "/vlans/rename", vlan_id="20", name="san").text)
    assert 'renamed from "storage" to "san"' in renamed.replace("&#34;", '"')

    ask = _text(_post(logged_in, "/vlans/delete", vlan_id="20").text)
    assert "Confirm the change" in ask and 'Delete VLAN 20 ("san")' in ask.replace("&#34;", '"')
    assert 20 in enabled.vlans  # nothing deleted yet
    done = _text(_post(logged_in, "/vlans/delete", vlan_id="20", confirm="yes").text)
    assert "VLAN 20" in done and "deleted" in done
    assert 20 not in enabled.vlans
    assert _config_requests(enabled) == [
        ["vlan 20", "name storage"],
        ["vlan 20", "name san"],
        ["no vlan 20"],
    ]


def test_create_without_a_name(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _text(_post(logged_in, "/vlans/create", vlan_id="30").text)
    assert "Done: VLAN 30 created" in done
    assert _config_requests(enabled) == [["vlan 30"]]


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"vlan_id": "1"}, "VLAN 1 already exists"),
        ({"vlan_id": "0"}, "a number from 1 to 4094"),
        ({"vlan_id": "20", "name": "two words"}, "no spaces"),
        ({"vlan_id": "20", "name": "x" * 33}, "1-32"),
        ({"vlan_id": "20;reload"}, "a number from 1 to 4094"),
    ],
)
def test_create_refusals_send_nothing(
    logged_in: TestClient, enabled: FakeSwitch, fields: dict, message: str
) -> None:
    response = _post(logged_in, "/vlans/create", **fields)
    assert response.status_code == 400
    assert message in response.text
    assert _config_requests(enabled) == []


def test_reserved_vlan_shows_the_switch_refusal(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = _post(logged_in, "/vlans/create", vlan_id="3999")
    assert response.status_code == 400
    assert "invalid vlans (reserved values)" in response.text
    assert 3999 not in enabled.vlans


def test_vlan_1_cannot_be_renamed_or_deleted(logged_in: TestClient, enabled: FakeSwitch) -> None:
    assert "cannot be changed" in _post(logged_in, "/vlans/rename", vlan_id="1", name="x").text
    assert "cannot be deleted" in _post(logged_in, "/vlans/delete", vlan_id="1").text
    assert _config_requests(enabled) == []


def test_a_vlan_in_use_is_not_deleted(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.vlans[20] = "lab"
    enabled.port_state["Ethernet1/7"] = {"access": "20"}
    enabled.port_state["Ethernet1/9"] = {"mode": "trunk", "allowed": "1,20"}
    for confirm in ("", "yes"):
        response = _post(logged_in, "/vlans/delete", vlan_id="20", confirm=confirm)
        assert response.status_code == 400
        assert "still used by Ethernet1/7, Ethernet1/9" in response.text
        assert "Move those ports to another VLAN" in response.text
    assert 20 in enabled.vlans and _config_requests(enabled) == []
    # The page lists them too.
    assert "Ethernet1/7" in _text(logged_in.get("/vlans").text)


def test_missing_vlans_are_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    assert "does not exist" in _post(logged_in, "/vlans/rename", vlan_id="77", name="x").text
    assert "does not exist" in _post(logged_in, "/vlans/delete", vlan_id="77").text
    assert _config_requests(enabled) == []


def test_vlan_changes_are_refused_while_off(logged_in: TestClient, switch: FakeSwitch) -> None:
    response = _post(logged_in, "/vlans/create", vlan_id="20")
    assert response.status_code == 400
    assert "VLAN changes are off" in response.text
    assert _config_requests(switch) == []


# ---- a port's VLANs ---------------------------------------------------------


def _port_vlans(client: TestClient, name: str = "Ethernet1/3", confirm: str = "", **fields: str):
    form = {"mode": "access", "access_vlan": "1", "native_vlan": "1", "allowed": "1-4094"}
    form.update(fields)
    page = f"/ports/detail?name={name}"
    return _post(client, "/ports/vlans", page, name=name, confirm=confirm, **form)


def test_port_page_shows_its_vlans(logged_in: TestClient, enabled: FakeSwitch) -> None:
    text = _text(logged_in.get("/ports/detail", params={"name": "Ethernet1/3"}).text)
    assert "VLANs on this port" in text
    assert "Mode access" in text and "Access VLAN 1 (default)" in text
    assert "Change VLANs" in text


def test_port_page_without_vlan_changes(logged_in: TestClient, switch: FakeSwitch) -> None:
    text = _text(logged_in.get("/ports/detail", params={"name": "Ethernet1/3"}).text)
    assert "VLANs on this port" in text and "Change VLANs" not in text


def test_moving_an_access_port_asks_then_applies(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.vlans[20] = "lab"
    ask = _text(_port_vlans(logged_in, access_vlan="20").text)
    assert "Access VLAN: 1 → 20." in ask
    assert "loses its connection to VLAN 1" in ask
    assert _config_requests(enabled) == []
    done = _text(_port_vlans(logged_in, access_vlan="20", confirm="yes").text)
    assert "Done: Access VLAN: 1 → 20." in done
    assert "Access VLAN 20 (lab)" in done  # read back from the switch
    assert _config_requests(enabled) == [["interface Ethernet1/3", "switchport access vlan 20"]]


def test_switching_to_trunk_warns(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.vlans[20] = "lab"
    fields = {"mode": "trunk", "native_vlan": "1", "allowed": "1,20"}
    ask = _text(_port_vlans(logged_in, **fields).text)
    assert "Mode: access → trunk." in ask
    assert "may lose its connection for a moment" in ask
    assert "VLANs carried: 1-4094 → 1,20." in ask
    _port_vlans(logged_in, confirm="yes", **fields)
    assert _config_requests(enabled) == [
        [
            "interface Ethernet1/3",
            "switchport mode trunk",
            "switchport trunk allowed vlan 1,20",
        ]
    ]
    text = _text(logged_in.get("/ports/detail", params={"name": "Ethernet1/3"}).text)
    assert "Mode trunk" in text and "VLANs carried 1,20" in text
    # Now in use by a trunk that names it: VLAN 20 cannot be deleted.
    assert "still used by Ethernet1/3" in _post(logged_in, "/vlans/delete", vlan_id="20").text


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"access_vlan": "20"}, "VLAN 20 does not exist"),
        ({"mode": "trunk", "native_vlan": "20"}, "VLAN 20 does not exist"),
        ({"mode": "trunk", "allowed": "1;reload"}, "not a VLAN or range"),
        ({"mode": "trunk", "allowed": "10-5"}, "runs backwards"),
        ({"mode": "routed"}, "pick access or trunk"),
    ],
)
def test_port_vlan_refusals_send_nothing(
    logged_in: TestClient, enabled: FakeSwitch, fields: dict, message: str
) -> None:
    for confirm in ("", "yes"):
        response = _port_vlans(logged_in, confirm=confirm, **fields)
        assert response.status_code == 400
        assert message in response.text
    assert _config_requests(enabled) == []


def test_unchanged_port_vlans_send_nothing(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = _port_vlans(logged_in, confirm="yes")
    assert "Nothing to change" in response.text
    assert _config_requests(enabled) == []


@pytest.mark.parametrize("name", ["mgmt0", "Ethernet9/99", "Ethernet1/3; reload"])
def test_port_vlans_unknown_ports(logged_in: TestClient, enabled: FakeSwitch, name: str) -> None:
    response = logged_in.post(
        "/ports/vlans",
        data={"csrf": _csrf(logged_in, "/vlans"), "name": name, "mode": "trunk", "confirm": "yes"},
    )
    assert response.status_code in (400, 404)
    assert _config_requests(enabled) == []


# ---- installs that turned port changes on before VLANs existed --------------


@pytest.fixture
def ports_only(logged_in: TestClient, enabled: FakeSwitch, settings: Settings) -> FakeSwitch:
    """Port changes on with the stage-5 role: port rules only, role version 1."""
    role = enabled.roles[ROLE_NAME]
    role.entities = {e for e in role.entities if "vlan" not in e}
    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE switch_connection SET role_version = 1")
    conn.commit()
    conn.close()
    return enabled


def test_old_role_offers_turning_on_vlan_changes(
    logged_in: TestClient, ports_only: FakeSwitch
) -> None:
    text = _text(logged_in.get("/switch").text)
    assert "On for ports" in text
    assert (
        "Turn on VLAN, port settings, feature, neighbor, port-channel, VLAN interface and VRF "
        "changes" in text
    )
    assert "There is no wait this time" in text
    assert "VLAN changes are off" in _text(logged_in.get("/vlans").text)
    page = _text(logged_in.get("/ports/detail", params={"name": "Ethernet1/3"}).text)
    assert "VLAN changes are off" in page and "Change VLANs" not in page


def test_turning_on_vlan_changes_needs_no_wait(
    logged_in: TestClient, ports_only: FakeSwitch
) -> None:
    response = _enable(logged_in)
    text = _text(response.text)
    assert (
        "VLAN, port settings, feature, neighbor, port-channel, VLAN interface "
        "and VRF changes are on: nxray may now "
        "also create, rename and delete VLANs" in text
    )
    assert "no wait" in text and "leaving the switch alone" not in text
    assert ADMIN_PASSWORD not in response.text
    assert ports_only.saved
    # The pages read the switch straight away, and VLAN changes work.
    assert "Create VLAN" in logged_in.get("/vlans").text
    ports_only.requests.clear()
    _post(logged_in, "/vlans/create", vlan_id="20")
    assert _config_requests(ports_only) == [["vlan 20"]]
    assert (
        "Turn on VLAN, port settings, feature, neighbor, port-channel, VLAN interface and VRF "
        "changes" not in logged_in.get("/switch").text
    )
    assert (
        "read, plus port changes, VLANs, port settings, features, CDP, LLDP, the MAC "
        "address table, port-channels, VLAN interfaces and VRFs"
        in _text(logged_in.get("/switch").text)
    )


# ---- protection -------------------------------------------------------------


@pytest.mark.parametrize(
    "path", ["/vlans/create", "/vlans/rename", "/vlans/delete", "/ports/vlans"]
)
def test_vlan_posts_need_the_token(logged_in: TestClient, enabled: FakeSwitch, path: str) -> None:
    for token in ("", "0" * 64):
        response = logged_in.post(
            path,
            data={
                "csrf": token,
                "vlan_id": "20",
                "name": "Ethernet1/3",
                "mode": "trunk",
                "confirm": "yes",
            },
        )
        assert response.status_code == 403, path
    assert enabled.requests == [] and 20 not in enabled.vlans


def test_anonymous_vlan_posts_go_to_login(client: TestClient) -> None:
    for path in ("/vlans/create", "/vlans/rename", "/vlans/delete", "/ports/vlans"):
        response = client.post(path, data={"csrf": "x"})
        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")


def test_save_from_the_vlans_page_stays_there(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _post(logged_in, "/vlans/create", vlan_id="20", name="storage")
    page = logged_in.get("/vlans").text
    assert '<input type="hidden" name="back" value="vlans">' in page
    saved = _post(logged_in, "/switch/save", "/vlans", back="vlans")
    assert saved.status_code == 200
    assert '<h1 class="page-title">VLANs</h1>' in saved.text
    assert "Saved: the switch keeps its current configuration" in saved.text
    assert "changed the switch since" not in saved.text
    assert "storage" in saved.text  # the page was read again
    assert enabled.saved
