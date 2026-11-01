"""Port changes through the pages: turning them on, the wait, changing a port, Save config."""

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
    fake.saved = False
    return fake


def _enable(client: TestClient, **overrides: str):
    form = {
        "csrf": _csrf(client),
        "admin_user": "admin",
        "admin_password": ADMIN_PASSWORD,
        "ssh_port": "22",
        "confirm_save": "yes",
    }
    form.update(overrides)
    return client.post("/switch/enable-changes", data=form)


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    """Port changes on, and the wait already over."""
    assert _enable(logged_in).status_code == 200
    _end_pause(settings)
    switch.requests.clear()
    switch.saved = False
    return switch


def _change(client: TestClient, name: str, action: str, description: str = "", confirm=""):
    return client.post(
        "/ports/change",
        data={
            "csrf": _csrf(client),
            "name": name,
            "action": action,
            "description": description,
            "confirm": confirm,
        },
    )


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


# ---- turning port changes on ------------------------------------------------


def test_switch_page_offers_port_changes(logged_in: TestClient, switch: FakeSwitch) -> None:
    text = _text(logged_in.get("/switch").text)
    assert (
        "Port, VLAN, port settings, feature, neighbor, port-channel, VLAN interface, VRF, static "
        "route, routing protocol, spanning tree, switch admin, security and config and layer 2 "
        "security changes"
        in text
        and "Off: NXray's account can only read" in text
    )
    assert (
        "Turn on port, VLAN, port settings, feature, neighbor, port-channel, VLAN interface, "
        "VRF, static route, routing protocol, spanning tree, switch admin, security and "
        "config and layer 2 security changes" in text
    )
    assert "This wait happens once" in text
    assert "(read-only)" in text


def test_ports_say_changes_are_off(logged_in: TestClient, switch: FakeSwitch) -> None:
    text = _text(logged_in.get("/ports/detail", params={"name": "Ethernet1/3"}).text)
    assert "Port changes are off" in text
    assert "Change description" not in text


def test_turning_on_gives_the_role_saves_and_waits(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    response = _enable(logged_in)
    assert response.status_code == 200
    text = _text(response.text)
    assert (
        "Port, VLAN, port settings, feature, neighbor, port-channel, VLAN interface, VRF, static "
        "route, routing protocol, spanning tree, switch admin, security and config and layer 2 "
        "security changes "
        "are on: nxray may now turn the 54 front ports on or off" in text
    )
    assert "waits about 11 minutes" in text
    assert "configuration was saved" in text
    assert ROLE_NAME in switch.roles_of("nxray")
    assert switch.saved
    assert ADMIN_PASSWORD not in response.text

    # While waiting, no page contacts the switch with NXray's account.
    switch.requests.clear()
    for path in ("/", "/ports", "/ports/detail?name=Ethernet1/3"):
        assert "leaving the switch alone for about 11 more minutes" in logged_in.get(path).text
    tested = logged_in.post("/switch/test", data={"csrf": _csrf(logged_in)}).text
    assert "leaving the switch alone" in tested
    assert switch.requests == []


def test_after_the_wait_the_pages_read_the_switch_again(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    text = _text(logged_in.get("/switch").text)
    assert "read, plus port changes" in text and "Save config" in text
    assert "leaving the switch alone" not in text
    assert "Connected to nexus-lab" in logged_in.get("/").text


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("confirm_save", "", "Tick the box"),
        ("admin_password", "", "admin username and password"),
        ("ssh_port", "0", "1 to 65535"),
        ("ssh_port", "ssh", "1 to 65535"),
    ],
)
def test_turning_on_checks_the_form_first(
    logged_in: TestClient, switch: FakeSwitch, field: str, value: str, message: str
) -> None:
    response = _enable(logged_in, **{field: value})
    assert response.status_code == 400
    assert message in response.text
    assert switch.ssh_lines == [] and switch.requests == []


def test_turning_on_with_a_wrong_admin_password(logged_in: TestClient, switch: FakeSwitch) -> None:
    response = _enable(logged_in, admin_password="Wrong-pw-1")
    assert response.status_code == 400
    assert "refused the admin username or password" in response.text
    assert "Wrong-pw-1" not in response.text
    assert ROLE_NAME not in switch.roles_of("nxray")
    # Still off, so it can be tried again.
    assert (
        "Turn on port, VLAN, port settings, feature, neighbor, port-channel, VLAN interface, "
        "VRF, static route, routing protocol, spanning tree, switch admin, security and "
        "config and layer 2 security changes" in response.text
    )


# ---- changing a port --------------------------------------------------------


def test_port_page_offers_the_changes(logged_in: TestClient, enabled: FakeSwitch) -> None:
    text = _text(logged_in.get("/ports/detail", params={"name": "Ethernet1/3"}).text)
    assert "Change this port" in text and "Change description" in text
    assert "Turn off this port" in text


def test_description_change_asks_first_then_applies(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    confirm = _change(logged_in, "Ethernet1/3", "description", "xcp-host-1 <storage>")
    assert confirm.status_code == 200
    text = _text(confirm.text)
    # Quotes and angle brackets reach the page escaped.
    assert (
        "Change the description of Ethernet1/3 from &#34;none&#34; to "
        "&#34;xcp-host-1 &lt;storage&gt;&#34;" in text
    )
    assert "<storage>" not in confirm.text
    assert _config_requests(enabled) == []  # nothing changed yet

    done = _change(logged_in, "Ethernet1/3", "description", "xcp-host-1 <storage>", "yes")
    assert done.status_code == 200
    assert _config_requests(enabled) == [
        ["interface Ethernet1/3", "description xcp-host-1 <storage>"]
    ]
    text = _text(done.text)
    assert "Done: Ethernet1/3 now has the description &#34;xcp-host-1 &lt;storage&gt;&#34;" in text
    assert "Description xcp-host-1 &lt;storage&gt;" in text  # read back from the switch
    assert "changed the switch since its configuration was last saved" in text


def test_removing_a_description(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.port_state["Ethernet1/3"] = {"desc": "old"}
    done = _change(logged_in, "Ethernet1/3", "description", "", "yes")
    assert _config_requests(enabled) == [["interface Ethernet1/3", "no description"]]
    assert "Ethernet1/3 no longer has a description" in done.text


def test_turning_off_an_up_port_warns(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.bodies["show interface"] = _with_port_up("Ethernet1/3")
    confirm = _text(_change(logged_in, "Ethernet1/3", "off").text)
    assert "Turn off Ethernet1/3." in confirm
    assert "loses its connection at once" in confirm
    assert _config_requests(enabled) == []


def test_turning_off_and_on(logged_in: TestClient, enabled: FakeSwitch) -> None:
    confirm = _text(_change(logged_in, "Ethernet1/3", "off").text)
    assert "Turn off Ethernet1/3." in confirm and "loses its connection" not in confirm
    off = _text(_change(logged_in, "Ethernet1/3", "off", confirm="yes").text)
    assert "Ethernet1/3 is turned off" in off
    assert "Disabled" in off and "Turn on this port" in off
    on = _text(_change(logged_in, "Ethernet1/3", "on", confirm="yes").text)
    assert "Ethernet1/3 is turned on" in on and "Turn off this port" in on
    assert _config_requests(enabled) == [
        ["interface Ethernet1/3", "shutdown"],
        ["interface Ethernet1/3", "no shutdown"],
    ]


@pytest.mark.parametrize(
    ("description", "message"),
    [("why?", "cannot contain"), ("café", "plain letters"), ("x" * 255, "at most 254")],
)
def test_bad_descriptions_are_refused_before_the_switch(
    logged_in: TestClient, enabled: FakeSwitch, description: str, message: str
) -> None:
    for confirm in ("", "yes"):
        response = _change(logged_in, "Ethernet1/3", "description", description, confirm)
        assert response.status_code == 400
        assert message in response.text
    assert _config_requests(enabled) == []


def test_unchanged_description_sends_nothing(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.port_state["Ethernet1/3"] = {"desc": "same"}
    response = _change(logged_in, "Ethernet1/3", "description", "same", "yes")
    assert "already has that description" in response.text
    assert _config_requests(enabled) == []


@pytest.mark.parametrize(
    ("name", "action"),
    [
        ("Ethernet9/99", "off"),
        ("mgmt0", "off"),
        ("Ethernet1/3; reload", "off"),
        ("Ethernet1/3", "speed"),
        ("Ethernet1/3", ""),
    ],
)
def test_unknown_ports_and_actions_change_nothing(
    logged_in: TestClient, enabled: FakeSwitch, name: str, action: str
) -> None:
    response = _change(logged_in, name, action, confirm="yes")
    assert response.status_code in (400, 404)
    assert _config_requests(enabled) == []


def test_changes_are_refused_while_off(logged_in: TestClient, switch: FakeSwitch) -> None:
    response = _change(logged_in, "Ethernet1/3", "off", confirm="yes")
    assert response.status_code == 400
    assert "Port changes are off" in response.text
    assert _config_requests(switch) == []


def test_changes_are_refused_while_waiting(logged_in: TestClient, switch: FakeSwitch) -> None:
    _enable(logged_in)
    switch.requests.clear()
    response = _change(logged_in, "Ethernet1/3", "off", confirm="yes")
    assert "leaving the switch alone" in response.text
    assert switch.requests == []


def test_switch_refusal_is_explained(logged_in: TestClient, enabled: FakeSwitch) -> None:
    # As when the switch has not applied the role yet, or it was removed.
    enabled.extra_roles.clear()
    response = _change(logged_in, "Ethernet1/3", "off", confirm="yes")
    assert response.status_code == 400
    assert "may not make this change yet" in response.text
    assert "Ethernet1/3" not in enabled.port_state


# ---- several ports at once --------------------------------------------------


def _bulk(client: TestClient, names: list[str], **form):
    return client.post("/ports/bulk", data={"csrf": _csrf(client), "names": names, **form})


def test_ports_page_offers_ticks_once_changes_are_on(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    page = logged_in.get("/ports").text
    assert "Change several ports" not in page and 'name="names"' not in page
    _enable(logged_in)
    from tests.test_vlans_page import _end_pause as end  # same helper, same database

    end(logged_in.app.state.settings)  # type: ignore[attr-defined]
    page = logged_in.get("/ports").text
    assert "Change several ports" in page
    assert page.count('name="names"') == 54
    assert 'value="Ethernet1/3" aria-label="Tick Ethernet1/3"' in page
    assert " checked" not in page.split('id="change-several"')[1].split("</table>")[0]


def test_tick_every_port_shown(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.bodies["show interface"] = _with_port_up("Ethernet1/3")
    page = logged_in.get("/ports", params={"show": "up", "select": "all"}).text
    assert page.count('name="names"') == 1
    assert 'value="Ethernet1/3" aria-label="Tick Ethernet1/3" checked' in page
    assert 'name="show" value="up"' in page


def test_turning_several_ports_off_asks_then_goes_port_by_port(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.bodies["show interface"] = _with_port_up("Ethernet1/3")
    names = ["Ethernet1/10", "Ethernet1/3", "Ethernet1/4", "Ethernet1/3"]
    ask = _text(_bulk(logged_in, names, power="off").text)
    # Every port, in front-panel order, once; a warning for the one that is up.
    assert (
        "Ethernet1/3: Turn off Ethernet1/3. Ethernet1/4: Turn off Ethernet1/4. "
        "Ethernet1/10: Turn off Ethernet1/10." in ask
    )
    assert "Ethernet1/3: This port is up now" in ask
    assert "Ethernet1/4: This port is up now" not in ask
    assert _config_requests(enabled) == []

    names = ["Ethernet1/3", "Ethernet1/4", "Ethernet1/10"]
    done = _bulk(logged_in, names, power="off", confirm="yes")
    text = _text(done.text)
    assert done.status_code == 200
    assert "Done: changed Ethernet1/3, Ethernet1/4, Ethernet1/10." in text
    assert "Not saved yet" in text
    assert "changed the switch since its configuration was last saved" in text
    assert 'name="back" value="ports"' in done.text
    assert _config_requests(enabled) == [
        ["interface Ethernet1/3", "shutdown"],
        ["interface Ethernet1/4", "shutdown"],
        ["interface Ethernet1/10", "shutdown"],
    ]
    activity = _text(logged_in.get("/activity").text)
    assert "Ethernet1/3: Turn off Ethernet1/3. Ethernet1/4: Turn off Ethernet1/4." in activity


def test_ports_already_as_asked_are_left_alone(logged_in: TestClient, enabled: FakeSwitch) -> None:
    enabled.port_state["Ethernet1/4"] = {"admin_up": False}
    ask = _bulk(logged_in, ["Ethernet1/3", "Ethernet1/4"], power="off")
    assert "Ethernet1/3: Turn off Ethernet1/3." in _text(ask.text)
    assert "Unchanged: Ethernet1/4 is already set as asked." in _text(ask.text)
    assert 'name="names" value="Ethernet1/4"' not in ask.text
    nothing = _bulk(logged_in, ["Ethernet1/4"], power="off", confirm="yes")
    assert "Nothing to change: Ethernet1/4 is already set as asked." in _text(nothing.text)
    assert _config_requests(enabled) == []


def test_one_description_for_several_ports(logged_in: TestClient, enabled: FakeSwitch) -> None:
    names = ["Ethernet1/5", "Ethernet1/6"]
    form = {"set_description": "yes", "description": "lab rack 4"}
    ask = _text(_bulk(logged_in, names, **form).text).replace("&#34;", '"')
    assert 'Change the description of Ethernet1/5 from "none" to "lab rack 4".' in ask
    done = _text(_bulk(logged_in, names, confirm="yes", **form).text).replace("&#34;", '"')
    assert "Done: changed Ethernet1/5, Ethernet1/6." in done
    assert _config_requests(enabled) == [
        ["interface Ethernet1/5", "description lab rack 4"],
        ["interface Ethernet1/6", "description lab rack 4"],
    ]
    cleared = _bulk(logged_in, names, set_description="yes", description="", confirm="yes")
    assert 'from "lab rack 4" to "none"' in _text(cleared.text).replace("&#34;", '"')
    assert _config_requests(enabled)[-1] == ["interface Ethernet1/6", "no description"]


def test_a_description_is_left_alone_unless_its_box_is_ticked(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    response = _bulk(logged_in, ["Ethernet1/5"], description="typed but not ticked")
    assert response.status_code == 400
    assert "fill in at least one setting to change" in response.text
    _bulk(logged_in, ["Ethernet1/5"], description="not ticked", power="off", confirm="yes")
    assert _config_requests(enabled) == [["interface Ethernet1/5", "shutdown"]]


def test_a_refusal_partway_names_what_changed_and_what_did_not(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.reject.add("interface Ethernet1/5")
    names = ["Ethernet1/4", "Ethernet1/5", "Ethernet1/6", "Ethernet1/7"]
    response = _bulk(logged_in, names, power="off", confirm="yes")
    text = _text(response.text)
    assert response.status_code == 400
    assert "Changed: Ethernet1/4: Turn off Ethernet1/4." in text
    assert "Ethernet1/5 was not changed. The switch refused a command" in text
    assert "Not tried: Ethernet1/6, Ethernet1/7." in text
    assert "Not saved yet" in text
    # Ethernet1/5 was sent and refused; the ports after it were never sent.
    assert _config_requests(enabled) == [
        ["interface Ethernet1/4", "shutdown"],
        ["interface Ethernet1/5", "shutdown"],
    ]
    assert "Ethernet1/5" not in enabled.port_state
    # The ticks and the form are kept, to try again.
    for name in names:
        assert f'value="{name}" aria-label="Tick {name}" checked' in response.text
    assert '<option value="off" selected>Turn off</option>' in response.text


def test_a_refusal_at_the_first_port_changes_nothing(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    enabled.extra_roles.clear()  # as before the switch applied the role
    response = _bulk(logged_in, ["Ethernet1/3", "Ethernet1/4"], power="off", confirm="yes")
    text = _text(response.text).replace("&#39;", "'")
    assert "Changed:" not in text and "Not saved yet" not in text
    assert "Ethernet1/3 was not changed. The switch refused: NXray's account may not" in text
    assert "Not tried: Ethernet1/4." in text
    assert "changed the switch since" not in text


@pytest.mark.parametrize(
    ("names", "form", "message"),
    [
        ([], {"power": "off"}, "tick at least one port"),
        (["Ethernet1/3"], {"power": "speed"}, "turn the ports on or off"),
        (["Ethernet1/3"], {}, "fill in at least one setting to change"),
        (["Ethernet1/3", "Ethernet9/99"], {"power": "off"}, "no port called Ethernet9/99"),
        (["mgmt0"], {"power": "off"}, "no port called mgmt0"),
        (["Ethernet1/3; reload"], {"power": "off"}, "no port called"),
        (["Ethernet1/3"], {"set_description": "yes", "description": "why?"}, "cannot contain"),
        (["Ethernet1/3"], {"set_description": "yes", "description": "x" * 255}, "at most 254"),
    ],
)
def test_bad_bulk_changes_send_nothing(
    logged_in: TestClient,
    enabled: FakeSwitch,
    names: list[str],
    form: dict[str, str],
    message: str,
) -> None:
    for confirm in ("", "yes"):
        response = _bulk(logged_in, names, confirm=confirm, **form)
        assert response.status_code == 400
        assert message in response.text
    assert _config_requests(enabled) == []


def test_bulk_changes_are_refused_while_off(logged_in: TestClient, switch: FakeSwitch) -> None:
    response = _bulk(logged_in, ["Ethernet1/3"], power="off", confirm="yes")
    assert response.status_code == 400
    assert "Port changes are off" in response.text
    assert _config_requests(switch) == []


# ---- Save config ------------------------------------------------------------


def test_save_config_clears_the_reminder(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _change(logged_in, "Ethernet1/3", "off", confirm="yes")
    assert "changed the switch since" in logged_in.get("/switch").text
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in)})
    assert "Saved: the switch keeps its current configuration" in saved.text
    assert enabled.saved
    assert enabled.requests[-1] == ["copy running-config startup-config"]
    assert "changed the switch since" not in logged_in.get("/switch").text
    assert "changed the switch since" not in logged_in.get("/ports/detail?name=Ethernet1/3").text


def test_failed_save_keeps_the_reminder(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _change(logged_in, "Ethernet1/3", "off", confirm="yes")
    enabled.save_text = "Copy failed\n"
    response = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in)})
    assert "lost if the switch restarts" in response.text
    assert "changed the switch since" in logged_in.get("/switch").text


def _page_title(html: str) -> str:
    match = re.search(r'<h1 class="page-title">([^<]+)</h1>', html)
    assert match, "no page title"
    return match.group(1)


def test_save_from_a_port_page_stays_on_that_port(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    _change(logged_in, "Ethernet1/3", "off", confirm="yes")
    page = logged_in.get("/ports/detail?name=Ethernet1/3").text
    assert '<input type="hidden" name="back" value="port">' in page
    assert '<input type="hidden" name="port" value="Ethernet1/3">' in page
    saved = logged_in.post(
        "/switch/save",
        data={"csrf": _csrf(logged_in), "back": "port", "port": "Ethernet1/3"},
    )
    assert saved.status_code == 200
    assert _page_title(saved.text) == "Ethernet1/3"
    assert "Saved: the switch keeps its current configuration" in saved.text
    assert "changed the switch since" not in saved.text
    assert enabled.saved


def test_save_from_the_ports_page_stays_there(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _bulk(logged_in, ["Ethernet1/3"], power="off", confirm="yes")
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "ports"})
    assert _page_title(saved.text) == "Ports"
    assert "Saved: the switch keeps its current configuration" in saved.text
    assert enabled.saved


def test_failed_save_from_a_port_page_says_so_there(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    _change(logged_in, "Ethernet1/3", "off", confirm="yes")
    enabled.save_text = "Copy failed\n"
    response = logged_in.post(
        "/switch/save",
        data={"csrf": _csrf(logged_in), "back": "port", "port": "Ethernet1/3"},
    )
    assert _page_title(response.text) == "Ethernet1/3"
    assert "lost if the switch restarts" in response.text
    assert "changed the switch since" in response.text


@pytest.mark.parametrize(
    "back", ["", "https://example.com/", "//example.com/", "/vlans", "switch", "PORT"]
)
def test_save_with_another_back_value_shows_the_switch_page(
    logged_in: TestClient, enabled: FakeSwitch, back: str
) -> None:
    saved = logged_in.post(
        "/switch/save", data={"csrf": _csrf(logged_in), "back": back, "port": "Ethernet1/3"}
    )
    assert saved.status_code == 200
    assert _page_title(saved.text) == "Switch"
    assert "Saved: the switch keeps its current configuration" in saved.text
    assert "location" not in saved.headers


# ---- protection -------------------------------------------------------------


@pytest.mark.parametrize(
    "path", ["/switch/enable-changes", "/switch/save", "/ports/change", "/ports/bulk"]
)
def test_new_posts_need_the_token(logged_in: TestClient, enabled: FakeSwitch, path: str) -> None:
    for token in ("", "0" * 64):
        response = logged_in.post(
            path,
            data={
                "csrf": token,
                "name": "Ethernet1/3",
                "names": ["Ethernet1/3"],
                "action": "off",
                "confirm": "yes",
                "admin_user": "admin",
                "admin_password": ADMIN_PASSWORD,
                "confirm_save": "yes",
            },
        )
        assert response.status_code == 403, path
    assert enabled.requests == [] and "Ethernet1/3" not in enabled.port_state


def test_anonymous_posts_go_to_login(client: TestClient) -> None:
    for path in ("/switch/enable-changes", "/switch/save", "/ports/change", "/ports/bulk"):
        response = client.post(path, data={"csrf": "x"})
        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")


def _with_port_up(name: str) -> dict:
    from tests.conftest import load_fixture

    body = load_fixture("show_interface")
    for row in body["TABLE_interface"]["ROW_interface"]:
        if row["interface"] == name:
            row.update(state="up", eth_speed="25 Gb/s")
    return body
