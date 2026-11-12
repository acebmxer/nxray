"""The AAA page (#83), end to end against the fake switch, and its lines. AAA changes need
the stored admin login and an NXray admin: they decide who may sign in."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.aaa import build_aaa_change, parse_aaa
from app.config import Settings
from tests.conftest import load_fixture
from tests.fake_switch import FakeSwitch
from tests.stage_d_helpers import config_requests, csrf, enable, set_up, sign_in_as, text


def test_the_lines() -> None:
    def change(scope: str, setting: str, action: str = "set", ident=None, **values: str):
        return build_aaa_change(scope, setting, action, ident or {}, values)

    login = change("methods", "login_groups", service="default", group1="tg", group2="rg")
    assert login.lines == ("aaa authentication login default group tg rg",)
    assert login.warning  # can lock everyone out
    assert change("methods", "login_local", service="console").lines == (
        "aaa authentication login console local",
    )
    with pytest.raises(ValueError):
        change("methods", "login_groups", service="default", group1="a", group3="c")
    host = change(
        "radius",
        "host",
        host="192.0.2.11",
        key="s3cret",
        auth_port="1812",
        authentication="yes",
        timeout="4",
    )
    assert host.lines == (
        "radius-server host 192.0.2.11 key 0 s3cret auth-port 1812 authentication timeout 4",
    )
    assert "s3cret" not in " ".join(host.labels) and "s3cret" not in host.describe
    assert change("radius", "host", "remove", host="192.0.2.11").lines == (
        "no radius-server host 192.0.2.11",
    )
    assert change("tacacs", "timeout", "remove", seconds="7").lines == (
        "no tacacs-server timeout 7",
    )
    group = change("tacacs_group", "server", ident={"group": "tg"}, server="192.0.2.10")
    assert group.lines == ("aaa group server tacacs+ tg", "server 192.0.2.10")
    with pytest.raises(ValueError):
        change("radius_group", "vrf", ident={"group": "rg"}, vrf="default")
    with pytest.raises(ValueError):
        build_aaa_change("radius_group", "", "delete", {"group": "radius"}, {})


def test_the_view_from_recorded_shapes() -> None:
    fake = FakeSwitch()
    fake.aaa_lines += ["radius-server host 192.0.2.11 key 0 k timeout 4"]
    fake.aaa_groups[("radius", "rg")] = ["server 192.0.2.11", "use-vrf management"]
    bodies = [
        fake._aaa_show(c)  # noqa: SLF001 - the fake's own reader
        for c in (
            "show aaa authentication",
            "show aaa authentication login error-enable",
            "show aaa accounting",
            "show aaa authorization",
            "show aaa groups",
            "show aaa user default-role",
            "show radius-server",
        )
    ]
    groups = fake._aaa_show("show radius-server groups")  # noqa: SLF001
    view = parse_aaa([*bodies, load_fixture("show_vrf")], groups, None)
    (methods,) = view.of("methods")
    assert dict(methods.facts)["Default sign-in"] == "local"
    (group,) = view.of("radius_group")  # the built-in "radius" group is not one to change
    assert group.ident == {"group": "rg"} and group.values["vrf"] == {"vrf": "management"}
    assert view.tables[0].rows == (("192.0.2.11", "1812 / 1813", "4", "switch-wide", "yes"),)
    assert any("TACACS+ is off" in note for note in view.notes)


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    return set_up(logged_in)


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/aaa/change", data=data)


def test_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/aaa")
    assert page.status_code == 200, text(page.text)
    shown = text(page.text)
    assert "Default sign-in local" in shown and "TACACS+ is off" in shown
    # NXray's own (limited) account is refused the RADIUS groups, as on cisco-25gb.
    assert "may not read the RADIUS groups" in shown
    assert "/aaa/change" not in page.text  # changes are off
    assert 'href="/aaa"' in logged_in.get("/").text


def test_with_the_admin_login_stored_the_page_reads_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "stored")
    switch.aaa_groups[("radius", "rg")] = ["server 192.0.2.11"]
    shown = text(logged_in.get("/aaa").text)
    assert "may not read the RADIUS groups" not in shown and "rg" in shown


def test_the_broad_role_cannot_change_aaa(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    refused = _change(logged_in, scope="radius", setting="host", action="set", v_host="192.0.2.11")
    assert refused.status_code == 400 and "need the stored admin login" in text(refused.text)
    assert config_requests(switch) == []


def test_with_the_admin_login_stored_a_server_and_group_are_made(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "stored")
    fields = {
        "scope": "radius",
        "setting": "host",
        "action": "set",
        "v_host": "192.0.2.11",
        "v_key": "s3cret",
    }
    asked = _change(logged_in, confirm=False, **fields)
    assert "radius-server host 192.0.2.11 key 0 ***" in text(asked.text)
    assert "s3cret" not in text(asked.text)  # only in the hidden field the confirm sends
    done = _change(logged_in, **fields)
    assert done.status_code == 200, text(done.text)
    assert "admin" in switch.signed_in
    made = _change(logged_in, scope="radius_group", action="create", id_group="rg")
    assert made.status_code == 200, text(made.text)
    _change(
        logged_in,
        scope="radius_group",
        setting="server",
        action="set",
        id_group="rg",
        v_server="192.0.2.11",
    )
    assert switch.aaa_groups[("radius", "rg")] == ["server 192.0.2.11"]
    shown = text(logged_in.get("/aaa").text)
    assert "192.0.2.11 1812 / 1813" in shown and "rg" in shown


def test_tacacs_is_refused_while_its_feature_is_off(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "stored")
    refused = _change(logged_in, scope="tacacs", setting="host", action="set", v_host="192.0.2.10")
    assert refused.status_code == 400 and "Invalid command" in text(refused.text)
    switch.feature_state["tacacs"] = True
    done = _change(logged_in, scope="tacacs", setting="host", action="set", v_host="192.0.2.10")
    assert done.status_code == 200, text(done.text)
    assert "TACACS+ servers" in text(logged_in.get("/aaa").text)


def test_an_operator_looks_only(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "stored")
    otto = sign_in_as(logged_in, "otto", "operator")
    page = otto.get("/aaa")
    assert "only an NXray admin changes it" in text(page.text)
    assert "/aaa/change" not in page.text
    refused = otto.post("/aaa/change", data={"csrf": csrf(otto), "scope": "methods"})
    assert refused.status_code == 403
