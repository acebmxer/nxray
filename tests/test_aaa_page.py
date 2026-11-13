"""The AAA page (#83), end to end against the fake switch, and its lines. AAA changes need
the stored admin login and an NXray admin: they decide who may sign in."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.aaa import (
    LdapReads,
    build_aaa_change,
    parse_aaa,
    parse_ldap_config,
    parse_ldap_groups,
    parse_ldap_servers,
)
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


# ---- LDAP (#95) ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures"
LDAP_SERVER = (FIXTURES / "show_ldap_server.txt").read_text()
LDAP_GROUPS = (FIXTURES / "show_ldap_server_groups.txt").read_text()
LDAP_CONFIG = (FIXTURES / "show_running_config_section_ldap.txt").read_text()


def test_the_ldap_lines() -> None:
    def change(scope: str, setting: str, action: str = "set", ident=None, **values: str):
        return build_aaa_change(scope, setting, action, ident or {}, values)

    assert change("ldap", "host", host="192.0.2.20").lines == ("ldap-server host 192.0.2.20",)
    assert change("ldap", "ssl", host="192.0.2.20").lines == (
        "ldap-server host 192.0.2.20 enable-ssl",
    )
    assert change("ldap", "port", host="192.0.2.20", port="636").lines == (
        "ldap-server host 192.0.2.20 port 636",
    )
    bind = change(
        "ldap", "bind", host="192.0.2.20", dn="cn=admin,dc=example,dc=com", password="pw1"
    )
    assert bind.lines == (
        'ldap-server host 192.0.2.20 rootDN "cn=admin,dc=example,dc=com" password pw1',
    )
    assert "pw1" not in " ".join(bind.labels) and "pw1" not in bind.describe
    assert change(
        "ldap", "bind", "remove", host="192.0.2.20", dn="cn=admin,dc=example,dc=com"
    ).lines == ('no ldap-server host 192.0.2.20 rootDN "cn=admin,dc=example,dc=com"',)
    assert change("ldap", "deadtime", minutes="2").lines == ("ldap-server deadtime 2",)
    group = change("ldap_group", "cert_dn", ident={"group": "lgrp"})
    assert group.lines == ("aaa group server ldap lgrp", "enable Cert-DN-match")
    assert change("ldap_group", "search_map", ident={"group": "lgrp"}, map="smap").lines == (
        "aaa group server ldap lgrp",
        "ldap-search-map smap",
    )
    assert change("ldap_map", "", "create", ident={"map": "smap"}).lines == (
        "ldap search-map smap",
    )
    assert change("ldap_map", "", "delete", ident={"map": "smap"}).lines == (
        "no ldap search-map smap",
    )
    with pytest.raises(ValueError):
        change("ldap", "timeout_all", seconds="61")


def test_the_ldap_reads_are_parsed() -> None:
    wide, servers = parse_ldap_servers(LDAP_SERVER)
    assert wide == {"timeout": "5", "port": "389", "deadtime": "2"}
    assert servers == [
        {
            "host": "10.250.250.250",
            "tls": "yes",
            "timeout": "7",
            "port": "636",
            "dn": "cn=admin,dc=example,dc=com",
        }
    ]
    (group,) = parse_ldap_groups(LDAP_GROUPS)
    assert group == {
        "name": "lgrp",
        "vrf": "management",
        "servers": ["10.250.250.250"],
        "map": "smap",
        "cert_dn": True,
        "user_group": True,
    }
    assert parse_ldap_config(LDAP_CONFIG) == (["smap"], {"lgrp": "3"})
    assert parse_ldap_config(None) == ([], {})


def test_the_view_with_ldap_on_and_off() -> None:
    fake = FakeSwitch()
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
    ] + [{}]
    off = parse_aaa(bodies, None, None)
    assert any("LDAP is off" in note for note in off.notes) and not off.of("ldap")
    on = parse_aaa(bodies, None, None, LdapReads(LDAP_SERVER, LDAP_GROUPS, LDAP_CONFIG))
    assert dict(on.of("ldap")[0].facts)["Port"] == "389"
    assert on.of("ldap")[0].values["deadtime"] == {"minutes": "2"}
    (lgrp,) = on.of("ldap_group")
    assert lgrp.values == {
        "vrf": {"vrf": "management"},
        "search_map": {"map": "smap"},
        "cert_dn": {},
        "user_group": {},
        "deadtime": {"minutes": "3"},
    }
    assert [i.title for i in on.of("ldap_map")] == ["smap"]
    assert any(t.title == "LDAP servers" and t.rows[0][4] == "yes" for t in on.tables)
    no_config = parse_aaa(bodies, None, None, LdapReads(LDAP_SERVER, LDAP_GROUPS, None))
    assert any("may not read the configuration" in note for note in no_config.notes)


def test_ldap_is_refused_while_its_feature_is_off(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "stored")
    refused = _change(logged_in, scope="ldap", setting="host", action="set", v_host="192.0.2.20")
    assert refused.status_code == 400 and "Invalid command" in text(refused.text)
    assert "LDAP is off" in text(logged_in.get("/aaa").text)


def test_ldap_servers_groups_and_maps_are_made(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "stored")
    switch.feature_state["ldap"] = True
    switch.texts.update(
        {
            "show ldap-server": LDAP_SERVER,
            "show ldap-server groups": LDAP_GROUPS,
        }
    )
    fields = {"scope": "ldap", "setting": "bind", "action": "set", "v_host": "192.0.2.20",
              "v_dn": "cn=admin,dc=example,dc=com", "v_password": "pw-secret"}  # fmt: skip
    asked = _change(logged_in, confirm=False, **fields)
    assert "password ***" in text(asked.text) and "pw-secret" not in text(asked.text)
    for step in (
        {"scope": "ldap", "setting": "host", "action": "set", "v_host": "192.0.2.20"},
        fields,
        {
            "scope": "ldap",
            "setting": "port",
            "action": "set",
            "v_host": "192.0.2.20",
            "v_port": "636",
        },  # fmt: skip
        {"scope": "ldap_map", "action": "create", "id_map": "smap"},
        {"scope": "ldap_group", "action": "create", "id_group": "lgrp"},
        {
            "scope": "ldap_group",
            "setting": "server",
            "action": "set",
            "id_group": "lgrp",
            "v_server": "192.0.2.20",
        },  # fmt: skip
        {
            "scope": "ldap_group",
            "setting": "search_map",
            "action": "set",
            "id_group": "lgrp",
            "v_map": "smap",
        },  # fmt: skip
        {"scope": "ldap_group", "setting": "cert_dn", "action": "set", "id_group": "lgrp"},
    ):
        done = _change(logged_in, **step)
        assert done.status_code == 200, text(done.text)
    assert "ldap-server host 192.0.2.20" in switch.mgmt_lines
    assert "ldap-server host 192.0.2.20 port 636" in switch.mgmt_lines
    assert "ldap search-map smap" in switch.mgmt_lines
    assert "aaa group server ldap lgrp ; server 192.0.2.20" in switch.mgmt_lines
    assert "aaa group server ldap lgrp ; ldap-search-map smap" in switch.mgmt_lines
    assert "aaa group server ldap lgrp ; enable Cert-DN-match" in switch.mgmt_lines
    shown = text(logged_in.get("/aaa").text)
    assert "LDAP servers" in shown and "10.250.250.250" in shown and "lgrp" in shown
    gone = _change(logged_in, scope="ldap_group", action="delete", id_group="lgrp")
    assert gone.status_code == 200, text(gone.text)
    assert not any(line.startswith("aaa group server ldap lgrp") for line in switch.mgmt_lines)
