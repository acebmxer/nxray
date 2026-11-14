"""How much access NXray's switch account gets (issue #40): the three role modes."""

from __future__ import annotations

import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.port_changes import (
    BROAD_RULES,
    LIMITED_RULES,
    ROLE_NAME,
    ROLE_VERSION,
    enable_port_changes,
    role_lines,
    rules_for_mode,
)
from app.role_upgrade import upgrade_stored_roles
from app.switch_connection import BROAD_ROLE_VERSION, ROLE_BROAD, ROLE_LIMITED, ROLE_STORED
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

PORTS = ["Ethernet1/1", "Ethernet1/2"]


def _numbers(rules: tuple[str, ...]) -> list[int]:
    return [int(rule.split()[1]) for rule in rules]


# ---- the rules ------------------------------------------------------------


def test_broad_rules_fit_a_role_and_the_denies_beat_the_permit() -> None:
    numbers = _numbers(BROAD_RULES)
    assert len(set(numbers)) == len(numbers) and max(numbers) <= 256
    permit = next(r for r in BROAD_RULES if r.endswith("permit command conf t ; *"))
    denies = [r for r in BROAD_RULES if " deny command " in r]
    assert {r.split("conf t ; ")[1] for r in denies} == {
        f"{form}{word} *"
        for word in (
            "username",
            "role",
            "aaa",
            "tacacs-server",
            "radius-server",
            "boot",
            "event manager",
        )
        for form in ("", "no ")
    }
    # The rule with the higher number wins, so every deny is numbered above the permit.
    assert all(int(d.split()[1]) > int(permit.split()[1]) for d in denies)
    assert "rule 14 permit command show *" in BROAD_RULES


def test_limited_rules_have_no_deny_and_no_wildcard_configuration() -> None:
    assert all(" permit command " in rule for rule in LIMITED_RULES)
    assert "rule 1 permit command conf t ; *" not in LIMITED_RULES
    assert rules_for_mode(ROLE_STORED) == rules_for_mode(ROLE_LIMITED) == LIMITED_RULES
    assert rules_for_mode(ROLE_BROAD) == BROAD_RULES
    with pytest.raises(ValueError):
        rules_for_mode("everything")


def test_a_new_role_removes_nothing() -> None:
    for mode in (ROLE_LIMITED, ROLE_BROAD, ROLE_STORED):
        assert not [x for x in role_lines(PORTS, "nxray", mode=mode) if x.startswith("no rule")]


def test_changing_mode_removes_the_old_modes_rules() -> None:
    to_broad = role_lines(PORTS, "nxray", mode=ROLE_BROAD, previous_mode=ROLE_LIMITED)
    gone = [x for x in to_broad if x.startswith("no rule")]
    assert gone == [f"no rule {n}" for n in _numbers(LIMITED_RULES)]
    assert to_broad.index(gone[-1]) < to_broad.index(BROAD_RULES[0])

    to_limited = role_lines(PORTS, "nxray", mode=ROLE_LIMITED, previous_mode=ROLE_BROAD)
    assert [x for x in to_limited if x.startswith("no rule")] == [
        f"no rule {n}" for n in _numbers(BROAD_RULES)
    ]


def test_limited_and_stored_share_their_rules_so_switching_removes_none() -> None:
    for before, after in ((ROLE_LIMITED, ROLE_STORED), (ROLE_STORED, ROLE_LIMITED)):
        lines = role_lines(PORTS, "nxray", mode=after, previous_mode=before)
        assert not [x for x in lines if x.startswith("no rule")]


def test_the_port_list_stays_in_every_mode() -> None:
    for mode in (ROLE_LIMITED, ROLE_BROAD, ROLE_STORED):
        lines = role_lines(PORTS, "nxray", mode=mode)
        assert lines.index("interface policy deny") < lines.index("permit interface Ethernet1/1")
        assert "permit interface port-channel1-4096" in lines


# ---- on the (pretend) switch ----------------------------------------------


def _enable(fake: FakeSwitch, **overrides):
    args = {
        "host": "192.0.2.10",
        "nxapi_port": 443,
        "ssh_port": 22,
        "admin_user": "admin",
        "admin_password": ADMIN_PASSWORD,
        "account_name": "nxray",
        "transport": fake.transport(),
        "ssh_opener": fake.ssh_opener(),
    }
    args.update(overrides)
    return enable_port_changes(**args)


@pytest.fixture
def fake() -> FakeSwitch:
    switch = FakeSwitch()
    switch.users["nxray"] = ("Nxray4Test9Pw", "network-operator")
    return switch


def test_broad_role_is_written_and_going_back_removes_it(fake: FakeSwitch) -> None:
    _enable(fake, mode=ROLE_BROAD)
    role = fake.roles[ROLE_NAME]
    assert role.rules[1] == ("permit", "conf t ; *")
    assert ("deny", "conf t ; username *") in role.rules.values()
    assert "conf t ; interface * ; shutdown" not in role.entities

    _enable(fake, mode=ROLE_LIMITED, previous_mode=ROLE_BROAD)
    role = fake.roles[ROLE_NAME]
    assert not [a for a, _ in role.rules.values() if a == "deny"]
    assert "conf t ; *" not in role.entities and "show *" not in role.entities
    assert role.entities == {r.split(" permit command ")[1] for r in LIMITED_RULES}


def test_limited_to_broad_leaves_none_of_the_limited_rules(fake: FakeSwitch) -> None:
    _enable(fake)
    _enable(fake, mode=ROLE_BROAD, previous_mode=ROLE_LIMITED)
    role = fake.roles[ROLE_NAME]
    assert sorted(role.rules) == sorted(_numbers(BROAD_RULES))


# ---- through the pages ------------------------------------------------------


def _csrf(client: TestClient, path: str = "/switch") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    return fake


def _setup(client: TestClient, **overrides: str):
    form = {
        "csrf": _csrf(client),
        "host": "192.0.2.10",
        "port": "443",
        "admin_user": "admin",
        "admin_password": ADMIN_PASSWORD,
        "account_name": "nxray",
        "turn_on_changes": "yes",
        "ssh_port": "22",
        "confirm_save": "yes",
    }
    form.update(overrides)
    return client.post("/switch/setup", data=form)


def _enable_page(client: TestClient, path: str = "/switch/enable-changes", **overrides: str):
    form = {
        "csrf": _csrf(client),
        "admin_user": "admin",
        "admin_password": ADMIN_PASSWORD,
        "ssh_port": "22",
        "confirm_save": "yes",
    }
    form.update(overrides)
    return client.post(path, data=form)


def _row(settings: Settings) -> sqlite3.Row:
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM switch_connection").fetchone()
    finally:
        conn.close()


def test_setup_defaults_to_the_limited_role_and_stores_no_login(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    assert _setup(logged_in).status_code == 200
    row = _row(settings)
    assert (row["role_mode"], row["role_version"]) == (ROLE_LIMITED, ROLE_VERSION)
    assert row["admin_user"] == "" and row["admin_password_encrypted"] == ""
    assert ADMIN_PASSWORD not in open(settings.db_path, "rb").read().decode("latin-1")


def test_setup_offers_the_three_choices(logged_in: TestClient, switch: FakeSwitch) -> None:
    body = logged_in.get("/switch").text
    for mode in ("limited", "broad", "stored"):
        assert f'name="role_mode" value="{mode}"' in body
    assert 'value="limited" checked' in body


def test_setup_with_the_login_stored_keeps_it_encrypted(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    response = _setup(logged_in, role_mode=ROLE_STORED)
    assert response.status_code == 200 and "admin login is stored" in _text(response.text)
    row = _row(settings)
    assert (row["role_mode"], row["admin_user"], row["admin_ssh_port"]) == (
        ROLE_STORED,
        "admin",
        22,
    )
    assert row["admin_password_encrypted"] and ADMIN_PASSWORD not in row["admin_password_encrypted"]
    assert ADMIN_PASSWORD not in open(settings.db_path, "rb").read().decode("latin-1")
    assert "Delete the stored admin login" in logged_in.get("/switch").text


def test_setup_refuses_an_unknown_mode(logged_in: TestClient, switch: FakeSwitch) -> None:
    response = _setup(logged_in, role_mode="everything")
    assert response.status_code == 400 and "how much access" in response.text
    assert switch.roles == {}


def test_broad_role_never_asks_for_a_role_update(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    assert _setup(logged_in, role_mode=ROLE_BROAD).status_code == 200
    row = _row(settings)
    assert (row["role_mode"], row["role_version"]) == (ROLE_BROAD, BROAD_ROLE_VERSION)
    body = _text(logged_in.get("/switch").text)
    assert "Broad role with a deny list" in body
    assert "Off: this version of NXray can also" not in body
    assert switch.roles[ROLE_NAME].rules[1] == ("permit", "conf t ; *")


def test_an_older_broad_role_is_flagged_and_updating_it_adds_the_eem_deny(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    # A broad role written before the EEM denies (BROAD_ROLE_VERSION 1000): an applet's
    # commands run as the switch's admin, so the role is flagged until it is written again.
    assert _setup(logged_in, role_mode=ROLE_BROAD).status_code == 200
    role = switch.roles[ROLE_NAME]
    for number in (23, 24):
        role.rules.pop(number)
    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE switch_connection SET role_version = 1000")
    conn.commit()
    conn.close()
    assert "does not deny EEM applets yet" in _text(logged_in.get("/switch").text)
    assert "does not yet deny EEM applets" in _text(logged_in.get("/vlans").text)

    response = _enable_page(logged_in)
    assert response.status_code == 200
    assert "The role now also denies EEM applets" in _text(response.text)
    assert switch.roles[ROLE_NAME].rules[23] == ("deny", "conf t ; event manager *")
    assert switch.roles[ROLE_NAME].rules[24] == ("deny", "conf t ; no event manager *")
    assert _row(settings)["role_version"] == BROAD_ROLE_VERSION
    assert "deny EEM applets" not in _text(logged_in.get("/switch").text)
    assert "deny EEM applets" not in _text(logged_in.get("/vlans").text)


def test_changing_the_mode_asks_for_the_login_and_removes_the_old_rules(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _setup(logged_in)
    response = _enable_page(logged_in, role_mode=ROLE_BROAD, admin_password="")
    assert response.status_code == 400 and "admin username and password" in response.text

    response = _enable_page(logged_in, role_mode=ROLE_BROAD, path="/switch/role-mode")
    assert response.status_code == 200 and "Broad role with a deny list" in response.text
    assert sorted(switch.roles[ROLE_NAME].rules) == sorted(_numbers(BROAD_RULES))
    assert _row(settings)["role_version"] == BROAD_ROLE_VERSION

    response = _enable_page(logged_in, role_mode=ROLE_LIMITED)
    assert response.status_code == 200
    assert max(switch.roles[ROLE_NAME].rules) == max(_numbers(LIMITED_RULES))
    row = _row(settings)
    assert (row["role_mode"], row["role_version"]) == (ROLE_LIMITED, ROLE_VERSION)


def test_going_to_the_stored_mode_stores_the_typed_login_and_leaving_it_forgets_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _setup(logged_in)
    _enable_page(logged_in, role_mode=ROLE_STORED, ssh_port="2222")
    row = _row(settings)
    assert (row["role_mode"], row["admin_ssh_port"]) == (ROLE_STORED, 2222)
    assert row["admin_password_encrypted"]

    _enable_page(logged_in, role_mode=ROLE_BROAD, ssh_port="22")
    row = _row(settings)
    assert (row["role_mode"], row["admin_user"], row["admin_password_encrypted"]) == (
        ROLE_BROAD,
        "",
        "",
    )


def test_with_the_login_stored_update_the_port_list_needs_no_login(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _setup(logged_in, role_mode=ROLE_STORED)
    switch.ssh_lines.clear()
    response = _enable_page(logged_in, admin_user="", admin_password="", ssh_port="")
    assert response.status_code == 200 and "The port list is updated" in response.text
    assert "configure terminal" in switch.ssh_lines
    assert "No login is needed" in logged_in.get("/switch").text


def test_deleting_the_stored_login_returns_to_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _setup(logged_in, role_mode=ROLE_STORED)
    rules = dict(switch.roles[ROLE_NAME].rules)
    response = logged_in.post("/switch/forget-admin-login", data={"csrf": _csrf(logged_in)})
    assert response.status_code == 200 and "stored admin login is deleted" in response.text
    row = _row(settings)
    assert (row["role_mode"], row["admin_user"], row["admin_password_encrypted"]) == (
        ROLE_LIMITED,
        "",
        "",
    )
    assert row["role_version"] == ROLE_VERSION
    assert switch.roles[ROLE_NAME].rules == rules  # the role on the switch is left alone
    again = logged_in.post("/switch/forget-admin-login", data={"csrf": _csrf(logged_in)})
    assert "had no admin login stored" in again.text


def test_forgetting_the_switch_forgets_the_stored_login(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _setup(logged_in, role_mode=ROLE_STORED)
    logged_in.post("/switch/forget", data={"csrf": _csrf(logged_in)})
    conn = sqlite3.connect(settings.db_path)
    assert conn.execute("SELECT COUNT(*) FROM switch_connection").fetchone()[0] == 0
    conn.close()


def test_role_mode_forms_need_the_csrf_token(logged_in: TestClient, switch: FakeSwitch) -> None:
    _setup(logged_in)
    for path in ("/switch/enable-changes", "/switch/role-mode", "/switch/forget-admin-login"):
        assert logged_in.post(path, data={"csrf": "wrong"}).status_code == 403


# ---- adding new rules by itself --------------------------------------------


def _behind(settings: Settings, version: int) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE switch_connection SET role_version = ?", (version,))
    conn.commit()
    conn.close()


def test_a_stored_login_adds_new_rules_at_start_up(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _setup(logged_in, role_mode=ROLE_STORED)
    _behind(settings, 10)
    updated = upgrade_stored_roles(
        settings, transport=switch.transport(), ssh_opener=switch.ssh_opener()
    )
    assert updated == 1
    row = _row(settings)
    assert (row["role_version"], row["role_mode"]) == (ROLE_VERSION, ROLE_STORED)
    assert switch.saved


@pytest.mark.parametrize("mode", [ROLE_LIMITED, ROLE_BROAD])
def test_other_modes_are_left_for_an_admin(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings, mode: str
) -> None:
    _setup(logged_in, role_mode=mode)
    _behind(settings, 10)
    switch.ssh_lines.clear()
    assert (
        upgrade_stored_roles(settings, transport=switch.transport(), ssh_opener=switch.ssh_opener())
        == 0
    )
    assert switch.ssh_lines == [] and _row(settings)["role_version"] == 10


def test_a_refused_upgrade_is_logged_not_raised(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _setup(logged_in, role_mode=ROLE_STORED)
    _behind(settings, 10)
    switch.users["admin"] = ("Changed-pw-1", "network-admin")
    assert (
        upgrade_stored_roles(settings, transport=switch.transport(), ssh_opener=switch.ssh_opener())
        == 0
    )
    assert _row(settings)["role_version"] == 10
