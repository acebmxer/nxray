"""Several switches in one NXray: adding them, picking one, keeping them apart."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app import history
from app.config import Settings
from app.config_tools import get_backup, list_backups, store_backup
from app.db import _MIGRATIONS, init_db, migrate, open_db
from app.switch_choice import SWITCH_COOKIE
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIRST = "192.0.2.10"
SECOND = "192.0.2.20"


def _csrf(client: TestClient, path: str = "/switch") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


class Fleet:
    """Two pretend switches behind one transport, told apart by address."""

    def __init__(self) -> None:
        self.first = FakeSwitch()
        self.second = FakeSwitch(hostname="leaf2")
        version = load_fixture("show_version")
        version["host_name"] = "leaf2"
        self.second.bodies["show version"] = version
        self.by_host = {FIRST: self.first, SECOND: self.second}

    def handle(self, request: httpx.Request) -> httpx.Response:
        return self.by_host[request.url.host].handle(request)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def clear(self) -> None:
        self.first.requests.clear()
        self.second.requests.clear()


def _add(client: TestClient, host: str, account: str = "nxray"):
    return client.post(
        "/switch/setup",
        data={
            "csrf": _csrf(client),
            "host": host,
            "port": "443",
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "account_name": account,
            "confirm_save": "yes",
        },
    )


def _ids(settings: Settings) -> dict[str, int]:
    with open_db(settings.db_path) as conn:
        return {r["host"]: r["id"] for r in conn.execute("SELECT id, host FROM switch_connection")}


def _pick(client: TestClient, switch_id: int, path: str = "/"):
    return client.post(
        "/switches/select",
        data={"csrf": _csrf(client, path), "switch_id": str(switch_id), "next": path},
    )


@pytest.fixture
def fleet(logged_in: TestClient) -> Fleet:
    fleet = Fleet()
    logged_in.app.state.nxapi_transport = fleet.transport()  # type: ignore[attr-defined]
    assert "NXray created the account" in _add(logged_in, FIRST).text
    assert "NXray created the account" in _add(logged_in, SECOND).text
    fleet.clear()
    return fleet


def test_a_second_switch_is_added_and_shown(
    logged_in: TestClient, fleet: Fleet, settings: Settings
) -> None:
    ids = _ids(settings)
    assert set(ids) == {FIRST, SECOND}
    assert logged_in.cookies.get(SWITCH_COOKIE) == str(ids[SECOND])
    assert logged_in.get("/").status_code == 200
    assert fleet.second.requests and not fleet.first.requests
    page = _text(logged_in.get("/switch").text)
    assert "NXray has 2 switches" in page
    assert "Add another switch" in page


def test_the_picker_lists_both_and_switches_every_page(
    logged_in: TestClient, fleet: Fleet, settings: Settings
) -> None:
    ids = _ids(settings)
    dashboard = logged_in.get("/").text
    assert 'action="/switches/select"' in dashboard
    assert f'value="{ids[FIRST]}"' in dashboard and f'value="{ids[SECOND]}"' in dashboard
    fleet.clear()

    response = _pick(logged_in, ids[FIRST], "/ports")
    assert response.status_code == 303
    assert response.headers["location"] == "/ports"
    assert logged_in.cookies.get(SWITCH_COOKIE) == str(ids[FIRST])
    fleet.clear()
    logged_in.get("/ports")
    assert fleet.first.requests and not fleet.second.requests


def test_the_picker_works_for_a_viewer(
    logged_in: TestClient, fleet: Fleet, settings: Settings
) -> None:
    ids = _ids(settings)
    logged_in.post(
        "/users/create",
        data={
            "csrf": _csrf(logged_in, "/users"),
            "new_username": "vera",
            "password": "viewer-password-1",
            "confirm_password": "viewer-password-1",
            "role": "viewer",
        },
    )
    logged_in.post("/logout")
    logged_in.cookies.clear()
    logged_in.post("/login", data={"username": "vera", "password": "viewer-password-1"})
    assert _pick(logged_in, ids[FIRST]).status_code == 303
    assert logged_in.cookies.get(SWITCH_COOKIE) == str(ids[FIRST])


def test_an_unknown_switch_is_not_picked(
    logged_in: TestClient, fleet: Fleet, settings: Settings
) -> None:
    ids = _ids(settings)
    response = _pick(logged_in, 999)
    assert response.status_code == 303
    assert logged_in.cookies.get(SWITCH_COOKIE) == str(ids[SECOND])


def test_the_picker_needs_the_csrf_token(logged_in: TestClient, fleet: Fleet) -> None:
    response = logged_in.post("/switches/select", data={"csrf": "nope", "switch_id": "1"})
    assert response.status_code == 403


def test_a_stale_cookie_falls_back_to_the_first_switch(
    logged_in: TestClient, fleet: Fleet, settings: Settings
) -> None:
    logged_in.cookies.set(SWITCH_COOKIE, "999")
    fleet.clear()
    logged_in.get("/")
    assert fleet.first.requests and not fleet.second.requests


def test_a_form_shown_for_one_switch_is_refused_after_picking_another(
    logged_in: TestClient, fleet: Fleet, settings: Settings
) -> None:
    """A page loaded for the second switch, then the first picked in another tab:
    the old page's form must not change the first switch."""
    ids = _ids(settings)
    old_token = _csrf(logged_in, "/ports/detail?name=Ethernet1/3")
    _pick(logged_in, ids[FIRST])
    response = logged_in.post(
        "/ports/label", data={"csrf": old_token, "name": "Ethernet1/3", "label": "NAS"}
    )
    assert response.status_code == 403
    with open_db(settings.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM port_labels").fetchone()[0] == 0
    # A fresh page's form works, on the switch it was shown for.
    response = logged_in.post(
        "/ports/label",
        data={
            "csrf": _csrf(logged_in, "/ports/detail?name=Ethernet1/3"),
            "name": "Ethernet1/3",
            "label": "NAS",
        },
    )
    assert response.status_code == 200
    with open_db(settings.db_path) as conn:
        rows = conn.execute("SELECT switch_id, label FROM port_labels").fetchall()
    assert [tuple(r) for r in rows] == [(ids[FIRST], "NAS")]


def test_labels_belong_to_their_switch(
    logged_in: TestClient, fleet: Fleet, settings: Settings
) -> None:
    ids = _ids(settings)
    path = "/ports/detail?name=Ethernet1/3"
    logged_in.post(
        "/ports/label",
        data={"csrf": _csrf(logged_in, path), "name": "Ethernet1/3", "label": "Backup NAS"},
    )
    assert 'name="label" type="text" value="Backup NAS"' in logged_in.get(path).text
    _pick(logged_in, ids[FIRST])
    assert 'name="label" type="text" value=""' in logged_in.get(path).text


def test_switch_page_actions_are_about_the_switch_shown(
    logged_in: TestClient, fleet: Fleet, settings: Settings
) -> None:
    ids = _ids(settings)
    _pick(logged_in, ids[FIRST], "/switch")
    fleet.clear()
    response = logged_in.post("/switch/test", data={"csrf": _csrf(logged_in)})
    assert response.status_code == 200
    assert fleet.first.requests and not fleet.second.requests
    with open_db(settings.db_path) as conn:
        tested = dict(conn.execute("SELECT id, last_tested_at IS NOT NULL FROM switch_connection"))
    # Setup records a test result for both; this one is newer on the first only.
    assert tested == {ids[FIRST]: 1, ids[SECOND]: 1}


def test_moving_a_switch_onto_another_switchs_address_is_refused(
    logged_in: TestClient, fleet: Fleet, settings: Settings
) -> None:
    response = logged_in.post(
        "/switch/address", data={"csrf": _csrf(logged_in), "host": FIRST, "port": "443"}
    )
    assert response.status_code == 400
    assert "NXray already has another switch at 192.0.2.10" in response.text
    assert set(_ids(settings)) == {FIRST, SECOND}


def test_forgetting_one_switch_keeps_the_other(
    logged_in: TestClient, fleet: Fleet, settings: Settings
) -> None:
    ids = _ids(settings)
    history.Sampler(settings, fleet.transport).sample_once()
    response = logged_in.post("/switch/forget", data={"csrf": _csrf(logged_in)})
    assert "NXray forgot the switch leaf2" in _text(response.text)
    assert _ids(settings) == {FIRST: ids[FIRST]}
    assert logged_in.cookies.get(SWITCH_COOKIE) == str(ids[FIRST])
    with open_db(settings.db_path) as conn:
        kept = {row[0] for row in conn.execute("SELECT DISTINCT switch_id FROM history")}
    assert kept == {ids[FIRST]}
    fleet.clear()
    logged_in.get("/")
    assert fleet.first.requests and not fleet.second.requests


def test_forgetting_the_last_switch_shows_the_setup_form(
    logged_in: TestClient, fleet: Fleet
) -> None:
    logged_in.post("/switch/forget", data={"csrf": _csrf(logged_in)})
    response = logged_in.post("/switch/forget", data={"csrf": _csrf(logged_in)})
    assert "Set up the switch" in response.text
    assert SWITCH_COOKIE not in logged_in.cookies


def test_the_sampler_reads_every_switch_and_keeps_their_history_apart(
    logged_in: TestClient, fleet: Fleet, settings: Settings
) -> None:
    ids = _ids(settings)
    sampler = history.Sampler(settings, fleet.transport)
    assert sampler.sample_once() is None
    assert len(fleet.first.requests) == 1 and len(fleet.second.requests) == 1
    with open_db(settings.db_path) as conn:
        counts = dict(
            conn.execute("SELECT switch_id, COUNT(*) FROM history GROUP BY switch_id").fetchall()
        )
    assert set(counts) == {ids[FIRST], ids[SECOND]}
    assert counts[ids[FIRST]] == counts[ids[SECOND]]


def test_a_switch_that_fails_is_named_and_the_other_still_sampled(
    logged_in: TestClient, fleet: Fleet, settings: Settings
) -> None:
    ids = _ids(settings)
    fleet.first.reachable = False
    message = history.Sampler(settings, fleet.transport).sample_once()
    assert message and message.startswith("nexus-lab (192.0.2.10): ")
    with open_db(settings.db_path) as conn:
        kept = {row[0] for row in conn.execute("SELECT DISTINCT switch_id FROM history")}
    assert kept == {ids[SECOND]}


def test_alerts_name_their_switch(logged_in: TestClient, fleet: Fleet, settings: Settings) -> None:
    fleet.first.reachable = False
    sampler = history.Sampler(settings, fleet.transport, background_alerts=False)
    sampler.sample_once()
    sampler.sample_once()
    with open_db(settings.db_path) as conn:
        problems = conn.execute("SELECT switch_id, key FROM alert_open").fetchall()
        logged = conn.execute("SELECT kind, switch FROM alert_log").fetchall()
    assert [tuple(row) for row in problems] == [(_ids(settings)[FIRST], "unreachable")]
    assert [tuple(row) for row in logged] == [("problem", "nexus-lab (192.0.2.10)")]
    page = _text(logged_in.get("/alerts").text)
    assert "nexus-lab (192.0.2.10) NXray cannot read the switch" in page


def test_the_history_page_shows_the_switch_picked(
    logged_in: TestClient, fleet: Fleet, settings: Settings
) -> None:
    ids = _ids(settings)
    fleet.first.reachable = False
    history.Sampler(settings, fleet.transport).sample_once()
    assert "No data in this range yet." not in logged_in.get("/history").text
    _pick(logged_in, ids[FIRST], "/history")
    assert "No data in this range yet." in logged_in.get("/history").text


# ---- storage ----


def test_backups_belong_to_their_switch(tmp_path: Path) -> None:
    db = tmp_path / "nxray.db"
    init_db(db)
    with open_db(db) as conn:
        one = store_backup(conn, 1, config="hostname a", created_by="admin", switch="a")
        two = store_backup(conn, 2, config="hostname b", created_by="admin", switch="b")
        assert [b.id for b in list_backups(conn, 1)] == [one]
        assert [b.id for b in list_backups(conn, 2)] == [two]
        assert get_backup(conn, 1, two) is None
        found = get_backup(conn, 2, two)
        assert found is not None and found[1] == "hostname b"


def _schema_12(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    for index, script in enumerate(_MIGRATIONS[:12], start=1):
        conn.executescript(script)
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (index,))
    conn.commit()
    return conn


def test_an_existing_install_keeps_its_switch_and_what_belongs_to_it(tmp_path: Path) -> None:
    conn = _schema_12(tmp_path / "old.db")
    conn.execute(
        "INSERT INTO switch_connection (id, host, port, username, password_encrypted, "
        "switch_hostname, created_at, config_saved, role_version) "
        "VALUES (1, 'h', 443, 'nxray', 'x', 'sw', 0, 1, 14)"
    )
    conn.execute("INSERT INTO history (ts, metric, item, value) VALUES (1, 'cpu', '', 5)")
    conn.execute(
        "INSERT INTO port_labels (port, label, updated_at, updated_by) "
        "VALUES ('Ethernet1/1', 'NAS', 1, 'admin')"
    )
    conn.execute("INSERT INTO alert_open (key, since, message) VALUES ('cpu', 1, 'hot')")
    conn.execute(
        "INSERT INTO config_backups (created_at, created_by, switch, config) "
        "VALUES (1, 'admin', 'h', 'hostname sw')"
    )
    conn.commit()
    assert migrate(conn) == len(_MIGRATIONS)
    for table in ("history", "port_labels", "alert_open", "config_backups"):
        assert [r[0] for r in conn.execute(f"SELECT switch_id FROM {table}")] == [1], table
    row = conn.execute("SELECT id, role_version FROM switch_connection").fetchone()
    assert tuple(row) == (1, 14)
    conn.execute(
        "INSERT INTO switch_connection (host, port, username, password_encrypted, "
        "switch_hostname, created_at, config_saved) VALUES ('h2', 443, 'n', 'x', 's', 0, 1)"
    )
    assert conn.execute("SELECT MAX(id) FROM switch_connection").fetchone()[0] == 2
    conn.close()


def test_a_forgotten_switchs_leftovers_are_not_inherited(tmp_path: Path) -> None:
    conn = _schema_12(tmp_path / "old.db")
    conn.execute("INSERT INTO history (ts, metric, item, value) VALUES (1, 'cpu', '', 5)")
    conn.commit()
    migrate(conn)
    conn.execute(
        "INSERT INTO switch_connection (host, port, username, password_encrypted, "
        "switch_hostname, created_at, config_saved) VALUES ('h', 443, 'n', 'x', 's', 0, 1)"
    )
    assert conn.execute("SELECT id FROM switch_connection").fetchone()[0] == 2
    conn.close()


def test_a_fresh_install_starts_at_switch_1(tmp_path: Path) -> None:
    db = tmp_path / "new.db"
    init_db(db)
    with open_db(db) as conn:
        conn.execute(
            "INSERT INTO switch_connection (host, port, username, password_encrypted, "
            "switch_hostname, created_at, config_saved) VALUES ('h', 443, 'n', 'x', 's', 0, 1)"
        )
        assert conn.execute("SELECT id FROM switch_connection").fetchone()[0] == 1


def test_the_picker_comes_back_to_the_same_page(logged_in: TestClient, fleet: Fleet) -> None:
    page = logged_in.get("/ports/detail?name=Ethernet1/3").text
    assert 'name="next" value="/ports/detail?name=Ethernet1/3"' in page
    after_a_form = logged_in.post("/switch/test", data={"csrf": _csrf(logged_in)}).text
    assert 'name="next" value="/"' in after_a_form
