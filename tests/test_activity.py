"""The activity log: recording, listing and the Activity page."""

from __future__ import annotations

import html
import re
import sqlite3

from fastapi.testclient import TestClient

from app.activity import KEEP_DAYS, activity_csv, list_activity, record_activity, utc_time
from app.config import Settings
from app.db import init_db, open_db


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match
    return match.group(1)


def test_record_list_filter_and_prune(settings: Settings) -> None:
    init_db(settings.db_path)
    with open_db(settings.db_path) as conn:
        record_activity(conn, "old", "Ports", "too old", now=1000.0)
        now = 1000.0 + KEEP_DAYS * 86400 + 10
        record_activity(conn, "alice", "Ports", "Ethernet1/3: shutdown", "192.0.2.10", now=now)
        record_activity(conn, "bob", "VLANs", "Created VLAN 30 (100%_off)", now=now + 1)
        assert [e.username for e in list_activity(conn)] == ["bob", "alice"]
        assert [e.what for e in list_activity(conn, username="alice")] == ["Ethernet1/3: shutdown"]
        assert [e.area for e in list_activity(conn, area="VLANs")] == ["VLANs"]
        assert len(list_activity(conn, search="ethernet1/3")) == 1
        assert len(list_activity(conn, search="192.0.2.10")) == 1
        # LIKE wildcards in the search are taken literally.
        assert len(list_activity(conn, search="%_")) == 1
        assert len(list_activity(conn, search="0%")) == 1


def test_csv_neutralises_formulas() -> None:
    from app.activity import Activity

    out = activity_csv([Activity(1, 0.0, "=evil", "Ports", "+1", "")])
    assert out.splitlines()[1] == "1970-01-01T00:00:00Z,'=evil,Ports,,'+1"
    assert utc_time(0.0) == "1970-01-01 00:00:00 UTC"


def test_page_is_for_admins_only(logged_in: TestClient, settings: Settings) -> None:
    assert 'href="/activity"' in logged_in.get("/").text
    assert "Nothing has been changed through NXray yet" in _text(logged_in.get("/activity").text)
    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE users SET role = 'operator'")
    conn.commit()
    conn.close()
    assert logged_in.get("/activity").status_code == 403
    assert logged_in.get("/activity.csv").status_code == 403


def test_account_changes_are_recorded_and_downloadable(logged_in: TestClient) -> None:
    response = logged_in.post(
        "/users/create",
        data={
            "csrf": _csrf(logged_in, "/users"),
            "new_username": "alice",
            "password": "a-long-enough-password",
            "confirm_password": "a-long-enough-password",
            "role": "viewer",
        },
    )
    assert response.status_code == 200, _text(response.text)
    text = _text(logged_in.get("/activity").text)
    assert "Users Added the account alice as viewer" in text
    assert "a-long-enough-password" not in text
    filtered = _text(logged_in.get("/activity?area=Ports").text)
    assert "No change matches" in filtered
    csv = logged_in.get("/activity.csv")
    assert csv.headers["content-type"].startswith("text/csv")
    assert "Added the account alice as viewer" in csv.text
