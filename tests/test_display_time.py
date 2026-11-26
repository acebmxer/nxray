"""The time zone NXray shows times in (issue #110): the clock, the graph axes, the
Settings page and the places that write a time."""

from __future__ import annotations

import html
import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import alerts
from app.charts import time_label, time_ticks
from app.config import Settings
from app.db import init_db, open_db
from app.display_time import (
    abbreviation,
    clock,
    load_zone,
    local_time,
    moment_of,
    offset_at,
    save_zone,
    set_zone,
    zone_choices,
    zone_name,
)

# 2026-11-26 12:38:55 UTC: winter, so US Eastern is UTC-5 (EST).
WINTER = 1_795_696_735
# 2026-07-01 12:00:00 UTC: summer, so US Eastern is UTC-4 (EDT).
SUMMER = 1_782_907_200


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _csrf(client: TestClient, path: str = "/settings") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match
    return match.group(1)


def test_utc_is_the_default_and_changes_nothing() -> None:
    assert zone_name() == "UTC"
    assert offset_at(WINTER) == 0
    assert local_time(WINTER) == "2026-11-26 12:38:55 UTC"
    assert local_time(WINTER, seconds=False) == "2026-11-26 12:38 UTC"


def test_a_zone_shifts_the_clock_and_follows_summer_time() -> None:
    set_zone("America/New_York")
    assert zone_name() == "America/New_York"
    assert offset_at(WINTER) == -5 * 3600
    assert local_time(WINTER) == "2026-11-26 07:38:55 EST"
    assert offset_at(SUMMER) == -4 * 3600
    assert local_time(SUMMER) == "2026-07-01 08:00:00 EDT"
    assert abbreviation(SUMMER) == "EDT"
    assert clock(WINTER, "%H:%M") == "07:38"


def test_a_zone_with_a_half_hour_offset() -> None:
    set_zone("Asia/Kolkata")
    assert offset_at(WINTER) == 5 * 3600 + 1800
    assert clock(WINTER, "%H:%M") == "18:08"


def test_moment_of_is_the_reverse_of_the_local_clock() -> None:
    for name in ("UTC", "America/New_York", "Asia/Kolkata", "Pacific/Auckland"):
        set_zone(name)
        for moment in (WINTER, SUMMER, 0):
            local = moment + offset_at(moment)
            assert moment_of(local) == moment, name


def test_an_unknown_zone_is_refused_and_the_old_one_kept() -> None:
    set_zone("Europe/Paris")
    with pytest.raises(ValueError):
        set_zone("Mars/Olympus_Mons")
    with pytest.raises(ValueError):
        set_zone("../../etc/passwd")
    assert zone_name() == "Europe/Paris"


def test_the_pick_list_has_utc_first_and_no_confusing_names() -> None:
    names = zone_choices()
    assert names[0] == "UTC"
    assert "America/New_York" in names and "Europe/London" in names
    assert not [n for n in names if n.startswith(("posix/", "right/", "Etc/"))]
    assert names[1:] == sorted(names[1:])


def test_axis_ticks_land_on_the_zones_round_hours() -> None:
    set_zone("America/New_York")
    moments, step = time_ticks(WINTER - 4 * 3600, WINTER)
    assert step == 3600
    assert [clock(m, "%H:%M") for m in moments] == ["04:00", "05:00", "06:00", "07:00"]
    # A zone 5:45 ahead still gets labels on its own round hours.
    set_zone("Asia/Kathmandu")
    moments, step = time_ticks(WINTER - 4 * 3600, WINTER)
    assert all(clock(m, "%M") == "00" for m in moments)


def test_a_day_boundary_is_the_zones_midnight() -> None:
    set_zone("America/New_York")
    midnight = 1_795_669_200  # 2026-11-26 00:00 on New York's clock (05:00 UTC)
    assert clock(midnight, "%H:%M") == "00:00"
    assert time_label(midnight, 4 * 3600) == "Nov 26"
    assert time_label(midnight + 4 * 3600, 4 * 3600) == "04:00"
    # In UTC the same instant is 05:00, an ordinary label.
    set_zone("UTC")
    assert time_label(midnight, 4 * 3600) == "05:00"


def test_the_choice_is_stored_and_loaded(settings: Settings) -> None:
    init_db(settings.db_path)
    with open_db(settings.db_path) as conn:
        assert load_zone(conn) == "UTC"
        save_zone(conn, "Europe/Berlin")
    set_zone("UTC")
    with open_db(settings.db_path) as conn:
        assert load_zone(conn) == "Europe/Berlin"
        with pytest.raises(ValueError):
            save_zone(conn, "Nowhere/Land")
        stored = conn.execute("SELECT time_zone FROM display_settings").fetchone()[0]
    assert stored == "Europe/Berlin"


def test_a_stored_name_the_machine_lacks_falls_back_to_utc(settings: Settings) -> None:
    init_db(settings.db_path)
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("UPDATE display_settings SET time_zone = 'Atlantis/Lost'")
    assert load_zone(conn) == "UTC"
    conn.close()


def test_the_alert_message_is_stamped_in_the_zone() -> None:
    event = alerts.AlertEvent("problem", "Fan Fan2 reports Failure.", "fan:Fan2")
    set_zone("America/New_York")
    _, text = alerts.compose([event], "", WINTER)
    assert "2026-11-26 07:38:55 EST" in text.splitlines()[0]
    set_zone("UTC")
    _, text = alerts.compose([event], "", WINTER)
    assert "2026-11-26 12:38:55 UTC" in text.splitlines()[0]


def test_the_settings_page_offers_the_choice_and_saves_it(
    logged_in: TestClient, settings: Settings
) -> None:
    page = logged_in.get("/settings").text
    assert 'action="/settings/time-zone"' in page
    assert '<option value="UTC" selected>' in page
    assert '<option value="America/New_York">' in page

    response = logged_in.post(
        "/settings/time-zone", data={"csrf": _csrf(logged_in), "time_zone": "America/New_York"}
    )
    assert response.status_code == 200
    assert "Times are now shown in America/New_York." in _text(response.text)
    assert '<option value="America/New_York" selected>' in response.text
    assert zone_name() == "America/New_York"
    with open_db(settings.db_path) as conn:
        assert conn.execute("SELECT time_zone FROM display_settings").fetchone()[0] == (
            "America/New_York"
        )
        logged = [r[0] for r in conn.execute("SELECT what FROM activity")]
    assert "Set the time zone to America/New_York" in logged


def test_the_pages_and_their_notes_follow_the_choice(logged_in: TestClient) -> None:
    from app.dependencies import templates

    logged_in.post(
        "/settings/time-zone", data={"csrf": _csrf(logged_in), "time_zone": "Asia/Tokyo"}
    )
    # The notes under the graphs (history.html, traffic.html, _traffic_cards.html) say so.
    note = templates.env.from_string("Times are {{ time_zone_name() }}.")
    assert note.render() == "Times are Asia/Tokyo."
    for name in ("history.html", "traffic.html", "_traffic_cards.html"):
        source = (templates.env.loader.get_source(templates.env, name))[0]
        assert "Times are UTC" not in source, name
        assert "Times are {{ time_zone_name() }}" in source, name
    # The activity log writes the time of the change in that zone.
    activity = _text(logged_in.get("/activity").text)
    assert "Set the time zone to Asia/Tokyo" in activity
    assert re.search(r"\d\d:\d\d:\d\d JST", activity)


def test_an_unknown_zone_is_refused_by_the_page(logged_in: TestClient) -> None:
    response = logged_in.post(
        "/settings/time-zone", data={"csrf": _csrf(logged_in), "time_zone": "Mars/Base"}
    )
    assert response.status_code == 400
    assert "Choose a time zone from the list." in _text(response.text)
    assert zone_name() == "UTC"


def test_only_an_admin_with_the_token_can_change_it(
    logged_in: TestClient, settings: Settings
) -> None:
    assert (
        logged_in.post(
            "/settings/time-zone", data={"csrf": "wrong", "time_zone": "Asia/Tokyo"}
        ).status_code
        == 403
    )
    token = _csrf(logged_in)
    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE users SET role = 'operator'")
    conn.commit()
    conn.close()
    response = logged_in.post(
        "/settings/time-zone", data={"csrf": token, "time_zone": "Asia/Tokyo"}
    )
    assert response.status_code == 403
    assert zone_name() == "UTC"


def test_the_next_start_uses_the_stored_zone(settings: Settings, make_client) -> None:
    init_db(settings.db_path)
    with open_db(settings.db_path) as conn:
        save_zone(conn, "Europe/London")
    set_zone("UTC")
    make_client(settings)  # starting the app loads the stored choice
    assert zone_name() == "Europe/London"
