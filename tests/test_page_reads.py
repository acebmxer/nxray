"""Recent switch answers reused by the pages a person opens (#98)."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, load_settings
from app.page_reads import LONG_LIVED, MAX_ANSWERS, PageReads, lifetime
from tests.conftest import with_settings
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

SWITCH = ("192.0.2.10", "443", "nxray")


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Reads:
    """A pretend switch for ``PageReads``: counts what it was asked and answers each
    command with a body saying how many times it has been read."""

    def __init__(self) -> None:
        self.asked: list[list[str]] = []
        self.reads: dict[str, int] = {}

    def __call__(self, commands: list[str]) -> list[dict]:
        self.asked.append(list(commands))
        bodies = []
        for command in commands:
            self.reads[command] = self.reads.get(command, 0) + 1
            bodies.append({"command": command, "read": self.reads[command]})
        return bodies


def test_only_the_listed_commands_are_kept() -> None:
    assert lifetime("show feature", 15) == 15
    assert lifetime("show interface Ethernet1/1 capabilities", 15) == 15
    assert lifetime("show interface Ethernet1/1 flowcontrol", 15) == 15
    assert lifetime("show interface Ethernet1/1 counters storm-control", 15) == 15
    assert lifetime("show cdp interface Ethernet1/1", 15) == 15
    assert lifetime("show lldp interface Ethernet1/1", 15) == 15
    # a running figure or a counter a page is opened to look at is always read
    assert lifetime("show system resources", 15) == 0
    assert lifetime("show system uptime", 15) == 0
    assert lifetime("show environment", 15) == 0
    assert lifetime("show interface Ethernet1/1", 15) == 0
    assert lifetime("show queuing interface", 15) == 0
    assert lifetime("show feature", 0) == 0


def test_show_version_is_kept_longer_but_never_shorter() -> None:
    assert lifetime("show version", 15) == LONG_LIVED["show version"]
    assert lifetime("show version", 120) == LONG_LIVED["show version"]
    assert lifetime("show version", 0) == 0


def test_the_second_page_asks_the_switch_only_for_what_it_lacks() -> None:
    clock, reads = Clock(), Reads()
    reuse = PageReads(clock).reader(15)
    first = reuse(SWITCH, ["show feature", "show interface brief", "show environment"], reads)
    clock.now += 5
    second = reuse(SWITCH, ["show vrf", "show feature", "show environment"], reads)
    assert reads.asked == [
        ["show feature", "show interface brief", "show environment"],
        ["show vrf", "show environment"],
    ]
    assert [b["command"] for b in first] == [
        "show feature",
        "show interface brief",
        "show environment",
    ]
    assert [b["command"] for b in second] == ["show vrf", "show feature", "show environment"]
    assert second[1]["read"] == 1  # reused
    assert second[2]["read"] == 2  # read again: never kept


def test_an_answer_is_read_again_after_its_seconds() -> None:
    clock, reads = Clock(), Reads()
    reuse = PageReads(clock).reader(15)
    reuse(SWITCH, ["show feature"], reads)
    clock.now += 14
    assert reuse(SWITCH, ["show feature"], reads)[0]["read"] == 1
    clock.now += 2
    assert reuse(SWITCH, ["show feature"], reads)[0]["read"] == 2


def test_each_switch_and_account_has_its_own_answers() -> None:
    reads = Reads()
    reuse = PageReads(Clock()).reader(15)
    reuse(SWITCH, ["show feature"], reads)
    reuse(("192.0.2.11", "443", "nxray"), ["show feature"], reads)
    reuse(("192.0.2.10", "443", "other"), ["show feature"], reads)
    assert len(reads.asked) == 3


def test_clearing_forgets_everything() -> None:
    reads = Reads()
    cache = PageReads(Clock())
    reuse = cache.reader(15)
    reuse(SWITCH, ["show feature", "show version"], reads)
    cache.clear()
    assert reuse(SWITCH, ["show feature", "show version"], reads)[0]["read"] == 2


def test_a_page_cannot_change_what_another_page_gets() -> None:
    reads = Reads()
    reuse = PageReads(Clock()).reader(15)
    (body,) = reuse(SWITCH, ["show feature"], reads)
    body["read"] = 99
    body["extra"] = True
    (again,) = reuse(SWITCH, ["show feature"], reads)
    assert again == {"command": "show feature", "read": 1}


def test_a_failed_read_keeps_nothing() -> None:
    cache = PageReads(Clock())
    reuse = cache.reader(15)
    reads = Reads()

    def refused(commands: list[str]) -> list[dict]:
        raise RuntimeError("the switch said no")

    with pytest.raises(RuntimeError):
        reuse(SWITCH, ["show feature", "show vrf"], refused)
    assert reuse(SWITCH, ["show feature", "show vrf"], reads)[0]["read"] == 1


def test_a_command_asked_twice_in_one_page_is_read_once() -> None:
    reads = Reads()
    bodies = PageReads(Clock()).reader(15)(SWITCH, ["show feature", "show feature"], reads)
    assert reads.asked == [["show feature"]]
    assert bodies[0] == bodies[1]


def test_the_answers_kept_are_capped() -> None:
    clock, reads = Clock(), Reads()
    cache = PageReads(clock)
    reuse = cache.reader(15)
    for port in range(MAX_ANSWERS + 50):
        clock.now += 0.001
        reuse(SWITCH, [f"show cdp interface Ethernet1/{port}"], reads)
    assert len(cache._answers) <= MAX_ANSWERS


def test_old_answers_are_dropped() -> None:
    clock, reads = Clock(), Reads()
    cache = PageReads(clock)
    reuse = cache.reader(15)
    reuse(SWITCH, ["show feature"], reads)
    clock.now += max(LONG_LIVED.values()) + 1
    reuse(SWITCH, ["show vrf"], reads)
    assert [command for _switch, command in cache._answers] == ["show vrf"]


def test_the_setting_comes_from_the_environment(tmp_path, monkeypatch) -> None:
    from app.config import ConfigError

    monkeypatch.setenv("NXRAY_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NXRAY_ADMIN_PASSWORD_HASH", "$argon2id$x")
    assert load_settings().page_read_seconds == 15
    monkeypatch.setenv("NXRAY_PAGE_READ_SECONDS", "0")
    assert load_settings().page_read_seconds == 0
    monkeypatch.setenv("NXRAY_PAGE_READ_SECONDS", "60")
    assert load_settings().page_read_seconds == 60
    monkeypatch.setenv("NXRAY_PAGE_READ_SECONDS", "121")
    with pytest.raises(ConfigError):
        load_settings()


# ---- through the app --------------------------------------------------------------


@pytest.fixture
def reusing(settings: Settings, make_client) -> TestClient:
    """A signed-in client for an app that reuses recent answers."""
    client = make_client(with_settings(settings, page_read_seconds=15))
    response = client.post(
        "/login", data={"username": "admin", "password": "correct-horse-battery", "next": "/"}
    )
    assert response.status_code == 303
    return client


@pytest.fixture
def switch(reusing: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
    reusing.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', reusing.get("/switch").text)
    assert csrf
    response = reusing.post(
        "/switch/setup",
        data={
            "csrf": csrf.group(1),
            "host": "192.0.2.10",
            "port": "443",
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "account_name": "nxray",
            "confirm_save": "yes",
        },
    )
    assert "NXray created the account" in response.text
    reusing.app.state.page_reads.clear()  # type: ignore[attr-defined]
    fake.requests.clear()
    return fake


def _commands(switch: FakeSwitch) -> list[str]:
    return [command for request in switch.requests for command in request]


def test_a_second_page_does_not_ask_again_for_what_the_first_read(
    reusing: TestClient, switch: FakeSwitch
) -> None:
    assert reusing.get("/ports").status_code == 200
    first = _commands(switch)
    switch.requests.clear()
    assert reusing.get("/neighbors").status_code == 200
    second = _commands(switch)
    for command in ("show interface", "show interface status", "show port-channel summary"):
        assert command in first
        assert command not in second
    # Whatever the second page did ask for, it did not ask again for a kept answer.
    assert all(command not in first or lifetime(command, 15) == 0 for command in second)


def test_the_same_page_twice_asks_the_switch_once(reusing: TestClient, switch: FakeSwitch) -> None:
    first = reusing.get("/ports")
    asked = len(switch.requests)
    again = reusing.get("/ports")
    assert asked > 0
    assert len(switch.requests) == asked
    assert again.text == first.text


def test_a_form_sent_empties_it(reusing: TestClient, switch: FakeSwitch) -> None:
    reusing.get("/ports")
    kept = reusing.app.state.page_reads._answers  # type: ignore[attr-defined]
    assert kept
    refused = reusing.post("/login", data={"username": "admin", "password": "wrong"})
    assert refused.status_code != 303
    assert not kept


@pytest.mark.parametrize("asked", ["max-age=0", "no-cache"])
def test_a_reload_reads_the_switch_again(
    reusing: TestClient, switch: FakeSwitch, asked: str
) -> None:
    reusing.get("/ports")
    switch.requests.clear()
    reusing.get("/ports", headers={"Cache-Control": asked})
    assert "show interface" in _commands(switch)


def test_nothing_is_reused_when_the_setting_is_zero(
    logged_in: TestClient, settings: Settings
) -> None:
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', logged_in.get("/switch").text)
    assert csrf
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": csrf.group(1),
            "host": "192.0.2.10",
            "port": "443",
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "account_name": "nxray",
            "confirm_save": "yes",
        },
    )
    fake.requests.clear()
    logged_in.get("/ports")
    asked = len(fake.requests)
    logged_in.get("/ports")
    assert len(fake.requests) == 2 * asked


def test_a_page_refreshing_itself_reads_through_the_live_cache(
    reusing: TestClient, switch: FakeSwitch
) -> None:
    """Live figures are read at their own floor, never from the answers kept for a page a
    person opens: a Live page asking for 3 seconds must not get 15 second old figures."""
    reusing.get("/vlans")
    switch.requests.clear()
    live = {"X-Requested-With": "nxray-live"}
    assert reusing.get("/vlans", headers=live).status_code == 200
    assert len(switch.requests) > 0
    switch.requests.clear()
    assert reusing.get("/live/ports", headers=live).status_code == 200
    assert len(switch.requests) > 0


def test_the_dashboard_still_reads_what_changes_every_time(
    reusing: TestClient, switch: FakeSwitch
) -> None:
    reusing.get("/")
    reusing.get("/")
    assert len(switch.requests) == 2
    assert all("show system resources" in request for request in switch.requests)
    assert "show interface brief" not in switch.requests[1]
