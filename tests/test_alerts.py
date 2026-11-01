"""Alerts: noticing problems, keeping them open, sending them, and the Alerts page."""

from __future__ import annotations

import copy
import hashlib
import hmac
import html
import json
import re
import smtplib
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from app import alerts, history
from app.alerts import AlertEvent, AlertMonitor, AlertRules, AlertSettingsError
from app.config import Settings
from app.db import init_db, open_db
from app.ports import parse_ports
from app.switch import Fan, PowerSupply, TempSensor, parse_environment, parse_resources
from app.users import create_user
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

HOOK_URL = "https://hooks.example.com/services/T000/B000/secret-token"


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _csrf(client: TestClient, path: str = "/alerts") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match
    return match.group(1)


def _reading(*, up: tuple[str, ...] = ("Ethernet1/3",), describe: dict[str, str] | None = None):
    interfaces = load_fixture("show_interface")
    for row in interfaces["TABLE_interface"]["ROW_interface"]:
        if row["interface"] in up:
            row.update({"state": "up", "admin_state": "up"})
        elif row["interface"] in (describe or {}):
            row.update(
                {"state": "down", "admin_state": "up", "state_rsn_desc": "Link not connected"}
            )
        if row["interface"] in (describe or {}):
            row["desc"] = describe[row["interface"]]
    return (
        parse_environment(load_fixture("show_environment")),
        parse_resources(load_fixture("show_system_resources")),
        parse_ports(interfaces, {}, {}),
    )


def _db(settings: Settings):
    init_db(settings.db_path)
    return open_db(settings.db_path)


class FakeSMTP:
    """Stands in for smtplib.SMTP and SMTP_SSL; remembers what was sent."""

    sent: list[tuple[str, str]] = []
    calls: list[str] = []
    fail: Exception | None = None

    def __init__(self, host: str, port: int, timeout: float = 0, context=None) -> None:
        FakeSMTP.calls.append(f"connect {host}:{port}{' ssl' if context else ''}")

    def __enter__(self) -> FakeSMTP:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def starttls(self, context=None) -> None:
        FakeSMTP.calls.append("starttls")

    def login(self, user: str, password: str) -> None:
        FakeSMTP.calls.append(f"login {user} {password}")

    def send_message(self, message) -> None:
        if FakeSMTP.fail:
            raise FakeSMTP.fail
        FakeSMTP.sent.append((message["Subject"], message.get_content()))


@pytest.fixture
def smtp(monkeypatch: pytest.MonkeyPatch) -> type[FakeSMTP]:
    FakeSMTP.sent, FakeSMTP.calls, FakeSMTP.fail = [], [], None
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)
    return FakeSMTP


class Receiver:
    """A webhook receiver behind httpx.MockTransport."""

    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.requests: list[httpx.Request] = []

    def transport(self) -> httpx.MockTransport:
        def handle(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return httpx.Response(self.status)

        return httpx.MockTransport(handle)

    def bodies(self) -> list[dict]:
        return [json.loads(request.content) for request in self.requests]


# ---- noticing problems ----


def _find(rules: AlertRules, reading, **kw):
    environment, resources, ports = reading
    args = {"labels": {}, "new_errors": {}, "was_up": None, "open_keys": set()}
    args.update(kw)
    return alerts.find_problems(rules, environment, resources, ports, **args)


def test_a_healthy_switch_has_no_problems() -> None:
    assert _find(AlertRules(), _reading()) == {}


def test_temperature_fans_and_power_use_the_switchs_own_judgement() -> None:
    environment, resources, ports = _reading()
    environment = replace(
        environment,
        temperatures=[TempSensor("1", "Intake", 92, 80, 90, "Ok")],
        fans=[Fan("Fan2", "m", "back-to-front", "Failure")],
        power_supplies=[PowerSupply("2", "m", None, None, None, "Shutdown")],
    )
    found = _find(AlertRules(), (environment, resources, ports))
    assert found["temperature:Intake:minor"].startswith("Temperature Intake is 92°C")
    assert "major limit of 90°C" in found["temperature:Intake:major"]
    assert found["fan:Fan2"] == "Fan Fan2 reports Failure."
    assert found["power:2"] == "Power supply 2 reports Shutdown."
    off = AlertRules(temperature=False, fans=False, power=False)
    assert _find(off, (environment, resources, ports)) == {}


def test_cpu_memory_and_errors_have_limits() -> None:
    environment, resources, ports = _reading()
    busy = replace(resources, cpu_used_percent=97.5, memory_used_percent=40.0)
    rules = AlertRules(cpu_percent=90, memory_percent=80, port_errors=10)
    found = _find(
        rules, (environment, busy, ports), new_errors={"Ethernet1/3": 12.0, "Ethernet1/4": 2.0}
    )
    assert found["cpu"] == "CPU use is 97.5%, at or above the limit of 90%."
    assert "memory" not in found
    assert set(k for k in found if k.startswith("errors:")) == {"errors:Ethernet1/3"}


def test_a_port_is_a_problem_once_it_goes_down_from_up() -> None:
    rules = AlertRules(port_down="all")
    down = _reading(up=(), describe={"Ethernet1/3": "esx-01"})
    # Just after NXray started nothing is known about before: not a problem.
    assert _find(rules, down) == {}
    found = _find(rules, down, was_up={"Ethernet1/3"})
    assert found == {"down:Ethernet1/3": "Ethernet1/3 (esx-01) went down: Link not connected."}
    # Still down after a restart, when it was already open: still a problem.
    assert "down:Ethernet1/3" in _find(rules, down, open_keys={"down:Ethernet1/3"})
    # Back up: not a problem any more.
    assert _find(rules, _reading(), open_keys={"down:Ethernet1/3"}) == {}


def test_only_described_or_labelled_ports_are_watched_when_asked() -> None:
    rules = AlertRules(port_down="described")
    down = _reading(up=(), describe={"Ethernet1/3": "esx-01"})
    was_up = {"Ethernet1/3", "Ethernet1/4"}
    assert set(_find(rules, down, was_up=was_up)) == {"down:Ethernet1/3"}
    labelled = _find(rules, down, was_up=was_up, labels={"Ethernet1/4": "nas"})
    assert set(labelled) == {"down:Ethernet1/3", "down:Ethernet1/4"}


def test_a_port_turned_off_is_not_a_problem() -> None:
    interfaces = load_fixture("show_interface")
    for row in interfaces["TABLE_interface"]["ROW_interface"]:
        if row["interface"] == "Ethernet1/3":
            row.update({"state": "down", "admin_state": "down"})
    environment, resources, _ = _reading()
    ports = parse_ports(interfaces, {}, {})
    assert (
        _find(AlertRules(port_down="all"), (environment, resources, ports), was_up={"Ethernet1/3"})
        == {}
    )


# ---- keeping them open ----


def test_a_problem_is_sent_once_and_again_when_resolved(settings: Settings) -> None:
    with _db(settings) as conn:
        first = alerts.update_open(conn, 100.0, {"fan:Fan2": "Fan Fan2 reports Failure."})
        assert [(e.kind, e.key) for e in first] == [("problem", "fan:Fan2")]
        assert alerts.update_open(conn, 160.0, {"fan:Fan2": "different words"}) == []
        assert alerts.list_open(conn)[0].message == "Fan Fan2 reports Failure."
        done = alerts.update_open(conn, 400.0, {})
        assert [(e.kind, e.since) for e in done] == [("resolved", 100.0)]
        assert alerts.list_open(conn) == []


def test_the_monitor_waits_for_two_failures_and_keeps_other_problems(settings: Settings) -> None:
    monitor = AlertMonitor()
    with _db(settings) as conn:
        alerts.update_open(conn, 1.0, {"fan:Fan2": "Fan Fan2 reports Failure."})
        assert monitor.failed(conn, 60.0, "timed out") == []
        events = monitor.failed(conn, 120.0, "timed out")
        assert [(e.kind, e.message) for e in events] == [
            ("problem", "NXray cannot read the switch: timed out")
        ]
        assert {p.key for p in alerts.list_open(conn)} == {"fan:Fan2", "unreachable"}
        # Reachable again, and the fan is fine now: both resolve.
        back = monitor.checked(conn, 180.0, _reading(), {}, {})
        assert sorted(e.key for e in back) == ["fan:Fan2", "unreachable"]
        assert {e.kind for e in back} == {"resolved"}


def test_cpu_must_stay_over_its_limit_for_three_checks(settings: Settings) -> None:
    monitor = AlertMonitor()
    environment, resources, ports = _reading()
    busy = (environment, replace(resources, cpu_used_percent=99.0), ports)
    with _db(settings) as conn:
        alerts.save_rules(conn, AlertRules(cpu_percent=90))
        assert monitor.checked(conn, 1.0, busy, {}, {}) == []
        assert monitor.checked(conn, 2.0, busy, {}, {}) == []
        assert [e.key for e in monitor.checked(conn, 3.0, busy, {}, {})] == ["cpu"]
        assert monitor.checked(conn, 4.0, busy, {}, {}) == []


def test_a_restart_does_not_send_an_open_problem_again(settings: Settings) -> None:
    environment, resources, ports = _reading()
    broken = (replace(environment, fans=[Fan("Fan2", "m", "", "Failure")]), resources, ports)
    with _db(settings) as conn:
        assert len(AlertMonitor().checked(conn, 1.0, broken, {}, {})) == 1
        assert AlertMonitor().checked(conn, 2.0, broken, {}, {}) == []


def test_turning_a_check_off_drops_its_problems_quietly(settings: Settings) -> None:
    with _db(settings) as conn:
        alerts.update_open(conn, 1.0, {"fan:Fan2": "x", "power:1": "y", "down:Ethernet1/3": "z"})
        alerts.save_rules(conn, AlertRules(fans=False, port_down="off"))
        assert [p.key for p in alerts.list_open(conn)] == ["power:1"]


# ---- the form values ----


def test_parse_rules_reads_boxes_and_blank_numbers() -> None:
    rules = alerts.parse_rules({"fans": "yes", "cpu_percent": "85", "port_down": "described"})
    assert rules == AlertRules(
        unreachable=False,
        temperature=False,
        fans=True,
        power=False,
        cpu_percent=85,
        port_down="described",
    )
    with pytest.raises(AlertSettingsError):
        alerts.parse_rules({"cpu_percent": "150"})
    with pytest.raises(AlertSettingsError):
        alerts.parse_rules({"port_down": "some"})


def _email(**changes: object):
    values = {
        "host": "smtp.example.com",
        "port": "587",
        "security": "starttls",
        "username": "nxray",
        "password": "pw",
        "keep_password": False,
        "sender": "nxray@example.com",
        "recipients": "noc@example.com; ops@example.com",
    }
    values.update(changes)
    return alerts.validate_email(**values)  # type: ignore[arg-type]


def test_validate_email_checks_every_field() -> None:
    email = _email()
    assert email.recipients == ("noc@example.com", "ops@example.com")
    assert email.has_password
    for bad in (
        {"host": "smtp example"},
        {"port": "70000"},
        {"security": "tls13"},
        {"sender": "nxray@example.com\r\nBcc: x@evil.example"},
        {"recipients": ""},
        {"recipients": "not-an-address"},
        {"security": "none"},  # a password over plain text
        {"username": ""},  # a password without a username
    ):
        with pytest.raises(AlertSettingsError):
            _email(**bad)
    assert not _email(security="none", username="", password="").has_password
    assert _email(host="[2001:db8::25]").host == "2001:db8::25"


def test_validate_webhook_and_the_url_shown() -> None:
    assert alerts.validate_webhook(" NOC ", HOOK_URL, "slack", "")[0] == "NOC"
    for bad in (
        ("", HOOK_URL, "json", ""),
        ("x", "ftp://example.com/x", "json", ""),
        ("x", "https:///nohost", "json", ""),
        ("x", "https://example.com/a b", "json", ""),
        ("x", HOOK_URL, "teams", ""),
        ("x", HOOK_URL, "slack", "secret"),  # only JSON is signed
    ):
        with pytest.raises(AlertSettingsError):
            alerts.validate_webhook(*bad)
    assert alerts.shown_url(HOOK_URL) == "https://hooks.example.com/…"
    assert alerts.shown_url("http://[2001:db8::1]:8080") == "http://[2001:db8::1]:8080"


# ---- what is sent ----


def test_compose_names_the_switch_and_each_event() -> None:
    events = [
        AlertEvent("problem", "Fan Fan2 reports Failure.", "fan:Fan2"),
        AlertEvent("resolved", "CPU use is 95%.", "cpu", since=0.0),
    ]
    subject, text = alerts.compose(events, "leaf1 (192.0.2.10)", 7500.0)
    assert subject == "[NXray] leaf1 (192.0.2.10): 1 problem, 1 resolved"
    assert "Problem: Fan Fan2 reports Failure." in text
    assert "Resolved after 2 hours 5 minutes: CPU use is 95%." in text
    single, _ = alerts.compose(events[:1], "", 0.0)
    assert single == "[NXray] Problem: Fan Fan2 reports Failure."
    assert alerts.duration_words(86400 + 3 * 3600) == "1 day 3 hours"


def test_webhook_formats() -> None:
    events = [AlertEvent("problem", "Fan Fan2 reports Failure.", "fan:Fan2")]
    own = alerts.webhook_payload("json", events, "leaf1", 0.0)
    assert own["source"] == "nxray" and own["events"][0]["key"] == "fan:Fan2"
    assert "Fan Fan2" in alerts.webhook_payload("slack", events, "leaf1", 0.0)["text"]
    assert "Fan Fan2" in alerts.webhook_payload("discord", events, "leaf1", 0.0)["content"]


def _store_email(settings: Settings, conn, **changes: object) -> None:
    alerts.save_email(
        conn, _email(**changes), str(changes.get("password", "pw")), settings.secret_key
    )


def test_deliver_sends_e_mail_and_signed_webhooks(settings: Settings, smtp) -> None:
    receiver = Receiver()
    events = [AlertEvent("problem", "Fan Fan2 reports Failure.", "fan:Fan2")]
    with _db(settings) as conn:
        _store_email(settings, conn)
        alerts.add_webhook(conn, "ops", HOOK_URL, "json", "s3cret", settings.secret_key)
        outcome = alerts.deliver(
            conn, settings.secret_key, events, "leaf1", 0.0, receiver.transport()
        )
    assert outcome == "e-mail sent to noc@example.com, ops@example.com; webhook ops sent"
    assert smtp.calls == ["connect smtp.example.com:587", "starttls", "login nxray pw"]
    assert smtp.sent[0][0] == "[NXray] leaf1: Problem: Fan Fan2 reports Failure."
    request = receiver.requests[0]
    assert str(request.url) == HOOK_URL
    expected = hmac.new(b"s3cret", request.content, hashlib.sha256).hexdigest()
    assert request.headers["X-NXray-Signature"] == f"sha256={expected}"


def test_failures_are_reported_without_the_webhook_url(settings: Settings, smtp) -> None:
    smtp.fail = smtplib.SMTPRecipientsRefused({"noc@example.com": (550, b"no")})
    events = [AlertEvent("test", "hello")]

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot connect to {request.url}")

    with _db(settings) as conn:
        _store_email(settings, conn)
        alerts.add_webhook(conn, "ops", HOOK_URL, "slack", "", settings.secret_key)
        outcome = alerts.deliver(
            conn, settings.secret_key, events, "", 0.0, httpx.MockTransport(refuse)
        )
        status = alerts.deliver(
            conn, settings.secret_key, events, "", 0.0, Receiver(404).transport()
        )
    assert outcome.startswith("e-mail failed: ")
    assert "webhook ops failed: cannot connect to https://hooks.example.com/…" in outcome
    assert "secret-token" not in outcome
    assert "webhook ops failed: it answered HTTP 404" in status


def test_nothing_set_up_is_said(settings: Settings) -> None:
    with _db(settings) as conn:
        outcome = alerts.deliver(conn, settings.secret_key, [AlertEvent("test", "x")], "", 0.0)
    assert outcome == "Not sent: no e-mail or webhook is set up."


def test_a_stored_secret_that_cannot_be_read_says_so(settings: Settings, smtp) -> None:
    with _db(settings) as conn:
        _store_email(settings, conn)
        alerts.add_webhook(conn, "ops", HOOK_URL, "json", "", settings.secret_key)
        outcome = alerts.deliver(conn, "another-key", [AlertEvent("test", "x")], "", 0.0)
    assert "e-mail not sent: the stored password cannot be read" in outcome
    assert "webhook ops not sent: its URL cannot be read" in outcome


def test_secrets_are_stored_encrypted(settings: Settings) -> None:
    with _db(settings) as conn:
        _store_email(settings, conn, password="hunter2-mail")
        alerts.add_webhook(conn, "ops", HOOK_URL, "json", "sign-me", settings.secret_key)
        dump = "\n".join(conn.iterdump())
    assert "hunter2-mail" not in dump
    assert "secret-token" not in dump
    assert "sign-me" not in dump


# ---- against the pretend switch, through history ----


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
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


def test_a_failed_fan_is_sent_from_a_history_sample(settings: Settings, switch: FakeSwitch) -> None:
    receiver = Receiver()
    with open_db(settings.db_path) as conn:
        alerts.add_webhook(conn, "ops", HOOK_URL, "json", "", settings.secret_key)
    broken = copy.deepcopy(load_fixture("show_environment"))
    broken["fandetails"]["TABLE_faninfo"]["ROW_faninfo"][0]["fanstatus"] = "Failure"
    switch.bodies["show environment"] = broken
    sampler = history.Sampler(
        settings, switch.transport, receiver.transport, background_alerts=False
    )
    assert sampler.sample_once() is None
    assert sampler.sample_once() is None  # still broken: not sent again
    assert len(receiver.requests) == 1
    body = receiver.bodies()[0]
    assert body["switch"].endswith("(192.0.2.10)")
    assert body["events"][0]["key"] == "fan:Fan1(sys_fan1)"
    del switch.bodies["show environment"]
    sampler.sample_once()
    assert receiver.bodies()[1]["events"][0]["kind"] == "resolved"
    with open_db(settings.db_path) as conn:
        sent = alerts.list_sent(conn)
    assert [a.kind for a in sent] == ["resolved", "problem"]
    assert sent[0].delivery == "webhook ops sent"


def test_an_unreachable_switch_is_sent_after_two_tries(
    settings: Settings, switch: FakeSwitch
) -> None:
    receiver = Receiver()
    with open_db(settings.db_path) as conn:
        alerts.add_webhook(conn, "ops", HOOK_URL, "slack", "", settings.secret_key)

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    sampler = history.Sampler(
        settings, lambda: httpx.MockTransport(refuse), receiver.transport, background_alerts=False
    )
    assert sampler.sample_once()
    assert receiver.requests == []
    assert sampler.sample_once()
    assert "cannot read the switch" in receiver.bodies()[0]["text"]


def test_forgetting_the_switch_forgets_its_problems(
    settings: Settings, switch: FakeSwitch, logged_in: TestClient
) -> None:
    with open_db(settings.db_path) as conn:
        alerts.update_open(conn, 1.0, {"fan:Fan2": "x"})
    logged_in.post("/switch/forget", data={"csrf": _csrf(logged_in, "/switch")})
    with open_db(settings.db_path) as conn:
        assert alerts.list_open(conn) == []


# ---- the page ----


def test_the_page_is_for_admins_only(logged_in: TestClient, settings: Settings) -> None:
    with open_db(settings.db_path) as conn:
        create_user(conn, "olive", "operator-password-1", "operator-password-1", "operator")
    assert logged_in.get("/alerts").status_code == 200
    logged_in.post("/logout")
    logged_in.post("/login", data={"username": "olive", "password": "operator-password-1"})
    assert logged_in.get("/alerts").status_code == 403
    assert logged_in.post("/alerts/rules", data={"csrf": "x"}).status_code == 403
    assert "/alerts" not in logged_in.get("/").text


def test_forms_need_the_csrf_token(logged_in: TestClient) -> None:
    for path in ("/alerts/rules", "/alerts/email", "/alerts/webhook/add", "/alerts/email/test"):
        assert logged_in.post(path, data={"csrf": "wrong"}).status_code == 403, path


def test_the_rules_are_saved_and_recorded(logged_in: TestClient, settings: Settings) -> None:
    response = logged_in.post(
        "/alerts/rules",
        data={
            "csrf": _csrf(logged_in),
            "unreachable": "yes",
            "cpu_percent": "90",
            "port_down": "all",
        },
    )
    assert response.status_code == 200
    assert "Saved." in response.text
    with open_db(settings.db_path) as conn:
        rules = alerts.load_rules(conn)
        what = conn.execute("SELECT what FROM activity").fetchone()["what"]
    assert rules == AlertRules(
        unreachable=True,
        temperature=False,
        fans=False,
        power=False,
        cpu_percent=90,
        port_down="all",
    )
    assert what == "Set what is alerted on: switch unreachable, CPU at 90%, ports down (every port)"
    bad = logged_in.post("/alerts/rules", data={"csrf": _csrf(logged_in), "cpu_percent": "x"})
    assert bad.status_code == 400


def test_e_mail_settings_keep_the_password_and_never_show_it(
    logged_in: TestClient, settings: Settings, smtp
) -> None:
    form = {
        "host": "smtp.example.com",
        "port": "465",
        "security": "ssl",
        "smtp_username": "nxray",
        "smtp_password": "hunter2-mail",
        "sender": "nxray@example.com",
        "recipients": "noc@example.com",
    }
    saved = logged_in.post("/alerts/email", data={"csrf": _csrf(logged_in), **form})
    assert saved.status_code == 200
    assert "hunter2-mail" not in saved.text
    # Saved again with the password left empty: the stored one stays.
    logged_in.post("/alerts/email", data={"csrf": _csrf(logged_in), **form, "smtp_password": ""})
    test = logged_in.post("/alerts/email/test", data={"csrf": _csrf(logged_in)})
    assert "Test: e-mail sent to noc@example.com." in _text(test.text)
    assert smtp.calls == ["connect smtp.example.com:465 ssl", "login nxray hunter2-mail"]
    with open_db(settings.db_path) as conn:
        whats = [r["what"] for r in conn.execute("SELECT what FROM activity")]
        assert alerts.list_sent(conn)[0].kind == "test"
    assert all("hunter2" not in what for what in whats)
    removed = logged_in.post("/alerts/email/delete", data={"csrf": _csrf(logged_in)})
    assert "no more e-mail alerts" in removed.text
    with open_db(settings.db_path) as conn:
        assert not alerts.load_email(conn).configured


def test_a_bad_e_mail_setting_is_refused(logged_in: TestClient) -> None:
    response = logged_in.post(
        "/alerts/email",
        data={
            "csrf": _csrf(logged_in),
            "host": "smtp.example.com",
            "port": "25",
            "security": "none",
            "smtp_username": "nxray",
            "smtp_password": "pw",
            "sender": "nxray@example.com",
            "recipients": "noc@example.com",
        },
    )
    assert response.status_code == 400
    assert "only over an encrypted connection" in response.text


def test_webhooks_are_added_tested_and_deleted(logged_in: TestClient, settings: Settings) -> None:
    receiver = Receiver()
    logged_in.app.state.alert_transport = receiver.transport()  # type: ignore[attr-defined]
    added = logged_in.post(
        "/alerts/webhook/add",
        data={"csrf": _csrf(logged_in), "name": "ops", "url": HOOK_URL, "format": "discord"},
    )
    assert added.status_code == 200
    page = logged_in.get("/alerts").text
    assert "https://hooks.example.com/…" in page
    assert "secret-token" not in page
    with open_db(settings.db_path) as conn:
        hook = alerts.list_webhooks(conn)[0]
        assert "secret-token" not in conn.execute("SELECT what FROM activity").fetchone()["what"]
    tested = logged_in.post(
        "/alerts/webhook/test", data={"csrf": _csrf(logged_in), "id": str(hook.id)}
    )
    assert "Test: webhook ops sent." in _text(tested.text)
    assert "test alert" in receiver.bodies()[0]["content"]
    gone = logged_in.post(
        "/alerts/webhook/delete", data={"csrf": _csrf(logged_in), "id": str(hook.id)}
    )
    assert "Webhook ops deleted." in gone.text
    missing = logged_in.post(
        "/alerts/webhook/test", data={"csrf": _csrf(logged_in), "id": str(hook.id)}
    )
    assert missing.status_code == 404


def test_changes_are_sent_when_asked(logged_in: TestClient, settings: Settings) -> None:
    receiver = Receiver()
    logged_in.app.state.alert_transport = receiver.transport()  # type: ignore[attr-defined]
    logged_in.app.state.alerts_background = False  # type: ignore[attr-defined]
    logged_in.post(
        "/alerts/webhook/add",
        data={"csrf": _csrf(logged_in), "name": "ops", "url": HOOK_URL, "format": "json"},
    )
    assert receiver.requests == []  # changes are off by default
    logged_in.post("/alerts/rules", data={"csrf": _csrf(logged_in), "changes": "yes"})
    events = receiver.bodies()[0]["events"]
    assert events[0]["kind"] == "change"
    assert events[0]["message"] == "admin on the Alerts page: Set what is alerted on: changes"


def test_the_page_lists_open_problems_and_warns_when_history_is_off(
    logged_in: TestClient, settings: Settings
) -> None:
    with open_db(settings.db_path) as conn:
        alerts.update_open(conn, 1.0, {"fan:Fan2": "Fan Fan2 reports Failure."})
    page = _text(logged_in.get("/alerts").text)
    assert "Fan Fan2 reports Failure." in page
    assert "History is off" in page  # the test settings turn history off
