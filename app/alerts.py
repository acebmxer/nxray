"""Alerts: telling someone by e-mail or webhook when the switch needs attention.

What is watched is checked each time history samples the switch
(``app/history.py``), from the same three read-only commands, so alerts cost
the switch nothing more. With history off (``NXRAY_HISTORY_INTERVAL=0``) the
switch is not read on its own and no problem is noticed; change alerts still
go out.

A problem has a key ("fan:Fan2", "down:Ethernet1/5") and is kept open in the
``alert_open`` table until it goes away, so each one is sent once when it
starts and once when it is resolved, also across a restart of NXray. Every
alert sent, with how its delivery went, is kept in ``alert_log`` for
``KEEP_DAYS``.

The e-mail settings and the webhooks live in the database, set on the Alerts
page by an admin. The SMTP password, each webhook's URL (Slack and Discord
URLs are themselves the secret) and its signing secret are stored encrypted
(``app/crypto.py``) and never shown again.

Delivery happens on a thread of its own, so a slow mail server never holds up
history or a page.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import re
import smtplib
import sqlite3
import ssl
import threading
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, fields, replace
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from urllib.parse import urlsplit

import httpx

from app import __version__
from app.config import Settings
from app.crypto import DecryptionError, decrypt, encrypt
from app.db import open_db
from app.ports import Port
from app.switch import Environment, Resources

log = logging.getLogger("nxray.alerts")

KEEP_DAYS = 90
# How many sent alerts the Alerts page lists.
LOG_LIMIT = 100
MAX_WEBHOOKS = 10
MAX_RECIPIENTS = 10
SEND_TIMEOUT = 15
# Failed reads in a row before "cannot reach the switch" is sent: one timeout
# is not worth waking anyone for.
UNREACHABLE_AFTER = 2
# Samples in a row CPU or memory must be at or above the limit before it is
# sent, so a short spike is not.
SUSTAINED = 3
MESSAGE_MAX = 1000

SECURITY_CHOICES = {
    "starttls": "STARTTLS (usually port 587)",
    "ssl": "SSL/TLS from the start (usually port 465)",
    "none": "None (a relay on a trusted network, usually port 25)",
}
FORMATS = {
    "json": "JSON (NXray's own, any receiver)",
    "slack": "Slack",
    "discord": "Discord",
}
PORT_WATCH = {
    "off": "Off",
    "described": "Ports with a description or a label",
    "all": "Every port",
}

PROBLEM = "problem"
RESOLVED = "resolved"
CHANGE = "change"
TEST = "test"
KIND_WORDS = {PROBLEM: "Problem", RESOLVED: "Resolved", CHANGE: "Change", TEST: "Test"}

UNREACHABLE_KEY = "unreachable"

_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_ADDRESS = re.compile(
    r"^[A-Za-z0-9.!#$%&*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"
)
_PRINTABLE = re.compile(r"^[^\x00-\x1f\x7f]*$")


class AlertSettingsError(ValueError):
    """A value typed on the Alerts page that cannot be used; the message says why."""


@dataclass(frozen=True)
class AlertRules:
    """What NXray alerts on. A number of 0 means that check is off."""

    unreachable: bool = True
    temperature: bool = True
    fans: bool = True
    power: bool = True
    cpu_percent: int = 0
    memory_percent: int = 0
    port_down: str = "off"
    port_errors: int = 0
    changes: bool = False


@dataclass(frozen=True)
class EmailSettings:
    """Where e-mail alerts go, without the password (only whether there is one)."""

    host: str = ""
    port: int = 587
    security: str = "starttls"
    username: str = ""
    has_password: bool = False
    sender: str = ""
    recipients: tuple[str, ...] = ()

    @property
    def configured(self) -> bool:
        return bool(self.host and self.sender and self.recipients)


@dataclass(frozen=True)
class Webhook:
    """A webhook as the page shows it: the URL cut to its scheme and host."""

    id: int
    name: str
    shown: str
    format: str
    signed: bool


@dataclass(frozen=True)
class OpenProblem:
    key: str
    since: float
    message: str


@dataclass(frozen=True)
class AlertEvent:
    """One line of an alert: a problem started or was resolved, a change, a test."""

    kind: str
    message: str
    key: str = ""
    # For a resolved problem, when it started.
    since: float | None = None


@dataclass(frozen=True)
class SentAlert:
    """One line of the alert log."""

    id: int
    at: float
    kind: str
    message: str
    delivery: str


# ---- the rules and destinations, stored ----

_RULE_COLUMNS = {
    "unreachable": "rule_unreachable",
    "temperature": "rule_temperature",
    "fans": "rule_fans",
    "power": "rule_power",
    "cpu_percent": "cpu_percent",
    "memory_percent": "memory_percent",
    "port_down": "port_down",
    "port_errors": "port_errors",
    "changes": "rule_changes",
}


def _row(conn: sqlite3.Connection) -> sqlite3.Row:
    conn.execute("INSERT OR IGNORE INTO alert_settings (id) VALUES (1)")
    conn.commit()
    return conn.execute("SELECT * FROM alert_settings WHERE id = 1").fetchone()


def load_rules(conn: sqlite3.Connection) -> AlertRules:
    """What NXray alerts on, the defaults until an admin changes them."""
    row = _row(conn)
    defaults = AlertRules()
    values: dict[str, object] = {}
    for item in fields(AlertRules):
        value = row[_RULE_COLUMNS[item.name]]
        values[item.name] = bool(value) if isinstance(getattr(defaults, item.name), bool) else value
    rules = AlertRules(**values)  # type: ignore[arg-type]
    return rules if rules.port_down in PORT_WATCH else replace(rules, port_down="off")


def _rule_for(key: str) -> str:
    """The rule a problem key belongs to."""
    prefix = key.split(":", 1)[0]
    return {
        UNREACHABLE_KEY: "unreachable",
        "temperature": "temperature",
        "fan": "fans",
        "power": "power",
        "cpu": "cpu_percent",
        "memory": "memory_percent",
        "down": "port_down",
        "errors": "port_errors",
    }.get(prefix, "")


def save_rules(conn: sqlite3.Connection, rules: AlertRules) -> None:
    """Store the rules. Open problems of a check turned off are dropped without a
    "resolved" alert, which would claim something got better."""
    before = load_rules(conn)
    columns = ", ".join(f"{column} = ?" for column in _RULE_COLUMNS.values())
    values = [getattr(rules, name) for name in _RULE_COLUMNS]
    conn.execute(f"UPDATE alert_settings SET {columns} WHERE id = 1", values)
    for problem in list_open(conn):
        rule = _rule_for(problem.key)
        if not rule:
            continue
        now_on = getattr(rules, rule)
        if not now_on or now_on == "off" or (rule == "port_down" and now_on != before.port_down):
            conn.execute("DELETE FROM alert_open WHERE key = ?", (problem.key,))
    conn.commit()


def _number(value: str, name: str, low: int, high: int) -> int:
    text = value.strip()
    if not text or text == "0":
        return 0
    if not text.isdigit() or not low <= int(text) <= high:
        raise AlertSettingsError(
            f"{name} must be blank (off) or a whole number from {low} to {high}."
        )
    return int(text)


def parse_rules(form: Mapping[str, str]) -> AlertRules:
    """The rules from the Alerts page's form: a ticked box is "yes", a number
    left blank turns that check off."""
    port_down = form.get("port_down", "off")
    if port_down not in PORT_WATCH:
        raise AlertSettingsError("Choose which ports to watch from the list.")
    return AlertRules(
        unreachable=form.get("unreachable") == "yes",
        temperature=form.get("temperature") == "yes",
        fans=form.get("fans") == "yes",
        power=form.get("power") == "yes",
        cpu_percent=_number(form.get("cpu_percent", ""), "The CPU limit", 10, 100),
        memory_percent=_number(form.get("memory_percent", ""), "The memory limit", 10, 100),
        port_down=port_down,
        port_errors=_number(form.get("port_errors", ""), "The number of errors", 1, 1_000_000),
        changes=form.get("changes") == "yes",
    )


def load_email(conn: sqlite3.Connection) -> EmailSettings:
    """The e-mail settings, without the password."""
    row = _row(conn)
    return EmailSettings(
        host=row["smtp_host"],
        port=row["smtp_port"],
        security=row["smtp_security"],
        username=row["smtp_username"],
        has_password=bool(row["smtp_password_encrypted"]),
        sender=row["mail_from"],
        recipients=tuple(split_addresses(row["mail_to"])),
    )


def split_addresses(text: str) -> list[str]:
    """Addresses typed with commas, semicolons, spaces or new lines between them."""
    return [part for part in re.split(r"[\s,;]+", text) if part]


def _check_host(host: str) -> str:
    host = host.strip().strip("[]")
    if not host:
        raise AlertSettingsError("Type the mail server's name or address.")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not _HOST.match(host) or ".." in host:
        raise AlertSettingsError(f"{host!r} is not a server name or address.")
    return host.lower()


def _check_address(address: str, what: str) -> str:
    if len(address) > 254 or not _ADDRESS.match(address) or ".." in address.split("@")[1]:
        raise AlertSettingsError(f"{what} {address!r} is not an e-mail address.")
    return address


def validate_email(
    *,
    host: str,
    port: str,
    security: str,
    username: str,
    password: str,
    keep_password: bool,
    sender: str,
    recipients: str,
) -> EmailSettings:
    """The e-mail settings from the form, checked; raises AlertSettingsError.

    A password is only ever sent over an encrypted connection, so one with
    security "none" is refused.
    """
    host = _check_host(host)
    if not port.strip().isdigit() or not 1 <= int(port) <= 65535:
        raise AlertSettingsError("The port must be a number from 1 to 65535.")
    if security not in SECURITY_CHOICES:
        raise AlertSettingsError("Choose the connection's security from the list.")
    username = username.strip()
    if len(username) > 254 or not _PRINTABLE.match(username):
        raise AlertSettingsError("The username is too long or holds characters it cannot.")
    if len(password) > 256 or not _PRINTABLE.match(password):
        raise AlertSettingsError("The password is too long or holds characters it cannot.")
    has_password = bool(password) or keep_password
    if has_password and not username:
        raise AlertSettingsError("A password needs a username.")
    if has_password and security == "none":
        raise AlertSettingsError(
            "NXray sends a password only over an encrypted connection: choose STARTTLS or SSL/TLS."
        )
    sender = _check_address(sender.strip(), "The sender")
    addresses = split_addresses(recipients)
    if not addresses:
        raise AlertSettingsError("Type at least one address to send alerts to.")
    if len(addresses) > MAX_RECIPIENTS:
        raise AlertSettingsError(f"Alerts go to at most {MAX_RECIPIENTS} addresses.")
    checked = tuple(dict.fromkeys(_check_address(a, "The address") for a in addresses))
    return EmailSettings(
        host=host,
        port=int(port),
        security=security,
        username=username,
        has_password=has_password,
        sender=sender,
        recipients=checked,
    )


def save_email(
    conn: sqlite3.Connection, email: EmailSettings, password: str, secret_key: str
) -> None:
    """Store checked e-mail settings. An empty ``password`` keeps the stored one
    when ``email.has_password``, and removes it otherwise."""
    row = _row(conn)
    if password:
        stored = encrypt(password, secret_key)
    elif email.has_password:
        stored = row["smtp_password_encrypted"]
    else:
        stored = ""
    conn.execute(
        "UPDATE alert_settings SET smtp_host = ?, smtp_port = ?, smtp_security = ?, "
        "smtp_username = ?, smtp_password_encrypted = ?, mail_from = ?, mail_to = ? WHERE id = 1",
        (
            email.host,
            email.port,
            email.security,
            email.username,
            stored,
            email.sender,
            ", ".join(email.recipients),
        ),
    )
    conn.commit()


def delete_email(conn: sqlite3.Connection) -> None:
    """Forget the e-mail settings and the password; no more e-mail alerts."""
    _row(conn)
    conn.execute(
        "UPDATE alert_settings SET smtp_host = '', smtp_port = 587, smtp_security = 'starttls', "
        "smtp_username = '', smtp_password_encrypted = '', mail_from = '', mail_to = '' "
        "WHERE id = 1"
    )
    conn.commit()


def shown_url(url: str) -> str:
    """A webhook URL as the page shows it: scheme and host, never the path or
    query, which hold the secret in Slack and Discord URLs."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = f":{parts.port}" if parts.port else ""
    rest = "/…" if parts.path.strip("/") or parts.query else ""
    return f"{parts.scheme}://{host}{port}{rest}"


def validate_webhook(name: str, url: str, fmt: str, secret: str) -> tuple[str, str, str, str]:
    """A webhook's name, URL, format and signing secret, checked."""
    name = " ".join(name.split())
    if not name or len(name) > 64:
        raise AlertSettingsError("Give the webhook a name of 1 to 64 characters.")
    url = url.strip()
    if len(url) > 2000 or not url or any(c.isspace() or ord(c) < 32 for c in url):
        raise AlertSettingsError("Paste the webhook's whole URL, without spaces.")
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - raises for a port that is not a number
    except ValueError as exc:
        raise AlertSettingsError("That URL cannot be read.") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise AlertSettingsError("The URL must start with https:// (or http://) and name a host.")
    if fmt not in FORMATS:
        raise AlertSettingsError("Choose the webhook's format from the list.")
    if len(secret) > 256 or not _PRINTABLE.match(secret):
        raise AlertSettingsError("The signing secret is too long or holds characters it cannot.")
    if secret and fmt != "json":
        raise AlertSettingsError("Only NXray's own JSON format is signed; leave the secret empty.")
    return name, url, fmt, secret


def add_webhook(
    conn: sqlite3.Connection, name: str, url: str, fmt: str, secret: str, secret_key: str
) -> int:
    """Store a checked webhook, its URL and secret encrypted. Returns its id."""
    count = conn.execute("SELECT COUNT(*) FROM alert_webhooks").fetchone()[0]
    if count >= MAX_WEBHOOKS:
        raise AlertSettingsError(f"NXray keeps at most {MAX_WEBHOOKS} webhooks.")
    cursor = conn.execute(
        "INSERT INTO alert_webhooks (name, url_encrypted, url_shown, format, secret_encrypted, "
        "created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            name,
            encrypt(url, secret_key),
            shown_url(url),
            fmt,
            encrypt(secret, secret_key) if secret else "",
            time.time(),
        ),
    )
    conn.commit()
    return int(cursor.lastrowid or 0)


def list_webhooks(conn: sqlite3.Connection) -> list[Webhook]:
    """The webhooks, oldest first, without their URLs and secrets."""
    return [
        Webhook(r["id"], r["name"], r["url_shown"], r["format"], bool(r["secret_encrypted"]))
        for r in conn.execute(
            "SELECT id, name, url_shown, format, secret_encrypted FROM alert_webhooks ORDER BY id"
        )
    ]


def delete_webhook(conn: sqlite3.Connection, webhook_id: int) -> Webhook | None:
    """Delete one webhook; the one deleted, or None when there was none."""
    found = next((hook for hook in list_webhooks(conn) if hook.id == webhook_id), None)
    if found is not None:
        conn.execute("DELETE FROM alert_webhooks WHERE id = ?", (webhook_id,))
        conn.commit()
    return found


# ---- open problems and the log ----


def list_open(conn: sqlite3.Connection) -> list[OpenProblem]:
    """The problems open now, oldest first."""
    return [
        OpenProblem(r["key"], r["since"], r["message"])
        for r in conn.execute("SELECT key, since, message FROM alert_open ORDER BY since, key")
    ]


def clear_open(conn: sqlite3.Connection) -> None:
    """Forget every open problem, without alerts; for when the switch is forgotten."""
    conn.execute("DELETE FROM alert_open")
    conn.commit()


def update_open(conn: sqlite3.Connection, now: float, found: Mapping[str, str]) -> list[AlertEvent]:
    """Store the problems found now. A problem not open before is a new alert;
    an open one not found any more is resolved. One already open stays as it
    was first sent."""
    before = {problem.key: problem for problem in list_open(conn)}
    events: list[AlertEvent] = []
    for key, message in found.items():
        if key not in before:
            message = message[:MESSAGE_MAX]
            conn.execute(
                "INSERT INTO alert_open (key, since, message) VALUES (?, ?, ?)",
                (key, now, message),
            )
            events.append(AlertEvent(PROBLEM, message, key))
    for key, problem in before.items():
        if key not in found:
            conn.execute("DELETE FROM alert_open WHERE key = ?", (key,))
            events.append(AlertEvent(RESOLVED, problem.message, key, problem.since))
    conn.commit()
    return events


def log_alerts(
    conn: sqlite3.Connection, now: float, events: Sequence[AlertEvent], delivery: str
) -> list[int]:
    """Keep the events in the alert log, and delete lines older than ``KEEP_DAYS``."""
    ids = []
    for event in events:
        cursor = conn.execute(
            "INSERT INTO alert_log (at, kind, message, delivery) VALUES (?, ?, ?, ?)",
            (now, event.kind, event.message[:MESSAGE_MAX], delivery),
        )
        ids.append(int(cursor.lastrowid or 0))
    conn.execute("DELETE FROM alert_log WHERE at < ?", (now - KEEP_DAYS * 86400,))
    conn.commit()
    return ids


def set_delivery(conn: sqlite3.Connection, ids: Iterable[int], delivery: str) -> None:
    """Note how the alerts in ``ids`` were delivered."""
    conn.executemany("UPDATE alert_log SET delivery = ? WHERE id = ?", [(delivery, i) for i in ids])
    conn.commit()


def list_sent(conn: sqlite3.Connection, limit: int = LOG_LIMIT) -> list[SentAlert]:
    """The newest alerts, newest first, with how each was delivered."""
    return [
        SentAlert(r["id"], r["at"], r["kind"], r["message"], r["delivery"])
        for r in conn.execute(
            "SELECT id, at, kind, message, delivery FROM alert_log ORDER BY id DESC LIMIT ?",
            (limit,),
        )
    ]


# ---- noticing problems ----


def _watched(port: Port, watch: str, labels: Mapping[str, str]) -> bool:
    if watch == "all":
        return True
    if watch == "described":
        return bool(port.description.strip() or labels.get(port.name, "").strip())
    return False


def find_problems(
    rules: AlertRules,
    environment: Environment,
    resources: Resources,
    ports: Sequence[Port],
    *,
    labels: Mapping[str, str],
    new_errors: Mapping[str, float],
    was_up: set[str] | None,
    open_keys: set[str],
) -> dict[str, str]:
    """Every problem the rules ask about in one reading of the switch: {key: words}.

    Temperatures, fans and power supplies use the switch's own judgement, as
    the dashboard does. A watched port is a problem once it goes down from up
    (``was_up``, the ports up in the previous reading; None just after NXray
    started) while it is still turned on; it stays one, also across a
    restart (``open_keys``), until it is up again or turned off.
    """
    found: dict[str, str] = {}
    if rules.temperature:
        for sensor in environment.temperatures:
            if sensor.level in ("warn", "crit"):
                found[f"temperature:{sensor.name}:minor"] = (
                    f"Temperature {sensor.name} is {sensor.current_c}°C, at or above its "
                    f"minor limit of {sensor.minor_c}°C."
                )
            if sensor.level == "crit":
                found[f"temperature:{sensor.name}:major"] = (
                    f"Temperature {sensor.name} is {sensor.current_c}°C, at or above its "
                    f"major limit of {sensor.major_c}°C."
                )
    if rules.fans:
        for fan in environment.fans:
            if not fan.ok:
                found[f"fan:{fan.name}"] = f"Fan {fan.name} reports {fan.status or 'no status'}."
    if rules.power:
        for supply in environment.power_supplies:
            if not supply.ok:
                found[f"power:{supply.number}"] = (
                    f"Power supply {supply.number} reports {supply.status or 'no status'}."
                )
    cpu = resources.cpu_used_percent
    if rules.cpu_percent and cpu is not None and cpu >= rules.cpu_percent:
        found["cpu"] = f"CPU use is {cpu:g}%, at or above the limit of {rules.cpu_percent}%."
    memory = resources.memory_used_percent
    if rules.memory_percent and memory is not None and memory >= rules.memory_percent:
        found["memory"] = (
            f"Memory use is {memory:g}%, at or above the limit of {rules.memory_percent}%."
        )
    if rules.port_errors:
        for name, count in sorted(new_errors.items()):
            if count >= rules.port_errors:
                found[f"errors:{name}"] = (
                    f"{name} had {count:g} new errors and discards since the previous check "
                    f"(the limit is {rules.port_errors})."
                )
    if rules.port_down != "off":
        for port in ports:
            key = f"down:{port.name}"
            if port.up or not port.admin_up or not _watched(port, rules.port_down, labels):
                continue
            if key in open_keys or (was_up is not None and port.name in was_up):
                what = port.description.strip() or labels.get(port.name, "").strip()
                found[key] = (
                    f"{port.name}{f' ({what})' if what else ''} went down"
                    f"{f': {port.reason}' if port.reason else ''}."
                )
    return found


class AlertMonitor:
    """Turns readings of the switch into alerts. Remembers, between readings,
    which ports were up and how long a limit or a failure has lasted."""

    def __init__(self) -> None:
        self._was_up: set[str] | None = None
        self._streaks: dict[str, int] = {}
        self._failures = 0

    def _sustained(self, found: dict[str, str], open_keys: set[str]) -> dict[str, str]:
        for key in ("cpu", "memory"):
            if key in found:
                self._streaks[key] = self._streaks.get(key, 0) + 1
                if key not in open_keys and self._streaks[key] < SUSTAINED:
                    del found[key]
            else:
                self._streaks.pop(key, None)
        return found

    def checked(
        self,
        conn: sqlite3.Connection,
        now: float,
        reading: tuple[Environment, Resources, list[Port]],
        new_errors: Mapping[str, float],
        labels: Mapping[str, str],
    ) -> list[AlertEvent]:
        """The alerts one successful reading starts or resolves."""
        self._failures = 0
        rules = load_rules(conn)
        open_keys = {problem.key for problem in list_open(conn)}
        environment, resources, ports = reading
        found = find_problems(
            rules,
            environment,
            resources,
            ports,
            labels=labels,
            new_errors=new_errors,
            was_up=self._was_up,
            open_keys=open_keys,
        )
        self._was_up = {port.name for port in ports if port.up}
        return update_open(conn, now, self._sustained(found, open_keys))

    def failed(self, conn: sqlite3.Connection, now: float, reason: str) -> list[AlertEvent]:
        """The alert a failed reading may start. Every other open problem stays
        open: nothing is known about it."""
        self._failures += 1
        rules = load_rules(conn)
        found = {problem.key: problem.message for problem in list_open(conn)}
        if rules.unreachable and (self._failures >= UNREACHABLE_AFTER or UNREACHABLE_KEY in found):
            found.setdefault(UNREACHABLE_KEY, f"NXray cannot read the switch: {reason}")
        return update_open(conn, now, found)


# ---- what is sent ----


def duration_words(seconds: float) -> str:
    """``3 minutes``, ``2 hours 5 minutes``, ``1 day 3 hours``."""
    minutes = max(1, round(seconds / 60))
    days, rest = divmod(minutes, 1440)
    hours, minutes = divmod(rest, 60)

    def unit(count: int, word: str) -> str:
        return f"{count} {word}{'' if count == 1 else 's'}"

    if days:
        return unit(days, "day") + (f" {unit(hours, 'hour')}" if hours else "")
    if hours:
        return unit(hours, "hour") + (f" {unit(minutes, 'minute')}" if minutes else "")
    return unit(minutes, "minute")


def event_line(event: AlertEvent, now: float) -> str:
    """One event in words, as e-mails and webhooks show it."""
    if event.kind == RESOLVED and event.since is not None:
        return f"Resolved after {duration_words(now - event.since)}: {event.message}"
    return f"{KIND_WORDS.get(event.kind, event.kind)}: {event.message}"


def compose(events: Sequence[AlertEvent], switch: str, now: float) -> tuple[str, str]:
    """The subject and the text of one alert holding ``events``."""
    where = f" {switch}:" if switch else ""
    if len(events) == 1:
        subject = f"[NXray]{where} {event_line(events[0], now)}"
    else:
        counts = []
        for kind in (PROBLEM, RESOLVED, CHANGE, TEST):
            count = sum(1 for event in events if event.kind == kind)
            if count:
                word = {PROBLEM: "problem", RESOLVED: "resolved", CHANGE: "change", TEST: "test"}
                plural = "s" if count != 1 and kind != RESOLVED else ""
                counts.append(f"{count} {word[kind]}{plural}")
        subject = f"[NXray]{where} " + ", ".join(counts)
    if len(subject) > 200:
        subject = subject[:199] + "…"
    stamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now))
    head = f"NXray{f', switch {switch}' if switch else ''}, {stamp}"
    text = "\n".join([head, "", *(event_line(event, now) for event in events)])
    return subject, text


def _iso(moment: float | None) -> str | None:
    return None if moment is None else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(moment))


def webhook_payload(
    fmt: str, events: Sequence[AlertEvent], switch: str, now: float
) -> dict[str, object]:
    """The JSON body of a webhook in its format."""
    _, text = compose(events, switch, now)
    if fmt == "slack":
        return {"text": text}
    if fmt == "discord":
        return {"content": text if len(text) <= 2000 else text[:1999] + "…"}
    return {
        "source": "nxray",
        "version": __version__,
        "switch": switch,
        "sent_at": _iso(now),
        "text": text,
        "events": [
            {"kind": e.kind, "key": e.key, "message": e.message, "since": _iso(e.since)}
            for e in events
        ],
    }


def signature(secret: str, body: bytes) -> str:
    """The ``X-NXray-Signature`` header of a signed webhook: an HMAC-SHA256 of
    the body with the webhook's secret."""
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def send_email(
    email: EmailSettings, password: str, subject: str, text: str, now: float | None = None
) -> None:
    """Send one e-mail, checking the server's certificate. Raises on failure."""
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = email.sender
    message["To"] = ", ".join(email.recipients)
    message["Date"] = formatdate(now, usegmt=True)
    message["Message-ID"] = make_msgid(domain=email.sender.split("@")[1])
    message.set_content(text + "\n\n-- \nSent by NXray. Its Alerts page says what is sent.\n")
    context = ssl.create_default_context()
    if email.security == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(
            email.host, email.port, timeout=SEND_TIMEOUT, context=context
        )
    else:
        server = smtplib.SMTP(email.host, email.port, timeout=SEND_TIMEOUT)
    with server:
        if email.security == "starttls":
            server.starttls(context=context)
        if email.username and password:
            server.login(email.username, password)
        server.send_message(message)


def post_webhook(
    url: str,
    fmt: str,
    secret: str,
    events: Sequence[AlertEvent],
    switch: str,
    now: float,
    transport: httpx.BaseTransport | None = None,
) -> None:
    """POST one alert to a webhook. Raises on failure, with the URL kept out of
    the message."""
    body = json.dumps(webhook_payload(fmt, events, switch, now)).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": f"NXray/{__version__}"}
    if secret:
        headers["X-NXray-Signature"] = signature(secret, body)
    try:
        with httpx.Client(transport=transport, timeout=SEND_TIMEOUT) as client:
            response = client.post(url, content=body, headers=headers)
    except httpx.HTTPError as exc:
        raise RuntimeError(str(exc).replace(url, shown_url(url)) or type(exc).__name__) from None
    if not 200 <= response.status_code < 300:
        raise RuntimeError(f"it answered HTTP {response.status_code}")


def _failure(exc: BaseException) -> str:
    text = " ".join(str(exc).split()) or type(exc).__name__
    return text[:200]


def deliver(
    conn: sqlite3.Connection,
    secret_key: str,
    events: Sequence[AlertEvent],
    switch: str,
    now: float,
    transport: httpx.BaseTransport | None = None,
    *,
    webhook_id: int | None = None,
    email_only: bool = False,
) -> str:
    """Send ``events`` by e-mail and to every webhook; how it went, in words.

    ``webhook_id`` sends to that webhook only, ``email_only`` by e-mail only:
    the Alerts page's test buttons.
    """
    results: list[str] = []
    email = load_email(conn)
    if email.configured and webhook_id is None:
        subject, text = compose(events, switch, now)
        try:
            stored = _row(conn)["smtp_password_encrypted"]
            password = decrypt(stored, secret_key) if stored else ""
            send_email(email, password, subject, text, now)
            results.append(f"e-mail sent to {', '.join(email.recipients)}")
        except DecryptionError:
            results.append("e-mail not sent: the stored password cannot be read; type it again")
        except (smtplib.SMTPException, OSError, ValueError) as exc:
            results.append(f"e-mail failed: {_failure(exc)}")
    if not email_only:
        rows = conn.execute(
            "SELECT id, name, url_encrypted, format, secret_encrypted FROM alert_webhooks "
            "ORDER BY id"
        ).fetchall()
        for row in rows:
            if webhook_id is not None and row["id"] != webhook_id:
                continue
            try:
                url = decrypt(row["url_encrypted"], secret_key)
                secret = (
                    decrypt(row["secret_encrypted"], secret_key) if row["secret_encrypted"] else ""
                )
                post_webhook(url, row["format"], secret, events, switch, now, transport)
                results.append(f"webhook {row['name']} sent")
            except DecryptionError:
                results.append(
                    f"webhook {row['name']} not sent: its URL cannot be read; add it again"
                )
            except RuntimeError as exc:
                results.append(f"webhook {row['name']} failed: {_failure(exc)}")
    if not results:
        return "Not sent: no e-mail or webhook is set up."
    return "; ".join(results)


def switch_label(conn: sqlite3.Connection) -> str:
    """The switch as alerts name it: ``leaf1 (192.0.2.10)``; empty with none set up."""
    row = conn.execute("SELECT switch_hostname, host FROM switch_connection").fetchone()
    if row is None:
        return ""
    return f"{row['switch_hostname']} ({row['host']})" if row["switch_hostname"] else row["host"]


def dispatch(
    settings: Settings,
    events: Sequence[AlertEvent],
    transport: httpx.BaseTransport | None = None,
    *,
    background: bool = True,
    now: float | None = None,
) -> None:
    """Log ``events`` and send them, on a thread of their own unless
    ``background`` is False. Never raises: a failure is logged and noted."""
    if not events:
        return
    moment = time.time() if now is None else now
    with open_db(settings.db_path) as conn:
        ids = log_alerts(conn, moment, events, "sending")
        switch = switch_label(conn)

    def _send() -> None:
        try:
            with open_db(settings.db_path) as conn:
                outcome = deliver(conn, settings.secret_key, events, switch, moment, transport)
                set_delivery(conn, ids, outcome)
            log.info("alert sent (%d events): %s", len(events), outcome)
        except Exception:
            log.exception("sending an alert failed")
            with open_db(settings.db_path) as conn:
                set_delivery(conn, ids, "failed: unexpected error, see the log")

    if background:
        threading.Thread(target=_send, daemon=True, name="alert").start()
    else:
        _send()


def notify_change(
    settings: Settings,
    username: str,
    area: str,
    what: str,
    transport: httpx.BaseTransport | None = None,
    *,
    background: bool = True,
) -> None:
    """Send a change made through NXray, when the rules ask for that. Never raises."""
    try:
        with open_db(settings.db_path) as conn:
            if not load_rules(conn).changes:
                return
        message = f"{username} on the {area} page: {' '.join(what.split())}"
        dispatch(
            settings, [AlertEvent(CHANGE, message[:MESSAGE_MAX])], transport, background=background
        )
    except Exception:
        log.exception("could not send a change alert")


def send_test(
    settings: Settings,
    transport: httpx.BaseTransport | None = None,
    *,
    webhook_id: int | None = None,
    email_only: bool = False,
) -> str:
    """Send a test alert now and wait for it; how it went, in words."""
    now = time.time()
    events = [AlertEvent(TEST, "This is a test alert from NXray's Alerts page.")]
    with open_db(settings.db_path) as conn:
        switch = switch_label(conn)
        outcome = deliver(
            conn,
            settings.secret_key,
            events,
            switch,
            now,
            transport,
            webhook_id=webhook_id,
            email_only=email_only,
        )
        log_alerts(conn, now, events, outcome)
    return outcome
