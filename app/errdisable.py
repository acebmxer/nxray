"""Errdisable: which problems shut a port down (detection), which of them let it come
back by itself after a while (recovery), how long that while is, and the ports shut
down now.

When the switch detects a problem on a port (a BPDU on a BPDU-guarded port, a link that
flaps, a loop, a storm-control or port-security violation...) it puts the port in the
err-disabled state. Without recovery the port stays down until someone turns it off and
on; with recovery for that cause the switch tries again after the interval.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): one scope (the switch), each setting the one configuration line
it sends with checked values in its blanks, and ``build_change`` building the lines.
``NxapiClient.configure_errdisable`` sends them.

Read from the switch, in one request: ``show errdisable detect`` and ``show errdisable
recovery`` (``TABLE_errdisable`` rows of ``cause`` and ``state``; the recovery table's last
row also carries ``time_interval``); then ``show interface status err-disabled`` as text
(its JSON is empty when no port is err-disabled, and its rows were never seen filled).

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-11) with an account holding NXray's broad role,
every line undone afterwards: ``errdisable recovery cause <cause>`` and its ``no`` form
for the causes in ``RECOVERY_CAUSES`` except ``all``; the switch refused ``miscabling``
(which Cisco's guide lists), ``arp-inspection``, ``dhcp-rate-limit``, ``ip-addr-conflict``
and ``pause-rate-limit``. ``errdisable recovery interval 300`` (the default) and
``errdisable detect cause link-flap``, ``loopback`` and ``all`` (already on) were taken.
Not tried: ``errdisable recovery cause all``, ``errdisable detect cause acl-exception``,
and the ``no`` forms of the detect lines and of the interval (from Cisco's NX-OS 9.3
Interfaces Configuration Guide).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.nxapi import NxapiClient, NxapiCommandError
from app.protocols import (
    Field,
    Instance,
    Protocol,
    ProtocolChange,
    ProtocolView,
    Scope,
    Setting,
    Table,
    build_change,
    table_rows,
)
from app.switch import text

COMMANDS = ("show errdisable detect", "show errdisable recovery")
PORTS_COMMAND = "show interface status err-disabled"
# The causes ``errdisable recovery cause`` takes on NX-OS 9.3(16), checked on a switch
# (``all`` from Cisco's guide).
RECOVERY_CAUSES = (
    "all",
    "bpduguard",
    "failed-port-state",
    "link-flap",
    "loopback",
    "psecure-violation",
    "security-violation",
    "storm-control",
    "udld",
    "vpc-peerlink",
)
DETECT_CAUSES = ("all", "acl-exception", "link-flap", "loopback")
INTERVAL_MIN = 30
INTERVAL_MAX = 65535
INTERVAL_DEFAULT = 300

_SWITCH = Scope(
    key="errdisable",
    label="Whole switch",
    ident=(),
    enter=(),
    help=(
        "Recovery brings a port shut down for a cause back by itself after the interval. "
        "Without it the port stays down until it is turned off and on again (on its own "
        "page)."
    ),
    settings=(
        Setting(
            key="recovery",
            label="Recover from a cause",
            line="errdisable recovery cause {cause}",
            group="Recovery",
            fields=(
                Field(
                    "cause",
                    "Cause",
                    "choice",
                    choices=RECOVERY_CAUSES,
                    hint="all: every cause the switch can recover from",
                ),
            ),
            help="Set turns recovery on for the cause; Remove turns it off again.",
        ),
        Setting(
            key="interval",
            label="Recovery interval",
            line="errdisable recovery interval {seconds}",
            removable=False,
            group="Recovery",
            fields=(
                Field(
                    "seconds",
                    "Seconds",
                    "int",
                    INTERVAL_MIN,
                    INTERVAL_MAX,
                    hint=f"{INTERVAL_MIN} to {INTERVAL_MAX}; the switch starts with "
                    f"{INTERVAL_DEFAULT}",
                    placeholder=str(INTERVAL_DEFAULT),
                ),
            ),
            help="How long a port stays err-disabled before the switch tries it again. To "
            f"go back to the default, set {INTERVAL_DEFAULT}.",
        ),
        Setting(
            key="detect",
            label="Detect a cause",
            line="errdisable detect cause {cause}",
            group="Detection",
            fields=(Field("cause", "Cause", "choice", choices=DETECT_CAUSES),),
            help="Detection is on for every cause from the start. Remove stops the switch "
            "shutting a port down for that cause: the problem then goes on unchecked.",
        ),
    ),
)


def _states(body: Any) -> dict[str, str]:
    """``cause -> state`` of one ``show errdisable`` table."""
    return {
        text(row.get("cause")): text(row.get("state"))
        for row in table_rows(body, "TABLE_errdisable", "ROW_errdisable")
        if text(row.get("cause"))
    }


def recovery_interval(body: Any) -> str:
    """The recovery interval in seconds, from the row of ``show errdisable recovery``
    that carries it; "" when none does."""
    for row in table_rows(body, "TABLE_errdisable", "ROW_errdisable"):
        if row.get("time_interval") not in (None, ""):
            return text(row.get("time_interval"))
    return ""


_PORT_LINE = re.compile(r"^((?:Eth|Ethernet|Po|port-channel)\d\S*)\s+(.*)$", re.IGNORECASE)


def parse_err_disabled(text_out: str) -> list[tuple[str, str, str]]:
    """The ports in ``show interface status err-disabled``: (port, description, reason).

    Each line starts with the port; the status word (err-disabled, errDisabled...) splits
    the description before it from the reason after it."""
    found = []
    for line in text_out.splitlines():
        match = _PORT_LINE.match(line.strip())
        if not match:
            continue
        words = match.group(2).split()
        status = next((i for i, w in enumerate(words) if w.lower().startswith("err")), None)
        if status is None:
            found.append((match.group(1), "", " ".join(words)))
            continue
        found.append(
            (match.group(1), " ".join(words[:status]), " ".join(words[status + 1 :]) or "-")
        )
    return found


def _on(state: str) -> str:
    return "on" if state.lower().startswith("enab") else "off"


def parse_errdisable(bodies: list[Any], ports_text: str = "") -> ProtocolView:
    """The page from ``show errdisable detect`` and ``show errdisable recovery`` (bodies in
    that order) and the err-disabled ports' text."""
    detect = _states(bodies[0] if bodies else None)
    recovery_body = bodies[1] if len(bodies) > 1 else None
    recovery = _states(recovery_body)
    interval = recovery_interval(recovery_body)
    causes = list(detect) + [c for c in recovery if c not in detect]
    rows = tuple(
        (
            cause,
            _on(detect[cause]) if cause in detect else "-",
            _on(recovery[cause]) if cause in recovery else "-",
        )
        for cause in causes
    )
    recovering = [c for c in causes if c in recovery and _on(recovery[c]) == "on"]
    facts = (
        ("Recovery interval", f"{interval} seconds" if interval else "-"),
        ("Recovers by itself from", ", ".join(recovering) or "none"),
    )
    values = {"interval": {"seconds": interval}} if interval else {}
    instance = Instance("errdisable", {}, "Errdisable on the switch", facts, values)
    ports = parse_err_disabled(ports_text)
    tables = (
        Table(
            "Ports shut down now",
            ("Port", "Description", "Reason"),
            tuple(ports),
            empty="No port is err-disabled.",
            note="Turn a port off and on again on its own page to bring it back now.",
        ),
        Table(
            "Causes",
            ("Cause", "Detected", "Recovers by itself"),
            rows,
            empty="The switch listed no errdisable causes.",
            note="The names are the switch's own, cut to 20 letters in places.",
        ),
    )
    return ProtocolView((instance,) if detect or recovery else (), tables)


ERRDISABLE = Protocol(
    key="errdisable",
    name="Errdisable",
    summary="Which problems shut a port down, and which let it come back by itself",
    features=(),
    commands=COMMANDS,
    parse=lambda bodies: parse_errdisable(bodies),
    scopes=(_SWITCH,),
    about=(
        "A port the switch shuts down for a problem (err-disabled) stays down until it is "
        "turned off and on again, unless recovery is on for that cause."
    ),
)


@dataclass(frozen=True)
class ErrdisablePage:
    """Everything the Errdisable page shows."""

    protocol: Protocol
    view: ProtocolView
    problem: str = ""
    missing: tuple[str, ...] = ()  # always empty: errdisable needs no feature


def load_errdisable_page(client: NxapiClient) -> ErrdisablePage:
    """One request for the detection and recovery tables; one for the err-disabled
    ports' text."""
    bodies = client.show(*COMMANDS)
    try:
        ports = client.show_text(PORTS_COMMAND)
    except NxapiCommandError as exc:
        return ErrdisablePage(
            ERRDISABLE,
            parse_errdisable(bodies),
            f"The switch did not list the err-disabled ports: {exc}",
        )
    return ErrdisablePage(ERRDISABLE, parse_errdisable(bodies, ports))


def build_errdisable_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Errdisable page."""
    return build_change(ERRDISABLE, scope, setting, action, ident, values)
