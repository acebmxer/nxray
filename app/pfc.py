"""Priority flow control (PFC): a port's pause mode, the watchdog and the pause counters.

PFC lets a port tell the sender to pause one traffic class (one CoS value) instead of
everything, so a lossless class such as storage or RoCE does not drop packets. The PFC
page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (a port, the whole switch), each setting the one
configuration line it sends with checked values in its blanks, and ``build_change``
building the lines. ``NxapiClient.configure_pfc`` sends them.

Read from the switch: ``show interface priority-flow-control detail`` (JSON) and
``show interface brief`` (the ports). Which classes are paused is set on the QoS page
(a network-qos policy with ``pause pfc-cos``).

Read on cisco-25gb (NX-OS 9.3(16), 2026-11-10): the JSON of the show command above. The
configuration lines were NOT tried on a switch; they are written from Cisco's NX-OS 9.3
Quality of Service guide:

* per port: ``priority-flow-control mode on|off|auto`` (``auto`` negotiates with the
  neighbour over DCBX and is the default) and ``priority-flow-control watch-dog-interval
  on|off``;
* switch-wide: ``priority-flow-control watch-dog-interval on|off`` and
  ``priority-flow-control override-interface mode off``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.monitor import all_port_names
from app.nxapi import NxapiClient
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
    port_field,
    table_rows,
)
from app.switch import text

PAGE_COMMANDS = ("show interface brief",)
COUNTERS_COMMAND = "show interface priority-flow-control detail"
MODES = ("on", "off", "auto")
WATCHDOG = ("on", "off")
COS = range(8)

_PORT = Scope(
    key="pfc_port",
    label="Port",
    ident=(port_field(),),
    enter=("interface {port}",),
    help="PFC on one port. The default is auto: the port uses PFC when the neighbour does.",
    settings=(
        Setting(
            key="mode",
            label="PFC mode",
            line="priority-flow-control mode {mode}",
            no_line="no priority-flow-control mode",
            group="Mode",
            fields=(
                Field(
                    "mode",
                    "Mode",
                    "choice",
                    choices=MODES,
                    hint="on: always; off: never; auto: when the neighbour asks (DCBX)",
                ),
            ),
            help="Whether this port sends and obeys pause frames for single classes.",
            warning="Changing the mode can briefly drop packets on this port.",
        ),
        Setting(
            key="watchdog",
            label="PFC watchdog",
            line="priority-flow-control watch-dog-interval {state}",
            no_line="no priority-flow-control watch-dog-interval",
            group="Watchdog",
            fields=(Field("state", "Watchdog", "choice", choices=WATCHDOG),),
            help="Watches for a class that stays paused for too long (a stuck neighbour) and "
            "drops its packets so the port does not stall.",
        ),
    ),
)

_SWITCH = Scope(
    key="pfc_switch",
    label="Whole switch",
    ident=(),
    enter=(),
    help="PFC settings for every port at once.",
    settings=(
        Setting(
            key="watchdog",
            label="PFC watchdog on all ports",
            line="priority-flow-control watch-dog-interval {state}",
            no_line="no priority-flow-control watch-dog-interval",
            group="Watchdog",
            fields=(Field("state", "Watchdog", "choice", choices=WATCHDOG),),
            help="Turns the watchdog on or off for every port.",
        ),
        Setting(
            key="override",
            label="Force PFC off on all ports",
            line="priority-flow-control override-interface mode off",
            no_line="no priority-flow-control override-interface mode off",
            group="Mode",
            help="Overrides every port's own mode: PFC is off everywhere.",
            warning="Every port stops using PFC, whatever its own mode says.",
        ),
    ),
)


def _count(value: Any) -> int:
    """A counter the switch gives as a number or as text."""
    try:
        return int(text(value) or 0)
    except ValueError:
        return 0


def parse_pfc(bodies: list[dict[str, Any]]) -> ProtocolView:
    """The ports from ``show interface priority-flow-control detail``: a table of every
    port's mode, state and pause counts, a table of the pause counts per priority (CoS),
    and a place for each port whose mode is not the default."""
    body = bodies[0] if bodies else {}
    rows = [
        row
        for module in table_rows(body, "TABLE_module", "ROW_module")
        for row in table_rows(module, "TABLE_pfc_interface", "ROW_pfc_interface")
    ]
    ports: list[tuple[str, ...]] = []
    per_cos: list[tuple[str, ...]] = []
    instances: list[Instance] = []
    for row in rows:
        name = text(row.get("if_name_str"))
        if not name:
            continue
        admin, oper = text(row.get("admin")), text(row.get("oper"))
        rx, tx = _count(row.get("rx-stats")), _count(row.get("tx-stats"))
        ports.append((name, admin or "-", oper or "-", str(rx), str(tx)))
        received = [_count(row.get(f"rx_ppp_cos_{n}")) for n in COS]
        sent = [_count(row.get(f"tx_ppp_cos_{n}")) for n in COS]
        if any(received) or any(sent):
            per_cos.append((name, *(f"{a} / {b}" for a, b in zip(received, sent, strict=True))))
        if admin.lower() in ("on", "off"):
            instances.append(
                Instance(
                    "pfc_port",
                    {"port": name},
                    name,
                    (("PFC mode", admin), ("State", oper or "-")),
                    {"mode": {"mode": admin.lower()}},
                )
            )
    tables = (
        Table(
            "Ports",
            ("Port", "Mode", "State", "Pause received", "Pause sent"),
            tuple(ports),
            empty="The switch listed no ports with PFC.",
            note="Mode is what the port is set to; state is whether PFC is working on it now.",
        ),
        Table(
            "Pause frames by priority (received / sent)",
            ("Port", *(f"CoS {n}" for n in COS)),
            tuple(per_cos),
            empty="No pause frames have been counted on any port.",
        ),
    )
    return ProtocolView(tuple(instances), tables)


PFC = Protocol(
    key="pfc",
    name="Priority flow control",
    summary="Pause single traffic classes per port, with the pause counters (PFC)",
    features=(),
    commands=(COUNTERS_COMMAND,),
    parse=parse_pfc,
    scopes=(_PORT, _SWITCH),
    about=(
        "Set a port's PFC mode and the watchdog here. Which classes are paused (pause "
        "pfc-cos) is set in a network-qos policy on the QoS page."
    ),
)


@dataclass(frozen=True)
class PfcPage:
    """Everything the Priority flow control page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # the front ports and port-channels
    vlans: tuple[str, ...] = ()  # kept for the template
    problem: str = ""
    missing: tuple[str, ...] = ()  # PFC needs no feature; kept for the template


def load_pfc_page(client: NxapiClient) -> PfcPage:
    """One request for the ports and one for the PFC state and counters."""
    (brief,) = client.show(*PAGE_COMMANDS)
    (counters,) = client.show(COUNTERS_COMMAND)
    return PfcPage(PFC, parse_pfc([counters]), all_port_names(brief))


def build_pfc_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Priority flow control page."""
    return build_change(PFC, scope, setting, action, ident, values)
