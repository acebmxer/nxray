"""Flex Links: a pair of layer 2 ports (or port-channels) where one is the backup of the
other. Only one of the two forwards at a time; when the active one fails, the backup takes
over at once, with no spanning tree (spanning tree is off on both ports of a pair).

On the active port, ``switchport backup interface <backup>`` makes the pair. Optional, on
the same port: ``... preemption mode forced|bandwidth|off`` (which port forwards once both
are up again: always the active one, the faster one, or whichever is forwarding),
``... preemption delay <1-300>`` (how long it waits first; default 35 seconds, used by forced
and bandwidth only) and ``... multicast fast-convergence`` (the backup learns the IGMP
groups too, so multicast moves over at once).

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): one scope, the pair, made and deleted with its ``switchport backup
interface`` line, each setting the one line it sends with checked values in its blanks.
``NxapiClient.configure_flexlink`` sends them.

Read from the switch: ``show feature``, ``show version`` and ``show interface brief`` in one
request; while the feature is on, ``show interface switchport backup`` as text (its columns
Active Interface, Backup Interface and State) and ``show running-config`` as text, where the
pairs' lines are read.

Everything here follows Cisco's NX-OS 9.3 Layer 2 Switching guide and was not tried on a
switch: Flex Links run only on the Nexus 9300-EX, -FX, -FX2 and -GX, the 9364C, the
93108TC-FX3H and -FX3P and the 93180YC-FX3, and cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16),
2026-11-13) refused ``feature flexlink`` ("Feature flexlink is not supported on this
platform"), ``switchport backup interface`` and ``show interface switchport backup``. The
page says so on a Nexus 9200. The guide gives no ``mmu`` (MAC address-table move update)
lines for the Nexus 9000, so none is offered; nor does it give the ``no`` forms of the
preemption lines, which are sent as ``no`` and the line.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
from typing import Any

from app.features import feature_states
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
    check_value,
    port_field,
)
from app.routing import long_name
from app.spanning_tree import switch_port_names
from app.switch import text
from app.vxlan import parse_vxlan_config

FEATURE = "Flexlink"  # as show feature names it; the command is feature flexlink
PAGE_COMMANDS = ("show feature", "show version", "show interface brief")
STATE_COMMAND = "show interface switchport backup"
CONFIG_COMMAND = "show running-config"
DELAY_MAX = 300
PREEMPTION_MODES = ("forced", "bandwidth", "off")

NOT_ON_9200 = (
    'This switch does not do Flex Links: it refuses feature flexlink ("Feature flexlink is '
    "not supported on this platform\"). Cisco's NX-OS 9.3 guide lists them for the Nexus "
    "9300-EX, -FX, -FX2 and -GX, the 9364C, the 93108TC-FX3H and -FX3P and the 93180YC-FX3."
)


def _backup() -> Field:
    return Field(
        "backup",
        "Backup port",
        "port",
        hint="A front port or port-channel, not a port-channel's member",
        placeholder="Ethernet1/2",
    )


def _active() -> Field:
    field = port_field()
    return dataclasses.replace(field, label="Active port", placeholder="Ethernet1/1")


_LINE = "switchport backup interface {backup}"

_PAIR = Scope(
    key="pair",
    label="Flex Link pair",
    ident=(_active(), _backup()),
    enter=("interface {port}", _LINE),
    create=True,
    create_label="Make a Flex Link pair",
    delete=("interface {port}", f"no {_LINE}"),
    delete_warning="Both ports then run spanning tree again and may both forward.",
    help="The active port forwards; the backup takes over when it fails. Both stay layer 2 "
    "ports with spanning tree off, so they must not make a loop any other way.",
    settings=(
        Setting(
            "preemption_mode",
            "Preemption",
            f"{_LINE} preemption mode {{mode}}",
            (
                Field(
                    "mode",
                    "Mode",
                    "choice",
                    choices=PREEMPTION_MODES,
                    hint="forced: the active port takes back over; bandwidth: the faster "
                    "port does; off (default): whichever forwards stays",
                ),
            ),
            removable=False,
            ident=("backup",),
            group="Preemption",
            help="Which port forwards once both are up again.",
        ),
        Setting(
            "preemption_delay",
            "Preemption delay",
            f"{_LINE} preemption delay {{seconds}}",
            (
                Field(
                    "seconds",
                    "Seconds",
                    "int",
                    minimum=1,
                    maximum=DELAY_MAX,
                    hint=f"1 to {DELAY_MAX}; default 35",
                ),
            ),
            ident=("backup",),
            group="Preemption",
            help="How long a port that came back waits before taking over (forced and "
            "bandwidth only).",
        ),
        Setting(
            "fast_convergence",
            "Multicast fast convergence",
            f"{_LINE} multicast fast-convergence",
            ident=("backup",),
            group="Multicast",
            help="The backup port learns the IGMP groups too, so multicast moves over at once.",
        ),
    ),
)

SCOPES = (_PAIR,)


# ---- reading -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Pair:
    """One port's ``switchport backup interface`` lines."""

    port: str
    backup: str
    values: dict[str, dict[str, str]]


def parse_flexlink_config(config: str) -> list[Pair]:
    """The Flex Link pairs in ``show running-config``: the ports with ``switchport backup
    interface`` lines, and the options in them."""
    tree = parse_vxlan_config(config)
    found: dict[tuple[str, str], dict[str, dict[str, str]]] = {}
    for line in tree.children():
        if not line.startswith("interface "):
            continue
        port = line.split(" ", 1)[1]
        for child in tree.children(line):
            match = re.fullmatch(r"switchport backup interface (\S+)(?: (.+))?", child)
            if not match:
                continue
            values = found.setdefault((port, match.group(1)), {})
            rest = match.group(2) or ""
            if mode := re.fullmatch(r"preemption mode (\S+)", rest):
                values["preemption_mode"] = {"mode": mode.group(1)}
            elif delay := re.fullmatch(r"preemption delay (\d+)", rest):
                values["preemption_delay"] = {"seconds": delay.group(1)}
            elif rest == "multicast fast-convergence":
                values["fast_convergence"] = {}
    return [Pair(port, backup, values) for (port, backup), values in found.items()]


def _name(port: str) -> str:
    """A port as the configuration writes it: Eth1/1 -> Ethernet1/1, Po10 -> port-channel10."""
    if re.fullmatch(r"Po\d+", port):
        return "port-channel" + port[2:]
    return long_name(port)


def parse_backup_state(output: str | None) -> list[tuple[str, str, str]]:
    """``show interface switchport backup`` as text: (active port, backup port, state), from
    the rows under its ``Active Interface  Backup Interface  State`` heading."""
    rows = []
    for line in (output or "").splitlines():
        match = re.match(r"^\s*((?:Eth|Ethernet|Po|port-channel)\S+)\s+(\S+)\s+(\S.*?)\s*$", line)
        if match:
            active, backup, state = match.groups()
            rows.append((_name(active), _name(backup), state))
    return rows


def _facts(pair: Pair, state: str) -> tuple[tuple[str, str], ...]:
    mode = pair.values.get("preemption_mode", {}).get("mode", "off")
    delay = pair.values.get("preemption_delay", {}).get("seconds", "35")
    facts = [
        ("State", state or "not reported"),
        ("Preemption", mode),
        ("Preemption delay", f"{delay} seconds" if mode != "off" else "not used"),
        (
            "Multicast fast convergence",
            "on" if "fast_convergence" in pair.values else "off",
        ),
    ]
    return tuple(facts)


def parse_flexlink(config: str | None, state: str | None) -> ProtocolView:
    """The page from the configuration text (None: not shown) and the pairs' state text
    (None: not shown)."""
    states = {(a, b): s for a, b, s in parse_backup_state(state)}
    pairs = parse_flexlink_config(config or "")
    instances = [
        Instance(
            "pair",
            {"port": p.port, "backup": p.backup},
            f"{p.port} backed up by {p.backup}",
            _facts(p, states.get((p.port, p.backup), "")),
            p.values,
        )
        for p in pairs
    ]
    notes = []
    if config is None:
        notes.append(
            "The switch did not show its configuration to NXray's account: the pairs' "
            "settings are not filled in."
        )
    table = Table(
        "Pairs",
        ("Active port", "Backup port", "State"),
        tuple(parse_backup_state(state)),
        empty="No Flex Link pair is set up."
        if state is not None
        else "The switch did not report its Flex Link pairs.",
    )
    return ProtocolView(tuple(instances), (table,), tuple(notes))


FLEXLINK = Protocol(
    key="flexlink",
    name="Flex Links",
    summary="A backup port that takes over at once when its active port fails",
    features=(FEATURE,),
    commands=(),
    parse=lambda bodies: parse_flexlink(None, None),
    scopes=SCOPES,
    about=(
        "Pair two layer 2 ports or port-channels, usually uplinks: the backup waits and "
        "forwards only while the active one is down. Spanning tree is off on both, so give "
        "them no spanning tree settings (edge port, BPDU guard) and make no other loop. "
        "Neither may be a port-channel's member or a vPC."
    ),
)


@dataclass(frozen=True)
class FlexlinkPage:
    """Everything the Flex Links page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # the switched front ports and port-channels
    problem: str = ""
    missing: tuple[str, ...] = ()  # the Flexlink feature, when it is off


def model_note(version: Any) -> str:
    """The plain refusal for a switch Cisco's guide does not list (a Nexus 9200), from
    ``show version``; "" for any other."""
    chassis = text(version.get("chassis_id")) if isinstance(version, dict) else ""
    if re.search(r"\bC92\d", chassis):
        return NOT_ON_9200
    return ""


def load_flexlink_page(client: NxapiClient) -> FlexlinkPage:
    """One request for the features, model and ports; while Flex Links are on, the pairs'
    state and the configuration text."""
    feature, version, brief = client.show(*PAGE_COMMANDS)
    ports = tuple(switch_port_names(brief or {}))
    problem = model_note(version)
    if not feature_states(feature).get(FEATURE, False):
        return FlexlinkPage(FLEXLINK, ProtocolView(), ports, problem, (FEATURE,))
    try:
        state: str | None = client.show_text(STATE_COMMAND)
    except NxapiCommandError:
        state = None
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = None
    return FlexlinkPage(FLEXLINK, parse_flexlink(config, state), ports, problem)


def check_flexlink_place(page: FlexlinkPage, ident: dict[str, str]) -> None:
    """Refuse a port the switch does not have as a layer 2 port (unless a pair already names
    it, so it can still be removed), and a port backing itself up."""
    names = []
    for name, spec in (("port", _active()), ("backup", _backup())):
        raw = ident.get(name, "").strip()
        try:
            names.append(check_value(spec, raw) if raw else "")
        except ValueError:
            return  # build_change names the field
    port, backup = names
    if port and port == backup:
        raise ValueError("a port cannot be its own backup")
    listed = {i.ident.get(k) for i in page.view.instances for k in ("port", "backup")}
    for name in (port, backup):
        if name and name not in page.ports and name not in listed:
            raise ValueError(f"the switch has no layer 2 port {name}")


def build_flexlink_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Flex Links page. A setting's own line carries the backup
    port, so the pair's line itself is not typed again before it."""
    change = build_change(FLEXLINK, scope, setting, action, ident, values)
    if action in ("set", "remove"):
        lines = (change.lines[0], *change.lines[2:])
        labels = (change.labels[0], *change.labels[2:])
        change = dataclasses.replace(change, lines=lines, labels=labels)
    return change
