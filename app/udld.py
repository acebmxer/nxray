"""UDLD (UniDirectional Link Detection): finds a cable that carries traffic one way only.

Two switches that both run UDLD send each other small messages on a link. A port that
stops hearing its own messages echoed back has a one-way cable (a broken fibre strand,
a bad transceiver), and UDLD can turn the port off before it causes a loop. The page is
described with the same parts as the Monitor sessions page (``app/protocols.py``):
scopes (a port, the whole switch), each setting the one configuration line it sends
with checked values in its blanks, and ``build_change`` building the lines.
``NxapiClient.configure_udld`` sends them.

Read from the switch: ``show feature`` and ``show interface brief`` in one request;
while ``feature udld`` is on (the commands are refused before), ``show udld global``
and ``show udld`` as text (``NxapiClient.show_text``).

NOT tried on a switch: turning ``feature udld`` on starts UDLD on every fibre port, and
cisco-25gb is in production. Written from Cisco's NX-OS 9.3 Interfaces Configuration
Guide ("Enable UDLD modes on interfaces" and its ``show udld global`` and ``show udld
ethernet`` samples):

* switch-wide: ``udld message-time <7-90>`` (default 15 seconds) and ``udld aggressive``
  (fibre ports only);
* per port: ``udld enable`` (a copper port is off by default; ``no udld enable`` puts
  it back), ``udld disable`` (a fibre port is on by default; ``no udld disable`` puts
  it back) and ``udld aggressive``.

The guide prints no neighbour lines, so the text is read tolerantly: any ``label:
value`` line under a port is kept, and the neighbour's device and port are taken from
the labels other Cisco software prints (``Device ID``, ``Port ID``, ``Device name``). A
line worded differently shows empty rather than breaking the page.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.features import feature_states
from app.monitor import all_port_names
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
)

PAGE_COMMANDS = ("show feature", "show interface brief")
GLOBAL_COMMAND = "show udld global"
PORTS_COMMAND = "show udld"
PORT_STATES = ("enable", "disable")
MESSAGE_TIME_MIN, MESSAGE_TIME_MAX = 7, 90

_PORT = Scope(
    key="udld_port",
    label="Port",
    ident=(
        Field(
            "port",
            "Port",
            "port",
            hint="A front port such as Ethernet1/3",
            placeholder="Ethernet1/3",
        ),
    ),
    enter=("interface {port}",),
    help="UDLD on one port. A fibre port runs UDLD as soon as the feature is on; a copper "
    "port only when it is turned on here. The other end must run UDLD too.",
    settings=(
        Setting(
            key="state",
            label="UDLD on this port",
            line="udld {state}",
            no_line="no udld {state}",
            group="UDLD",
            fields=(
                Field(
                    "state",
                    "State",
                    "choice",
                    choices=PORT_STATES,
                    hint="enable: run UDLD (for copper ports); disable: do not (for fibre ports)",
                ),
            ),
            help="Set types the line; Remove takes that same line away, so the port goes "
            "back to its default (fibre on, copper off).",
        ),
        Setting(
            key="aggressive",
            label="Aggressive mode",
            line="udld aggressive",
            group="UDLD",
            help="Also turns the port off when the neighbour stops answering altogether. "
            "Use it only on a link between two devices that both have it set.",
            warning="In aggressive mode the switch turns this port off when the neighbour "
            "stops answering UDLD.",
        ),
    ),
)

_SWITCH = Scope(
    key="udld_switch",
    label="Whole switch",
    ident=(),
    enter=(),
    help="UDLD settings for every port at once.",
    settings=(
        Setting(
            key="message_time",
            label="Message interval",
            line="udld message-time {seconds}",
            removable=False,
            group="UDLD",
            fields=(
                Field(
                    "seconds",
                    "Seconds",
                    "int",
                    minimum=MESSAGE_TIME_MIN,
                    maximum=MESSAGE_TIME_MAX,
                    hint="7 to 90; the switch starts with 15",
                    placeholder="15",
                ),
            ),
            help="How often each port sends a UDLD message. Set 15 to go back to the "
            "switch's own value.",
        ),
        Setting(
            key="aggressive",
            label="Aggressive mode on all fibre ports",
            line="udld aggressive",
            group="UDLD",
            help="Copper ports are not included: set those one by one under Port.",
            warning="In aggressive mode the switch turns a fibre port off when its "
            "neighbour stops answering UDLD.",
        ),
    ),
)


@dataclass(frozen=True)
class UdldPort:
    """One port's block in ``show udld``."""

    name: str
    setting: str = ""  # "device-default", "enabled", "disabled"
    state: str = ""  # "enabled", "enabled-aggressive", "disabled"
    link: str = ""  # "bidirectional", "unknown", "unidirectional"
    detail: str = ""  # "advertisement - Single neighbor detected"
    neighbors: tuple[tuple[str, str, str], ...] = ()  # (device, port, state)


@dataclass
class _Block:
    name: str
    own: dict[str, str] = field(default_factory=dict)
    entries: list[dict[str, str]] = field(default_factory=list)


_INTERFACE = re.compile(r"^Interface\s+(\S+)\s*$")
_ENTRY = re.compile(r"^\s*Entry\s+\d+\s*$", re.IGNORECASE)
_PAIR = re.compile(r"^\s*([A-Za-z][^:]*?)\s*:\s*(.*?)\s*$")


def parse_udld_global(text_out: str) -> dict[str, str]:
    """``show udld global`` as ``{"mode": "enabled-aggressive", "interval": "15"}``; a
    line the switch words differently is left out."""
    found: dict[str, str] = {}
    for line in text_out.splitlines():
        match = _PAIR.match(line)
        if not match:
            continue
        label, value = match.group(1).lower(), match.group(2)
        if "configuration mode" in label:
            found["mode"] = value
        elif "message interval" in label:
            found["interval"] = value
    return found


def parse_udld_ports(text_out: str) -> list[UdldPort]:
    """The ports in ``show udld``: one block per port (``Interface Ethernet1/1``), its
    ``label: value`` lines, and one ``Entry`` per neighbour under it."""
    blocks: list[_Block] = []
    for line in text_out.splitlines():
        if match := _INTERFACE.match(line):
            blocks.append(_Block(match.group(1)))
            continue
        if not blocks:
            continue
        block = blocks[-1]
        if _ENTRY.match(line):
            block.entries.append({})
            continue
        match = _PAIR.match(line)
        if not match:
            continue
        target = block.entries[-1] if block.entries else block.own
        target.setdefault(match.group(1).lower(), match.group(2))
    ports = []
    for block in blocks:
        own = block.own
        neighbors = tuple(
            (
                entry.get("cdp device name")
                or entry.get("device name")
                or entry.get("device id", ""),
                entry.get("port id", ""),
                entry.get("current neighbor state", ""),
            )
            for entry in block.entries
        )
        ports.append(
            UdldPort(
                block.name,
                own.get("port enable administrative configuration setting", ""),
                own.get("port enable operational state", ""),
                own.get("current bidirectional state", ""),
                own.get("current operational state", ""),
                neighbors,
            )
        )
    return ports


def parse_udld(global_text: str, ports_text: str) -> ProtocolView:
    """The page from ``show udld global`` and ``show udld``: the switch-wide mode and
    message interval, a table of every port UDLD lists, a table of the neighbours it
    hears, and a place for each port whose setting is not the default."""
    switch = parse_udld_global(global_text)
    ports = parse_udld_ports(ports_text)
    instances: list[Instance] = []
    if switch:
        values: dict[str, dict[str, str]] = {}
        if switch.get("interval", "").isdigit():
            values["message_time"] = {"seconds": switch["interval"]}
        if "aggressive" in switch.get("mode", "").lower():
            values["aggressive"] = {}
        instances.append(
            Instance(
                "udld_switch",
                {},
                "UDLD on the switch",
                (
                    ("Mode", switch.get("mode", "-")),
                    (
                        "Message interval",
                        f"{switch['interval']} s" if "interval" in switch else "-",
                    ),
                ),
                values,
            )
        )
    port_rows: list[tuple[str, ...]] = []
    neighbor_rows: list[tuple[str, ...]] = []
    for port in ports:
        port_rows.append(
            (
                port.name,
                port.setting or "-",
                port.state or "-",
                port.link or "-",
                port.detail or "-",
            )
        )
        for device, remote, state in port.neighbors:
            neighbor_rows.append((port.name, device or "-", remote or "-", state or "-"))
        setting = port.setting.lower()
        if setting and setting != "device-default":
            state = "enable" if setting.startswith("enable") else "disable"
            port_values: dict[str, dict[str, str]] = {"state": {"state": state}}
            if "aggressive" in setting:
                port_values["aggressive"] = {}
            instances.append(
                Instance(
                    "udld_port",
                    {"port": port.name},
                    port.name,
                    (("Set to", port.setting), ("Running", port.state or "-")),
                    port_values,
                )
            )
    tables = (
        Table(
            "Ports",
            ("Port", "Set to", "Running", "Link", "Detail"),
            tuple(port_rows),
            empty="The switch listed no ports for UDLD.",
            note="Set to device-default means the port follows its type: fibre on, copper "
            "off. Link is bidirectional when traffic passes both ways, unknown before a "
            "neighbour answers.",
            wrap_column=4,
        ),
        Table(
            "Neighbours",
            ("Port", "Device", "Its port", "State"),
            tuple(neighbor_rows),
            empty="No port hears a UDLD neighbour.",
        ),
    )
    return ProtocolView(tuple(instances), tables)


UDLD = Protocol(
    key="udld",
    name="UDLD",
    summary="Find a cable that carries traffic one way only and turn its port off (UDLD)",
    features=("udld",),
    commands=(),
    parse=lambda bodies: ProtocolView(),
    scopes=(_PORT, _SWITCH),
    about=(
        "UDLD works only when the device at the other end runs it too. Turning the udld "
        "feature on starts it on every fibre port at once."
    ),
)


@dataclass(frozen=True)
class UdldPage:
    """Everything the UDLD page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # the front ports
    problem: str = ""
    missing: tuple[str, ...] = ()  # the feature, when it is off


def load_udld_page(client: NxapiClient) -> UdldPage:
    """One request for the feature and the ports; while udld is on, one for the
    switch-wide state and one for every port's."""
    feature, brief = client.show(*PAGE_COMMANDS)
    ports = tuple(p for p in all_port_names(brief) if p.startswith("Ethernet"))
    states = feature_states(feature)
    missing = tuple(name for name in UDLD.features if not states.get(name, False))
    if missing:
        return UdldPage(UDLD, ProtocolView(), ports, missing=missing)
    problem = ""
    try:
        global_text = client.show_text(GLOBAL_COMMAND)
        ports_text = client.show_text(PORTS_COMMAND)
    except NxapiCommandError as exc:
        global_text = ports_text = ""
        problem = f"The switch did not report UDLD's state: {exc}"
    return UdldPage(UDLD, parse_udld(global_text, ports_text), ports, problem)


def build_udld_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the UDLD page."""
    return build_change(UDLD, scope, setting, action, ident, values)
