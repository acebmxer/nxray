"""The front-panel ports, from NX-API show output.

Pure functions over parsed JSON bodies, like app/switch.py, so they are
tested against output recorded from a real switch. Three commands together
describe a port: ``show interface`` (state, speed, counters, rates),
``show interface status`` (VLAN, description) and ``show interface
transceiver`` (what is plugged in).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.nxapi import NxapiClient
from app.switch import rows

PORTS_COMMANDS = (
    "show interface",
    "show interface status",
    "show interface transceiver",
)

_PORT_NAME = re.compile(r"^Ethernet(\d+)/(\d+)(?:/(\d+))?$")


def _int(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def port_sort_key(name: str) -> tuple[int, ...]:
    """Ethernet1/2 before Ethernet1/10, breakouts after their parent port."""
    match = _PORT_NAME.match(name)
    if not match:
        return (999_999,)
    return tuple(int(part) if part else 0 for part in match.groups())


@dataclass(frozen=True)
class Transceiver:
    present: bool
    type: str = ""
    vendor: str = ""
    part_number: str = ""
    serial: str = ""


@dataclass(frozen=True)
class Port:
    name: str
    description: str
    up: bool
    admin_up: bool
    reason: str
    speed: str
    vlan: str
    mode: str
    mtu: str
    hardware: str
    mac: str
    last_flap: str
    transceiver: Transceiver
    in_bits_per_second: int
    out_bits_per_second: int
    in_bytes: int
    out_bytes: int
    in_packets: int
    out_packets: int
    counters: dict[str, int] = field(default_factory=dict)

    @property
    def errors(self) -> int:
        """Errors and discards in both directions, as one number."""
        return sum(self.counters.get(name, 0) for name in ERROR_COUNTERS)

    @property
    def state_label(self) -> str:
        if self.up:
            return "Up"
        if not self.admin_up:
            return "Disabled"
        return "Down"


# Counters shown on a port's own page, with the words used there.
COUNTER_LABELS = {
    "eth_inucast": "Unicast in",
    "eth_inmcast": "Multicast in",
    "eth_inbcast": "Broadcast in",
    "eth_outucast": "Unicast out",
    "eth_outmcast": "Multicast out",
    "eth_outbcast": "Broadcast out",
    "eth_inerr": "Input errors",
    "eth_crc": "CRC errors",
    "eth_runts": "Runts",
    "eth_giants": "Giants",
    "eth_indiscard": "Input discards",
    "eth_outerr": "Output errors",
    "eth_outdiscard": "Output discards",
    "eth_coll": "Collisions",
    "eth_inpause": "Pause frames in",
    "eth_outpause": "Pause frames out",
}

# Summed into Port.errors. CRC errors are already part of input errors.
ERROR_COUNTERS = ("eth_inerr", "eth_outerr", "eth_indiscard", "eth_outdiscard")


def parse_transceivers(body: dict[str, Any]) -> dict[str, Transceiver]:
    """Transceivers by port name, from ``show interface transceiver``."""
    found: dict[str, Transceiver] = {}
    for row in rows(body, "TABLE_interface", "ROW_interface"):
        name = str(row.get("interface", ""))
        present = str(row.get("sfp", "")).strip().lower() == "present"
        found[name] = Transceiver(
            present=present,
            type=str(row.get("type", "")).strip() if present else "",
            vendor=str(row.get("name", "")).strip() if present else "",
            part_number=str(row.get("partnum", "")).strip() if present else "",
            serial=str(row.get("serialnum", "")).strip() if present else "",
        )
    return found


def _speed(interface: dict[str, Any], status: dict[str, Any]) -> str:
    """The running speed when the port is up, otherwise the configured one."""
    running = str(interface.get("eth_speed", "")).strip()
    if running and running != "auto-speed":
        return running
    configured = str(status.get("speed", "")).strip()
    return "auto" if configured in ("", "auto") else configured


def parse_ports(
    interface_body: dict[str, Any],
    status_body: dict[str, Any],
    transceiver_body: dict[str, Any],
) -> list[Port]:
    """Every Ethernet port, in front-panel order. mgmt0 is left out."""
    statuses = {
        str(row.get("interface", "")): row
        for row in rows(status_body, "TABLE_interface", "ROW_interface")
    }
    transceivers = parse_transceivers(transceiver_body)
    ports: list[Port] = []
    for row in rows(interface_body, "TABLE_interface", "ROW_interface"):
        name = str(row.get("interface", ""))
        if not name.startswith("Ethernet"):
            continue
        status = statuses.get(name, {})
        up = str(row.get("state", "")).lower() == "up"
        ports.append(
            Port(
                name=name,
                description=str(row.get("desc") or status.get("name") or "").strip(),
                up=up,
                admin_up=str(row.get("admin_state", "up")).lower() == "up",
                reason="" if up else str(row.get("state_rsn_desc", "")).strip(),
                speed=_speed(row, status),
                vlan=str(status.get("vlan", "")).strip(),
                mode=str(row.get("eth_mode", "")).strip(),
                mtu=str(row.get("eth_mtu", "")).strip(),
                hardware=str(row.get("eth_hw_desc", "")).strip(),
                mac=str(row.get("eth_hw_addr", "")).strip(),
                last_flap=str(row.get("eth_link_flapped", "")).strip(),
                transceiver=transceivers.get(name, Transceiver(present=False)),
                in_bits_per_second=_int(row.get("eth_inrate1_bits")),
                out_bits_per_second=_int(row.get("eth_outrate1_bits")),
                in_bytes=_int(row.get("eth_inbytes")),
                out_bytes=_int(row.get("eth_outbytes")),
                in_packets=_int(row.get("eth_inpkts")),
                out_packets=_int(row.get("eth_outpkts")),
                counters={key: _int(row.get(key)) for key in COUNTER_LABELS},
            )
        )
    ports.sort(key=lambda port: port_sort_key(port.name))
    return ports


def load_ports(client: NxapiClient) -> list[Port]:
    """Every port, from one NX-API request."""
    interfaces, statuses, transceivers = client.show(*PORTS_COMMANDS)
    return parse_ports(interfaces, statuses, transceivers)


def human_bytes(count: int) -> str:
    """1536 -> "1.5 KB". Powers of 1024, as the switch counts memory."""
    value = float(count)
    unit = "B"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if value < 1024 or unit == "PB":
            break
        value /= 1024
    return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"


def human_rate(bits_per_second: int) -> str:
    """12_500_000 -> "12.5 Mb/s". Powers of 1000, as link speeds are."""
    value = float(bits_per_second)
    unit = "b/s"
    for unit in ("b/s", "kb/s", "Mb/s", "Gb/s", "Tb/s"):
        if value < 1000 or unit == "Tb/s":
            break
        value /= 1000
    return f"{int(value)} {unit}" if unit == "b/s" else f"{value:.1f} {unit}"
