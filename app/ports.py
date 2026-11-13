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
from app.switch import int_or, rows

PORTS_COMMANDS = (
    "show interface",
    "show interface status",
    "show interface transceiver",
)

_PORT_NAME = re.compile(r"^Ethernet(\d+)/(\d+)(?:/(\d+))?$")


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
    # The link's bandwidth (the running speed when up), 0 when not reported.
    bandwidth_bits: int = 0
    # The speed column of ``show interface status``: the configured speed
    # ("auto", "10G", "1000") while the port is down, the running one while up.
    status_speed: str = ""
    duplex: str = ""
    # Forward error correction: what is set, and what the link runs with.
    fec: str = ""
    fec_oper: str = ""
    # Seconds the switch averages In and Out over (``load-interval counter
    # 1``), 0 when not reported.
    load_interval: int = 0

    @property
    def errors(self) -> int:
        """Errors and discards in both directions, as one number."""
        return sum(self.counters.get(name, 0) for name in ERROR_COUNTERS)

    @property
    def error_kinds(self) -> list[tuple[str, int]]:
        """What ``errors`` is made of, as (kind, count) for each kind that is not zero.

        The switch's input errors already include CRC errors, runts and giants, so those
        are named first and only what is left is "Other input errors": the counts add up
        to ``errors``.
        """
        count = self.counters.get
        crc, runts, giants = count("eth_crc", 0), count("eth_runts", 0), count("eth_giants", 0)
        kinds = [
            ("CRC errors", crc),
            ("Runts", runts),
            ("Giants", giants),
            ("Other input errors", max(count("eth_inerr", 0) - crc - runts - giants, 0)),
            ("Input discards", count("eth_indiscard", 0)),
            ("Output errors", count("eth_outerr", 0)),
            ("Output discards", count("eth_outdiscard", 0)),
        ]
        return [(kind, number) for kind, number in kinds if number]

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

# The counters ``Port.error_kinds`` names, as written on the Counters card of a port's page.
ERROR_KEYS = frozenset({*ERROR_COUNTERS, "eth_crc", "eth_runts", "eth_giants"})


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
                in_bits_per_second=int_or(row.get("eth_inrate1_bits")),
                out_bits_per_second=int_or(row.get("eth_outrate1_bits")),
                in_bytes=int_or(row.get("eth_inbytes")),
                out_bytes=int_or(row.get("eth_outbytes")),
                in_packets=int_or(row.get("eth_inpkts")),
                out_packets=int_or(row.get("eth_outpkts")),
                counters={key: int_or(row.get(key)) for key in COUNTER_LABELS},
                # eth_bw is in kilobits per second.
                bandwidth_bits=int_or(row.get("eth_bw")) * 1000,
                status_speed=str(status.get("speed", "")).strip(),
                duplex=str(row.get("eth_duplex", "")).strip(),
                fec=str(row.get("eth_admin_fec_state", "")).strip(),
                fec_oper=str(row.get("eth_oper_fec_state", "")).strip(),
                load_interval=int_or(row.get("eth_load_interval1_rx")),
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
