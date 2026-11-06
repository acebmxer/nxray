"""Traffic per device and per VLAN, estimated from the ports' own figures.

The switch measures traffic per port (``show interface``: the in and out
rates averaged over 30 seconds). It does not say which VLAN or which device
the traffic belongs to. Two cases still let NXray tell, without asking the
switch for anything more:

- **A device on its own access port.** An access port carries one VLAN; when
  the MAC address table has a single address on it, the port's traffic is
  that device's traffic. A trunk, a port in a port-channel, or a port with
  several addresses behind it (a downstream switch, a hypervisor) cannot be
  split, so no device gets a figure there.
- **A VLAN's access ports.** Adding up the access ports in a VLAN gives the
  traffic its devices exchange with the switch through those ports. Trunks
  carry several VLANs and their counters cannot be split, so they are left
  out; so are routed ports.

Both are estimates and are always shown as such, with what they leave out.
Pure functions over parsed show output, like ``app/ports.py``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from app.neighbors import MacEntry, NeighborView, PortDevices
from app.nxapi import NxapiClient, NxapiCommandError
from app.ports import Port, parse_ports

# How many devices "Busiest devices" lists.
BUSIEST_DEVICES = 10


@dataclass(frozen=True)
class DeviceTraffic:
    """A device whose traffic is its port's traffic.

    Named from the device's side: what it sends comes in on the port (the
    port's in rate), what it receives goes out of it (the out rate).
    """

    mac: str
    port: str
    vlan: str
    sends_bits: int
    receives_bits: int

    @property
    def total_bits(self) -> int:
        return self.sends_bits + self.receives_bits


@dataclass(frozen=True)
class VlanTraffic:
    """A VLAN's access ports that are up, added up."""

    vlan: int
    in_bits: int  # sent into the switch by the VLAN's devices
    out_bits: int  # sent by the switch to them
    ports: int  # how many access ports were added up


def port_device(port: Port, devices: PortDevices) -> tuple[MacEntry | None, str]:
    """(the one device the port's traffic belongs to, why there is none).

    The device is None when the traffic cannot be given to one device, and
    the reason says why in words ("" when there is nothing on the port).
    """
    learned = [entry for entry in devices.macs if not entry.switch_own]
    if not learned:
        return None, ""
    if devices.channel is not None:
        return None, (
            "The port is part of a port-channel, so its traffic is not the traffic of one device."
        )
    if port.mode != "access":
        return None, (
            "The port is not an access port: a trunk carries several VLANs, so "
            "its traffic cannot be split between the devices behind it."
        )
    # One address learned in several VLANs is still one device.
    addresses = {entry.mac for entry in learned}
    if len(addresses) > 1:
        return None, (
            f"{len(addresses)} devices are behind this port (a switch, a hypervisor or "
            "a phone with a computer behind it, for example), so its traffic cannot "
            "be split between them."
        )
    return learned[0], ""


def device_traffic(ports: Sequence[Port], neighbors: NeighborView) -> dict[str, DeviceTraffic]:
    """By MAC address: every device alone on an access port that is up."""
    found: dict[str, DeviceTraffic] = {}
    for port in ports:
        if not port.up:
            continue
        entry, _ = port_device(port, neighbors.for_port(port.name))
        if entry is None:
            continue
        found[entry.mac] = DeviceTraffic(
            mac=entry.mac,
            port=port.name,
            vlan=entry.vlan,
            sends_bits=port.in_bits_per_second,
            receives_bits=port.out_bits_per_second,
        )
    return found


def load_device_traffic(client: NxapiClient, neighbors: NeighborView) -> dict[str, DeviceTraffic]:
    """``device_traffic`` with the ports read fresh (``show interface`` alone,
    which has each port's mode and rates). Empty when the switch refuses it:
    the figures are extra, never a reason to lose the page."""
    try:
        (interfaces,) = client.show("show interface")
    except NxapiCommandError:
        return {}
    return device_traffic(parse_ports(interfaces, {}, {}), neighbors)


def busiest_devices(
    traffic: dict[str, DeviceTraffic], limit: int = BUSIEST_DEVICES
) -> list[DeviceTraffic]:
    """The devices with the most traffic in both directions, busiest first.

    Devices with no traffic at all are left out.
    """
    moving = [item for item in traffic.values() if item.total_bits > 0]
    moving.sort(key=lambda item: (-item.total_bits, item.mac))
    return moving[:limit]


def vlan_traffic(ports: Sequence[Port]) -> dict[int, VlanTraffic]:
    """By VLAN number: the access ports that are up, added up.

    The VLAN is the one ``show interface status`` names for the port; a port
    without one (trunks, routed ports) is left out.
    """
    sums: dict[int, list[int]] = {}
    for port in ports:
        if not port.up or port.mode != "access" or not port.vlan.isdigit():
            continue
        totals = sums.setdefault(int(port.vlan), [0, 0, 0])
        totals[0] += port.in_bits_per_second
        totals[1] += port.out_bits_per_second
        totals[2] += 1
    return {
        vlan: VlanTraffic(vlan, in_bits, out_bits, count)
        for vlan, (in_bits, out_bits, count) in sorted(sums.items())
    }
