"""Neighbors and tables: what is connected to the switch, from NX-API show output.

Pure functions over parsed JSON bodies, like app/ports.py, tested against
output recorded from a real switch:

- ``show cdp neighbors detail`` and ``show lldp neighbors detail``: the
  devices next to each port that announce themselves (CDP is Cisco's own
  protocol, LLDP the standard one most servers and switches speak);
- ``show mac address-table``: every MAC address the switch has learned and
  the port it was learned on, which is how "which device is on this port" is
  answered for devices that announce nothing;
- ``show ip arp detail vrf all``: the IPv4 address behind a MAC address, for
  the networks the switch itself has an address in;
- ``show port-channel summary``: which ports are bundled, because the switch
  learns addresses on the bundle, not on its member ports;
- ``show feature`` and ``show cdp global``: whether LLDP and CDP are on. With
  the lldp feature off, every ``show lldp`` command is "% Invalid command", so
  the neighbor commands go in a second request, only for what is on.

NX-API returns some numbers as JSON numbers where ``| json`` over SSH gives
strings, so every value goes through ``str()``.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from app.nxapi import NxapiClient, NxapiCommandError
from app.oui import format_mac, is_local_mac, mac_maker, normalize_mac
from app.ports import port_sort_key
from app.switch import rows

NEIGHBOR_COMMANDS = (
    "show feature",
    "show cdp global",
    "show mac address-table",
    "show mac address-table aging-time",
    "show ip arp detail vrf all",
    "show port-channel summary",
)
CDP_NEIGHBORS = "show cdp neighbors detail"
LLDP_NEIGHBORS = "show lldp neighbors detail"

# LLDP capability letters, as the switch prints them.
_LLDP_CAPABILITIES = {
    "B": "bridge",
    "C": "DOCSIS cable device",
    "O": "other",
    "P": "repeater",
    "R": "router",
    "S": "station",
    "T": "telephone",
    "W": "WLAN access point",
}

_DURATION = re.compile(r"^P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$")


def _text(value: Any) -> str:
    """A value from NX-OS JSON as stripped text; "" for missing or null."""
    if value is None:
        return ""
    return str(value).strip()


def _advertised(value: Any) -> str:
    """LLDP's "not advertised" means the neighbor did not say; shown as nothing."""
    text = _text(value)
    return "" if text.lower() == "not advertised" else text


def long_port_name(name: str) -> str:
    """``Eth1/3`` -> ``Ethernet1/3``, ``Po43`` -> ``port-channel43``; anything else as is.

    The MAC table and LLDP write port names short. Deliberately not
    ``port_settings._long_name``, which handles only Ethernet ports: the MAC
    table names port-channels too. Do not add a third.
    """
    name = name.strip()
    if name.startswith("Eth") and not name.startswith("Ethernet"):
        return "Ethernet" + name[3:]
    if re.fullmatch(r"Po\d+", name):
        return "port-channel" + name[2:]
    return name


def readable_duration(value: Any) -> str:
    """An ISO 8601 duration such as ``PT1M41S`` -> ``1m 41s``; other text as is."""
    text = _text(value)
    match = _DURATION.match(text)
    if not match or not any(match.groups()):
        return text
    parts = [
        f"{int(number)}{unit}"
        for number, unit in zip(match.groups(), "dhms", strict=True)
        if number
    ]
    return " ".join(parts)


@dataclass(frozen=True)
class Neighbor:
    """A device next to one of the switch's ports that announced itself."""

    protocol: str  # "CDP" or "LLDP"
    local_port: str  # this switch's port: "Ethernet1/47", "mgmt0"
    name: str  # the neighbor's own name for itself
    remote_port: str  # the neighbor's port the cable goes into
    platform: str  # model (CDP) or the first line of its description (LLDP)
    address: str  # its management IPv4 address, if it gave one
    capabilities: str  # "router, switch"
    vlan: str  # the VLAN it says the link is in (CDP native VLAN, LLDP VLAN ID)
    software: str = ""  # CDP's version line, or LLDP's whole description
    hold_seconds: int | None = None  # how long the switch keeps it without hearing again


@dataclass(frozen=True)
class MacEntry:
    """One line of the MAC address table."""

    mac: str  # aa:bb:cc:dd:ee:ff
    vlan: str  # "10"; "" when the switch shows "-"
    kind: str  # "dynamic", "static", ...
    port: str  # "Ethernet1/47", "port-channel43", or the switch's own words
    secure: bool = False
    maker: str = ""
    local: bool = False  # made up by the device, so it has no maker

    @property
    def switch_own(self) -> bool:
        """The switch's own address (\"sup-eth1(R)\"): traffic for the switch itself."""
        return self.port.lower().startswith("sup-eth")

    @property
    def maker_text(self) -> str:
        if self.maker:
            return self.maker
        if self.local:
            return "Locally administered (often a VM, a container or a phone's private address)"
        return ""


@dataclass(frozen=True)
class ArpEntry:
    """An IPv4 address the switch has looked up the MAC address for."""

    ip: str
    mac: str  # aa:bb:cc:dd:ee:ff; "" while the switch is still asking
    interface: str  # the switch interface with the address in that network
    port: str  # the physical port the answer came in on
    vrf: str
    age: str  # "1m 41s"


@dataclass(frozen=True)
class PortChannel:
    name: str  # "port-channel43"
    members: tuple[str, ...]  # "Ethernet1/43", ...
    protocol: str  # "LACP" or "NONE"
    up: bool


@dataclass(frozen=True)
class PortDevices:
    """What is plugged into one port, as far as the switch can tell."""

    neighbors: list[Neighbor]
    macs: list[MacEntry]
    channel: PortChannel | None = None


@dataclass(frozen=True)
class NeighborView:
    neighbors: list[Neighbor] = field(default_factory=list)
    macs: list[MacEntry] = field(default_factory=list)
    arps: list[ArpEntry] = field(default_factory=list)
    port_channels: list[PortChannel] = field(default_factory=list)
    cdp_enabled: bool = False
    lldp_enabled: bool = False
    aging_seconds: int | None = None

    @property
    def aging_text(self) -> str:
        """How long a learned address is kept, in words; "" when not reported."""
        if self.aging_seconds is None:
            return ""
        if self.aging_seconds == 0:
            return "Learned addresses are kept until the switch restarts (aging is off)."
        if self.aging_seconds % 60 == 0:
            minutes = self.aging_seconds // 60
            amount = f"{minutes} minute" + ("" if minutes == 1 else "s")
        else:
            amount = f"{self.aging_seconds} seconds"
        return f"An address is forgotten after {amount} without traffic."

    def channel_of(self, port: str) -> PortChannel | None:
        """The port-channel a port belongs to, if any."""
        return next((pc for pc in self.port_channels if port in pc.members), None)

    def ips_of(self, mac: str) -> list[str]:
        """The IPv4 addresses the ARP table has for a MAC address."""
        wanted = normalize_mac(mac)
        return [arp.ip for arp in self.arps if arp.mac and normalize_mac(arp.mac) == wanted]

    def for_port(self, port: str) -> PortDevices:
        """The neighbors on a port and the addresses learned on it.

        A port in a port-channel learns nothing itself: the switch files the
        addresses under the port-channel, so those are given for each member.
        """
        channel = self.channel_of(port)
        homes = {port, channel.name} if channel else {port}
        return PortDevices(
            neighbors=[n for n in self.neighbors if n.local_port == port],
            macs=[m for m in self.macs if m.port in homes],
            channel=channel,
        )


def feature_enabled(body: dict[str, Any], name: str) -> bool:
    """Whether ``show feature`` lists the feature as enabled (any instance of it)."""
    for row in rows(body, "TABLE_cfcFeatureCtrlTable", "ROW_cfcFeatureCtrlTable"):
        if _text(row.get("cfcFeatureCtrlName2")).lower() == name.lower():
            if _text(row.get("cfcFeatureCtrlOpStatus2")).lower() == "enabled":
                return True
    return False


def cdp_enabled(body: dict[str, Any]) -> bool:
    """Whether CDP is on for the whole switch, from ``show cdp global``."""
    return _text(body.get("cdp_global_enabled")).lower() == "enabled"


def _hold(value: Any) -> int | None:
    try:
        return int(_text(value))
    except ValueError:
        return None


def parse_cdp_neighbors(body: dict[str, Any]) -> list[Neighbor]:
    """Neighbors from ``show cdp neighbors detail``."""
    found: list[Neighbor] = []
    for row in rows(body, "TABLE_cdp_neighbor_detail_info", "ROW_cdp_neighbor_detail_info"):
        capability = row.get("capability")
        if isinstance(capability, list):
            capabilities = ", ".join(_text(item) for item in capability if _text(item))
        else:
            capabilities = _text(capability)
        found.append(
            Neighbor(
                protocol="CDP",
                local_port=long_port_name(_text(row.get("intf_id"))),
                name=_text(row.get("sysname")) or _text(row.get("device_id")),
                remote_port=_text(row.get("port_id")),
                platform=_text(row.get("platform_id")),
                address=_text(row.get("v4mgmtaddr")) or _text(row.get("v4addr")),
                capabilities=capabilities,
                vlan=_text(row.get("nativevlan")),
                software=_text(row.get("version")),
                hold_seconds=_hold(row.get("ttl")),
            )
        )
    return found


def _lldp_capabilities(row: dict[str, Any]) -> str:
    codes = (
        _text(row.get("enabled_capability"))
        or _text(row.get("system_capability"))
        or _text(row.get("capability"))
    )
    words = [_LLDP_CAPABILITIES.get(code.strip(), code.strip()) for code in codes.split(",")]
    return ", ".join(word for word in words if word)


def parse_lldp_neighbors(body: dict[str, Any]) -> list[Neighbor]:
    """Neighbors from ``show lldp neighbors detail``.

    Field names follow Cisco's NX-API reference for NX-OS 9.3; LLDP has been
    off on the switch NXray was built against, so this has not yet been seen
    against real output.
    """
    found: list[Neighbor] = []
    for row in rows(body, "TABLE_nbor_detail", "ROW_nbor_detail"):
        description = _advertised(row.get("sys_desc"))
        found.append(
            Neighbor(
                protocol="LLDP",
                local_port=long_port_name(_text(row.get("l_port_id"))),
                name=_advertised(row.get("sys_name")) or _text(row.get("chassis_id")),
                remote_port=_advertised(row.get("port_desc")) or _text(row.get("port_id")),
                platform=description.splitlines()[0] if description else "",
                address=_advertised(row.get("mgmt_addr")),
                capabilities=_lldp_capabilities(row),
                vlan=_advertised(row.get("vlan_id")),
                software=description,
                hold_seconds=_hold(row.get("ttl")),
            )
        )
    return found


def parse_mac_table(body: dict[str, Any]) -> list[MacEntry]:
    """The MAC address table, by port and then VLAN, from ``show mac address-table``."""
    found: list[MacEntry] = []
    for row in rows(body, "TABLE_mac_address", "ROW_mac_address"):
        raw = _text(row.get("disp_mac_addr"))
        if not raw:
            continue
        vlan = _text(row.get("disp_vlan"))
        found.append(
            MacEntry(
                mac=format_mac(raw),
                vlan="" if vlan == "-" else vlan,
                kind=_text(row.get("disp_type")),
                port=long_port_name(_text(row.get("disp_port"))),
                secure=_text(row.get("disp_is_secure")).upper() == "T",
                maker=mac_maker(raw),
                local=is_local_mac(raw),
            )
        )
    found.sort(key=_mac_order)
    return found


def _mac_order(entry: MacEntry) -> tuple[Any, ...]:
    vlan = int(entry.vlan) if entry.vlan.isdigit() else 0
    return (entry.switch_own, port_sort_key(entry.port), entry.port, vlan, entry.mac)


def parse_aging_time(body: dict[str, Any]) -> int | None:
    """Seconds a learned address is kept without traffic.

    From ``show mac address-table aging-time``; 0 means kept for good.
    """
    return _hold(body.get("age"))


def parse_arp(body: dict[str, Any]) -> list[ArpEntry]:
    """The ARP table of every VRF, from ``show ip arp detail vrf all``."""
    found: list[ArpEntry] = []
    for vrf_row in rows(body, "TABLE_vrf", "ROW_vrf"):
        for row in rows(vrf_row, "TABLE_adj", "ROW_adj"):
            mac = _text(row.get("mac"))
            found.append(
                ArpEntry(
                    ip=_text(row.get("ip-addr-out")),
                    mac=format_mac(mac) if normalize_mac(mac) else "",
                    interface=long_port_name(_text(row.get("intf-out"))),
                    port=long_port_name(_text(row.get("phy-intf"))),
                    vrf=_text(row.get("adj-vrf-name")) or _text(vrf_row.get("vrf-name-out")),
                    age=readable_duration(row.get("time-stamp")),
                )
            )
    return found


def parse_port_channels(body: dict[str, Any]) -> list[PortChannel]:
    """Port-channels and their member ports, from ``show port-channel summary``."""
    found: list[PortChannel] = []
    for row in rows(body, "TABLE_channel", "ROW_channel"):
        name = _text(row.get("port-channel")) or f"port-channel{_text(row.get('group'))}"
        members = tuple(
            long_port_name(_text(member.get("port")))
            for member in rows(row, "TABLE_member", "ROW_member")
            if _text(member.get("port"))
        )
        found.append(
            PortChannel(
                name=name,
                members=members,
                protocol=_text(row.get("prtcl")),
                # "U" (up) in the status column; "D" is down.
                up="U" in _text(row.get("status")).upper(),
            )
        )
    return found


def parse_neighbor_view(
    feature_body: dict[str, Any],
    cdp_global_body: dict[str, Any],
    mac_body: dict[str, Any],
    aging_body: dict[str, Any],
    arp_body: dict[str, Any],
    channel_body: dict[str, Any],
    cdp_body: dict[str, Any] | None = None,
    lldp_body: dict[str, Any] | None = None,
) -> NeighborView:
    """Everything the Neighbors page shows.

    From the bodies of NEIGHBOR_COMMANDS, in order, and of the neighbor
    commands (None for a protocol that is off).
    """
    neighbors = parse_cdp_neighbors(cdp_body or {}) + parse_lldp_neighbors(lldp_body or {})
    neighbors.sort(key=_neighbor_order)
    return NeighborView(
        neighbors=neighbors,
        macs=parse_mac_table(mac_body),
        arps=parse_arp(arp_body),
        port_channels=parse_port_channels(channel_body),
        cdp_enabled=cdp_enabled(cdp_global_body),
        lldp_enabled=feature_enabled(feature_body, "lldp"),
        aging_seconds=parse_aging_time(aging_body),
    )


def _neighbor_order(neighbor: Neighbor) -> tuple[Any, ...]:
    return (port_sort_key(neighbor.local_port), neighbor.local_port, neighbor.protocol)


def load_neighbors(client: NxapiClient) -> NeighborView:
    """The neighbors and tables, from two requests: the tables, then the neighbor
    lists of whichever of CDP and LLDP is on (a ``show lldp`` command fails while
    LLDP is off)."""
    feature, cdp_global, macs, aging, arp, channels = client.show(*NEIGHBOR_COMMANDS)
    wanted: list[str] = []
    if cdp_enabled(cdp_global):
        wanted.append(CDP_NEIGHBORS)
    if feature_enabled(feature, "lldp"):
        wanted.append(LLDP_NEIGHBORS)
    answers = dict(zip(wanted, client.show(*wanted), strict=True)) if wanted else {}
    return parse_neighbor_view(
        feature,
        cdp_global,
        macs,
        aging,
        arp,
        channels,
        answers.get(CDP_NEIGHBORS),
        answers.get(LLDP_NEIGHBORS),
    )


def try_load_neighbors(client: NxapiClient) -> NeighborView | None:
    """Like load_neighbors, but None when the switch refuses one of the commands.

    The Ports page and a port's page show the neighbors beside what they
    already read; a refusal there must not cost them the rest of the page.
    """
    try:
        return load_neighbors(client)
    except NxapiCommandError:
        return None


def filter_macs(macs: Sequence[MacEntry], query: str) -> list[MacEntry]:
    """The entries matching a search.

    A number of up to four digits is a VLAN. A port is matched whole
    (``Ethernet1/3``, ``Eth1/3``, ``1/3``, ``port-channel43``, ``Po43``).
    Anything else is part of a MAC address in any form (``0cea``,
    ``0c:ea:14``) or part of a maker's name (``dell``).
    """
    query = query.strip()
    if not query:
        return list(macs)
    lowered = query.lower()
    if query.isdigit() and len(query) <= 4:
        return [entry for entry in macs if entry.vlan == query]
    ports = {long_port_name(query).lower(), "ethernet" + lowered}
    digits = "".join(ch for ch in lowered if ch not in ".:-")
    is_hex = len(digits) >= 2 and all(ch in "0123456789abcdef" for ch in digits)
    return [
        entry
        for entry in macs
        if entry.port.lower() in ports
        or (is_hex and digits in entry.mac.replace(":", ""))
        or lowered in entry.maker.lower()
    ]
