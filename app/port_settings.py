"""Port settings: speed, MTU, FEC, flow control, storm control, layer 2 or 3, breakout.

Pure functions over parsed JSON bodies, like app/ports.py and app/vlans.py,
tested against output recorded from a real switch. NXray's switch account
may not read the running configuration, so the settings come from show
commands instead:

- ``show interface`` (already read for every port page): MTU, duplex, FEC.
- ``show interface status``: the configured speed while the port is down.
  While it is up, the switch reports the speed it runs at, which may come
  from "auto"; the form starts from that, so leaving it alone sends nothing.
- ``show interface <port> capabilities``: the speeds the port can run at,
  whether it can be routed, and whether it can be split (breakout).
- ``show interface <port> flowcontrol``: flow control as set.
- ``show interface <port> counters storm-control``: the storm-control levels
  (100.00 means no limit) and the action.
- ``show ip interface vrf all``: the port's IPv4 address when it is routed,
  and its extra (secondary) IPv4 addresses.
- ``show ipv6 interface vrf all``: its IPv6 addresses. Both kinds of extra
  address are added and removed on the Routing page (app/routing.py); this
  page only takes them off before a routed port goes back to switched.

The commands themselves are built by ``NxapiClient.configure_port_settings``,
``breakout_port`` and ``join_port`` from checked values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.nxapi import (
    BREAKOUT_MAPS,
    FEC_MODES,
    MTU_MAX,
    MTU_MIN,
    ON_OFF,
    STORM_ACTIONS,
    STORM_TYPES,
    NxapiClient,
    NxapiCommandError,
    validate_ip_interface,
    validate_port_name,
    validate_storm_level,
)
from app.ports import Port
from app.routing import parse_ipv4, parse_ipv6
from app.switch import rows
from app.vlans import PortVlans

# A port carrying VLANs (switched) may only use the standard MTU or the
# switch's jumbo MTU (``system jumbomtu``, 9216 on cisco-25gb); a routed port
# takes any MTU in the range.
STANDARD_MTU = 1500
JUMBO_MTU = 9216
SWITCHED_MTUS = (STANDARD_MTU, JUMBO_MTU)

# What the switch's own default storm-control level is: no limit.
NO_STORM_LIMIT = "100.00"

LAYERS = ("switched", "routed")

FEC_LABELS = {
    "auto": "Auto (picked from the transceiver and speed)",
    "off": "Off",
    "fc-fec": "FC-FEC (Firecode, 25G)",
    "rs-fec": "RS-FEC (Reed-Solomon)",
    "rs-ieee": "RS-IEEE",
    "rs-cons16": "RS-CONS16 (consortium, 100G)",
}

BREAKOUT_LABELS = {"10g-4x": "4 x 10G", "25g-4x": "4 x 25G"}

_SPEED_TEXT = re.compile(r"^([0-9]+)(G?)$", re.IGNORECASE)


def speed_mbps(text: str) -> str:
    """The switch's speed words as the ``speed`` command takes them: "10G" -> "10000".

    "auto" stays "auto"; anything not understood gives "".
    """
    cleaned = text.strip()
    if cleaned.lower() in ("auto", "auto-speed"):
        return "auto"
    match = _SPEED_TEXT.match(cleaned)
    if not match:
        return ""
    number = int(match.group(1))
    return str(number * 1000 if match.group(2) else number)


def speed_label(mbps: str) -> str:
    """ "10000" -> "10 Gb/s", "100" -> "100 Mb/s", "auto" -> "Auto"."""
    if mbps == "auto":
        return "Auto"
    if not mbps.isdigit():
        return mbps or "unknown"
    number = int(mbps)
    if number >= 1000 and number % 1000 == 0:
        return f"{number // 1000} Gb/s"
    return f"{number} Mb/s"


@dataclass(frozen=True)
class PortSettings:
    """One port's settings, as the switch reports them."""

    name: str
    speeds: tuple[str, ...]  # what the port can run at, in Mb/s
    speed: str  # "auto" or Mb/s; see the module notes for a port that is up
    duplex: str
    mtu: int
    fec: str
    fec_oper: str
    flow_receive: str
    flow_send: str
    storm: dict[str, str] = field(default_factory=dict)  # type -> level, "100.00" = none
    storm_action: str = "none"
    routed: bool = False
    routed_capable: bool = True
    ip_address: str = ""  # "192.0.2.1/24" on a routed port with an address
    vrf: str = ""
    ip_secondaries: tuple[str, ...] = ()  # extra IPv4 addresses
    ipv6_addresses: tuple[str, ...] = ()
    breakout_capable: bool = False

    @property
    def layer(self) -> str:
        return "routed" if self.routed else "switched"

    @property
    def is_breakout_port(self) -> bool:
        """True for one of the four ports a split made (Ethernet1/50/2)."""
        return self.name.count("/") == 2

    @property
    def parent(self) -> str:
        """The port that was split: Ethernet1/50/2 -> Ethernet1/50."""
        return self.name.rsplit("/", 1)[0] if self.is_breakout_port else self.name

    def storm_text(self, kind: str) -> str:
        """A storm-control level for the page: "none" when there is no limit."""
        level = self.storm.get(kind, NO_STORM_LIMIT)
        return "none" if level == NO_STORM_LIMIT else f"{level}%"

    def storm_field(self, kind: str) -> str:
        """What the form's level box starts with: empty for no limit."""
        level = self.storm.get(kind, NO_STORM_LIMIT)
        return "" if level == NO_STORM_LIMIT else level


def settings_commands(name: str) -> tuple[str, ...]:
    """The per-port show commands, beside the ones every port page reads."""
    validate_port_name(name)
    return (
        f"show interface {name} capabilities",
        f"show interface {name} flowcontrol",
        f"show interface {name} counters storm-control",
        "show ip interface vrf all",
        "show ipv6 interface vrf all",
    )


def _first_row(body: dict[str, Any], table: str, row: str, name: str) -> dict[str, Any]:
    for item in rows(body, table, row):
        if str(item.get("interface", "")) == name:
            return item
    return {}


def _long_name(name: str) -> str:
    """ "Eth1/3" (as ``show ip interface`` may write it) -> "Ethernet1/3"."""
    if name.startswith("Eth") and not name.startswith("Ethernet"):
        return "Ethernet" + name[3:]
    return name


def parse_ip_addresses(body: dict[str, Any]) -> dict[str, tuple[str, str]]:
    """Port name -> ("192.0.2.1/24", VRF) from ``show ip interface vrf all``."""
    found: dict[str, tuple[str, str]] = {}
    for row in rows(body, "TABLE_intf", "ROW_intf"):
        name = _long_name(str(row.get("intf-name", "")))
        prefix = str(row.get("prefix", "")).strip()
        masklen = str(row.get("masklen", "")).strip()
        if prefix and masklen:
            found[name] = (f"{prefix}/{masklen}", str(row.get("vrf-name-out", "")).strip())
    return found


def _storm_action(text: str) -> str:
    lowered = text.lower()
    for action in STORM_ACTIONS:
        if action in lowered:
            return action
    return "none"


def _level(value: Any) -> str:
    try:
        return validate_storm_level(str(value))
    except ValueError:
        return NO_STORM_LIMIT


def parse_port_settings(
    port: Port,
    vlans: PortVlans | None,
    capabilities_body: dict[str, Any],
    flowcontrol_body: dict[str, Any],
    storm_body: dict[str, Any],
    ip_body: dict[str, Any],
    ipv6_body: dict[str, Any] | None = None,
) -> PortSettings:
    """One port's settings from the bodies of ``settings_commands`` plus its Port."""
    name = port.name
    caps = _first_row(capabilities_body, "TABLE_interface", "ROW_interface", name)
    flow = _first_row(flowcontrol_body, "TABLE_interface", "ROW_interface", name)
    storm = _first_row(storm_body, "TABLE_interface", "ROW_interface", name)
    speeds = tuple(
        speed for speed in (s.strip() for s in str(caps.get("speed", "")).split(",")) if speed
    )
    address, vrf = parse_ip_addresses(ip_body).get(name, ("", ""))
    _, ipv4, _ = parse_ipv4(ip_body).get(name, ("", [], {}))
    _, ipv6, _ = parse_ipv6(ipv6_body or {}).get(name, ("", [], ""))
    try:
        mtu = int(port.mtu)
    except ValueError:
        mtu = STANDARD_MTU
    return PortSettings(
        name=name,
        speeds=speeds,
        speed=speed_mbps(port.status_speed) or "auto",
        duplex=str(caps.get("duplex") or port.duplex or "").strip(),
        mtu=mtu,
        fec=port.fec,
        fec_oper=port.fec_oper,
        flow_receive=str(flow.get("recv_admin", "off")).strip().lower(),
        flow_send=str(flow.get("send_admin", "off")).strip().lower(),
        storm={
            "broadcast": _level(storm.get("eth_bcast_supp", NO_STORM_LIMIT)),
            "multicast": _level(storm.get("eth_mcast_supp", NO_STORM_LIMIT)),
            "unicast": _level(storm.get("eth_ucast_supp", NO_STORM_LIMIT)),
        },
        storm_action=_storm_action(str(storm.get("supp_action", ""))),
        routed=vlans is not None and not vlans.switchport,
        routed_capable="routed" in str(caps.get("port_mode", "Routed")).lower(),
        ip_address=address,
        vrf=vrf,
        ip_secondaries=tuple(a.text for a in ipv4 if a.secondary),
        ipv6_addresses=tuple(a.text for a in ipv6),
        breakout_capable=str(caps.get("bkout_capable", "")).strip().lower() == "yes",
    )


def load_port_settings(client: NxapiClient, port: Port, vlans: PortVlans | None) -> PortSettings:
    """One port's settings, from one NX-API request."""
    caps, flow, storm, ips, ips6 = client.show(*settings_commands(port.name))
    return parse_port_settings(port, vlans, caps, flow, storm, ips, ips6)


def try_load_port_settings(
    client: NxapiClient, port: Port, vlans: PortVlans | None
) -> PortSettings | None:
    """Like load_port_settings, but None when the switch refuses one of the commands."""
    try:
        return load_port_settings(client, port, vlans)
    except NxapiCommandError:
        return None


@dataclass(frozen=True)
class SettingsChange:
    """What the settings form asks for, checked. Only the changed values are set."""

    layer: str | None = None
    # (address, secondary) pairs taken off before ``remove_ip``: the extra IPv4
    # and the IPv6 addresses of a routed port going back to switched.
    remove_extra: tuple[tuple[str, bool], ...] = ()
    remove_ip: str | None = None
    ip_address: str | None = None
    speed: str | None = None
    mtu: int | None = None
    fec: str | None = None
    flow_receive: str | None = None
    flow_send: str | None = None
    storm_levels: dict[str, str] = field(default_factory=dict)
    storm_action: str | None = None

    @property
    def empty(self) -> bool:
        return (
            self.layer is None
            and not self.remove_extra
            and self.remove_ip is None
            and self.ip_address is None
            and self.speed is None
            and self.mtu is None
            and self.fec is None
            and self.flow_receive is None
            and self.flow_send is None
            and not self.storm_levels
            and self.storm_action is None
        )


def plan_port_settings(current: PortSettings, form: dict[str, str]) -> SettingsChange:
    """Check the settings form against the port and keep only what changes.

    ``form`` holds the form's fields: layer, ip_address, speed, mtu, fec,
    flow_receive, flow_send, storm_broadcast, storm_multicast,
    storm_unicast (empty = no limit) and storm_action. Raises ValueError
    with the reason.
    """
    layer = form.get("layer", current.layer).strip() or current.layer
    if layer not in LAYERS:
        raise ValueError("pick switched (layer 2) or routed (layer 3)")
    if layer == "routed" and not current.routed_capable:
        raise ValueError(f"{current.name} cannot be a routed port")
    new_layer = layer if layer != current.layer else None

    # The IPv4 address only counts on a routed port.
    remove_ip = ip_address = None
    remove_extra: tuple[tuple[str, bool], ...] = ()
    if layer == "routed":
        typed = form.get("ip_address", "").strip()
        wanted = validate_ip_interface(typed) if typed else ""
        if wanted != current.ip_address:
            if current.ip_address and current.ip_secondaries:
                raise ValueError(
                    f"{current.name} has extra IPv4 addresses; remove them on the Routing page "
                    "before changing its main one"
                )
            remove_ip = current.ip_address or None
            ip_address = wanted or None
    elif new_layer:
        remove_ip = current.ip_address or None
        remove_extra = (
            *((a, True) for a in current.ip_secondaries),
            *((a, False) for a in current.ipv6_addresses),
        )

    speed = form.get("speed", current.speed).strip() or current.speed
    if speed != "auto" and speed not in current.speeds:
        raise ValueError(
            f"{current.name} runs at "
            + ", ".join(speed_label(s) for s in current.speeds)
            + " or auto"
        )

    mtu_text = form.get("mtu", "").strip() or str(current.mtu)
    if not mtu_text.isascii() or not mtu_text.isdigit():
        raise ValueError(f"the MTU is a number from {MTU_MIN} to {MTU_MAX}")
    mtu = int(mtu_text)
    if layer == "switched" and mtu not in SWITCHED_MTUS:
        raise ValueError(
            f"a switched port's MTU is {STANDARD_MTU} (standard) or {JUMBO_MTU} (jumbo frames)"
        )
    if not MTU_MIN <= mtu <= MTU_MAX:
        raise ValueError(f"the MTU is a number from {MTU_MIN} to {MTU_MAX}")

    fec = form.get("fec", current.fec).strip() or current.fec
    if fec not in FEC_MODES:
        raise ValueError("pick a FEC mode from the list")

    flows: dict[str, str] = {}
    for key in ("flow_receive", "flow_send"):
        default = str(getattr(current, key))
        value = form.get(key, default).strip() or default
        if value not in ON_OFF:
            raise ValueError("flow control is on or off")
        flows[key] = value

    # Storm control only applies to a switched port.
    storm_levels: dict[str, str] = {}
    storm_action = None
    if layer == "switched":
        for kind in STORM_TYPES:
            typed = form.get(f"storm_{kind}", current.storm_field(kind)).strip().rstrip("%")
            level = validate_storm_level(typed) if typed else NO_STORM_LIMIT
            if level != current.storm.get(kind, NO_STORM_LIMIT):
                storm_levels[kind] = level
        action = form.get("storm_action", current.storm_action).strip() or current.storm_action
        if action not in ("none", *STORM_ACTIONS):
            raise ValueError("storm-control action is none, shutdown or trap")
        if action != current.storm_action:
            storm_action = action

    return SettingsChange(
        layer=new_layer,
        remove_extra=remove_extra,
        remove_ip=remove_ip,
        ip_address=ip_address,
        speed=speed if speed != current.speed else None,
        mtu=mtu if mtu != current.mtu else None,
        fec=fec if fec != current.fec else None,
        flow_receive=flows["flow_receive"]
        if flows["flow_receive"] != current.flow_receive
        else None,
        flow_send=flows["flow_send"] if flows["flow_send"] != current.flow_send else None,
        storm_levels=storm_levels,
        storm_action=storm_action,
    )


def _storm_words(level: str) -> str:
    return "no limit" if level == NO_STORM_LIMIT else f"{level}%"


def describe_port_settings(
    current: PortSettings, change: SettingsChange, *, up: bool
) -> tuple[list[str], list[str]]:
    """(what the change does, one line each; warnings for the confirm page)."""
    lines: list[str] = []
    warnings: list[str] = []
    if change.layer == "routed":
        lines.append("Layer: switched (layer 2) → routed (layer 3).")
        warnings.append(
            "A routed port carries no VLANs: its VLAN settings are removed and the device "
            "on it loses its connection to every VLAN at once."
        )
    elif change.layer == "switched":
        lines.append("Layer: routed (layer 3) → switched (layer 2).")
        warnings.append(
            "The port starts carrying VLANs with the switch's defaults (access, VLAN 1), "
            "and the device on it loses its routed connection at once."
        )
    if change.remove_extra:
        removed = ", ".join(address for address, _ in change.remove_extra)
        lines.append(f"Its other addresses are taken off: {removed}.")
    if change.remove_ip and not change.ip_address:
        lines.append(f"IPv4 address: {change.remove_ip} → none.")
    elif change.ip_address:
        lines.append(f"IPv4 address: {current.ip_address or 'none'} → {change.ip_address}.")
    if change.speed is not None:
        lines.append(f"Speed: {speed_label(current.speed)} → {speed_label(change.speed)}.")
    if change.mtu is not None:
        lines.append(f"MTU: {current.mtu} → {change.mtu}.")
    if change.fec is not None:
        lines.append(f"FEC: {current.fec or 'unknown'} → {change.fec}.")
    if change.flow_receive is not None:
        lines.append(f"Flow control, receive: {current.flow_receive} → {change.flow_receive}.")
    if change.flow_send is not None:
        lines.append(f"Flow control, send: {current.flow_send} → {change.flow_send}.")
    for kind, level in change.storm_levels.items():
        lines.append(
            f"Storm control, {kind}: {_storm_words(current.storm.get(kind, NO_STORM_LIMIT))}"
            f" → {_storm_words(level)}."
        )
    if change.storm_action is not None:
        lines.append(f"Storm-control action: {current.storm_action} → {change.storm_action}.")
    link_settings = change.speed is not None or change.fec is not None or change.layer
    if up and link_settings:
        warnings.append(
            "The link goes down while the port changes, so the device on it loses its "
            "connection for a moment, and stays cut off if it cannot use the new settings."
        )
    if change.mtu is not None and change.mtu != JUMBO_MTU and current.mtu > change.mtu:
        warnings.append(
            f"Frames larger than {change.mtu} bytes are dropped on this port from now on."
        )
    if change.storm_action == "shutdown":
        warnings.append(
            "Storm-control action shutdown turns the port off when traffic goes over a "
            "level; it stays off until someone turns it on again."
        )
    return lines, warnings


@dataclass(frozen=True)
class BreakoutPlan:
    """A split of one 100G port into four, or the four joined back into one."""

    action: str  # "split" or "join"
    port: str  # the port that is split (Ethernet1/50)
    mapping: str
    lines: list[str]
    warnings: list[str]


def plan_breakout(settings: PortSettings, action: str, mapping: str) -> BreakoutPlan:
    """Check a split or join against the port. Raises ValueError with the reason."""
    if mapping not in BREAKOUT_MAPS:
        raise ValueError("pick 4 x 10G or 4 x 25G")
    label = BREAKOUT_LABELS[mapping]
    parent = settings.parent
    new_ports = f"{parent}/1 to {parent}/4"
    if action == "split":
        if settings.is_breakout_port or not settings.breakout_capable:
            raise ValueError(f"{settings.name} cannot be split")
        return BreakoutPlan(
            action,
            parent,
            mapping,
            [f"Split {parent} into four ports ({label}): {new_ports}."],
            [
                f"{parent} stops existing: its settings (description, VLANs, speed and the "
                f"rest) are removed, and {new_ports} start with the switch's defaults. "
                "Whatever is plugged in loses its connection.",
                "NXray's role on the switch names every port it may change one by one, so "
                "an NXray admin then presses Update the port list on the Switch page before "
                "NXray can change the new ports.",
            ],
        )
    if action == "join":
        if not settings.is_breakout_port:
            raise ValueError(f"{settings.name} is not one of four split ports")
        return BreakoutPlan(
            action,
            parent,
            mapping,
            [f"Join {new_ports} back into one port, {parent}."],
            [
                f"{new_ports} stop existing and their settings are removed; {parent} starts "
                "with the switch's defaults. Whatever is plugged into them loses its "
                "connection.",
                "An NXray admin then presses Update the port list on the Switch page before "
                f"NXray can change {parent}.",
            ],
        )
    raise ValueError("pick split or join")


def guess_breakout_map(sibling_speeds: list[str]) -> str | None:
    """The split the four ports were made with, from their speed column, or None."""
    found = {speed_mbps(speed) for speed in sibling_speeds} - {"", "auto"}
    if found == {"25000"}:
        return "25g-4x"
    if found == {"10000"}:
        return "10g-4x"
    return None
