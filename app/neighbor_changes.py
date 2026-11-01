"""Neighbor changes: CDP and LLDP per port, and the MAC address table.

Reads what a port does with CDP and LLDP now, and turns a submitted form
into a checked change plus the plain-words lines and warnings its confirm
page shows. The commands themselves are built by ``NxapiClient``
(``set_port_discovery``, ``set_mac_aging``, ``add_static_mac``,
``remove_static_mac``, ``clear_learned_macs``) from checked values.

What a port does with CDP comes from ``show cdp interface <port>``
(``cdp_intf_enabled``, recorded on cisco-25gb). LLDP's ``show lldp interface
<port>`` exists only while the lldp feature is on, which it has never been on
the switch NXray was built against: its ``tx_enabled`` and ``rx_enabled``
fields are named in Cisco's guides, so they are looked for wherever they sit
in the answer.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from app.neighbors import MacEntry, NeighborView, long_port_name
from app.nxapi import (
    NxapiClient,
    NxapiCommandError,
    validate_device_mac,
    validate_mac_aging,
    validate_port_name,
    validate_vlan_id,
)
from app.oui import format_mac, normalize_mac
from app.switch import rows

# What the "where" box of a static entry takes for "drop its traffic".
DROP = "drop"

# How learned addresses can be cleared: the forms the switch's command takes.
CLEAR_SCOPES = ("all", "port", "vlan", "address")

RELEARN_WARNING = (
    "Devices that are still connected are learned again as soon as they send "
    "something. Until then the switch sends traffic for them out of every port in "
    "their VLAN, as it does for any address it does not know."
)


@dataclass(frozen=True)
class PortDiscovery:
    """Whether a port speaks CDP and LLDP.

    The LLDP values are None while LLDP is off on the switch: then they can
    be neither read nor set.
    """

    cdp: bool
    lldp_transmit: bool | None = None
    lldp_receive: bool | None = None

    @property
    def lldp_known(self) -> bool:
        return self.lldp_transmit is not None and self.lldp_receive is not None


def _on(value: Any) -> bool | None:
    """The switch's ways of saying on or off: "enabled", "TRUE", "yes"; None if neither."""
    text = str(value).strip().lower() if value is not None else ""
    if text in ("enabled", "true", "yes", "on"):
        return True
    if text in ("disabled", "false", "no", "off"):
        return False
    return None


def parse_cdp_interface(body: dict[str, Any]) -> bool | None:
    """Whether CDP is on for the port in ``show cdp interface <port>``; None if not said."""
    for row in rows(body, "TABLE_cdp_all", "ROW_cdp_all"):
        return _on(row.get("cdp_intf_enabled"))
    return None


def _find(body: Any, key: str) -> Any:
    """The first value stored under ``key`` anywhere in a nested answer."""
    if isinstance(body, dict):
        if key in body:
            return body[key]
        values = list(body.values())
    elif isinstance(body, list):
        values = body
    else:
        return None
    for value in values:
        found = _find(value, key)
        if found is not None:
            return found
    return None


def parse_lldp_interface(body: dict[str, Any]) -> tuple[bool | None, bool | None]:
    """(sending, listening) for the port in ``show lldp interface <port>``.

    Cisco's guides print these as ``tx_enabled: TRUE`` and ``rx_enabled:
    TRUE``; the shape around them has not been seen on a real switch.
    """
    return _on(_find(body, "tx_enabled")), _on(_find(body, "rx_enabled"))


def load_port_discovery(client: NxapiClient, port: str, lldp_on: bool) -> PortDiscovery | None:
    """What a port does with CDP and LLDP, in one request; None when the switch
    refuses a command or does not say, so the port's page keeps the rest.

    ``port`` must be a port the switch reported (a show command naming a
    missing port fails the whole request).
    """
    commands = [f"show cdp interface {validate_port_name(port)}"]
    if lldp_on:
        commands.append(f"show lldp interface {port}")
    try:
        bodies = client.show(*commands)
    except NxapiCommandError:
        return None
    cdp = parse_cdp_interface(bodies[0])
    if cdp is None:
        return None
    if not lldp_on:
        return PortDiscovery(cdp=cdp)
    transmit, receive = parse_lldp_interface(bodies[1])
    return PortDiscovery(cdp=cdp, lldp_transmit=transmit, lldp_receive=receive)


@dataclass(frozen=True)
class DiscoveryChange:
    """What to send for a port: None leaves that setting alone."""

    cdp: bool | None = None
    lldp_transmit: bool | None = None
    lldp_receive: bool | None = None

    @property
    def empty(self) -> bool:
        return self.cdp is None and self.lldp_transmit is None and self.lldp_receive is None


def plan_port_discovery(
    current: PortDiscovery, *, cdp: bool, lldp_transmit: bool, lldp_receive: bool, lldp_shown: bool
) -> DiscoveryChange:
    """The settings that differ from what the port does now.

    The form is a page of tick boxes, so an unticked box means off. The LLDP
    boxes count only when the page showed them (``lldp_shown``) and LLDP can
    be read now; otherwise LLDP is left alone.
    """
    use_lldp = lldp_shown and current.lldp_known
    return DiscoveryChange(
        cdp=cdp if cdp != current.cdp else None,
        lldp_transmit=lldp_transmit
        if use_lldp and lldp_transmit != current.lldp_transmit
        else None,
        lldp_receive=lldp_receive if use_lldp and lldp_receive != current.lldp_receive else None,
    )


def describe_port_discovery(port: str, change: DiscoveryChange) -> tuple[list[str], list[str]]:
    """(what the change does, warnings), for the confirm page and the done message."""
    lines: list[str] = []
    warnings: list[str] = []
    if change.cdp is not None:
        lines.append(f"Turn CDP {'on' if change.cdp else 'off'} on {port}.")
        if not change.cdp:
            warnings.append(
                "With CDP off on this port, a Cisco device on it no longer hears this switch, "
                "and NXray stops showing it as a CDP neighbor once its hold time runs out."
            )
    if change.lldp_transmit is not None:
        lines.append(f"{'Start' if change.lldp_transmit else 'Stop'} sending LLDP on {port}.")
        if not change.lldp_transmit:
            warnings.append("The device on this port no longer hears this switch over LLDP.")
    if change.lldp_receive is not None:
        lines.append(f"{'Start' if change.lldp_receive else 'Stop'} listening for LLDP on {port}.")
        if not change.lldp_receive:
            warnings.append(
                "The switch ignores what the device on this port says over LLDP, so NXray "
                "stops showing it as an LLDP neighbor once its hold time runs out."
            )
    return lines, warnings


# ---- the MAC address table ---------------------------------------------------


def aging_words(seconds: int) -> str:
    """``1800`` -> "1800 seconds (30 minutes)"; ``0`` -> "never"."""
    if seconds == 0:
        return "never (kept until the switch restarts)"
    if seconds % 60 == 0:
        minutes = seconds // 60
        return f"{seconds} seconds ({minutes} minute{'' if minutes == 1 else 's'})"
    return f"{seconds} seconds"


def plan_mac_aging(view: NeighborView, text: str) -> tuple[int, list[str], list[str]]:
    """(seconds, lines, warnings) for a new aging time; ValueError when not a change."""
    seconds = validate_mac_aging(text)
    if view.aging_seconds is not None and seconds == view.aging_seconds:
        raise ValueError("the switch already forgets addresses after that time")
    before = aging_words(view.aging_seconds) if view.aging_seconds is not None else "unknown"
    lines = [
        f"Forget a learned address after {aging_words(seconds)} without traffic (now {before}).",
        "This is for the whole switch, every VLAN and port.",
    ]
    warnings = []
    if seconds == 0:
        warnings.append(
            "With aging off the table only grows: an address stays filed under the port it "
            "was last seen on, even after the device moves, until it is cleared by hand."
        )
    return seconds, lines, warnings


def static_entries(view: NeighborView) -> list[MacEntry]:
    """The static entries someone added (not the switch's own address)."""
    return [m for m in view.macs if m.kind.lower() == "static" and not m.switch_own]


def static_target(entry: MacEntry) -> str | None:
    """Where a static entry sends its traffic as NXray names it: a front port or
    ``DROP``; None for one NXray did not make and does not remove (a port-channel)."""
    try:
        return validate_port_name(entry.port)
    except ValueError:
        return DROP if "drop" in entry.port.lower() else None


@dataclass(frozen=True)
class StaticMac:
    mac: str  # the switch's form, 0200.0000.0001
    vlan: int
    port: str | None  # None: drop the address's traffic

    @property
    def where(self) -> str:
        return f"on {self.port}" if self.port else "dropped"


def _find_static(view: NeighborView, mac: str, vlan: int) -> MacEntry | None:
    wanted = normalize_mac(mac)
    return next(
        (m for m in static_entries(view) if normalize_mac(m.mac) == wanted and m.vlan == str(vlan)),
        None,
    )


def plan_static_mac(
    view: NeighborView, *, mac: str, vlan: str, where: str, vlan_ids: set[int], ports: list[str]
) -> tuple[StaticMac, list[str], list[str]]:
    """A new static entry, checked against the switch's VLANs and front ports.

    ``where`` is a port (``Ethernet1/5``, ``Eth1/5`` or ``1/5``) or ``drop``.
    Raises ValueError with the reason it cannot be added.
    """
    address = validate_device_mac(mac)
    number = validate_vlan_id(vlan)
    if number not in vlan_ids:
        raise ValueError(f"VLAN {number} does not exist on the switch; create it first")
    place = where.strip()
    port: str | None
    if place.lower() == DROP:
        port = None
    else:
        name = long_port_name(place)
        if not name.startswith("Ethernet"):
            name = "Ethernet" + name
        if name not in ports:
            raise ValueError(f"{place!r} is not one of the switch's front ports, or drop")
        port = name
    if _find_static(view, address, number) is not None:
        raise ValueError(
            f"{format_mac(address)} already has a static entry in VLAN {number}; remove it first"
        )
    entry = StaticMac(address, number, port)
    shown = format_mac(address)
    if port is None:
        lines = [f"Drop all traffic to and from {shown} in VLAN {number}."]
    else:
        lines = [f"Always send traffic for {shown} in VLAN {number} to {port}."]
    lines.append("The switch keeps this entry until it is removed; it never ages out.")
    warnings = []
    learned = [
        m
        for m in view.macs
        if normalize_mac(m.mac) == normalize_mac(address) and m.vlan == str(number)
    ]
    for m in learned:
        if port is None:
            warnings.append(
                f"{shown} is in use now (learned on {m.port}): it loses its connection."
            )
        elif m.port != port:
            warnings.append(
                f"{shown} was learned on {m.port}. Once the entry is in, traffic for it goes to "
                f"{port} only, so the device loses its connection if it is really on {m.port}."
            )
    return entry, lines, warnings


def plan_static_removal(
    view: NeighborView, *, mac: str, vlan: str
) -> tuple[StaticMac, list[str], list[str]]:
    """Removing a static entry the table shows; ValueError when there is none."""
    address = validate_device_mac(mac)
    number = validate_vlan_id(vlan)
    entry = _find_static(view, address, number)
    if entry is None:
        raise ValueError(
            f"the switch has no static entry for {format_mac(address)} in VLAN {number}"
        )
    target = static_target(entry)
    if target is None:
        raise ValueError(
            f"NXray does not remove the static entry on {entry.port}; remove it on the switch"
        )
    port = None if target == DROP else target
    change = StaticMac(address, number, port)
    line = f"Remove the static entry for {format_mac(address)} in VLAN {number} ({change.where})."
    return change, [line, "Afterwards the switch learns the address from traffic again."], []


@dataclass(frozen=True)
class ClearRequest:
    """What ``NxapiClient.clear_learned_macs`` gets: all None clears everything."""

    port: str | None = None
    vlan: int | None = None
    mac: str | None = None
    done: str = ""  # what the page says once the switch has cleared them


def plan_clear(
    view: NeighborView,
    *,
    scope: str,
    ports: list[str],
    port: str = "",
    vlan: str = "",
    mac: str = "",
) -> tuple[ClearRequest, list[str], list[str]]:
    """Clearing learned addresses: everything, one port, one VLAN or one address.

    ``ports`` are the switch's front ports. Static entries are never cleared.
    Raises ValueError for a scope or value the switch would not take.
    """
    learned = [m for m in view.macs if m.kind.lower() == "dynamic"]
    warnings = [RELEARN_WARNING]
    if scope == "all":
        request = ClearRequest()
        chosen = learned
        what = "every learned address"
    elif scope == "port":
        name = long_port_name(port.strip())
        if name not in ports:
            raise ValueError(f"{port.strip()!r} is not one of the switch's front ports")
        request = ClearRequest(port=name)
        chosen = [m for m in learned if m.port == name]
        what = f"the addresses learned on {name}"
        channel = view.channel_of(name)
        if channel is not None:
            warnings.insert(
                0,
                f"{name} is part of {channel.name}, and the switch files the addresses of its "
                f"ports under {channel.name}, so this may clear nothing.",
            )
    elif scope == "vlan":
        number = validate_vlan_id(vlan)
        request = ClearRequest(vlan=number)
        chosen = [m for m in learned if m.vlan == str(number)]
        what = f"the addresses learned in VLAN {number}"
    elif scope == "address":
        address = validate_device_mac(mac)
        number = validate_vlan_id(vlan) if vlan.strip() else None
        request = ClearRequest(mac=address, vlan=number)
        chosen = [
            m
            for m in learned
            if normalize_mac(m.mac) == normalize_mac(address)
            and (number is None or m.vlan == str(number))
        ]
        what = f"{format_mac(address)}" + (f" in VLAN {number}" if number is not None else "")
    else:
        raise ValueError("choose what to clear")
    count = len(chosen)
    amount = f"{count} learned address" + ("" if count == 1 else "es")
    lines = [f"Forget {what} ({amount} in the table now). Static entries stay."]
    done = f"The switch forgot {what} ({amount} were in the table)."
    return replace(request, done=done), lines, warnings
