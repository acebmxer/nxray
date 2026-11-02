"""Resetting a port or a port-channel to how it came out of the box.

One command does it all: ``default interface <name>``, which NXray sends
with ``NxapiClient.reset_ports`` (front-panel ports) and
``NxapiClient.reset_port_channel`` (a port-channel). It clears everything
NXray can put on a front-panel port (its description, VLANs, mode, speed,
MTU, FEC, flow control, storm control, layer and any IP address) and leaves
it a plain, unconfigured access port in VLAN 1, turned on. On a port-channel
it clears only the port-channel's own settings (its description and LACP
minimum links); its members keep their channel-group membership, which is
set on each member port, not on the port-channel.

The role rule for it (``conf t ; default interface *``) is added in
app/port_changes.py, ROLE_VERSION 16.

This module only describes what a reset removes, for the confirm page; the
switch is never asked here (see app/routes/ports.py and
app/routes/port_channels.py).
"""

from __future__ import annotations

from app.port_channels import Channel
from app.port_settings import STANDARD_MTU, PortSettings
from app.ports import Port
from app.vlans import PortVlans, VlanView

# A plain access port keeps this VLAN; nothing is lost in naming it.
DEFAULT_ACCESS_VLAN = 1


def _vlans_removed(vlans: PortVlans | None) -> list[str]:
    if vlans is None or not vlans.switchport:
        return []
    if vlans.mode == "trunk":
        return [f"its trunk (native VLAN {vlans.native_vlan}, carrying {vlans.allowed_text})"]
    if vlans.access_vlan != DEFAULT_ACCESS_VLAN:
        return [f"its access VLAN, {vlans.access_vlan}"]
    return []


def _settings_removed(settings: PortSettings | None) -> list[str]:
    if settings is None:
        return []
    removed = []
    if settings.routed:
        address = f" and IPv4 address {settings.ip_address}" if settings.ip_address else ""
        removed.append(f"its routed (layer 3) setting{address}")
    if settings.speed != "auto":
        removed.append(f"its speed, set to {settings.speed}")
    if settings.mtu != STANDARD_MTU:
        removed.append(f"its MTU, set to {settings.mtu}")
    if settings.fec not in ("", "auto"):
        removed.append(f"its FEC, set to {settings.fec}")
    if settings.flow_receive == "on" or settings.flow_send == "on":
        removed.append(
            f"its flow control (receive {settings.flow_receive}, send {settings.flow_send})"
        )
    if not settings.routed:
        levels = [settings.storm_text(kind) for kind in ("broadcast", "multicast", "unicast")]
        if any(level != "none" for level in levels) or settings.storm_action != "none":
            removed.append(
                "its storm control (broadcast {}, multicast {}, unicast {}, action {})".format(
                    *levels, settings.storm_action
                )
            )
    return removed


def port_reset_summary(
    port: Port, settings: PortSettings | None, vlans: PortVlans | None
) -> tuple[str, list[str]]:
    """(the confirm line for resetting one port, warnings).

    The line names everything the reset removes, so it is clear what is
    being lost before pressing the button; a port already a plain,
    unconfigured access port says so instead of an empty list.
    """
    removed: list[str] = []
    if port.description:
        removed.append(f'its description, "{port.description}"')
    removed += _vlans_removed(vlans)
    removed += _settings_removed(settings)
    warnings = []
    if port.up:
        warnings.append(
            f"{port.name} is up now: whatever is plugged into it loses its connection while "
            "it resets."
        )
    if not removed:
        line = f"{port.name}: nothing to remove; it is already a plain, unconfigured access port."
    else:
        line = f"{port.name} loses " + "; ".join(removed) + "."
    return line, warnings


def plan_bulk_reset(
    ports: list[Port],
    names: list[str],
    view: VlanView | None,
    settings: dict[str, PortSettings | None],
) -> tuple[list[Port], list[str], list[str]]:
    """Plan resetting every ticked port.

    Returns (the ports in front-panel order, one confirm line per port, every
    warning once). Raises ValueError naming any ticked port the switch does
    not have.
    """
    if not names:
        raise ValueError("tick at least one port")
    known = {port.name for port in ports}
    unknown = sorted(set(names) - known)
    if unknown:
        raise ValueError(f"the switch has no port called {', '.join(unknown)}")
    wanted = set(names)
    chosen = [port for port in ports if port.name in wanted]
    lines: list[str] = []
    warnings: list[str] = []
    for port in chosen:
        vlans = view.ports.get(port.name) if view else None
        line, found = port_reset_summary(port, settings.get(port.name), vlans)
        lines.append(line)
        for warning in found:
            if warning not in warnings:
                warnings.append(warning)
    return chosen, lines, warnings


def channel_reset_summary(channel: Channel) -> tuple[str, list[str]]:
    """(the confirm line for resetting a port-channel's own settings, warnings).

    LACP minimum links is not listed: the switch reports it to no command
    NXray's account may run (see app/port_channels.py), so NXray cannot say
    whether a reset would remove it.
    """
    removed: list[str] = []
    if channel.description:
        removed.append(f'its description, "{channel.description}"')
    warnings: list[str] = []
    if channel.members:
        warnings.append(
            f"{channel.name} affects {', '.join(channel.member_names)}: each stays in the "
            "port-channel (that is set on the member port, not here), but the port-channel's "
            "own settings reset."
        )
    if channel.up:
        warnings.append(
            f"{channel.name} is up now: traffic on it may be interrupted while it resets."
        )
    if not removed:
        line = f"{channel.name}: nothing to remove; it already has none of its own settings."
    else:
        line = f"{channel.name} loses " + "; ".join(removed) + "."
    return line, warnings
