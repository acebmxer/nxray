"""VLANs: the switch's VLAN list, each port's VLAN settings, and planned changes.

Pure functions over parsed JSON bodies, like app/ports.py, tested against
output recorded from a real switch. ``show vlan brief`` gives the VLANs and
their names; ``show interface switchport`` gives each port's mode (access or
trunk), access VLAN, native VLAN and the VLANs a trunk carries.

The commands themselves are built by ``NxapiClient.configure_vlan``,
``delete_vlan`` and ``configure_port_vlans`` from checked values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.nxapi import (
    PORT_MODES,
    NxapiClient,
    format_vlan_list,
    parse_vlan_list,
    validate_vlan_id,
)
from app.ports import PORTS_COMMANDS, Port, parse_ports, port_sort_key
from app.switch import rows

VLAN_COMMANDS = ("show vlan brief", "show interface switchport")
# The VLANs page also reads which VLANs have a VLAN interface.
VLAN_PAGE_COMMANDS = (*VLAN_COMMANDS, "show interface brief")

# Every VLAN: what a trunk carries unless told otherwise.
ALL_VLANS = frozenset(range(1, 4095))


@dataclass(frozen=True)
class Vlan:
    id: int
    name: str
    state: str  # "active", or "suspended" / "shutdown" as the switch reports


@dataclass(frozen=True)
class PortVlans:
    """One port's VLAN settings, as ``show interface switchport`` reports them."""

    name: str
    switchport: bool  # False for a routed port, which has no VLANs
    mode: str  # "access" or "trunk" (others are shown as the switch names them)
    access_vlan: int
    native_vlan: int
    allowed: frozenset[int] = field(default_factory=lambda: ALL_VLANS)

    @property
    def allowed_text(self) -> str:
        """The trunk's VLANs as the switch writes them: "1-4094", "1,10-12"."""
        return format_vlan_list(self.allowed)

    def uses(self, vlan_id: int) -> bool:
        """True when deleting the VLAN would cut this port off from traffic it carries.

        An access port uses its access VLAN. A trunk uses its native VLAN, and
        a VLAN it was told to carry by name; a trunk still carrying every VLAN
        (the default) loses nothing it was set up for.
        """
        if not self.switchport:
            return False
        if self.mode == "access":
            return self.access_vlan == vlan_id
        if self.mode == "trunk":
            if self.native_vlan == vlan_id:
                return True
            return self.allowed != ALL_VLANS and vlan_id in self.allowed
        return False


@dataclass(frozen=True)
class VlanView:
    """The VLAN list plus every port's VLAN settings, read together."""

    vlans: list[Vlan]
    ports: dict[str, PortVlans]
    # VLANs with a VLAN interface (Vlan10); only the VLANs page reads them.
    interfaces: frozenset[int] = frozenset()

    @property
    def ids(self) -> set[int]:
        return {vlan.id for vlan in self.vlans}

    def get(self, vlan_id: int) -> Vlan | None:
        return next((vlan for vlan in self.vlans if vlan.id == vlan_id), None)

    def ports_using(self, vlan_id: int) -> list[str]:
        """The ports that use the VLAN (see ``PortVlans.uses``), in front-panel order."""
        names = [name for name, port in self.ports.items() if port.uses(vlan_id)]
        return sorted(names, key=port_sort_key)


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def parse_vlans(body: dict[str, Any]) -> list[Vlan]:
    """Every VLAN in ``show vlan brief``, lowest number first."""
    vlans = []
    for row in rows(body, "TABLE_vlanbriefxbrief", "ROW_vlanbriefxbrief"):
        vlan_id = _int(row.get("vlanshowbr-vlanid"))
        if vlan_id < 1:
            continue
        state = str(row.get("vlanshowbr-vlanstate", "")).strip()
        if str(row.get("vlanshowbr-shutstate", "")).strip() == "shutdown":
            state = "shutdown"
        vlans.append(
            Vlan(id=vlan_id, name=str(row.get("vlanshowbr-vlanname", "")).strip(), state=state)
        )
    return sorted(vlans, key=lambda vlan: vlan.id)


def _allowed(text: Any) -> frozenset[int]:
    try:
        return frozenset(parse_vlan_list(str(text)))
    except ValueError:
        return ALL_VLANS


def parse_switchports(body: dict[str, Any]) -> dict[str, PortVlans]:
    """Each Ethernet port's VLAN settings from ``show interface switchport``, by name."""
    found: dict[str, PortVlans] = {}
    for row in rows(body, "TABLE_interface", "ROW_interface"):
        name = str(row.get("interface", ""))
        if not name.startswith("Ethernet"):
            continue
        found[name] = PortVlans(
            name=name,
            switchport=str(row.get("switchport", "")).strip().lower() == "enabled",
            mode=str(row.get("oper_mode", "")).strip().lower(),
            access_vlan=_int(row.get("access_vlan"), 1),
            native_vlan=_int(row.get("native_vlan"), 1),
            allowed=_allowed(row.get("trunk_vlans", "1-4094")),
        )
    return found


def load_vlans(client: NxapiClient) -> VlanView:
    """The VLAN list and every port's VLAN settings, from one NX-API request."""
    vlans, switchports = client.show(*VLAN_COMMANDS)
    return VlanView(parse_vlans(vlans), parse_switchports(switchports))


def vlan_interface_ids(brief_body: dict[str, Any]) -> frozenset[int]:
    """The VLANs that have a VLAN interface (``Vlan10``), from ``show interface brief``."""
    found = set()
    for row in rows(brief_body, "TABLE_interface", "ROW_interface"):
        match = re.fullmatch(r"Vlan(\d+)", str(row.get("interface", "")).strip())
        if match:
            found.add(int(match.group(1)))
    return frozenset(found)


def load_vlan_page(client: NxapiClient) -> VlanView:
    """What the VLANs page shows: the VLANs, every port's VLAN settings and which
    VLANs have a VLAN interface, from one NX-API request."""
    vlans, switchports, brief = client.show(*VLAN_PAGE_COMMANDS)
    return VlanView(parse_vlans(vlans), parse_switchports(switchports), vlan_interface_ids(brief))


def load_ports_with_vlans(client: NxapiClient) -> tuple[list[Port], VlanView]:
    """Everything a port's own page shows, from one NX-API request."""
    interfaces, statuses, transceivers, vlans, switchports = client.show(
        *PORTS_COMMANDS, *VLAN_COMMANDS
    )
    return (
        parse_ports(interfaces, statuses, transceivers),
        VlanView(parse_vlans(vlans), parse_switchports(switchports)),
    )


@dataclass(frozen=True)
class PortVlanChange:
    """What the port's VLAN form asks for, checked. Only the changed values are set."""

    mode: str | None = None
    access_vlan: int | None = None
    native_vlan: int | None = None
    allowed_vlans: list[int] | None = None

    @property
    def empty(self) -> bool:
        return (
            self.mode is None
            and self.access_vlan is None
            and self.native_vlan is None
            and self.allowed_vlans is None
        )


def plan_port_vlans(
    current: PortVlans,
    view: VlanView,
    *,
    mode: str,
    access_vlan: str,
    native_vlan: str,
    allowed: str,
) -> PortVlanChange:
    """Check the port's VLAN form against the switch and keep only what changes.

    Only the settings of the chosen mode count: an access port's form leaves
    the trunk settings alone and the other way round. Access and native
    VLANs must exist (the switch would accept a missing one and leave the
    port passing no traffic). Raises ValueError with the reason.
    """
    if not current.switchport:
        raise ValueError(f"{current.name} is a routed port, which has no VLANs")
    if mode not in PORT_MODES:
        raise ValueError("pick access or trunk")
    new_mode = mode if mode != current.mode else None

    def existing(value: str, what: str) -> int:
        vlan = validate_vlan_id(value)
        if vlan not in view.ids:
            raise ValueError(
                f"VLAN {vlan} does not exist on the switch; create it on the VLANs page first "
                f"({what})"
            )
        return vlan

    if mode == "access":
        access = existing(access_vlan, "access VLAN")
        return PortVlanChange(
            mode=new_mode,
            access_vlan=access if access != current.access_vlan or new_mode else None,
        )
    native = existing(native_vlan, "native VLAN")
    wanted = frozenset(parse_vlan_list(allowed))
    return PortVlanChange(
        mode=new_mode,
        native_vlan=native if native != current.native_vlan else None,
        allowed_vlans=sorted(wanted) if wanted != current.allowed else None,
    )


def describe_port_vlans(current: PortVlans, change: PortVlanChange) -> tuple[list[str], list[str]]:
    """(what the change does, one line each; warnings for the confirm page)."""
    lines: list[str] = []
    warnings: list[str] = []
    if change.mode is not None:
        lines.append(f"Mode: {current.mode} → {change.mode}.")
        warnings.append(
            "Switching between access and trunk: the device on this port may lose its "
            "connection for a moment, and stays cut off if it is not set up for the new mode."
        )
    if change.access_vlan is not None:
        lines.append(f"Access VLAN: {current.access_vlan} → {change.access_vlan}.")
        if change.mode is None:
            warnings.append(
                f"The device on this port moves from VLAN {current.access_vlan} to VLAN "
                f"{change.access_vlan} at once, and loses its connection to VLAN "
                f"{current.access_vlan}."
            )
    if change.native_vlan is not None:
        lines.append(f"Native (untagged) VLAN: {current.native_vlan} → {change.native_vlan}.")
    if change.allowed_vlans is not None:
        new = frozenset(change.allowed_vlans)
        lines.append(
            f"VLANs carried: {current.allowed_text} → {format_vlan_list(change.allowed_vlans)}."
        )
        removed = current.allowed - new
        if removed and (change.mode is None and current.mode == "trunk"):
            warnings.append(
                f"VLANs {format_vlan_list(removed)} stop passing over this port at once."
            )
    return lines, warnings
