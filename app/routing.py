"""Layer 3: VLAN interfaces, routed ports and their addresses, and the checked
changes the Routing page offers.

A VLAN interface (``interface vlan<n>``, an SVI) gives the switch its own
address in a VLAN, so devices there can reach it and use it as their gateway,
and the switch routes between its VLAN interfaces and routed ports. The
switch offers VLAN interfaces only while the interface-vlan feature is on;
turning it on makes ``Vlan1`` by itself (turned off).

Read from show output recorded on cisco-25gb, in one request:

- ``show feature``: whether interface-vlan is on;
- ``show interface brief``: the VLAN interfaces (``Vlan10``) and the routed
  front ports and port-channels (``portmode`` routed);
- ``show vlan brief``: the VLANs, for the names and for which VLANs have no
  VLAN interface yet;
- ``show ip interface vrf all``: each interface's IPv4 address, its extra
  (secondary) addresses and its VRF; the switch writes front ports here as
  ``Ethernet1/54`` or ``Eth1/54``;
- ``show ipv6 interface vrf all``: each interface's IPv6 addresses and the
  link-local address the switch made for it;
- ``show interface description``: the descriptions, VLAN interfaces too.

and, when there are VLAN interfaces, one ``show interface vlan<n>`` each in a
second request, for its MTU and whether it is on and up.

The commands themselves are built by ``NxapiClient.configure_vlan_interface``,
``delete_vlan_interface`` and ``set_interface_addresses`` from checked values.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from app.neighbors import feature_enabled
from app.nxapi import (
    MTU_MAX,
    MTU_MIN,
    VLAN_INTERFACE_MAX,
    NxapiClient,
    validate_description,
    validate_interface_address,
    validate_routed_interface,
    validate_vlan_id,
)
from app.ports import port_sort_key
from app.switch import rows
from app.vlans import Vlan, parse_vlans

ROUTING_COMMANDS = (
    "show feature",
    "show interface brief",
    "show vlan brief",
    "show ip interface vrf all",
    "show ipv6 interface vrf all",
    "show interface description",
)

# A VLAN interface's MTU when nobody set one.
DEFAULT_MTU = 1500

FEATURE_OFF = (
    "VLAN interfaces are off on the switch: an NXray admin turns on interface-vlan on the "
    "Features page first"
)

_VLAN_NAME = re.compile(r"^Vlan(\d+)$")


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def long_name(name: str) -> str:
    """ "Eth1/3" (as ``show ip interface`` may write it) -> "Ethernet1/3"; others unchanged.

    The same as ``port_settings._long_name``, which the port page has used since
    before this module; both stay, so do not add a third.
    """
    if name.startswith("Eth") and not name.startswith("Ethernet"):
        return "Ethernet" + name[3:]
    return name


@dataclass(frozen=True)
class Address:
    """One address on an interface: "192.0.2.1/24" or "2001:db8::1/64"."""

    text: str
    secondary: bool = False

    @property
    def ipv6(self) -> bool:
        return ":" in self.text

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return ipaddress.ip_interface(self.text).network


@dataclass(frozen=True)
class L3Interface:
    """A VLAN interface, routed front port or routed port-channel."""

    name: str  # "Vlan10", "Ethernet1/54", "port-channel5"
    vrf: str = "default"
    admin_up: bool = True
    up: bool = False
    reason: str = ""  # why it is down, as the switch says it ("Administratively down")
    description: str = ""
    mtu: int | None = None
    addresses: tuple[Address, ...] = ()
    link_local: str = ""

    @property
    def vlan(self) -> int | None:
        match = _VLAN_NAME.match(self.name)
        return int(match.group(1)) if match else None

    @property
    def kind(self) -> str:
        if self.vlan is not None:
            return "vlan"
        return "channel" if self.name.startswith("port-channel") else "port"

    @property
    def primary(self) -> Address | None:
        return next((a for a in self.addresses if not a.ipv6 and not a.secondary), None)

    @property
    def secondaries(self) -> list[Address]:
        return [a for a in self.addresses if not a.ipv6 and a.secondary]

    @property
    def ipv4(self) -> list[Address]:
        return [a for a in self.addresses if not a.ipv6]

    @property
    def ipv6(self) -> list[Address]:
        return [a for a in self.addresses if a.ipv6]

    def address(self, text: str) -> Address | None:
        return next((a for a in self.addresses if a.text == text), None)

    @property
    def state_words(self) -> str:
        if not self.admin_up:
            return "off"
        return "up" if self.up else (f"down ({self.reason})" if self.reason else "down")


@dataclass(frozen=True)
class RoutingView:
    interface_vlan_on: bool = False
    vlan_interfaces: list[L3Interface] = field(default_factory=list)
    routed_ports: list[L3Interface] = field(default_factory=list)
    vlans: list[Vlan] = field(default_factory=list)

    def vlan_interface(self, vlan: int) -> L3Interface | None:
        return next((i for i in self.vlan_interfaces if i.vlan == vlan), None)

    def interface(self, name: str) -> L3Interface | None:
        return next(
            (i for i in (*self.vlan_interfaces, *self.routed_ports) if i.name == name), None
        )

    def vlan(self, number: int) -> Vlan | None:
        return next((v for v in self.vlans if v.id == number), None)

    @property
    def free_vlans(self) -> list[Vlan]:
        """VLANs with no VLAN interface yet, which can get one (up to
        ``VLAN_INTERFACE_MAX``, the range NXray's role names)."""
        taken = {i.vlan for i in self.vlan_interfaces}
        return [v for v in self.vlans if v.id not in taken and v.id <= VLAN_INTERFACE_MAX]

    @property
    def interfaces(self) -> list[L3Interface]:
        return [*self.vlan_interfaces, *self.routed_ports]


# ---- reading ----------------------------------------------------------------


def parse_ipv4(body: dict[str, Any]) -> dict[str, tuple[str, list[Address], dict[str, Any]]]:
    """Interface -> (VRF, IPv4 addresses with the primary first, row) from
    ``show ip interface vrf all``."""
    found: dict[str, tuple[str, list[Address], dict[str, Any]]] = {}
    for row in rows(body, "TABLE_intf", "ROW_intf"):
        name = long_name(_text(row.get("intf-name")))
        addresses = []
        prefix, masklen = _text(row.get("prefix")), _text(row.get("masklen"))
        if prefix and masklen:
            addresses.append(Address(f"{prefix}/{masklen}"))
        for extra in rows(row, "TABLE_secondary_address", "ROW_secondary_address"):
            # One row per address; the keys carry a number (prefix1, masklen1).
            prefixes = sorted(k for k in extra if re.fullmatch(r"prefix\d*", k))
            for key in prefixes:
                mask = _text(extra.get("masklen" + key[len("prefix") :]))
                if _text(extra.get(key)) and mask:
                    addresses.append(Address(f"{_text(extra[key])}/{mask}", secondary=True))
        found[name] = (_text(row.get("vrf-name-out")) or "default", addresses, row)
    return found


def parse_ipv6(body: dict[str, Any]) -> dict[str, tuple[str, list[Address], str]]:
    """Interface -> (VRF, IPv6 addresses, link-local address) from
    ``show ipv6 interface vrf all``."""
    found: dict[str, tuple[str, list[Address], str]] = {}
    for row in rows(body, "TABLE_intf", "ROW_intf"):
        name = long_name(_text(row.get("intf-name")))
        addresses = [
            Address(_text(item.get("addr")))
            for item in rows(row, "TABLE_addr", "ROW_addr")
            if "/" in _text(item.get("addr"))
        ]
        found[name] = (
            _text(row.get("vrf-name-out")) or "default",
            addresses,
            _text(row.get("linklocal-addr")),
        )
    return found


def _descriptions(body: dict[str, Any]) -> dict[str, str]:
    return {
        _text(row.get("interface")): _text(row.get("desc"))
        for row in rows(body, "TABLE_interface", "ROW_interface")
        if _text(row.get("desc"))
    }


def parse_brief(brief_body: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    """(VLAN interface names, rows of routed front ports and port-channels) from
    ``show interface brief``."""
    svis = []
    routed = []
    for row in rows(brief_body, "TABLE_interface", "ROW_interface"):
        name = _text(row.get("interface"))
        if _VLAN_NAME.match(name):
            svis.append(name)
        elif _text(row.get("portmode")).lower() == "routed" and (
            name.startswith("Ethernet") or name.startswith("port-channel")
        ):
            routed.append(row)
    return svis, routed


def _int(value: Any) -> int | None:
    text = _text(value)
    return int(text) if text.isdigit() else None


def parse_vlan_interface(
    name: str,
    svi_body: dict[str, Any],
    ipv4: dict[str, tuple[str, list[Address], dict[str, Any]]],
    ipv6: dict[str, tuple[str, list[Address], str]],
    descriptions: dict[str, str],
) -> L3Interface:
    """One VLAN interface from its ``show interface vlan<n>`` body and the shared ones."""
    row = next(
        (
            r
            for r in rows(svi_body, "TABLE_interface", "ROW_interface")
            if r.get("interface") == name
        ),
        {},
    )
    vrf4, addresses4, _ = ipv4.get(name, ("", [], {}))
    vrf6, addresses6, link_local = ipv6.get(name, ("", [], ""))
    admin_up = _text(row.get("svi_admin_state")).lower() == "up"
    return L3Interface(
        name=name,
        vrf=vrf4 or vrf6 or "default",
        admin_up=admin_up,
        up=_text(row.get("svi_line_proto")).lower() == "up",
        reason="" if admin_up else _text(row.get("svi_rsn_desc")),
        description=_text(row.get("svi_desc")) or descriptions.get(name, ""),
        mtu=_int(row.get("svi_mtu")),
        addresses=(*addresses4, *addresses6),
        link_local=link_local,
    )


def parse_routed_port(
    row: dict[str, Any],
    ipv4: dict[str, tuple[str, list[Address], dict[str, Any]]],
    ipv6: dict[str, tuple[str, list[Address], str]],
    descriptions: dict[str, str],
) -> L3Interface:
    name = _text(row.get("interface"))
    vrf4, addresses4, ip_row = ipv4.get(name, ("", [], {}))
    vrf6, addresses6, link_local = ipv6.get(name, ("", [], ""))
    reason = _text(row.get("state_rsn_desc"))
    return L3Interface(
        name=name,
        vrf=vrf4 or vrf6 or "default",
        admin_up="administratively down" not in reason.lower(),
        up=_text(row.get("state")).lower() == "up",
        reason=reason,
        description=descriptions.get(name, ""),
        mtu=_int(ip_row.get("mtu")),
        addresses=(*addresses4, *addresses6),
        link_local=link_local,
    )


def load_routing(client: NxapiClient) -> RoutingView:
    """Everything the Routing page shows: one request, plus one for the VLAN interfaces."""
    feature, brief, vlans, ip4, ip6, descriptions = client.show(*ROUTING_COMMANDS)
    svi_names, routed_rows = parse_brief(brief)
    ipv4, ipv6, descs = parse_ipv4(ip4), parse_ipv6(ip6), _descriptions(descriptions)
    svis = []
    if svi_names:
        bodies = client.show(*(f"show interface {name.lower()}" for name in svi_names))
        svis = [
            parse_vlan_interface(name, body, ipv4, ipv6, descs)
            for name, body in zip(svi_names, bodies, strict=True)
        ]
    routed = [parse_routed_port(row, ipv4, ipv6, descs) for row in routed_rows]
    return RoutingView(
        interface_vlan_on=feature_enabled(feature, "interface-vlan"),
        vlan_interfaces=sorted(svis, key=lambda i: i.vlan or 0),
        routed_ports=sorted(routed, key=lambda i: port_sort_key(i.name)),
        vlans=parse_vlans(vlans),
    )


# ---- changes ------------------------------------------------------------------


def _check_overlap(view: RoutingView, address: str, vrf: str, own: str) -> None:
    """Refuse an address whose network another interface in the same VRF already has.

    The switch refuses it too; this says which interface has it. The interface
    ``own`` itself does not count: an extra address may share its main one's
    network (``ip address 198.51.100.2/24 secondary`` beside 198.51.100.1/24 was
    taken on cisco-25gb).
    """
    network = ipaddress.ip_interface(address).network
    for other in view.interfaces:
        if other.vrf != vrf or other.name == own:
            continue
        for existing in other.addresses:
            if existing.ipv6 == (":" in address) and existing.network.overlaps(network):
                raise ValueError(
                    f"{address} is in the same network as {existing.text} on {other.name}"
                )


def _mtu(text: str, current: int | None) -> int | None:
    cleaned = text.strip()
    if not cleaned:
        return None
    if not cleaned.isascii() or not cleaned.isdigit() or not MTU_MIN <= int(cleaned) <= MTU_MAX:
        raise ValueError(f"the MTU is a number from {MTU_MIN} to {MTU_MAX}")
    value = int(cleaned)
    return None if value == (current or DEFAULT_MTU) else value


@dataclass(frozen=True)
class VlanInterfaceChange:
    vlan: int
    description: str | None = None  # "" removes it
    mtu: int | None = None
    enabled: bool | None = None
    remove: tuple[tuple[str, bool], ...] = ()
    add: tuple[tuple[str, bool], ...] = ()


def _in_range(number: int) -> None:
    """Refuse a VLAN interface outside the range NXray's role names."""
    if number > VLAN_INTERFACE_MAX:
        raise ValueError(
            f"NXray changes VLAN interfaces of VLANs 1 to {VLAN_INTERFACE_MAX} only, the range "
            f"its role on the switch names; change Vlan{number} on the switch itself"
        )


def _existing_vlan_interface(view: RoutingView, vlan: str) -> L3Interface:
    number = validate_vlan_id(vlan.strip().removeprefix("Vlan").removeprefix("vlan"))
    _in_range(number)
    interface = view.vlan_interface(number)
    if interface is None:
        raise ValueError(f"the switch has no VLAN interface for VLAN {number}")
    return interface


def _gateway_warning(name: str, vlan: int | None) -> str:
    where = f"VLAN {vlan}" if vlan is not None else name
    return (
        f"Devices that use the switch as their gateway in {where} lose their way to other "
        "networks while it is off or has no address there."
    )


def plan_create_vlan_interface(
    view: RoutingView,
    *,
    vlan: str,
    ipv4: str,
    ipv6: str,
    description: str,
    mtu: str,
    enabled: bool,
) -> tuple[VlanInterfaceChange, list[str], list[str]]:
    """A new VLAN interface for a VLAN that has none."""
    if not view.interface_vlan_on:
        raise ValueError(FEATURE_OFF)
    number = validate_vlan_id(vlan)
    _in_range(number)
    if view.vlan(number) is None:
        raise ValueError(f"VLAN {number} does not exist; create it on the VLANs page first")
    if view.vlan_interface(number) is not None:
        raise ValueError(f"VLAN {number} has a VLAN interface already; change it below")
    add = []
    lines = [f"Make a VLAN interface for VLAN {number} (Vlan{number})."]
    if ipv4.strip():
        address = validate_interface_address(ipv4)
        if ":" in address:
            raise ValueError("put the IPv6 address in the IPv6 box")
        _check_overlap(view, address, "default", f"Vlan{number}")
        add.append((address, False))
        lines.append(f"IPv4 address: {address}.")
    if ipv6.strip():
        address = validate_interface_address(ipv6)
        if ":" not in address:
            raise ValueError("put the IPv4 address in the IPv4 box")
        _check_overlap(view, address, "default", f"Vlan{number}")
        add.append((address, False))
        lines.append(f"IPv6 address: {address}.")
    text = validate_description(description)
    if text:
        lines.append(f'Description: "{text}".')
    new_mtu = _mtu(mtu, None)
    if new_mtu is not None:
        lines.append(f"MTU: {new_mtu}.")
    lines.append("Turn it on." if enabled else "Leave it off (the switch makes it turned off).")
    warnings = []
    if enabled and add:
        warnings.append(
            f"The switch answers at {' and '.join(a for a, _ in add)} in VLAN {number} at once, "
            "and routes between VLAN "
            f"{number} and its other VLAN interfaces and routed ports in the same VRF."
        )
    change = VlanInterfaceChange(
        vlan=number,
        description=text or None,
        mtu=new_mtu,
        enabled=True if enabled else None,
        add=tuple(add),
    )
    return change, lines, warnings


def plan_vlan_interface_settings(
    view: RoutingView,
    *,
    vlan: str,
    ipv4: str,
    description: str,
    mtu: str,
    enabled: bool,
) -> tuple[VlanInterfaceChange, list[str], list[str]]:
    """A VLAN interface's IPv4 address, description, MTU and on/off; only what differs."""
    current = _existing_vlan_interface(view, vlan)
    number = current.vlan
    assert number is not None
    lines: list[str] = []
    warnings: list[str] = []
    remove: list[tuple[str, bool]] = []
    add: list[tuple[str, bool]] = []
    typed = ipv4.strip()
    wanted = validate_interface_address(typed) if typed else ""
    if wanted and ":" in wanted:
        raise ValueError("this box is for the IPv4 address; add IPv6 addresses below")
    old = current.primary.text if current.primary else ""
    if wanted != old:
        if old and current.secondaries:
            raise ValueError(
                f"Vlan{number} has extra IPv4 addresses; remove them below before changing "
                "its main one"
            )
        if wanted:
            _check_overlap(view, wanted, current.vrf, current.name)
        if old:
            remove.append((old, False))
        if wanted:
            add.append((wanted, False))
        lines.append(f"IPv4 address: {old or 'none'} → {wanted or 'none'}.")
        if old and current.admin_up:
            warnings.append(_gateway_warning(current.name, number))
    text = validate_description(description)
    new_description = text if text != current.description else None
    if new_description is not None:
        lines.append(f'Description: "{current.description or "none"}" → "{text or "none"}".')
    new_mtu = _mtu(mtu, current.mtu)
    if new_mtu is not None:
        lines.append(f"MTU: {current.mtu or DEFAULT_MTU} → {new_mtu}.")
    new_enabled = enabled if enabled != current.admin_up else None
    if new_enabled is True:
        lines.append("Turn it on.")
    elif new_enabled is False:
        lines.append("Turn it off.")
        if current.addresses:
            warnings.append(_gateway_warning(current.name, number))
    if not lines:
        raise ValueError("nothing to change")
    change = VlanInterfaceChange(
        vlan=number,
        description=new_description,
        mtu=new_mtu,
        enabled=new_enabled,
        remove=tuple(remove),
        add=tuple(add),
    )
    return change, lines, warnings


def plan_delete_vlan_interface(view: RoutingView, *, vlan: str) -> tuple[int, list[str], list[str]]:
    """Deleting a VLAN interface; the VLAN itself stays."""
    current = _existing_vlan_interface(view, vlan)
    number = current.vlan
    assert number is not None
    if number == 1:
        raise ValueError(
            "the switch keeps the VLAN 1 interface while VLAN interfaces are on; turn it off "
            "instead"
        )
    lines = [f"Delete Vlan{number}. VLAN {number} itself stays, with its ports."]
    warnings = []
    if current.addresses:
        lines.append(
            "Its addresses go with it: " + ", ".join(a.text for a in current.addresses) + "."
        )
        if current.admin_up:
            warnings.append(_gateway_warning(current.name, number))
    return number, lines, warnings


@dataclass(frozen=True)
class AddressChange:
    name: str
    remove: tuple[tuple[str, bool], ...] = ()
    add: tuple[tuple[str, bool], ...] = ()


def _routed(view: RoutingView, name: str) -> L3Interface:
    cleaned = validate_routed_interface(name)
    if match := _VLAN_NAME.match(cleaned):
        _in_range(int(match.group(1)))
    interface = view.interface(cleaned)
    if interface is None:
        raise ValueError(f"{cleaned} is not a VLAN interface or routed port on the switch")
    return interface


def plan_add_address(
    view: RoutingView, *, name: str, address: str
) -> tuple[AddressChange, list[str], list[str]]:
    """One more address on an interface: IPv6, or IPv4 (the main one when it has none,
    else an extra, secondary one)."""
    interface = _routed(view, name)
    if not address.strip():
        raise ValueError(
            f"the address box of {interface.name} was empty; type the address in the box "
            f"right above Add address to {interface.name}"
        )
    text = validate_interface_address(address)
    if interface.address(text) is not None:
        raise ValueError(f"{interface.name} has {text} already")
    _check_overlap(view, text, interface.vrf, interface.name)
    if ":" in text:
        secondary = False
        line = f"Add the IPv6 address {text} to {interface.name}."
    else:
        secondary = interface.primary is not None
        kind = "an extra IPv4 address" if secondary else "its IPv4 address"
        line = f"Give {interface.name} {kind}: {text}."
    warnings = []
    if interface.admin_up:
        warnings.append(
            f"The switch answers at {text} at once and routes that network to its other "
            "interfaces in the same VRF."
        )
    return AddressChange(interface.name, add=((text, secondary),)), [line], warnings


def plan_remove_address(
    view: RoutingView, *, name: str, address: str
) -> tuple[AddressChange, list[str], list[str]]:
    """Taking one address off an interface."""
    interface = _routed(view, name)
    text = validate_interface_address(address)
    existing = interface.address(text)
    if existing is None:
        raise ValueError(f"{interface.name} has no address {text}")
    if not existing.ipv6 and not existing.secondary and interface.secondaries:
        raise ValueError(
            f"{text} is the main IPv4 address of {interface.name}; remove its extra IPv4 "
            "addresses first"
        )
    warnings = [
        f"Devices that reach the switch at {text}, or use it as their gateway there, lose "
        "that connection."
    ]
    change = AddressChange(interface.name, remove=((text, existing.secondary),))
    return change, [f"Take {text} off {interface.name}."], warnings
