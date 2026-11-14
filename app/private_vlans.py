"""Private VLANs: primary, isolated and community VLANs, and the ports and VLAN
interfaces that use them.

A private VLAN splits one VLAN (the primary) into parts that cannot reach each other.
Ports in an isolated VLAN reach only the promiscuous ports (a router, a firewall);
ports in a community VLAN reach each other and the promiscuous ports. A host port sits
in one secondary VLAN of one primary VLAN (its host association); a promiscuous port
talks to the primary and the secondary VLANs it is mapped to. A VLAN interface on the
primary VLAN routes for the secondary VLANs mapped to it.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (a VLAN, a port, a VLAN interface), each setting the one
configuration line it sends with checked values in its blanks, and ``build_change``
building the lines. ``NxapiClient.configure_private_vlans`` sends them.

Read from the switch: ``show feature``, ``show vlan brief`` and ``show interface brief``
in one request; while ``feature private-vlan`` is on (the commands do not exist before),
``show vlan private-vlan type``, ``show vlan private-vlan`` and ``show interface
switchport`` in one, and ``show interface private-vlan mapping`` on its own. Nothing
made is an empty answer.

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-10, on a spare port and throwaway VLANs,
all removed afterwards): every line below and its ``no`` form, and the JSON of the show
commands. What the switch does, as seen there:

* ``private-vlan association``, ``switchport private-vlan mapping``, ``private-vlan
  mapping`` (on a VLAN interface) and ``switchport private-vlan trunk allowed vlan``
  ADD the VLANs they name to what is there; the ``remove`` forms take VLANs off;
* ``no switchport mode private-vlan <mode>`` puts the port back in access mode;
* a VLAN's private VLAN lines take effect a few seconds after they are sent;
* ``show vlan private-vlan`` gives the ports as one internal number, so the ports are
  read from ``show interface switchport`` instead;
* a trunk's native VLAN cannot be a primary or community VLAN.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.features import feature_states
from app.nxapi import VLAN_INTERFACE_MAX, NxapiClient, format_vlan_list, parse_vlan_list
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
    port_field,
    table_rows,
)
from app.spanning_tree import switch_port_names
from app.switch import text
from app.vlans import parse_vlans

PAGE_COMMANDS = ("show feature", "show vlan brief", "show interface brief")
COMMANDS = ("show vlan private-vlan type", "show vlan private-vlan", "show interface switchport")
MAPPING_COMMAND = "show interface private-vlan mapping"
TYPES = ("primary", "isolated", "community")
PORT_MODES = ("host", "promiscuous", "trunk promiscuous", "trunk secondary")

_ADDS = "Set adds the VLANs you list to those already there; Remove takes the ones you list off."


def _vlan(name: str, label: str, hint: str) -> Field:
    return Field(name, label, "vlan", hint=hint)


def _vlans(name: str, label: str, hint: str) -> Field:
    return Field(name, label, "vlans", hint=hint, placeholder="101,102-105")


_VLAN = Scope(
    key="vlan",
    label="Private VLAN",
    ident=(
        Field(
            "vlan",
            "VLAN",
            "vlan",
            hint="A VLAN made on the VLANs page",
        ),
    ),
    enter=("vlan {vlan}",),
    help=(
        "Make a VLAN a primary, isolated or community VLAN, then give each primary VLAN "
        "its secondary (isolated and community) VLANs. A primary VLAN has at most one "
        "isolated VLAN."
    ),
    settings=(
        Setting(
            key="type",
            label="Private VLAN type",
            line="private-vlan {type}",
            no_line="no private-vlan {type}",
            group="Type",
            fields=(
                Field(
                    "type",
                    "Type",
                    "choice",
                    choices=TYPES,
                    hint="primary: the shared VLAN; isolated: ports reach only promiscuous "
                    "ports; community: ports reach each other and promiscuous ports",
                ),
            ),
            help="Remove makes it a plain VLAN again.",
            warning=(
                "Ports that use this VLAN as a plain access or trunk VLAN can stop passing "
                "its traffic until they are set up as host or promiscuous ports."
            ),
        ),
        Setting(
            key="association",
            label="Secondary VLANs",
            line="private-vlan association {secondary}",
            no_line="private-vlan association remove {secondary}",
            group="Secondary VLANs (on a primary VLAN)",
            fields=(
                _vlans(
                    "secondary",
                    "Secondary VLANs",
                    "Isolated and community VLANs, such as 101,102-105",
                ),
            ),
            help=f"The isolated and community VLANs that belong to this primary VLAN. {_ADDS}",
        ),
        Setting(
            key="association_all",
            label="Every secondary VLAN",
            line="private-vlan association",
            no_line="no private-vlan association",
            settable=False,
            group="Secondary VLANs (on a primary VLAN)",
            help="Remove takes every secondary VLAN off this primary VLAN.",
        ),
    ),
)

_PORT = Scope(
    key="port",
    label="Port",
    ident=(port_field(),),
    enter=("interface {port}",),
    help=(
        "Set the port's private VLAN mode, then its VLANs: a host port gets a host "
        "association, a promiscuous port a mapping, and a private VLAN trunk its trunk "
        "lines."
    ),
    settings=(
        Setting(
            key="mode",
            label="Private VLAN mode",
            line="switchport mode private-vlan {mode}",
            no_line="no switchport mode private-vlan {mode}",
            group="Mode",
            fields=(
                Field(
                    "mode",
                    "Mode",
                    "choice",
                    choices=PORT_MODES,
                    hint="host: a device in one secondary VLAN; promiscuous: a router or "
                    "firewall that reaches every secondary VLAN; trunk promiscuous and "
                    "trunk secondary: the same over a trunk",
                ),
            ),
            help="Remove puts the port back in access mode.",
            warning=(
                "The port leaves its access or trunk VLANs: its traffic stops until it has "
                "a host association or mapping."
            ),
        ),
        Setting(
            key="host",
            label="Host association",
            line="switchport private-vlan host-association {primary} {secondary}",
            no_line="no switchport private-vlan host-association",
            group="Host port",
            fields=(
                _vlan("primary", "Primary VLAN", "The primary VLAN"),
                _vlan("secondary", "Secondary VLAN", "One of its isolated or community VLANs"),
            ),
            help="The one secondary VLAN a host port is in.",
        ),
        Setting(
            key="mapping",
            label="Mapping",
            line="switchport private-vlan mapping {primary} {secondary}",
            no_line="switchport private-vlan mapping {primary} remove {secondary}",
            group="Promiscuous port",
            fields=(
                _vlan("primary", "Primary VLAN", "The primary VLAN"),
                _vlans("secondary", "Secondary VLANs", "Its isolated and community VLANs"),
            ),
            help=f"The secondary VLANs a promiscuous port reaches. {_ADDS}",
        ),
        Setting(
            key="mapping_all",
            label="The whole mapping",
            line="switchport private-vlan mapping",
            no_line="no switchport private-vlan mapping",
            settable=False,
            group="Promiscuous port",
            help="Remove takes the port's whole mapping off.",
        ),
        Setting(
            key="trunk_mapping",
            label="Trunk mapping",
            line="switchport private-vlan mapping trunk {primary} {secondary}",
            no_line="no switchport private-vlan mapping trunk",
            group="Private VLAN trunk",
            fields=(
                _vlan("primary", "Primary VLAN", "The primary VLAN"),
                _vlans("secondary", "Secondary VLANs", "Its isolated and community VLANs"),
            ),
            help=(
                "On a trunk promiscuous port: a primary VLAN and the secondary VLANs it "
                "reaches; set once per primary VLAN. Remove takes every trunk mapping off."
            ),
        ),
        Setting(
            key="trunk_association",
            label="Trunk association",
            line="switchport private-vlan association trunk {primary} {secondary}",
            no_line="no switchport private-vlan association trunk {primary}",
            group="Private VLAN trunk",
            fields=(
                _vlan("primary", "Primary VLAN", "The primary VLAN"),
                _vlan("secondary", "Secondary VLAN", "One of its isolated or community VLANs"),
            ),
            help=(
                "On a trunk secondary port: the secondary VLAN it carries for a primary "
                "VLAN; set once per primary VLAN. Remove needs only the primary VLAN."
            ),
        ),
        Setting(
            key="trunk_allowed",
            label="Plain VLANs on the trunk",
            line="switchport private-vlan trunk allowed vlan {vlans}",
            no_line="no switchport private-vlan trunk allowed vlan {vlans}",
            group="Private VLAN trunk",
            fields=(_vlans("vlans", "VLANs", "Ordinary VLANs the trunk also carries"),),
            help=f"Ordinary (not private) VLANs a private VLAN trunk carries too. {_ADDS}",
        ),
        Setting(
            key="trunk_native",
            label="Native VLAN on the trunk",
            line="switchport private-vlan trunk native vlan {vlan}",
            no_line="no switchport private-vlan trunk native vlan",
            group="Private VLAN trunk",
            fields=(_vlan("vlan", "VLAN", "Not a primary or community VLAN"),),
            help="The VLAN a private VLAN trunk sends without a tag.",
        ),
    ),
)

_SVI = Scope(
    key="svi",
    label="VLAN interface",
    ident=(
        Field(
            "interface",
            "VLAN interface",
            "interface",
            hint="The VLAN interface of a primary VLAN, made on the Routing page",
            placeholder="Vlan100",
        ),
    ),
    enter=("interface {interface}",),
    help=(
        "Lets the VLAN interface of a primary VLAN route for its secondary VLANs, so their "
        "devices have a gateway."
    ),
    settings=(
        Setting(
            key="mapping",
            label="Secondary VLANs routed",
            line="private-vlan mapping {secondary}",
            no_line="private-vlan mapping remove {secondary}",
            group="Mapping",
            fields=(_vlans("secondary", "Secondary VLANs", "Its isolated and community VLANs"),),
            help=_ADDS,
        ),
        Setting(
            key="mapping_all",
            label="The whole mapping",
            line="private-vlan mapping",
            no_line="no private-vlan mapping",
            settable=False,
            group="Mapping",
            help="Remove takes every secondary VLAN off this VLAN interface.",
        ),
    ),
)


# ---- reading the switch ------------------------------------------------------------------


def _number(value: Any) -> int | None:
    found = text(value)
    return int(found) if found.isdigit() else None


def _listed(value: Any) -> str:
    """'251-252' as the switch writes a VLAN list; "" for "none" or nothing."""
    found = text(value).strip()
    return "" if found.lower() in ("", "none") else found


def _join(numbers: set[int]) -> str:
    return format_vlan_list(numbers) if numbers else ""


def _numbers(listed: str) -> set[int]:
    try:
        return set(parse_vlan_list(listed)) if listed else set()
    except ValueError:
        return set()


# "(250 251-252) (260 261)": a private VLAN trunk's primary VLANs, each with its secondaries.
_TRUNK_PAIR = re.compile(r"\(\s*(\d+)\s+([0-9,-]+)\s*\)")


@dataclass(frozen=True)
class PvlanPort:
    """One port's private VLAN settings, from ``show interface switchport``."""

    name: str
    mode: str  # one of PORT_MODES, or "" when the port is not in a private VLAN mode
    host: tuple[str, str] = ("", "")  # (primary, secondary)
    mapping: tuple[str, str] = ("", "")  # (primary, secondaries)
    trunk_pairs: tuple[tuple[str, str], ...] = ()  # (primary, secondaries) on a trunk
    trunk_vlans: str = ""  # ordinary VLANs on a private VLAN trunk
    trunk_native: str = ""
    operational: str = ""  # what the switch reports it uses now


def parse_pvlan_ports(body: dict[str, Any]) -> list[PvlanPort]:
    """The ports with any private VLAN setting in ``show interface switchport``."""
    found: list[PvlanPort] = []
    for row in table_rows(body, "TABLE_interface", "ROW_interface"):
        name = text(row.get("interface"))
        if not name:
            continue
        operating = text(row.get("oper_mode")).lower()
        mode = (
            operating.removeprefix("private-vlan ") if operating.startswith("private-vlan") else ""
        )
        host = (
            _listed(row.get("admin_pvlan_pri_assoc")),
            _listed(row.get("admin_pvlan_sec_assoc")),
        )
        mapping = (
            _listed(row.get("admin_pvlan_pri_mapping")),
            _listed(row.get("admin_pvlan_sec_mapping")),
        )
        pairs = tuple(_TRUNK_PAIR.findall(text(row.get("admin_pvlan_trunk_private"))))
        if not (mode or host[0] or mapping[0] or pairs):
            continue
        trunk = mode.startswith("trunk")
        found.append(
            PvlanPort(
                name,
                mode if mode in PORT_MODES else "",
                host,
                mapping,
                pairs,
                _listed(row.get("admin_pvlan_trunk_normal")) if trunk else "",
                _listed(row.get("admin_pvlan_trunk_native")) if trunk else "",
                _listed(row.get("oper_pvlan")),
            )
        )
    return found


def parse_private_vlans(
    bodies: list[dict[str, Any]], mapping: dict[str, Any] | None = None
) -> ProtocolView:
    """The page from ``show vlan private-vlan type``, ``show vlan private-vlan`` and
    ``show interface switchport`` (``bodies``, in that order) and ``show interface
    private-vlan mapping`` (``mapping``; None when it was not read)."""
    type_body, pairs_body, ports_body = (list(bodies) + [{}, {}, {}])[:3]
    types: dict[int, str] = {}
    for row in table_rows(type_body, "TABLE_pvlantype", "ROW_pvlantype"):
        number = _number(row.get("vlan-num"))
        if number is not None:
            types[number] = text(row.get("pvlan-type")).lower()
    secondaries: dict[int, set[int]] = {}
    primary_of: dict[int, int] = {}
    state_of: dict[int, str] = {}  # a secondary's state: its type, or "non-operational"
    for row in table_rows(pairs_body, "TABLE_pvlan_primary", "ROW_pvlan_primary"):
        primary, secondary = _number(row.get("primary")), _number(row.get("secondary"))
        if primary is not None and secondary is not None:
            secondaries.setdefault(primary, set()).add(secondary)
            primary_of[secondary] = primary
            state_of[secondary] = text(row.get("pvlan-type")).lower()
    ports = parse_pvlan_ports(ports_body)
    svi: dict[str, set[int]] = {}
    for row in table_rows(mapping or {}, "TABLE_interf_mapp", "ROW_interf_mapp"):
        name, secondary = text(row.get("interface-id")), _number(row.get("secondary-vlan"))
        if name and secondary is not None:
            # "Vlan250" as the switch writes it; "vlan250" in its text output.
            svi.setdefault(name[:1].upper() + name[1:], set()).add(secondary)

    hosts: dict[tuple[int, int], list[str]] = {}
    promiscuous: dict[int, list[str]] = {}
    for port in ports:
        pairs = [port.host] if port.host[0] else []
        if port.mode == "trunk secondary":
            pairs += list(port.trunk_pairs)
        for primary, secondary in pairs:
            for number in _numbers(secondary):
                hosts.setdefault((int(primary), number), []).append(port.name)
        if port.mapping[0]:
            promiscuous.setdefault(int(port.mapping[0]), []).append(port.name)
        if port.mode == "trunk promiscuous":
            for primary, _ in port.trunk_pairs:
                promiscuous.setdefault(int(primary), []).append(port.name)

    rows: list[tuple[str, ...]] = []
    instances: list[Instance] = []
    for number in sorted(types):
        kind = types[number]
        facts: list[tuple[str, str]] = [("Type", kind)]
        values: dict[str, dict[str, str]] = {"type": {"type": kind}} if kind in TYPES else {}
        if kind == "primary":
            joined = _join(secondaries.get(number, set()))
            facts.append(("Secondary VLANs", joined or "none yet"))
            facts.append(("Promiscuous ports", ", ".join(promiscuous.get(number, [])) or "none"))
            if f"Vlan{number}" in svi:
                facts.append(("Routed by", f"Vlan{number}"))
            if joined:
                values["association"] = {"secondary": joined}
            if not secondaries.get(number):
                rows.append((str(number), "-", "primary", "-", "-"))
        else:
            primary = primary_of.get(number)
            facts.append(("Primary VLAN", str(primary) if primary else "not associated yet"))
            if primary is None:
                rows.append(("-", str(number), kind, "-", "-"))
        instances.append(
            Instance("vlan", {"vlan": str(number)}, f"VLAN {number}", tuple(facts), values)
        )
    for primary in sorted(secondaries):
        for secondary in sorted(secondaries[primary]):
            rows.append(
                (
                    str(primary),
                    str(secondary),
                    state_of.get(secondary) or types.get(secondary, "-"),
                    ", ".join(hosts.get((primary, secondary), [])) or "-",
                    ", ".join(promiscuous.get(primary, [])) or "-",
                )
            )

    port_rows: list[tuple[str, ...]] = []
    for port in ports:
        facts = [("Mode", port.mode or "not a private VLAN mode")]
        values = {"mode": {"mode": port.mode}} if port.mode else {}
        if port.host[0]:
            facts.append(("Host association", f"primary {port.host[0]}, secondary {port.host[1]}"))
            values["host"] = {"primary": port.host[0], "secondary": port.host[1]}
        if port.mapping[0]:
            facts.append(("Mapping", f"primary {port.mapping[0]}, secondary {port.mapping[1]}"))
            values["mapping"] = {"primary": port.mapping[0], "secondary": port.mapping[1]}
        for primary, secondary in port.trunk_pairs:
            facts.append(("On the trunk", f"primary {primary}, secondary {secondary}"))
        if port.trunk_vlans:
            facts.append(("Plain VLANs on the trunk", port.trunk_vlans))
        if port.trunk_native:
            facts.append(("Native VLAN", port.trunk_native))
            values["trunk_native"] = {"vlan": port.trunk_native}
        instances.append(Instance("port", {"port": port.name}, port.name, tuple(facts), values))
        port_rows.append((port.name, port.mode or "-", port.operational or "-"))
    for name in sorted(svi, key=lambda n: int(n[4:]) if n[4:].isdigit() else 0):
        joined = _join(svi[name])
        instances.append(
            Instance(
                "svi",
                {"interface": name},
                name,
                (("Secondary VLANs routed", joined),),
                {"mapping": {"secondary": joined}},
            )
        )

    tables = (
        Table(
            "Private VLANs",
            ("Primary", "Secondary", "Type", "Host ports", "Promiscuous ports"),
            tuple(rows),
            empty="No private VLAN yet. Make a VLAN on the VLANs page, then give it a type below.",
            note="A secondary VLAN whose type was taken away shows as non-operational.",
        ),
        Table(
            "Ports in private VLANs",
            ("Port", "Mode", "Private VLANs in use"),
            tuple(port_rows),
            empty="No port is in a private VLAN mode.",
        ),
    )
    return ProtocolView(tuple(instances), tables)


PRIVATE_VLANS = Protocol(
    key="private-vlans",
    name="Private VLANs",
    summary="Keep ports in the same VLAN from reaching each other (primary, isolated and "
    "community VLANs)",
    features=("private-vlan",),
    commands=COMMANDS,
    parse=parse_private_vlans,
    scopes=(_VLAN, _PORT, _SVI),
    about=(
        "Set up in this order: make the VLANs on the VLANs page, give each its type here, "
        "give the primary VLAN its secondary VLANs, then set each port's mode and its "
        "host association or mapping. Changes to a VLAN take a few seconds to show."
    ),
)


# ---- the page ------------------------------------------------------------------------------


@dataclass(frozen=True)
class PrivateVlanPage:
    """Everything the Private VLANs page shows."""

    protocol: Protocol
    view: ProtocolView
    vlans: tuple[str, ...]  # the VLANs on the switch, VLAN 1 left out
    ports: tuple[str, ...]  # the switched front ports and port-channels
    interfaces: tuple[str, ...]  # the VLAN interfaces NXray may change
    problem: str = ""
    missing: tuple[str, ...] = ()  # the features still off (show feature names)


def _vlan_interfaces(brief: dict[str, Any]) -> tuple[str, ...]:
    found = []
    for row in table_rows(brief, "TABLE_interface", "ROW_interface"):
        match = re.fullmatch(r"Vlan(\d+)", text(row.get("interface")))
        if match and int(match.group(1)) <= VLAN_INTERFACE_MAX:
            found.append(int(match.group(1)))
    return tuple(f"Vlan{n}" for n in sorted(found))


def load_private_vlan_page(client: NxapiClient) -> PrivateVlanPage:
    """One request for the features, VLANs and ports; while private-vlan is on, one for
    the private VLANs and the ports' settings and one for the VLAN interface mappings."""
    feature, vlan_body, brief = client.show(*PAGE_COMMANDS)
    states = feature_states(feature)
    missing = tuple(name for name in PRIVATE_VLANS.features if not states.get(name, False))
    vlans = tuple(str(v.id) for v in parse_vlans(vlan_body) if v.id != 1)
    ports = tuple(switch_port_names(brief))
    interfaces = _vlan_interfaces(brief)
    if missing:
        return PrivateVlanPage(
            PRIVATE_VLANS, ProtocolView(), vlans, ports, interfaces, missing=missing
        )
    bodies = client.show(*COMMANDS)
    (mapping,) = client.show(MAPPING_COMMAND)
    view = parse_private_vlans(bodies, mapping)
    return PrivateVlanPage(PRIVATE_VLANS, view, vlans, ports, interfaces)


def build_private_vlan_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Private VLANs page."""
    return build_change(PRIVATE_VLANS, scope, setting, action, ident, values)
