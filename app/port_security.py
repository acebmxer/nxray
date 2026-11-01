"""Port security: which devices' addresses a switched front port accepts, and what
it does about others, and every change the Port security page makes.

Described with the same parts as the routing protocol pages
(``app/protocols.py``): one scope, a switched front port (``interface
{port}``), with each ``switchport port-security ...`` line a setting.
``NxapiClient.configure_port_security`` sends what
``build_port_security_change`` builds.

Port security needs the port-security feature (``show feature`` calls it
``eth-port-sec``): with it off the page says so and links to Features. Read:
``show feature`` and ``show interface brief``, and the running configuration as
text, where the ports' settings show (NXray's role allows that read from role
version 12). NX-OS's defaults, when a port has no line for them: one address,
shut the port down on a violation, addresses kept until the port goes down.
The lines follow Cisco's NX-OS 9.3 Security Configuration Guide; not yet tried
on a switch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.config_tools import RUNNING_COMMAND, config_sections
from app.features import feature_states
from app.nxapi import NxapiClient, NxapiCommandError
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
)
from app.spanning_tree import stp_vlan_numbers, switch_port_names

FEATURE = "eth-port-sec"
MAXIMUM_MAX = 1025
AGING_MAX = 1440
VIOLATIONS = ("shutdown", "restrict", "protect")

_PREFIX = "switchport port-security"

PORT = Scope(
    "port",
    "Ports",
    (port_field(),),
    ("interface {port}",),
    (
        Setting(
            "enable",
            "Port security",
            _PREFIX,
            help="On: the port accepts only the addresses it learned or was given, up to the "
            "maximum. The port must be switched (access or trunk)",
            warning="Devices beyond the maximum are refused at once; with the default (one "
            "address, shut down on a violation) a second device turns the port off.",
            group="Port security",
        ),
        Setting(
            "maximum",
            "Most addresses",
            _PREFIX + " maximum {maximum}",
            (Field("maximum", "Addresses", "int", 1, MAXIMUM_MAX, hint="Default 1"),),
            group="Port security",
        ),
        Setting(
            "violation",
            "On a violation",
            _PREFIX + " violation {mode}",
            (
                Field(
                    "mode",
                    "Then",
                    "choice",
                    choices=VIOLATIONS,
                    hint="shutdown: turn the port off (default); restrict: drop and count; "
                    "protect: drop quietly",
                ),
            ),
            group="Port security",
        ),
        Setting(
            "sticky",
            "Keep learned addresses",
            _PREFIX + " mac-address sticky",
            help="Sticky: learned addresses become lines of the configuration, so they stay "
            "after Save config and a restart",
            group="Addresses",
        ),
        Setting(
            "mac",
            "A known address",
            _PREFIX + " mac-address {mac}[ vlan {vlan}]",
            (
                Field("mac", "MAC address", "mac", placeholder="0200.0000.0001"),
                Field("vlan", "VLAN", "vlan", optional=True, hint="Trunk ports: which VLAN"),
            ),
            help="An address the port always accepts. Remove takes the same address",
            group="Addresses",
        ),
        Setting(
            "aging_time",
            "Forget addresses after",
            _PREFIX + " aging time {minutes}",
            (Field("minutes", "Minutes", "int", 1, AGING_MAX),),
            help="Learned addresses are dropped after this long. Remove: kept until the port "
            "goes down",
            group="Aging",
        ),
        Setting(
            "aging_type",
            "Counted from",
            _PREFIX + " aging type {type}",
            (
                Field(
                    "type",
                    "Counted from",
                    "choice",
                    choices=("absolute", "inactivity"),
                    hint="absolute: from when it was learned (default); inactivity: from its "
                    "last packet",
                ),
            ),
            group="Aging",
        ),
    ),
    help="Pick a front port carrying VLANs, then a setting.",
)


@dataclass
class PortSecurity:
    """One port's port security lines, as the running configuration has them."""

    enabled: bool = False
    maximum: str = ""
    violation: str = ""
    sticky: bool = False
    aging_time: str = ""
    aging_type: str = ""
    macs: list[tuple[str, str]] = field(default_factory=list)  # address, VLAN ("" none)


def parse_port_security_config(config: str) -> dict[str, PortSecurity]:
    """``show running-config`` as text: every port with a port security line."""
    found: dict[str, PortSecurity] = {}
    for header, body in config_sections(config):
        words = header.split()
        if len(words) != 2 or words[0] != "interface":
            continue
        lines = [line for line in body if line.startswith(_PREFIX)]
        if not lines:
            continue
        port = found.setdefault(words[1], PortSecurity())
        for line in lines:
            rest = line[len(_PREFIX) :].split()
            if not rest:
                port.enabled = True
            elif rest[0] == "maximum" and len(rest) > 1:
                port.maximum = rest[1]
            elif rest[0] == "violation" and len(rest) > 1:
                port.violation = rest[1]
            elif rest[:2] == ["mac-address", "sticky"]:
                port.sticky = True
            elif rest[0] == "mac-address" and len(rest) > 1:
                vlan = rest[rest.index("vlan") + 1] if "vlan" in rest[:-1] else ""
                port.macs.append((rest[1], vlan))
            elif rest[:2] == ["aging", "time"] and len(rest) > 2:
                port.aging_time = rest[2]
            elif rest[:2] == ["aging", "type"] and len(rest) > 2:
                port.aging_type = rest[2]
    return found


def _values(port: PortSecurity) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    if port.enabled:
        values["enable"] = {"on": "yes"}
    if port.maximum:
        values["maximum"] = {"maximum": port.maximum}
    if port.violation:
        values["violation"] = {"mode": port.violation}
    if port.sticky:
        values["sticky"] = {"on": "yes"}
    if port.aging_time:
        values["aging_time"] = {"minutes": port.aging_time}
    if port.aging_type:
        values["aging_type"] = {"type": port.aging_type}
    return values


def parse_port_security(
    bodies: list[dict[str, Any]], config_text: str | None = None
) -> ProtocolView:
    """The Port security page from the running configuration (None: NXray may not
    read it)."""
    if config_text is None:
        return ProtocolView(
            notes=(
                "NXray's role on the switch does not let it read the switch's configuration "
                "yet, the only place port security shows: an NXray admin turns on security "
                "and config changes on the Switch page.",
            )
        )
    instances = []
    rows = []
    for name, port in parse_port_security_config(config_text).items():
        addresses = ", ".join(mac + (f" (VLAN {vlan})" if vlan else "") for mac, vlan in port.macs)
        aging = (
            f"after {port.aging_time} minutes ({port.aging_type or 'absolute'})"
            if port.aging_time
            else "when the port goes down"
        )
        facts = (
            ("Port security", "on" if port.enabled else "off (settings kept)"),
            ("Most addresses", port.maximum or "1 (default)"),
            ("On a violation", port.violation or "shutdown (default)"),
            (
                "Learned addresses",
                "kept in the configuration (sticky)" if port.sticky else "not kept",
            ),
            ("Known addresses", addresses or "none"),
            ("Forgotten", aging),
        )
        instances.append(Instance("port", {"port": name}, name, facts, _values(port)))
        rows.append(
            (
                name,
                "on" if port.enabled else "off",
                port.maximum or "1",
                port.violation or "shutdown",
                str(len(port.macs)),
            )
        )
    table = Table(
        "Ports with port security",
        ("Port", "On", "Most addresses", "On a violation", "Known addresses"),
        tuple(rows),
        empty="None: every port accepts any device.",
    )
    return ProtocolView(tuple(instances), (table,))


PORT_SECURITY = Protocol(
    key="port-security",
    name="Port security",
    summary="Which devices a port accepts, by their MAC address, and what happens to others",
    features=(FEATURE,),
    commands=("show feature", "show interface brief"),
    parse=parse_port_security,
    scopes=(PORT,),
    about="Set the limits first, then turn port security on: it takes effect at once.",
)


@dataclass(frozen=True)
class PortSecurityPage:
    """Everything the Port security page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # switched front ports
    vlans: tuple[str, ...] = ()  # filled for the VLAN field's list
    problem: str = ""
    missing: tuple[str, ...] = ()  # the feature, when it is off


def load_port_security_page(client: NxapiClient) -> PortSecurityPage:
    """One request for the feature and the ports, one for the configuration text."""
    features, brief, vlan_body = client.show(*PORT_SECURITY.commands, "show vlan brief")
    ports = tuple(p for p in switch_port_names(brief) if p.startswith("Ethernet"))
    vlans = tuple(str(n) for n in stp_vlan_numbers(vlan_body))
    missing = () if feature_states(features).get(FEATURE, False) else (FEATURE,)
    try:
        config: str | None = client.show_text(RUNNING_COMMAND)
    except NxapiCommandError:
        config = None
    view = parse_port_security([features, brief], config)
    return PortSecurityPage(PORT_SECURITY, view, ports, vlans, "", missing)


def build_port_security_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Port security page."""
    return build_change(PORT_SECURITY, scope, setting, action, ident, values)
