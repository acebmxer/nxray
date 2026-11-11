"""VTP (VLAN Trunking Protocol): the VTP mode, domain, version and password, and which
ports take part.

On other Cisco switches VTP copies the VLAN list from one switch to the rest. A Nexus
9000 does not: Cisco's guide says VTP works "only in transparent mode" there, so the
switch keeps its own VLAN list and only passes other switches' VTP messages on from
trunk to trunk (inside the VTP domain it is given). The page is described with the same
parts as the Monitor sessions page (``app/protocols.py``): scopes (the switch, a port),
each setting the one configuration line it sends with checked values in its blanks, and
``build_change`` building the lines. ``NxapiClient.configure_vtp`` sends them.

Read from the switch: ``show feature`` and ``show interface brief`` in one request;
while ``feature vtp`` is on (the commands are refused before), ``show vtp status``,
``show vtp interface`` and ``show vtp counters`` as text (``NxapiClient.show_text``).
``show vtp password`` is never read: the page does not show the password.

NOT tried on a switch (cisco-25gb is in production and has VTP off). Written from
Cisco's NX-OS 9.3 Layer 2 Switching Configuration Guide ("Configuring VTP"), which gives
``vtp domain <name>``, ``vtp version 1|2`` and ``vtp password <password>``. Three lines
come from the guide's words rather than a printed command: ``vtp mode transparent|off``
(it names both modes, and no other), and ``vtp`` / ``no vtp`` on a port ("VTP can be
turned on or off per port", on by default). The guide prints no show output, so the text
is read tolerantly: every ``label : value`` line is shown as it is, and the mode, domain
and version are picked out of the labels Cisco software prints (``VTP Operating Mode``,
``VTP Domain Name``, ``VTP version running``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

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
from app.spanning_tree import switch_port_names

PAGE_COMMANDS = ("show feature", "show interface brief")
STATUS_COMMAND = "show vtp status"
INTERFACE_COMMAND = "show vtp interface"
COUNTERS_COMMAND = "show vtp counters"
MODES = ("transparent", "off")
VERSIONS = ("1", "2")
DOMAIN_MAX = 32  # a VTP domain name is 1 to 32 characters

_SWITCH = Scope(
    key="vtp_switch",
    label="Whole switch",
    ident=(),
    enter=(),
    help="The switch's VTP settings. They change nothing about its own VLANs.",
    settings=(
        Setting(
            key="mode",
            label="VTP mode",
            line="vtp mode {mode}",
            removable=False,
            group="VTP",
            fields=(
                Field(
                    "mode",
                    "Mode",
                    "choice",
                    choices=MODES,
                    hint="transparent: pass other switches' VTP messages on; off: drop them",
                ),
            ),
            help="A Nexus 9000 has no server or client mode: it never takes its VLAN list "
            "from another switch.",
        ),
        Setting(
            key="domain",
            label="VTP domain",
            line="vtp domain {name}",
            removable=False,
            group="VTP",
            fields=(
                Field(
                    "name",
                    "Domain name",
                    "name",
                    maximum=DOMAIN_MAX,
                    hint="The same name as on the neighbouring switches, upper and lower "
                    "case included",
                    placeholder="campus",
                ),
            ),
            help="The switch passes on VTP messages of this domain only.",
        ),
        Setting(
            key="version",
            label="VTP version",
            line="vtp version {version}",
            removable=False,
            group="VTP",
            fields=(Field("version", "Version", "choice", choices=VERSIONS),),
            help="The switch starts with version 1. Use the version the neighbours use.",
        ),
        Setting(
            key="password",
            label="VTP password",
            line="vtp password {password}",
            no_line="no vtp password",
            group="VTP",
            fields=(Field("password", "Password", "secret"),),
            help="The domain's password, the same as on the neighbouring switches. NXray "
            "does not show the one that is set.",
        ),
    ),
)

_PORT = Scope(
    key="vtp_port",
    label="Port",
    ident=(port_field(),),
    enter=("interface {port}",),
    help="VTP on one trunk port. Every port takes part until it is turned off here.",
    settings=(
        Setting(
            key="vtp",
            label="VTP on this port",
            line="vtp",
            group="VTP",
            help="Set turns it on (the default). Remove turns it off: the port then drops "
            "the VTP messages it gets and sends none.",
        ),
    ),
)

# A colon inside a value (a time of day) is not a separator: one is followed by a space
# or ends the line.
_PAIR = re.compile(r"^\s*([A-Za-z][^:]*?)\s*:(?:\s+(.*?))?\s*$")
_PORT_LINE = re.compile(r"^\s*((?:Ethernet|Eth|port-channel|Po)\d\S*)\s+(\S.*?)\s*$", re.IGNORECASE)
_SHORT = re.compile(r"^(?:Eth(?!ernet)|Po(?!rt))", re.IGNORECASE)


def parse_pairs(text_out: str) -> list[tuple[str, str]]:
    """Every ``label : value`` line of a show command's text, in order, as it is."""
    found = []
    for line in text_out.splitlines():
        match = _PAIR.match(line)
        if match and match.group(2):  # a heading ("VTP statistics:") has no value
            found.append((match.group(1), match.group(2)))
    return found


def _long_name(name: str) -> str:
    """'Eth1/3' -> 'Ethernet1/3', 'Po20' -> 'port-channel20'; a full name as it is."""
    if not _SHORT.match(name):
        return name
    return re.sub(r"(?i)^eth", "Ethernet", re.sub(r"(?i)^po", "port-channel", name))


def parse_vtp_ports(text_out: str) -> list[tuple[str, str]]:
    """The ports in ``show vtp interface`` with what the switch says about each (Enabled
    or Disabled): every line that starts with a port's name."""
    found = []
    for line in text_out.splitlines():
        match = _PORT_LINE.match(line)
        if match:
            found.append((_long_name(match.group(1)), match.group(2)))
    return found


def _pick(pairs: list[tuple[str, str]], *words: str) -> str:
    """The value of the first line whose label has every one of ``words``."""
    for label, value in pairs:
        lowered = label.lower()
        if all(word in lowered for word in words):
            return value
    return ""


def parse_vtp(status_text: str, interface_text: str = "", counters_text: str = "") -> ProtocolView:
    """The page from ``show vtp status``, ``show vtp interface`` and ``show vtp
    counters``: the switch's VTP settings as a place, the status lines as the switch
    prints them, the ports with VTP on or off, and the message counters."""
    status = parse_pairs(status_text)
    ports = parse_vtp_ports(interface_text)
    counters = parse_pairs(counters_text)
    instances: list[Instance] = []
    if status:
        mode = _pick(status, "operating mode")
        domain = _pick(status, "domain name")
        version = _pick(status, "version running") or _pick(status, "vtp version")
        values: dict[str, dict[str, str]] = {}
        if mode.lower() in MODES:
            values["mode"] = {"mode": mode.lower()}
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", domain):
            values["domain"] = {"name": domain}
        number = version.split()[0] if version.split() else ""
        if number in VERSIONS:
            values["version"] = {"version": number}
        instances.append(
            Instance(
                "vtp_switch",
                {},
                "VTP on the switch",
                (
                    ("Mode", mode or "-"),
                    ("Domain", domain or "not set"),
                    ("Version", number or version or "-"),
                ),
                values,
            )
        )
    for name, state in ports:
        if state.lower().startswith("disab"):
            instances.append(Instance("vtp_port", {"port": name}, name, (("VTP", state),), {}))
    tables = (
        Table(
            "Status",
            ("Setting", "Value"),
            tuple(status),
            empty="The switch reported no VTP status.",
            wrap_column=1,
        ),
        Table(
            "Ports",
            ("Port", "VTP"),
            tuple(ports),
            empty="The switch listed no ports for VTP.",
            note="VTP messages travel on trunk ports only.",
        ),
        Table(
            "Messages",
            ("Counter", "Count"),
            tuple(counters),
            empty="The switch reported no VTP counters.",
        ),
    )
    return ProtocolView(tuple(instances), tables)


VTP = Protocol(
    key="vtp",
    name="VTP",
    summary="The VTP mode, domain, version and password, and the ports that pass VTP on",
    features=("vtp",),
    commands=(),
    parse=lambda bodies: ProtocolView(),
    scopes=(_SWITCH, _PORT),
    about=(
        "On this kind of switch VTP never changes the VLAN list: the switch only passes "
        "other switches' VTP messages on (transparent mode), or drops them (off). VLANs "
        "are still made on the VLANs page."
    ),
)


@dataclass(frozen=True)
class VtpPage:
    """Everything the VTP page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # the switched front ports and port-channels
    problem: str = ""
    missing: tuple[str, ...] = ()  # the feature, when it is off


def load_vtp_page(client: NxapiClient) -> VtpPage:
    """One request for the feature and the ports; while vtp is on, one each for the
    status, the ports and the counters."""
    feature, brief = client.show(*PAGE_COMMANDS)
    ports = tuple(switch_port_names(brief))
    states = feature_states(feature)
    missing = tuple(name for name in VTP.features if not states.get(name, False))
    if missing:
        return VtpPage(VTP, ProtocolView(), ports, missing=missing)
    try:
        status = client.show_text(STATUS_COMMAND)
    except NxapiCommandError as exc:
        return VtpPage(VTP, parse_vtp(""), ports, f"The switch did not report VTP's status: {exc}")
    extra = []
    for command in (INTERFACE_COMMAND, COUNTERS_COMMAND):
        try:
            extra.append(client.show_text(command))
        except NxapiCommandError:
            extra.append("")  # the status is still worth showing
    return VtpPage(VTP, parse_vtp(status, *extra), ports)


def build_vtp_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the VTP page."""
    return build_change(VTP, scope, setting, action, ident, values)
