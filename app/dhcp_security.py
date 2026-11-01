"""DHCP and ARP: DHCP snooping, DHCP relay, dynamic ARP inspection and IP Source
Guard, and every change the DHCP and ARP page makes.

Described with the same parts as the routing protocol pages
(``app/protocols.py``): one switch-wide scope (the ``ip dhcp snooping ...``,
``ip dhcp relay ...``, ``ip arp inspection ...`` and ``ip source binding ...``
lines), a switched port scope (trusted for DHCP snooping and ARP inspection,
its DHCP rate limit, IP Source Guard), a layer 3 interface scope (the DHCP
servers it relays to), and ARP ACLs, made and deleted from the page, which
let ARP inspection pass hosts with fixed addresses.
``NxapiClient.configure_dhcp`` sends what ``build_dhcp_change`` builds.

All of it needs the dhcp feature (``feature dhcp``); with it off the page
says so and links to Features. On a Nexus 9000 DHCP snooping, ARP inspection
and IP Source Guard also need TCAM space, set on the ACLs page (it takes a
restart). Changes need NXray's role version 14.

Read: ``show feature``, ``show interface brief``, ``show vlan brief`` and
``show vrf``; the running configuration as text, where every line above shows;
and ``show ip dhcp snooping binding`` as text, the addresses the switch learned
(and the fixed ones). NX-OS's defaults, when the configuration has no line for
them: snooping off, the DHCP relay on, MAC addresses checked against the DHCP
packets, every port untrusted. The lines follow Cisco's NX-OS 9.3 Security
Configuration Guide; not yet tried on a switch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.acls import layer3_names
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
    interface_field,
    port_field,
)
from app.spanning_tree import stp_vlan_numbers, switch_port_names
from app.switch_admin import vrf_choices

FEATURE = "dhcp"
BINDING_COMMAND = "show ip dhcp snooping binding"
RATE_MAX = 2048
LOG_BUFFER_MAX = 1024
SEQ_MAX = 4294967295
VALIDATE = (
    "src-mac",
    "dst-mac",
    "ip",
    "src-mac dst-mac",
    "src-mac ip",
    "dst-mac ip",
    "src-mac dst-mac ip",
)


def _vlans(hint: str) -> Field:
    return Field("vlans", "VLANs", "vlans", hint=hint, placeholder="10,20-30")


def _arp_acl_name(name: str = "name") -> Field:
    return Field(
        name,
        "ARP ACL",
        "name",
        maximum=64,
        hint="Letters, digits, '.', '_' or '-'",
        placeholder="fixed-hosts",
    )


SWITCH = Scope(
    "switch",
    "Switch-wide",
    (),
    (),
    (
        Setting(
            "snooping",
            "DHCP snooping",
            "ip dhcp snooping",
            help="On: the switch checks DHCP packets in the VLANs below, learns which address "
            "each device got, and drops DHCP server answers that come in on untrusted ports",
            warning="In the VLANs snooping covers, DHCP servers answer only through trusted "
            "ports: trust the port toward the server (or the uplink) first.",
            group="DHCP snooping",
        ),
        Setting(
            "snooping_vlans",
            "Snooping in VLANs",
            "ip dhcp snooping vlan {vlans}",
            (_vlans("Snooping covers these VLANs. Remove takes the same VLANs"),),
            warning="DHCP server answers that come in on untrusted ports of these VLANs are "
            "dropped at once.",
            group="DHCP snooping",
        ),
        Setting(
            "option82",
            "Add option 82",
            "ip dhcp snooping information option",
            help="The switch adds which port and VLAN a request came from (option 82) before "
            "passing it on",
            group="DHCP snooping",
        ),
        Setting(
            "verify_mac",
            "Check MAC addresses",
            "ip dhcp snooping verify mac-address",
            help="On by default: a DHCP request whose client address differs from the frame's "
            "source is dropped. Remove turns the check off",
            group="DHCP snooping",
        ),
        Setting(
            "relay",
            "DHCP relay",
            "ip dhcp relay",
            help="On by default once the dhcp feature is: VLAN interfaces and routed ports "
            "with a DHCP server set below pass requests to it. Remove turns it off",
            group="DHCP relay",
        ),
        Setting(
            "relay_option82",
            "Relay adds option 82",
            "ip dhcp relay information option",
            group="DHCP relay",
        ),
        Setting(
            "relay_vpn",
            "Relay across VRFs",
            "ip dhcp relay information option vpn",
            help="Needed when the DHCP server is reached in another VRF (use-vrf)",
            group="DHCP relay",
        ),
        Setting(
            "relay6",
            "DHCPv6 relay",
            "ipv6 dhcp relay",
            help="On by default once the dhcp feature is. Remove turns it off",
            group="DHCP relay",
        ),
        Setting(
            "arp_vlans",
            "ARP inspection in VLANs",
            "ip arp inspection vlan {vlans}",
            (_vlans("Inspection covers these VLANs. Remove takes the same VLANs"),),
            help="ARP packets on untrusted ports of these VLANs pass only when DHCP snooping "
            "learned that address on that port, or an ARP ACL below permits it",
            warning="Devices whose address DHCP snooping did not learn (fixed addresses) lose "
            "their ARP at once on untrusted ports, unless an ARP ACL permits them.",
            group="ARP inspection",
        ),
        Setting(
            "arp_validate",
            "Also check",
            "ip arp inspection validate {checks}",
            (
                Field(
                    "checks",
                    "Checks",
                    "choice",
                    choices=VALIDATE,
                    hint="src-mac: the sender's MAC is the frame's source; dst-mac: the "
                    "target's MAC is the frame's destination (replies); ip: no 0.0.0.0, "
                    "broadcast or multicast addresses",
                ),
            ),
            group="ARP inspection",
        ),
        Setting(
            "arp_filter",
            "ARP ACL for VLANs",
            "ip arp inspection filter {acl} vlan {vlans}",
            (_arp_acl_name("acl"), _vlans("The ACL applies in these VLANs")),
            help="Hosts with fixed addresses: the ARP ACL's entries pass before the DHCP "
            "snooping bindings are checked",
            group="ARP inspection",
        ),
        Setting(
            "arp_log_buffer",
            "Log buffer",
            "ip arp inspection log-buffer entries {entries}",
            (Field("entries", "Entries", "int", 1, LOG_BUFFER_MAX, hint="Default 32"),),
            group="ARP inspection",
        ),
        Setting(
            "binding",
            "A fixed binding",
            "ip source binding {address} {mac} vlan {vlan} interface {port}",
            (
                Field("address", "IPv4 address", "ipv4", placeholder="192.0.2.20"),
                Field("mac", "MAC address", "mac", placeholder="0200.0000.0020"),
                Field("vlan", "VLAN", "vlan"),
                port_field(),
            ),
            help="A device with a fixed address: IP Source Guard and ARP inspection let it "
            "through on that port as if DHCP snooping had learned it. Remove takes the same "
            "values",
            group="IP Source Guard",
        ),
    ),
    help="Turn DHCP snooping on, pick its VLANs, then trust the ports toward the DHCP "
    "server. ARP inspection and IP Source Guard check against what snooping learned.",
)

PORT = Scope(
    "port",
    "Ports",
    (port_field(),),
    ("interface {port}",),
    (
        Setting(
            "snooping_trust",
            "Trusted for DHCP",
            "ip dhcp snooping trust",
            help="DHCP server answers may come in on this port: the one toward the DHCP "
            "server, or an uplink",
            group="DHCP snooping",
        ),
        Setting(
            "snooping_rate",
            "DHCP rate limit",
            "ip dhcp snooping limit rate {rate}",
            (Field("rate", "Packets a second", "int", 1, RATE_MAX),),
            help="More DHCP packets a second than this turn the port off (error-disabled)",
            warning="A port that goes over the rate is turned off until it is turned on again.",
            group="DHCP snooping",
        ),
        Setting(
            "arp_trust",
            "Trusted for ARP",
            "ip arp inspection trust",
            help="ARP inspection lets every ARP packet on this port through: uplinks and "
            "ports toward other switches",
            group="ARP inspection",
        ),
        Setting(
            "source_guard",
            "IP Source Guard",
            "ip verify source dhcp-snooping-vlan",
            help="IP packets on this port pass only from the addresses DHCP snooping learned "
            "on it, or a fixed binding names",
            warning="Devices on this port whose address is neither learned nor bound lose "
            "their traffic at once.",
            group="IP Source Guard",
        ),
    ),
    help="Pick a front port or port-channel carrying VLANs, then a setting.",
)

RELAY = Scope(
    "relay",
    "DHCP relay on interfaces",
    (interface_field(),),
    ("interface {interface}",),
    (
        Setting(
            "server",
            "DHCP server",
            "ip dhcp relay address {server}[ use-vrf {vrf}]",
            (
                Field("server", "Server address", "ipv4", placeholder="192.0.2.53"),
                Field(
                    "vrf",
                    "Reached in VRF",
                    "usevrf",
                    optional=True,
                    hint="Leave default when the server is in this interface's VRF",
                ),
            ),
            help="Requests from the devices on this interface go to this server. Up to 32. "
            "Remove takes the same values",
            group="IPv4",
        ),
        Setting(
            "server6",
            "DHCPv6 server",
            "ipv6 dhcp relay address {server}[ use-vrf {vrf}]",
            (
                Field("server", "Server address", "ipv6", placeholder="2001:db8::53"),
                Field("vrf", "Reached in VRF", "usevrf", optional=True),
            ),
            group="IPv6",
        ),
    ),
    help="The VLAN interfaces and routed ports whose devices get their addresses from a "
    "DHCP server in another network.",
)

ARP_ACL = Scope(
    "arp_acl",
    "ARP ACLs",
    (_arp_acl_name(),),
    ("arp access-list {name}",),
    (
        Setting(
            "entry",
            "Entry",
            "{seq} {action} ip {address} mac {mac}[ {log}]",
            (
                Field("seq", "Number", "int", 1, SEQ_MAX, placeholder="10"),
                Field("action", "Action", "choice", choices=("permit", "deny")),
                Field(
                    "address",
                    "Sender IPv4",
                    "arpip",
                    hint="any, or one address",
                    placeholder="192.0.2.20",
                ),
                Field(
                    "mac",
                    "Sender MAC",
                    "arpmac",
                    hint="any, or one address",
                    placeholder="0200.0000.0020",
                ),
                Field("log", "Log matches", "flag", choices=("log",)),
            ),
            no_line="no {seq}",
            help="Checked from the lowest number up. To change an entry, remove it (only "
            "its number is needed) and add it again",
            group="Entries",
        ),
    ),
    create=True,
    create_label="Make an ARP ACL",
    delete=("no arp access-list {name}",),
    delete_warning="VLANs that use it for ARP inspection keep naming it; their fixed-address "
    "hosts are then checked against the DHCP snooping bindings only.",
    help="Lists of hosts with fixed addresses that ARP inspection lets through; apply one to "
    "VLANs with ARP ACL for VLANs above.",
)

# ---- reading ------------------------------------------------------------------------


@dataclass
class PortDhcp:
    """One port's DHCP snooping, ARP inspection and IP Source Guard lines."""

    snooping_trust: bool = False
    rate: str = ""
    arp_trust: bool = False
    source_guard: bool = False


@dataclass
class DhcpConfig:
    """The DHCP and ARP lines of the running configuration."""

    snooping: bool = False
    snooping_vlans: list[str] = field(default_factory=list)
    option82: bool = False
    verify_mac: bool = True
    relay: bool = True
    relay_option82: bool = False
    relay_vpn: bool = False
    relay6: bool = True
    arp_vlans: list[str] = field(default_factory=list)
    arp_validate: str = ""
    arp_filters: list[tuple[str, str]] = field(default_factory=list)  # ACL, VLANs
    arp_log_buffer: str = ""
    bindings: list[tuple[str, str, str, str]] = field(default_factory=list)  # ip, mac, vlan, port
    ports: dict[str, PortDhcp] = field(default_factory=dict)
    servers: dict[str, list[tuple[str, str, str]]] = field(default_factory=dict)  # family, ip, vrf
    arp_acls: dict[str, list[str]] = field(default_factory=dict)


_SWITCH_FLAGS = {
    "ip dhcp snooping": ("snooping", True),
    "ip dhcp snooping information option": ("option82", True),
    "no ip dhcp snooping verify mac-address": ("verify_mac", False),
    "ip dhcp relay": ("relay", True),
    "no ip dhcp relay": ("relay", False),
    "ip dhcp relay information option": ("relay_option82", True),
    "ip dhcp relay information option vpn": ("relay_vpn", True),
    "ipv6 dhcp relay": ("relay6", True),
    "no ipv6 dhcp relay": ("relay6", False),
}


def _top_line(found: DhcpConfig, line: str) -> None:
    if line in _SWITCH_FLAGS:
        name, value = _SWITCH_FLAGS[line]
        setattr(found, name, value)
        return
    words = line.split()
    if words[:4] == ["ip", "dhcp", "snooping", "vlan"] and len(words) == 5:
        found.snooping_vlans.append(words[4])
    elif words[:4] == ["ip", "arp", "inspection", "vlan"] and len(words) >= 5:
        found.arp_vlans.append(words[4])
    elif words[:4] == ["ip", "arp", "inspection", "validate"] and len(words) > 4:
        found.arp_validate = " ".join(words[4:])
    elif words[:4] == ["ip", "arp", "inspection", "filter"] and len(words) == 7:
        found.arp_filters.append((words[4], words[6]))
    elif words[:5] == ["ip", "arp", "inspection", "log-buffer", "entries"] and len(words) == 6:
        found.arp_log_buffer = words[5]
    elif words[:3] == ["ip", "source", "binding"] and len(words) == 9:
        found.bindings.append((words[3], words[4], words[6], words[8]))


def _interface(found: DhcpConfig, name: str, body: list[str]) -> None:
    port = PortDhcp()
    for line in body:
        words = line.split()
        if line == "ip dhcp snooping trust":
            port.snooping_trust = True
        elif words[:4] == ["ip", "dhcp", "snooping", "limit"] and len(words) == 6:
            port.rate = words[5]
        elif line == "ip arp inspection trust":
            port.arp_trust = True
        elif line == "ip verify source dhcp-snooping-vlan":
            port.source_guard = True
        elif words[1:4] == ["dhcp", "relay", "address"] and words[0] in ("ip", "ipv6"):
            vrf = words[words.index("use-vrf") + 1] if "use-vrf" in words[:-1] else ""
            family = "ipv4" if words[0] == "ip" else "ipv6"
            found.servers.setdefault(name, []).append((family, words[4], vrf))
    if port != PortDhcp():
        found.ports[name] = port


def parse_dhcp_config(config: str) -> DhcpConfig:
    """``show running-config`` as text: the DHCP snooping, relay, ARP inspection and
    IP Source Guard lines, switch-wide and per interface."""
    found = DhcpConfig()
    for header, body in config_sections(config):
        words = header.split()
        if len(words) == 2 and words[0] == "interface":
            _interface(found, words[1], body)
        elif len(words) == 3 and words[:2] == ["arp", "access-list"]:
            found.arp_acls[words[2]] = [line for line in body if line.split()[0].isdigit()]
        elif not body:
            _top_line(found, header)
    return found


_BINDING = re.compile(
    r"^\s*([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}|[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})"
    r"\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s*$"
)


def parse_bindings(text: str) -> list[tuple[str, ...]]:
    """``show ip dhcp snooping binding`` as text: (MAC, IP address, lease seconds,
    type, VLAN, interface) per line such as ``0f:00:60:b3:2c:00  10.5.5.2  6943
    dhcp-snoop  10  Ethernet2/3``."""
    return [m.groups() for line in text.splitlines() if (m := _BINDING.match(line))]


def _yes(value: bool) -> str:
    return "on" if value else "off"


def _switch_instance(config: DhcpConfig) -> Instance:
    facts = (
        ("DHCP snooping", _yes(config.snooping)),
        ("Snooping in VLANs", ", ".join(config.snooping_vlans) or "none"),
        ("Option 82", _yes(config.option82)),
        ("MAC addresses checked", _yes(config.verify_mac)),
        ("DHCP relay", _yes(config.relay)),
        ("Relay option 82", _yes(config.relay_option82)),
        ("Relay across VRFs", _yes(config.relay_vpn)),
        ("DHCPv6 relay", _yes(config.relay6)),
        ("ARP inspection in VLANs", ", ".join(config.arp_vlans) or "none"),
        ("ARP also checks", config.arp_validate or "nothing more"),
        (
            "ARP ACLs for VLANs",
            ", ".join(f"{acl} (VLAN {vlans})" for acl, vlans in config.arp_filters) or "none",
        ),
        ("ARP log buffer", config.arp_log_buffer or "32 (default)"),
        ("Fixed bindings", str(len(config.bindings))),
    )
    values: dict[str, dict[str, str]] = {}
    for key in ("snooping", "option82", "verify_mac", "relay", "relay_option82", "relay_vpn"):
        if getattr(config, key):
            values[key] = {"on": "yes"}
    if config.relay6:
        values["relay6"] = {"on": "yes"}
    if config.arp_validate in VALIDATE:
        values["arp_validate"] = {"checks": config.arp_validate}
    if config.arp_log_buffer:
        values["arp_log_buffer"] = {"entries": config.arp_log_buffer}
    return Instance("switch", {}, "Switch-wide", facts, values)


def parse_dhcp(
    bodies: list[dict[str, Any]], config_text: str | None = None, binding_text: str | None = None
) -> ProtocolView:
    """The DHCP and ARP page from the running configuration (None: NXray may not read
    it) and the snooping bindings (None: not read)."""
    if config_text is None:
        return ProtocolView(
            notes=(
                "NXray's role on the switch does not let it read the switch's configuration "
                "yet, the only place these settings show: an NXray admin turns on security "
                "and config changes on the Switch page.",
            )
        )
    config = parse_dhcp_config(config_text)
    instances = [_switch_instance(config)]
    port_rows = []
    for name, port in config.ports.items():
        facts = (
            ("Trusted for DHCP", "yes" if port.snooping_trust else "no"),
            ("DHCP rate limit", f"{port.rate} a second" if port.rate else "none"),
            ("Trusted for ARP", "yes" if port.arp_trust else "no"),
            ("IP Source Guard", _yes(port.source_guard)),
        )
        values: dict[str, dict[str, str]] = {}
        if port.snooping_trust:
            values["snooping_trust"] = {"on": "yes"}
        if port.rate:
            values["snooping_rate"] = {"rate": port.rate}
        if port.arp_trust:
            values["arp_trust"] = {"on": "yes"}
        if port.source_guard:
            values["source_guard"] = {"on": "yes"}
        instances.append(Instance("port", {"port": name}, name, facts, values))
        port_rows.append((name, *(value for _, value in facts)))
    relay_rows = []
    for name, servers in config.servers.items():
        shown = [f"{ip} (VRF {vrf})" if vrf else ip for _, ip, vrf in servers]
        instances.append(
            Instance("relay", {"interface": name}, name, (("DHCP servers", ", ".join(shown)),))
        )
        relay_rows.append((name, ", ".join(shown)))
    for name, entries in config.arp_acls.items():
        facts_list = [(line.split(" ", 1)[0], line.split(" ", 1)[1]) for line in entries]
        used = [vlans for acl, vlans in config.arp_filters if acl == name]
        facts_list.append(("For VLANs", ", ".join(used) or "none yet"))
        instances.append(Instance("arp_acl", {"name": name}, name, tuple(facts_list)))
    if binding_text is None:
        learned: tuple[tuple[str, ...], ...] = ()
        binding_note = "The switch did not answer show ip dhcp snooping binding."
    else:
        learned = tuple(tuple(row) for row in parse_bindings(binding_text))
        binding_note = ""
    fixed = tuple((mac, ip, "—", "static", vlan, port) for ip, mac, vlan, port in config.bindings)
    known = {(row[1], row[4]) for row in learned}
    tables = (
        Table(
            "Ports",
            ("Port", "Trusted for DHCP", "DHCP rate limit", "Trusted for ARP", "IP Source Guard"),
            tuple(port_rows),
            empty="None: every port is untrusted, with no limit and no IP Source Guard.",
        ),
        Table(
            "DHCP relay",
            ("Interface", "DHCP servers"),
            tuple(relay_rows),
            empty="No interface relays DHCP.",
        ),
        Table(
            "Bindings",
            ("MAC address", "IP address", "Lease (s)", "Type", "VLAN", "Port"),
            learned + tuple(row for row in fixed if (row[1], row[4]) not in known),
            empty="None: DHCP snooping learned no address yet, and no binding is fixed.",
            note=binding_note,
        ),
    )
    return ProtocolView(tuple(instances), tables)


DHCP = Protocol(
    key="dhcp",
    name="DHCP and ARP",
    summary="DHCP snooping, DHCP relay, dynamic ARP inspection and IP Source Guard",
    features=(FEATURE,),
    commands=("show feature", "show interface brief", "show vlan brief", "show vrf"),
    parse=parse_dhcp,
    scopes=(SWITCH, PORT, RELAY, ARP_ACL),
    about="DHCP snooping first (its VLANs, then the trusted ports); ARP inspection and IP "
    "Source Guard check against what it learns. On a Nexus 9000 they need TCAM space, set "
    "on the ACLs page.",
)


@dataclass(frozen=True)
class DhcpPage:
    """Everything the DHCP and ARP page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # switched front ports and port-channels
    interfaces: tuple[str, ...]  # VLAN interfaces up to Vlan254, routed ports and channels
    vlans: tuple[str, ...] = ()
    vrfs: tuple[str, ...] = ()
    problem: str = ""
    missing: tuple[str, ...] = ()  # the feature, when it is off


def load_dhcp_page(client: NxapiClient) -> DhcpPage:
    """One request for the feature, ports, VLANs and VRFs, one for the configuration
    text, one for the bindings."""
    features, brief, vlan_body, vrf_body = client.show(*DHCP.commands)
    missing = () if feature_states(features).get(FEATURE, False) else (FEATURE,)
    try:
        config: str | None = client.show_text(RUNNING_COMMAND)
    except NxapiCommandError:
        config = None
    bindings: str | None = None
    if not missing:
        try:
            bindings = client.show_text(BINDING_COMMAND)
        except NxapiCommandError:
            bindings = None
    view = parse_dhcp([features, brief], config, bindings)
    return DhcpPage(
        DHCP,
        view,
        tuple(switch_port_names(brief)),
        layer3_names(brief),
        tuple(str(n) for n in stp_vlan_numbers(vlan_body)),
        vrf_choices(vrf_body),
        "",
        missing,
    )


def build_dhcp_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the DHCP and ARP page."""
    return build_change(DHCP, scope, setting, action, ident, values)
