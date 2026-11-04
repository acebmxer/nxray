"""A pretend NX-API switch for tests, served through httpx.MockTransport.

It keeps local accounts and roles, checks Basic auth on every request,
answers the show commands NXray uses from recorded output, and applies the
configuration commands NXray sends, so setup and port changes can be tested
end to end without a switch. ``ssh_opener()`` gives a pretend SSH command
line into the same switch, which understands the role lines NXray types.

Permissions copy what cisco-25gb did when tried (see app/port_changes.py):
network-admin may do anything; another account may enter an Ethernet port
only when one of its roles has a "conf t ; interface * ; ..." rule and its
interface policy permits that port, and may then run only the commands its
rules name. Entering a VLAN (which creates it) likewise needs a
"conf t ; vlan * ; ..." rule. A batch stops at the first refused command.

VLANs live in ``vlans`` (number -> name) and each port's VLAN settings in
``port_state`` next to its description, so ``show vlan brief`` and ``show
interface switchport`` answer with what the commands set. Port settings
(speed, MTU, FEC, flow control, storm control, routed with an address) live
there too, and a split 100G port in ``breakouts`` (port -> map), so the show
commands list its four ports instead.

The MAC address table starts as recorded and lives in ``mac_rows`` once
anything changes it (static entries, clearing), with the aging time in
``mac_aging``; CDP and LLDP per port are in ``port_state`` too.

Port-channels live in ``channels`` (number -> member port -> mode), starting
as recorded (port-channel43 of Ethernet1/43-44, LACP active); a member's LACP
rate and priority in ``port_state``, the switch's LACP priority in
``lacp_priority``. As on cisco-25gb, "channel-group" creates a missing
port-channel, a role reaches a port-channel's own settings only when its port
list names port-channels, and a member's LACP rate changes only while the
port is turned off.

VLAN interfaces live in ``svis`` (VLAN numbers), their settings in
``port_state["Vlan<n>"]``. As on cisco-25gb they exist only while the
interface-vlan feature is on (off as recorded), turning it on makes Vlan1
(turned off), a role reaches one only when its port list names VLAN
interfaces, and deleting one needs the rule "conf t ; no interface Vlan *".
Extra IPv4 and IPv6 addresses of a routed port or VLAN interface are in its
``port_state`` (``secondaries``, ``ipv6``).

VRFs made on the switch live in ``vrfs`` (default and management are always
there), an interface's VRF in its ``port_state`` (``vrf``). As on cisco-25gb,
entering a VRF (which makes it) needs a "conf t ; vrf context * ; ..." rule,
and "vrf member" or "no vrf member" deletes the interface's addresses.
Static routes live in ``static_routes`` as (VRF, destination, next hop),
starting with management's default route as recorded.

The Switch admin lines (hostname, banner, clock, DNS, NTP, logging, SNMP) live
in ``admin_lines`` as typed, one per setting or server, starting empty; name
servers typed inside a VRF in ``context_name_servers``. ``show running-config``
(text, needs rule 170 or network-admin) prints them; ``clock set`` goes to
``clock_sets``. ``show logging last <n>`` prints ``log_text``. ``show clock``
and ``show ntp peer-status`` answer from bodies shaped after Cisco's NX-API
reference, never recorded on cisco-25gb.

ACL lines and the ACL and port security lines of interfaces live in
``security_lines``, kept the same way as the protocol lines (``ip access-list
web ; 10 permit tcp any any eq 22``, ``interface Ethernet1/3 ; switchport
port-security``); port security lines need the port-security feature on.
``show running-config`` prints them too. So do the role version 14 lines
(DHCP snooping and relay, ARP inspection, IP Source Guard, MAC and ARP ACLs,
object groups, VLAN access maps and filters, TCAM regions): modes the same way,
top-level lines as typed (``no`` removes one; for the lines on by default,
``no ip dhcp relay`` is kept as typed), and their DHCP lines need the dhcp
feature on. ``show hardware access-list tcam region`` prints the regions with
the sizes set (applied at once, unlike a switch, which waits for a restart);
``show ip dhcp snooping binding`` prints ``binding_text``. ``checkpoint <name>`` keeps a copy of
the hostname, the admin and the security lines in ``checkpoints``, and
``rollback running-config checkpoint <name>`` puts them back. ``show
startup-config`` prints what the last save kept (the running configuration as
it was at the start until then); ``show checkpoint summary`` lists the
checkpoints. Their shapes follow Cisco's guides, never recorded on cisco-25gb.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.features import CATALOG
from app.switch_ssh import SshAuthError, SshUnreachable
from tests.conftest import FIXTURES, load_fixture

ADMIN_PASSWORD = "Adm1n-switch-pw"

# cisco-25gb's answer to a copy sent while another one runs.
SAVE_BUSY = (
    "Configuration update aborted: another request for config change is already in progress\n"
)

_RECORDED = {
    "show version": "show_version",
    "show environment": "show_environment",
    "show system resources": "show_system_resources",
    "show interface brief": "show_interface_brief",
    "show interface status": "show_interface_status",
    "show interface transceiver": "show_interface_transceiver",
    "show cdp global": "show_cdp_global",
    "show cdp neighbors detail": "show_cdp_neighbors_detail",
    "show ip arp detail vrf all": "show_ip_arp_detail_vrf_all",
}

_INTERFACE_COMMANDS = ("shutdown", "no shutdown", "no description")

# Port settings commands, the rule entity that permits each, and the
# port_state key the value goes to (None: the command itself is the value).
_SETTINGS = (
    (re.compile(r"speed (\S+)"), "speed *", "speed"),
    (re.compile(r"mtu (\d+)"), "mtu *", "mtu"),
    (re.compile(r"fec (\S+)"), "fec *", "fec"),
    (re.compile(r"flowcontrol receive (on|off)"), "flowcontrol receive *", "flow_receive"),
    (re.compile(r"flowcontrol send (on|off)"), "flowcontrol send *", "flow_send"),
    (
        re.compile(r"storm-control broadcast level (\S+)"),
        "storm-control broadcast level *",
        "storm_broadcast",
    ),
    (
        re.compile(r"storm-control multicast level (\S+)"),
        "storm-control multicast level *",
        "storm_multicast",
    ),
    (
        re.compile(r"storm-control unicast level (\S+)"),
        "storm-control unicast level *",
        "storm_unicast",
    ),
    (re.compile(r"storm-control action (shutdown|trap)"), "storm-control action *", "storm_action"),
    (re.compile(r"no storm-control action (\S+)"), "no storm-control action *", None),
    (re.compile(r"load-interval counter 1 (\d+)"), "load-interval *", "load_interval"),
    (re.compile(r"no load-interval counter 1"), "no load-interval *", None),
    (re.compile(r"switchport"), "switchport", None),
    (re.compile(r"no switchport"), "no switchport", None),
    (re.compile(r"ip address (\S+)"), "ip address *", "ip"),
    (re.compile(r"no ip address (\S+)"), "no ip address *", None),
)

# The speed column of show interface status for a speed command's value.
_STATUS_SPEED = {"auto": "auto", "1000": "1000", "100": "100"}

_BREAKOUT = re.compile(r"(no )?interface breakout module (\d+) port (\d+) map (10g-4x|25g-4x)")

# CDP and LLDP per port: the command, its port_state key and the value it sets.
_DISCOVERY = {
    "cdp enable": ("cdp", True),
    "no cdp enable": ("cdp", False),
    "lldp transmit": ("lldp_transmit", True),
    "no lldp transmit": ("lldp_transmit", False),
    "lldp receive": ("lldp_receive", True),
    "no lldp receive": ("lldp_receive", False),
}

_STATIC_MAC = re.compile(
    r"(no )?mac address-table static ([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}) vlan (\d+) "
    r"(?:interface (Ethernet\S+)|drop)"
)
_CLEAR_MAC = re.compile(
    r"clear mac address-table dynamic"
    r"(?: interface (Ethernet\S+)| address ([0-9a-f.]+)(?: vlan (\d+))?| vlan (\d+))?"
)

# Interface commands with a value, and the rule entity that permits each.
_SWITCHPORT = (
    (re.compile(r"switchport mode (access|trunk)"), "switchport mode *", "mode"),
    (re.compile(r"switchport access vlan (\d+)"), "switchport access vlan *", "access"),
    (re.compile(r"switchport trunk native vlan (\d+)"), "switchport trunk native vlan *", "native"),
    (
        re.compile(r"switchport trunk allowed vlan ([0-9,-]+|none|all)"),
        "switchport trunk allowed vlan *",
        "allowed",
    ),
)

# What follows "feature" -> the name show feature uses for it.
_FEATURE_NAMES = {info.command: name for name, info in CATALOG.items() if info.command is not None}

# Routing protocols (stage 15d). Global lines that enter a protocol's
# configuration mode, interface lines of a protocol, and global one-line
# settings; each with the feature it needs (None: always there). As on
# cisco-25gb, a line of a feature that is off is "% Invalid command", and a
# role rule naming a mode ("conf t ; router ospf *") covers every line inside
# it, at any depth.
_PROTOCOL_MODES = (
    (re.compile(r"router ospf \S+"), "ospf"),
    (re.compile(r"router ospfv3 \S+"), "ospfv3"),
    (re.compile(r"router bgp \S+"), "bgp"),
    (re.compile(r"router eigrp \S+"), "eigrp"),
    (re.compile(r"router rip \S+"), "rip"),
    (re.compile(r"router isis \S+"), "isis"),
    (re.compile(r"route-map \S+ (?:permit|deny) \d+"), None),
    (re.compile(r"key chain \S+"), None),
)
_PROTOCOL_GLOBAL = (
    ("ip prefix-list ", None),
    ("ipv6 prefix-list ", None),
    ("ip pim ", "pim"),
    ("ipv6 pim ", "pim6"),
    ("ip msdp ", "msdp"),
    ("bfd ", "bfd"),
)
_PROTOCOL_INTERFACE = (
    (re.compile(r"ip router (ospf|eigrp|rip|isis) "), None),
    (re.compile(r"ipv6 router (ospfv3|eigrp|rip|isis) "), None),
    (re.compile(r"ip ospf "), "ospf"),
    (re.compile(r"ospfv3 "), "ospfv3"),
    (re.compile(r"ipv6? \S+ eigrp "), "eigrp"),
    (re.compile(r"ipv6? eigrp "), "eigrp"),
    (re.compile(r"ipv6? rip "), "rip"),
    (re.compile(r"isis "), "isis"),
    (re.compile(r"hsrp "), "hsrp_engine"),
    (re.compile(r"vrrp "), "vrrp"),
    (re.compile(r"vrrpv3 "), "vrrpv3"),
    (re.compile(r"ip pim "), "pim"),
    (re.compile(r"ipv6 pim "), "pim6"),
    (re.compile(r"ip igmp "), "pim"),
    (re.compile(r"bfd(?: |$)"), "bfd"),
)
# Lines inside a protocol's mode that open a deeper mode.
_PROTOCOL_SUBMODES = re.compile(
    r"(?:vrf \S+|address-family .+|neighbor \S+(?: remote-as \S+)?|key \d+|template .+)"
)
# Interface lines that open a group's mode (HSRP, VRRP, VRRPv3).
_GROUP_MODES = re.compile(r"(?:hsrp \d+(?: ipv6)?|vrrp \d+|vrrpv3 \d+ address-family ipv[46])")

# Role version 14 lines (see the module notes): the modes, the top-level lines and
# the interface lines, and the defaults of the TCAM regions shown.
_LAYER2_MODES = re.compile(
    r"(mac access-list|arp access-list|object-group (?:ip|ipv6) address|object-group ip port"
    r"|vlan access-map) \S+(?: \d+)?"
)
_LAYER2_TOP = re.compile(
    r"(ip dhcp snooping|ip dhcp relay|ipv6 dhcp relay|ip arp inspection|ip source binding"
    r"|vlan filter|hardware access-list tcam region)(?: |$)"
)
_NEEDS_DHCP = {
    "ip dhcp snooping",
    "ip dhcp relay",
    "ipv6 dhcp relay",
    "ip arp inspection",
    "ip source binding",
}
_LAYER2_DEFAULT_ON = {"ip dhcp relay", "ipv6 dhcp relay", "ip dhcp snooping verify mac-address"}
_LAYER2_INTERFACE = re.compile(
    r"(ip dhcp snooping|ip arp inspection|ip verify source|ip dhcp relay address"
    r"|ipv6 dhcp relay address|mac port access-group) ?"
)
_TCAM_NAMES = {
    "nat": "NAT ACL",
    "ing-ifacl": "Ingress PACL",
    "vacl": "VACL",
    "ing-racl": "Ingress RACL",
    "ing-l2-qos": "Ingress L2 QOS",
    "ing-sup": "Ingress SUP",
    "egr-racl": "Egress RACL",
}
_TCAM_DEFAULTS = {
    "nat": 0,
    "ing-ifacl": 0,
    "vacl": 0,
    "ing-racl": 1536,
    "ing-l2-qos": 256,
    "ing-sup": 512,
    "egr-racl": 1792,
}

# Switch admin lines: what identifies the line a new one replaces (and its
# "no" form removes), checked in order.
_ADMIN_KEYS = tuple(
    re.compile(p)
    for p in (
        r"(ntp server \S+)",
        r"(ip name-server \S+)",
        r"(logging server \S+)",
        r"(snmp-server community \S+)",
        r"(snmp-server host \S+ (?:traps|use-vrf))",
        r"(ip domain-name)",
        r"(clock timezone)",
        r"(clock summer-time)",
        r"(logging logfile)",
        r"(logging console)",
        r"(logging monitor)",
        r"(logging timestamp)",
        r"(snmp-server contact)",
        r"(snmp-server location)",
        r"(banner motd)",
    )
)

# VLANs NX-OS keeps for itself (show system vlan reserved).
RESERVED_VLANS = range(3968, 4096)

# Two of the roles every NX-OS switch has (cisco-25gb lists 27).
BUILTIN_ROLES = ("network-admin", "network-operator")


@dataclass
class Role:
    entities: set[str] = field(default_factory=set)  # what each "permit command" rule names
    interface_policy_deny: bool = False
    interfaces: set[str] = field(default_factory=set)  # lower-cased port names

    def names(self, interface: str) -> bool:
        """Whether the port list covers ``interface`` (a range for port-channels)."""
        lowered = interface.lower()
        if lowered in self.interfaces:
            return True
        kind = "vlan" if lowered.startswith("vlan") else "port-channel"
        number = lowered.removeprefix(kind)
        if number == lowered or not number.isdigit():
            return False
        for entry in self.interfaces:
            match = re.fullmatch(rf"{kind}(\d+)-(\d+)", entry)
            if match and int(match.group(1)) <= int(number) <= int(match.group(2)):
                return True
        return False


@dataclass
class FakeSwitch:
    users: dict[str, tuple[str, str]] = field(
        default_factory=lambda: {"admin": (ADMIN_PASSWORD, "network-admin")}
    )
    # Roles given to an account on top of the one in ``users``.
    extra_roles: dict[str, set[str]] = field(default_factory=dict)
    roles: dict[str, Role] = field(default_factory=dict)
    saved: bool = False
    reachable: bool = True
    ssh_reachable: bool = True
    # Command prefixes the switch rejects with an NX-API error.
    reject: set[str] = field(default_factory=set)
    # Line prefixes the SSH command line refuses.
    ssh_reject: set[str] = field(default_factory=set)
    save_text: str | None = None
    requests: list[list[str]] = field(default_factory=list)
    ssh_lines: list[str] = field(default_factory=list)
    # As on cisco-25gb: once a role's port list gains port-channels, NX-API
    # stops answering every account for a while (SSH keeps working). Off unless
    # a test asks, since the freeze ends on its own on the switch.
    freeze_on_channel_permit: bool = False
    nxapi_frozen: bool = False
    # Show commands answered from these bodies instead of the recorded ones.
    bodies: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Port settings changed through NX-API: name -> {"desc": str, "admin_up": bool,
    # "mode": str, "access": str, "native": str, "allowed": str}.
    port_state: dict[str, dict[str, Any]] = field(default_factory=dict)
    vlans: dict[int, str] = field(default_factory=lambda: {1: "default"})
    # As on cisco-25gb: an account that made an NX-API call keeps a session,
    # and "no username" is refused while it lives. Off by default.
    sessions_block_delete: bool = False
    signed_in: set[str] = field(default_factory=set)
    # As on cisco-25gb: a copy takes a while (2-3 s there), and a second copy
    # sent meanwhile is refused. 0 means instant.
    save_seconds: float = 0.0
    # Split 100G ports: "Ethernet1/50" -> "25g-4x".
    breakouts: dict[str, str] = field(default_factory=dict)
    # The lldp feature, off as on cisco-25gb: every "show lldp" command is then
    # "% Invalid command". On, "show lldp neighbors detail" answers from a body
    # shaped after Cisco's NX-API reference (never recorded on cisco-25gb).
    lldp: bool = False
    # Other features turned on or off since the start: show name -> on. The
    # rest answer as in the recording (show_feature_full: icam, lacp, nxapi
    # and sshServer on).
    feature_state: dict[str, bool] = field(default_factory=dict)
    # The MAC address table's rows once something changed it; None: as recorded.
    mac_rows: list[dict[str, Any]] | None = None
    mac_aging: int = 1800
    # Port-channels: number -> {member port: "active" | "passive" | "on"}.
    channels: dict[int, dict[str, str]] = field(
        default_factory=lambda: {43: {"Ethernet1/43": "active", "Ethernet1/44": "active"}}
    )
    lacp_priority: int = 32768
    # VLAN interfaces (VLAN numbers); only while interface-vlan is on.
    svis: set[int] = field(default_factory=set)
    # VRFs made on the switch, besides default and management.
    vrfs: list[str] = field(default_factory=list)
    # Static routes: (VRF, destination, next hop).
    static_routes: list[tuple[str, str, str]] = field(
        default_factory=lambda: [("management", "0.0.0.0/0", "203.0.113.254")]
    )
    # Routing protocol lines as entered, each the mode path joined with " ; "
    # ("router ospf core ; vrf lab ; router-id 192.0.2.1").
    protocol_lines: list[str] = field(default_factory=list)
    # Spanning tree lines as entered, the same way ("interface Ethernet1/54 ;
    # spanning-tree cost 100"); ``show running-config spanning-tree`` prints them.
    stp_lines: list[str] = field(default_factory=list)
    # Switch admin (see the module notes).
    hostname: str = "nexus-lab"
    admin_lines: list[str] = field(default_factory=list)
    context_name_servers: list[tuple[str, str]] = field(default_factory=list)
    clock_sets: list[str] = field(default_factory=list)
    log_text: str = field(
        default_factory=lambda: FIXTURES.joinpath("show_logging_last_doc.txt").read_text()
    )
    # ACL and port security lines (see the module notes).
    security_lines: list[str] = field(default_factory=list)
    # Checkpoints: name -> (hostname, admin lines, security lines).
    checkpoints: dict[str, tuple[str, list[str], list[str]]] = field(default_factory=dict)
    # show startup-config; None: the running configuration as at the start.
    startup_text: str | None = None
    # Restarts over SSH, and whether the configuration was saved at each.
    reloads: int = 0
    saved_at_reload: list[bool] = field(default_factory=list)
    # show ip dhcp snooping binding, as text (after Cisco's guide).
    binding_text: str = field(
        default_factory=lambda: FIXTURES.joinpath("show_ip_dhcp_snooping_binding.txt").read_text()
    )
    # What the switch prints after a rollback; contains "failed" to refuse it.
    rollback_text: str = "Rollback completed successfully.\n"
    # sFlow, while the sflow feature is on: rate, collector, vrf, port, agent and
    # sources (front ports and port-channels sampled). ``show sflow`` prints it as
    # text, as recorded on cisco-25gb (a port-channel source not yet recorded).
    # As there, a port in a port-channel is refused as a source.
    sflow: dict[str, Any] = field(default_factory=dict)
    _copying: bool = False

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def roles_of(self, user: str) -> set[str]:
        return {self.users[user][1], *self.extra_roles.get(user, set())}

    def handle(self, request: httpx.Request) -> httpx.Response:
        if not self.reachable:
            raise httpx.ConnectError("connection refused", request=request)
        if self.nxapi_frozen:
            raise httpx.ReadTimeout("timed out", request=request)
        user = self._authenticate(request)
        if user is None:
            return httpx.Response(401, text="Unauthorized")
        self.signed_in.add(user)
        entries = json.loads(request.content)
        self.requests.append([entry["params"]["cmd"] for entry in entries])
        replies: list[dict[str, Any]] = []
        context: tuple[str, str] | None = None  # ("interface", name) or ("vlan", number)
        for entry in entries:
            ident = entry["id"]
            if replies and "error" in replies[-1]:
                replies.append(_error(ident, "Command not ran due to previous failures"))
                continue
            if entry.get("method") == "cli_ascii":
                reply = self._ascii(user, entry["params"]["cmd"], ident)
            else:
                reply, context = self._run(user, entry["params"]["cmd"], ident, context)
            replies.append(reply)
        status = 500 if any("error" in reply for reply in replies) else 200
        return httpx.Response(status, json=replies[0] if len(replies) == 1 else replies)

    def _authenticate(self, request: httpx.Request) -> str | None:
        header = request.headers.get("authorization", "")
        if not header.startswith("Basic "):
            return None
        name, _, password = base64.b64decode(header[6:]).decode().partition(":")
        known = self.users.get(name)
        return name if known and known[0] == password else None

    # ---- NX-API -------------------------------------------------------------

    def _role_allows(self, user: str, entity: str, interface: str | None) -> bool:
        for name in self.roles_of(user):
            role = self.roles.get(name)
            if role is None:
                continue
            if interface is not None and role.interface_policy_deny:
                if not role.names(interface):
                    continue
            if entity in ("interface", "vlan", "vrf context"):
                if any(e.startswith(f"conf t ; {entity} * ; ") for e in role.entities):
                    return True
            elif entity in role.entities:
                return True
        return False

    def _role_matches(self, user: str, path: str, interface: str | None) -> bool:
        """Whether a rule of the account's roles covers ``path`` ("conf t ; router ospf
        core ; router-id 1.1.1.1"): "*" stands for anything, and a rule naming a mode
        covers every line inside it."""
        for name in self.roles_of(user):
            role = self.roles.get(name)
            if role is None:
                continue
            if interface is not None and role.interface_policy_deny and not role.names(interface):
                continue
            for entity in role.entities:
                pattern = re.escape(entity).replace(r"\*", ".*")
                if re.fullmatch(pattern, path):
                    return True
        return False

    def _feature_on(self, name: str | None) -> bool:
        return name is None or self.feature_state.get(name, False)

    def _record(self, path: str, kept: list[str] | None = None) -> None:
        """Keep a protocol line; its "no" form removes it and everything under it.
        ``kept`` is the list to keep it in (the protocol lines when not given)."""
        lines = self.protocol_lines if kept is None else kept
        parts = path.split(" ; ")
        last = parts[-1]
        if last.startswith("no "):
            gone = " ; ".join([*parts[:-1], last[3:]])
            lines[:] = [
                line
                for line in lines
                if line != gone
                and not line.startswith(gone + " ; ")
                and not line.startswith(gone + " ")
            ]
        elif path not in lines:
            lines.append(path)

    def _spanning_tree(
        self, user: str, is_admin: bool, cmd: str, ident: int, context: tuple[str, str] | None
    ) -> tuple[dict[str, Any], tuple[str, str] | None] | None:
        """A spanning tree line, or None when ``cmd`` is not one. As proven on
        cisco-25gb: the role's "conf t ; spanning-tree *" rule covers the MST
        region's submode, the interface rules every port line."""
        kind = context[0] if context else None
        interface = context[1] if context and kind == "interface" else None
        if kind == "stp-mst" and context:
            path = f"{context[1]} ; {cmd}"
        elif interface is not None and cmd.removeprefix("no ").startswith("spanning-tree "):
            path = f"interface {interface} ; {cmd}"
        elif kind is None and cmd.removeprefix("no ").startswith("spanning-tree "):
            path = cmd
        else:
            return None
        if not (is_admin or self._role_matches(user, f"conf t ; {path}", interface)):
            return _error(ident, "% Permission denied for the role\n"), context
        self._record(path, self.stp_lines)
        if cmd == "spanning-tree mst configuration":
            return _ok(ident, None), ("stp-mst", cmd)
        return _ok(ident, None), context

    def stp_config(self) -> str:
        """``show running-config spanning-tree`` from the lines entered: the top-level
        ones, then the MST region's, then each port's."""
        top = [
            p for p in self.stp_lines if " ; " not in p and p != "spanning-tree mst configuration"
        ]
        region = [
            p.split(" ; ", 1)[1]
            for p in self.stp_lines
            if p.startswith("spanning-tree mst configuration ; ")
        ]
        out = list(top)
        if region:
            out += ["spanning-tree mst configuration", *(f"  {line}" for line in region)]
        ports: dict[str, list[str]] = {}
        for p in self.stp_lines:
            if p.startswith("interface "):
                place, line = p.split(" ; ", 1)
                ports.setdefault(place, []).append(line)
        for place, lines in ports.items():
            out += [place, *(f"  {line}" for line in lines)]
        return "\n".join(out) + ("\n" if out else "")

    def _ascii(self, user: str, cmd: str, ident: int) -> dict[str, Any]:
        """A ``cli_ascii`` request: ``show running-config spanning-tree`` and ``show
        running-config``, which the read-only account may run only once its role has
        the rule for it, and ``show logging last <n>``, which any account may."""
        if any(cmd.startswith(prefix) for prefix in self.reject):
            return _error(ident, f"% Rejected by the fake switch: {cmd}\n")
        if cmd == "show sflow":
            if not self._feature_on("sflow"):
                return _error(ident, "% Invalid command at '^' marker.\n")
            return {"jsonrpc": "2.0", "result": {"msg": self.sflow_text()}, "id": ident}
        if cmd == "show hardware access-list tcam region":
            return {"jsonrpc": "2.0", "result": {"msg": self.tcam_regions()}, "id": ident}
        if cmd == "show ip dhcp snooping binding":
            if not self._feature_on("dhcp"):
                return _error(ident, "% Invalid command at '^' marker.\n")
            return {"jsonrpc": "2.0", "result": {"msg": self.binding_text}, "id": ident}
        if re.fullmatch(r"show logging last \d+", cmd):
            wanted = int(cmd.split()[-1])
            lines = self.log_text.splitlines(keepends=True)[-wanted:]
            return {"jsonrpc": "2.0", "result": {"msg": "".join(lines)}, "id": ident}
        known = (
            "show running-config spanning-tree",
            "show running-config",
            "show startup-config",
            "show checkpoint summary",
        )
        if cmd not in known:
            return _error(ident, f"% Not recorded by the fake switch: {cmd}\n")
        if "network-admin" not in self.roles_of(user) and not self._role_matches(user, cmd, None):
            return _error(ident, "% Permission denied for the role\n")
        if cmd == "show startup-config":
            text = self.startup_text if self.startup_text is not None else self._start_config
        elif cmd == "show checkpoint summary":
            text = self.checkpoint_summary()
        else:
            text = self.stp_config() if cmd.endswith("spanning-tree") else self.running_config()
        return {"jsonrpc": "2.0", "result": {"msg": text}, "id": ident}

    def running_config(self) -> str:
        """``show running-config``, with only what the fake switch keeps: the hostname,
        the switch admin lines, the VRFs and their name servers."""
        out = [
            "!Command: show running-config",
            "!Time: Sun Nov  1 10:00:00 2026",
            f"hostname {self.hostname}",
            *self.admin_lines,
        ]
        contexts = ["management", *self.vrfs]
        for vrf in contexts:
            servers = [a for a, v in self.context_name_servers if v == vrf]
            out.append(f"vrf context {vrf}")
            out += [f"  ip name-server {a}" for a in servers]
        places: dict[str, list[str]] = {}
        for path in self.security_lines:
            place, _, line = path.partition(" ; ")
            lines = places.setdefault(place, [])
            if line:
                lines.append(line)
        for place, lines in places.items():
            out += [place, *(f"  {line}" for line in lines)]
        return "\n".join(out) + "\n"

    def __post_init__(self) -> None:
        self._start_config = self.running_config()

    def checkpoint_summary(self) -> str:
        """``show checkpoint summary``, as Cisco's guide shows it."""
        out = ["User Checkpoint Summary", "-" * 80]
        for number, name in enumerate(self.checkpoints, start=1):
            out += [
                f"{number}) {name}:",
                "Created by nxray",
                "Created at Sun, 10:00:00 01 Nov 2026",
                "Size is 1,234 bytes",
                "Description: None",
                "",
            ]
        return "\n".join(out) + "\n"

    def _security(
        self, user: str, is_admin: bool, cmd: str, ident: int, context: tuple[str, str] | None
    ) -> tuple[dict[str, Any], tuple[str, str] | None] | None:
        """An ACL, port security, checkpoint or rollback line, or None when ``cmd`` is
        not one."""
        denied = _error(ident, "% Permission denied for the role\n")
        kind = context[0] if context else None
        if kind is None and (m := re.fullmatch(r"(no )?checkpoint (\S+)", cmd)):
            if not (is_admin or self._role_matches(user, cmd, None)):
                return denied, context
            name = m.group(2)
            if m.group(1):
                if name not in self.checkpoints:
                    return _error(ident, f"% Checkpoint {name} does not exist\n"), context
                del self.checkpoints[name]
                return _ok(ident, None), context
            if name in self.checkpoints:
                return _error(ident, f"% Checkpoint {name} already exists\n"), context
            self.checkpoints[name] = (
                self.hostname,
                list(self.admin_lines),
                list(self.security_lines),
            )
            return _ok(ident, {"msg": "Done\n"}), context
        if kind is None and (m := re.fullmatch(r"rollback running-config checkpoint (\S+)", cmd)):
            if not (is_admin or self._role_matches(user, cmd, None)):
                return denied, context
            if m.group(1) not in self.checkpoints:
                return _error(ident, f"% Checkpoint {m.group(1)} does not exist\n"), context
            if "fail" in self.rollback_text.lower():
                return _ok(ident, self.rollback_text), context
            hostname, admin, security = self.checkpoints[m.group(1)]
            self.hostname, self.admin_lines, self.security_lines = (
                hostname,
                list(admin),
                list(security),
            )
            return _ok(ident, self.rollback_text), context
        if kind is None and (m := re.fullmatch(r"(no )?(ip|ipv6) access-list (\S+)", cmd)):
            if not (is_admin or self._role_matches(user, f"conf t ; {cmd}", None)):
                return denied, context
            place = f"{m.group(2)} access-list {m.group(3)}"
            if m.group(1):
                if place not in self.security_lines:
                    return _error(ident, "% ACL not found\n"), context
                self._record(cmd, self.security_lines)
                return _ok(ident, None), None
            if place not in self.security_lines:
                self.security_lines.append(place)
            return _ok(ident, None), ("acl", place)
        if kind == "acl" and context:
            path = f"{context[1]} ; {cmd}"
            if not (is_admin or self._role_matches(user, f"conf t ; {path}", None)):
                return denied, context
            words = cmd.split()
            if words[0] == "no" and len(words) == 2:
                if not any(
                    p.startswith(f"{context[1]} ; {words[1]} ") for p in self.security_lines
                ):
                    return _error(ident, "% Entry not found\n"), context
            elif words[0].isdigit() and any(
                p.startswith(f"{context[1]} ; {words[0]} ") for p in self.security_lines
            ):
                return _error(ident, "% Duplicate sequence number\n"), context
            self._record(path, self.security_lines)
            return _ok(ident, None), context
        if kind == "interface" and context:
            bare = cmd.removeprefix("no ")
            acl = re.fullmatch(
                r"(?:ip (?:port )?access-group|ipv6 (?:port )?traffic-filter) \S+ (?:in|out)", bare
            )
            port_security = bare == "switchport port-security" or bare.startswith(
                "switchport port-security "
            )
            if not (acl or port_security):
                return None
            if port_security and not self._feature_on("eth-port-sec"):
                return _error(ident, "% Invalid command at '^' marker.\n"), context
            path = f"interface {context[1]} ; {cmd}"
            if not (is_admin or self._role_matches(user, f"conf t ; {path}", context[1])):
                return denied, context
            if not cmd.startswith("no "):
                place = f"interface {context[1]}"
                if place not in self.security_lines:
                    self.security_lines.append(place)
            self._record(path, self.security_lines)
            return _ok(ident, None), context
        return None

    def _layer2(
        self, user: str, is_admin: bool, cmd: str, ident: int, context: tuple[str, str] | None
    ) -> tuple[dict[str, Any], tuple[str, str] | None] | None:
        """A role version 14 line (see the module notes), or None when ``cmd`` is not
        one."""
        denied = _error(ident, "% Permission denied for the role\n")
        invalid = _error(ident, "% Invalid command at '^' marker.\n")
        bare = cmd.removeprefix("no ")
        undo = cmd.startswith("no ")
        kind = context[0] if context else None
        if kind is None and (mode := _LAYER2_MODES.fullmatch(bare)):
            if mode.group(1) == "arp access-list" and not self._feature_on("dhcp"):
                return invalid, context
            if not (is_admin or self._role_matches(user, f"conf t ; {cmd}", None)):
                return denied, context
            if undo:
                if bare not in self.security_lines:
                    return _error(ident, "% Not found\n"), context
                self._record(cmd, self.security_lines)
                return _ok(ident, None), None
            if bare not in self.security_lines:
                self.security_lines.append(bare)
            return _ok(ident, None), ("layer2", bare)
        if kind == "layer2" and context:
            path = f"{context[1]} ; {cmd}"
            if not (is_admin or self._role_matches(user, f"conf t ; {path}", None)):
                return denied, context
            if undo and not any(
                p == f"{context[1]} ; {bare}" or p.startswith(f"{context[1]} ; {bare} ")
                for p in self.security_lines
            ):
                return _error(ident, "% Entry not found\n"), context
            self._record(path, self.security_lines)
            return _ok(ident, None), context
        if kind is None and (top := _LAYER2_TOP.match(bare)):
            if top.group(1) in _NEEDS_DHCP and not self._feature_on("dhcp"):
                return invalid, context
            if not (is_admin or self._role_matches(user, f"conf t ; {cmd}", None)):
                return denied, context
            if bare in _LAYER2_DEFAULT_ON:
                self.security_lines = [p for p in self.security_lines if p != f"no {bare}"]
                if undo:
                    self.security_lines.append(cmd)
            elif bare.startswith("hardware access-list tcam region "):
                region = bare.split()[4]
                self.security_lines = [
                    p
                    for p in self.security_lines
                    if not p.startswith(f"hardware access-list tcam region {region} ")
                ]
                if not undo:
                    self.security_lines.append(bare)
            elif undo:
                if bare not in self.security_lines:
                    return _error(ident, "% Not found\n"), context
                self.security_lines.remove(bare)
            elif bare not in self.security_lines:
                self.security_lines.append(bare)
            return _ok(ident, None), context
        if kind == "interface" and context and (line := _LAYER2_INTERFACE.match(bare)):
            if line.group(1) != "mac port access-group" and not self._feature_on("dhcp"):
                return invalid, context
            path = f"interface {context[1]} ; {cmd}"
            if not (is_admin or self._role_matches(user, f"conf t ; {path}", context[1])):
                return denied, context
            place = f"interface {context[1]}"
            if not undo and place not in self.security_lines:
                self.security_lines.append(place)
            if undo:
                self.security_lines = [p for p in self.security_lines if p != f"{place} ; {bare}"]
            elif f"{place} ; {bare}" not in self.security_lines:
                self.security_lines.append(f"{place} ; {bare}")
            return _ok(ident, None), context
        return None

    def tcam_regions(self) -> str:
        """``show hardware access-list tcam region``, after the shape Cisco's guide
        shows, with the sizes set (the fake switch applies them at once)."""
        sizes = dict(_TCAM_DEFAULTS)
        for path in self.security_lines:
            if path.startswith("hardware access-list tcam region "):
                words = path.split()
                sizes[words[4]] = int(words[5])
        names = dict(_TCAM_NAMES)
        return "".join(f"{names[r]} [{r}] size = {sizes[r]:4}\n" for r in names)

    def _admin(
        self, user: str, is_admin: bool, cmd: str, ident: int, context: tuple[str, str] | None
    ) -> tuple[dict[str, Any], tuple[str, str] | None] | None:
        """A Switch admin line, or None when ``cmd`` is not one."""
        denied = _error(ident, "% Permission denied for the role\n")
        bare = cmd.removeprefix("no ")
        undo = cmd.startswith("no ")
        if context and context[0] == "vrf" and bare.startswith("ip name-server "):
            path = f"conf t ; vrf context {context[1]} ; {cmd}"
            if not (is_admin or self._role_matches(user, path, None)):
                return denied, context
            address = bare.split()[2]
            entry = (address, context[1])
            if undo:
                if entry not in self.context_name_servers:
                    return _error(ident, "% Name server not found\n"), context
                self.context_name_servers.remove(entry)
            elif entry not in self.context_name_servers:
                self.context_name_servers.append(entry)
            return _ok(ident, None), context
        if context is not None:
            return None
        if cmd.startswith("clock set "):
            if not (is_admin or self._role_matches(user, cmd, None)):
                return denied, context
            self.clock_sets.append(cmd.removeprefix("clock set "))
            return _ok(ident, None), context
        if bare.startswith("hostname "):
            if undo or not (is_admin or self._role_matches(user, f"conf t ; {cmd}", None)):
                return denied, context
            self.hostname = bare.split()[1]
            return _ok(ident, None), context
        if bare == "ip domain-lookup":
            if not (is_admin or self._role_matches(user, f"conf t ; {cmd}", None)):
                return denied, context
            self.admin_lines = [line for line in self.admin_lines if line != "no ip domain-lookup"]
            if undo:
                self.admin_lines.append("no ip domain-lookup")
            return _ok(ident, None), context
        key = next((m.group(1) for p in _ADMIN_KEYS if (m := p.match(bare))), None)
        if key is None:
            return None
        if not (is_admin or self._role_matches(user, f"conf t ; {cmd}", None)):
            return denied, context
        if (
            undo
            and not any(line == key or line.startswith(key + " ") for line in self.admin_lines)
            and key not in ("logging console", "logging monitor")
        ):
            return _error(ident, f"% {key} not configured\n"), context
        self.admin_lines = [
            line
            for line in self.admin_lines
            if not (line.removeprefix("no ") == key or line.startswith(key + " "))
        ]
        if undo and key in ("logging console", "logging monitor"):
            self.admin_lines.append(cmd)
        elif not undo:
            self.admin_lines.append(cmd)
        return _ok(ident, None), context

    def _protocol(
        self, user: str, is_admin: bool, cmd: str, ident: int, context: tuple[str, str] | None
    ) -> tuple[dict[str, Any], tuple[str, str] | None] | None:
        """A routing protocol line, or None when ``cmd`` is not one."""
        bare = cmd.removeprefix("no ")
        denied = _error(ident, "% Permission denied for the role\n")
        invalid = _error(ident, "% Invalid command at '^' marker.\n")
        for pattern, feature in _PROTOCOL_MODES:
            if pattern.fullmatch(bare):
                if not self._feature_on(feature):
                    return invalid, None
                if not (is_admin or self._role_matches(user, f"conf t ; {cmd}", None)):
                    return denied, None
                self._record(cmd)
                return _ok(ident, None), None if cmd.startswith("no ") else ("protocol", cmd)
        kind = context[0] if context else None
        if kind in (None, "vrf"):
            for prefix, feature in _PROTOCOL_GLOBAL:
                if bare.startswith(prefix):
                    if not self._feature_on(feature):
                        return invalid, context
                    where = f"vrf context {context[1]} ; " if kind == "vrf" and context else ""
                    if not (is_admin or self._role_matches(user, f"conf t ; {where}{cmd}", None)):
                        return denied, context
                    self._record(f"{where}{cmd}")
                    return _ok(ident, None), context
            return None
        if kind == "interface" and context:
            name = context[1]
            for pattern, feature in _PROTOCOL_INTERFACE:
                if match := pattern.match(bare):
                    needed = (
                        feature
                        or {
                            "ospf": "ospf",
                            "ospfv3": "ospfv3",
                            "eigrp": "eigrp",
                            "rip": "rip",
                            "isis": "isis",
                        }[match.group(1)]
                    )
                    if not self._feature_on(needed):
                        return invalid, context
                    path = f"interface {name} ; {cmd}"
                    if not (is_admin or self._role_matches(user, f"conf t ; {path}", name)):
                        return denied, context
                    self._record(path)
                    if not cmd.startswith("no ") and _GROUP_MODES.fullmatch(cmd):
                        return _ok(ident, None), ("protocol", path)
                    return _ok(ident, None), context
            return None
        if kind == "protocol" and context:
            path = f"{context[1]} ; {cmd}"
            interface = None
            if context[1].startswith("interface "):
                interface = context[1].split(" ; ")[0].removeprefix("interface ")
            if not (is_admin or self._role_matches(user, f"conf t ; {path}", interface)):
                return denied, context
            self._record(path)
            if not cmd.startswith("no ") and _PROTOCOL_SUBMODES.fullmatch(cmd):
                return _ok(ident, None), ("protocol", path)
            return _ok(ident, None), context
        return None

    def _run(
        self, user: str, cmd: str, ident: int, context: tuple[str, str] | None
    ) -> tuple[dict[str, Any], tuple[str, str] | None]:
        if any(cmd.startswith(prefix) for prefix in self.reject):
            # Echoes the whole command, password included, so tests can check
            # NXray never passes a switch error on unscrubbed.
            return _error(ident, f"% Rejected by the fake switch: {cmd}\n"), context
        if ";" in cmd or "?" in cmd:
            return _error(ident, "Request contains invalid special characters"), context
        is_admin = "network-admin" in self.roles_of(user)
        denied = _error(ident, "% Permission denied for the role\n")
        interface = context[1] if context and context[0] == "interface" else None
        vlan = int(context[1]) if context and context[0] == "vlan" else None

        if cmd in self.bodies:
            return _ok(ident, self.bodies[cmd]), context
        if cmd.startswith("show "):
            return self._show(cmd, ident), context
        if protocol_reply := self._protocol(user, is_admin, cmd, ident, context):
            return protocol_reply
        if stp_reply := self._spanning_tree(user, is_admin, cmd, ident, context):
            return stp_reply
        if admin_reply := self._admin(user, is_admin, cmd, ident, context):
            return admin_reply
        if security_reply := self._security(user, is_admin, cmd, ident, context):
            return security_reply
        if layer2_reply := self._layer2(user, is_admin, cmd, ident, context):
            return layer2_reply
        if interface is None and (match := re.fullmatch(r"(no )?sflow (.+)", cmd)):
            rule = "conf t ; no sflow *" if match.group(1) else "conf t ; sflow *"
            if not (is_admin or self._role_allows(user, rule, None)):
                return denied, context
            if not self._feature_on("sflow"):
                return _error(ident, "% Invalid command at '^' marker.\n"), context
            return self._sflow(ident, bool(match.group(1)), match.group(2)), context

        if match := re.fullmatch(r"interface (Ethernet\d+/\d+(?:/\d+)?)", cmd):
            name = match.group(1)
            if name not in self.port_names():
                return _error(ident, "% Invalid interface\n"), None
            if not (is_admin or self._role_allows(user, "interface", name)):
                if self._role_allows(user, "interface", None):
                    # As on cisco-25gb: the role has port rules, but not for this port.
                    return _error(ident, "% Interface permission denied\n"), None
                return denied, None
            return _ok(ident, None), ("interface", name)
        if match := re.fullmatch(r"(no )?interface [Vv]lan ?(\d+)", cmd):
            undo, number = match.group(1), int(match.group(2))
            name = f"Vlan{number}"
            if not self.feature_state.get("interface-vlan", False):
                return _error(ident, "% Invalid command at '^' marker.\n"), None
            rule = "conf t ; no interface Vlan *" if undo else "interface"
            if not (is_admin or self._role_allows(user, rule, name)):
                if self._role_allows(user, "interface", None):
                    return _error(ident, "% Interface permission denied\n"), None
                return denied, None
            if undo:
                if number == 1:
                    return _ok(
                        ident, {"msg": "Warning: Vlan 1 is default vlan and cannot be deleted\n"}
                    ), context
                self.svis.discard(number)
                self.port_state.pop(name, None)
                return _ok(ident, None), context
            if number not in self.svis:
                self.svis.add(number)
                self.port_state[name] = {"routed": True, "admin_up": False}
            return _ok(ident, None), ("interface", name)
        if interface is not None and (
            reply := self._address_command(user, is_admin, cmd, ident, interface)
        ):
            return reply, context
        if interface is not None and (
            reply := self._vrf_member(user, is_admin, cmd, ident, interface)
        ):
            return reply, context
        if match := re.fullmatch(r"(no )?(ip|ipv6) route (\S+) (\S+)", cmd):
            undo, family, prefix, hop = match.groups()
            in_vrf = context[1] if context and context[0] == "vrf" else None
            rule = f"conf t ; {'vrf context * ; ' if in_vrf else ''}{undo or ''}{family} route *"
            if not (is_admin or self._role_allows(user, rule, None)):
                return denied, context
            route = (in_vrf or "default", prefix, hop)
            if undo:
                if route not in self.static_routes:
                    return _error(ident, "% Route not found\n"), context
                self.static_routes.remove(route)
            elif route not in self.static_routes:
                self.static_routes.append(route)
            return _ok(ident, None), context
        if match := re.fullmatch(r"(no )?vrf context (\S+)", cmd):
            undo, name = match.groups()
            rule = "conf t ; no vrf context *" if undo else "vrf context"
            if not (is_admin or self._role_allows(user, rule, None)):
                return denied, None
            if name == "management" and not undo:
                return _ok(ident, None), ("vrf", name)
            if name in ("default", "management"):
                return _error(ident, f"% VRF {name} is reserved\n"), None
            if undo:
                if name not in self.vrfs:
                    return _error(ident, f"% VRF {name} not found\n"), context
                self.vrfs.remove(name)
                self.static_routes = [r for r in self.static_routes if r[0] != name]
                for state in self.port_state.values():
                    if state.get("vrf") == name:
                        _drop_l3(state)
                        state.pop("vrf")
                return _ok(ident, None), context
            if name not in self.vrfs:
                self.vrfs.append(name)
            return _ok(ident, None), ("vrf", name)
        if match := re.fullmatch(r"(no )?interface port-channel(\d+)", cmd):
            undo, number = match.group(1), int(match.group(2))
            name = f"port-channel{number}"
            rule = "conf t ; no interface port-channel *" if undo else "interface"
            if not (is_admin or self._role_allows(user, rule, name)):
                if self._role_allows(user, "interface", None):
                    return _error(ident, "% Interface permission denied\n"), None
                return denied, None
            if undo:
                if number not in self.channels:
                    return _ok(ident, {"msg": f"{name}: port-channel not present\n"}), context
                # As on cisco-25gb: the ports leave the channel with it.
                del self.channels[number]
                self.port_state.pop(name, None)
                return _ok(ident, None), context
            self.channels.setdefault(number, {})
            return _ok(ident, None), ("interface", name)
        if match := re.fullmatch(r"default interface (\S+)", cmd):
            name = match.group(1)
            rule = "conf t ; default interface *"
            if not (is_admin or self._role_allows(user, rule, name)):
                if self._role_allows(user, "interface", None):
                    return _error(ident, "% Interface permission denied\n"), None
                return denied, None
            # As on the switch: back to how it came out of the box.
            self.port_state.pop(name, None)
            return _ok(ident, None), context
        if match := re.fullmatch(r"lacp system-priority (\d+)", cmd):
            if not (is_admin or self._role_allows(user, "conf t ; lacp system-priority *", None)):
                return denied, context
            self.lacp_priority = int(match.group(1))
            return _ok(ident, None), context
        if interface is not None and (
            reply := self._channel_command(user, is_admin, cmd, ident, interface)
        ):
            return reply, context
        if match := _BREAKOUT.fullmatch(cmd):
            undo, module, port, mapping = match.groups()
            rule = (
                "conf t ; no interface breakout module * port * map *"
                if undo
                else "conf t ; interface breakout module * port * map *"
            )
            if not (is_admin or self._role_allows(user, rule, None)):
                return denied, context
            parent = f"Ethernet{module}/{port}"
            if undo:
                if self.breakouts.get(parent) != mapping:
                    return _error(ident, "% Breakout not configured with this map\n"), context
                del self.breakouts[parent]
            elif parent not in ("Ethernet1/50", "Ethernet1/52") or parent in self.breakouts:
                return _error(ident, "% Port does not support breakout\n"), context
            else:
                self.breakouts[parent] = mapping
            for name in list(self.port_state):
                if name == parent or name.startswith(parent + "/"):
                    del self.port_state[name]
            return _ok(ident, None), context
        if interface is not None and (cmd in _INTERFACE_COMMANDS or cmd.startswith("description ")):
            entity = "description *" if cmd.startswith("description ") else cmd
            if not (
                is_admin or self._role_allows(user, f"conf t ; interface * ; {entity}", interface)
            ):
                return denied, context
            state = self.port_state.setdefault(interface, {})
            if cmd == "shutdown":
                state["admin_up"] = False
            elif cmd == "no shutdown":
                state["admin_up"] = True
            elif cmd == "no description":
                state["desc"] = ""
            else:
                state["desc"] = cmd[len("description ") :]
            return _ok(ident, None), context
        if interface is not None:
            for pattern, entity, key in _SETTINGS:
                if match := pattern.fullmatch(cmd):
                    if not (
                        is_admin
                        or self._role_allows(user, f"conf t ; interface * ; {entity}", interface)
                    ):
                        return denied, context
                    return self._setting(ident, interface, cmd, key, match), context
            for pattern, entity, key in _SWITCHPORT:
                if match := pattern.fullmatch(cmd):
                    if not (
                        is_admin
                        or self._role_allows(user, f"conf t ; interface * ; {entity}", interface)
                    ):
                        return denied, context
                    value = match.group(1)
                    self.port_state.setdefault(interface, {})[key] = (
                        "1-4094" if value == "all" else value
                    )
                    return _ok(ident, None), context
        if interface is not None and cmd in _DISCOVERY:
            if not (
                is_admin or self._role_allows(user, f"conf t ; interface * ; {cmd}", interface)
            ):
                return denied, context
            if cmd.removeprefix("no ").startswith("lldp") and not self.lldp:
                # As NX-OS answers a command of a feature that is off.
                return _error(ident, "% Invalid command at '^' marker.\n"), context
            key, value = _DISCOVERY[cmd]
            self.port_state.setdefault(interface, {})[key] = value
            return _ok(ident, None), context
        if match := re.fullmatch(r"mac address-table aging-time (\d+)", cmd):
            rule = "conf t ; mac address-table aging-time *"
            if not (is_admin or self._role_allows(user, rule, None)):
                return denied, context
            self.mac_aging = int(match.group(1))
            return _ok(ident, None), context
        if match := _STATIC_MAC.fullmatch(cmd):
            undo, mac, vlan_text, port = match.groups()
            rule = (
                "conf t ; no mac address-table static *"
                if undo
                else "conf t ; mac address-table static *"
            )
            if not (is_admin or self._role_allows(user, rule, None)):
                return denied, context
            return self._static_mac(ident, bool(undo), mac, vlan_text, port), context
        if match := _CLEAR_MAC.fullmatch(cmd):
            rule = "clear mac address-table dynamic" + (" *" if cmd.count(" ") > 3 else "")
            if not (is_admin or self._role_allows(user, rule, None)):
                return denied, context
            port, mac, mac_vlan, vlan = match.groups()
            self._clear_macs(port, mac, mac_vlan or vlan)
            return _ok(ident, None), context
        if match := re.fullmatch(r"vlan (\d+)", cmd):
            number = int(match.group(1))
            if not (is_admin or self._role_allows(user, "vlan", None)):
                return denied, None
            if number in RESERVED_VLANS:
                return _error(ident, "invalid vlans (reserved values)\n"), None
            self.vlans.setdefault(number, f"VLAN{number:04d}")
            return _ok(ident, None), ("vlan", str(number))
        if vlan is not None and (match := re.fullmatch(r"name (\S+)", cmd)):
            if not (is_admin or self._role_allows(user, "conf t ; vlan * ; name *", None)):
                return denied, context
            self.vlans[vlan] = match.group(1)
            return _ok(ident, None), context
        if match := re.fullmatch(r"no vlan (\d+)", cmd):
            if not (is_admin or self._role_allows(user, "conf t ; no vlan *", None)):
                return denied, context
            number = int(match.group(1))
            if number == 1:
                return _error(ident, "Deletion of VLAN 1 is not allowed!!\n"), context
            self.vlans.pop(number, None)
            return _ok(ident, None), context
        if match := re.fullmatch(r"(no )?feature (.+)", cmd):
            rule = "conf t ; no feature *" if match.group(1) else "conf t ; feature *"
            if not (is_admin or self._role_allows(user, rule, None)):
                return denied, context
            name = _FEATURE_NAMES.get(match.group(2))
            if name is None:
                return _error(ident, f"% Invalid command at '^' marker: {cmd}\n"), context
            if name == "lldp":
                self.lldp = not match.group(1)
            else:
                self.feature_state[name] = not match.group(1)
            if name == "sflow" and match.group(1):
                self.sflow = {}
            if name == "interface-vlan":
                # As on cisco-25gb: on makes Vlan1 (turned off), off removes them all.
                for number in self.svis:
                    self.port_state.pop(f"Vlan{number}", None)
                self.svis = set()
                if not match.group(1):
                    self.svis.add(1)
                    self.port_state["Vlan1"] = {"routed": True, "admin_up": False}
            return _ok(ident, None), context
        if cmd == "copy running-config startup-config":
            if not (is_admin or self._role_allows(user, cmd, None)):
                return denied, context
            if self.save_text is not None:
                return _ok(ident, self.save_text), context
            if self._copying:
                return _error(ident, SAVE_BUSY), context
            self._copying = True
            try:
                time.sleep(self.save_seconds)
            finally:
                self._copying = False
            self.saved = True
            self.startup_text = self.running_config()
            return _ok(ident, None), context
        if not is_admin:
            return denied, context
        if match := re.fullmatch(r"username (\S+) password (\S+) role (\S+)", cmd):
            name, password, role = match.groups()
            if name in self.users:
                # As on cisco-25gb: an existing account gets the new password at
                # once and keeps every role it had; the named role is added.
                primary = self.users[name][1]
                self.users[name] = (password, primary)
                if role != primary:
                    self.extra_roles.setdefault(name, set()).add(role)
            else:
                self.users[name] = (password, role)
            return _ok(ident, None), context
        if match := re.fullmatch(r"username (\S+) password (\S+)", cmd):
            # Shaped after Cisco's NX-OS guides (the role is optional there),
            # not recorded on cisco-25gb: a new password, the roles kept.
            name, password = match.groups()
            if name not in self.users:
                return _error(ident, f"% User {name} does not exist\n"), context
            self.users[name] = (password, self.users[name][1])
            return _ok(ident, None), context
        if match := re.fullmatch(r"no username (\S+) role (\S+)", cmd):
            # Shaped after Cisco's NX-OS guides, not recorded on cisco-25gb.
            name, role = match.groups()
            if name not in self.users:
                return _error(ident, f"% User {name} does not exist\n"), context
            primary = self.users[name][1]
            extra = self.extra_roles.get(name, set())
            if role in extra:
                extra.discard(role)
            elif role == primary and extra:
                # The primary role goes; another one takes its place.
                new_primary = sorted(extra)[0]
                extra.discard(new_primary)
                self.users[name] = (self.users[name][0], new_primary)
            elif role == primary:
                return _error(ident, "% Cannot remove the last role of a user\n"), context
            return _ok(ident, None), context
        if match := re.fullmatch(r"username (\S+) role (\S+)", cmd):
            name, role = match.groups()
            if name not in self.users:
                return _error(ident, f"% User {name} does not exist\n"), context
            if role not in self.roles and role not in BUILTIN_ROLES:
                return _error(ident, "% Role does not exist\n"), context
            self.extra_roles.setdefault(name, set()).add(role)
            return _ok(ident, None), context
        if match := re.fullmatch(r"no username (\S+)", cmd):
            if self.sessions_block_delete and match.group(1) in self.signed_in:
                return _error(ident, f"{match.group(1)} account cannot be deactivated\n"), context
            self.users.pop(match.group(1), None)
            self.extra_roles.pop(match.group(1), None)
            return _ok(ident, None), context
        return _error(ident, f"% Invalid command: {cmd.split()[0]}\n"), context

    def _sflow(self, ident: int, undo: bool, rest: str) -> dict[str, Any]:
        state = self.sflow
        sources = state.setdefault("sources", set())
        if match := re.fullmatch(r"data-source interface ethernet (\d+/\d+(?:/\d+)?)", rest):
            name = f"Ethernet{match.group(1)}"
            if name not in self.port_names():
                return _error(ident, "% Invalid interface\n")
            channel = self.channel_of(name)
            if channel is not None and not undo:
                # As on cisco-25gb: a port-channel's port is sampled only through it.
                return _error(
                    ident,
                    f"ERR sflow data source eth{match.group(1)}(0x1a005000) is already member "
                    f"of a portchannel po{channel}(0x16000028)\n",
                )
            (sources.discard if undo else sources.add)(name)
        elif match := re.fullmatch(r"data-source interface port-channel (\d+)", rest):
            if int(match.group(1)) not in self.channels:
                return _error(ident, "% Invalid interface\n")
            name = f"port-channel{match.group(1)}"
            (sources.discard if undo else sources.add)(name)
        elif match := re.fullmatch(r"sampling-rate (\d+)", rest):
            if not 4096 <= int(match.group(1)) <= 1_000_000_000:
                return _error(ident, "% Invalid number, range is (4096:1000000000)\n")
            state["rate"] = int(match.group(1))
        elif match := re.fullmatch(r"collector-ip (\S+) vrf (\S+)", rest):
            state["collector"], state["vrf"] = match.groups()
        elif match := re.fullmatch(r"collector-port (\d+)", rest):
            state["port"] = int(match.group(1))
        elif match := re.fullmatch(r"agent-ip (\S+)", rest):
            state["agent"] = match.group(1)
        else:
            return _error(ident, f"% Invalid command at '^' marker: sflow {rest}\n")
        return _ok(ident, None)

    def sflow_text(self) -> str:
        """``show sflow`` as Cisco's guide prints it."""
        state = self.sflow
        lines = [
            f"sflow sampling-rate : {state.get('rate', 4096)}",
            "sflow max-sampled-size : 128",
            "sflow counter-poll-interval : 20",
            "sflow max-datagram-size : 1400",
            f"sflow collector-ip : {state.get('collector', '0.0.0.0')} , vrf : "
            f"{state.get('vrf', 'default')}",
            f"sflow collector-port : {state.get('port', 6343)}",
            f"sflow agent-ip : {state.get('agent', '0.0.0.0')}",
        ]
        lines += [
            f"sflow data-source interface {name}" for name in sorted(state.get("sources", ()))
        ]
        return "\n".join(lines) + "\n"

    def _setting(
        self, ident: int, interface: str, cmd: str, key: str | None, match: re.Match[str]
    ) -> dict[str, Any]:
        state = self.port_state.setdefault(interface, {})
        routed = state.get("routed", False)
        if cmd == "switchport":
            if state.get("ip") or state.get("secondaries") or state.get("ipv6"):
                return _error(ident, "ERROR: Remove the IP address first\n")
            state["routed"] = False
        elif cmd == "no switchport":
            state["routed"] = True
        elif cmd.startswith("no storm-control action"):
            state.pop("storm_action", None)
        elif cmd == "no load-interval counter 1":
            state.pop("load_interval", None)
        elif cmd.startswith("no ip address"):
            if state.get("ip") != match.group(1):
                return _error(ident, "% Address not found\n")
            if state.get("secondaries"):
                return _error(ident, "% Remove the secondary addresses first\n")
            state.pop("ip", None)
        elif key == "ip" and not routed:
            return _error(ident, "% IP address not allowed on a switched port\n")
        elif key == "mtu" and not routed and match.group(1) not in ("1500", "9216"):
            return _error(ident, "ERROR: MTU on L2 interfaces can only be 1500 or 9216\n")
        elif key is not None:
            state[key] = match.group(1)
        return _ok(ident, None)

    def _address_command(
        self, user: str, is_admin: bool, cmd: str, ident: int, interface: str
    ) -> dict[str, Any] | None:
        """Extra IPv4 (secondary) and IPv6 addresses; None for any other command."""
        denied = _error(ident, "% Permission denied for the role\n")
        secondary = re.fullmatch(r"(no )?ip address (\S+) secondary", cmd)
        ipv6 = re.fullmatch(r"(no )?ipv6 address (\S+)", cmd)
        match = secondary or ipv6
        if match is None:
            return None
        undo, address = match.groups()
        entity = "ipv6 address *" if ipv6 else "ip address *"
        if undo:
            entity = "no " + entity
        if not (is_admin or self._role_allows(user, f"conf t ; interface * ; {entity}", interface)):
            return denied
        state = self.port_state.setdefault(interface, {})
        if not state.get("routed"):
            return _error(ident, "% IP address not allowed on a switched port\n")
        key = "ipv6" if ipv6 else "secondaries"
        if secondary and not undo and not state.get("ip"):
            return _error(ident, "% Configure the primary address first\n")
        found = state.setdefault(key, [])
        if undo:
            if address not in found:
                return _error(ident, "% Address not found\n")
            found.remove(address)
        elif address not in found:
            found.append(address)
        return _ok(ident, None)

    def _vrf_member(
        self, user: str, is_admin: bool, cmd: str, ident: int, interface: str
    ) -> dict[str, Any] | None:
        """``vrf member <name>`` and its ``no`` form; None for any other command."""
        match = re.fullmatch(r"(no )?vrf member (\S+)", cmd)
        if match is None:
            return None
        undo, name = match.groups()
        entity = "no vrf member *" if undo else "vrf member *"
        if not (is_admin or self._role_allows(user, f"conf t ; interface * ; {entity}", interface)):
            return _error(ident, "% Permission denied for the role\n")
        state = self.port_state.setdefault(interface, {})
        if not state.get("routed"):
            return _error(ident, "% Configure layer 3 on the interface first\n")
        if undo:
            if state.get("vrf", "default") != name:
                return _error(ident, f"% {interface} is not a member of VRF {name}\n")
            state.pop("vrf", None)
        else:
            if name not in self.vrfs:
                return _error(ident, f"% VRF {name} does not exist\n")
            state["vrf"] = name
        _drop_l3(state)
        return _ok(ident, {"msg": f"Warning: Deleted all L3 config on interface {interface}\n"})

    def vrf_of(self, name: str) -> str:
        return self.port_state.get(name, {}).get("vrf", "default")

    def vrf_table(self) -> dict[str, Any]:
        """``show vrf``, shaped as recorded on cisco-25gb."""
        names = ["default", "management", *self.vrfs]
        found = [
            {"vrf_name": n, "vrf_id": i, "vrf_state": "Up", "vrf_reason": "--"}
            for i, n in enumerate(names, 1)
        ]
        return {"TABLE_vrf": {"ROW_vrf": found}}

    def vrf_interfaces(self) -> dict[str, Any]:
        """``show vrf interface``: the VLAN interfaces, mgmt0 and the routed ports."""
        ids = {n: i for i, n in enumerate(["default", "management", *self.vrfs], 1)}
        names = [f"Vlan{n}" for n in sorted(self.svis)]
        found: list[dict[str, Any]] = [{"if_name": n, "vrf_name": self.vrf_of(n)} for n in names]
        found.append({"if_name": "mgmt0", "vrf_name": "management"})
        for name, state in sorted(self.port_state.items(), key=lambda item: _port_key(item[0])):
            if state.get("routed") and name.startswith("Ethernet"):
                found.append({"if_name": name, "vrf_name": self.vrf_of(name)})
        for row in found:
            row.update(vrf_id=ids[row["vrf_name"]], soo="--")
        return {"TABLE_if": {"ROW_if": found}}

    def ipv4_static(self) -> dict[str, Any]:
        """``show ip static-route vrf all``, shaped as recorded on cisco-25gb; a route is
        installed when an interface in its VRF has an address in the next hop's network."""

        def installed(vrf: str, hop: str) -> bool:
            if vrf == "management":
                return True
            for name, state in self.port_state.items():
                if state.get("routed") and self.vrf_of(name) == vrf and state.get("ip"):
                    if ipaddress.ip_address(hop) in ipaddress.ip_interface(state["ip"]).network:
                        return True
            return False

        found = []
        for vrf in ["default", "management", *self.vrfs]:
            routes = [r for r in self.static_routes if r[0] == vrf and ":" not in r[1]]
            if not routes:
                continue
            rows = [
                {
                    "prefix_addr_msk": prefix,
                    "nhop_addr_msk": f"{hop}/32",
                    "nhop_vrf_info": "",
                    "nhop_intr_info": "",
                    "urib_stat": "    (installed in urib)"
                    if installed(vrf, hop)
                    else "    (not installed in urib)",
                    "nhop_urib_stat": "    rnh(installed in urib)",
                }
                for _, prefix, hop in routes
            ]
            found.append(
                {
                    "cntxt_name": vrf,
                    "TABLE_each_vrf": {"ROW_each_vrf": rows[0] if len(rows) == 1 else rows},
                }
            )
        return {"TABLE_vrf_all": {"ROW_vrf_all": found}} if found else {}

    def ipv6_static(self) -> dict[str, Any]:
        """``show ipv6 static-route vrf all``, shaped as recorded: a list of tables."""
        routes = [
            {"ROW_route": {"prefix-out": prefix, "next-hop": f"{hop}/128", "pref": 1,
                           "next-hop-vrf": vrf}}
            for vrf, prefix, hop in self.static_routes
            if ":" in prefix
        ]  # fmt: skip
        vrfs = [{"ROW_vrf": {"vrf-name-out": v}} for v in ["default", "management", *self.vrfs]]
        return {"TABLE_route": routes, "TABLE_vrf": vrfs} if routes else {"TABLE_vrf": vrfs}

    def _channel_command(
        self, user: str, is_admin: bool, cmd: str, ident: int, interface: str
    ) -> dict[str, Any] | None:
        """The port-channel and LACP commands inside an interface; None for any other."""
        denied = _error(ident, "% Permission denied for the role\n")
        checks = (
            (
                re.fullmatch(r"channel-group (\d+)(?: mode (active|passive|on))?", cmd),
                "channel-group *",
            ),
            (re.fullmatch(r"no channel-group", cmd), "no channel-group"),
            (re.fullmatch(r"lacp rate (normal|fast)", cmd), "lacp rate *"),
            (re.fullmatch(r"lacp port-priority (\d+)", cmd), "lacp port-priority *"),
            (re.fullmatch(r"lacp min-links (\d+)", cmd), "lacp min-links *"),
        )
        for match, entity in checks:
            if match is None:
                continue
            if not (
                is_admin or self._role_allows(user, f"conf t ; interface * ; {entity}", interface)
            ):
                return denied
            state = self.port_state.setdefault(interface, {})
            current = self.channel_of(interface)
            if entity == "channel-group *":
                number, mode = int(match.group(1)), match.group(2) or "on"
                if mode != "on" and not self.lacp_on():
                    return _error(ident, "% LACP is not enabled\n")
                if current is not None and current != number:
                    return _error(ident, f"{interface} is already in port-channel{current}\n")
                members = self.channels.setdefault(number, {})
                if any(other != mode for port, other in members.items() if port != interface):
                    return _error(
                        ident,
                        "Port-channel mode cannot be changed in a non-empty port-channel, and "
                        "port mode must match with port-channel mode\n",
                    )
                members[interface] = mode
            elif entity == "no channel-group":
                if current is not None:
                    del self.channels[current][interface]
            elif entity == "lacp rate *":
                if current is not None and state.get("admin_up", True):
                    return _error(
                        ident, "Cannot set lacp rate. Port is not admin down in port-channel\n"
                    )
                state["lacp_rate"] = match.group(1)
            elif entity == "lacp port-priority *":
                state["lacp_priority"] = int(match.group(1))
            else:
                state["min_links"] = int(match.group(1))
            return _ok(ident, None)
        return None

    def lacp_on(self) -> bool:
        return self.feature_state.get("lacp", True)

    def channel_of(self, port: str) -> int | None:
        return next((n for n, members in self.channels.items() if port in members), None)

    def channel_summary(self) -> dict[str, Any]:
        """``show port-channel summary`` for ``channels``: port-channel43's two ports as
        recorded (up), any other port down (nothing is plugged in)."""
        recorded = {
            m["port"]: m["port-status"]
            for m in load_fixture("show_port_channel_summary")["TABLE_channel"]["ROW_channel"][
                "TABLE_member"
            ]["ROW_member"]
        }
        found = []
        for number, members in sorted(self.channels.items()):
            rows = [
                {"port": port, "port-status": recorded.get(port, "D") if number == 43 else "D"}
                for port in sorted(members, key=_port_key)
            ]
            row: dict[str, Any] = {
                "group": str(number),
                "port-channel": f"port-channel{number}",
                "layer": "S",
                "status": "U" if any(r["port-status"] == "P" for r in rows) else "D",
                "type": "Eth",
                "prtcl": "LACP" if any(m != "on" for m in members.values()) else "NONE",
            }
            if rows:
                row["TABLE_member"] = {"ROW_member": rows[0] if len(rows) == 1 else rows}
            found.append(row)
        if not found:
            return {}
        return {"TABLE_channel": {"ROW_channel": found[0] if len(found) == 1 else found}}

    def channel_database(self) -> dict[str, Any]:
        found = []
        for number, members in sorted(self.channels.items()):
            rows = [
                {"port": p, "mode": m, "port-status": "down"} for p, m in sorted(members.items())
            ]
            row: dict[str, Any] = {
                "interface": f"port-channel{number}",
                "total-ports": str(len(rows)),
            }
            if rows:
                row["TABLE_member"] = {"ROW_member": rows[0] if len(rows) == 1 else rows}
            found.append(row)
        if not found:
            return {}
        return {"TABLE_interface": {"ROW_interface": found[0] if len(found) == 1 else found}}

    def descriptions(self) -> dict[str, Any]:
        """``show interface description``: the recorded ports, then the port-channels."""
        rows = [
            dict(row)
            for row in load_fixture("show_interface_description")["TABLE_interface"][
                "ROW_interface"
            ]
            if not row["interface"].startswith("port-channel")
        ]
        for row in rows:
            desc = self.port_state.get(row["interface"], {}).get("desc")
            if desc is not None:
                row.pop("desc", None)
                if desc:
                    row["desc"] = desc
        for number in sorted(self.channels):
            name = f"port-channel{number}"
            row = {"interface": name}
            desc = self.port_state.get(name, {}).get(
                "desc", "storage-server" if number == 43 else ""
            )
            if desc:
                row["desc"] = desc
            rows.append(row)
        for svi in self.svi_rows():
            row = {"interface": svi["interface"]}
            if svi.get("svi_desc"):
                row["desc"] = svi["svi_desc"]
            rows.append(row)
        return {"TABLE_interface": {"ROW_interface": rows}}

    def lacp_interfaces(self) -> dict[str, Any]:
        body = load_fixture("show_lacp_interface")
        for row in body["TABLE_lacp_intf"]["ROW_lacp_intf"]:
            state = self.port_state.get(row["interface"], {})
            if "lacp_rate" in state:
                row["localport"]["local-timeout"] = (
                    "Short" if state["lacp_rate"] == "fast" else "Long"
                )
            if "lacp_priority" in state:
                row["localport"]["local-port-priority"] = hex(state["lacp_priority"])
        return body

    def lacp_neighbors(self) -> dict[str, Any]:
        """The recorded neighbor of port-channel43's ports, while they are still in it."""
        body = load_fixture("show_lacp_neighbor")
        channel = body["TABLE_interface"]["ROW_interface"]
        members = channel["TABLE_member"]["ROW_member"]
        kept = [m for m in members if m["port"] in self.channels.get(43, {})]
        if not kept:
            return {}
        channel["TABLE_member"]["ROW_member"] = kept[0] if len(kept) == 1 else kept
        return body

    def macs(self) -> list[dict[str, Any]]:
        """The MAC address table's rows, starting from the recorded ones."""
        if self.mac_rows is None:
            self.mac_rows = list(
                load_fixture("show_mac_address_table")["TABLE_mac_address"]["ROW_mac_address"]
            )
        return self.mac_rows

    def _static_mac(
        self, ident: int, undo: bool, mac: str, vlan_text: str, port: str | None
    ) -> dict[str, Any]:
        vlan = int(vlan_text)
        if vlan not in self.vlans:
            return _error(ident, f"ERROR: vlan {vlan} not configured\n")
        rows = self.macs()
        found = [
            row
            for row in rows
            if row["disp_mac_addr"] == mac
            and row["disp_vlan"] == str(vlan)
            and row["disp_type"] == "static"
        ]
        if undo:
            if not found:
                return _error(ident, "ERROR: Entry does not exist\n")
            rows.remove(found[0])
            return _ok(ident, None)
        if port is not None and port not in self.port_names():
            return _error(ident, "% Invalid interface\n")
        # A static entry replaces what was learned for the address in that VLAN.
        self.mac_rows = [
            row
            for row in rows
            if not (row["disp_mac_addr"] == mac and row["disp_vlan"] == str(vlan))
        ]
        self.mac_rows.append(
            {
                "disp_mac_addr": mac,
                "disp_type": "static",
                "disp_vlan": str(vlan),
                "disp_age": "-",
                "disp_is_secure": "F",
                "disp_is_ntfy": "F",
                # How a dropped entry shows is a guess: never seen on cisco-25gb.
                "disp_port": port.replace("Ethernet", "Eth") if port else "Drop",
            }
        )
        return _ok(ident, None)

    def _clear_macs(self, port: str | None, mac: str | None, vlan: str | None) -> None:
        short = port.replace("Ethernet", "Eth") if port else None

        def cleared(row: dict[str, Any]) -> bool:
            if row["disp_type"] != "dynamic":
                return False
            if short is not None and row["disp_port"] != short:
                return False
            if mac is not None and row["disp_mac_addr"] != mac:
                return False
            return vlan is None or row["disp_vlan"] == vlan

        self.mac_rows = [row for row in self.macs() if not cleared(row)]

    def discovery(self, name: str, protocol: str) -> dict[str, Any]:
        """``show cdp interface <port>`` (as recorded) or ``show lldp interface <port>``
        (shaped after Cisco's guides, never seen on cisco-25gb)."""
        state = self.port_state.get(name, {})
        if protocol == "cdp":
            row = dict(load_fixture("show_cdp_interface")["TABLE_cdp_all"]["ROW_cdp_all"])
            row["intf_id"] = name
            row["cdp_intf_enabled"] = "enabled" if state.get("cdp", True) else "disabled"
            return {"TABLE_cdp_all": {"ROW_cdp_all": row}}
        return {
            "TABLE_interface": {
                "ROW_interface": {
                    "interface": name,
                    "tx_enabled": "TRUE" if state.get("lldp_transmit", True) else "FALSE",
                    "rx_enabled": "TRUE" if state.get("lldp_receive", True) else "FALSE",
                }
            }
        }

    def port_names(self) -> list[str]:
        """Every Ethernet port, with split ports listed as their four parts."""
        names = [row["interface"] for row in self._expand(load_fixture("show_interface_status"))]
        return [name for name in names if name.startswith("Ethernet")]

    def _expand(self, body: dict[str, Any]) -> list[dict[str, Any]]:
        """A body's rows, a split port's row replaced by four renamed copies."""
        found = []
        for row in body["TABLE_interface"]["ROW_interface"]:
            mapping = self.breakouts.get(row.get("interface", ""))
            if mapping is None:
                found.append(row)
                continue
            for part in range(1, 5):
                copy = dict(row, interface=f"{row['interface']}/{part}")
                if "speed" in copy:
                    copy["speed"] = "25G" if mapping == "25g-4x" else "10G"
                if "eth_bw" in copy:
                    copy["eth_bw"] = 25_000_000 if mapping == "25g-4x" else 10_000_000
                found.append(copy)
        body["TABLE_interface"]["ROW_interface"] = found
        return found

    def _row_for(self, fixture: str, name: str, template: str) -> dict[str, Any]:
        """One port's row from a recorded all-ports body; a split port's from its parent."""
        rows = load_fixture(fixture)["TABLE_interface"]["ROW_interface"]
        by_name = {row["interface"]: row for row in rows}
        row = by_name.get(name) or by_name.get(name.rsplit("/", 1)[0]) or by_name[template]
        return dict(row, interface=name)

    def capabilities(self, name: str) -> dict[str, Any]:
        """``show interface <port> capabilities``, from the two recorded kinds."""
        base = name.rsplit("/", 1)[0] if name.count("/") == 2 else name
        fixture = (
            "show_interface_capabilities_qsfp"
            if base in ("Ethernet1/50", "Ethernet1/52") and base == name
            else "show_interface_capabilities_sfp"
        )
        row = dict(load_fixture(fixture)["TABLE_interface"]["ROW_interface"], interface=name)
        if name.count("/") == 2:
            row["speed"] = "10000,25000"
        return {"TABLE_interface": {"ROW_interface": row}}

    def flowcontrol(self, name: str) -> dict[str, Any]:
        row = self._row_for("show_interface_flowcontrol", name, "Ethernet1/1")
        state = self.port_state.get(name, {})
        if "flow_receive" in state:
            row["recv_admin"] = row["recv_oper"] = state["flow_receive"]
        if "flow_send" in state:
            row["send_admin"] = row["send_oper"] = state["flow_send"]
        return {"TABLE_interface": {"ROW_interface": row}}

    def storm_control(self, name: str) -> dict[str, Any]:
        row = self._row_for("show_interface_counters_storm_control", name, "Ethernet1/1")
        state = self.port_state.get(name, {})
        for key, field_name in (
            ("storm_broadcast", "eth_bcast_supp"),
            ("storm_multicast", "eth_mcast_supp"),
            ("storm_unicast", "eth_ucast_supp"),
        ):
            if key in state:
                row[field_name] = state[key]
        if "storm_action" in state:
            row["supp_action"] = f"[{state['storm_action']}]"
        return {"TABLE_interface": {"ROW_interface": row}}

    def ip_interfaces(self) -> dict[str, Any]:
        """``show ip interface vrf all``: mgmt0 as recorded, plus routed ports with an address."""
        body = load_fixture("show_ip_interface_vrf_all")
        rows = [body["TABLE_intf"]["ROW_intf"]]
        for name, state in sorted(self.port_state.items()):
            if state.get("routed") and state.get("ip"):
                address, _, masklen = state["ip"].partition("/")
                row: dict[str, Any] = {
                    "vrf-name-out": state.get("vrf", "default"),
                    # Written short, as NX-OS writes port names here.
                    "intf-name": name.replace("Ethernet", "Eth"),
                    "prefix": address,
                    "masklen": int(masklen),
                    "mtu": int(state.get("mtu", 1500)),
                }
                extra = []
                for text in state.get("secondaries", []):
                    prefix, _, length = text.partition("/")
                    extra.append({"prefix1": prefix, "masklen1": int(length)})
                if extra:
                    row["TABLE_secondary_address"] = {
                        "ROW_secondary_address": extra[0] if len(extra) == 1 else extra
                    }
                rows.append(row)
        return {"TABLE_intf": {"ROW_intf": rows[0] if len(rows) == 1 else rows}}

    def ipv6_interfaces(self) -> dict[str, Any]:
        """``show ipv6 interface vrf all``, shaped as recorded on cisco-25gb."""
        rows = []
        for name, state in sorted(self.port_state.items()):
            if state.get("routed") and state.get("ipv6"):
                addresses = [{"addr": a} for a in state["ipv6"]]
                rows.append(
                    {
                        "vrf-name-out": state.get("vrf", "default"),
                        "intf-name": name,
                        "prefix": state["ipv6"][0],
                        "linklocal-addr": "fe80::7279:b3ff:fe00:1",
                        "mtu": int(state.get("mtu", 1500)),
                        "TABLE_addr": {
                            "ROW_addr": addresses[0] if len(addresses) == 1 else addresses
                        },
                    }
                )
        if not rows:
            return {}
        return {"TABLE_intf": {"ROW_intf": rows[0] if len(rows) == 1 else rows}}

    def svi_rows(self) -> list[dict[str, Any]]:
        """The VLAN interfaces as ``show interface vlan<n>`` writes them."""
        found = []
        for number in sorted(self.svis):
            state = self.port_state.get(f"Vlan{number}", {})
            up = state.get("admin_up", False)
            row: dict[str, Any] = {
                "interface": f"Vlan{number}",
                "svi_admin_state": "up" if up else "down",
                "svi_line_proto": "up" if up and number in self.vlans else "down",
                "svi_mtu": str(state.get("mtu", 1500)),
            }
            if not up:
                row["svi_rsn_desc"] = "Administratively down"
            if state.get("desc"):
                row["svi_desc"] = state["desc"]
            found.append(row)
        return found

    def switchports(self) -> dict[str, Any]:
        """``show interface switchport`` with the VLAN settings changed so far."""
        body = load_fixture("show_interface_switchport")
        for row in self._expand(body):
            state = self.port_state.get(row["interface"], {})
            if state.get("routed"):
                row["switchport"] = "Disabled"
            if "mode" in state:
                row["oper_mode"] = state["mode"]
            if "access" in state:
                row["access_vlan"] = state["access"]
            if "native" in state:
                row["native_vlan"] = state["native"]
            if "allowed" in state:
                row["trunk_vlans"] = state["allowed"]
        return body

    def vlan_brief(self) -> dict[str, Any]:
        """``show vlan brief`` for ``vlans``; ports listed as the switch lists them."""
        ports = self.switchports()["TABLE_interface"]["ROW_interface"]
        rows = []
        for number, name in sorted(self.vlans.items()):
            members = []
            for port in ports:
                if port["oper_mode"] == "access" and int(port["access_vlan"]) == number:
                    members.append(port["interface"])
                elif port["oper_mode"] == "trunk" and number in _vlan_numbers(port["trunk_vlans"]):
                    members.append(port["interface"])
            row = {
                "vlanshowbr-vlanid": str(number),
                "vlanshowbr-vlanid-utf": str(number),
                "vlanshowbr-vlanname": name,
                "vlanshowbr-vlanstate": "active",
                "vlanshowbr-shutstate": "noshutdown",
            }
            if members:
                row["vlanshowplist-ifidx"] = ",".join(members)
            rows.append(row)
        return {
            "TABLE_vlanbriefxbrief": {"ROW_vlanbriefxbrief": rows[0] if len(rows) == 1 else rows}
        }

    def features(self) -> dict[str, Any]:
        """``show feature`` as recorded, with lldp on or off as ``lldp`` says and the
        others as ``feature_state`` says."""
        body = load_fixture("show_feature_full")
        for row in body["TABLE_cfcFeatureCtrlTable"]["ROW_cfcFeatureCtrlTable"]:
            name = row["cfcFeatureCtrlName2"]
            on = self.lldp if name == "lldp" else self.feature_state.get(name)
            if on is not None:
                row["cfcFeatureCtrlOpStatus2"] = "enabled" if on else "disabled"
        return body

    def _show(self, cmd: str, ident: int) -> dict[str, Any]:
        if cmd == "show feature":
            return _ok(ident, self.features())
        if cmd == "show port-channel summary":
            return _ok(ident, self.channel_summary())
        if cmd == "show port-channel database":
            return _ok(ident, self.channel_database())
        if cmd == "show interface description":
            return _ok(ident, self.descriptions())
        if cmd.startswith("show lacp"):
            if not self.lacp_on():
                return _error(ident, "% Invalid command\n")
            if cmd == "show lacp system-identifier":
                return _ok(
                    ident,
                    {"system-priority": str(self.lacp_priority), "system-mac": "70-79-b3-00-00-01"},
                )
            if cmd == "show lacp interface":
                return _ok(ident, self.lacp_interfaces())
            if cmd == "show lacp neighbor":
                return _ok(ident, self.lacp_neighbors())
        if cmd.startswith("show lldp"):
            if not self.lldp:
                return _error(ident, "% Invalid command\n")
            if cmd == "show lldp neighbors detail":
                return _ok(ident, load_fixture("show_lldp_neighbors_detail"))
        if match := re.fullmatch(r"show (cdp|lldp) interface (Ethernet\S+)", cmd):
            protocol, name = match.groups()
            if name not in self.port_names():
                return _error(ident, "% Invalid interface format\n")
            return _ok(ident, self.discovery(name, protocol))
        if cmd == "show mac address-table":
            rows = self.macs()
            body = {"TABLE_mac_address": {"ROW_mac_address": rows[0] if len(rows) == 1 else rows}}
            return _ok(ident, body if rows else {})
        if cmd == "show mac address-table aging-time":
            return _ok(ident, {"age_str": "Aging Time\n----------\n", "age": str(self.mac_aging)})
        port_show = re.fullmatch(
            r"show interface (Ethernet\S+) (capabilities|flowcontrol|counters storm-control)", cmd
        )
        if port_show:
            name, what = port_show.groups()
            if name not in self.port_names():
                return _error(ident, "% Invalid interface format\n")
            if what == "capabilities":
                return _ok(ident, self.capabilities(name))
            if what == "flowcontrol":
                return _ok(ident, self.flowcontrol(name))
            return _ok(ident, self.storm_control(name))
        if cmd == "show vrf":
            return _ok(ident, self.vrf_table())
        if cmd == "show vrf interface":
            return _ok(ident, self.vrf_interfaces())
        if cmd == "show ip static-route vrf all":
            return _ok(ident, self.ipv4_static())
        if cmd == "show ipv6 static-route vrf all":
            return _ok(ident, self.ipv6_static())
        if cmd == "show ip interface vrf all":
            return _ok(ident, self.ip_interfaces())
        if cmd == "show ipv6 interface vrf all":
            return _ok(ident, self.ipv6_interfaces())
        if match := re.fullmatch(r"show interface vlan(\d+)", cmd):
            row = next(
                (r for r in self.svi_rows() if r["interface"] == f"Vlan{match.group(1)}"), None
            )
            if row is None:
                return _error(ident, "% Invalid interface format\n")
            return _ok(ident, {"TABLE_interface": {"ROW_interface": row}})
        if cmd == "show interface brief":
            body = load_fixture("show_interface_brief")
            for row in self._expand(body):
                state = self.port_state.get(row["interface"], {})
                if state.get("admin_up") is False:
                    row.update(state="down", state_rsn_desc="Administratively down")
                if state.get("routed") and row["interface"].startswith("Ethernet"):
                    row.update(portmode="routed", vlan="--")
            for svi in self.svi_rows():
                row = {"interface": svi["interface"], "svi_admin_state": svi["svi_admin_state"]}
                if "svi_rsn_desc" in svi:
                    row["svi_rsn_desc"] = svi["svi_rsn_desc"]
                body["TABLE_interface"]["ROW_interface"].append(row)
            return _ok(ident, body)
        if cmd == "show interface status":
            body = load_fixture("show_interface_status")
            for row in self._expand(body):
                speed = self.port_state.get(row["interface"], {}).get("speed")
                if speed is not None:
                    row["speed"] = _STATUS_SPEED.get(speed, f"{int(speed) // 1000}G")
            return _ok(ident, body)
        if cmd in _RECORDED:
            return _ok(ident, load_fixture(_RECORDED[cmd]))
        if cmd == "show interface":
            body = load_fixture("show_interface")
            for row in self._expand(body):
                state = self.port_state.get(row["interface"], {})
                if "mtu" in state:
                    row["eth_mtu"] = state["mtu"]
                if "fec" in state:
                    row["eth_admin_fec_state"] = state["fec"]
                if "load_interval" in state:
                    row["eth_load_interval1_rx"] = state["load_interval"]
                    row["eth_load_interval1_tx"] = state["load_interval"]
                if "desc" in state:
                    if state["desc"]:
                        row["desc"] = state["desc"]
                    else:
                        row.pop("desc", None)
                if state.get("admin_up") is False:
                    row.update(
                        admin_state="down", state="down", state_rsn_desc="Administratively down"
                    )
                elif state.get("admin_up") is True:
                    row["admin_state"] = "up"
            return _ok(ident, body)
        if cmd == "show interface switchport":
            return _ok(ident, self.switchports())
        if cmd == "show interface snmp-ifindex":
            # Every switchport's ifIndex as the switch numbers them: 0x1a000000
            # plus 512 for each port, and Po41 after the Ethernet ports.
            names = [
                row["interface"] for row in self.switchports()["TABLE_interface"]["ROW_interface"]
            ]
            table = [
                {"interface": name, "snmp-ifindex": str(0x1A000000 + 512 * number)}
                for number, name in enumerate(names)
            ]
            return _ok(ident, {"TABLE_interface": {"ROW_interface": table}})
        if cmd == "show vlan brief":
            return _ok(ident, self.vlan_brief())
        if cmd == "show hostname":
            return _ok(ident, {"hostname": self.hostname})
        if cmd == "show nxapi":
            return _ok(ident, {"nxapi_status": "nxapi enabled", "timeout": "10"})
        if cmd == "show role":
            names = [*BUILTIN_ROLES, *sorted(self.roles)]
            table = [{"role_name": name, "role_description": ""} for name in names]
            return _ok(ident, {"TABLE_role": {"ROW_role": table}})
        if cmd == "show user-account":
            rows = []
            for name in self.users:
                roles = [{"role": role} for role in sorted(self.roles_of(name))]
                rows.append(
                    {
                        "usr_name": name,
                        # One row is an object, several a list, as on the switch.
                        "TABLE_role": {"ROW_role": roles[0] if len(roles) == 1 else roles},
                    }
                )
            return _ok(
                ident, {"TABLE_template": {"ROW_template": rows[0] if len(rows) == 1 else rows}}
            )
        for name in (cmd.replace(" ", "_"), cmd.replace(" ", "_") + "_doc"):
            # The routing protocols' show commands, as recorded on cisco-25gb
            # (or, for neighbors never seen live, shaped after Cisco's docs).
            if FIXTURES.joinpath(name + ".json").exists():
                return _ok(ident, load_fixture(name))
        return _error(ident, "% Invalid command\n")

    # ---- SSH ----------------------------------------------------------------

    def ssh_opener(self):
        """An opener for app.state.ssh_opener (see app/switch_ssh.py)."""

        def opener(host: str, port: int, username: str, password: str, timeout: float):
            if not self.ssh_reachable:
                raise SshUnreachable(f"could not open SSH to {host}:{port}: refused")
            known = self.users.get(username)
            if not known or known[0] != password:
                raise SshAuthError("the switch refused the SSH username or password")
            return FakeShell(self, username)

        return opener


class FakeShell:
    """The pretend switch's command line, for the lines NXray types over SSH."""

    def __init__(self, switch: FakeSwitch, user: str = "admin") -> None:
        self.switch = switch
        self.user = user
        self.dont_ask = False
        self.mode: list[str] = []  # e.g. ["config", "role", "role-interface"]
        self.role: Role | None = None
        self.closed = False

    def run(self, line: str) -> str:
        self.switch.ssh_lines.append(line)
        invalid = "% Invalid command at '^' marker."
        if any(line.startswith(prefix) for prefix in self.switch.ssh_reject):
            return invalid
        if not self.mode and line == "terminal dont-ask":
            self.dont_ask = True
            return ""
        if not self.mode and line == "reload":
            # As NX-OS: only network-admin may; without terminal dont-ask it asks
            # first (and the pretend shell, like NXray's, hears no answer).
            if "network-admin" not in self.switch.roles_of(self.user):
                return "% Permission denied for the role"
            if not self.dont_ask:
                raise SshUnreachable("the switch stopped answering over SSH within 30 seconds")
            self.switch.reloads += 1
            self.switch.saved_at_reload.append(self.switch.saved)
            raise SshUnreachable("the switch closed the SSH session")
        if line == "configure terminal":
            self.mode = ["config"]
            return "Enter configuration commands, one per line.  End with CNTL/Z."
        if line == "end":
            self.mode = []
            return ""
        if not self.mode and (match := re.fullmatch(r"show user-account (\S+)", line)):
            name = match.group(1)
            if name not in self.switch.users:
                return ""
            roles = " ".join(sorted(self.switch.roles_of(name)))
            return f"user:{name}\n\tthis user account has no expiry date\n\troles:{roles}"
        if not self.mode and line == "copy running-config startup-config":
            if self.switch.save_text is not None:
                return self.switch.save_text.strip()
            self.switch.saved = True
            return "Copy complete, now saving to disk (please wait)...\nCopy complete."
        if line == "exit":
            if self.mode:
                self.mode.pop()
            return ""
        current = self.mode[-1] if self.mode else ""
        if current == "config":
            if match := re.fullmatch(r"role name (\S+)", line):
                self.role = self.switch.roles.setdefault(match.group(1), Role())
                self.mode.append("role")
                return ""
            if match := re.fullmatch(r"username (\S+) role (\S+)", line):
                name, role = match.groups()
                if name not in self.switch.users:
                    return f"% User {name} does not exist"
                if role not in self.switch.roles:
                    return "% Role does not exist"
                self.switch.extra_roles.setdefault(name, set()).add(role)
                return ""
        if current == "role" and self.role is not None:
            if line.startswith("description "):
                return ""
            if match := re.fullmatch(r"rule \d+ permit command (.+)", line):
                self.role.entities.add(match.group(1))
                return ""
            if line == "interface policy deny":
                self.role.interface_policy_deny = True
                self.mode.append("role-interface")
                return ""
        if current == "role-interface" and self.role is not None:
            if match := re.fullmatch(r"permit interface (\S+)", line):
                name = match.group(1).lower()
                if name.startswith("vlan") and not self.switch.feature_state.get(
                    "interface-vlan", False
                ):
                    # As on cisco-25gb: the Vlan type exists only while the feature is on.
                    return "% Invalid interface format at '^' marker."
                if (
                    self.switch.freeze_on_channel_permit
                    and name.startswith("port-channel")
                    and name not in self.role.interfaces
                ):
                    self.switch.nxapi_frozen = True
                self.role.interfaces.add(name)
                return ""
        return invalid

    def close(self) -> None:
        self.closed = True


def _drop_l3(state: dict[str, Any]) -> None:
    """What the switch deletes from an interface whose VRF changes: its addresses."""
    for key in ("ip", "secondaries", "ipv6"):
        state.pop(key, None)


def _port_key(name: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", name))


def _vlan_numbers(text: str) -> set[int]:
    if text == "none":
        return set()
    found: set[int] = set()
    for item in text.split(","):
        first, _, last = item.partition("-")
        found.update(range(int(first), int(last or first) + 1))
    return found


def _ok(ident: int, body: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "result": None if body is None else {"body": body}, "id": ident}


def _error(ident: int, msg: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "error": {"code": -32602, "message": "Invalid params", "data": {"msg": msg}},
        "id": ident,
    }
