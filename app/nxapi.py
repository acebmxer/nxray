"""Client for Cisco NX-API (JSON-RPC over HTTPS).

This is the only module that talks to the switch. Everything else asks it to
run commands and receives parsed JSON bodies back.

NX-API is turned on with ``feature nxapi`` on the switch. It accepts CLI
commands at ``https://<switch>/ins`` as JSON-RPC 2.0 requests and answers
with the same structured data that ``<command> | json`` prints in an SSH
session.

The switch's HTTPS certificate is not checked. NX-API ships with a
self-signed certificate it generates itself, and NXray deliberately accepts
it: the traffic is still encrypted, but the switch's identity is not
verified. This is a project decision, not an oversight.

Read-only ``show`` commands go through ``show()``. The few configuration
commands NXray needs have their own methods (``create_user``,
``give_role``, ``delete_user``, ``configure_port``, ``configure_vlan``,
``delete_vlan``, ``configure_port_vlans``, ``configure_port_settings``,
``breakout_port``, ``join_port``, ``set_feature``, ``set_port_discovery``,
``set_mac_aging``, ``add_static_mac``, ``remove_static_mac``,
``clear_learned_macs``, ``join_port_channel``, ``leave_port_channel``,
``delete_port_channel``, ``configure_port_channel``, ``set_port_lacp``,
``set_lacp_system_priority``, ``configure_vlan_interface``,
``delete_vlan_interface``, ``set_interface_addresses``, ``save_config``), each building
its commands from checked values, so nothing that renders a page can change
the switch by accident and no caller can pass free text to the switch's
configuration.
"""

from __future__ import annotations

import ipaddress
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import httpx

from app.oui import normalize_mac

# A hostname (RFC 1123 labels) or an IPv4/IPv6 literal. Anything else, such
# as a value with a path, scheme or credentials in it, is refused so the
# setting can never point the client at a URL other than the switch's /ins.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)

# NX-API runs several commands in one "cli" call when they are separated by
# " ;". Refusing ";" and line breaks keeps one request entry equal to exactly
# one command, so a value that reaches show() cannot smuggle a second one in.
_FORBIDDEN_IN_COMMAND = re.compile(r"[;\r\n]")

# NX-OS user names: up to 28 characters. Stricter than NX-OS itself (which
# also allows + and =) so a name is always safe inside a command line.
_ACCOUNT_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,27}$")

# Only letters and digits: no character the NX-OS command line could read as
# a separator, a quote or a request for help ("?").
_SAFE_PASSWORD = re.compile(r"^[A-Za-z0-9]{8,64}$")

# The only role NXray creates its own account with.
ALLOWED_ROLES = frozenset({"network-operator"})

# The role that allows port and VLAN changes (app/port_changes.py builds it).
# The only role NXray ever adds to its account afterwards.
PORT_CHANGES_ROLE = "nxray-ports"

# A front-panel port: Ethernet1/3, or a breakout port such as Ethernet1/49/2.
_PORT_NAME = re.compile(r"^Ethernet[0-9]{1,2}/[0-9]{1,3}(?:/[0-9]{1,2})?$")

# What NX-OS stores in a port description, found by trying them on the
# switch: printable ASCII up to 254 characters. NX-API refuses "?" and ";"
# anywhere in a request, and anything outside ASCII is silently cut off.
DESCRIPTION_MAX = 254
_DESCRIPTION = re.compile(r"^[\x20-\x7e]*$")

# VLAN numbers a port or the VLAN list can name. VLAN 1 always exists and
# cannot be deleted; NX-OS keeps a block at the top (3968-4094 unless changed
# on the switch) for itself and refuses to create those with its own message.
VLAN_MIN = 1
VLAN_MAX = 4094

# The highest VLAN that can have a VLAN interface NXray changes. NXray's role
# names the VLAN interfaces as one range, and NX-OS 9.3(16) stores that range
# as one line per VLAN interface: Vlan1-4094 took the switch minutes (NXray's
# SSH session timed out at Vlan3400) and NX-API stopped answering (issue #11).
# Vlan1-254 is 254 lines, a few seconds.
VLAN_INTERFACE_MAX = 254

# What NX-OS 9.3 stores as a VLAN name, found by trying them on the switch:
# no spaces ("% Invalid command"), and a name of 33 to 128 characters is
# accepted but silently not stored. NXray allows the plainest subset.
VLAN_NAME_MAX = 32
_VLAN_NAME = re.compile(r"^[A-Za-z0-9._-]{1,32}$")

# One item of a VLAN list as typed: "10" or "10-20".
_VLAN_LIST_ITEM = re.compile(r"^([0-9]{1,4})(?:-([0-9]{1,4}))?$")

# The two port modes NXray sets.
PORT_MODES = ("access", "trunk")

# Port settings (app/port_settings.py checks a form against the port first).
# Speeds are in Mb/s, as the switch's "speed" command takes them.
PORT_SPEEDS = ("auto", "100", "1000", "10000", "25000", "40000", "50000", "100000")
FEC_MODES = ("auto", "off", "fc-fec", "rs-fec", "rs-ieee", "rs-cons16")
ON_OFF = ("on", "off")
STORM_TYPES = ("broadcast", "multicast", "unicast")
STORM_ACTIONS = ("shutdown", "trap")
MTU_MIN = 576
MTU_MAX = 9216
# How a 100G port is split: four 10G or four 25G ports.
BREAKOUT_MAPS = ("10g-4x", "25g-4x")

# What may follow "feature": the commands ``feature ?`` lists on an
# N9K-C92160YC-X with NX-OS 9.3(16), with the two-word ones written out
# (``feature nv ?`` gives overlay). Left out: ``password`` (not a feature),
# ``license`` alone, and ``ntp``, ``netflow``, ``pnp`` and
# ``signature-verification``, which ``show feature`` does not list, so NXray
# cannot show whether they are on.
FEATURE_COMMANDS = frozenset(
    {
        "analytics", "bash-shell", "bfd", "bgp", "container-tracker", "dhcp", "dot1x",
        "eigrp", "epbr", "evb", "evmed", "fabric forwarding", "flexlink", "grpc", "hsrp",
        "imp", "interface-vlan", "isis", "itd", "lacp", "ldap", "license smart", "lldp",
        "mpls segment-routing", "msdp", "nat", "nbm", "netconf", "ngmvpn", "ngoam",
        "nv overlay", "nxapi", "nxsdk", "openflow", "ospf", "ospfv3", "pbr", "pim", "pim6",
        "port-security", "private-vlan", "ptp", "restconf", "rip", "scheduler",
        "scp-server", "sflow", "sftp-server", "sla responder", "sla sender",
        "sla twamp-server", "ssh", "tacacs+", "telemetry", "telnet", "tunnel",
        "tunnel-encryption", "udld", "vmtracker", "vn-segment-vlan-based", "vpc", "vrrp",
        "vrrpv3", "vtp",
    }
)  # fmt: skip

# How long the switch keeps a learned MAC address without traffic, in
# seconds: 0 keeps them for good, otherwise 120 to 918000 in steps of 5 (the
# switch rounds anything else down to a multiple of 5 and only says so in a
# note; found by trying it on the switch).
MAC_AGING_MIN = 120
MAC_AGING_MAX = 918000
MAC_AGING_STEP = 5

# Port-channels, as the switch numbers them (``interface port-channel ?``).
CHANNEL_MIN = 1
CHANNEL_MAX = 4096
# How a port joins a port-channel: LACP active (it starts the negotiation),
# LACP passive (it answers one) or static "on" (no LACP at all).
CHANNEL_MODES = ("active", "passive", "on")
# How often a port sends LACP messages: every 30 seconds or every second.
LACP_RATES = ("normal", "fast")
# The ranges ``lacp system-priority ?``, ``lacp port-priority ?`` and
# ``lacp min-links ?`` give on an N9K-C92160YC-X with NX-OS 9.3(16).
LACP_PRIORITY_MIN = 1
LACP_PRIORITY_MAX = 65535
MIN_LINKS_MIN = 1
MIN_LINKS_MAX = 32

# VRF names: Cisco's guides give up to 32 case-sensitive letters and digits;
# NXray also allows "-" and "_" inside one. NX-OS keeps default and management
# for itself (mgmt0 lives in management), and "all" is what show commands take
# for every VRF, so NXray never creates, deletes or moves interfaces into those.
VRF_NAME_MAX = 32
_VRF_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
RESERVED_VRFS = frozenset({"default", "management", "all"})
DEFAULT_VRF = "default"

# Features NXray needs itself: it never sends their "no feature".
NEEDED_FEATURES = frozenset({"nxapi", "ssh"})

# Turning a feature on or off can take the switch a while.
FEATURE_TIMEOUT = 120.0

# Names NX-OS keeps for itself, plus the switch's own admin account.
RESERVED_ACCOUNT_NAMES = frozenset(
    {
        "admin", "adm", "bin", "daemon", "ftp", "ftpuser", "games", "gdm", "gopher",
        "halt", "lp", "mail", "mailnull", "man", "mtsuser", "news", "nobody", "nscd",
        "operator", "root", "rpc", "rpcuser", "shutdown", "sync", "sys", "uucp", "xfs",
    }
)  # fmt: skip

# Saving the configuration can take a while on a busy switch.
SAVE_CONFIG_TIMEOUT = 120.0

# One save at a time from this process. NX-OS refuses a second copy while
# one runs ("another request for config change is already in progress"),
# so a double-clicked Save config would turn a save that worked into an
# error on the page. A second save waits here for the first, then runs.
_save_lock = threading.Lock()


class NxapiError(Exception):
    """Base class: the switch could not give an answer."""


class NxapiUnreachable(NxapiError):
    """No HTTP answer at all: wrong address, NX-API off, firewall, timeout."""


class NxapiAuthError(NxapiError):
    """The switch refused the username or password."""


class NxapiCommandError(NxapiError):
    """The switch answered, but rejected a command."""


class NxapiProtocolError(NxapiError):
    """The switch answered with something that is not a usable NX-API reply."""


@dataclass(frozen=True)
class SwitchTarget:
    """Where the switch's NX-API is and how to log in to it."""

    host: str
    port: int
    username: str
    password: str
    timeout: float

    def __repr__(self) -> str:
        # Never let the password reach a log line or a traceback.
        return f"SwitchTarget(host={self.host!r}, port={self.port}, username={self.username!r})"

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"https://{host}:{self.port}/ins"


def is_valid_host(value: str) -> bool:
    """True for a bare hostname or IP address, with nothing else attached."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(_HOSTNAME.match(value))


def validate_account_name(name: str) -> str:
    """Return the name, or raise ValueError if NXray would not use it on a switch."""
    if not _ACCOUNT_NAME.match(name):
        raise ValueError(
            "an account name is 1-28 characters: a letter first, then letters, "
            "digits, dots, dashes or underscores"
        )
    if name.lower() in RESERVED_ACCOUNT_NAMES:
        raise ValueError(f"{name!r} is reserved on the switch; pick another name")
    return name


def validate_port_name(name: str) -> str:
    """Return the name, or raise ValueError if it is not a front-panel Ethernet port."""
    if not _PORT_NAME.match(name):
        raise ValueError(f"{name!r} is not a front-panel port name such as Ethernet1/3")
    return name


def validate_description(text: str) -> str:
    """Return the description as the switch will store it, or raise ValueError.

    Leading spaces are dropped (the switch drops them too). An empty result
    means "no description".
    """
    cleaned = text.lstrip(" ").rstrip("\r\n")
    if len(cleaned) > DESCRIPTION_MAX:
        raise ValueError(f"a description is at most {DESCRIPTION_MAX} characters")
    if not _DESCRIPTION.match(cleaned):
        raise ValueError(
            "a description can only use plain letters, digits, spaces and the usual "
            "punctuation (no accented letters, tabs or line breaks)"
        )
    if "?" in cleaned or ";" in cleaned:
        raise ValueError('a description cannot contain "?" or ";" (NX-API refuses them)')
    return cleaned


def validate_vlan_id(value: int | str) -> int:
    """Return the VLAN number as an int, or raise ValueError if it is not 1-4094."""
    text = str(value).strip()
    if not text.isascii() or not text.isdigit() or not VLAN_MIN <= int(text) <= VLAN_MAX:
        raise ValueError(f"a VLAN is a number from {VLAN_MIN} to {VLAN_MAX}")
    return int(text)


def validate_vlan_name(name: str) -> str:
    """Return the VLAN name, or raise ValueError if the switch would not store it."""
    cleaned = name.strip()
    if not _VLAN_NAME.match(cleaned):
        raise ValueError(
            f"a VLAN name is 1-{VLAN_NAME_MAX} letters, digits, dots, dashes or "
            "underscores, with no spaces"
        )
    return cleaned


def parse_vlan_list(text: str) -> list[int]:
    """Turn a typed VLAN list into numbers: "10,20-22" gives [10, 20, 21, 22].

    "all" gives 1-4094 and "none" (or nothing) gives []. Raises ValueError
    for anything else, so only numbers reach a command.
    """
    cleaned = text.strip().lower()
    if cleaned == "all":
        return list(range(VLAN_MIN, VLAN_MAX + 1))
    if cleaned in ("none", ""):
        return []
    found: set[int] = set()
    # Spaces are allowed around the commas only: "10 20" is refused, not read as 1020.
    for item in (part.strip() for part in cleaned.split(",")):
        match = _VLAN_LIST_ITEM.match(item)
        if not match:
            raise ValueError(
                f"{item!r} is not a VLAN or range; write VLANs like 10,20-30, or all, or none"
            )
        first = validate_vlan_id(match.group(1))
        last = validate_vlan_id(match.group(2)) if match.group(2) else first
        if last < first:
            raise ValueError(f"the range {item} runs backwards")
        found.update(range(first, last + 1))
    return sorted(found)


def format_vlan_list(vlans: Iterable[int]) -> str:
    """[1, 10, 11, 12, 30] -> "1,10-12,30", as the switch writes it; [] -> "none"."""
    ordered = sorted({validate_vlan_id(vlan) for vlan in vlans})
    if not ordered:
        return "none"
    parts: list[str] = []
    start = previous = ordered[0]
    for vlan in [*ordered[1:], None]:
        if vlan is not None and vlan == previous + 1:
            previous = vlan
            continue
        parts.append(str(start) if start == previous else f"{start}-{previous}")
        if vlan is not None:
            start = previous = vlan
    return ",".join(parts)


def validate_ip_interface(text: str) -> str:
    """Return an IPv4 address with its prefix ("192.0.2.1/24"), or raise ValueError.

    The address must be one a port can have: not the network's own address
    or its broadcast address (both allowed on /31 and /32).
    """
    cleaned = text.strip()
    try:
        interface = ipaddress.IPv4Interface(cleaned)
    except ValueError as exc:
        raise ValueError(
            f"{cleaned!r} is not an IPv4 address with a prefix length, such as 192.0.2.1/24"
        ) from exc
    if "/" not in cleaned:
        raise ValueError(f"add the prefix length to {cleaned!r}, such as /24")
    network = interface.network
    if network.prefixlen < 31 and interface.ip in (
        network.network_address,
        network.broadcast_address,
    ):
        raise ValueError(f"{cleaned} is the network's own or broadcast address")
    return f"{interface.ip}/{network.prefixlen}"


def validate_ipv6_interface(text: str) -> str:
    """Return an IPv6 address with its prefix ("2001:db8::1/64"), or raise ValueError.

    Only an address a device can be reached at: not a link-local address
    (the switch makes one of those on every IPv6 interface by itself), and not
    a multicast, loopback or unspecified one.
    """
    cleaned = text.strip()
    try:
        interface = ipaddress.IPv6Interface(cleaned)
    except ValueError as exc:
        raise ValueError(
            f"{cleaned!r} is not an IPv6 address with a prefix length, such as 2001:db8::1/64"
        ) from exc
    if "/" not in cleaned:
        raise ValueError(f"add the prefix length to {cleaned!r}, such as /64")
    address = interface.ip
    if address.is_link_local:
        raise ValueError(
            f"{address} is a link-local address; the switch makes one by itself on every "
            "IPv6 interface"
        )
    if address.is_multicast or address.is_loopback or address.is_unspecified:
        raise ValueError(f"{address} is not an address a device can be reached at")
    return f"{address}/{interface.network.prefixlen}"


def validate_interface_address(text: str) -> str:
    """An IPv4 or IPv6 address with its prefix, as the switch takes it; or raise ValueError."""
    cleaned = text.strip()
    if ":" in cleaned:
        return validate_ipv6_interface(cleaned)
    return validate_ip_interface(cleaned)


def validate_routed_interface(name: str) -> str:
    """Return a name an address can go on: ``Vlan10``, a front port or ``port-channel5``.

    Raises ValueError for anything else (mgmt0 above all, which NXray never
    changes).
    """
    cleaned = name.strip()
    if match := re.fullmatch(r"[Vv]lan([0-9]{1,4})", cleaned):
        return f"Vlan{validate_vlan_id(match.group(1))}"
    if match := re.fullmatch(r"port-channel([0-9]{1,4})", cleaned):
        return f"port-channel{validate_channel_number(match.group(1))}"
    return validate_port_name(cleaned)


def validate_route_prefix(text: str) -> str:
    """A static route's destination, a network with its prefix length
    (``203.0.113.0/24``, ``2001:db8::/48``, ``0.0.0.0/0``), or raise ValueError."""
    cleaned = text.strip()
    if "/" not in cleaned:
        raise ValueError(f"add the prefix length to {cleaned!r}, such as /24")
    try:
        loose = ipaddress.ip_network(cleaned, strict=False)
    except ValueError as exc:
        raise ValueError(
            f"{cleaned!r} is not a network such as 203.0.113.0/24 or 2001:db8::/48"
        ) from exc
    try:
        network = ipaddress.ip_network(cleaned)
    except ValueError as exc:
        raise ValueError(
            f"{cleaned} is not the start of its network; did you mean {loose}?"
        ) from exc
    if network.is_multicast or (network.prefixlen and network.network_address.is_unspecified):
        raise ValueError(f"{network} is not a network a route can go to")
    return str(network)


def validate_next_hop(text: str) -> str:
    """A static route's next hop: one IPv4 or IPv6 address a device can have, or
    raise ValueError. Not a link-local IPv6 address: the switch would also need
    the interface it is on."""
    cleaned = text.strip()
    try:
        address = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValueError(
            f"{cleaned!r} is not an address such as 192.0.2.254 or 2001:db8::fe"
        ) from exc
    if address.is_link_local and address.version == 6:
        raise ValueError(f"{address} is a link-local address; use the router's other address")
    if address.is_multicast or address.is_loopback or address.is_unspecified:
        raise ValueError(f"{address} is not an address a router can have")
    return str(address)


def static_route_line(prefix: str, next_hop: str) -> str:
    """``ip route P NH`` or ``ipv6 route P NH``; its ``no`` form removes the route."""
    network = validate_route_prefix(prefix)
    hop = validate_next_hop(next_hop)
    if (":" in network) != (":" in hop):
        raise ValueError("the destination and the next hop must both be IPv4 or both IPv6")
    return f"{'ipv6' if ':' in network else 'ip'} route {network} {hop}"


def validate_vrf_name(name: str) -> str:
    """Return a VRF name NXray may create, delete or move interfaces into, or raise
    ValueError (never default, management or all)."""
    cleaned = name.strip()
    if not _VRF_NAME.fullmatch(cleaned):
        raise ValueError(
            f"a VRF name is 1 to {VRF_NAME_MAX} letters, digits, '-' or '_', starting with a "
            "letter or digit"
        )
    if cleaned.lower() in RESERVED_VRFS:
        raise ValueError(f"the switch keeps the VRF name {cleaned!r} for itself")
    return cleaned


def validate_storm_level(value: str | float) -> str:
    """A storm-control level as the switch writes it ("10.00"), or raise ValueError."""
    text = str(value).strip()
    if not re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,2})?", text) or not 0 <= float(text) <= 100:
        raise ValueError(
            "a storm-control level is a percentage from 0 to 100, with up to two decimals"
        )
    return f"{float(text):.2f}"


def validate_mac_aging(value: int | str) -> int:
    """The MAC address aging time in seconds, or raise ValueError.

    0 (never forget) or 120 to 918000 in steps of 5, as the switch takes it.
    """
    text = str(value).strip()
    seconds = int(text) if text.isascii() and text.isdigit() else -1
    if seconds == 0:
        return 0
    if not MAC_AGING_MIN <= seconds <= MAC_AGING_MAX:
        raise ValueError(
            f"the aging time is 0 (never forget) or {MAC_AGING_MIN} to {MAC_AGING_MAX} seconds"
        )
    if seconds % MAC_AGING_STEP:
        raise ValueError(
            f"the switch takes the aging time in steps of {MAC_AGING_STEP} seconds, such as "
            f"{seconds - seconds % MAC_AGING_STEP}"
        )
    return seconds


def validate_device_mac(text: str) -> str:
    """One device's MAC address in the switch's own form (``0200.0000.0001``), or raise ValueError.

    Accepts any common way of writing one. A group (multicast or broadcast)
    address and the all-zero address belong to no device and are refused:
    static entries and clearing one address are for a device.
    """
    digits = normalize_mac(text)
    if digits is None:
        raise ValueError(f"{text.strip()!r} is not a MAC address such as 00:11:22:33:44:55")
    if int(digits[:2], 16) & 0x01:
        raise ValueError("that is a multicast address, not one device's address")
    if digits == "0" * 12:
        raise ValueError("00:00:00:00:00:00 is not a device's address")
    return f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}"


def validate_channel_number(value: int | str) -> int:
    """A port-channel's number as an int, or raise ValueError if it is not 1-4096."""
    text = str(value).strip()
    if not text.isascii() or not text.isdigit() or not CHANNEL_MIN <= int(text) <= CHANNEL_MAX:
        raise ValueError(f"a port-channel is a number from {CHANNEL_MIN} to {CHANNEL_MAX}")
    return int(text)


def validate_lacp_priority(value: int | str) -> int:
    """An LACP priority (the switch's or a port's), or raise ValueError if not 1-65535."""
    text = str(value).strip()
    if (
        not text.isascii()
        or not text.isdigit()
        or not LACP_PRIORITY_MIN <= int(text) <= LACP_PRIORITY_MAX
    ):
        raise ValueError(
            f"an LACP priority is a number from {LACP_PRIORITY_MIN} to {LACP_PRIORITY_MAX}"
        )
    return int(text)


def validate_min_links(value: int | str) -> int:
    """How many ports must be up for a port-channel to be up, or raise ValueError if not 1-32."""
    text = str(value).strip()
    if not text.isascii() or not text.isdigit() or not MIN_LINKS_MIN <= int(text) <= MIN_LINKS_MAX:
        raise ValueError(f"the minimum is a number from {MIN_LINKS_MIN} to {MIN_LINKS_MAX}")
    return int(text)


def breakout_numbers(name: str) -> tuple[int, int]:
    """(module, port) of a port or breakout port: Ethernet1/50/2 gives (1, 50)."""
    validate_port_name(name)
    module, port = name[len("Ethernet") :].split("/")[:2]
    return int(module), int(port)


def address_line(address: str, secondary: bool = False) -> str:
    """The interface line that puts an address on: ``ip address A [secondary]`` or
    ``ipv6 address A``. Its ``no`` form takes it off again."""
    text = validate_interface_address(address)
    if ":" in text:
        if secondary:
            raise ValueError("an IPv6 address has no primary or secondary")
        return f"ipv6 address {text}"
    return f"ip address {text}" + (" secondary" if secondary else "")


def _address_commands(
    remove: Iterable[tuple[str, bool]], add: Iterable[tuple[str, bool]]
) -> list[str]:
    return [f"no {address_line(a, s)}" for a, s in remove] + [address_line(a, s) for a, s in add]


def validate_show_command(command: str) -> str:
    """Return the command stripped, or raise ValueError if it is not a lone show."""
    cleaned = command.strip()
    if not cleaned.lower().startswith("show "):
        raise ValueError(f"only show commands are allowed here, got {cleaned!r}")
    if _FORBIDDEN_IN_COMMAND.search(cleaned):
        raise ValueError(f"a command must not contain ';' or a line break: {cleaned!r}")
    return cleaned


def build_payload(commands: list[str]) -> list[dict[str, Any]]:
    """The JSON-RPC request body for running ``commands`` in order."""
    return [
        {
            "jsonrpc": "2.0",
            "method": "cli",
            "params": {"cmd": command, "version": 1},
            "id": index,
        }
        for index, command in enumerate(commands, start=1)
    ]


def parse_response(
    payload: Any,
    commands: list[str],
    labels: list[str] | None = None,
    allow_text: bool = False,
) -> list[dict[str, Any]]:
    """Turn a JSON-RPC reply into one body per command, in request order.

    NX-API answers a one-command request with a single object rather than a
    one-element list, so both shapes are accepted. A command that prints
    nothing comes back with a null body, returned here as an empty dict.

    ``labels`` replace the commands in error messages, for commands that
    carry a secret (a password) that must never reach a log or a page.
    ``allow_text`` accepts a plain-text answer (configuration commands have
    no structured output) and returns it as ``{"text": ...}``.
    """
    names = labels if labels is not None else commands
    entries = payload if isinstance(payload, list) else [payload]
    if len(entries) != len(commands):
        raise NxapiProtocolError(
            f"asked for {len(commands)} command(s), the switch answered {len(entries)}"
        )

    by_id: dict[int, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), int):
            raise NxapiProtocolError("the switch sent a reply entry without an id")
        by_id[entry["id"]] = entry

    bodies: list[dict[str, Any]] = []
    for index, command in enumerate(names, start=1):
        entry = by_id.get(index)
        if entry is None:
            raise NxapiProtocolError(f"no answer for {command!r}")
        if "error" in entry:
            raise NxapiCommandError(f"{command!r}: {error_message(entry['error'])}")
        result = entry.get("result")
        if result is None:
            bodies.append({})
            continue
        body = result.get("body") if isinstance(result, dict) else None
        if body is None:
            bodies.append({})
        elif isinstance(body, dict):
            bodies.append(body)
        elif allow_text and isinstance(body, str):
            bodies.append({"text": body})
        else:
            raise NxapiProtocolError(f"{command!r} returned text, not structured data")
    return bodies


def error_message(error: Any) -> str:
    """The most specific message in a JSON-RPC error object."""
    if not isinstance(error, dict):
        return "unknown error"
    data = error.get("data")
    if isinstance(data, dict) and isinstance(data.get("msg"), str) and data["msg"].strip():
        return data["msg"].strip()
    message = error.get("message")
    return message.strip() if isinstance(message, str) and message.strip() else "unknown error"


class NxapiClient:
    """A connection to one switch's NX-API.

    ``transport`` exists for tests, which pass an ``httpx.MockTransport`` that
    answers from recorded switch output instead of opening a socket.
    """

    def __init__(self, target: SwitchTarget, transport: httpx.BaseTransport | None = None):
        self._target = target
        self._http = httpx.Client(
            auth=(target.username, target.password),
            # The switch's self-signed certificate is accepted on purpose;
            # see the module docstring.
            verify=False,
            timeout=target.timeout,
            transport=transport,
            headers={"Content-Type": "application/json-rpc"},
        )

    def __enter__(self) -> NxapiClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    def show(self, *commands: str) -> list[dict[str, Any]]:
        """Run show commands in one request; one parsed body per command."""
        if not commands:
            raise ValueError("no commands given")
        cleaned = [validate_show_command(command) for command in commands]
        return self._send(cleaned, cleaned, self._target.timeout)

    def create_user(self, name: str, password: str, role: str) -> None:
        """Create a local switch account. Needs an admin login.

        Every value is checked before anything is sent, so the one command
        built here can only ever be ``username <name> password <pw> role <r>``.
        The password never appears in an error message.
        """
        validate_account_name(name)
        if not _SAFE_PASSWORD.match(password):
            raise ValueError("the password must be 8-64 letters and digits")
        if role not in ALLOWED_ROLES:
            raise ValueError(f"role {role!r} is not one NXray gives its account")
        command = f"username {name} password {password} role {role}"
        label = f"username {name} password ... role {role}"
        self._send([command], [label], self._target.timeout, allow_text=True)

    def give_role(self, name: str, role: str) -> None:
        """Add NXray's port-changes role to an account. Needs an admin login.

        Used by Run setup again when it makes NXray's account again: the
        role must be on the account before its first sign-in, because the
        switch keeps a signed-in account's roles until its NX-API session
        ends.
        """
        validate_account_name(name)
        if role != PORT_CHANGES_ROLE:
            raise ValueError(f"role {role!r} is not one NXray gives its account")
        command = f"username {name} role {role}"
        self._send([command], [command], self._target.timeout, allow_text=True)

    def delete_user(self, name: str) -> None:
        """Remove a local switch account. Needs an admin login.

        Only used to undo an account NXray created moments earlier when the
        rest of setup failed, so a retry is not blocked by a leftover. The
        switch refuses it while the account has an NX-API session.
        """
        validate_account_name(name)
        command = f"no username {name}"
        self._send([command], [command], self._target.timeout, allow_text=True)

    def configure_port(
        self, name: str, *, description: str | None = None, enabled: bool | None = None
    ) -> None:
        """Set one port's description and/or turn it on or off, in one request.

        ``description=""`` removes the description. Only these two settings
        exist here, matching the role NXray's account is given for them.
        """
        validate_port_name(name)
        if description is None and enabled is None:
            raise ValueError("nothing to change")
        commands = [f"interface {name}"]
        if description is not None:
            text = validate_description(description)
            commands.append(f"description {text}" if text else "no description")
        if enabled is not None:
            commands.append("no shutdown" if enabled else "shutdown")
        self._send(commands, commands, self._target.timeout, allow_text=True)

    def configure_vlan(self, vlan_id: int, name: str | None = None) -> None:
        """Create a VLAN, or rename one: ``vlan <n>`` then ``name <name>``.

        ``vlan <n>`` creates the VLAN when it does not exist yet and only
        selects it when it does, so the caller decides which one it means.
        """
        vlan = validate_vlan_id(vlan_id)
        commands = [f"vlan {vlan}"]
        if name is not None:
            commands.append(f"name {validate_vlan_name(name)}")
        self._send(commands, commands, self._target.timeout, allow_text=True)

    def delete_vlan(self, vlan_id: int) -> None:
        """``no vlan <n>``. VLAN 1 is refused here as it is on the switch."""
        vlan = validate_vlan_id(vlan_id)
        if vlan == 1:
            raise ValueError("VLAN 1 cannot be deleted")
        command = f"no vlan {vlan}"
        self._send([command], [command], self._target.timeout, allow_text=True)

    def configure_port_vlans(
        self,
        name: str,
        *,
        mode: str | None = None,
        access_vlan: int | None = None,
        native_vlan: int | None = None,
        allowed_vlans: list[int] | None = None,
    ) -> None:
        """Set a port's mode and VLANs, in one request; only the values given are sent.

        ``mode`` is access or trunk. ``allowed_vlans`` is the trunk's whole
        list (it replaces the old one); an empty list allows none.
        """
        validate_port_name(name)
        commands = [f"interface {name}"]
        if mode is not None:
            if mode not in PORT_MODES:
                raise ValueError(f"mode {mode!r} is not access or trunk")
            commands.append(f"switchport mode {mode}")
        if access_vlan is not None:
            commands.append(f"switchport access vlan {validate_vlan_id(access_vlan)}")
        if native_vlan is not None:
            commands.append(f"switchport trunk native vlan {validate_vlan_id(native_vlan)}")
        if allowed_vlans is not None:
            commands.append(f"switchport trunk allowed vlan {format_vlan_list(allowed_vlans)}")
        if len(commands) == 1:
            raise ValueError("nothing to change")
        self._send(commands, commands, self._target.timeout, allow_text=True)

    def configure_port_settings(
        self,
        name: str,
        *,
        layer: str | None = None,
        remove_extra: Iterable[tuple[str, bool]] = (),
        remove_ip: str | None = None,
        ip_address: str | None = None,
        speed: str | None = None,
        mtu: int | None = None,
        fec: str | None = None,
        flow_receive: str | None = None,
        flow_send: str | None = None,
        storm_levels: dict[str, str] | None = None,
        storm_action: str | None = None,
        old_storm_action: str | None = None,
    ) -> None:
        """Change a port's settings in one request; only the values given are sent.

        ``layer`` is "switched" (``switchport``) or "routed" (``no
        switchport``). ``remove_extra`` are (address, secondary) pairs taken
        off first: a routed port's extra IPv4 and its IPv6 addresses.
        ``remove_ip`` is the address to take off the port, sent before a new
        ``ip_address`` and before ``switchport``. A storm-control
        level of 100.00 is the switch's own default (no limit).
        ``storm_action`` "none" removes ``old_storm_action``.
        """
        validate_port_name(name)
        commands = [f"interface {name}"]
        if layer is not None and layer not in ("switched", "routed"):
            raise ValueError(f"layer {layer!r} is not switched or routed")
        commands += _address_commands(remove_extra, ())
        if remove_ip is not None:
            commands.append(f"no ip address {validate_ip_interface(remove_ip)}")
        if layer == "switched":
            commands.append("switchport")
        elif layer == "routed":
            commands.append("no switchport")
        if ip_address is not None:
            commands.append(f"ip address {validate_ip_interface(ip_address)}")
        if speed is not None:
            if speed not in PORT_SPEEDS:
                raise ValueError(f"speed {speed!r} is not one the switch takes")
            commands.append(f"speed {speed}")
        if mtu is not None:
            if not MTU_MIN <= int(mtu) <= MTU_MAX:
                raise ValueError(f"an MTU is {MTU_MIN} to {MTU_MAX}")
            commands.append(f"mtu {int(mtu)}")
        if fec is not None:
            if fec not in FEC_MODES:
                raise ValueError(f"FEC {fec!r} is not one NXray sets")
            commands.append(f"fec {fec}")
        for direction, value in (("receive", flow_receive), ("send", flow_send)):
            if value is not None:
                if value not in ON_OFF:
                    raise ValueError("flow control is on or off")
                commands.append(f"flowcontrol {direction} {value}")
        for kind, level in (storm_levels or {}).items():
            if kind not in STORM_TYPES:
                raise ValueError(f"storm-control type {kind!r} is not known")
            commands.append(f"storm-control {kind} level {validate_storm_level(level)}")
        if storm_action is not None:
            if storm_action in STORM_ACTIONS:
                commands.append(f"storm-control action {storm_action}")
            elif storm_action == "none" and old_storm_action in STORM_ACTIONS:
                commands.append(f"no storm-control action {old_storm_action}")
            else:
                raise ValueError("storm-control action is none, shutdown or trap")
        if len(commands) == 1:
            raise ValueError("nothing to change")
        self._send(commands, commands, self._target.timeout, allow_text=True)

    def breakout_port(self, name: str, mapping: str) -> None:
        """Split a 100G port into four: ``interface breakout module M port P map <map>``."""
        if mapping not in BREAKOUT_MAPS:
            raise ValueError(f"split {mapping!r} is not 10g-4x or 25g-4x")
        module, port = breakout_numbers(name)
        command = f"interface breakout module {module} port {port} map {mapping}"
        self._send([command], [command], self._target.timeout, allow_text=True)

    def join_port(self, name: str, mapping: str) -> None:
        """Join a split port's four ports back into one: the ``no`` form of the split."""
        if mapping not in BREAKOUT_MAPS:
            raise ValueError(f"split {mapping!r} is not 10g-4x or 25g-4x")
        module, port = breakout_numbers(name)
        command = f"no interface breakout module {module} port {port} map {mapping}"
        self._send([command], [command], self._target.timeout, allow_text=True)

    def set_feature(self, command: str, enabled: bool) -> None:
        """``feature <command>`` or ``no feature <command>``, for one known feature.

        ``command`` must be one of FEATURE_COMMANDS. NX-API and SSH, which
        NXray itself uses, are never turned off from here.
        """
        if command not in FEATURE_COMMANDS:
            raise ValueError(f"{command!r} is not a feature NXray turns on or off")
        if not enabled and command in NEEDED_FEATURES:
            raise ValueError(f"NXray does not turn off {command}: it needs it")
        line = f"feature {command}" if enabled else f"no feature {command}"
        timeout = max(self._target.timeout, FEATURE_TIMEOUT)
        self._send([line], [line], timeout, allow_text=True)

    def set_port_discovery(
        self,
        name: str,
        *,
        cdp: bool | None = None,
        lldp_transmit: bool | None = None,
        lldp_receive: bool | None = None,
    ) -> None:
        """Turn CDP, LLDP sending and LLDP listening on or off on one port, in one request.

        Only the values given are sent. The switch refuses the LLDP lines while
        the lldp feature is off.
        """
        validate_port_name(name)
        commands = [f"interface {name}"]
        for value, line in (
            (cdp, "cdp enable"),
            (lldp_transmit, "lldp transmit"),
            (lldp_receive, "lldp receive"),
        ):
            if value is not None:
                commands.append(line if value else f"no {line}")
        if len(commands) == 1:
            raise ValueError("nothing to change")
        self._send(commands, commands, self._target.timeout, allow_text=True)

    def set_mac_aging(self, seconds: int) -> None:
        """``mac address-table aging-time <seconds>``; 0 keeps learned addresses for good."""
        command = f"mac address-table aging-time {validate_mac_aging(seconds)}"
        self._send([command], [command], self._target.timeout, allow_text=True)

    def add_static_mac(self, mac: str, vlan: int, port: str | None) -> None:
        """A static MAC address entry: always on ``port``, or dropped when ``port`` is None.

        ``mac address-table static <mac> vlan <n> interface <port>`` or ``... drop``.
        """
        command = self._static_mac_line(mac, vlan, port)
        self._send([command], [command], self._target.timeout, allow_text=True)

    def remove_static_mac(self, mac: str, vlan: int, port: str | None) -> None:
        """Remove a static entry: the ``no`` form of the line that made it."""
        command = "no " + self._static_mac_line(mac, vlan, port)
        self._send([command], [command], self._target.timeout, allow_text=True)

    @staticmethod
    def _static_mac_line(mac: str, vlan: int, port: str | None) -> str:
        where = "drop" if port is None else f"interface {validate_port_name(port)}"
        return (
            f"mac address-table static {validate_device_mac(mac)} "
            f"vlan {validate_vlan_id(vlan)} {where}"
        )

    def clear_learned_macs(
        self, *, port: str | None = None, vlan: int | None = None, mac: str | None = None
    ) -> None:
        """``clear mac address-table dynamic``: forget learned addresses.

        Everything when nothing is given; else those on one port, in one VLAN,
        or one address (optionally only in one VLAN), the forms the switch
        takes. Static entries stay. Not a configuration change, so there is
        nothing to save afterwards.
        """
        command = "clear mac address-table dynamic"
        if port is not None:
            if vlan is not None or mac is not None:
                raise ValueError("a port cannot be combined with a VLAN or an address")
            command += f" interface {validate_port_name(port)}"
        else:
            if mac is not None:
                command += f" address {validate_device_mac(mac)}"
            if vlan is not None:
                command += f" vlan {validate_vlan_id(vlan)}"
        self._send([command], [command], self._target.timeout, allow_text=True)

    def join_port_channel(
        self,
        number: int,
        ports: list[str],
        mode: str,
        *,
        fast_rate: bool = False,
        description: str | None = None,
    ) -> None:
        """Put ports into a port-channel, in one request; the switch creates it if needed.

        Per port: ``interface <port>``, ``lacp rate fast`` when asked (the
        switch takes it only before the port is in a channel), then
        ``channel-group <n> mode active|passive``, or ``channel-group <n>``
        for static "on". ``description`` then names the port-channel itself.
        """
        channel = validate_channel_number(number)
        if mode not in CHANNEL_MODES:
            raise ValueError(f"mode {mode!r} is not active, passive or on")
        if fast_rate and mode == "on":
            raise ValueError("a static port-channel sends no LACP, so it has no LACP rate")
        if not ports:
            raise ValueError("no ports given")
        commands: list[str] = []
        for port in ports:
            commands.append(f"interface {validate_port_name(port)}")
            if fast_rate:
                commands.append("lacp rate fast")
            commands.append(
                f"channel-group {channel}"
                if mode == "on"
                else f"channel-group {channel} mode {mode}"
            )
        if description is not None:
            text = validate_description(description)
            if text:
                commands += [f"interface port-channel{channel}", f"description {text}"]
        self._send(commands, commands, self._target.timeout, allow_text=True)

    def leave_port_channel(self, port: str) -> None:
        """Take a port out of its port-channel: ``no channel-group``. Its own settings stay."""
        commands = [f"interface {validate_port_name(port)}", "no channel-group"]
        self._send(commands, commands, self._target.timeout, allow_text=True)

    def delete_port_channel(self, number: int) -> None:
        """``no interface port-channel<n>``.

        The switch also takes the ports out of the channel when it still has
        some; NXray refuses that before it gets here (app/port_channels.py).
        """
        command = f"no interface port-channel{validate_channel_number(number)}"
        self._send([command], [command], self._target.timeout, allow_text=True)

    def configure_port_channel(
        self, number: int, *, description: str | None = None, min_links: int | None = None
    ) -> None:
        """Set a port-channel's description and/or LACP minimum links, in one request.

        ``description=""`` removes the description.
        """
        commands = [f"interface port-channel{validate_channel_number(number)}"]
        if description is not None:
            text = validate_description(description)
            commands.append(f"description {text}" if text else "no description")
        if min_links is not None:
            commands.append(f"lacp min-links {validate_min_links(min_links)}")
        if len(commands) == 1:
            raise ValueError("nothing to change")
        self._send(commands, commands, self._target.timeout, allow_text=True)

    def set_port_lacp(
        self, port: str, *, rate: str | None = None, priority: int | None = None
    ) -> None:
        """Set a port's LACP rate (normal or fast) and/or LACP port priority, in one request.

        The switch refuses a rate change on a port that is in a port-channel
        and not turned off.
        """
        commands = [f"interface {validate_port_name(port)}"]
        if rate is not None:
            if rate not in LACP_RATES:
                raise ValueError(f"LACP rate {rate!r} is not normal or fast")
            commands.append(f"lacp rate {rate}")
        if priority is not None:
            commands.append(f"lacp port-priority {validate_lacp_priority(priority)}")
        if len(commands) == 1:
            raise ValueError("nothing to change")
        self._send(commands, commands, self._target.timeout, allow_text=True)

    def set_lacp_system_priority(self, priority: int) -> None:
        """``lacp system-priority <n>``: the switch's LACP priority, for every port-channel."""
        command = f"lacp system-priority {validate_lacp_priority(priority)}"
        self._send([command], [command], self._target.timeout, allow_text=True)

    def configure_vlan_interface(
        self,
        vlan: int,
        *,
        description: str | None = None,
        mtu: int | None = None,
        enabled: bool | None = None,
        remove: Iterable[tuple[str, bool]] = (),
        add: Iterable[tuple[str, bool]] = (),
        vrf: str | None = None,
    ) -> None:
        """Make a VLAN interface (``interface vlan<n>``) or change one, in one request.

        ``interface vlan<n>`` makes it when it does not exist yet. ``vrf`` puts
        it into that VRF first (``vrf member``; for a new one, since the switch
        deletes an interface's addresses when its VRF changes). ``remove`` and
        ``add`` are (address, secondary) pairs, sent in that order, before the
        description and MTU; turning it on or off comes last. Only the values
        given are sent. ``description=""`` removes the description.
        """
        commands = [f"interface vlan{validate_vlan_id(vlan)}"]
        if vrf is not None:
            commands.append(f"vrf member {validate_vrf_name(vrf)}")
        commands += _address_commands(remove, add)
        if description is not None:
            text = validate_description(description)
            commands.append(f"description {text}" if text else "no description")
        if mtu is not None:
            if not MTU_MIN <= int(mtu) <= MTU_MAX:
                raise ValueError(f"an MTU is {MTU_MIN} to {MTU_MAX}")
            commands.append(f"mtu {int(mtu)}")
        if enabled is not None:
            commands.append("no shutdown" if enabled else "shutdown")
        if len(commands) == 1:
            raise ValueError("nothing to change")
        self._send(commands, commands, self._target.timeout, allow_text=True)

    def delete_vlan_interface(self, vlan: int) -> None:
        """``no interface vlan<n>``. Its addresses go with it; the VLAN itself stays."""
        number = validate_vlan_id(vlan)
        if number == 1:
            # The switch answers "Vlan 1 is default vlan and cannot be deleted"
            # as a note, not an error, and keeps it.
            raise ValueError("the switch keeps the VLAN 1 interface; turn it off instead")
        command = f"no interface vlan{number}"
        self._send([command], [command], self._target.timeout, allow_text=True)

    def set_interface_addresses(
        self,
        name: str,
        *,
        remove: Iterable[tuple[str, bool]] = (),
        add: Iterable[tuple[str, bool]] = (),
    ) -> None:
        """Take addresses off and put addresses on a VLAN interface, routed port or
        routed port-channel, in one request.

        ``remove`` and ``add`` are (address, secondary) pairs: ``ip address A``,
        ``ip address A secondary`` or ``ipv6 address A``, and their ``no`` forms.
        """
        commands = [f"interface {validate_routed_interface(name)}"]
        commands += _address_commands(remove, add)
        if len(commands) == 1:
            raise ValueError("nothing to change")
        self._send(commands, commands, self._target.timeout, allow_text=True)

    def create_vrf(self, name: str) -> None:
        """``vrf context <name>``, which makes the VRF when it does not exist yet."""
        command = f"vrf context {validate_vrf_name(name)}"
        self._send([command], [command], self._target.timeout, allow_text=True)

    def delete_vrf(self, name: str) -> None:
        """``no vrf context <name>``.

        The switch also takes the interfaces out of it; NXray refuses that
        before it gets here (app/routing.py).
        """
        command = f"no vrf context {validate_vrf_name(name)}"
        self._send([command], [command], self._target.timeout, allow_text=True)

    def set_interface_vrf(self, name: str, vrf: str, *, current: str) -> None:
        """Move a VLAN interface, routed port or routed port-channel from VRF
        ``current`` to ``vrf`` (either may be ``default``), in one request.

        ``no vrf member <current>`` leaves a VRF, ``vrf member <vrf>`` joins
        one. The switch deletes the interface's addresses each time ("Deleted
        all L3 config on interface").
        """
        commands = [f"interface {validate_routed_interface(name)}"]
        if current != DEFAULT_VRF:
            commands.append(f"no vrf member {validate_vrf_name(current)}")
        if vrf != DEFAULT_VRF:
            commands.append(f"vrf member {validate_vrf_name(vrf)}")
        if len(commands) == 1 or vrf == current:
            raise ValueError("nothing to change")
        self._send(commands, commands, self._target.timeout, allow_text=True)

    def set_static_route(self, vrf: str, prefix: str, next_hop: str, *, add: bool) -> None:
        """Add (``add=True``) or remove one static route in a VRF: ``ip route P NH``
        or ``ipv6 route P NH`` and their ``no`` forms, inside ``vrf context <vrf>``
        unless ``vrf`` is ``default``. Never in management."""
        line = static_route_line(prefix, next_hop)
        if not add:
            line = "no " + line
        commands = [line] if vrf == DEFAULT_VRF else [f"vrf context {validate_vrf_name(vrf)}", line]
        self._send(commands, commands, self._target.timeout, allow_text=True)

    def configure_protocol(
        self,
        protocol: str,
        scope: str,
        setting: str,
        action: str,
        ident: dict[str, str],
        values: dict[str, str],
    ) -> None:
        """One change on a routing protocol's page (OSPF, BGP, HSRP, route-maps, ...).

        The lines are built here from the protocol's own description and the
        checked values (``routing_protocols.build_protocol_change``): entering the
        place (``router ospf core``, ``interface Vlan10``) and the one setting
        line, or making or deleting the place. Secrets are masked in error
        messages.
        """
        # Imported here: the protocol modules use this module's checks.
        from app.routing_protocols import build_protocol_change

        change = build_protocol_change(protocol, scope, setting, action, ident, values)
        self._send(list(change.lines), list(change.labels), self._target.timeout, allow_text=True)

    def save_config(self) -> None:
        """``copy running-config startup-config``: keep changes over a reboot.

        Saves from this process run one after another (``_save_lock``).
        """
        command = "copy running-config startup-config"
        timeout = max(self._target.timeout, SAVE_CONFIG_TIMEOUT)
        if not _save_lock.acquire(timeout=timeout):
            raise NxapiCommandError(
                f"{command!r}: another save from NXray is still running; try again shortly"
            )
        try:
            (body,) = self._send([command], [command], timeout, allow_text=True)
        finally:
            _save_lock.release()
        # The switch reports a failed copy as text, not as an error.
        text = str(body.get("text", ""))
        if "fail" in text.lower() or "error" in text.lower():
            raise NxapiCommandError(f"{command!r}: {text.strip()}")

    def _send(
        self,
        commands: list[str],
        labels: list[str],
        timeout: float,
        allow_text: bool = False,
    ) -> list[dict[str, Any]]:
        """POST commands as one JSON-RPC request and parse the answer."""
        try:
            response = self._http.post(
                self._target.url, json=build_payload(commands), timeout=timeout
            )
        except httpx.TimeoutException as exc:
            raise NxapiUnreachable(
                f"no answer from {self._target.host}:{self._target.port} within {timeout:g} seconds"
            ) from exc
        except httpx.HTTPError as exc:
            raise NxapiUnreachable(
                f"could not connect to {self._target.host}:{self._target.port}: {exc}"
            ) from exc

        if response.status_code in (401, 403):
            raise NxapiAuthError("the switch refused the NX-API username or password")

        # A rejected command comes back as HTTP 500 with a JSON-RPC error
        # body, so the body is read before the status decides anything.
        try:
            payload = response.json()
        except ValueError as exc:
            raise NxapiProtocolError(
                f"the switch answered HTTP {response.status_code} without JSON "
                "(is this address really NX-API?)"
            ) from exc

        return parse_response(payload, commands, labels, allow_text)
