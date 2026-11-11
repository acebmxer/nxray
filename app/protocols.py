"""Routing protocols: the shared parts every protocol page is built from.

Each protocol (OSPF, BGP, HSRP, ...) is described once, as data, in its own
module (``app/protocols_*.py``): what NXray reads from the switch for it, how
that output turns into what the page shows, and every setting the page can
change. A setting names the one configuration line it sends, with a typed,
checked value in each blank (``router-id {router_id}``). The command lines
are built here and only here, from those descriptions and checked values, so
nothing a user types reaches the switch except as a value that passed its
field's check (an address, a number in range, a name of letters and digits).
``NxapiClient.configure_protocol`` sends what ``build_change`` returns.

Words used throughout:

- A **scope** is a kind of place settings live: an OSPF process, an OSPF
  process inside a VRF, an interface's OSPF settings, a BGP neighbor, an HSRP
  group. A scope has identity fields (the process name, the interface) and
  the lines that enter it (``router ospf {tag}``, then ``vrf {vrf}``).
- An **instance** is one place of a scope that exists on the switch (process
  ``core`` in VRF ``lab``), with what the switch reports about it and the
  settings it currently has, when the switch's output tells.
- A **setting** is one line inside a scope, set with its values and removed
  with its ``no`` form.

Templates: ``{name}`` is replaced by the checked value of field ``name``;
text in ``[...]`` is left out when a field inside it is empty (optional
fields, unticked boxes). Brackets do not nest.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from app.nxapi import (
    DEFAULT_VRF,
    VLAN_INTERFACE_MAX,
    validate_channel_number,
    validate_description,
    validate_port_name,
    validate_routed_interface,
    validate_vlan_id,
    validate_vrf_name,
)
from app.oui import is_group_mac, normalize_mac
from app.switch import text
from app.switch_setup import scrub_secrets

# ---- fields --------------------------------------------------------------------

# Names the switch takes for process tags, route-maps, prefix-lists and key
# chains: a letter or digit first, then letters, digits, ".", "_" or "-".
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
# Secrets (passwords, keys): printable ASCII without spaces, ";" or "?",
# which NX-API refuses or splits on.
_SECRET = re.compile(r"^[\x21-\x7e]{1,63}$")
# An IS-IS NET: area (1-13 bytes), system ID (6 bytes), selector 00, in
# groups of four hex digits: 49.0001.1920.0000.2001.00.
_ISIS_NET = re.compile(r"^[0-9a-fA-F]{2}(?:\.[0-9a-fA-F]{4}){1,6}(?:\.[0-9a-fA-F]{4}){3}\.00$")
# BGP AS numbers: 1-4294967295, or the dotted form 1.0 - 65535.65535.
AS_MAX = 4294967295

KINDS = (
    "int",  # a whole number from minimum to maximum
    "ipv4",  # one IPv4 address
    "ipv6",  # one IPv6 address (link-local allowed where the protocol takes one)
    "ip",  # one IPv4 or IPv6 address
    "prefix4",  # an IPv4 network with its length: 192.0.2.0/24
    "prefix6",  # an IPv6 network with its length
    "prefix",  # either
    "group4",  # an IPv4 multicast group range: 224.0.0.0/4
    "group6",  # an IPv6 multicast group range: ff00::/8
    "area",  # an OSPF area: 0-4294967295 or dotted, written dotted
    "asn",  # a BGP AS number
    "name",  # a process tag, route-map, prefix-list or key chain name
    "secret",  # a password or key, never shown back
    "text",  # a description: printable ASCII, no "?" or ";"
    "choice",  # one of ``choices``
    "flag",  # a tick box; its value is the word ``choices[0]`` or nothing
    "interface",  # a VLAN interface (1-254), routed front port or port-channel
    "source",  # an interface whose address is used: as "interface", or a loopback
    "vrf",  # default or a VRF made on the switch; never management
    "net",  # an IS-IS NET
    "mac",  # a unicast MAC address, written 0200.0000.0001
    "maddr4",  # one IPv4 multicast group address: 239.1.1.1
    "port",  # a front port or port-channel, switched (layer 2): spanning tree
    "channel",  # a port-channel that exists on the switch: port-channel20 (or po20)
    "numlist",  # whole numbers and ranges from minimum to maximum: 46 or 8,10-12
    "vlan",  # one VLAN number, 1 to 3967 (the switch keeps 3968-4094 for itself)
    "vlans",  # VLAN numbers and ranges, 1 to 3967: 10 or 10,20-30
    "host",  # a server: an IP address or a DNS name such as ntp.example.net
    "domain",  # a DNS domain name such as example.net
    "usevrf",  # the VRF a server is reached in: default (sent as ""), management or another
    "hhmm",  # a time of day written 02:00
    "hhmmss",  # a time of day written 14:30:00
    "aclnet4",  # an ACL's IPv4 match: any, a network 192.0.2.0/24, or one address (as /32);
    # or an object group: addrgroup <name>
    "aclnet6",  # an ACL's IPv6 match: any, a network 2001:db8::/32, or one address (as /128);
    # or addrgroup <name>
    "l4port",  # a TCP or UDP port match: 22, 1024-65535, >1023, <1024 or !=23; or portgroup <name>
    "aclmac",  # a MAC ACL's match: any, one address, or an address and a mask (any MAC)
    "ethertype",  # an EtherType written 0x0800, 0x0600 to 0xffff
    "arpip",  # an ARP ACL's IPv4 match: any, or one address (as host <address>)
    "arpmac",  # an ARP ACL's MAC match: any, or one address (as host <address>)
    "url",  # a web address: http://<host>[:<port>][/<path>], no "?" (NX-API refuses it)
    "slalife",  # how long an IP SLA entry runs: forever, or 1 to 2147483647 seconds
    "slastart",  # when an IP SLA entry starts: now, pending, after 00:10:00, 14:30 or
    # 14:30:00, with a date after it if wanted (14:30:00 Nov 12)
)

# The highest VLAN a spanning-tree line may name: NX-OS keeps 3968-4094 as its
# own internal VLANs.
STP_VLAN_MAX = 3967


@dataclass(frozen=True)
class Field:
    """One blank in a setting's line."""

    name: str
    label: str
    kind: str
    minimum: int | None = None
    maximum: int | None = None
    choices: tuple[str, ...] = ()
    optional: bool = False
    hint: str = ""
    placeholder: str = ""

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown field kind {self.kind!r}")
        if self.kind in ("choice", "flag") and not self.choices:
            raise ValueError(f"field {self.name} needs choices")


def _int(value: str, low: int | None, high: int | None, label: str) -> str:
    if not value.isascii() or not value.isdigit():
        raise ValueError(f"{label} is a whole number")
    number = int(value)
    if low is not None and number < low or high is not None and number > high:
        raise ValueError(f"{label} is a number from {low} to {high}")
    return str(number)


def _network(value: str, version: int | None, label: str) -> str:
    if "/" not in value:
        raise ValueError(f"{label}: add the prefix length to {value!r}, such as /24")
    try:
        loose = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"{label}: {value!r} is not a network such as 192.0.2.0/24") from exc
    if version is not None and loose.version != version:
        raise ValueError(f"{label} must be an IPv{version} network")
    try:
        network = ipaddress.ip_network(value)
    except ValueError as exc:
        raise ValueError(
            f"{label}: {value} is not the start of its network; did you mean {loose}?"
        ) from exc
    return str(network)


def _address(value: str, version: int | None, label: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{label}: {value!r} is not an IP address") from exc
    if version is not None and address.version != version:
        raise ValueError(f"{label} must be an IPv{version} address")
    if address.is_unspecified or address.is_loopback or address.is_multicast:
        raise ValueError(f"{label}: {address} is not an address a router can have")
    return str(address)


def _area(value: str, label: str) -> str:
    if value.isascii() and value.isdigit():
        number = int(value)
        if number > 4294967295:
            raise ValueError(f"{label} is 0 to 4294967295 or written like 0.0.0.1")
        return str(ipaddress.IPv4Address(number))
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError as exc:
        raise ValueError(f"{label} is a number such as 0 or written like 0.0.0.1") from exc


def _asn(value: str, label: str) -> str:
    if re.fullmatch(r"[0-9]{1,10}", value) and 1 <= int(value) <= AS_MAX:
        return str(int(value))
    if match := re.fullmatch(r"([0-9]{1,5})\.([0-9]{1,5})", value):
        high, low = int(match.group(1)), int(match.group(2))
        if high <= 65535 and low <= 65535 and (high or low):
            return f"{high}.{low}"
    raise ValueError(f"{label} is an AS number from 1 to {AS_MAX} (or written like 1.10)")


def _group(value: str, version: int, label: str) -> str:
    network = _network(value, version, label)
    if not ipaddress.ip_network(network).is_multicast:
        raise ValueError(f"{label}: {network} is not a multicast group range")
    return network


def _interface(value: str, label: str) -> str:
    try:
        name = validate_routed_interface(value)
    except ValueError as exc:
        raise ValueError(f"{label}: {exc}") from exc
    if name.startswith("Vlan") and int(name[4:]) > VLAN_INTERFACE_MAX:
        raise ValueError(
            f"{label}: NXray changes VLAN interfaces of VLANs 1 to {VLAN_INTERFACE_MAX} only"
        )
    return name


_LOOPBACK = re.compile(r"(?i)^(?:lo|loopback)\s*([0-9]{1,4})$")
# Characters a key or password may not start with: the switch reads them as
# an output pipe, a redirect, an escape or the start of a quoted string.
_SECRET_FIRST = "|>\\('\""


# A DNS name: labels of letters, digits and "-" (not first or last), joined by ".".
_DNS_NAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_HHMM = re.compile(r"^([0-9]{1,2}):([0-9]{2})$")
_HHMMSS = re.compile(r"^([0-9]{1,2}):([0-9]{2}):([0-9]{2})$")


def _host(value: str, label: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if not _DNS_NAME.fullmatch(value) or value.replace(".", "").isdigit():
            raise ValueError(
                f"{label} is an IP address or a name such as ntp.example.net"
            ) from None
        return value.lower()
    return _address(value, None, label)


def _domain(value: str, label: str) -> str:
    if not _DNS_NAME.fullmatch(value) or value.replace(".", "").isdigit():
        raise ValueError(f"{label} is a domain name such as example.net")
    return value.lower()


def _use_vrf(value: str, label: str) -> str:
    if value == DEFAULT_VRF:
        return ""
    if value == "management":
        return value
    try:
        return validate_vrf_name(value)
    except ValueError as exc:
        raise ValueError(f"{label}: {exc}") from exc


def _time_of_day(value: str, label: str, seconds: bool) -> str:
    match = (_HHMMSS if seconds else _HHMM).fullmatch(value)
    written = "14:30:00" if seconds else "02:00"
    if not match:
        raise ValueError(f"{label} is a time of day written like {written}")
    parts = [int(g) for g in match.groups()]
    if parts[0] > 23 or parts[1] > 59 or (seconds and parts[2] > 59):
        raise ValueError(f"{label} is a time of day from 00:00 to 23:59, written like {written}")
    return ":".join(f"{p:02d}" for p in parts)


_CHANNEL = re.compile(r"(?i)^(?:po|port-channel)\s*([0-9]{1,4})$")
_ETHERNET = re.compile(r"(?i)^(?:eth|ethernet)\s*([0-9]+/[0-9]+(?:/[0-9]+)?)$")
_VLAN_LIST = re.compile(r"^[0-9]{1,4}(?:-[0-9]{1,4})?(?:,[0-9]{1,4}(?:-[0-9]{1,4})?)*$")


def _switch_port(value: str, label: str) -> str:
    if match := _CHANNEL.fullmatch(value):
        try:
            return f"port-channel{validate_channel_number(match.group(1))}"
        except ValueError as exc:
            raise ValueError(f"{label}: {exc}") from exc
    match = _ETHERNET.fullmatch(value)
    try:
        return validate_port_name(f"Ethernet{match.group(1)}" if match else value)
    except ValueError as exc:
        raise ValueError(f"{label}: a front port such as Ethernet1/3 or a port-channel") from exc


def _channel_name(value: str, label: str) -> str:
    match = _CHANNEL.fullmatch(value)
    if not match:
        raise ValueError(f"{label} is a port-channel such as port-channel20")
    try:
        return f"port-channel{validate_channel_number(match.group(1))}"
    except ValueError as exc:
        raise ValueError(f"{label}: {exc}") from exc


def _vlan(value: str, label: str) -> str:
    try:
        number = validate_vlan_id(value)
    except ValueError as exc:
        raise ValueError(f"{label}: {exc}") from exc
    if number > STP_VLAN_MAX:
        raise ValueError(f"{label}: VLANs {STP_VLAN_MAX + 1} to 4094 are the switch's own")
    return str(number)


def _vlans(value: str, label: str) -> str:
    """'10, 20-30' -> '10,20-30': every number 1-3967, every range low-high."""
    compact = re.sub(r"\s*([,-])\s*", r"\1", value)
    if not _VLAN_LIST.fullmatch(compact):
        raise ValueError(f"{label} is VLAN numbers and ranges such as 10,20-30")
    for part in compact.split(","):
        low, _, high = part.partition("-")
        _vlan(low, label)
        if high:
            _vlan(high, label)
            if int(high) <= int(low):
                raise ValueError(f"{label}: in {part} the second number must be the higher one")
    return compact


_NUMBER_LIST = re.compile(r"^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*$")


def _numlist(value: str, low: int | None, high: int | None, label: str) -> str:
    """'8, 10-12' -> '8,10-12': every number from ``low`` to ``high``, every range
    lower-higher."""
    compact = re.sub(r"\s*([,-])\s*", r"\1", value)
    if not _NUMBER_LIST.fullmatch(compact):
        raise ValueError(f"{label} is numbers and ranges such as 8,10-12")
    for part in compact.split(","):
        first, _, last = part.partition("-")
        _int(first, low, high, label)
        if last:
            _int(last, low, high, label)
            if int(last) <= int(first):
                raise ValueError(f"{label}: in {part} the second number must be the higher one")
    return compact


def _source(value: str, label: str) -> str:
    if match := _LOOPBACK.fullmatch(value):
        number = int(match.group(1))
        if number > 1023:
            raise ValueError(f"{label}: loopbacks are numbered 0 to 1023")
        return f"loopback{number}"
    return _interface(value, label)


def _mac(value: str, label: str) -> str:
    digits = normalize_mac(value)
    if digits is None:
        raise ValueError(f"{label} is written like 0200.0000.0001")
    if is_group_mac(digits):
        raise ValueError(f"{label}: {value} is a multicast MAC address, not one a gateway can have")
    if digits == "0" * 12:
        raise ValueError(f"{label}: 0000.0000.0000 is not a MAC address a gateway can have")
    return f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}"


def _multicast_address(value: str, label: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ValueError(f"{label}: {value!r} is not an IPv4 address such as 239.1.1.1") from exc
    if not address.is_multicast:
        raise ValueError(
            f"{label}: {address} is not a multicast group (224.0.0.0 to 239.255.255.255)"
        )
    if address in ipaddress.IPv4Network("224.0.0.0/24"):
        raise ValueError(f"{label}: {address} is kept for routers talking to each other")
    return str(address)


def _acl_network(value: str, version: int, label: str) -> str:
    """'any', a network with its length, or one address written as /32 (/128)."""
    if value.lower() == "any":
        return "any"
    if group := _object_group(value, "addrgroup", label):
        return group
    example = "192.0.2.0/24" if version == 4 else "2001:db8::/32"
    if "/" not in value:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(
                f"{label} is any, a network such as {example}, or one address"
            ) from exc
        if address.version != version:
            raise ValueError(f"{label} must be an IPv{version} address")
        return f"{address}/{address.max_prefixlen}"
    return _network(value, version, label)


_L4PORT = re.compile(r"^(eq|gt|lt|neq|>|<|!=)?\s*([0-9]{1,5})$")
_L4RANGE = re.compile(r"^(?:range\s+)?([0-9]{1,5})\s*[- ]\s*([0-9]{1,5})$")
_L4WORDS = {None: "eq", ">": "gt", "<": "lt", "!=": "neq"}


def _l4port(value: str, label: str) -> str:
    """'22' -> 'eq 22', '1024-65535' -> 'range 1024 65535', '>1023' -> 'gt 1023',
    '<1024' -> 'lt 1024', '!=23' -> 'neq 23'; the words themselves are taken too."""
    if group := _object_group(value, "portgroup", label):
        return group
    wrong = f"{label} is a port (22), a range (1024-65535), >1023, <1024 or !=23"
    if match := _L4RANGE.fullmatch(value):
        low, high = (int(g) for g in match.groups())
        if high > 65535 or low >= high:
            raise ValueError(f"{label}: a range is two ports from 0 to 65535, lower first")
        return f"range {low} {high}"
    match = _L4PORT.fullmatch(value)
    if not match:
        raise ValueError(wrong)
    number = int(match.group(2))
    if number > 65535:
        raise ValueError(f"{label}: ports go from 0 to 65535")
    word = _L4WORDS.get(match.group(1), match.group(1))
    return f"{word} {number}"


def _object_group(value: str, word: str, label: str) -> str:
    """'addrgroup web' -> 'addrgroup web' (the same for portgroup); "" when ``value``
    does not start with ``word``."""
    parts = value.split()
    if not parts or parts[0].lower() != word:
        return ""
    if len(parts) != 2 or not _NAME.fullmatch(parts[1]) or len(parts[1]) > 64:
        raise ValueError(f"{label}: {word} is followed by an object group's name")
    return f"{word} {parts[1]}"


def _any_mac(value: str, label: str) -> str:
    """Any MAC address, multicast and broadcast too, written 0200.0000.0001."""
    digits = normalize_mac(value)
    if digits is None:
        raise ValueError(f"{label}: {value!r} is not a MAC address such as 0200.0000.0001")
    return f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}"


def _acl_mac(value: str, label: str) -> str:
    """'any', one address (matched exactly: mask 0000.0000.0000), or an address and
    a mask whose 1 bits are ignored: '0200.0000.0000 0000.00ff.ffff'."""
    if value.lower() == "any":
        return "any"
    parts = value.split()
    if len(parts) == 1:
        return f"{_any_mac(parts[0], label)} 0000.0000.0000"
    if len(parts) == 2:
        return f"{_any_mac(parts[0], label)} {_any_mac(parts[1], label + ' mask')}"
    raise ValueError(f"{label} is any, an address, or an address and a mask")


def _ethertype(value: str, label: str) -> str:
    match = re.fullmatch(r"(?:0x)?([0-9a-fA-F]{1,4})", value)
    number = int(match.group(1), 16) if match else -1
    if number < 0x600:
        raise ValueError(f"{label} is an EtherType from 0x0600 to 0xffff, such as 0x0800")
    return f"0x{number:04x}"


def _arp_match(value: str, kind: str, label: str) -> str:
    """'any' or one address, sent as 'host <address>'."""
    if value.lower() == "any":
        return "any"
    if kind == "arpmac":
        return f"host {_any_mac(value, label)}"
    return f"host {_address(value, 4, label)}"


_URL = re.compile(r"^http://([^/:\s]+)(?::([0-9]{1,5}))?(/[A-Za-z0-9._~%!$&'()*+,=:@/-]*)?$")


def _url(value: str, label: str) -> str:
    """'http://192.0.2.1/', 'http://www.example.net:8080/status': an address the switch
    fetches. Only http: the switch's IP SLA ``http get`` takes no other scheme."""
    match = _URL.fullmatch(value)
    if not match:
        raise ValueError(f"{label} is a web address such as http://192.0.2.1/index.html")
    host = _host(match.group(1), label)
    port = match.group(2)
    if port is not None and not 1 <= int(port) <= 65535:
        raise ValueError(f"{label}: the port is 1 to 65535")
    return f"http://{host}{':' + port if port else ''}{match.group(3) or '/'}"


# The longest life and the largest number of seconds an IP SLA line takes.
SLA_SECONDS_MAX = 2147483647
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_SLA_AT = re.compile(r"^([0-9]{1,2}:[0-9]{2}(?::[0-9]{2})?)(?:\s+([A-Za-z]{3})\s+([0-9]{1,2}))?$")


def _sla_life(value: str, label: str) -> str:
    if value.lower() == "forever":
        return "forever"
    return _int(value, 1, SLA_SECONDS_MAX, label + " (seconds, or forever)")


def _sla_start(value: str, label: str) -> str:
    """now, pending, 'after 00:10:00' (a wait), or a time of day with an optional date:
    '14:30', '14:30:00', '14:30:00 Nov 12'."""
    words = " ".join(value.split())
    if words.lower() in ("now", "pending"):
        return words.lower()
    if words.lower().startswith("after "):
        return "after " + _time_of_day(words[6:], label + " (after)", True)
    match = _SLA_AT.fullmatch(words)
    if not match:
        raise ValueError(
            f"{label} is now, pending, after 00:10:00, or a time such as 14:30 or 14:30:00 Nov 12"
        )
    clock = match.group(1)
    when = _time_of_day(clock, label, clock.count(":") == 2)
    if match.group(2) is None:
        return when
    month = match.group(2).capitalize()
    day = int(match.group(3))
    if month not in _MONTHS or not 1 <= day <= 31:
        raise ValueError(f"{label}: the date is a month and a day, such as Nov 12")
    return f"{when} {month} {day}"


def check_value(spec: Field, raw: str) -> str:
    """``raw`` as the switch should get it, or "" for an empty optional field.

    Raises ValueError with a message naming the field.
    """
    value = raw.strip()
    if spec.kind == "flag":
        return spec.choices[0] if value else ""
    if not value:
        if spec.optional:
            return ""
        raise ValueError(f"{spec.label} is needed")
    if _FORBIDDEN.search(value) and spec.kind != "secret":
        raise ValueError(f'{spec.label} cannot contain ";", "?" or a line break')
    kind = spec.kind
    if kind == "int":
        return _int(value, spec.minimum, spec.maximum, spec.label)
    if kind in ("ipv4", "ipv6", "ip"):
        return _address(value, {"ipv4": 4, "ipv6": 6}.get(kind), spec.label)
    if kind in ("prefix4", "prefix6", "prefix"):
        return _network(value, {"prefix4": 4, "prefix6": 6}.get(kind), spec.label)
    if kind in ("group4", "group6"):
        return _group(value, 4 if kind == "group4" else 6, spec.label)
    if kind == "area":
        return _area(value, spec.label)
    if kind == "asn":
        return _asn(value, spec.label)
    if kind == "name":
        longest = spec.maximum or 63
        if not _NAME.fullmatch(value) or len(value) > longest:
            raise ValueError(
                f"{spec.label} is 1 to {longest} letters, digits, '.', '_' or '-', starting with "
                "a letter or digit"
            )
        return value
    if kind == "secret":
        longest = spec.maximum or 63
        if not _SECRET.fullmatch(value) or ";" in value or "?" in value or len(value) > longest:
            raise ValueError(
                f'{spec.label} is 1 to {longest} characters without spaces, ";" or "?"'
            )
        if value[0] in _SECRET_FIRST:
            raise ValueError(f"{spec.label} cannot start with any of {' '.join(_SECRET_FIRST)}")
        return value
    if kind == "text":
        try:
            text = validate_description(value)
        except ValueError as exc:
            raise ValueError(f"{spec.label}: {exc}") from exc
        if spec.maximum is not None and len(text) > spec.maximum:
            raise ValueError(f"{spec.label} is at most {spec.maximum} characters")
        return text
    if kind == "choice":
        if value not in spec.choices:
            raise ValueError(f"{spec.label} is one of {', '.join(spec.choices)}")
        return value
    if kind == "interface":
        return _interface(value, spec.label)
    if kind == "source":
        return _source(value, spec.label)
    if kind == "mac":
        return _mac(value, spec.label)
    if kind == "maddr4":
        return _multicast_address(value, spec.label)
    if kind == "port":
        return _switch_port(value, spec.label)
    if kind == "channel":
        return _channel_name(value, spec.label)
    if kind == "vlan":
        return _vlan(value, spec.label)
    if kind == "vlans":
        return _vlans(value, spec.label)
    if kind == "numlist":
        return _numlist(value, spec.minimum, spec.maximum, spec.label)
    if kind == "host":
        return _host(value, spec.label)
    if kind == "domain":
        return _domain(value, spec.label)
    if kind == "usevrf":
        return _use_vrf(value, spec.label)
    if kind in ("aclnet4", "aclnet6"):
        return _acl_network(value, 4 if kind == "aclnet4" else 6, spec.label)
    if kind == "l4port":
        return _l4port(value, spec.label)
    if kind == "aclmac":
        return _acl_mac(value, spec.label)
    if kind == "ethertype":
        return _ethertype(value, spec.label)
    if kind in ("arpip", "arpmac"):
        return _arp_match(value, kind, spec.label)
    if kind == "url":
        return _url(value, spec.label)
    if kind == "slalife":
        return _sla_life(value, spec.label)
    if kind == "slastart":
        return _sla_start(value, spec.label)
    if kind in ("hhmm", "hhmmss"):
        return _time_of_day(value, spec.label, kind == "hhmmss")
    if kind == "vrf":
        if value == DEFAULT_VRF:
            if not spec.optional:
                raise ValueError(
                    f"{spec.label}: pick a VRF other than default; the default VRF's settings "
                    "are the process's own"
                )
            return ""
        try:
            return validate_vrf_name(value)
        except ValueError as exc:
            raise ValueError(f"{spec.label}: {exc}") from exc
    if kind == "net":
        if not _ISIS_NET.fullmatch(value):
            raise ValueError(f"{spec.label} is written like 49.0001.1920.0000.2001.00")
        return value.lower()
    raise ValueError(f"unknown field kind {kind!r}")  # pragma: no cover - __post_init__


_FORBIDDEN = re.compile(r"[;?\r\n]")

# ---- templates -------------------------------------------------------------------

_SEGMENT = re.compile(r"\[([^\[\]]*)\]")
_BLANK = re.compile(r"\{([a-z_0-9]+)\}")


def render(template: str, values: dict[str, str]) -> str:
    """Fill a template with checked values; ``[...]`` parts with an empty value drop out.

    Every ``{name}`` must have an entry in ``values`` (KeyError otherwise),
    so a template and its fields cannot drift apart unnoticed.
    """

    def optional(match: re.Match[str]) -> str:
        part = match.group(1)
        names = _BLANK.findall(part)
        if any(not values[name] for name in names):
            return ""
        return _BLANK.sub(lambda m: values[m.group(1)], part)

    text = _SEGMENT.sub(optional, template)
    text = _BLANK.sub(lambda m: values[m.group(1)], text)
    return " ".join(text.split())


def blanks(template: str) -> set[str]:
    """The field names a template uses."""
    return set(_BLANK.findall(template))


# ---- settings, scopes, protocols -----------------------------------------------


@dataclass(frozen=True)
class Setting:
    """One configuration line inside a scope.

    ``line`` sets it; ``no_line`` (default: ``no`` + the line) removes it;
    removing checks only the fields ``no_line`` uses, so a password is not
    typed again to remove it. ``group`` sorts the page's forms under a
    heading. ``warning`` is shown on the confirm page, for settings that
    break or restart something. ``check``, when given, gets the checked
    values before a set and raises ValueError for a combination the fields
    alone cannot refuse (a prefix-list entry's lengths). ``ident`` names the
    scope's identity fields the lines also use, for scopes whose lines are
    typed at the top level and carry the place in them (``spanning-tree vlan
    {vlan} priority {priority}``); the scope checks it has them. ``config``
    false marks a command that changes no configuration (``clock set``): it
    leaves nothing to save.
    """

    key: str
    label: str
    line: str
    fields: tuple[Field, ...] = ()
    no_line: str | None = None
    settable: bool = True
    removable: bool = True
    help: str = ""
    warning: str = ""
    group: str = "Settings"
    check: Callable[[dict[str, str]], None] | None = None
    ident: tuple[str, ...] = ()
    config: bool = True

    def __post_init__(self) -> None:
        names = {f.name for f in self.fields} | set(self.ident)
        used = blanks(self.line) | blanks(self.no_line or "")
        if used - names:
            raise ValueError(f"setting {self.key}: no field for {sorted(used - names)}")

    @property
    def secret_fields(self) -> set[str]:
        return {f.name for f in self.fields if f.kind == "secret"}

    @property
    def remove_fields(self) -> tuple[Field, ...]:
        """The fields removing needs: those ``no_line`` uses, or all of them."""
        if self.no_line is None:
            return self.fields
        used = blanks(self.no_line)
        return tuple(f for f in self.fields if f.name in used)


@dataclass(frozen=True)
class Scope:
    """A kind of place settings live, and how to get into it.

    ``enter`` are the templates of the lines that enter one place (all of
    them run before a setting's line). ``create`` true: entering makes the
    place when it is missing (``router ospf {tag}``); the page then offers a
    form to make one. ``delete`` are the lines that remove one place, run
    instead of entering it. ``parent`` names the scope whose identity fields
    this one starts with (a process's VRF part inside the process).
    """

    key: str
    label: str
    ident: tuple[Field, ...]
    enter: tuple[str, ...]
    settings: tuple[Setting, ...] = ()
    create: bool = False
    create_label: str = ""
    delete: tuple[str, ...] | None = None
    delete_warning: str = ""
    help: str = ""

    def __post_init__(self) -> None:
        names = {f.name for f in self.ident}
        used: set[str] = set()
        for template in (*self.enter, *(self.delete or ())):
            used |= blanks(template)
        if used - names:
            raise ValueError(f"scope {self.key}: no identity field for {sorted(used - names)}")
        clash = names & {f.name for s in self.settings for f in s.fields}
        if clash:
            raise ValueError(f"scope {self.key}: settings reuse identity field names {clash}")
        borrowed = {name for s in self.settings for name in s.ident}
        if borrowed - names:
            raise ValueError(f"scope {self.key}: no identity field for {sorted(borrowed - names)}")

    def setting(self, key: str) -> Setting | None:
        return next((s for s in self.settings if s.key == key), None)

    @property
    def groups(self) -> list[tuple[str, list[Setting]]]:
        """The settings grouped by ``Setting.group``, in first-seen order."""
        found: dict[str, list[Setting]] = {}
        for setting in self.settings:
            found.setdefault(setting.group, []).append(setting)
        return list(found.items())


@dataclass(frozen=True)
class Table:
    """A table the page shows as it is: neighbors, interfaces, groups, routes."""

    title: str
    columns: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...] = ()
    empty: str = "None."
    note: str = ""
    # When set, only this column (counted from 0) wraps its text and takes the spare
    # width; the other columns stay on one line. None: every column wraps.
    wrap_column: int | None = None


@dataclass(frozen=True)
class Instance:
    """One place of a scope that exists on the switch.

    ``ident`` holds its identity field values (as the page sends them back);
    ``values`` the settings it has now, by setting key, as field values, for
    the ones the switch's output tells. ``facts`` are shown as they are.
    """

    scope: str
    ident: dict[str, str]
    title: str
    facts: tuple[tuple[str, str], ...] = ()
    values: dict[str, dict[str, str]] = field(default_factory=dict)


@dataclass(frozen=True)
class ProtocolView:
    """What a protocol's page shows, from its parser."""

    instances: tuple[Instance, ...] = ()
    tables: tuple[Table, ...] = ()
    notes: tuple[str, ...] = ()

    def of(self, scope: str) -> list[Instance]:
        return [i for i in self.instances if i.scope == scope]


@dataclass(frozen=True)
class Protocol:
    """One page under Routing protocols.

    ``features`` are the ``show feature`` names that must be on (all of
    them; the page says which is off and links to Features). ``commands``
    are read in one request while they are; ``parse`` turns their bodies,
    in that order, into a ProtocolView.
    """

    key: str
    name: str
    summary: str
    features: tuple[str, ...]
    commands: tuple[str, ...]
    parse: Callable[[list[dict[str, Any]]], ProtocolView]
    scopes: tuple[Scope, ...]
    about: str = ""

    def scope(self, key: str) -> Scope | None:
        return next((s for s in self.scopes if s.key == key), None)


# ---- building a change ---------------------------------------------------------

ACTIONS = ("set", "remove", "create", "delete")


@dataclass(frozen=True)
class ProtocolChange:
    """The lines one change sends, with the secrets masked in ``labels``.

    ``describe`` is the plain-words line for the confirm page and the
    notice afterwards. ``config`` is false for a command that changes no
    configuration, so there is nothing to save afterwards.
    """

    protocol: str
    scope: str
    setting: str
    action: str
    lines: tuple[str, ...]
    labels: tuple[str, ...]
    describe: str
    warning: str = ""
    config: bool = True


def _checked(fields: Iterable[Field], raw: dict[str, str]) -> dict[str, str]:
    return {f.name: check_value(f, raw.get(f.name, "")) for f in fields}


def _where(scope: Scope, ident: dict[str, str]) -> str:
    parts = [f"{f.label} {ident[f.name]}" for f in scope.ident if ident.get(f.name)]
    return f"{scope.label} ({', '.join(parts)})" if parts else scope.label


def build_change(
    protocol: Protocol,
    scope_key: str,
    setting_key: str,
    action: str,
    ident: dict[str, str],
    values: dict[str, str],
) -> ProtocolChange:
    """The checked lines for one change, or ValueError naming what is wrong.

    ``action``: ``set`` or ``remove`` a setting, ``create`` or ``delete`` a
    place of a scope that allows it (``setting_key`` is then ignored).
    """
    if action not in ACTIONS:
        raise ValueError(f"unknown action {action!r}")
    scope = protocol.scope(scope_key)
    if scope is None:
        raise ValueError(f"{protocol.name} has no {scope_key!r} settings")
    where = _checked(scope.ident, ident)
    enter = [line for line in (render(t, where) for t in scope.enter) if line]
    if action == "create":
        if not scope.create:
            raise ValueError(f"a {scope.label.lower()} is not made from here")
        return ProtocolChange(
            protocol.key,
            scope.key,
            "",
            action,
            tuple(enter),
            tuple(enter),
            f"{protocol.name}: make {_where(scope, where)}.",
        )
    if action == "delete":
        if scope.delete is None:
            raise ValueError(f"a {scope.label.lower()} is not deleted from here")
        lines = tuple(line for line in (render(t, where) for t in scope.delete) if line)
        return ProtocolChange(
            protocol.key,
            scope.key,
            "",
            action,
            lines,
            lines,
            f"{protocol.name}: delete {_where(scope, where)}.",
            scope.delete_warning,
        )
    setting = scope.setting(setting_key)
    if setting is None:
        raise ValueError(f"{protocol.name} {scope.label.lower()} has no setting {setting_key!r}")
    if action == "set" and not setting.settable:
        raise ValueError(f"{setting.label} is only removed from here")
    if action == "remove" and not setting.removable:
        raise ValueError(f"{setting.label} cannot be removed, only changed")
    borrowed = {name: where[name] for name in setting.ident}
    if action == "set":
        checked = _checked(setting.fields, values)
        if setting.check is not None:
            setting.check(checked)
        line = render(setting.line, {**borrowed, **checked})
    else:
        checked = _checked(setting.remove_fields, values)
        line = (
            render(setting.no_line, {**borrowed, **checked})
            if setting.no_line
            else "no " + render(setting.line, {**borrowed, **checked})
        )
    label = scrub_secrets(line, *(checked.get(name, "") for name in setting.secret_fields))
    shown = [
        "***" if f.kind == "secret" else checked[f.name]
        for f in setting.fields
        if checked.get(f.name)
    ]
    verb = "set" if action == "set" else "remove"
    return ProtocolChange(
        protocol.key,
        scope.key,
        setting.key,
        action,
        (*enter, line),
        (*enter, label),
        f"{protocol.name}, {_where(scope, where)}: {verb} {setting.label}"
        + (f" ({' '.join(shown)})" if shown else "")
        + ".",
        setting.warning if action == "set" else "",
        setting.config,
    )


# ---- helpers for the protocol modules ------------------------------------------


_DURATION = re.compile(r"^P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$")


def route_age(value: str) -> str:
    """'P1DT13H30M23S' (how the switch writes a route's or session's age) -> '1d 13h 30m';
    'PT11S' -> '11s'; anything else as it is."""
    match = _DURATION.match(value)
    if not match or not any(match.groups()):
        return value
    days, hours, minutes, seconds = (int(g) if g else 0 for g in match.groups())
    parts = (
        f"{days}d" if days else "",
        f"{hours}h" if hours else "",
        f"{minutes}m" if minutes else "",
    )
    shown = " ".join(part for part in parts if part)
    return shown or f"{seconds}s"


def table_rows(body: Any, table: str, row: str) -> list[dict[str, Any]]:
    """The rows of an NX-OS table, one row or many, at any level of a body.

    The same as ``app.switch.rows`` but also takes a list of tables, which
    some protocol outputs give (``TABLE_route`` in ``show ipv6 static-route``,
    several ``TABLE_vrf`` levels); deliberately not a change to ``rows``, which
    many parsers rely on as it is.
    """
    if not isinstance(body, dict):
        return []
    container = body.get(table)
    containers = container if isinstance(container, list) else [container]
    found: list[dict[str, Any]] = []
    for item in containers:
        if not isinstance(item, dict):
            continue
        value = item.get(row)
        if isinstance(value, dict):
            found.append(value)
        elif isinstance(value, list):
            found.extend(v for v in value if isinstance(v, dict))
    return found


def vrf_field(optional: bool = True) -> Field:
    """The VRF identity field most protocol scopes share."""
    return Field(
        "vrf",
        "VRF",
        "vrf",
        optional=optional,
        hint="default, or a VRF made on the Routing page",
        placeholder="default",
    )


def source_field(name: str = "source", label: str = "Source interface") -> Field:
    """An interface whose address a protocol uses: a loopback, VLAN interface,
    routed port or routed port-channel."""
    return Field(
        name,
        label,
        "source",
        hint="Its address is used: a loopback (loopback0), VLAN interface, routed port or "
        "routed port-channel",
        placeholder="loopback0",
    )


def port_field() -> Field:
    """The port identity field of spanning-tree port scopes: a switched front port
    or port-channel."""
    return Field(
        "port",
        "Port",
        "port",
        hint="A front port (Ethernet1/3) or port-channel (port-channel43)",
        placeholder="Ethernet1/3",
    )


def channel_field() -> Field:
    """The port-channel identity field of the vPC page's port-channel scope."""
    return Field(
        "channel",
        "Port-channel",
        "channel",
        hint="A port-channel made on the Port-channels page",
        placeholder="port-channel20",
    )


def interface_field() -> Field:
    """The interface identity field of interface scopes."""
    return Field(
        "interface",
        "Interface",
        "interface",
        hint="A VLAN interface (Vlan1 to Vlan254), routed port or routed port-channel",
        placeholder="Vlan10",
    )


__all__ = [
    "ACTIONS",
    "Field",
    "Instance",
    "KINDS",
    "Protocol",
    "ProtocolChange",
    "ProtocolView",
    "Scope",
    "Setting",
    "Table",
    "blanks",
    "build_change",
    "channel_field",
    "check_value",
    "interface_field",
    "port_field",
    "render",
    "route_age",
    "source_field",
    "table_rows",
    "text",
    "vrf_field",
]
