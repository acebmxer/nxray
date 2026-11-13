"""VXLAN OAM (NGOAM): ping, traceroute and pathtrace across a VXLAN fabric, the profiles
they use, and loop detection.

With ``feature ngoam`` on, the switch sends OAM messages inside VXLAN: ``ping nve`` checks
that a VTEP or host answers, ``traceroute nve`` lists the switches on the way, and
``pathtrace nve`` adds each hop's ports and their state (and, with ``req-stats``, their
counters). Each is aimed one of four ways: an address in a VNI (``ip <a> [profile <p>] vni
<n>``), an address in a VRF (``ip <a> vrf <v> [profile <p>]``), a host found by its traffic
(``ip unknown vrf <v> payload [mac-addr <dst> <src>] [ip <dst> <src>] [port <src> <dst>]
[proto <n>] payload-end``), or a MAC address in a VLAN (``mac <m> <vlan> [<port>]``). Then
the outer UDP source port (``sport``), the address to send from (``source``), how many and
how big (ping's ``count``, ``packet-size``, ``interval``), ``timeout``, how many hops
(``max-ttl``), the port to send out of (``egress``) and ``verbose``.

A **profile** (``ngoam profile <1-1023>``) holds what a tool sends: the hop count, the outer
source port, the NVO3 channel (``oam-channel 2``), the payload's pad, a VLAN tag or port, and
a **flow** (``flow forward|reverse``) with the inner addresses, ports and protocol. Switch
wide: ``ngoam install acl``, ``ngoam authentication-key``, ``ngoam xconnect hb-interval``
(VXLAN cross connect). **Loop detection** (``ngoam loop-detection``) probes VLANs for loops
and blocks a looped port until it recovers or is brought up again.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes, each setting the one line it sends with checked values in its
blanks, and ``build_ngoam_change`` building the lines. ``NxapiClient.configure_ngoam`` sends
them, and for a tool returns what the switch printed, shown on the page as it is.

Read from the switch: ``show feature``, ``show inventory`` and ``show interface brief`` in one
request; while ngoam is on, ``show ngoam loopback|traceroute|pathtrace
statistics summary`` in one request, ``show ngoam acl status`` and ``show running-config``
as text.

Tried on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-13), all removed and the feature
turned back off afterwards; the switch had VXLAN on but no NVE interface, so every tool
answered "request not sent" ("Failed to get vni data from nve", "Route not found"): replies
from a real fabric were not seen. ``feature ngoam`` was taken (it adds no other line); every
tool form here was typed in the order given above and taken (the profile comes before
``vni`` but after ``vrf``; ``source`` after ``sport``; a payload only with ``vrf``; a range of
source ports multiplies the probes, so one port is offered), with the switch's ranges: count
1-65535 (NXray offers up to 100), packet size 1-9500, interval 0-25, timeout 0-25 (traceroute
1-30), max-ttl 1-255, VNI 1-16777215. Every profile and flow line was taken with its bare
``no`` form, except that a profile's description cannot be removed (the switch answers and
keeps it). ``oam-channel`` takes only 2, and traceroute refuses a profile with it. A profile's
``interface`` takes front ports only: ``interface loopback250`` typed there made a loopback
instead, so NXray offers Ethernet ports only. ``ngoam xconnect hb-interval`` takes 150-5000;
``ngoam authentication-key`` is shown by the switch in plain text, and never by NXray. The
counters' clear commands were taken. Not tried: ``ngoam install acl`` (it writes an entry into
the switch's hardware access lists; after Cisco's guide), and loop detection, which this
switch refuses ("Loop detection not supported on this hardware"; Cisco's NX-OS 9.3 VXLAN guide
lists it for the Nexus 9300-EX, -FX and -FX2, the 9332C and 9364C and the 9500 with -EX and
-FX line cards); its lines follow the guide. Left out: the payload's ``dot1q`` and
``src-intf``, ping's ``sweep``, ``data-pattern`` and ``asynchronous``, traceroute's
``dport``, ``ngoam connect-check`` and the SRv6 options, which neither the guide's NGOAM
chapter nor the probe covered.

The tools, the counters' clears and loop detection's probe and bring-up are typed outside
configuration mode, which NXray's broad role allows from version ``BROAD_NGOAM_VERSION``
(``NGOAM_RULES``); a broad role written before needs Update the port list first.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.features import feature_states
from app.monitor import all_port_names
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
    table_rows,
)
from app.switch import chassis_model, text
from app.vxlan import VNI_MAX, parse_vxlan_config

FEATURE = "ngoam"
VXLAN_FEATURE = "nve"
PAGE_COMMANDS = ("show feature", "show inventory", "show interface brief")
STATS_COMMANDS = (
    "show ngoam loopback statistics summary",
    "show ngoam traceroute statistics summary",
    "show ngoam pathtrace statistics summary",
)
ACL_COMMAND = "show ngoam acl status"
CONFIG_COMMAND = "show running-config"
PROFILE_MAX = 1023
COUNT_MAX = 100  # pings NXray sends at most in one go (the switch takes up to 65535)
SIZE_MAX = 9500
WAIT_MAX = 25  # interval and timeout, in seconds (traceroute's timeout goes to 30)
TRACEROUTE_TIMEOUT_MAX = 30
TTL_MAX = 255
# The longest a tool may run from the page, in seconds: count x (interval + timeout) for
# ping, max-ttl x timeout for traceroute and pathtrace.
RUN_SECONDS_MAX = 300
# The switch's defaults, as its help says: 5 pings, interval 0, timeout 2, max-ttl 5.
DEFAULT_COUNT = 5
DEFAULT_TIMEOUT = 2
DEFAULT_TTL = 5
TOOLS = ("ping", "traceroute", "pathtrace")

VXLAN_OFF = (
    "VXLAN (feature nv overlay) is off: the OAM tools run inside VXLAN. Set VXLAN up on the "
    "VXLAN page first."
)
NO_LOOP_DETECTION = (
    'This switch does not do NGOAM loop detection: it refuses it ("Loop detection not '
    "supported on this hardware\"). Cisco's NX-OS 9.3 guide lists it for the Nexus 9300-EX, "
    "-FX and -FX2, the 9332C and 9364C, and the 9500 with -EX and -FX line cards."
)

# ---- fields ----------------------------------------------------------------------------------


def _profile_id() -> Field:
    return Field(
        "profile",
        "Profile",
        "int",
        minimum=1,
        maximum=PROFILE_MAX,
        hint=f"1 to {PROFILE_MAX}",
    )


def _use_profile() -> Field:
    return Field(
        "profile",
        "Profile",
        "int",
        minimum=1,
        maximum=PROFILE_MAX,
        optional=True,
        hint="A profile made below",
    )


def _address() -> Field:
    return Field(
        "address",
        "Address",
        "ip",
        hint="The VTEP or host to reach, IPv4 or IPv6",
        placeholder="192.0.2.20",
    )


def _vni() -> Field:
    return Field("vni", "VNI", "int", minimum=1, maximum=VNI_MAX, hint="The VXLAN segment it is in")


def _vrf() -> Field:
    return Field(
        "vrf",
        "VRF",
        "name",
        hint="default, or a VRF made on the Routing page",
        placeholder="default",
    )


def _sport() -> Field:
    return Field(
        "sport",
        "Outer UDP source port",
        "int",
        minimum=1,
        maximum=65535,
        optional=True,
        hint="Picks which of several equal paths it takes",
    )


def _source() -> Field:
    return Field(
        "source",
        "Send from",
        "ip",
        optional=True,
        hint="An address of this switch, the same IP version as the address",
    )


def _timeout(highest: int = WAIT_MAX) -> Field:
    low = 1 if highest == TRACEROUTE_TIMEOUT_MAX else 0
    return Field(
        "timeout",
        "Wait for each answer",
        "int",
        minimum=low,
        maximum=highest,
        optional=True,
        hint=f"Seconds, {low} to {highest}; default {DEFAULT_TIMEOUT}",
    )


def _ttl() -> Field:
    return Field(
        "ttl",
        "Most hops",
        "int",
        minimum=1,
        maximum=TTL_MAX,
        optional=True,
        hint=f"Default {DEFAULT_TTL}",
    )


def _egress() -> Field:
    return Field(
        "egress",
        "Out of port",
        "port",
        optional=True,
        hint="Send out of this front port or port-channel",
    )


def _flag(name: str, label: str, word: str, hint: str = "") -> Field:
    return Field(name, label, "flag", choices=(word,), hint=hint)


def _verbose() -> Field:
    return _flag("verbose", "Every answer in full", "verbose", "Why each one failed, too")


def _ping_fields() -> tuple[Field, ...]:
    return (
        Field(
            "count",
            "How many",
            "int",
            minimum=1,
            maximum=COUNT_MAX,
            optional=True,
            hint=f"1 to {COUNT_MAX}; default {DEFAULT_COUNT}",
        ),
        Field("size", "Packet size", "int", minimum=1, maximum=SIZE_MAX, optional=True),
        Field(
            "interval",
            "Seconds between",
            "int",
            minimum=0,
            maximum=WAIT_MAX,
            optional=True,
            hint="Default 0",
        ),
        _timeout(),
    )


_PING_OPTIONS = "[ count {count}][ packet-size {size}][ interval {interval}][ timeout {timeout}]"
_HOP_OPTIONS = "[ max-ttl {ttl}][ timeout {timeout}]"


def _mac_fields() -> tuple[Field, ...]:
    return (
        Field("mac", "MAC address", "mac", placeholder="0200.0000.0001"),
        Field("vlan", "VLAN", "vlan", hint="Where the MAC address is learnt"),
        Field(
            "port",
            "Port",
            "port",
            optional=True,
            hint="The port it is learnt on; empty: the switch looks it up",
        ),
    )


def _payload_fields() -> tuple[Field, ...]:
    return (
        Field("dmac", "Host's MAC address", "mac", optional=True),
        Field("smac", "Sender's MAC address", "mac", optional=True),
        Field("dip", "Host's address", "ipv4", optional=True),
        Field("sip", "Sender's address", "ipv4", optional=True),
        Field("psport", "Source port", "int", minimum=1, maximum=65535, optional=True),
        Field("pdport", "Destination port", "int", minimum=1, maximum=65535, optional=True),
        Field(
            "proto",
            "Protocol",
            "int",
            minimum=0,
            maximum=255,
            optional=True,
            hint="IANA number: 6 TCP, 17 UDP",
        ),
    )


_PAYLOAD = (
    " payload[ mac-addr {dmac} {smac}][ ip {dip} {sip}][ port {psport} {pdport}][ proto {proto}]"
    " payload-end"
)

# ---- checks ----------------------------------------------------------------------------------


def _same_version(values: dict[str, str]) -> None:
    if values.get("source") and values.get("address"):
        version = ipaddress.ip_address(values["address"]).version
        if ipaddress.ip_address(values["source"]).version != version:
            raise ValueError(f"send from an IPv{version} address, like the address to reach")


def _run_seconds(values: dict[str, str], tool: str) -> int:
    timeout = int(values.get("timeout") or DEFAULT_TIMEOUT)
    if tool == "ping":
        count = int(values.get("count") or DEFAULT_COUNT)
        return count * (int(values.get("interval") or 0) + timeout)
    return int(values.get("ttl") or DEFAULT_TTL) * timeout


def _not_too_long(tool: str) -> Callable[[dict[str, str]], None]:
    def check(values: dict[str, str]) -> None:
        _same_version(values)
        seconds = _run_seconds(values, tool)
        if seconds > RUN_SECONDS_MAX:
            what = (
                "count x (seconds between + wait)"
                if tool == "ping"
                else "most hops x wait for each answer"
            )
            raise ValueError(
                f"that could run for {seconds} seconds ({what}); NXray runs a "
                f"{tool} for {RUN_SECONDS_MAX} seconds at most"
            )

    return check


def _payload_check(tool: str) -> Callable[[dict[str, str]], None]:
    inner = _not_too_long(tool)

    def check(values: dict[str, str]) -> None:
        for one, other, what in (
            ("dmac", "smac", "both MAC addresses"),
            ("dip", "sip", "both addresses"),
            ("psport", "pdport", "both ports"),
        ):
            if bool(values.get(one)) != bool(values.get(other)):
                raise ValueError(f"the traffic to look for needs {what}, or neither")
        if not (values.get("dmac") or values.get("dip")):
            raise ValueError("give the host's MAC address or its address, with the sender's")
        inner(values)

    return check


# ---- the tools -------------------------------------------------------------------------------

_TOOL_HELP = {
    "ping": "Send OAM pings inside VXLAN and show what came back: '!' answered, '.' no "
    "answer in time, 'Q' not sent, 'D' unreachable. Nothing is changed or saved.",
    "traceroute": "List the switches on the way, hop by hop. Nothing is changed or saved.",
    "pathtrace": "Like traceroute, with each hop's ports in and out and their state. Every "
    "switch on the way needs ngoam on. Nothing is changed or saved.",
}


def _tool(key: str, label: str) -> Scope:
    word = f"{key} nve"
    if key == "ping":
        extra: tuple[Field, ...] = _ping_fields()
        options, tail = _PING_OPTIONS, "[ egress {egress}]"
        mac_options = "[ sport {sport}]" + _PING_OPTIONS
    else:
        highest = TRACEROUTE_TIMEOUT_MAX if key == "traceroute" else WAIT_MAX
        extra = (_ttl(), _timeout(highest))
        options, tail = _HOP_OPTIONS, "[ egress {egress}]"
        mac_options = "[ sport {sport}]" + _HOP_OPTIONS
    flags: tuple[Field, ...] = (_verbose(),)
    flag_line = "[ {verbose}]"
    if key == "pathtrace":
        flags = (_flag("req_stats", "Each hop's counters", "req-stats"), _verbose())
        flag_line = "[ {req_stats}][ {verbose}]"
    common = (_sport(), _source(), *extra, _egress(), *flags)
    after = f"[ sport {{sport}}][ source {{source}}]{options}{tail}"
    # Traceroute takes no profile with a MAC address (not tried there).
    mac_profile = "" if key == "traceroute" else "[ profile {profile}]"
    mac_fields = (*_mac_fields(), *(() if key == "traceroute" else (_use_profile(),)), _sport(),
                  *extra, *flags)  # fmt: skip
    settings = [
        Setting(
            "by_vni",
            f"{label} an address in a VNI",
            f"{word} ip {{address}}[ profile {{profile}}] vni {{vni}}{after}{flag_line}",
            (_address(), _vni(), _use_profile(), *common),
            removable=False,
            config=False,
            group="An address in a VNI",
            help="A VTEP or a host in a layer 2 or layer 3 VNI.",
            check=_not_too_long(key),
            button="Run",
        ),
        Setting(
            "by_vrf",
            f"{label} an address in a VRF",
            f"{word} ip {{address}} vrf {{vrf}}[ profile {{profile}}]{after}{flag_line}",
            (_address(), _vrf(), _use_profile(), *common),
            removable=False,
            config=False,
            group="An address in a VRF",
            help="A host in a tenant VRF.",
            check=_not_too_long(key),
            button="Run",
        ),
        Setting(
            "by_flow",
            f"{label} a host by its traffic",
            f"{word} ip unknown vrf {{vrf}}[ profile {{profile}}]{_PAYLOAD}{after}"
            + ("[ {verify}]" if key == "ping" else "")
            + flag_line,
            (
                _vrf(),
                _use_profile(),
                *_payload_fields(),
                *common[: -len(flags)],
                *(
                    (_flag("verify", "Check the host answers", "verify-host"),)
                    if key == "ping"
                    else ()
                ),
                *flags,
            ),  # fmt: skip
            removable=False,
            config=False,
            group="A host found by its traffic",
            help="The switch finds where to send from the traffic described: the host's and "
            "sender's MAC addresses or addresses, and if wanted their ports and protocol.",
            check=_payload_check(key),
            button="Run",
        ),
        Setting(
            "by_mac",
            f"{label} a MAC address",
            f"{word} mac {{mac}} {{vlan}}[ {{port}}]{mac_profile}{mac_options}{flag_line}",
            mac_fields,
            removable=False,
            config=False,
            group="A MAC address",
            help="A host by its MAC address in a VLAN tied to a VNI.",
            check=_not_too_long(key),
            button="Run",
        ),
    ]
    return Scope(key=key, label=label, ident=(), enter=(), help=_TOOL_HELP[key],
                 settings=tuple(settings))  # fmt: skip


# ---- the whole switch ------------------------------------------------------------------------

_GLOBAL = Scope(
    key="global",
    label="Whole switch",
    ident=(),
    enter=(),
    help="NGOAM settings for the whole switch.",
    settings=(
        Setting(
            "install_acl",
            "OAM access list",
            "ngoam install acl",
            group="Hardware",
            help="Puts NGOAM's entry into the switch's hardware access list, so OAM messages "
            "from other switches reach this one. A step of Cisco's NGOAM set-up.",
            warning="This writes an entry into the switch's hardware access lists.",
        ),
        Setting(
            "authentication_key",
            "Authentication key",
            "ngoam authentication-key {key}",
            (Field("key", "Key", "secret", hint="Never shown back"),),
            no_line="no ngoam authentication-key",
            group="Security",
            help="A key the OAM messages carry, the same on every switch of the fabric. The "
            "switch keeps it in plain text in its configuration.",
        ),
        Setting(
            "xconnect_hb",
            "Cross connect heartbeat",
            "ngoam xconnect hb-interval {ms}",
            (Field("ms", "Milliseconds", "int", minimum=150, maximum=5000),),
            no_line="no ngoam xconnect hb-interval",
            group="Cross connect",
            help="How often the two ends of a VXLAN cross connect check on each other.",
        ),
    ),
)

# ---- profiles and their flows ----------------------------------------------------------------


def _hex_pad(values: dict[str, str]) -> None:
    if not re.fullmatch(r"0x[0-9a-fA-F]{1,4}", values["pad"]):
        raise ValueError("the pad is a hexadecimal number from 0x0 to 0xffff, such as 0x2")


def _ethernet_only(values: dict[str, str]) -> None:
    port = values.get("port", "")
    if port and not port.startswith("Ethernet"):
        raise ValueError("a profile takes a front port here, such as Ethernet1/5")


_PROFILE = Scope(
    key="profile",
    label="Profile",
    ident=(_profile_id(),),
    enter=("ngoam profile {profile}",),
    create=True,
    create_label="Make a profile",
    delete=("no ngoam profile {profile}",),
    delete_warning="Tools typed with this profile are refused afterwards.",
    help="What a tool sends when it names the profile.",
    settings=(
        Setting(
            "description",
            "Description",
            "description {text}",
            (Field("text", "Description", "text", maximum=254),),
            removable=False,
            group="Profile",
            help="The switch keeps a description once set: set a new one to change it.",
        ),
        Setting(
            "hop",
            "Hop count",
            "hop {hops}",
            (Field("hops", "Hops", "int", minimum=1, maximum=TTL_MAX, hint="Default 5"),),
            no_line="no hop",
            group="Profile",
        ),
        Setting(
            "sport",
            "Outer UDP source port",
            "sport {port_number}",
            (Field("port_number", "Port", "int", minimum=1, maximum=65535),),
            no_line="no sport",
            group="Profile",
        ),
        Setting(
            "oam_channel",
            "NVO3 channel",
            "oam-channel 2",
            no_line="no oam-channel",
            group="Profile",
            help="Send in the NVO3 OAM channel. Traceroute refuses a profile with it.",
        ),
        Setting(
            "payload_pad",
            "Payload pad",
            "payload pad {pad}",
            (Field("pad", "Pad", "name", maximum=6, hint="0x0 to 0xffff", placeholder="0x2"),),
            no_line="no payload pad",
            group="Payload",
            check=_hex_pad,
        ),
        Setting(
            "dot1q",
            "VLAN tag",
            "dot1q {vlan}[ {port}]",
            (
                Field("vlan", "VLAN", "vlan"),
                Field("port", "Port", "port", optional=True, hint="A front port"),
            ),
            no_line="no dot1q",
            group="Payload",
            check=_ethernet_only,
        ),
        Setting(
            "interface",
            "Port",
            "interface {port}",
            (Field("port", "Port", "port", hint="A front port"),),
            no_line="no interface",
            group="Payload",
            help="The port the messages go out of.",
            check=_ethernet_only,
        ),
    ),
)


def _flow_address(key: str, word: str, label: str, kind: str) -> Setting:
    return Setting(
        key,
        label,
        f"{word} {{address}}",
        (Field("address", "Address", kind),),
        no_line=f"no {word}",
        group="Addresses",
    )


_FLOW = Scope(
    key="flow",
    label="Flow",
    ident=(
        _profile_id(),
        Field("direction", "Direction", "choice", choices=("forward", "reverse")),
    ),
    enter=("ngoam profile {profile}", "flow {direction}"),
    create=True,
    create_label="Add a flow to a profile",
    delete=("ngoam profile {profile}", "no flow {direction}"),
    help="The inner traffic a profile's messages carry, as a host's own: addresses, ports, "
    "protocol and VLAN. IPv4 and IPv6 addresses cannot share a flow.",
    settings=(
        _flow_address("ip_destination", "ip destination", "IPv4 destination", "ipv4"),
        _flow_address("ip_source", "ip source", "IPv4 source", "ipv4"),
        _flow_address("ipv6_destination", "ipv6 destination", "IPv6 destination", "ipv6"),
        _flow_address("ipv6_source", "ipv6 source", "IPv6 source", "ipv6"),
        _flow_address("mac_destination", "mac-address destination", "Destination MAC", "mac"),
        _flow_address("mac_source", "mac-address source", "Source MAC", "mac"),
        Setting(
            "port_destination",
            "Destination port",
            "port destination {number}",
            (Field("number", "Port", "int", minimum=1, maximum=65535),),
            no_line="no port destination",
            group="Ports and protocol",
        ),
        Setting(
            "port_source",
            "Source port",
            "port source {number}",
            (Field("number", "Port", "int", minimum=1, maximum=65535),),
            no_line="no port source",
            group="Ports and protocol",
        ),
        Setting(
            "protocol",
            "Protocol",
            "protocol {number}",
            (Field("number", "Number", "int", minimum=0, maximum=255, hint="6 TCP, 17 UDP"),),
            no_line="no protocol",
            group="Ports and protocol",
        ),
        Setting(
            "dot1q",
            "VLAN tag",
            "dot1q {vlan}[ cos {cos}]",
            (
                Field("vlan", "VLAN", "vlan"),
                Field("cos", "CoS", "int", minimum=0, maximum=7, optional=True),
            ),
            no_line="no dot1q",
            group="Ports and protocol",
        ),
    ),
)

# ---- loop detection --------------------------------------------------------------------------

_LOOP = Scope(
    key="loop",
    label="Loop detection",
    ident=(),
    enter=("ngoam loop-detection",),
    create=True,
    create_label="Turn on loop detection",
    delete=("no ngoam loop-detection",),
    delete_warning="Ports it blocked stay blocked until brought up or recovered.",
    help="Probes the VLANs for loops and blocks a looped port in that VLAN. Cisco: it needs "
    "the ing-sup TCAM region at 768 entries first, which takes a restart of the switch.",
    settings=(
        Setting(
            "disable",
            "Not in these VLANs",
            "disable vlan {vlans}[ port {port}]",
            (
                Field("vlans", "VLANs", "vlans"),
                Field("port", "Port", "port", optional=True, hint="Only on this port"),
            ),
            group="Where",
        ),
        Setting(
            "probe_interval",
            "Probe every",
            "periodic-probe-interval {seconds}",
            (Field("seconds", "Seconds", "int", minimum=60, maximum=3600, hint="Default 300"),),
            group="Timers",
        ),
        Setting(
            "recovery_interval",
            "Try a blocked port again every",
            "port-recovery-interval {seconds}",
            (Field("seconds", "Seconds", "int", minimum=300, maximum=3600, hint="Default 600"),),
            group="Timers",
        ),
    ),
)


def _loop_now(key: str, label: str, word: str, help_text: str) -> Setting:
    return Setting(
        key,
        label,
        f"ngoam loop-detection {word} vlan {{vlan}} port {{port}}",
        (Field("vlan", "VLAN", "vlan"), Field("port", "Port", "port")),
        removable=False,
        config=False,
        group="Now",
        help=help_text,
        button="Run",
    )


_LOOP_NOW = Scope(
    key="loop_now",
    label="Loop detection now",
    ident=(),
    enter=(),
    help="Nothing here is saved.",
    settings=(
        _loop_now("probe", "Probe now", "probe", "Look for a loop in a VLAN on a port now."),
        _loop_now(
            "bringup",
            "Bring a port up",
            "bringup",
            "Unblock a port loop detection blocked in a VLAN, without waiting for it.",
        ),
    ),
)

# ---- counters --------------------------------------------------------------------------------


def _clear(key: str, label: str, word: str) -> Setting:
    return Setting(
        key,
        label,
        f"clear ngoam {word} statistics summary",
        removable=False,
        config=False,
        group="Clear",
        button="Clear",
    )


_COUNTERS = Scope(
    key="counters",
    label="Counters",
    ident=(),
    enter=(),
    help="Set the tools' counters back to zero. Nothing here is saved.",
    settings=(
        _clear("loopback", "Ping counters", "loopback"),
        _clear("traceroute", "Traceroute counters", "traceroute"),
        _clear("pathtrace", "Pathtrace counters", "pathtrace"),
    ),
)

SCOPES = (
    _tool("ping", "Ping"),
    _tool("traceroute", "Traceroute"),
    _tool("pathtrace", "Pathtrace"),
    _GLOBAL,
    _PROFILE,
    _FLOW,
    _LOOP,
    _LOOP_NOW,
    _COUNTERS,
)


# ---- reading ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class NgoamConfig:
    """What ``show running-config`` says about NGOAM."""

    install_acl: bool
    key_set: bool  # an authentication key is set (never kept)
    hb_interval: str
    profiles: dict[str, dict[str, dict[str, str]]]  # number -> setting values
    flows: dict[tuple[str, str], dict[str, dict[str, str]]]  # (number, direction) -> values
    loop: dict[str, dict[str, str]] | None  # None: loop detection is off
    loop_disabled: tuple[str, ...]


_PROFILE_LINES = (
    (re.compile(r"description (.+)"), "description", ("text",)),
    (re.compile(r"hop (\d+)"), "hop", ("hops",)),
    (re.compile(r"sport (.+)"), "sport", ("port_number",)),
    (re.compile(r"oam-channel (2)"), "oam_channel", ()),
    (re.compile(r"payload pad (\S+)"), "payload_pad", ("pad",)),
    (re.compile(r"dot1q (\d+)(?: (\S+))?"), "dot1q", ("vlan", "port")),
    (re.compile(r"interface (\S+)"), "interface", ("port",)),
)
_FLOW_LINES = (
    (re.compile(r"ip destination (\S+)"), "ip_destination", ("address",)),
    (re.compile(r"ip source (\S+)"), "ip_source", ("address",)),
    (re.compile(r"ipv6 destination (\S+)"), "ipv6_destination", ("address",)),
    (re.compile(r"ipv6 source (\S+)"), "ipv6_source", ("address",)),
    (re.compile(r"mac-address destination (\S+)"), "mac_destination", ("address",)),
    (re.compile(r"mac-address source (\S+)"), "mac_source", ("address",)),
    (re.compile(r"port destination (\d+)"), "port_destination", ("number",)),
    (re.compile(r"port source (\d+)"), "port_source", ("number",)),
    (re.compile(r"protocol (\d+)"), "protocol", ("number",)),
    (re.compile(r"dot1q (\d+)(?: cos (\d+))?"), "dot1q", ("vlan", "cos")),
)
_LOOP_LINES = (
    (re.compile(r"periodic-probe-interval (\d+)"), "probe_interval", ("seconds",)),
    (re.compile(r"port-recovery-interval (\d+)"), "recovery_interval", ("seconds",)),
)


def _values(lines: list[str], known: tuple[Any, ...]) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    for line in lines:
        for pattern, key, names in known:
            if match := pattern.fullmatch(line):
                values[key] = {n: g or "" for n, g in zip(names, match.groups(), strict=False)}
                break
    return values


def parse_ngoam_config(config: str) -> NgoamConfig:
    """The NGOAM lines of ``show running-config``."""
    tree = parse_vxlan_config(config)
    profiles: dict[str, dict[str, dict[str, str]]] = {}
    flows: dict[tuple[str, str], dict[str, dict[str, str]]] = {}
    loop: dict[str, dict[str, str]] | None = None
    disabled: list[str] = []
    install = key = False
    hb = ""
    for line in tree.children():
        if line == "ngoam install acl":
            install = True
        elif line.startswith("ngoam authentication-key "):
            key = True
        elif match := re.fullmatch(r"ngoam xconnect hb-interval (\d+)", line):
            hb = match.group(1)
        elif match := re.fullmatch(r"ngoam profile (\d+)", line):
            number = match.group(1)
            inside = tree.children(line)
            profiles[number] = _values(inside, _PROFILE_LINES)
            for flow in inside:
                if found := re.fullmatch(r"flow (forward|reverse)", flow):
                    flows[(number, found.group(1))] = _values(
                        tree.children(line, flow), _FLOW_LINES
                    )
        elif line == "ngoam loop-detection":
            inside = tree.children(line)
            loop = _values(inside, _LOOP_LINES)
            disabled = [x.removeprefix("disable ") for x in inside if x.startswith("disable ")]
    return NgoamConfig(install, key, hb, profiles, flows, loop, tuple(disabled))


_COUNTER_ROWS = (
    ("Ping", "TABLE_statistics_summary", "ROW_statistics_summary"),
    ("Traceroute", "TABLE_summary", "ROW_summary"),
    ("Pathtrace", "TABLE_summary", "ROW_summary"),
)


def parse_counters(bodies: list[Any]) -> tuple[tuple[str, ...], ...]:
    """The three ``show ngoam ... statistics summary`` bodies: per tool, requests sent,
    answers received, timed out, not sent, requests received from others, answers sent,
    and when last cleared."""
    rows = []
    for (tool, table, row_name), body in zip(_COUNTER_ROWS, bodies, strict=False):
        for row in table_rows(body, table, row_name):
            rows.append(
                (
                    tool,
                    text(row.get("tx")),
                    text(row.get("resp-rx")),
                    text(row.get("timeout")),
                    text(row.get("unsent")),
                    text(row.get("rx")),
                    text(row.get("resp-tx")),
                    text(row.get("last-clear-summary-stats")),
                )
            )
    return tuple(rows)


def parse_acl_status(output: str | None) -> str:
    """``show ngoam acl status``: the bridge domains (VLANs) the OAM access list is on,
    "1" from "ACL installed on following BDs:\\n1, "."""
    match = re.search(r"ACL installed on following BDs:\s*(.*)", output or "", re.S)
    if not match:
        return ""
    return ", ".join(part.strip() for part in match.group(1).split(",") if part.strip())


def _profile_facts(values: dict[str, dict[str, str]], flows: list[str]) -> tuple[Any, ...]:
    def one(key: str, name: str, default: str) -> str:
        return values.get(key, {}).get(name) or default

    dot1q = values.get("dot1q")
    return (
        ("Description", one("description", "text", "none")),
        ("Hops", one("hop", "hops", "default (5)")),
        ("Source port", one("sport", "port_number", "any")),
        ("NVO3 channel", "yes" if "oam_channel" in values else "no"),
        ("Payload pad", one("payload_pad", "pad", "none")),
        ("VLAN tag", " ".join(v for v in (dot1q or {}).values() if v) or "none"),
        ("Port", one("interface", "port", "none")),
        ("Flows", ", ".join(flows) or "none"),
    )


def _flow_facts(values: dict[str, dict[str, str]]) -> tuple[Any, ...]:
    labels = {s.key: s.label for s in _FLOW.settings}
    return tuple(
        (labels[key], " ".join(v for v in found.values() if v) or "yes")
        for key, found in values.items()
    ) or (("Lines", "none yet"),)


def parse_ngoam(
    config: str | None,
    counters: list[Any] | None = None,
    acl: str | None = None,
    loop_refused: bool = False,
) -> ProtocolView:
    """The page from the configuration text (None: not shown), the counters' bodies and
    the ACL status text; ``loop_refused`` for a switch Cisco's guide does not list for loop
    detection."""
    found = parse_ngoam_config(config or "")
    on_bds = parse_acl_status(acl)
    global_facts = (
        ("OAM access list", "installed" if found.install_acl else "not installed"),
        ("Access list on VLANs", on_bds or "not reported"),
        ("Authentication key", "set" if found.key_set else "not set"),
        ("Cross connect heartbeat", f"{found.hb_interval} ms" if found.hb_interval else "default"),
    )
    global_values: dict[str, dict[str, str]] = {}
    if found.install_acl:
        global_values["install_acl"] = {}
    if found.hb_interval:
        global_values["xconnect_hb"] = {"ms": found.hb_interval}
    instances = [
        Instance(tool, {}, title)
        for tool, title in (
            ("ping", "Ping across the fabric"),
            ("traceroute", "Traceroute across the fabric"),
            ("pathtrace", "Pathtrace across the fabric"),
        )
    ]
    instances.append(Instance("global", {}, "Whole switch", global_facts, global_values))
    for number, values in found.profiles.items():
        directions = [d for (n, d) in found.flows if n == number]
        instances.append(
            Instance(
                "profile",
                {"profile": number},
                f"Profile {number}",
                _profile_facts(values, directions),
                values,
            )
        )
    for (number, direction), values in found.flows.items():
        instances.append(
            Instance(
                "flow",
                {"profile": number, "direction": direction},
                f"Profile {number}, flow {direction}",
                _flow_facts(values),
                values,
            )
        )
    if found.loop is not None:
        facts = (
            ("Probe every", f"{found.loop['probe_interval']['seconds']} seconds"
             if "probe_interval" in found.loop else "300 seconds (default)"),
            ("Try a blocked port every", f"{found.loop['recovery_interval']['seconds']} seconds"
             if "recovery_interval" in found.loop else "600 seconds (default)"),
            ("Not in", "; ".join(found.loop_disabled) or "none"),
        )  # fmt: skip
        instances.append(Instance("loop", {}, "Loop detection", facts, found.loop))
        instances.append(Instance("loop_now", {}, "Loop detection now"))
    instances.append(Instance("counters", {}, "Counters"))
    notes = []
    if loop_refused:
        notes.append(NO_LOOP_DETECTION)
    if config is None:
        notes.append(
            "The switch did not show its configuration to NXray's account: the profiles and "
            "switch-wide settings are not listed."
        )
    tables = (
        Table(
            "Counters",
            (
                "Tool",
                "Sent",
                "Answers",
                "Timed out",
                "Not sent",
                "Asked by others",
                "Answered others",
                "Last cleared",
            ),
            parse_counters(counters or []),
            empty="The switch did not report its OAM counters.",
        ),
    )
    return ProtocolView(tuple(instances), tables, tuple(notes))


NGOAM = Protocol(
    key="ngoam",
    name="VXLAN OAM",
    summary="Ping, traceroute and pathtrace across the VXLAN fabric, and their profiles",
    features=(FEATURE,),
    commands=(),
    parse=lambda bodies: parse_ngoam(None),
    scopes=SCOPES,
    about=(
        "Pick a tool and how to aim it: an address in a VNI, an address in a VRF, a host found "
        "by its traffic, or a MAC address. The switch's answer is shown under the message at "
        "the top. Pathtrace needs ngoam on every switch on the way."
    ),
)


@dataclass(frozen=True)
class NgoamPage:
    """Everything the VXLAN OAM page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # the front ports and port-channels
    problem: str = ""
    missing: tuple[str, ...] = ()  # the ngoam feature, when it is off


def loop_refused(inventory: Any) -> bool:
    """True for a switch Cisco's guide does not list for loop detection (a Nexus 9200, as
    ``show inventory`` names it)."""
    return bool(re.search(r"\bC92\d", chassis_model(inventory)))


def load_ngoam_page(client: NxapiClient) -> NgoamPage:
    """One request for the features, model and ports; while ngoam is on, one for the
    counters, and the ACL status and the configuration text."""
    feature, inventory, brief = client.show(*PAGE_COMMANDS)
    ports = all_port_names(brief or {})
    states = feature_states(feature)
    problem = "" if states.get(VXLAN_FEATURE, False) else VXLAN_OFF
    if not states.get(FEATURE, False):
        return NgoamPage(NGOAM, ProtocolView(), ports, problem, (FEATURE,))
    try:
        counters: list[Any] | None = client.show(*STATS_COMMANDS)
    except NxapiCommandError:
        counters = None
    try:
        acl: str | None = client.show_text(ACL_COMMAND)
    except NxapiCommandError:
        acl = None
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = None
    view = parse_ngoam(config, counters, acl, loop_refused(inventory))
    return NgoamPage(NGOAM, view, ports, problem)


def check_ngoam_place(page: NgoamPage, ident: dict[str, str]) -> None:
    """Nothing to refuse before the lines are built: a profile is any number, and the
    switch itself names a VRF, port or profile a tool's line gives that it does not have."""


def tool_wait(line: str) -> float:
    """How long, in seconds, the switch may take to answer a tool's line: what its count,
    interval, timeout and max-ttl add up to (the switch's defaults where not given), plus
    room for the switch to answer."""
    words = line.split()

    def after(word: str, default: int) -> int:
        return int(words[words.index(word) + 1]) if word in words else default

    timeout = after("timeout", DEFAULT_TIMEOUT)
    if words[0] == "ping":
        seconds = after("count", DEFAULT_COUNT) * (after("interval", 0) + max(timeout, 1))
    else:
        seconds = after("max-ttl", DEFAULT_TTL if words[0] == "pathtrace" else 30) * max(timeout, 1)
    return float(min(seconds, RUN_SECONDS_MAX) + 30)


def build_ngoam_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the VXLAN OAM page; a tool's line is described as run, not set."""
    change = build_change(NGOAM, scope, setting, action, ident, values)
    if scope in TOOLS or scope in ("counters", "loop_now"):
        place = NGOAM.scope(scope)
        found = place.setting(setting) if place is not None else None
        label = found.label if found is not None else setting
        change = dataclasses.replace(change, describe=f"VXLAN OAM: {label}: {change.lines[-1]}.")
    return change
