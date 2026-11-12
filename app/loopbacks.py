"""Loopback interfaces: made, described, addressed, moved into a VRF, turned off and
deleted.

A loopback is an interface of the switch's own that is never down unless turned off: no
cable, no port. Its address stays reachable as long as any path to the switch is up, so
routing protocols use it as their router ID and as the source of their sessions (BGP,
the VXLAN tunnel end, PIM's rendezvous point), and people use it to reach the switch.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): one scope (a loopback), each setting the one configuration line
it sends with checked values in its blanks, and ``build_change`` building the lines.
``NxapiClient.configure_loopbacks`` sends them.

Read from the switch, in one request: ``show interface brief`` (each loopback with its
state and description), ``show ip interface vrf all`` and ``show ipv6 interface vrf all``
(the addresses, the extra IPv4 ones too), ``show vrf`` and ``show vrf interface`` (the
VRFs, and which one each loopback is in, one with no address too).

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-11) with throwaway loopbacks 250 to 253 and a
throwaway VRF, all removed afterwards: every line the page sends, and the show output
above. What the switch showed and the page follows:

* loopbacks are numbered 0 to 1023 ("Invalid interface format" for 1024);
* ``interface loopbackN`` makes one, ``no interface loopbackN`` deletes it;
* ``ip address A/L`` takes a host address only ("All 0s host part is invalid" for
  198.51.100.0/24), and ``ip address A/L secondary`` adds more;
* ``vrf member V`` and ``no vrf member V`` delete every address on it ("Deleted all L3
  config on interface"), as on a VLAN interface;
* ``show interface brief`` writes a turned-off loopback as state "down".

NXray's broad role names the loopbacks in its port list (``permit interface
loopback0-1023``, stored by the switch as that one line): without it the switch answers
"Interface permission denied". A role written before that lacks it until Update the port
list writes it again (``BROAD_LOOPBACK_VERSION``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.nxapi import DEFAULT_VRF, NxapiClient
from app.protocols import (
    Field,
    Instance,
    Protocol,
    ProtocolChange,
    ProtocolView,
    Scope,
    Setting,
    build_change,
)
from app.routing import parse_ipv4, parse_ipv6, parse_vrf_members, parse_vrfs
from app.switch import rows, text

LOOPBACK_MAX = 1023
COMMANDS = (
    "show interface brief",
    "show ip interface vrf all",
    "show ipv6 interface vrf all",
    "show vrf",
    "show vrf interface",
)

_NAME = re.compile(r"^loopback(\d+)$", re.IGNORECASE)
_VRF_WARNING = (
    "The switch deletes every address on the loopback when its VRF changes: put them on "
    "again afterwards."
)


def _number_field() -> Field:
    return Field(
        "number",
        "Loopback",
        "int",
        minimum=0,
        maximum=LOOPBACK_MAX,
        hint=f"0 to {LOOPBACK_MAX}: the number after loopback",
        placeholder="0",
    )


_LOOPBACK = Scope(
    key="loopback",
    label="Loopback",
    ident=(_number_field(),),
    enter=("interface loopback{number}",),
    create=True,
    create_label="Make a loopback",
    delete=("no interface loopback{number}",),
    delete_warning=(
        "Its addresses go with it. A routing protocol, BGP neighbor or VXLAN tunnel that uses "
        "the loopback as its source or router ID stops working until it gets another one."
    ),
    help=(
        "An interface of the switch's own that stays up without a cable: give it an address "
        "for a router ID or as the source of routing sessions and tunnels."
    ),
    settings=(
        Setting(
            key="description",
            label="Description",
            line="description {text}",
            no_line="no description",
            group="Loopback",
            fields=(Field("text", "Description", "text", hint="What the loopback is for"),),
        ),
        Setting(
            key="ipv4",
            label="IPv4 address",
            line="ip address {address}",
            no_line="no ip address {address}",
            group="Addresses",
            fields=(
                Field(
                    "address",
                    "Address",
                    "ifaddr4",
                    hint="With its prefix length, usually /32",
                    placeholder="192.0.2.1/32",
                ),
            ),
            help="The loopback's main IPv4 address.",
        ),
        Setting(
            key="ipv4_secondary",
            label="Extra IPv4 address",
            line="ip address {address} secondary",
            group="Addresses",
            fields=(
                Field(
                    "address",
                    "Address",
                    "ifaddr4",
                    hint="With its prefix length, usually /32",
                    placeholder="192.0.2.2/32",
                ),
            ),
            help="Another IPv4 address beside the main one (a secondary address).",
        ),
        Setting(
            key="ipv6",
            label="IPv6 address",
            line="ipv6 address {address}",
            group="Addresses",
            fields=(
                Field(
                    "address",
                    "Address",
                    "ifaddr6",
                    hint="With its prefix length, usually /128",
                    placeholder="2001:db8::1/128",
                ),
            ),
            help="Set again for another address.",
        ),
        Setting(
            key="vrf",
            label="VRF",
            line="vrf member {vrf}",
            group="VRF",
            fields=(
                Field(
                    "vrf",
                    "VRF",
                    "vrf",
                    hint="A VRF made on the Routing page; remove to go back to default",
                ),
            ),
            help="Put the loopback in a VRF; Remove takes it back to the default VRF.",
            warning=_VRF_WARNING,
        ),
        Setting(
            key="admin_up",
            label="Turn on",
            line="no shutdown",
            group="State",
            removable=False,
            help="Bring the loopback up.",
        ),
        Setting(
            key="admin_down",
            label="Turn off",
            line="shutdown",
            group="State",
            removable=False,
            help="Take the loopback down: its addresses stop answering.",
            warning=(
                "A routing protocol or tunnel that uses this loopback stops working while it "
                "is off."
            ),
        ),
    ),
)


@dataclass(frozen=True)
class Loopback:
    """One loopback as the switch reports it."""

    number: int
    up: bool
    description: str
    vrf: str
    ipv4: tuple[str, ...]  # the main address first, then the extra ones
    ipv6: tuple[str, ...]


def parse_loopbacks(bodies: list[Any]) -> list[Loopback]:
    """Every loopback, in number order, from the page's five bodies (in ``COMMANDS``
    order)."""
    brief, ip4, ip6, _vrf, vrf_if = (list(bodies) + [None] * 5)[:5]
    ipv4 = parse_ipv4(ip4 or {})
    ipv6 = parse_ipv6(ip6 or {})
    members = parse_vrf_members(vrf_if or {})
    found = []
    for row in rows(brief or {}, "TABLE_interface", "ROW_interface"):
        name = text(row.get("interface"))
        match = _NAME.fullmatch(name)
        if not match:
            continue
        name = f"loopback{int(match.group(1))}"
        vrf4, addresses4, _ = ipv4.get(name, ("", [], {}))
        vrf6, addresses6, _ = ipv6.get(name, ("", [], ""))
        found.append(
            Loopback(
                number=int(match.group(1)),
                up=text(row.get("state")).lower() == "up",
                description=text(row.get("desc")),
                vrf=members.get(name) or vrf4 or vrf6 or DEFAULT_VRF,
                ipv4=tuple(a.text for a in addresses4),
                ipv6=tuple(a.text for a in addresses6),
            )
        )
    return sorted(found, key=lambda lo: lo.number)


def parse_loopback_view(bodies: list[Any]) -> ProtocolView:
    """The page: one place per loopback, with its state, VRF and addresses."""
    instances = []
    for lo in parse_loopbacks(bodies):
        facts = (
            ("State", "on" if lo.up else "off"),
            ("Description", lo.description or "-"),
            ("VRF", lo.vrf),
            ("IPv4", ", ".join(lo.ipv4) or "none"),
            ("IPv6", ", ".join(lo.ipv6) or "none"),
        )
        values: dict[str, dict[str, str]] = {}
        if lo.description:
            values["description"] = {"text": lo.description}
        if lo.ipv4:
            values["ipv4"] = {"address": lo.ipv4[0]}
        if lo.vrf != DEFAULT_VRF:
            values["vrf"] = {"vrf": lo.vrf}
        instances.append(
            Instance("loopback", {"number": str(lo.number)}, f"loopback{lo.number}", facts, values)
        )
    return ProtocolView(tuple(instances))


LOOPBACKS = Protocol(
    key="loopbacks",
    name="Loopbacks",
    summary="The switch's own interfaces that stay up without a cable",
    features=(),
    commands=COMMANDS,
    parse=parse_loopback_view,
    scopes=(_LOOPBACK,),
    about=(
        "Give a loopback an address to use as a router ID, as the source of BGP sessions or "
        "the VXLAN tunnel end, or to reach the switch by."
    ),
)


@dataclass(frozen=True)
class LoopbackPage:
    """Everything the Loopbacks page shows."""

    protocol: Protocol
    view: ProtocolView
    vrfs: tuple[str, ...]  # the VRFs made on the switch: never default or management
    numbers: tuple[int, ...]  # the loopbacks on the switch
    problem: str = ""
    missing: tuple[str, ...] = ()  # always empty: loopbacks need no feature


def load_loopback_page(client: NxapiClient) -> LoopbackPage:
    """One request for every read."""
    bodies = client.show(*COMMANDS)
    members = parse_vrf_members(bodies[4] or {})
    # The VRF form offers only the VRFs a loopback can be moved into; Remove moves it back
    # to default.
    vrfs = tuple(
        v.name
        for v in parse_vrfs(bodies[3] or {}, members)
        if v.name not in (DEFAULT_VRF, "management")
    )
    view = parse_loopback_view(bodies)
    numbers = tuple(int(i.ident["number"]) for i in view.of("loopback"))
    return LoopbackPage(LOOPBACKS, view, vrfs, numbers)


def build_loopback_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Loopbacks page."""
    return build_change(LOOPBACKS, scope, setting, action, ident, values)
