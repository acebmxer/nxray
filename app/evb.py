"""Edge Virtual Bridging (EVB, IEEE 802.1Qbg): a server's virtual switch tells the switch,
with VDP (the VSI discovery protocol), which virtual machine interfaces (VSIs) it is
bringing up on which port and VLAN, so the switch can set the network up for them. The
switch is the VDP bridge; the servers are the stations.

Switch-wide, as the switch's own command list gives them (``show cli syntax`` on
cisco-25gb): ``evb mac <address>`` (where VDP is sent: 0180.c200.0000, the nearest bridge,
by default), ``evb resource-wait-delay <exponent>`` and ``evb reinit-keep-alive
<exponent>`` (how long a station waits for the switch's answer, and how often it says a VSI
is still there: 10 microseconds times 2 to that power; 25 by default, about 335 seconds),
and ``evb batch-response disable``. Each has a ``no`` form that takes no value. The switch
lists no per-port EVB or VDP lines: VDP runs on every port while ``feature evb`` is on.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): one scope, the whole switch, each setting the one line it sends with
checked values in its blanks, and ``build_change`` building the lines.
``NxapiClient.configure_evb`` sends them.

Read from the switch: ``show feature`` first; while the feature is on, ``show evb`` (as JSON:
evb_role, evb_vdp_mac, evb_rwd, evb_rka and the VDP counters), then ``show evb hosts``,
``show evb vsi`` and ``show running-config`` as text. ``show evb hosts`` and ``show evb vsi``
give only their counts as JSON, so their rows are read from the text under the headings the
switch printed (Host Name, VNI, Vlan, BD, Mac-address, IP-Address, Interface; Mgr ID, VSI
ID, Interface, Profile ID, M-state, E-State, RWD/RKA).

Seen on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-13), where ``feature evb`` was
already on with its defaults: the shows above, with no host and no VSI (rows were not seen,
so the row parsers follow the headings). None of the lines was tried there: they are
switch-wide settings EVB already has, and the switch's range for the two exponents was not
read (the page takes 0 to 31, the standard's range, and the switch refuses what it does not
take). Cisco's NX-OS 9.3 guides have no EVB chapter; an ``evb resource-descriptor`` line is
not in the switch's command list, so none is offered.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

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
)
from app.routing import long_name
from app.switch import text
from app.vxlan import parse_vxlan_config

FEATURE = "evb"
STATE_COMMAND = "show evb"
HOSTS_COMMAND = "show evb hosts"
VSI_COMMAND = "show evb vsi"
CONFIG_COMMAND = "show running-config"
EXPONENT_MAX = 31
DEFAULT_EXPONENT = 25
# The VDP addresses IEEE 802.1Qbg names: the nearest bridge (the default) and the nearest
# bridge that is not a two-port relay.
VDP_MACS = ("0180.c200.0000", "0180.c200.0003")


def wait_time(exponent: Any) -> str:
    """An EVB timer exponent in words: 25 -> '25 (about 335 seconds)'."""
    value = text(exponent)
    if not value.isdigit():
        return value or "-"
    seconds = 2 ** int(value) / 100_000
    shown = str(int(seconds)) if seconds >= 10 else f"{seconds:.2g}"
    return f"{value} (about {shown} seconds)"


def _exponent(key: str, label: str, word: str, help_text: str) -> Setting:
    return Setting(
        key,
        label,
        f"evb {word} {{exponent}}",
        (
            Field(
                "exponent",
                "Exponent",
                "int",
                minimum=0,
                maximum=EXPONENT_MAX,
                hint=f"10 microseconds times 2 to this power; default {DEFAULT_EXPONENT} "
                "(about 335 seconds)",
            ),
        ),
        no_line=f"no evb {word}",
        group="VDP timers",
        help=help_text,
    )


_GLOBAL = Scope(
    key="global",
    label="Whole switch",
    ident=(),
    enter=(),
    help="EVB for every port. Remove puts a setting back to its default.",
    settings=(
        Setting(
            "mac",
            "VDP address",
            "evb mac {mac}",
            (
                Field(
                    "mac",
                    "Address",
                    "choice",
                    choices=VDP_MACS,
                    hint="0180.c200.0000: the nearest bridge (default); 0180.c200.0003: the "
                    "nearest bridge that is not a two-port relay",
                ),
            ),
            no_line="no evb mac",
            group="VDP",
            help="The address the servers send VDP to; it must match theirs.",
        ),
        _exponent(
            "resource_wait_delay",
            "Answer wait",
            "resource-wait-delay",
            "How long a server waits for the switch to answer a VDP request.",
        ),
        _exponent(
            "reinit_keep_alive",
            "Keep-alive",
            "reinit-keep-alive",
            "How often a server tells the switch its VSIs are still there.",
        ),
        Setting(
            "batch_response_off",
            "Answer each request on its own",
            "evb batch-response disable",
            group="VDP",
            help="Turns off answering several VDP requests in one message.",
        ),
    ),
)

SCOPES = (_GLOBAL,)

_COUNTERS = (
    ("VDP messages received", "evb_cnt_recv_vdpdu"),
    ("VDP messages dropped", "evb_cnt_drop_vdpdu"),
    ("TLVs received", "evb_cnt_recv_tlv"),
    ("Manager TLVs received", "evb_cnt_recv_mgr_tlv"),
    ("Association TLVs received", "evb_cnt_recv_assoc_tlv"),
    ("Commands received", "evb_cnt_recv_cmd"),
)
_HOST_COLUMNS = ("Host Name", "VNI", "Vlan", "BD", "Mac-address", "IP-Address", "Interface")
_VSI_COLUMNS = ("Mgr ID", "VSI ID", "Interface", "Profile ID", "M-state", "E-State", "RWD/RKA")


def parse_rows(output: str | None, first: str, width: int) -> list[tuple[str, ...]]:
    """The rows of an EVB table printed as text: the lines after the heading that starts
    with ``first`` and its dashes, with ``width`` cells parted by spaces (a host name with a
    space in it joins its first cells)."""
    rows = []
    started = False
    for line in (output or "").splitlines():
        if line.startswith(first):
            started = True
            continue
        stripped = line.strip()
        if not started or not stripped or set(stripped) <= {"-", " "}:
            continue
        cells = stripped.split()
        if len(cells) < width:
            continue
        cells = [" ".join(cells[: len(cells) - width + 1]), *cells[len(cells) - width + 1 :]]
        rows.append(tuple(cells))
    return rows


def parse_hosts(output: str | None) -> list[tuple[str, ...]]:
    """``show evb hosts`` as text: (host, VNI, VLAN, BD, MAC, IP address, port)."""
    rows = parse_rows(output, "Host Name", len(_HOST_COLUMNS))
    return [(*r[:-1], long_name(r[-1])) for r in rows]


def parse_vsis(output: str | None) -> list[tuple[str, ...]]:
    """``show evb vsi`` as text: (manager, VSI, port, profile, M-state, E-state,
    wait/keep-alive)."""
    rows = parse_rows(output, "Mgr ID", len(_VSI_COLUMNS))
    return [(r[0], r[1], long_name(r[2]), *r[3:]) for r in rows]


def parse_evb_config(config: str) -> dict[str, dict[str, str]]:
    """The switch-wide ``evb`` lines of ``show running-config``, as setting values."""
    values: dict[str, dict[str, str]] = {}
    for line in parse_vxlan_config(config).children():
        if match := re.fullmatch(r"evb mac (\S+)", line):
            values["mac"] = {"mac": match.group(1)}
        elif match := re.fullmatch(r"evb (resource-wait-delay|reinit-keep-alive) (\d+)", line):
            values[match.group(1).replace("-", "_")] = {"exponent": match.group(2)}
        elif line == "evb batch-response disable":
            values["batch_response_off"] = {}
    return values


def parse_evb(
    state: Any, hosts: str | None = None, vsis: str | None = None, config: str | None = None
) -> ProtocolView:
    """The page from ``show evb`` (JSON), the hosts and VSIs as text (None: not shown) and
    the configuration text (None: not shown)."""
    body = state if isinstance(state, dict) else {}
    values = parse_evb_config(config) if config is not None else {}
    if config is None:  # the current values from show evb, when the configuration is not read
        if body.get("evb_vdp_mac"):
            values["mac"] = {"mac": text(body.get("evb_vdp_mac"))}
        for key, source in (("resource_wait_delay", "evb_rwd"), ("reinit_keep_alive", "evb_rka")):
            if text(body.get(source)):
                values[key] = {"exponent": text(body.get(source))}
    facts = (
        ("Role", text(body.get("evb_role")) or "-"),
        ("VDP address", text(body.get("evb_vdp_mac")) or "-"),
        ("Answer wait", wait_time(body.get("evb_rwd"))),
        ("Keep-alive", wait_time(body.get("evb_rka"))),
        ("Answers each request on its own", "yes" if "batch_response_off" in values else "no"),
        *((label, text(body.get(key)) or "0") for label, key in _COUNTERS),
    )
    notes = []
    if config is None:
        notes.append(
            "The switch did not show its configuration to NXray's account: whether it "
            "answers each request on its own is not known."
        )
    tables = (
        Table(
            "Hosts",
            ("Host", "VNI", "VLAN", "Bridge domain", "MAC address", "IP address", "Port"),
            tuple(parse_hosts(hosts)),
            empty="No server has announced a VM over VDP."
            if hosts is not None
            else "The switch did not report its EVB hosts.",
        ),
        Table(
            "Virtual station interfaces (VSIs)",
            ("Manager", "VSI", "Port", "Profile", "M-state", "E-state", "Wait/keep-alive"),
            tuple(parse_vsis(vsis)),
            empty="No VSI." if vsis is not None else "The switch did not report its VSIs.",
            note="E-state: P pre-associated, PR pre-associated with a reservation, A "
            "associated, D de-associated, S standby.",
        ),
    )
    whole = Instance("global", {}, "Whole switch", facts, values)
    return ProtocolView((whole,), tables, tuple(notes))


EVB = Protocol(
    key="evb",
    name="Edge Virtual Bridging",
    summary="Servers' virtual switches announce their VMs to the switch with VDP",
    features=(FEATURE,),
    commands=(),
    parse=lambda bodies: parse_evb(None),
    scopes=SCOPES,
    about=(
        "With the evb feature on, the switch answers VDP on every port: a server's virtual "
        "switch tells it which VM interfaces come up on which port and VLAN. The VDP "
        "address and timers must match the servers'."
    ),
)


@dataclass(frozen=True)
class EvbPage:
    """Everything the Edge Virtual Bridging page shows."""

    protocol: Protocol
    view: ProtocolView
    problem: str = ""
    missing: tuple[str, ...] = ()  # the evb feature, when it is off


def load_evb_page(client: NxapiClient) -> EvbPage:
    """``show feature``; while EVB is on, ``show evb``, its hosts and VSIs as text and the
    configuration text."""
    (feature,) = client.show("show feature")
    if not feature_states(feature).get(FEATURE, False):
        return EvbPage(EVB, ProtocolView(), missing=(FEATURE,))
    problem = ""
    try:
        (state,) = client.show(STATE_COMMAND)
    except NxapiCommandError as exc:
        state, problem = None, f"The switch did not report EVB: {exc}"
    texts: list[str | None] = []
    for command in (HOSTS_COMMAND, VSI_COMMAND, CONFIG_COMMAND):
        try:
            texts.append(client.show_text(command))
        except NxapiCommandError:
            texts.append(None)
    return EvbPage(EVB, parse_evb(state, *texts), problem)


def check_evb_place(page: EvbPage, ident: dict[str, str]) -> None:
    """The page's one scope is the whole switch: nothing to check."""


def build_evb_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Edge Virtual Bridging page."""
    return build_change(EVB, scope, setting, action, ident, values)
