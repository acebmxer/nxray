"""Spanning tree: what the switch reports and every setting the Spanning tree page changes.

The page is described with the same parts as the routing protocol pages
(``app/protocols.py``): scopes (the whole switch, one VLAN, the MST region,
one MST instance, one port), each setting the one configuration line it
sends with checked values in its blanks, and ``build_change`` building the
lines. ``NxapiClient.configure_spanning_tree`` sends them.

Read in one request: ``show spanning-tree summary`` (mode and switch-wide
state), ``show spanning-tree detail`` (every tree and every port in it),
``show spanning-tree mst configuration`` (the MST region), ``show vlan brief``
and ``show interface brief``. Then ``show running-config spanning-tree``, the
only place the settings of a port that is down show; NX-API gives it only as
text (``NxapiClient.show_text``) and only once NXray's role allows it (role
version 11). Without it the page still shows everything the trees report.

Tried on cisco-25gb (NX-OS 9.3(16), 2026-10-31) with a throwaway account,
on one unused port and a throwaway VLAN: per-VLAN priority, root primary and
secondary, hello, forward and max age and their ``no`` forms; the MST
region's name, revision and instance lines; on a port: port type edge, edge
trunk, network and normal, BPDU guard and filter enable and disable, guard
root, loop and none, cost, port priority, per-VLAN cost and port priority,
link type, and each ``no`` form. Not tried, because each changes every VLAN
or every port of a switch in use: the mode, the path cost method, the
switch-wide edge, network, BPDU guard, BPDU filter and loop guard defaults,
Bridge Assurance, PVST simulation, the MST timers, MST instance priorities
and per-instance port settings, and turning spanning tree off for a VLAN.
Their syntax is from Cisco's NX-OS 9.3 Layer 2 Switching Configuration
Guide; the role rule that allows them was proven with the lines that were
tried.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.nxapi import NxapiClient, NxapiCommandError, validate_port_name
from app.protocols import (
    STP_VLAN_MAX,
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
    text,
)

# ---- fields ---------------------------------------------------------------------

BRIDGE_PRIORITIES = tuple(str(n * 4096) for n in range(16))  # 0, 4096, ... 61440
PORT_PRIORITIES = tuple(str(n * 32) for n in range(8))  # 0, 32, ... 224
DEFAULT_BRIDGE_PRIORITY = 32768
DEFAULT_TIMERS = {"hello": 2, "forward": 15, "max_age": 20}
# Path cost: 1-200000000 with the long method; the short method stops at 65535
# (the switch refuses a higher one).
COST_MAX = 200000000


def _seconds(name: str, label: str, low: int, high: int, default: int) -> Field:
    return Field(name, label, "int", low, high, hint=f"{low} to {high} seconds; default {default}")


def _priority() -> Field:
    return Field(
        "priority",
        "Priority",
        "choice",
        choices=BRIDGE_PRIORITIES,
        hint="Lower wins: the switch with the lowest becomes the root. Default 32768",
    )


def _root_fields() -> tuple[Field, ...]:
    return (
        Field("role", "Become", "choice", choices=("primary", "secondary")),
        Field(
            "diameter",
            "Network diameter",
            "int",
            2,
            7,
            optional=True,
            hint="The most switches between any two ends (2 to 7); leave empty for 7",
        ),
        Field(
            "hello",
            "Hello time",
            "int",
            1,
            10,
            optional=True,
            hint="1 to 10 seconds; needs the diameter",
        ),
    )


def _hello_needs_diameter(values: dict[str, str]) -> None:
    if values["hello"] and not values["diameter"]:
        raise ValueError("the hello time is only set together with the network diameter")


def _instance(name: str = "instance", low: int = 0) -> Field:
    return Field(
        name,
        "MST instance",
        "int",
        low,
        4094,
        hint="0 is the instance every VLAN not mapped elsewhere is in",
        placeholder="1",
    )


def _cost() -> Field:
    return Field(
        "cost",
        "Cost",
        "int",
        1,
        COST_MAX,
        hint="Lower is preferred. 1 to 65535 with the short path cost method, up to "
        "200000000 with long",
    )


# ---- the whole switch -------------------------------------------------------------

_ALL_VLANS = "Every VLAN's tree is worked out again: traffic can stop for a few seconds."

SWITCH = Scope(
    "switch",
    "Whole switch",
    (),
    (),
    (
        Setting(
            "mode",
            "Mode",
            "spanning-tree mode {mode}",
            (
                Field(
                    "mode",
                    "Mode",
                    "choice",
                    choices=("rapid-pvst", "mst"),
                    hint="rapid-pvst: one tree per VLAN. mst: a few trees, VLANs mapped to them "
                    "(set the MST region first)",
                ),
            ),
            removable=False,
            help="How the switch runs spanning tree",
            warning="Changing the mode restarts spanning tree on every VLAN and port: "
            "traffic stops until the new trees are up, and other switches must use a "
            "mode that works with it.",
            group="Mode",
        ),
        Setting(
            "pathcost",
            "Path cost method",
            "spanning-tree pathcost method {method}",
            (
                Field(
                    "method",
                    "Method",
                    "choice",
                    choices=("short", "long"),
                    hint="short: costs up to 65535. long: up to 200000000, better for 10G "
                    "and faster links. Default short",
                ),
            ),
            no_line="no spanning-tree pathcost method",
            help="Every switch in the network should use the same method",
            warning=_ALL_VLANS,
            group="Mode",
        ),
        Setting(
            "bridge_assurance",
            "Bridge Assurance",
            "spanning-tree bridge assurance",
            help="Network ports expect spanning tree messages from the other end and stop "
            "forwarding when they stop coming. On by default",
            warning="Ports of type network change state when it is turned on or off.",
            group="Protection",
        ),
        Setting(
            "edge_default",
            "Edge ports by default",
            "spanning-tree port type edge default",
            help="Every access port is an edge port (starts forwarding at once) unless it is "
            "set otherwise. Only for ports with a single computer on them",
            warning="Every access port becomes an edge port. A switch plugged into one can "
            "make a loop until spanning tree notices it.",
            group="Defaults for ports",
        ),
        Setting(
            "network_default",
            "Network ports by default",
            "spanning-tree port type network default",
            help="Every port is a network port (for links to other switches, with Bridge "
            "Assurance) unless it is set otherwise",
            warning="With Bridge Assurance on, every port whose other end sends no spanning "
            "tree messages (a server, a router) stops forwarding.",
            group="Defaults for ports",
        ),
        Setting(
            "bpduguard_default",
            "BPDU guard on edge ports by default",
            "spanning-tree port type edge bpduguard default",
            help="An edge port that hears from another switch is shut down (error-disabled)",
            group="Defaults for ports",
        ),
        Setting(
            "bpdufilter_default",
            "BPDU filter on edge ports by default",
            "spanning-tree port type edge bpdufilter default",
            help="Edge ports stop sending spanning tree messages; one that hears one becomes "
            "a normal port again",
            group="Defaults for ports",
        ),
        Setting(
            "loopguard_default",
            "Loop guard by default",
            "spanning-tree loopguard default",
            help="A port that stops hearing from the other end blocks instead of forwarding, "
            "on every point-to-point port",
            group="Defaults for ports",
        ),
        Setting(
            "pvst_simulate",
            "PVST simulation",
            "spanning-tree mst simulate pvst global",
            help="In mst mode, talk to switches running per-VLAN spanning tree on the same "
            "ports. On by default",
            group="MST",
        ),
        Setting(
            "mst_hello",
            "MST hello time",
            "spanning-tree mst hello-time {seconds}",
            (_seconds("seconds", "Hello time", 1, 10, 2),),
            no_line="no spanning-tree mst hello-time",
            group="MST",
        ),
        Setting(
            "mst_forward",
            "MST forward delay",
            "spanning-tree mst forward-time {seconds}",
            (_seconds("seconds", "Forward delay", 4, 30, 15),),
            no_line="no spanning-tree mst forward-time",
            group="MST",
        ),
        Setting(
            "mst_max_age",
            "MST maximum age",
            "spanning-tree mst max-age {seconds}",
            (_seconds("seconds", "Maximum age", 6, 40, 20),),
            no_line="no spanning-tree mst max-age",
            group="MST",
        ),
        Setting(
            "mst_max_hops",
            "MST maximum hops",
            "spanning-tree mst max-hops {hops}",
            (Field("hops", "Hops", "int", 1, 255, hint="1 to 255; default 20"),),
            no_line="no spanning-tree mst max-hops",
            group="MST",
        ),
    ),
    help="Settings for every VLAN and port",
)

# ---- one VLAN -----------------------------------------------------------------------

_VLAN = Field(
    "vlan",
    "VLAN",
    "vlan",
    hint=f"A VLAN on the switch (1 to {STP_VLAN_MAX})",
    placeholder="10",
)

VLAN = Scope(
    "vlan",
    "VLAN",
    (_VLAN,),
    (),
    (
        Setting(
            "priority",
            "Bridge priority",
            "spanning-tree vlan {vlan} priority {priority}",
            (_priority(),),
            no_line="no spanning-tree vlan {vlan} priority",
            help="Removing it goes back to 32768",
            warning="The VLAN's tree can change: traffic in it can stop for a moment.",
            group="Root",
            ident=("vlan",),
        ),
        Setting(
            "root",
            "Make this switch the root",
            "spanning-tree vlan {vlan} root {role}[ diameter {diameter}][ hello-time {hello}]",
            _root_fields(),
            removable=False,
            help="The switch picks a priority below the current root's (primary) or just above "
            "it (secondary) and stores that priority; change it back with Bridge priority",
            warning="The VLAN's tree can change: traffic in it can stop for a moment.",
            group="Root",
            check=_hello_needs_diameter,
            ident=("vlan",),
        ),
        Setting(
            "hello",
            "Hello time",
            "spanning-tree vlan {vlan} hello-time {seconds}",
            (_seconds("seconds", "Hello time", 1, 10, 2),),
            no_line="no spanning-tree vlan {vlan} hello-time",
            help="How often the root sends its messages",
            group="Timers",
            ident=("vlan",),
        ),
        Setting(
            "forward",
            "Forward delay",
            "spanning-tree vlan {vlan} forward-time {seconds}",
            (_seconds("seconds", "Forward delay", 4, 30, 15),),
            no_line="no spanning-tree vlan {vlan} forward-time",
            help="How long a port listens and learns before forwarding",
            group="Timers",
            ident=("vlan",),
        ),
        Setting(
            "max_age",
            "Maximum age",
            "spanning-tree vlan {vlan} max-age {seconds}",
            (_seconds("seconds", "Maximum age", 6, 40, 20),),
            no_line="no spanning-tree vlan {vlan} max-age",
            help="How long a port keeps the root's last message",
            group="Timers",
            ident=("vlan",),
        ),
        Setting(
            "off",
            "Spanning tree off for this VLAN",
            "no spanning-tree vlan {vlan}",
            no_line="spanning-tree vlan {vlan}",
            help="Set turns spanning tree off in this VLAN; Remove turns it back on",
            warning="Without spanning tree, a loop in this VLAN floods it and every port in "
            "it until the loop is unplugged.",
            group="On or off",
            ident=("vlan",),
        ),
    ),
    help="Each VLAN has its own tree in rapid-pvst mode",
)

# ---- MST ----------------------------------------------------------------------------

_REGION_WARNING = (
    "In mst mode the switch works its trees out again, and only switches with the same "
    "name, revision and VLAN mapping are in one region."
)

MST_REGION = Scope(
    "mst",
    "MST region",
    (),
    ("spanning-tree mst configuration",),
    (
        Setting(
            "name",
            "Region name",
            "name {name}",
            (Field("name", "Name", "name", maximum=32, placeholder="campus"),),
            no_line="no name",
            warning=_REGION_WARNING,
            group="Region",
        ),
        Setting(
            "revision",
            "Revision",
            "revision {revision}",
            (Field("revision", "Revision", "int", 0, 65535, hint="0 to 65535; default 0"),),
            no_line="no revision",
            warning=_REGION_WARNING,
            group="Region",
        ),
        Setting(
            "instance",
            "Map VLANs to an instance",
            "instance {instance} vlan {vlans}",
            (
                _instance(low=1),
                Field("vlans", "VLANs", "vlans", placeholder="10,20-30"),
            ),
            help="Remove takes just these VLANs out of the instance",
            warning=_REGION_WARNING,
            group="Instances",
        ),
        Setting(
            "remove_instance",
            "Instance",
            "instance {instance}",
            (_instance(low=1),),
            no_line="no instance {instance}",
            settable=False,
            help="Remove takes the instance away; its VLANs go back to instance 0",
            warning=_REGION_WARNING,
            group="Instances",
        ),
    ),
    help="Used in mst mode only: which VLANs share which tree",
)

_MST_ID = Field("instance", "MST instance", "int", 0, 4094, placeholder="1")

MST_INSTANCE = Scope(
    "mst_instance",
    "MST instance",
    (_MST_ID,),
    (),
    (
        Setting(
            "priority",
            "Bridge priority",
            "spanning-tree mst {instance} priority {priority}",
            (_priority(),),
            no_line="no spanning-tree mst {instance} priority",
            warning="The instance's tree can change: traffic in its VLANs can stop for a moment.",
            group="Root",
            ident=("instance",),
        ),
        Setting(
            "root",
            "Make this switch the root",
            "spanning-tree mst {instance} root {role}[ diameter {diameter}][ hello-time {hello}]",
            _root_fields(),
            removable=False,
            help="The switch picks and stores a priority, as for a VLAN",
            warning="The instance's tree can change: traffic in its VLANs can stop for a moment.",
            group="Root",
            check=_hello_needs_diameter,
            ident=("instance",),
        ),
    ),
    help="Used in mst mode only",
)

# ---- one port -----------------------------------------------------------------------

_PORT_TREE = "The port's state can change: traffic on it can stop for a moment."

PORT = Scope(
    "port",
    "Port",
    (port_field(),),
    ("interface {port}",),
    (
        Setting(
            "port_type",
            "Port type",
            "spanning-tree port type {type}",
            (
                Field(
                    "type",
                    "Type",
                    "choice",
                    choices=("edge", "edge trunk", "network", "normal"),
                    hint="edge: one computer or server, forwards at once (edge trunk for a "
                    "trunk to a server). network: a link to another switch, with Bridge "
                    "Assurance. normal: neither",
                ),
            ),
            no_line="no spanning-tree port type",
            help="Remove goes back to the switch-wide default",
            warning="An edge port with a switch behind it can make a loop until spanning tree "
            "notices; a network port whose other end sends no spanning tree messages stops "
            "forwarding while Bridge Assurance is on.",
            group="Port type",
        ),
        Setting(
            "bpduguard",
            "BPDU guard",
            "spanning-tree bpduguard {state}",
            (
                Field(
                    "state",
                    "BPDU guard",
                    "choice",
                    choices=("enable", "disable"),
                    hint="enable: the port is shut down (error-disabled) when it hears from "
                    "another switch",
                ),
            ),
            no_line="no spanning-tree bpduguard",
            help="Remove goes back to the default for edge ports",
            group="Protection",
        ),
        Setting(
            "bpdufilter",
            "BPDU filter",
            "spanning-tree bpdufilter {state}",
            (
                Field(
                    "state",
                    "BPDU filter",
                    "choice",
                    choices=("enable", "disable"),
                    hint="enable: the port neither sends nor listens to spanning tree messages, "
                    "so it cannot notice a loop",
                ),
            ),
            no_line="no spanning-tree bpdufilter",
            help="Remove goes back to the default for edge ports",
            warning="A port with BPDU filter on cannot notice a loop through it.",
            group="Protection",
        ),
        Setting(
            "guard",
            "Guard",
            "spanning-tree guard {guard}",
            (
                Field(
                    "guard",
                    "Guard",
                    "choice",
                    choices=("root", "loop", "none"),
                    hint="root: the port blocks if a better root shows up behind it. loop: the "
                    "port blocks if it stops hearing from the other end. none: neither, even "
                    "when loop guard is on by default",
                ),
            ),
            no_line="no spanning-tree guard",
            group="Protection",
        ),
        Setting(
            "cost",
            "Cost",
            "spanning-tree cost {cost}",
            (_cost(),),
            no_line="no spanning-tree cost",
            help="For every VLAN; remove goes back to the cost worked out from the speed",
            warning=_PORT_TREE,
            group="Cost and priority",
        ),
        Setting(
            "priority",
            "Port priority",
            "spanning-tree port-priority {priority}",
            (
                Field(
                    "priority",
                    "Priority",
                    "choice",
                    choices=PORT_PRIORITIES,
                    hint="Lower is preferred between two equal ports. Default 128",
                ),
            ),
            no_line="no spanning-tree port-priority",
            warning=_PORT_TREE,
            group="Cost and priority",
        ),
        Setting(
            "vlan_cost",
            "Cost in some VLANs",
            "spanning-tree vlan {vlans} cost {cost}",
            (Field("vlans", "VLANs", "vlans", placeholder="10,20-30"), _cost()),
            no_line="no spanning-tree vlan {vlans} cost",
            warning=_PORT_TREE,
            group="Cost and priority",
        ),
        Setting(
            "vlan_priority",
            "Port priority in some VLANs",
            "spanning-tree vlan {vlans} port-priority {priority}",
            (
                Field("vlans", "VLANs", "vlans", placeholder="10,20-30"),
                Field("priority", "Priority", "choice", choices=PORT_PRIORITIES),
            ),
            no_line="no spanning-tree vlan {vlans} port-priority",
            warning=_PORT_TREE,
            group="Cost and priority",
        ),
        Setting(
            "mst_cost",
            "Cost in an MST instance",
            "spanning-tree mst {instance} cost {cost}",
            (_instance(), _cost()),
            no_line="no spanning-tree mst {instance} cost",
            warning=_PORT_TREE,
            group="Cost and priority",
        ),
        Setting(
            "mst_priority",
            "Port priority in an MST instance",
            "spanning-tree mst {instance} port-priority {priority}",
            (_instance(), Field("priority", "Priority", "choice", choices=PORT_PRIORITIES)),
            no_line="no spanning-tree mst {instance} port-priority",
            warning=_PORT_TREE,
            group="Cost and priority",
        ),
        Setting(
            "link_type",
            "Link type",
            "spanning-tree link-type {type}",
            (
                Field(
                    "type",
                    "Link type",
                    "choice",
                    choices=("point-to-point", "shared", "auto"),
                    hint="point-to-point: straight to one other device (fast changes). "
                    "shared: a hub. auto: from the duplex (default)",
                ),
            ),
            no_line="no spanning-tree link-type",
            group="Port type",
        ),
    ),
    help="A front port or port-channel that carries VLANs (not a routed port)",
)

# ---- reading ------------------------------------------------------------------------

COMMANDS = (
    "show spanning-tree summary",
    "show spanning-tree detail",
    "show spanning-tree mst configuration",
    "show vlan brief",
    "show interface brief",
)
CONFIG_COMMAND = "show running-config spanning-tree"


def expand_vlans(spec: str) -> list[int]:
    """'1-2,10' -> [1, 2, 10]; anything that is not a list of numbers gives []."""
    found: list[int] = []
    for part in spec.replace(" ", "").split(","):
        low, _, high = part.partition("-")
        if not low.isdigit() or (high and not high.isdigit()):
            return []
        found.extend(range(int(low), int(high or low) + 1))
    return found


@dataclass
class StpConfig:
    """The spanning-tree lines of the running configuration, sorted by where they apply."""

    switch: list[str] = field(default_factory=list)  # lines typed at the top level
    vlans: dict[int, dict[str, str]] = field(default_factory=dict)  # vlan -> {setting: value}
    off_vlans: set[int] = field(default_factory=set)
    region: list[str] = field(default_factory=list)  # lines inside mst configuration
    instances: dict[int, dict[str, str]] = field(default_factory=dict)
    ports: dict[str, list[str]] = field(default_factory=dict)  # port -> its lines


_VLAN_LINE = re.compile(
    r"^spanning-tree vlan (\S+) (priority|hello-time|forward-time|max-age) (\d+)$"
)
_VLAN_OFF = re.compile(r"^no spanning-tree vlan (\S+)$")
_MST_LINE = re.compile(r"^spanning-tree mst (\S+) priority (\d+)$")
_VLAN_KEYS = {"priority": "priority", "hello-time": "hello", "forward-time": "forward"}


def parse_stp_config(config: str) -> StpConfig:
    """``show running-config spanning-tree`` (only the lines that differ from the
    defaults), as typed text, sorted by where each line applies."""
    found = StpConfig()
    block: str | None = None  # "region", or a port name, while inside one
    for raw in config.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.startswith("!"):
            continue
        if line.startswith(" "):
            if block == "region":
                found.region.append(line.strip())
            elif block is not None:
                found.ports.setdefault(block, []).append(line.strip())
            continue
        block = None
        if line == "spanning-tree mst configuration":
            block = "region"
        elif line.startswith("interface "):
            name = line.removeprefix("interface ")
            block = name if name.startswith(("Ethernet", "port-channel")) else "ignored"
        elif match := _VLAN_LINE.match(line):
            key = _VLAN_KEYS.get(match.group(2), "max_age")
            for vlan in expand_vlans(match.group(1)):
                found.vlans.setdefault(vlan, {})[key] = match.group(3)
        elif match := _VLAN_OFF.match(line):
            found.off_vlans.update(expand_vlans(match.group(1)))
        elif match := _MST_LINE.match(line):
            for instance in expand_vlans(match.group(1)):
                found.instances.setdefault(instance, {})["priority"] = match.group(2)
        else:
            found.switch.append(line)
    found.ports.pop("ignored", None)
    return found


# Switch-wide lines and the setting each one is (lines without a value).
_SWITCH_FLAGS = {
    "spanning-tree port type edge default": "edge_default",
    "spanning-tree port type network default": "network_default",
    "spanning-tree port type edge bpduguard default": "bpduguard_default",
    "spanning-tree port type edge bpdufilter default": "bpdufilter_default",
    "spanning-tree loopguard default": "loopguard_default",
}
_SWITCH_VALUES = {
    "spanning-tree mst hello-time ": ("mst_hello", "seconds"),
    "spanning-tree mst forward-time ": ("mst_forward", "seconds"),
    "spanning-tree mst max-age ": ("mst_max_age", "seconds"),
    "spanning-tree mst max-hops ": ("mst_max_hops", "hops"),
}
_PORT_VALUES = (
    (
        re.compile(r"^spanning-tree port type (edge trunk|edge|network|normal)$"),
        "port_type",
        "type",
    ),
    (re.compile(r"^spanning-tree bpduguard (enable|disable)$"), "bpduguard", "state"),
    (re.compile(r"^spanning-tree bpdufilter (enable|disable)$"), "bpdufilter", "state"),
    (re.compile(r"^spanning-tree guard (root|loop|none)$"), "guard", "guard"),
    (re.compile(r"^spanning-tree cost (\d+)$"), "cost", "cost"),
    (re.compile(r"^spanning-tree port-priority (\d+)$"), "priority", "priority"),
    (re.compile(r"^spanning-tree link-type (point-to-point|shared|auto)$"), "link_type", "type"),
)


def _port_values(lines: list[str]) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    for line in lines:
        for pattern, key, name in _PORT_VALUES:
            if match := pattern.match(line):
                values[key] = {name: match.group(1)}
    return values


def _switch_values(summary: dict[str, Any], config: StpConfig | None) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    mode = text(summary.get("stp-mode"))
    if mode in ("rapid-pvst", "mst"):
        values["mode"] = {"mode": mode}
    method = text(summary.get("pcost_method"))
    if method in ("1", "2"):
        values["pathcost"] = {"method": "short" if method == "1" else "long"}
    if text(summary.get("bridge_assurance")) == "1":
        values["bridge_assurance"] = {}
    if text(summary.get("simulate_pvst")) == "true":
        values["pvst_simulate"] = {}
    if text(summary.get("oper_loopguard")) == "true":
        values["loopguard_default"] = {}
    if text(summary.get("networkport_default")) == "1":
        values["network_default"] = {}
    if config is not None:
        for line in config.switch:
            if line in _SWITCH_FLAGS:
                values[_SWITCH_FLAGS[line]] = {}
            for start, (key, name) in _SWITCH_VALUES.items():
                if line.startswith(start):
                    values[key] = {name: line.removeprefix(start)}
    return values


def _on_off(value: Any) -> str:
    return {"1": "on", "true": "on", "0": "off", "false": "off"}.get(text(value), text(value))


def _bridge(priority: Any, mac: Any) -> str:
    shown = " ".join(p for p in (text(priority), text(mac)) if p)
    return shown or "—"


def _trees(detail: dict[str, Any]) -> list[dict[str, Any]]:
    return table_rows(detail, "TABLE_tree", "ROW_tree")


def _tree_name(tree: dict[str, Any]) -> str:
    kind = text(tree.get("tree_tree_type"))
    number = text(tree.get("tree_id"))
    return f"MST {number}" if kind == "mst" else f"VLAN {number}"


def _configured_priority(tree: dict[str, Any]) -> int | None:
    """The priority as typed: the switch adds the VLAN number to it (32768 + VLAN 10 =
    32778, the extended system ID)."""
    reported, number = text(tree.get("bridge_priority")), text(tree.get("tree_id"))
    if not reported.isdigit() or not number.isdigit():
        return None
    typed = int(reported) - int(number)
    return typed if typed >= 0 and typed % 4096 == 0 else None


def _ago(seconds: Any) -> str:
    value = text(seconds)
    if not value.isdigit():
        return ""
    total = int(value)
    days, rest = divmod(total, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    parts = [f"{days}d" if days else "", f"{hours}h" if hours else "", f"{minutes}m"]
    return " ".join(p for p in parts if p) + " ago"


def _problem(port: dict[str, Any]) -> str:
    """What is wrong with a port in one tree, in words; "" when nothing is."""
    found = []
    if text(port.get("inconsistency")) not in ("", "0"):
        found.append(f"inconsistent ({text(port.get('inconsistency'))})")
    if text(port.get("dispute")) == "true":
        found.append("dispute")
    if text(port.get("self_looped")) == "true":
        found.append("looped back to itself")
    if text(port.get("state")) in ("blocking", "broken"):
        found.append(text(port.get("state")))
    return ", ".join(found)


def parse_spanning_tree(
    bodies: list[dict[str, Any]], config_text: str | None = None
) -> ProtocolView:
    """The Spanning tree page from the five reads in ``COMMANDS`` and, when NXray may
    read it, ``show running-config spanning-tree`` as text (None when it may not).

    Every port row is from recorded output with all ports forwarding; blocked,
    inconsistent and disputed ports were never seen live, so their words come
    from the field names alone.
    """
    summary, detail, region, vlan_brief, brief = (list(bodies) + [{}] * 5)[:5]
    config = parse_stp_config(config_text) if config_text is not None else None
    mode = text(summary.get("stp-mode")) or "unknown"
    instances: list[Instance] = []
    notes: list[str] = []

    instances.append(
        Instance(
            "switch",
            {},
            "This switch",
            (
                ("Mode", mode),
                ("Root bridge for", text(summary.get("tree_root_bmp")) or "none"),
                (
                    "Path cost method",
                    {"1": "short", "2": "long"}.get(
                        text(summary.get("pcost_method")), text(summary.get("pcost_method"))
                    ),
                ),
                ("Bridge Assurance", _on_off(summary.get("bridge_assurance"))),
                ("Loop guard by default", _on_off(summary.get("oper_loopguard"))),
            ),
            _switch_values(summary, config),
        )
    )

    trees = _trees(detail)
    by_vlan = {text(t.get("tree_id")): t for t in trees if text(t.get("tree_tree_type")) == "vlan"}
    vlan_numbers = _vlan_numbers(vlan_brief)
    tree_rows: list[tuple[str, ...]] = []
    port_rows: list[tuple[str, ...]] = []
    problem_rows: list[tuple[str, ...]] = []
    port_states: dict[str, list[str]] = {}
    for tree in trees:
        name = _tree_name(tree)
        root_port = text(tree.get("root_port_if_index")) or "this switch is the root"
        tree_rows.append(
            (
                name,
                _bridge(
                    tree.get("tree_designated_root_priority"), tree.get("tree_designated_root")
                ),
                _bridge(tree.get("bridge_priority"), tree.get("bridge_mac")),
                root_port,
                text(tree.get("root_path_cost")),
                f"{text(tree.get('forwarding')) or '0'} / {text(tree.get('blocking')) or '0'}",
                f"{text(tree.get('topology_change_count'))}"
                + (
                    f", last {_ago(tree.get('topology_change_time_since_last'))}"
                    if _ago(tree.get("topology_change_time_since_last"))
                    else ""
                ),
                f"{text(tree.get('hello_time'))} / {text(tree.get('forward_delay'))} / "
                f"{text(tree.get('max_age'))}",
            )
        )
        for port in table_rows(tree, "TABLE_port", "ROW_port"):
            port_name = text(port.get("if_index"))
            edge = "edge" if text(port.get("oper_portfast")) == "true" else ""
            problem = _problem(port)
            port_rows.append(
                (
                    port_name,
                    name,
                    text(port.get("role")),
                    text(port.get("state")),
                    text(port.get("path_cost")),
                    text(port.get("port_priority")),
                    ", ".join(x for x in (edge, problem) if x),
                )
            )
            port_states.setdefault(port_name, []).append(
                f"{name}: {text(port.get('role'))} {text(port.get('state'))}"
            )
            if problem:
                problem_rows.append((port_name, name, problem))

    for number in vlan_numbers:
        tree = by_vlan.get(str(number))
        facts: list[tuple[str, str]] = []
        values: dict[str, dict[str, str]] = {}
        typed = config.vlans.get(number, {}) if config is not None else {}
        if config is not None and number in config.off_vlans:
            facts.append(("Spanning tree", "off"))
            values["off"] = {}
        if tree is not None:
            priority = _configured_priority(tree)
            facts += [
                ("This switch", _bridge(tree.get("bridge_priority"), tree.get("bridge_mac"))),
                (
                    "Root",
                    _bridge(
                        tree.get("tree_designated_root_priority"), tree.get("tree_designated_root")
                    ),
                ),
                ("Root port", text(tree.get("root_port_if_index")) or "this switch is the root"),
                (
                    "Hello / forward / max age",
                    f"{text(tree.get('bridge_hello_time'))} / "
                    f"{text(tree.get('bridge_forward_delay'))} / "
                    f"{text(tree.get('bridge_max_age'))}",
                ),
            ]
            if priority is not None and priority != DEFAULT_BRIDGE_PRIORITY:
                values["priority"] = {"priority": str(priority)}
            for key, reported in (
                ("hello", tree.get("bridge_hello_time")),
                ("forward", tree.get("bridge_forward_delay")),
                ("max_age", tree.get("bridge_max_age")),
            ):
                if text(reported).isdigit() and int(text(reported)) != DEFAULT_TIMERS[key]:
                    values[key] = {"seconds": text(reported)}
        elif not facts:
            facts.append(("Tree", "none: no port carrying this VLAN is up"))
        if typed.get("priority"):
            values["priority"] = {"priority": typed["priority"]}
        for key in ("hello", "forward", "max_age"):
            if typed.get(key):
                values[key] = {"seconds": typed[key]}
        instances.append(
            Instance("vlan", {"vlan": str(number)}, f"VLAN {number}", tuple(facts), values)
        )

    region_name = text(region.get("name"))
    revision = text(region.get("rev-id")) or "0"
    mapping = [
        (text(r.get("mst_id")), text(r.get("vlan_bit_map")))
        for r in table_rows(region, "TABLE_instance_to_vlan_map", "ROW_instance_to_vlan_map")
    ]
    region_values: dict[str, dict[str, str]] = {}
    if region_name:
        region_values["name"] = {"name": region_name}
    if revision != "0":
        region_values["revision"] = {"revision": revision}
    instances.append(
        Instance(
            "mst",
            {},
            "MST region",
            (
                ("Name", region_name or "none"),
                ("Revision", revision),
                *((f"Instance {i}", v) for i, v in mapping),
            ),
            region_values,
        )
    )
    for number, vlans in mapping:
        values = {}
        if config is not None and number.isdigit():
            typed_priority = config.instances.get(int(number), {}).get("priority")
            if typed_priority:
                values["priority"] = {"priority": typed_priority}
        instances.append(
            Instance(
                "mst_instance",
                {"instance": number},
                f"MST instance {number}",
                (("VLANs", vlans),),
                values,
            )
        )
    if mode != "mst":
        notes.append(
            "The MST region and instances are used only in mst mode; the switch keeps them "
            "until then."
        )

    configured = config.ports if config is not None else {}
    # Every switched port, cable or not, then any port a tree names that the
    # brief left out.
    shown = switch_port_names(brief)
    shown += [p for p in port_states if p not in shown]
    setting_rows: list[tuple[str, ...]] = []
    for port in shown:
        lines = configured.get(port, [])
        values = _port_values(lines)
        other = [line for line in lines if re.match(r"spanning-tree (vlan|mst) ", line)]
        setting_rows.append(
            (
                port,
                *(
                    next(iter(values[key].values())) if key in values else "default"
                    for key in (
                        "port_type",
                        "bpduguard",
                        "bpdufilter",
                        "guard",
                        "cost",
                        "priority",
                        "link_type",
                    )
                ),
                "; ".join(line.removeprefix("spanning-tree ") for line in other),
            )
        )
        port_facts = tuple(("In", state) for state in port_states.get(port, [])) or (
            ("In", "no tree: the port is down or carries no VLAN"),
        )
        instances.append(Instance("port", {"port": port}, port, port_facts, values))
    if config is None:
        notes.append(
            "NXray's role on the switch does not let it read the spanning tree settings yet, "
            "so the settings of ports that are down are not shown: an NXray admin turns on "
            "spanning tree changes on the Switch page."
        )

    tables = (
        Table(
            "Trees",
            (
                "Tree",
                "Root bridge",
                "This switch",
                "Root port",
                "Root cost",
                "Forwarding / blocking",
                "Topology changes",
                "Hello / forward / max age",
            ),
            tuple(tree_rows),
            empty="No tree: no port carrying a VLAN is up.",
            note="Bridges are written priority then MAC address. The priority includes the "
            "VLAN number (32768 + VLAN 10 = 32778).",
        ),
        Table(
            "Ports in the trees",
            ("Port", "Tree", "Role", "State", "Cost", "Priority", "Notes"),
            tuple(port_rows),
            empty="No port is in a tree.",
        ),
        Table(
            "Port settings",
            (
                "Port",
                "Port type",
                "BPDU guard",
                "BPDU filter",
                "Guard",
                "Cost",
                "Priority",
                "Link type",
                "Per VLAN or MST instance",
            ),
            tuple(setting_rows),
            empty="No front port or port-channel carries VLANs.",
            note="Every front port and port-channel that carries VLANs. default: the switch's "
            "default or switch-wide setting. Change one under Port below."
            if config is not None
            else "Every front port and port-channel that carries VLANs. Their own settings show "
            "once spanning tree changes are on.",
        ),
        Table(
            "Ports with a problem",
            ("Port", "Tree", "Problem"),
            tuple(problem_rows),
            empty="None: no port is blocked, inconsistent or in a dispute.",
        ),
    )
    return ProtocolView(tuple(instances), tables, tuple(notes))


def _vlan_numbers(vlan_brief: dict[str, Any]) -> list[int]:
    numbers = []
    for row in table_rows(vlan_brief, "TABLE_vlanbriefxbrief", "ROW_vlanbriefxbrief"):
        value = text(row.get("vlanshowbr-vlanid"))
        if value.isdigit() and int(value) <= STP_VLAN_MAX:
            numbers.append(int(value))
    return sorted(numbers)


def switch_port_names(brief: dict[str, Any]) -> list[str]:
    """The front ports and port-channels in ``show interface brief`` that are not
    routed: the ones spanning tree runs on."""
    names = []
    for row in table_rows(brief, "TABLE_interface", "ROW_interface"):
        name = text(row.get("interface"))
        if text(row.get("portmode")).lower() == "routed":
            continue
        if name.startswith("port-channel"):
            names.append(name)
            continue
        try:
            names.append(validate_port_name(name))
        except ValueError:
            continue
    return names


SPANNING_TREE = Protocol(
    key="spanning-tree",
    name="Spanning tree",
    summary="Keeps loops between switches from flooding the network: blocks the extra "
    "paths and opens them when a link fails",
    features=(),
    commands=COMMANDS,
    parse=parse_spanning_tree,
    scopes=(SWITCH, VLAN, MST_REGION, MST_INSTANCE, PORT),
    about="Spanning tree is always on. Settings for the whole switch come first, then each "
    "VLAN's tree, the MST region, and each port.",
)


@dataclass(frozen=True)
class SpanningTreePage:
    """Everything the Spanning tree page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # the switched front ports and port-channels
    vlans: tuple[str, ...]  # the VLANs on the switch, as text
    problem: str = ""
    missing: tuple[str, ...] = ()  # spanning tree needs no feature; kept for the template


def load_spanning_tree_page(client: NxapiClient) -> SpanningTreePage:
    """One request for the reads, one for the configuration text NXray may read."""
    bodies = client.show(*COMMANDS)
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = None  # the role predates the rule that allows it
    view = parse_spanning_tree(bodies, config)
    vlans = tuple(str(n) for n in _vlan_numbers(bodies[3]))
    return SpanningTreePage(SPANNING_TREE, view, tuple(switch_port_names(bodies[4])), vlans)


def build_stp_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Spanning tree page."""
    return build_change(SPANNING_TREE, scope, setting, action, ident, values)
