"""ITD (Intelligent Traffic Director): spreading traffic over a group of servers or
appliances (firewalls, load balancers, caches) from the switch's own hardware, with health
probes that take a node out when it stops answering.

A **device group** lists the nodes (their addresses) and how they are probed. A
**service** takes the traffic coming in on its ingress interfaces, optionally only the
traffic for a virtual address, and spreads it over a device group's nodes in buckets by
the source or destination address. ``itd statistics <service>`` counts what each node got.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (a device group, a node in one, a service, a service's
counters), each setting the one configuration line it sends with checked values in its
blanks, and ``build_change`` building the lines. ``NxapiClient.configure_itd`` sends them.

Read from the switch: ``show feature``, ``show interface brief`` and ``show vrf interface``
in one request; while ``feature pbr`` and ``feature itd`` are on, ``show itd`` (each
service with its state, buckets and nodes), ``show running-config`` as text (the device
groups and services as set, read with the role's ``show running-config`` rule) and ``show
itd <service> statistics`` for each service.

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-11) with a throwaway device group, service and
VLAN interface, removed afterwards, ``pbr`` and ``itd`` turned back off. What the switch
showed and the page follows:

* ITD needs ``feature pbr`` as well as ``feature itd``;
* a device group's ``probe icmp``, ``probe tcp port N``, ``probe udp port N`` and ``probe
  dns host X`` take ``frequency``, ``timeout``, ``retry-down-count`` and ``retry-up-count``;
  ``no probe icmp`` removes one, a bare ``no probe`` is incomplete;
* ``node ip A`` (IPv4 and IPv6 nodes cannot share a group), and inside it ``weight N``,
  ``standby ip X`` and ``mode hot-standby`` (not with a weight or a standby) and a probe of
  its own; ``admin-down`` and ``shutdown`` are not node commands;
* a service's ``device-group``, ``ingress interface``, ``virtual ip A MASK [tcp|udp P]
  [advertise enable]``, ``load-balance method src|dst ip|ip-l4port [tcp|udp range A B]
  [buckets N] [mask-position N]`` (``dst`` was refused while a virtual address existed),
  ``failaction node reassign|least-bucket|per-bucket`` and ``failaction bucket
  distribute``, ``peer local service X``, ``nat destination``, ``access-list`` (refused
  with a virtual address) and ``exclude access-list``, ``shutdown`` and ``no shutdown``;
  their ``no`` forms need the whole line;
* ``itd statistics X`` (typed outside configuration mode) turns counting on, ``no itd
  statistics X`` off, and ``clear itd statistics X`` zeroes the counters.

``show itd`` gives TABLE_summary/ROW_summary {service_name, state, reason, lb_scheme,
buckets, TABLE_vip/ROW_vip with TABLE_vip_node/ROW_vip_node {vip_node ("1   198.51.100.10":
the node's number and address), vip_config, vip_weight, vip_status, vip_node_probe},
TABLE_device {device_grp, dg_probe}}; the statistics TABLE_nice/ROW_nice {service_name,
dev_grp, vip, vip_pkt, percentage, TABLE_node/ROW_node/TABLE_bucket/ROW_bucket {bucket_acl,
node, mode, orig_node, acl_pkt, bucket_per}}.

The counters are turned on and off outside configuration mode, which NXray's broad role
allows from version ``BROAD_ITD_VERSION`` (rules 25 to 27); a broad role written before
needs Update the port list first.
"""

from __future__ import annotations

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
    table_rows,
)
from app.routing import parse_vrf_members
from app.routing_protocols import layer3_interfaces
from app.switch import text
from app.vxlan import parse_vxlan_config

FEATURES = ("pbr", "itd")
PAGE_COMMANDS = ("show feature", "show interface brief", "show vrf", "show vrf interface")
COMMANDS = ("show itd",)
CONFIG_COMMAND = "show running-config"
METHODS = ("src ip", "dst ip", "src ip-l4port", "dst ip-l4port")
FAILACTIONS = ("node reassign", "node least-bucket", "node per-bucket", "bucket distribute")


def _name(name: str, label: str, placeholder: str) -> Field:
    return Field(name, label, "name", hint="Letters, digits, - and _", placeholder=placeholder)


def _probe_options() -> str:
    return (
        "[ frequency {frequency}][ timeout {timeout}][ retry-down-count {down}]"
        "[ retry-up-count {up}]"
    )


def _probe_fields() -> tuple[Field, ...]:
    return (
        Field("frequency", "Every (seconds)", "int", minimum=1, optional=True),
        Field("timeout", "Timeout (seconds)", "int", minimum=1, optional=True),
        Field("down", "Failures before it is down", "int", minimum=1, optional=True),
        Field("up", "Answers before it is up again", "int", minimum=1, optional=True),
    )


def _probes(group: str, what: str) -> tuple[Setting, ...]:
    """The four probe settings of a device group or a node; the switch keeps one."""
    port = Field("port", "Port", "int", minimum=1, maximum=65535, placeholder="443")
    return (
        Setting(
            key="probe_icmp",
            label="Probe by ping",
            line="probe icmp" + _probe_options(),
            no_line="no probe icmp",
            group=group,
            fields=_probe_fields(),
            help=f"Ping {what} to see that it is up.",
        ),
        Setting(
            key="probe_tcp",
            label="Probe a TCP port",
            line="probe tcp port {port}" + _probe_options(),
            no_line="no probe tcp port {port}",
            group=group,
            fields=(port, *_probe_fields()),
            help=f"Open a TCP connection to {what}.",
        ),
        Setting(
            key="probe_udp",
            label="Probe a UDP port",
            line="probe udp port {port}" + _probe_options(),
            no_line="no probe udp port {port}",
            group=group,
            fields=(port, *_probe_fields()),
            help=f"Send to a UDP port of {what}.",
        ),
        Setting(
            key="probe_dns",
            label="Probe by DNS",
            line="probe dns host {host}" + _probe_options(),
            no_line="no probe dns host {host}",
            group=group,
            fields=(
                Field("host", "Name to look up", "host", placeholder="www.example.net"),
                *_probe_fields(),
            ),
            help=f"Ask {what}, a DNS server, for a name.",
        ),
    )


_GROUP = Scope(
    key="group",
    label="Device group",
    ident=(_name("name", "Device group", "web-servers"),),
    enter=("itd device-group {name}",),
    create=True,
    create_label="Make a device group",
    delete=("no itd device-group {name}",),
    delete_warning="A service that uses this group has no nodes to send traffic to.",
    help="The servers or appliances traffic is spread over, and how they are checked.",
    settings=_probes("Health probe", "each node"),
)

_NODE = Scope(
    key="node",
    label="Node",
    ident=(
        _name("group", "Device group", "web-servers"),
        Field(
            "address",
            "Address",
            "ip",
            hint="IPv4 and IPv6 nodes cannot share a group",
            placeholder="198.51.100.10",
        ),
    ),
    enter=("itd device-group {group}", "node ip {address}"),
    create=True,
    create_label="Add a node",
    delete=("itd device-group {group}", "no node ip {address}"),
    delete_warning="Its buckets go to the other nodes of the group.",
    help="One server or appliance in a device group.",
    settings=(
        Setting(
            key="weight",
            label="Weight",
            line="weight {weight}",
            group="Node",
            fields=(Field("weight", "Weight", "int", minimum=1, placeholder="2"),),
            help="How many buckets it gets compared with the others.",
        ),
        Setting(
            key="standby",
            label="Standby node",
            line="standby ip {standby}",
            group="Node",
            fields=(Field("standby", "Address", "ip", placeholder="198.51.100.20"),),
            help="A node that takes this one's traffic when it is down.",
        ),
        Setting(
            key="hot_standby",
            label="Hot standby",
            line="mode hot-standby",
            group="Node",
            help="This node gets traffic only when another node is down. Not with a weight "
            "or a standby node.",
        ),
        *_probes("Health probe", "this node"),
    ),
)

_SERVICE = Scope(
    key="service",
    label="Service",
    ident=(_name("name", "Service", "web"),),
    enter=("itd {name}",),
    create=True,
    create_label="Make a service",
    delete=("no itd {name}",),
    delete_warning="Traffic it spread is routed by the routing table again.",
    help="Which traffic is spread, over which device group, and how.",
    settings=(
        Setting(
            key="device_group",
            label="Device group",
            line="device-group {group}",
            group="Service",
            fields=(_name("group", "Device group", "web-servers"),),
        ),
        Setting(
            key="ingress",
            label="Ingress interface",
            line="ingress interface {interface}",
            group="Service",
            fields=(Field("interface", "Interface", "interface"),),
            help="Traffic coming in here is spread. Set again for another interface.",
        ),
        Setting(
            key="vip",
            label="Virtual address",
            line="virtual ip {address} {mask}[ {protocol} {port}][ {advertise}]",
            group="Service",
            fields=(
                Field("address", "Address", "ipv4", placeholder="198.51.100.100"),
                Field("mask", "Mask", "ipv4", placeholder="255.255.255.255"),
                Field("protocol", "Only", "choice", choices=("tcp", "udp"), optional=True),
                Field("port", "Port", "int", minimum=0, maximum=65535, optional=True),
                Field("advertise", "Advertise it", "flag", choices=("advertise enable",)),
            ),
            help="Spread only the traffic for this address. A service with a virtual "
            "address cannot spread by destination or use an access list.",
        ),
        Setting(
            key="load_balance",
            label="Spread by",
            line=(
                "load-balance method {method}[ {range_protocol} range {low} {high}]"
                "[ buckets {buckets}][ mask-position {mask}]"
            ),
            group="Spreading",
            fields=(
                Field("method", "Method", "choice", choices=METHODS),
                Field(
                    "range_protocol",
                    "Only ports of",
                    "choice",
                    choices=("tcp", "udp"),
                    optional=True,
                ),
                Field("low", "From port", "int", minimum=1, maximum=65535, optional=True),
                Field("high", "To port", "int", minimum=1, maximum=65535, optional=True),
                Field("buckets", "Buckets", "int", minimum=1, optional=True),
                Field("mask", "Mask position", "int", minimum=0, optional=True),
            ),
            help="Which address of the traffic picks the node.",
        ),
        Setting(
            key="failaction",
            label="When a node fails",
            line="failaction {mode}",
            group="Spreading",
            fields=(Field("mode", "Then", "choice", choices=FAILACTIONS),),
        ),
        Setting(
            key="peer",
            label="Peer service",
            line="peer local service {peer}",
            group="Spreading",
            fields=(_name("peer", "Service", "web-return"),),
            help="The service for the traffic coming back, so both ways go to one node.",
        ),
        Setting(
            key="nat",
            label="Rewrite the destination",
            line="nat destination",
            group="Spreading",
            help="Send traffic to the node's own address instead of the virtual address.",
        ),
        Setting(
            key="access_list",
            label="Only this traffic",
            line="access-list {acl}",
            group="Traffic",
            fields=(_name("acl", "ACL", "web-acl"),),
            help="Spread only the traffic an ACL permits. Not with a virtual address.",
        ),
        Setting(
            key="exclude",
            label="Leave out this traffic",
            line="exclude access-list {acl}",
            group="Traffic",
            fields=(_name("acl", "ACL", "mgmt-acl"),),
            help="Route the traffic an ACL permits as usual.",
        ),
        Setting(
            key="admin_up",
            label="Turn on",
            line="no shutdown",
            group="State",
            removable=False,
            help="Start spreading traffic.",
        ),
        Setting(
            key="admin_down",
            label="Turn off",
            line="shutdown",
            group="State",
            removable=False,
            help="Stop spreading: traffic is routed as usual.",
            warning="Traffic this service spread is routed by the routing table again.",
        ),
    ),
)

_COUNTERS = Scope(
    key="counters",
    label="Counters",
    ident=(_name("name", "Service", "web"),),
    enter=(),
    help="What each node of a service got.",
    settings=(
        Setting(
            key="statistics",
            label="Count the traffic",
            line="itd statistics {name}",
            no_line="no itd statistics {name}",
            ident=("name",),
            group="Counters",
            config=False,
            help="Count what each bucket and node gets; Remove stops counting.",
        ),
        Setting(
            key="clear",
            label="Clear the counters",
            line="clear itd statistics {name}",
            ident=("name",),
            group="Counters",
            config=False,
            removable=False,
        ),
    ),
)


def _probe_values(lines: list[str]) -> dict[str, dict[str, str]]:
    """The probe line among ``lines`` as its setting's field values."""
    for line in lines:
        words = line.split()
        if not words or words[0] != "probe" or len(words) < 2:
            continue
        found: dict[str, str] = {}
        rest = words[2:]
        if words[1] in ("tcp", "udp") and len(rest) >= 2 and rest[0] == "port":
            found["port"], rest = rest[1], rest[2:]
        elif words[1] == "dns" and len(rest) >= 2 and rest[0] == "host":
            found["host"], rest = rest[1], rest[2:]
        names = {"frequency": "frequency", "timeout": "timeout"}
        names |= {"retry-down-count": "down", "retry-up-count": "up"}
        for key, value in zip(rest[::2], rest[1::2], strict=False):
            if key in names:
                found[names[key]] = value
        return {f"probe_{words[1]}": found}
    return {}


def _value_of(lines: list[str], prefix: str) -> str:
    return next((line[len(prefix) :] for line in lines if line.startswith(prefix)), "")


@dataclass(frozen=True)
class ItdConfig:
    """The device groups (name -> lines, node address -> its lines) and services (name ->
    lines) of the running configuration."""

    groups: dict[str, list[str]]
    nodes: dict[str, dict[str, list[str]]]
    services: dict[str, list[str]]


def parse_itd_config(config: str) -> ItdConfig:
    """The ``itd device-group`` and ``itd`` blocks of ``show running-config``."""
    tree = parse_vxlan_config(config)
    groups: dict[str, list[str]] = {}
    nodes: dict[str, dict[str, list[str]]] = {}
    services: dict[str, list[str]] = {}
    for line in tree.children():
        words = line.split()
        if len(words) == 3 and words[:2] == ["itd", "device-group"]:
            inner = tree.children(line)
            groups[words[2]] = [i for i in inner if not i.startswith("node ")]
            nodes[words[2]] = {
                i.split()[-1]: tree.children(line, i) for i in inner if i.startswith("node ")
            }
        elif len(words) == 2 and words[0] == "itd" and words[1] != "statistics":
            services[words[1]] = tree.children(line)
    return ItdConfig(groups, nodes, services)


def _service_values(lines: list[str]) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    if group := _value_of(lines, "device-group "):
        values["device_group"] = {"group": group}
    if method := _value_of(lines, "load-balance method "):
        words = method.split()
        values["load_balance"] = {"method": " ".join(words[:2])}
    if mode := _value_of(lines, "failaction "):
        values["failaction"] = {"mode": mode}
    if peer := _value_of(lines, "peer local service "):
        values["peer"] = {"peer": peer}
    if acl := _value_of(lines, "access-list "):
        values["access_list"] = {"acl": acl}
    if acl := _value_of(lines, "exclude access-list "):
        values["exclude"] = {"acl": acl}
    if vip := _value_of(lines, "virtual ip "):
        words = vip.split()
        values["vip"] = {"address": words[0], "mask": words[1] if len(words) > 1 else ""}
        if len(words) > 3 and words[2] in ("tcp", "udp"):
            values["vip"] |= {"protocol": words[2], "port": words[3]}
        if "advertise" in words:
            values["vip"]["advertise"] = "advertise enable"
    if "nat destination" in lines:
        values["nat"] = {"on": "yes"}
    return values


def _node_values(lines: list[str]) -> dict[str, dict[str, str]]:
    values = _probe_values(lines)
    if weight := _value_of(lines, "weight "):
        values["weight"] = {"weight": weight}
    if standby := _value_of(lines, "standby ip "):
        values["standby"] = {"standby": standby}
    if "mode hot-standby" in lines:
        values["hot_standby"] = {"on": "yes"}
    return values


def parse_itd(
    body: Any, config: str | None, statistics: dict[str, Any] | None = None
) -> ProtocolView:
    """The page from ``show itd``, the configuration text (None when the role may not read
    it) and each service's statistics."""
    parsed = parse_itd_config(config or "")
    summaries = {
        text(row.get("service_name")): row
        for row in table_rows(body or {}, "TABLE_summary", "ROW_summary")
        if row.get("service_name")
    }
    node_rows: list[tuple[str, ...]] = []
    for name, row in summaries.items():
        for vip in table_rows(row, "TABLE_vip", "ROW_vip"):
            for node in table_rows(vip, "TABLE_vip_node", "ROW_vip_node"):
                words = text(node.get("vip_node")).split()
                node_rows.append(
                    (
                        name,
                        words[-1] if words else "",
                        text(node.get("vip_config")),
                        text(node.get("vip_weight")),
                        text(node.get("vip_status")),
                        text(node.get("vip_node_probe")),
                    )
                )
    groups = [
        Instance(
            "group",
            {"name": name},
            name,
            (
                ("Probe", next((x for x in lines if x.startswith("probe ")), "none")),
                ("Nodes", ", ".join(parsed.nodes.get(name, {})) or "none"),
            ),
            _probe_values(lines),
        )
        for name, lines in parsed.groups.items()
    ]
    nodes = [
        Instance(
            "node",
            {"group": group, "address": address},
            f"{address} in {group}",
            tuple(("Line", line) for line in lines) or (("Settings", "none"),),
            _node_values(lines),
        )
        for group, found in parsed.nodes.items()
        for address, lines in found.items()
    ]
    names = list(dict.fromkeys([*parsed.services, *summaries]))
    services = []
    for name in names:
        lines = parsed.services.get(name, [])
        row = summaries.get(name, {})
        state = text(row.get("state")) or ("off" if "shutdown" in lines else "-")
        facts = (
            ("State", state + (f" ({text(row.get('reason'))})" if row.get("reason") else "")),
            ("Device group", _value_of(lines, "device-group ") or "-"),
            ("Ingress", ", ".join(x.split()[-1] for x in lines if x.startswith("ingress "))),
            ("Virtual address", _value_of(lines, "virtual ip ") or "none"),
            ("Spread by", text(row.get("lb_scheme")) or _value_of(lines, "load-balance ")),
            ("Buckets", text(row.get("buckets")) or "-"),
        )
        services.append(Instance("service", {"name": name}, name, facts, _service_values(lines)))
    counting = statistics or {}
    counters = [
        Instance(
            "counters",
            {"name": name},
            name,
            (("Counting", "yes" if name in counting else "no"),),
            {"statistics": {"on": "yes"}} if name in counting else {},
        )
        for name in names
    ]
    bucket_rows: list[tuple[str, ...]] = []
    for name, stat in counting.items():
        for row in table_rows(stat or {}, "TABLE_nice", "ROW_nice"):
            for node in table_rows(row, "TABLE_node", "ROW_node"):
                for bucket in table_rows(node, "TABLE_bucket", "ROW_bucket"):
                    bucket_rows.append(
                        (
                            name,
                            text(bucket.get("node")),
                            text(bucket.get("bucket_acl")),
                            text(bucket.get("acl_pkt")) or "0",
                            text(bucket.get("bucket_per")),
                        )
                    )
    tables = (
        Table(
            "Nodes in service",
            ("Service", "Node", "Config", "Weight", "Status", "Probe"),
            tuple(node_rows),
            empty="No service is spreading traffic yet.",
        ),
        Table(
            "Counters",
            ("Service", "Node", "Bucket", "Packets", "Share"),
            tuple(bucket_rows),
            empty="No service counts its traffic. Turn on Count the traffic below.",
            note="Read when the page loads.",
        ),
    )
    notes = ()
    if config is None:
        notes = (
            "The switch did not show ITD's settings to NXray's account: only the state is shown.",
        )
    return ProtocolView((*groups, *nodes, *services, *counters), tables, notes)


ITD = Protocol(
    key="itd",
    name="ITD",
    summary="Spread traffic over a group of servers or appliances",
    features=FEATURES,
    commands=COMMANDS,
    parse=lambda bodies: parse_itd(bodies[0] if bodies else None, None),
    scopes=(_GROUP, _NODE, _SERVICE, _COUNTERS),
    about=(
        "Make a device group with its nodes and a health probe, then a service that names "
        "the group, the ingress interface and how traffic is spread, and turn it on."
    ),
)


@dataclass(frozen=True)
class ItdPage:
    """Everything the ITD page shows."""

    protocol: Protocol
    view: ProtocolView
    interfaces: tuple[str, ...]  # VLAN interfaces, routed ports and port-channels
    services: tuple[str, ...] = ()
    problem: str = ""
    missing: tuple[str, ...] = ()  # pbr and itd, those still off


def load_itd_page(client: NxapiClient) -> ItdPage:
    """One request for the features and interfaces; while pbr and itd are on, ``show
    itd``, the configuration text and each service's counters."""
    feature, brief, _vrf, vrf_members = client.show(*PAGE_COMMANDS)
    interfaces = layer3_interfaces(brief, parse_vrf_members(vrf_members))
    states = feature_states(feature)
    missing = tuple(name for name in FEATURES if not states.get(name, False))
    if missing:
        return ItdPage(ITD, ProtocolView(), interfaces, missing=missing)
    problem = ""
    try:
        (body,) = client.show(*COMMANDS)
    except NxapiCommandError as exc:
        body, problem = None, f"The switch did not report ITD's state: {exc}"
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = None
    names = [
        text(r.get("service_name")) for r in table_rows(body or {}, "TABLE_summary", "ROW_summary")
    ]
    statistics: dict[str, Any] = {}
    for name in dict.fromkeys(n for n in names if n):
        try:
            (stat,) = client.show(f"show itd {name} statistics")
        except NxapiCommandError:
            continue  # not counting
        if stat:
            statistics[name] = stat
    view = parse_itd(body, config, statistics)
    services = tuple(i.ident["name"] for i in view.of("service"))
    return ItdPage(ITD, view, interfaces, services, problem)


def check_itd_place(page: ItdPage, ident: dict[str, str]) -> None:
    """Nothing to refuse: a new device group, node or service name makes one."""


def build_itd_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the ITD page."""
    return build_change(ITD, scope, setting, action, ident, values)
