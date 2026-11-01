"""Multicast routing: PIM, PIM6, IGMP and MSDP, and BFD, the fast link check.

Multicast sends one stream (a video feed, a market data feed) to many
receivers at once. Receivers ask for a *group* address with IGMP; routers
pass those requests towards the sender with PIM (PIM6 for IPv6), which needs
a *rendezvous point* (RP) to bring senders and receivers together, except in
the source-specific (SSM) range. MSDP tells RPs in different networks about
each other's senders. BFD is here too: a quick heartbeat between neighbors
that PIM, BGP, OSPF and the others can use to notice a dead link in under a
second.

Read from the switch, in one request per page:

- PIM: ``show ip pim interface vrf all``, ``show ip pim neighbor vrf all``,
  ``show ip pim rp vrf all``, ``show ip pim group-range vrf all`` and
  ``show ip mroute vrf all``.
- PIM6: ``show ipv6 pim interface vrf all`` and ``show ipv6 pim rp vrf all``.
- IGMP: ``show ip igmp interface vrf all``.
- MSDP: ``show ip msdp peer vrf all`` and ``show ip msdp summary vrf all``.
- BFD: ``show bfd neighbors``.

What can be changed: per VRF, the rendezvous points (static, Anycast-RP,
BSR and Auto-RP candidates), the SSM range, shared-tree-only groups, the
register source, rate limit and filters, BSR and Auto-RP message handling
and filters, neighbor logging and BFD for PIM; per interface, PIM on or off,
DR priority and delay, hello interval and authentication, domain border,
passive mode, neighbor and join/prune filters and BFD. The same for PIM6
where the switch supports it (no Bidir, BSR, Auto-RP, BFD or hello
authentication for IPv6 on a Nexus 9000). IGMP per interface: version, query
timers and counts, robustness, static groups by route-map, report and access
filters, immediate leave. MSDP per VRF: peers, originator, reconnect and SA
intervals, group limits; per peer: connect source, description, password,
keepalive, mesh group, SA limit and filters, shut down. BFD: the switch-wide
timers, and per interface timers, echo and SHA-1 authentication.

Tried on cisco-25gb (NX-OS 9.3(16)) as NXray's restricted account:
``ip pim rp-address 192.0.2.10 group-list 224.0.0.0/4`` and its ``no`` form,
``ip pim ssm range 232.0.0.0/8`` and its ``no`` form, ``ipv6 pim rp-address
2001:db8:1::10 group-list ff00::/8`` and its ``no`` form; on Ethernet1/54
``ip pim sparse-mode``, ``ip pim dr-priority 10``, ``ip pim hello-interval
30000``, ``ipv6 pim sparse-mode``, ``ip igmp version 3`` and the ``no``
forms of all five; ``ip msdp originator-id``, ``ip msdp peer ...
connect-source``, ``ip msdp description`` and ``no ip msdp peer``, ``no ip
msdp originator-id``; ``bfd interval 250 min_rx 250 multiplier 3`` and
``bfd slow-timer 2000`` with their ``no`` forms, and on the interface ``bfd
interval 300 min_rx 300 multiplier 3`` and ``no bfd echo``. Every other line
follows Cisco's NX-OS 9.3 Multicast Routing guide, Interfaces guide and
command reference. Nothing was plugged in, so rows with PIM neighbors, real
multicast routes, an established MSDP peer or a BFD session were never seen
live; they are read by the NX-API field names Cisco documents for them.
"""

from __future__ import annotations

import re
from typing import Any

from app.protocols import (
    Field,
    Instance,
    Protocol,
    ProtocolView,
    Scope,
    Setting,
    Table,
    interface_field,
    source_field,
    table_rows,
    text,
    vrf_field,
)
from app.routing import long_name

# ---- shared fields -------------------------------------------------------------

_ROUTE_MAP_HINT = "The name of a route-map made on the Routing policy page"
_PREFIX_LIST_HINT = "The name of a prefix-list made on the Routing policy page"
_DR_PRIORITY_MAX = 4294967295
_HELLO_MS_MIN = 1000
_HELLO_MS_MAX = 18724286


def _int(name: str, label: str, low: int, high: int, **kw: Any) -> Field:
    return Field(name, label, "int", minimum=low, maximum=high, **kw)


def _route_map(name: str = "route_map", label: str = "Route-map") -> Field:
    return Field(name, label, "name", hint=_ROUTE_MAP_HINT)


def _prefix_list(name: str = "prefix_list", label: str = "Prefix-list") -> Field:
    return Field(name, label, "name", hint=_PREFIX_LIST_HINT)


def _source(label: str = "Source interface") -> Field:
    return source_field("source", label)


def _flag(name: str, word: str, label: str, hint: str = "") -> Field:
    return Field(name, label, "flag", choices=(word,), hint=hint)


def _rp_flags(bidir: bool) -> tuple[Field, ...]:
    override = _flag(
        "override",
        "override",
        "Override",
        "Use this RP even when BSR or Auto-RP learns another for the same groups",
    )
    if not bidir:
        return (override,)
    return (
        _flag("bidir", "bidir", "Bidirectional", "Treat these groups as PIM Bidir groups"),
        override,
    )


def _listen_forward() -> Field:
    return Field(
        "mode",
        "Messages",
        "choice",
        choices=("listen", "forward", "listen forward"),
        hint="listen: learn RPs from them; forward: pass them on to other routers",
    )


# ---- PIM and PIM6 settings -------------------------------------------------------


def _rp_settings(ip: str, address_kind: str, group_kind: str, bidir: bool) -> tuple[Setting, ...]:
    """The static RP lines, the same for PIM and PIM6 bar the address family."""
    address = Field("address", "RP address", address_kind, hint="The rendezvous point's address")
    flags = _rp_flags(bidir)
    flag_part = " ".join(f"[{{{f.name}}}]" for f in flags)
    group_hint = "The groups this RP serves; leave empty for all multicast groups"
    return (
        Setting(
            "rp_group",
            "Rendezvous point",
            f"{ip} pim rp-address {{address}} [group-list {{group}}] {flag_part}",
            (
                address,
                Field("group", "Groups", group_kind, optional=True, hint=group_hint),
                *flags,
            ),
            group="Rendezvous points",
            help="A fixed rendezvous point: every router in the network must name the same one.",
        ),
        Setting(
            "rp_route_map",
            "Rendezvous point (groups from a route-map)",
            f"{ip} pim rp-address {{address}} route-map {{route_map}} {flag_part}",
            (address, _route_map(), *flags),
            group="Rendezvous points",
            help="The groups are the ones the route-map's match multicast lines name.",
        ),
        Setting(
            "rp_prefix_list",
            "Rendezvous point (groups from a prefix-list)",
            f"{ip} pim rp-address {{address}} prefix-list {{prefix_list}} {flag_part}",
            (address, _prefix_list(), *flags),
            group="Rendezvous points",
        ),
        Setting(
            "anycast_rp",
            "Anycast-RP member",
            f"{ip} pim anycast-rp {{anycast}} {{member}}",
            (
                Field("anycast", "Shared RP address", address_kind),
                Field("member", "Member RP's own address", address_kind),
            ),
            group="Rendezvous points",
            help="Several RPs share one address; add one line per member, this switch included.",
        ),
    )


def _register_settings(ip: str) -> tuple[Setting, ...]:
    return (
        Setting(
            "register_rate_limit",
            "Register rate limit",
            f"{ip} pim register-rate-limit {{rate}}",
            (_int("rate", "Packets per second", 1, 65535),),
            group="Senders",
            help="At most this many register packets a second to the RP (default: no limit).",
        ),
        Setting(
            "register_policy",
            "Register filter",
            f"{ip} pim register-policy {{route_map}}",
            (_route_map(),),
            group="Senders",
            help="On the RP: accept register messages only for the senders and groups it permits.",
        ),
        Setting(
            "spt_infinity",
            "Shared tree only",
            f"{ip} pim spt-threshold infinity group-list {{route_map}}",
            (_route_map(),),
            group="Senders",
            help="For these groups, stay on the RP's shared tree and never switch to the sender's "
            "own path.",
        ),
        Setting(
            "log_neighbor_changes",
            "Log neighbor changes",
            f"{ip} pim log-neighbor-changes",
            group="Logging",
            help="Write a log line when a PIM neighbor comes or goes.",
        ),
    )


_PIM_VRF_SETTINGS: tuple[Setting, ...] = (
    *_rp_settings("ip", "ipv4", "group4", bidir=True),
    Setting(
        "ssm_range",
        "SSM range",
        "ip pim ssm range {group}",
        (Field("group", "Groups", "group4", placeholder="232.0.0.0/8"),),
        group="Source-specific multicast",
        help="Groups that need no RP: receivers name the sender too (default 232.0.0.0/8).",
    ),
    Setting(
        "ssm_route_map",
        "SSM range from a route-map",
        "ip pim ssm route-map {route_map}",
        (_route_map(),),
        group="Source-specific multicast",
    ),
    Setting(
        "ssm_prefix_list",
        "SSM range from a prefix-list",
        "ip pim ssm prefix-list {prefix_list}",
        (_prefix_list(),),
        group="Source-specific multicast",
    ),
    Setting(
        "ssm_none",
        "No SSM range",
        "ip pim ssm range none",
        group="Source-specific multicast",
        help="Removing this puts the default range 232.0.0.0/8 back.",
        warning="Every group then needs a rendezvous point, 232.0.0.0/8 included.",
    ),
    Setting(
        "bsr_listen",
        "BSR messages",
        "ip pim bsr {mode}",
        (_listen_forward(),),
        group="Bootstrap router (BSR)",
        help="BSR spreads the list of RPs automatically. Do not use it together with Auto-RP.",
    ),
    Setting(
        "bsr_candidate",
        "Candidate bootstrap router",
        "ip pim bsr bsr-candidate {source} [hash-len {hash_len}] [priority {priority}]",
        (
            _source(),
            _int("hash_len", "Hash length", 0, 32, optional=True, hint="Default 30"),
            _int("priority", "Priority", 0, 255, optional=True, hint="Higher wins; default 64"),
        ),
        no_line="no ip pim bsr bsr-candidate {source}",
        group="Bootstrap router (BSR)",
    ),
    Setting(
        "bsr_rp_candidate",
        "Candidate RP (BSR)",
        "ip pim bsr rp-candidate {source} group-list {group} [priority {priority}] "
        "[interval {interval}]",
        (
            _source(),
            Field("group", "Groups", "group4", placeholder="224.0.0.0/4"),
            _int("priority", "Priority", 0, 255, optional=True, hint="Lower wins; default 192"),
            _int("interval", "Interval (seconds)", 1, 65535, optional=True, hint="Default 60"),
        ),
        no_line="no ip pim bsr rp-candidate {source} group-list {group}",
        group="Bootstrap router (BSR)",
        help="Offer this switch as RP for these groups through BSR.",
    ),
    Setting(
        "bsr_policy",
        "BSR message filter",
        "ip pim bsr bsr-policy {route_map}",
        (_route_map(),),
        group="Bootstrap router (BSR)",
        help="Accept bootstrap messages only from the routers the route-map permits.",
    ),
    Setting(
        "bsr_rp_candidate_policy",
        "BSR candidate RP filter",
        "ip pim bsr rp-candidate-policy {route_map}",
        (_route_map(),),
        group="Bootstrap router (BSR)",
    ),
    Setting(
        "auto_rp_listen",
        "Auto-RP messages",
        "ip pim auto-rp {mode}",
        (_listen_forward(),),
        group="Auto-RP",
        help="Cisco's older way to spread the list of RPs. Do not use it together with BSR.",
    ),
    Setting(
        "auto_rp_mapping_agent",
        "Auto-RP mapping agent",
        "ip pim auto-rp mapping-agent {source} [scope {scope}]",
        (_source(), _int("scope", "Hops (TTL)", 1, 255, optional=True, hint="Default 32")),
        no_line="no ip pim auto-rp mapping-agent {source}",
        group="Auto-RP",
    ),
    Setting(
        "auto_rp_candidate",
        "Candidate RP (Auto-RP)",
        "ip pim auto-rp rp-candidate {source} group-list {group} [scope {scope}] "
        "[interval {interval}]",
        (
            _source(),
            Field("group", "Groups", "group4", placeholder="224.0.0.0/4"),
            _int("scope", "Hops (TTL)", 1, 255, optional=True, hint="Default 32"),
            _int("interval", "Interval (seconds)", 1, 65535, optional=True, hint="Default 60"),
        ),
        no_line="no ip pim auto-rp rp-candidate {source} group-list {group}",
        group="Auto-RP",
    ),
    Setting(
        "auto_rp_candidate_policy",
        "Auto-RP candidate RP filter",
        "ip pim auto-rp rp-candidate-policy {route_map}",
        (_route_map(),),
        group="Auto-RP",
    ),
    Setting(
        "auto_rp_mapping_agent_policy",
        "Auto-RP mapping agent filter",
        "ip pim auto-rp mapping-agent-policy {route_map}",
        (_route_map(),),
        group="Auto-RP",
    ),
    Setting(
        "register_source",
        "Register source",
        "ip pim register-source {source}",
        (_source(),),
        group="Senders",
        help="The address register messages to the RP come from.",
    ),
    *_register_settings("ip"),
    Setting(
        "bfd",
        "BFD on every PIM interface",
        "ip pim bfd",
        group="BFD",
        help="Notice a dead PIM neighbor in under a second. Needs the BFD feature.",
    ),
)


def _interface_settings(ip: str, ipv4: bool) -> tuple[Setting, ...]:
    neighbor_policy = (
        Setting(
            "neighbor_policy",
            "Neighbor filter",
            "ip pim neighbor-policy prefix-list {prefix_list}",
            (_prefix_list(),),
            group="Filters",
            help="Become PIM neighbors only with the routers the prefix-list permits.",
        )
        if ipv4
        else Setting(
            "neighbor_policy",
            "Neighbor filter",
            "ipv6 pim neighbor-policy {route_map}",
            (_route_map(),),
            group="Filters",
            help="Become PIM6 neighbors only with the routers the route-map permits.",
        )
    )
    settings: list[Setting] = [
        Setting(
            "sparse_mode",
            "PIM on this interface",
            f"{ip} pim sparse-mode",
            group="PIM",
            help="Route multicast through this interface (sparse mode, the only mode NX-OS has).",
            warning="Turning it off stops multicast routing through this interface.",
        ),
        Setting(
            "dr_priority",
            "DR priority",
            f"{ip} pim dr-priority {{priority}}",
            (_int("priority", "Priority", 1, _DR_PRIORITY_MAX, hint="Higher wins; default 1"),),
            group="PIM",
            help="Which router on this network sends for it (the designated router).",
        ),
    ]
    if ipv4:
        settings.append(
            Setting(
                "dr_delay",
                "DR election delay",
                "ip pim dr-delay {seconds}",
                (_int("seconds", "Seconds", 3, 65535),),
                group="PIM",
                help="After start-up or a change, wait this long before taking part in the DR "
                "election.",
            )
        )
    settings += [
        Setting(
            "hello_interval",
            "Hello interval",
            f"{ip} pim hello-interval {{milliseconds}}",
            (
                _int(
                    "milliseconds",
                    "Milliseconds",
                    _HELLO_MS_MIN,
                    _HELLO_MS_MAX,
                    hint="Default 30000 (30 seconds)",
                ),
            ),
            group="PIM",
        ),
    ]
    if ipv4:
        settings.append(
            Setting(
                "hello_authentication",
                "Hello authentication",
                "ip pim hello-authentication ah-md5 {key}",
                (Field("key", "Key", "secret", hint="Up to 16 characters"),),
                group="PIM",
                help="Neighbors must use the same key (MD5).",
                warning="A neighbor without the same key stops being a PIM neighbor.",
            )
        )
    settings += [
        Setting(
            "border",
            "Domain border",
            f"{ip} pim border",
            group="PIM",
            help="Send and accept no BSR or Auto-RP messages on this interface.",
        ),
        Setting(
            "passive",
            "Passive",
            f"{ip} pim passive",
            group="PIM",
            help="Route multicast here but send and accept no PIM messages.",
        ),
        neighbor_policy,
        Setting(
            "jp_policy",
            "Join/prune filter",
            f"{ip} pim jp-policy {{route_map}} [{{direction}}]",
            (
                _route_map(),
                Field(
                    "direction",
                    "Direction",
                    "choice",
                    choices=("in", "out"),
                    optional=True,
                    hint="Empty for both",
                ),
            ),
            group="Filters",
            help="Accept or send join and prune messages only for what the route-map permits.",
        ),
    ]
    if ipv4:
        settings.append(
            Setting(
                "bfd_instance",
                "BFD for PIM here",
                "ip pim bfd-instance [{disable}]",
                (_flag("disable", "disable", "Turn it off here instead"),),
                group="BFD",
                help="Overrides the VRF's BFD for PIM on this interface. Needs the BFD feature.",
            )
        )
    return tuple(settings)


_PIM6_VRF_SETTINGS: tuple[Setting, ...] = (
    *_rp_settings("ipv6", "ipv6", "group6", bidir=False),
    *_register_settings("ipv6"),
)


def _vrf_scope(settings: tuple[Setting, ...], name: str) -> Scope:
    return Scope(
        "vrf",
        "Global settings",
        (vrf_field(),),
        ("[vrf context {vrf}]",),
        settings,
        help=f"{name} settings for the whole switch, or for one VRF.",
    )


def _interface_scope(settings: tuple[Setting, ...], name: str) -> Scope:
    return Scope(
        "interface",
        "Interface",
        (interface_field(),),
        ("interface {interface}",),
        settings,
        help=f"{name} on one interface: turn it on there first.",
    )


# ---- reading helpers -------------------------------------------------------------


def _body(bodies: list[dict[str, Any]], index: int) -> dict[str, Any]:
    """Body ``index``, or {} when the command printed nothing."""
    if index < len(bodies) and isinstance(bodies[index], dict):
        return bodies[index]
    return {}


def _on(value: Any) -> bool:
    return text(value).lower() in ("true", "yes", "enabled", "on")


def _shown(value: Any) -> str:
    """An address from the output, or "" for the switch's "nobody" values."""
    found = text(value)
    if found in ("0.0.0.0", "0::", "::", "-", "*"):
        return ""
    return found


def _policy(value: Any) -> str:
    """A policy name, or "" for the switch's ways of saying there is none."""
    found = text(value)
    if found.lower() in ("", "none", "none configured", "no", "-"):
        return ""
    return found


def _vrfs(body: dict[str, Any]) -> list[dict[str, Any]]:
    return table_rows(body, "TABLE_vrf", "ROW_vrf")


def _vrf_name(row: dict[str, Any]) -> str:
    return (
        text(row.get("vrf-name"))
        or text(row.get("out-context"))
        or text(row.get("vrf"))
        or text(row.get("out-vrf"))
        or "default"
    )


def _address_summary(value: Any) -> str:
    """ "IP address: 192.0.2.1, IP subnet: 192.0.2.0/24" -> "192.0.2.1/24"."""
    found = text(value)
    match = re.search(r"IP address: ([^,\s]+), IP subnet: \S+/(\d+)", found)
    return f"{match.group(1)}/{match.group(2)}" if match else found


def _duration(value: Any) -> str:
    """ "P2DT13H19M57S" (ISO 8601, as MSDP gives it) -> "2d 13h 19m 57s"."""
    found = text(value)
    match = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", found)
    if not match or not found.strip("PT"):
        return found
    parts = [f"{n}{unit}" for n, unit in zip(match.groups(), "dhms", strict=True) if n]
    return " ".join(parts) or "0s"


def _incoming(value: Any) -> str:
    """A multicast route's incoming interface, or "" for "Null" (none yet)."""
    found = text(value)
    return "" if found in ("", "Null") else long_name(found)


def _ordered(names: list[str]) -> list[str]:
    """VRF names without repeats, default first."""
    seen = ["default"]
    for name in names:
        if name and name not in seen:
            seen.append(name)
    return seen


# ---- PIM and PIM6 parsing ----------------------------------------------------------


def _pim_interfaces(
    body: dict[str, Any], ipv4: bool
) -> tuple[list[Instance], list[tuple[str, ...]], list[str]]:
    instances: list[Instance] = []
    rows: list[tuple[str, ...]] = []
    vrfs: list[str] = []
    for vrf in _vrfs(body):
        vrf_name = _vrf_name(vrf)
        vrfs.append(vrf_name)
        for row in table_rows(vrf, "TABLE_iod", "ROW_iod"):
            name = long_name(text(row.get("if-name")))
            if not name:
                continue
            hello_s = text(row.get("hello-interval-sec"))
            values: dict[str, dict[str, str]] = {"sparse_mode": {}}
            priority = text(row.get("if-conf-dr-priority"))
            if priority:
                values["dr_priority"] = {"priority": priority}
            if hello_s.isdigit():
                values["hello_interval"] = {"milliseconds": str(int(hello_s) * 1000)}
            if _on(row.get("is-border")):
                values["border"] = {}
            if _on(row.get("is-passive")):
                values["passive"] = {}
            neighbor = _policy(row.get("nbr-policy-name"))
            if neighbor:
                key = "prefix_list" if ipv4 else "route_map"
                values["neighbor_policy"] = {key: neighbor}
            jp_in = _policy(row.get("jp-in-policy-name"))
            jp_out = _policy(row.get("jp-out-policy-name"))
            if jp_in and jp_in == jp_out:
                values["jp_policy"] = {"route_map": jp_in, "direction": ""}
            elif jp_in or jp_out:
                values["jp_policy"] = {
                    "route_map": jp_in or jp_out,
                    "direction": "in" if jp_in else "out",
                }
            if ipv4 and _on(row.get("pim-bfd-enabled")):
                values["bfd_instance"] = {"disable": ""}
            status = text(row.get("if-status"))
            address = _address_summary(row.get("if-addr-summary"))
            dr = _shown(row.get("pim-dr-address"))
            neighbors = text(row.get("nbr-cnt"))
            facts = [("VRF", vrf_name), ("State", status)]
            if address:
                facts.append(("Address", address))
            facts += [("Designated router", dr or "none yet"), ("Neighbors", neighbors)]
            if _on(row.get("isauth-config")):
                facts.append(("Hello authentication", "on"))
            instances.append(Instance("interface", {"interface": name}, name, tuple(facts), values))
            row_cells = [name, vrf_name, status]
            if ipv4:
                row_cells.append(address)
            row_cells += [
                dr,
                text(row.get("dr-priority")) or priority,
                neighbors,
                hello_s,
                "yes" if _on(row.get("is-border")) else "no",
                "yes" if _on(row.get("is-passive")) else "no",
            ]
            rows.append(tuple(row_cells))
    return instances, rows, vrfs


def _rps(
    body: dict[str, Any],
) -> tuple[list[tuple[str, ...]], dict[str, dict[str, Any]], list[str]]:
    """RP table rows, per-VRF facts and values, and the VRF names seen."""
    rows: list[tuple[str, ...]] = []
    per_vrf: dict[str, dict[str, Any]] = {}
    vrfs: list[str] = []
    for vrf in _vrfs(body):
        vrf_name = _vrf_name(vrf)
        vrfs.append(vrf_name)
        found: dict[str, Any] = {"facts": [], "values": {}}
        for label, key in (("BSR", "is-bsr-enabled"), ("Auto-RP", "is-autorp-enabled")):
            if text(vrf.get(key)):
                found["facts"].append((label, text(vrf.get(key))))
        for key, setting in (
            ("bsr-policy-name", "bsr_policy"),
            ("rp-cand-policy-name", "bsr_rp_candidate_policy"),
            ("rp-announce-policy-name", "auto_rp_candidate_policy"),
            ("rp-discovery-policy-name", "auto_rp_mapping_agent_policy"),
        ):
            name = _policy(vrf.get(key))
            if name:
                found["values"][setting] = {"route_map": name}
        statics = 0
        for rp in table_rows(vrf, "TABLE_rp", "ROW_rp"):
            address = text(rp.get("rp-addr"))
            groups: list[str] = []
            bidir = False
            for grange in table_rows(rp, "TABLE_grange", "ROW_grange"):
                group = f"{text(grange.get('grange-grp'))}/{text(grange.get('grange-masklen'))}"
                if _on(grange.get("grange-is-deny")):
                    group += " (denied)"
                bidir = bidir or _on(grange.get("is-bidir-grp"))
                groups.append(group)
            if _on(rp.get("is_static_source")):
                learned = "set here"
                statics += 1
                if "rp_group" not in found["values"]:
                    first = groups[0] if groups and "(" not in groups[0] else ""
                    found["values"]["rp_group"] = {
                        "address": address,
                        "group": first,
                        "bidir": "bidir" if bidir else "",
                        "override": "",
                    }
            elif _on(rp.get("is_bsr_source")):
                learned = "BSR"
            elif _on(rp.get("is_autorp_source")):
                learned = "Auto-RP"
            else:
                learned = text(rp.get("rp-source"))
            rows.append(
                (
                    address,
                    ", ".join(groups),
                    vrf_name,
                    learned,
                    text(rp.get("rp-priority")),
                    text(rp.get("rp-uptime")),
                    "yes" if _on(rp.get("is-rp-local")) else "no",
                )
            )
        found["facts"].append(("Static RPs", str(statics)))
        per_vrf[vrf_name] = found
    return rows, per_vrf, vrfs


def _vrf_instances(
    vrfs: list[str], per_vrf: dict[str, dict[str, Any]], extra: dict[str, dict[str, Any]]
) -> list[Instance]:
    instances = []
    for name in _ordered(vrfs):
        found = per_vrf.get(name, {"facts": [], "values": {}})
        values = dict(found["values"])
        facts = list(found["facts"])
        more = extra.get(name, {})
        values.update(more.get("values", {}))
        facts += more.get("facts", [])
        instances.append(Instance("vrf", {"vrf": name}, f"VRF {name}", tuple(facts), values))
    return instances


_PIM_INTERFACE_COLUMNS = (
    "Interface",
    "VRF",
    "State",
    "Address",
    "DR",
    "DR priority",
    "Neighbors",
    "Hello (s)",
    "Border",
    "Passive",
)
_RP_COLUMNS = ("RP", "Groups", "VRF", "Learned from", "Priority", "Up for", "This switch")


def parse_pim(bodies: list[dict[str, Any]]) -> ProtocolView:
    """PIM's page from show ip pim interface / neighbor / rp / group-range and show ip mroute."""
    interfaces, rows, vrfs = _pim_interfaces(_body(bodies, 0), ipv4=True)
    rp_rows, per_vrf, rp_vrfs = _rps(_body(bodies, 2))
    vrfs += rp_vrfs

    # Neighbor rows were never seen live (nothing was plugged in): read by the
    # field names Cisco documents for show ip pim neighbor (if-name, nbr-addr,
    # uptime, expires, dr-priority, bfd-state).
    neighbors: list[tuple[str, ...]] = []
    for vrf in _vrfs(_body(bodies, 1)):
        vrf_name = _vrf_name(vrf)
        vrfs.append(vrf_name)
        for row in table_rows(vrf, "TABLE_neighbor", "ROW_neighbor"):
            neighbors.append(
                (
                    text(row.get("nbr-addr")),
                    long_name(text(row.get("if-name"))),
                    vrf_name,
                    text(row.get("uptime")),
                    text(row.get("expires")),
                    text(row.get("dr-priority")),
                    text(row.get("bfd-state")),
                )
            )

    ranges: list[tuple[str, ...]] = []
    extra: dict[str, dict[str, Any]] = {}
    for vrf in _vrfs(_body(bodies, 3)):
        vrf_name = _vrf_name(vrf)
        vrfs.append(vrf_name)
        ssm: list[str] = []
        for row in table_rows(vrf, "TABLE_group", "ROW_group"):
            group = text(row.get("grp-addr"))
            mode = text(row.get("mode"))
            if mode.upper() == "SSM":
                ssm.append(group)
            ranges.append(
                (
                    group,
                    mode,
                    _shown(row.get("rp-addr")),
                    vrf_name,
                    text(row.get("origin")),
                    _policy(row.get("action")),
                )
            )
        found = extra.setdefault(vrf_name, {"facts": [], "values": {}})
        found["facts"].append(("SSM range", ", ".join(ssm) or "none"))
        if ssm:
            found["values"]["ssm_range"] = {"group": ssm[0]}

    mroutes: list[tuple[str, ...]] = []
    for vrf in _vrfs(_body(bodies, 4)):
        vrf_name = _vrf_name(vrf)
        vrfs.append(vrf_name)
        for row in table_rows(vrf, "TABLE_one_route", "ROW_one_route"):
            group = text(row.get("group_addrs"))
            if _on(row.get("bidir")):
                group += " (bidir)"
            mroutes.append(
                (
                    text(row.get("source_addrs")),
                    group,
                    vrf_name,
                    _incoming(row.get("route-iif")),
                    _shown(row.get("rpf-nbr")),
                    text(row.get("oif-count")),
                    text(row.get("uptime")),
                )
            )

    return ProtocolView(
        instances=(*_vrf_instances(vrfs, per_vrf, extra), *interfaces),
        tables=(
            Table(
                "PIM interfaces",
                _PIM_INTERFACE_COLUMNS,
                tuple(rows),
                empty="PIM is on on no interface.",
            ),
            Table(
                "PIM neighbors",
                ("Neighbor", "Interface", "VRF", "Up for", "Expires", "DR priority", "BFD"),
                tuple(neighbors),
                empty="No PIM neighbors.",
            ),
            Table("Rendezvous points", _RP_COLUMNS, tuple(rp_rows), empty="No RPs known."),
            Table(
                "Group ranges",
                ("Groups", "Mode", "RP", "VRF", "Set by", "Action"),
                tuple(ranges),
                note="ASM groups need an RP; SSM groups do not.",
            ),
            Table(
                "Multicast routes",
                (
                    "Source",
                    "Group",
                    "VRF",
                    "Comes in on",
                    "RPF neighbor",
                    "Outgoing interfaces",
                    "Up for",
                ),
                tuple(mroutes),
                empty="No multicast routes.",
                note="Source * means any sender (a shared-tree route).",
            ),
        ),
    )


def parse_pim6(bodies: list[dict[str, Any]]) -> ProtocolView:
    """PIM6's page from show ipv6 pim interface / rp."""
    interfaces, rows, vrfs = _pim_interfaces(_body(bodies, 0), ipv4=False)
    rp_rows, per_vrf, rp_vrfs = _rps(_body(bodies, 1))
    # PIM6 has no BSR or Auto-RP settings here: drop what the shared reader found.
    for found in per_vrf.values():
        found["facts"] = [f for f in found["facts"] if f[0] not in ("BSR", "Auto-RP")]
        found["values"] = {k: v for k, v in found["values"].items() if k == "rp_group"}
        if "rp_group" in found["values"]:
            found["values"]["rp_group"] = {
                k: v for k, v in found["values"]["rp_group"].items() if k != "bidir"
            }
    columns = tuple(c for c in _PIM_INTERFACE_COLUMNS if c != "Address")
    return ProtocolView(
        instances=(*_vrf_instances(vrfs + rp_vrfs, per_vrf, {}), *interfaces),
        tables=(
            Table("PIM6 interfaces", columns, tuple(rows), empty="PIM6 is on on no interface."),
            Table("Rendezvous points", _RP_COLUMNS, tuple(rp_rows), empty="No RPs known."),
        ),
    )


# ---- IGMP ------------------------------------------------------------------------

_IGMP_VALUES = (
    ("query_interval", "seconds", "ConfiguredQueryInterval"),
    ("query_max_response_time", "seconds", "ConfiguredMaxResponseTime"),
    ("startup_query_interval", "seconds", "ConfiguredStartupQueryInterval"),
    ("startup_query_count", "count", "StartupQueryCount"),
    ("robustness_variable", "count", "ConfiguredRobustnessVariable"),
    ("querier_timeout", "seconds", "ConfiguredQuerierTimeout"),
    ("last_member_query_response_time", "seconds", "LastMemberMTR"),
    ("last_member_query_count", "count", "LastMemberQueryCount"),
    ("group_timeout", "seconds", "ConfiguredGroupTimeout"),
)


def parse_igmp(bodies: list[dict[str, Any]]) -> ProtocolView:
    """IGMP's page from show ip igmp interface vrf all."""
    instances: list[Instance] = []
    rows: list[tuple[str, ...]] = []
    for vrf in _vrfs(_body(bodies, 0)):
        vrf_name = _vrf_name(vrf)
        for row in table_rows(vrf, "TABLE_if", "ROW_if"):
            name = long_name(text(row.get("if-name")))
            if not name:
                continue
            version = text(row.get("IGMPVersion"))
            values: dict[str, dict[str, str]] = {}
            if version in ("2", "3"):
                values["version"] = {"version": version}
            for key, field_name, source in _IGMP_VALUES:
                found = text(row.get(source))
                if found.isdigit():
                    values[key] = {field_name: found}
            if _on(row.get("ReportingForLinkLocal")):
                values["report_link_local_groups"] = {}
            if _on(row.get("ImmediateLeave")):
                values["immediate_leave"] = {}
            report = _policy(row.get("ReportPolicy"))
            if report:
                values["report_policy"] = {"route_map": report}
            status = text(row.get("if-status"))
            address = _address_summary(row.get("AddressSummary"))
            querier = _shown(row.get("querier"))
            groups = text(row.get("MemembershipCount"))
            facts = (
                ("VRF", vrf_name),
                ("State", status),
                ("Address", address),
                ("Querier", querier or "none yet"),
                ("Version", version),
                ("Groups joined", groups),
            )
            instances.append(Instance("interface", {"interface": name}, name, facts, values))
            rows.append(
                (
                    name,
                    vrf_name,
                    status,
                    address,
                    querier,
                    version,
                    groups,
                    text(row.get("QueryInterval")),
                )
            )
    return ProtocolView(
        instances=tuple(instances),
        tables=(
            Table(
                "IGMP interfaces",
                (
                    "Interface",
                    "VRF",
                    "State",
                    "Address",
                    "Querier",
                    "Version",
                    "Groups",
                    "Query interval (s)",
                ),
                tuple(rows),
                empty="IGMP runs on no interface (it starts with PIM on a routed interface).",
            ),
        ),
    )


# ---- MSDP ------------------------------------------------------------------------


def _msdp_peer_rows(body: dict[str, Any]) -> list[dict[str, Any]]:
    rows = table_rows(body, "TABLE_peer", "ROW_peer")
    for vrf in (*_vrfs(body), *table_rows(body, "TABLE_VRF", "ROW_VRF")):
        rows += table_rows(vrf, "TABLE_peer", "ROW_peer")
    return rows


def parse_msdp(bodies: list[dict[str, Any]]) -> ProtocolView:
    """MSDP's page from show ip msdp peer / summary vrf all."""
    per_vrf: dict[str, dict[str, Any]] = {}
    vrfs: list[str] = []
    for vrf in table_rows(_body(bodies, 1), "TABLE_VRF", "ROW_VRF"):
        name = _vrf_name(vrf)
        vrfs.append(name)
        facts = [
            ("Local AS", text(vrf.get("local-asn"))),
            ("Originator ID", text(vrf.get("originator-id"))),
            ("Peers", text(vrf.get("config-peer-count"))),
            ("Peers up", text(vrf.get("estb-peer-count"))),
            ("Peers shut down", text(vrf.get("shut-peer-count"))),
        ]
        per_vrf[name] = {"facts": [f for f in facts if f[1]], "values": {}}

    # Only a peer that never connected was seen live; the counters and states
    # of an established peer are read by the same documented field names.
    peers: list[Instance] = []
    rows: list[tuple[str, ...]] = []
    for row in _msdp_peer_rows(_body(bodies, 0)):
        address = text(row.get("peer-ipaddr"))
        if not address:
            continue
        vrf_name = _vrf_name(row)
        vrfs.append(vrf_name)
        state = text(row.get("connection-status"))
        asn = text(row.get("peer-asn"))
        asn = "" if asn == "0" else asn
        source = long_name(text(row.get("local-iface")))
        description = text(row.get("peer-description"))
        values: dict[str, dict[str, str]] = {}
        if source:
            values["connect_source"] = {"peer": address, "source": source, "remote_as": asn}
        if description:
            values["description"] = {"peer": address, "text": description}
        if _on(row.get("peer-password")):
            values["password"] = {"peer": address}
        interval, timeout = text(row.get("KeepaliveInterval")), text(row.get("KeepaliveTimeout"))
        if interval.isdigit() and timeout.isdigit():
            values["keepalive"] = {"peer": address, "interval": interval, "timeout": timeout}
        mesh = _policy(row.get("mesh-name"))
        if mesh:
            values["mesh_group"] = {"peer": address, "name": mesh}
        for direction in ("in", "out"):
            policy = _policy(row.get(f"sa-{direction}-policy"))
            if policy:
                values[f"sa_policy_{direction}"] = {"peer": address, "route_map": policy}
        if "shut" in state.lower():
            values["shutdown"] = {"peer": address}
        reconnect = text(row.get("ReconnectionInterval"))
        found = per_vrf.setdefault(vrf_name, {"facts": [], "values": {}})
        if reconnect.isdigit() and "reconnect_interval" not in found["values"]:
            found["values"]["reconnect_interval"] = {"seconds": reconnect}
        uptime = _duration(row.get("peer-uptime"))
        facts = (
            ("VRF", vrf_name),
            ("State", state),
            ("Local address", text(row.get("local-ipaddr"))),
            ("Connects from", source),
            ("Remote AS", asn or "same as ours"),
            ("In this state for", uptime),
            ("SAs received", text(row.get("sa-rcvd"))),
            ("SAs sent", text(row.get("sa-sent"))),
            ("Password", "set" if _on(row.get("peer-password")) else "none"),
        )
        peers.append(
            Instance(
                "peer",
                {"vrf": vrf_name, "address": address},
                f"Peer {address}",
                facts,
                values,
            )
        )
        rows.append(
            (
                address,
                vrf_name,
                state,
                asn,
                source,
                uptime,
                text(row.get("sa-rcvd")),
                text(row.get("sa-sent")),
                description,
            )
        )
    return ProtocolView(
        instances=(*_vrf_instances(vrfs, per_vrf, {}), *peers),
        tables=(
            Table(
                "MSDP peers",
                (
                    "Peer",
                    "VRF",
                    "State",
                    "Remote AS",
                    "Connects from",
                    "In this state for",
                    "SAs received",
                    "SAs sent",
                    "Description",
                ),
                tuple(rows),
                empty="No MSDP peers.",
            ),
        ),
    )


# ---- BFD -------------------------------------------------------------------------


def parse_bfd(bodies: list[dict[str, Any]]) -> ProtocolView:
    """BFD's page from show bfd neighbors (which prints nothing with no sessions)."""
    # Never seen live: the switch had no BFD session, and then the command
    # prints nothing at all. Read by the field names Cisco documents for show
    # bfd neighbors; the documented output can split one session over two rows
    # with the same local_disc, so rows are merged by it first.
    merged: dict[str, dict[str, Any]] = {}
    for row in table_rows(_body(bodies, 0), "TABLE_bfdNeighbor", "ROW_bfdNeighbor"):
        key = text(row.get("local_disc")) or str(len(merged))
        merged.setdefault(key, {}).update(row)
    rows: list[tuple[str, ...]] = []
    interfaces: dict[str, int] = {}
    for row in merged.values():
        interface = text(row.get("intf"))
        interface = "" if interface in ("0", "") else long_name(interface)
        if interface:
            interfaces[interface] = interfaces.get(interface, 0) + 1
        apps = [
            text(app.get("app"))
            for app in table_rows(row, "TABLE_bfdNeighborApp", "ROW_bfdNeighborApp")
        ]
        rows.append(
            (
                text(row.get("dest_ip_addr")) or text(row.get("dest_ipv6_addr")),
                text(row.get("src_ip_addr")) or text(row.get("src_ipv6_addr")),
                interface,
                text(row.get("vrf_name")),
                text(row.get("local_state")),
                text(row.get("remote_state")),
                text(row.get("cur_detect_mult")),
                text(row.get("holddown")),
                {"SH": "one hop", "MH": "multihop"}.get(text(row.get("sess_type")), ""),
                ", ".join(a for a in apps if a),
            )
        )
    instances = [Instance("global", {}, "Whole switch")]
    instances += [
        Instance(
            "interface",
            {"interface": name},
            name,
            (("Sessions", str(count)),),
        )
        for name, count in interfaces.items()
    ]
    return ProtocolView(
        instances=tuple(instances),
        tables=(
            Table(
                "BFD sessions",
                (
                    "Neighbor",
                    "Our address",
                    "Interface",
                    "VRF",
                    "State",
                    "Neighbor's state",
                    "Multiplier",
                    "Hold down (ms)",
                    "Type",
                    "Used by",
                ),
                tuple(rows),
                empty="No BFD sessions. A protocol (BGP, OSPF, PIM, ...) starts one when BFD is "
                "turned on for it.",
            ),
        ),
    )


# ---- the protocols -----------------------------------------------------------------

PIM = Protocol(
    key="pim",
    name="PIM",
    summary="IPv4 multicast routing: rendezvous points, SSM range and PIM per interface",
    features=("pim",),
    commands=(
        "show ip pim interface vrf all",
        "show ip pim neighbor vrf all",
        "show ip pim rp vrf all",
        "show ip pim group-range vrf all",
        "show ip mroute vrf all",
    ),
    parse=parse_pim,
    scopes=(
        _vrf_scope(_PIM_VRF_SETTINGS, "PIM"),
        _interface_scope(_interface_settings("ip", ipv4=True), "PIM"),
    ),
    about="PIM routes multicast (one stream, many receivers) between networks. Turn it on "
    "on every routed interface between senders, receivers and the rendezvous point (RP), "
    "and give every router the same RP; groups in the SSM range need no RP.",
)

PIM6 = Protocol(
    key="pim6",
    name="PIM6",
    summary="IPv6 multicast routing: rendezvous points and PIM6 per interface",
    features=("pim6",),
    commands=("show ipv6 pim interface vrf all", "show ipv6 pim rp vrf all"),
    parse=parse_pim6,
    scopes=(
        _vrf_scope(_PIM6_VRF_SETTINGS, "PIM6"),
        _interface_scope(_interface_settings("ipv6", ipv4=False), "PIM6"),
    ),
    about="PIM for IPv6. On a Nexus 9000 it has static and Anycast RPs only: no Bidir, "
    "BSR or Auto-RP, no BFD and no hello authentication.",
)

_IGMP_SETTINGS: tuple[Setting, ...] = (
    Setting(
        "version",
        "IGMP version",
        "ip igmp version {version}",
        (Field("version", "Version", "choice", choices=("2", "3"), hint="Default 2"),),
        group="IGMP",
        help="Version 3 lets receivers name the sender too (needed for SSM).",
    ),
    Setting(
        "query_interval",
        "Query interval",
        "ip igmp query-interval {seconds}",
        (_int("seconds", "Seconds", 1, 18000, hint="Default 125"),),
        group="Queries",
        help="How often to ask the hosts here which groups they want.",
    ),
    Setting(
        "query_max_response_time",
        "Query response time",
        "ip igmp query-max-response-time {seconds}",
        (_int("seconds", "Seconds", 1, 25, hint="Default 10; less than the query interval"),),
        group="Queries",
    ),
    Setting(
        "startup_query_interval",
        "Start-up query interval",
        "ip igmp startup-query-interval {seconds}",
        (_int("seconds", "Seconds", 1, 18000, hint="Default 31"),),
        group="Queries",
    ),
    Setting(
        "startup_query_count",
        "Start-up query count",
        "ip igmp startup-query-count {count}",
        (_int("count", "Queries", 1, 10, hint="Default 2"),),
        group="Queries",
    ),
    Setting(
        "robustness_variable",
        "Robustness",
        "ip igmp robustness-variable {count}",
        (_int("count", "Value", 1, 7, hint="Default 2; higher for a lossy network"),),
        group="Queries",
    ),
    Setting(
        "querier_timeout",
        "Querier timeout",
        "ip igmp querier-timeout {seconds}",
        (_int("seconds", "Seconds", 1, 65535, hint="Default 255"),),
        group="Queries",
        help="How long the other querier may stay silent before this switch takes over.",
    ),
    Setting(
        "last_member_query_response_time",
        "Last member response time",
        "ip igmp last-member-query-response-time {seconds}",
        (_int("seconds", "Seconds", 1, 25, hint="Default 1"),),
        group="Leaving",
    ),
    Setting(
        "last_member_query_count",
        "Last member query count",
        "ip igmp last-member-query-count {count}",
        (_int("count", "Queries", 1, 5, hint="Default 2"),),
        group="Leaving",
    ),
    Setting(
        "group_timeout",
        "Group timeout",
        "ip igmp group-timeout {seconds}",
        (_int("seconds", "Seconds", 3, 65535, hint="Default 260"),),
        group="Leaving",
        help="With no report for this long, the group is dropped here.",
    ),
    Setting(
        "immediate_leave",
        "Immediate leave",
        "ip igmp immediate-leave",
        group="Leaving",
        help="Stop a group as soon as a host leaves it. Only for one receiver per group here.",
    ),
    Setting(
        "report_link_local_groups",
        "Report link-local groups",
        "ip igmp report-link-local-groups",
        group="IGMP",
        help="Also send reports for groups in 224.0.0.0/24.",
    ),
    Setting(
        "report_policy",
        "Report filter",
        "ip igmp report-policy {route_map}",
        (_route_map(),),
        group="Filters",
        help="Accept reports only for the groups the route-map permits.",
    ),
    Setting(
        "access_group",
        "Allowed groups",
        "ip igmp access-group {route_map}",
        (_route_map(),),
        group="Filters",
        help="Hosts here may join only the groups the route-map's match multicast lines permit.",
    ),
    Setting(
        "join_group",
        "Join groups (switch itself)",
        "ip igmp join-group route-map {route_map}",
        (_route_map(),),
        group="Static groups",
        help="The switch joins these groups itself and handles their traffic in its CPU; "
        "use static groups for anything real.",
    ),
    Setting(
        "static_oif",
        "Static groups",
        "ip igmp static-oif route-map {route_map}",
        (_route_map(),),
        group="Static groups",
        help="Send these groups out of this interface even with no receiver asking.",
    ),
    Setting(
        "join_group_address",
        "Join one group (switch itself)",
        "ip igmp join-group {group} [source {sender}]",
        (
            Field("group", "Group", "maddr4", placeholder="239.1.1.1"),
            Field("sender", "Only from sender", "ipv4", optional=True, placeholder="192.0.2.10"),
        ),
        group="Static groups",
        help="The switch joins one group itself and handles its traffic in its CPU; use a "
        "static group for anything real.",
    ),
    Setting(
        "static_oif_address",
        "One static group",
        "ip igmp static-oif {group} [source {sender}]",
        (
            Field("group", "Group", "maddr4", placeholder="239.1.1.1"),
            Field("sender", "Only from sender", "ipv4", optional=True, placeholder="192.0.2.10"),
        ),
        group="Static groups",
        help="Send one group out of this interface even with no receiver asking.",
    ),
)

IGMP = Protocol(
    key="igmp",
    name="IGMP",
    summary="How receivers ask for multicast groups, per interface",
    features=("pim",),
    commands=("show ip igmp interface vrf all",),
    parse=parse_igmp,
    scopes=(
        Scope(
            "interface",
            "Interface",
            (interface_field(),),
            ("interface {interface}",),
            _IGMP_SETTINGS,
            help="IGMP on one routed interface: it runs where PIM is on.",
        ),
    ),
    about="Hosts use IGMP to tell the switch which multicast groups they want; the switch "
    "asks them now and then (the querier). It runs on routed interfaces with PIM on.",
)


def _peer_field() -> Field:
    return Field("peer", "Peer address", "ipv4", hint="The MSDP peer this applies to")


_MSDP_VRF_SETTINGS: tuple[Setting, ...] = (
    Setting(
        "peer",
        "Add a peer",
        "ip msdp peer {peer} connect-source {source} [remote-as {remote_as}]",
        (
            _peer_field(),
            _source("Connect from"),
            Field("remote_as", "Remote AS", "asn", optional=True, hint="Empty for our own AS"),
        ),
        group="Peers",
        settable=True,
        removable=False,
        help="Peer with another RP over TCP, from this interface's address.",
    ),
    Setting(
        "originator_id",
        "Originator",
        "ip msdp originator-id {source}",
        (_source("Interface"),),
        group="MSDP",
        help="The address put in the RP field of the source announcements this switch sends.",
    ),
    Setting(
        "reconnect_interval",
        "Reconnect interval",
        "ip msdp reconnect-interval {seconds}",
        (_int("seconds", "Seconds", 1, 60, hint="Default 10"),),
        group="MSDP",
    ),
    Setting(
        "sa_interval",
        "Announcement interval",
        "ip msdp sa-interval {seconds}",
        (_int("seconds", "Seconds", 60, 65535, hint="Default 60"),),
        group="MSDP",
        help="How often to announce this network's active senders (SA messages).",
    ),
    Setting(
        "group_limit",
        "Group limit",
        "ip msdp group-limit {limit} source {source}",
        (
            _int("limit", "Groups", 1, 4294967295),
            Field("source", "Senders", "prefix4", placeholder="192.0.2.0/24"),
        ),
        group="MSDP",
        help="At most this many groups for senders in this range.",
    ),
    Setting(
        "flush_routes",
        "Flush routes on restart",
        "ip msdp flush-routes",
        group="MSDP",
        help="Remove MSDP's routes when the MSDP process restarts.",
    ),
)

_MSDP_PEER_SETTINGS: tuple[Setting, ...] = (
    Setting(
        "connect_source",
        "Connect from",
        "ip msdp peer {peer} connect-source {source} [remote-as {remote_as}]",
        (
            _peer_field(),
            _source("Connect from"),
            Field("remote_as", "Remote AS", "asn", optional=True, hint="Empty for our own AS"),
        ),
        removable=False,
        group="Peer",
    ),
    Setting(
        "description",
        "Description",
        "ip msdp description {peer} {text}",
        (_peer_field(), Field("text", "Description", "text")),
        group="Peer",
    ),
    Setting(
        "password",
        "Password",
        "ip msdp password {peer} {password}",
        (_peer_field(), Field("password", "Password", "secret")),
        no_line="no ip msdp password {peer}",
        group="Peer",
        help="MD5 password for the TCP session.",
        warning="The peer must have the same password, or the session will not come up.",
    ),
    Setting(
        "keepalive",
        "Keepalive",
        "ip msdp keepalive {peer} {interval} {timeout}",
        (
            _peer_field(),
            _int("interval", "Every (seconds)", 1, 60, hint="Default 60"),
            _int("timeout", "Give up after (seconds)", 1, 90, hint="Default 90"),
        ),
        no_line="no ip msdp keepalive {peer}",
        group="Peer",
    ),
    Setting(
        "mesh_group",
        "Mesh group",
        "ip msdp mesh-group {peer} {name}",
        (_peer_field(), Field("name", "Mesh group", "name")),
        group="Peer",
        help="Peers in one mesh group all peer with each other and do not pass on each "
        "other's announcements.",
    ),
    Setting(
        "sa_limit",
        "Announcement limit",
        "ip msdp sa-limit {peer} {limit}",
        (_peer_field(), _int("limit", "Sources", 1, 4294967295)),
        no_line="no ip msdp sa-limit {peer}",
        group="Filters",
        help="Keep at most this many (source, group) entries from this peer.",
    ),
    Setting(
        "sa_policy_in",
        "Incoming announcement filter",
        "ip msdp sa-policy {peer} {route_map} in",
        (_peer_field(), _route_map()),
        group="Filters",
    ),
    Setting(
        "sa_policy_out",
        "Outgoing announcement filter",
        "ip msdp sa-policy {peer} {route_map} out",
        (_peer_field(), _route_map()),
        group="Filters",
    ),
    Setting(
        "shutdown",
        "Shut down",
        "ip msdp shutdown {peer}",
        (_peer_field(),),
        group="Peer",
        help="Close the session but keep its settings.",
        warning="The session with this peer closes.",
    ),
)

MSDP = Protocol(
    key="msdp",
    name="MSDP",
    summary="Telling other networks' rendezvous points about this network's senders",
    features=("msdp",),
    commands=("show ip msdp peer vrf all", "show ip msdp summary vrf all"),
    parse=parse_msdp,
    scopes=(
        _vrf_scope(_MSDP_VRF_SETTINGS, "MSDP"),
        Scope(
            "peer",
            "Peer",
            (vrf_field(), Field("address", "Peer address", "ipv4")),
            ("[vrf context {vrf}]",),
            _MSDP_PEER_SETTINGS,
            delete=("[vrf context {vrf}]", "no ip msdp peer {address}"),
            delete_warning="The session with this peer closes and its settings go.",
            help="One MSDP peer. Add peers under Global settings.",
        ),
    ),
    about="MSDP connects the rendezvous points of separate PIM networks (or of an Anycast-RP "
    "set) so receivers in one hear about senders in another. Needs PIM.",
)

_BFD_INTERVAL = Setting(
    "interval",
    "Timers",
    "bfd interval {tx} min_rx {rx} multiplier {multiplier}",
    (
        _int("tx", "Send every (ms)", 50, 999, hint="Default 50"),
        _int("rx", "Expect every (ms)", 50, 999, hint="Default 50"),
        _int("multiplier", "Missed before down", 1, 50, hint="Default 3"),
    ),
    group="Timers",
    help="A session goes down after this many heartbeats in a row do not arrive.",
)

BFD = Protocol(
    key="bfd",
    name="BFD",
    summary="Fast link checks other protocols use to notice a dead neighbor",
    features=("bfd",),
    commands=("show bfd neighbors",),
    parse=parse_bfd,
    scopes=(
        Scope(
            "global",
            "Whole switch",
            (),
            (),
            (
                _BFD_INTERVAL,
                Setting(
                    "slow_timer",
                    "Slow timer",
                    "bfd slow-timer {milliseconds}",
                    (_int("milliseconds", "Milliseconds", 1000, 30000, hint="Default 2000"),),
                    group="Timers",
                    help="How often sessions send while starting, or while echo does the checking.",
                ),
                Setting(
                    "startup_timer",
                    "Start-up delay",
                    "bfd startup-timer {seconds}",
                    (_int("seconds", "Seconds", 0, 30, hint="Default 5"),),
                    no_line="no bfd startup-timer",
                    group="Timers",
                    help="Wait this long after the switch starts before bringing sessions up.",
                ),
            ),
            help="Defaults for every BFD session; an interface's own settings win.",
        ),
        Scope(
            "interface",
            "Interface",
            (interface_field(),),
            ("interface {interface}",),
            (
                _BFD_INTERVAL,
                Setting(
                    "echo",
                    "Echo",
                    "bfd echo",
                    group="Echo",
                    help="The neighbor bounces our packets back (on by default). Remove to turn "
                    "it off.",
                ),
                Setting(
                    "authentication",
                    "Authentication",
                    "bfd authentication keyed-sha1 key-id {key_id} key {key}",
                    (_int("key_id", "Key ID", 0, 255), Field("key", "Key", "secret")),
                    no_line="no bfd authentication",
                    group="Authentication",
                    help="SHA-1 keyed authentication of every BFD packet on this interface.",
                    warning="The neighbor must use the same key ID and key, or the session "
                    "goes down.",
                ),
            ),
            help="BFD settings for one interface.",
        ),
    ),
    about="BFD sends small heartbeats to a neighbor many times a second, so BGP, OSPF, PIM "
    "and the others notice a dead link in well under a second. Each protocol turns it on "
    "for itself (BFD on its page); here are the timers.",
)

PROTOCOLS: tuple[Protocol, ...] = (PIM, PIM6, IGMP, MSDP, BFD)
