"""Non-blocking multicast (NBM): the switch reserving bandwidth for each multicast flow, so
media streams (video, audio) never overrun a link, part of Cisco's IP Fabric for Media.

In the **pim-active** mode (the default) the switch sets flows up itself as PIM and IGMP
ask for them; **flow policies** give groups their bandwidth, DSCP mark, policer and
priority; the **defaults** are for groups no policy names. **Host policies** say which
senders may send, which local receivers may join and which receivers behind PIM may get
a flow. A **flow definition** sets a flow up in advance. An **external link** is a routed
port towards another network. **NBM VRFs** have their own copy of all of it.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes, each setting the one line it sends with checked values in
its blanks, and ``build_change`` building the lines. ``NxapiClient.configure_nbm`` sends
them.

Read from the switch: ``show feature``, ``show interface brief``, ``show vrf`` and ``show
vrf interface`` in one request, ``show hardware access-list tcam region`` as text (as the
NAT page reads it); while ``feature nbm`` is on, ``show nbm defaults``, ``show nbm
flow-policy``, ``show nbm host-policy all sender|receiver local|receiver external``, ``show
nbm flows summary``, ``show nbm flows static`` and ``show nbm interface bandwidth`` in one
request, and ``show running-config`` as text, where the NBM lines are read.

Tried on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-13), all removed and the
feature turned back off: ``feature nbm`` was taken (VXLAN on, with no NVE interface); it
writes ``nbm mode pim-active`` and default-permit host policies. Taken: ``nbm flow
bandwidth <n> kbps|mbps|gbps`` (26 gbps refused), ``nbm flow dscp``, ``[no] nbm flow
policer``, ``nbm reserve unicast fabric bandwidth <0-100>``, ``nbm flow asm range
<group>``, ``nbm flow reserve-bandwidth receiver-only``; ``nbm flow-policy`` and ``policy
<name>`` (a ``-`` in the name is refused) with ``bandwidth`` (written in kbps), ``dscp``,
``no policer``, ``ip group-range <first> to <last>`` (first below last, not overlapping
another policy's) and ``ip group <address>`` with ``priority critical`` inside it; ``nbm
host-policy`` with ``sender``, ``receiver`` and ``pim`` entries numbered by hand, ``no
<n>``, and ``default permit|deny`` (refused while entries exist); ``nbm flow-definition
<group> <source>`` with ``stage-flow``, ``egress-interface`` and ``egress-host``; ``nbm
external-link`` on a routed port only; ``nbm mode pim-passive`` (refused while anything
custom exists); ``nbm vrf <name>``, which makes the VRF itself when it does not exist (so
the page refuses an unknown one). Every ``no`` form above was taken.

Cisco's NX-OS 9.3 IP Fabric for Media guide says NBM is not supported on a switch with
VXLAN on and may upset VXLAN's underlay multicast, and that it needs the TCAM regions
``ing-racl 256``, ``ing-l3-vlan-qos 256`` and ``ing-nbm 1536`` (counted after a restart);
cisco-25gb has VXLAN on and ``ing-nbm`` at 0, and the page says both plainly. No flow ran
on the probe switch: the flow and interface tables follow the JSON it printed with none.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from app.acls import TCAM_COMMAND, parse_tcam_regions
from app.features import feature_states
from app.nxapi import DEFAULT_VRF, NxapiClient, NxapiCommandError
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
    table_rows,
)
from app.routing import parse_vrf_members
from app.routing_protocols import layer3_interfaces
from app.switch import text
from app.switch_admin import vrf_choices
from app.vxlan import parse_vxlan_config

FEATURE = "nbm"
VXLAN_FEATURE = "nve"  # show feature's name for `feature nv overlay`
PAGE_COMMANDS = ("show feature", "show interface brief", "show vrf", "show vrf interface")
COMMANDS = (
    "show nbm defaults",
    "show nbm flow-policy",
    "show nbm host-policy all sender",
    "show nbm host-policy all receiver local",
    "show nbm host-policy all receiver external",
    "show nbm flows summary",
    "show nbm flows static",
    "show nbm interface bandwidth",
)
CONFIG_COMMAND = "show running-config"
MODES = ("pim-active", "pim-passive")
UNITS = ("kbps", "mbps", "gbps")
# The most a flow's bandwidth may be, per unit (Cisco's guide; 26 gbps was refused).
BANDWIDTH_MAX = {"kbps": 25000000, "mbps": 25000, "gbps": 25}
# Cisco's guide: the TCAM space NBM needs (counted after a restart of the switch).
NBM_REGION = "ing-nbm"
SEQUENCE_MAX = 4294967295

VXLAN_ON = (
    "VXLAN (feature nv overlay) is on. Cisco does not support NBM on a switch with VXLAN on: "
    "it can upset the multicast that VXLAN's underlay uses."
)
NO_TCAM = (
    "The switch's ing-nbm TCAM region has no space. Cisco's guide asks for ing-racl 256, "
    "ing-l3-vlan-qos 256 and ing-nbm 1536 (on the ACLs page, under TCAM regions), which count "
    "only after a restart of the switch; until then the switch takes NBM's lines but cannot "
    "reserve bandwidth in hardware."
)
_POLICY_NAME = re.compile(r"^[A-Za-z0-9]{1,63}$")


def _int(name: str, label: str, low: int, high: int, hint: str = "", **kw: Any) -> Field:
    return Field(name, label, "int", minimum=low, maximum=high, hint=hint, **kw)


def _vrf() -> Field:
    return Field(
        "vrf",
        "NBM VRF",
        "vrf",
        optional=True,
        hint="default, or a VRF made on the Routing page: it gets its own NBM settings",
        placeholder="default",
    )


_IN_VRF = "[nbm vrf {vrf}]"


def _bandwidth_fields() -> tuple[Field, ...]:
    return (
        _int("amount", "Bandwidth", 1, BANDWIDTH_MAX["kbps"], "Per flow, in the unit below"),
        Field("unit", "Unit", "choice", choices=UNITS),
    )


def _check_bandwidth(values: dict[str, str]) -> None:
    unit = values["unit"]
    if int(values["amount"]) > BANDWIDTH_MAX[unit]:
        raise ValueError(f"a flow takes at most {BANDWIDTH_MAX[unit]} {unit}")


def _dscp() -> Field:
    return _int("dscp", "DSCP", 0, 63, "0 to 63: the mark the flow's packets get")


# ---- the whole switch (or one NBM VRF) ------------------------------------------------------

_GLOBAL = Scope(
    key="global",
    label="NBM settings",
    ident=(_vrf(),),
    enter=(_IN_VRF,),
    help="For the whole switch, or one NBM VRF. The flow settings are the defaults for "
    "groups no flow policy names.",
    settings=(
        Setting(
            "mode",
            "Mode",
            "nbm mode {mode}",
            (
                Field(
                    "mode",
                    "Mode",
                    "choice",
                    choices=MODES,
                    hint="pim-active: the switch sets flows up itself; pim-passive: a "
                    "controller does, through the API",
                ),
            ),
            removable=False,
            group="Mode",
            warning="The switch refuses pim-passive while flow policies, host policy entries "
            "or flow definitions exist.",
        ),
        Setting(
            "flow_bandwidth",
            "Flow bandwidth",
            "nbm flow bandwidth {amount} {unit}",
            _bandwidth_fields(),
            check=_check_bandwidth,
            group="Default flows",
            help="Reserved for each flow no policy names (default 0).",
        ),
        Setting(
            "flow_dscp",
            "Flow DSCP",
            "nbm flow dscp {dscp}",
            (_dscp(),),
            group="Default flows",
        ),
        Setting(
            "flow_policer",
            "Flow policer",
            "nbm flow policer",
            group="Default flows",
            help="On by default: a flow sending more than its bandwidth is cut back. Remove "
            "turns it off.",
        ),
        Setting(
            "reserve_unicast",
            "Bandwidth kept for unicast",
            "nbm reserve unicast fabric bandwidth {percent}",
            (_int("percent", "Percent", 0, 100, "Of each fabric link; default 0"),),
            group="Links",
            help="Cisco: change it only with the fabric links flapped afterwards.",
        ),
        Setting(
            "asm_range",
            "ASM group range",
            "nbm flow asm range {group}",
            (Field("group", "Groups", "group4", placeholder="239.0.0.0/8"),),
            group="Groups",
            help="Groups that use a rendezvous point (ASM), for a fabric with more than one "
            "spine; up to 20 ranges.",
        ),
        Setting(
            "receiver_only",
            "Reserve only where receivers are",
            "nbm flow reserve-bandwidth receiver-only",
            group="Links",
            help="Reserve a flow's bandwidth only once a receiver has joined it.",
        ),
    ),
)

# ---- flow policies --------------------------------------------------------------------------


def _policy_field() -> Field:
    return Field(
        "name",
        "Policy name",
        "name",
        hint="Letters and digits only: the switch refuses a -",
        placeholder="video",
    )


_POLICY_ENTER = (_IN_VRF, "nbm flow-policy", "policy {name}")


def _check_range(values: dict[str, str]) -> None:
    if ipaddress.IPv4Address(values["first"]) >= ipaddress.IPv4Address(values["last"]):
        raise ValueError("the range's first group must come before its last")


_POLICY = Scope(
    key="policy",
    label="Flow policy",
    ident=(_vrf(), _policy_field()),
    enter=_POLICY_ENTER,
    create=True,
    create_label="Make a flow policy",
    delete=(_IN_VRF, "nbm flow-policy", "no policy {name}"),
    delete_warning="Its groups go back to the default flow settings.",
    help="The bandwidth, mark and policer of the flows in its groups.",
    settings=(
        Setting(
            "bandwidth",
            "Bandwidth",
            "bandwidth {amount} {unit}",
            _bandwidth_fields(),
            no_line="no bandwidth",
            check=_check_bandwidth,
            group="Flows",
            help="Reserved for each flow (the switch writes it in kbps).",
        ),
        Setting("dscp", "DSCP", "dscp {dscp}", (_dscp(),), no_line="no dscp", group="Flows"),
        Setting(
            "policer",
            "Policer",
            "policer",
            group="Flows",
            help="On by default. Remove turns it off: the flows can then send more than "
            "their bandwidth.",
        ),
        Setting(
            "group_range",
            "Group range",
            "ip group-range {first} to {last}",
            (
                Field("first", "First group", "maddr4", placeholder="239.1.1.1"),
                Field("last", "Last group", "maddr4", placeholder="239.1.1.255"),
            ),
            check=_check_range,
            group="Groups",
            help="Add a range of groups; a range may not overlap another policy's.",
        ),
    ),
)

_GROUP = Scope(
    key="group",
    label="Group of a flow policy",
    ident=(_vrf(), _policy_field(), Field("group", "Group", "maddr4", placeholder="239.1.2.1")),
    enter=(*_POLICY_ENTER, "ip group {group}"),
    create=True,
    create_label="Add one group to a flow policy",
    delete=(*_POLICY_ENTER, "no ip group {group}"),
    help="One group of the policy, which can be marked critical.",
    settings=(
        Setting(
            "priority",
            "Critical",
            "priority critical",
            group="Priority",
            help="The switch sets this group's flows up before the others.",
        ),
    ),
)

# ---- host policies ----------------------------------------------------------------------------


def _sequence() -> Field:
    return _int("seq", "Entry number", 1, SEQUENCE_MAX, "Entries are checked in number order")


def _action() -> Field:
    return Field("action", "Action", "choice", choices=("permit", "deny"))


def _host(name: str, label: str, hint: str) -> Field:
    return Field(name, label, "ipv4any", hint=hint, placeholder="192.0.2.10")


def _groups() -> Field:
    return Field("group", "Groups", "group4", placeholder="239.1.1.0/24")


def _entry(key: str, label: str, role: str, line: str, fields: tuple[Field, ...], help_text: str):
    return Scope(
        key=key,
        label=label,
        ident=(_vrf(), _sequence(), *fields, _action()),
        enter=(_IN_VRF, "nbm host-policy", role, line),
        create=True,
        create_label=f"Add a {label.lower()}",
        delete=(_IN_VRF, "nbm host-policy", role, "no {seq}"),
        help=help_text,
    )


_SENDER = _entry(
    "sender",
    "Sender entry",
    "sender",
    "{seq} host {host} group {group} {action}",
    (_host("host", "Sender", "Its address, or any for every sender"), _groups()),
    "Whether a host may send to these groups.",
)
_RECEIVER = _entry(
    "receiver",
    "Local receiver entry",
    "receiver",
    "{seq} host {host} source {source} group {group} {action}",
    (
        _host("host", "Receiver", "Its address, or any for every receiver"),
        _host("source", "Sender", "The sender's address, or any"),
        _groups(),
    ),
    "Whether a host on this switch may join these groups from this sender.",
)
_PIM = _entry(
    "pim",
    "PIM receiver entry",
    "pim",
    "{seq} source {source} group {group} {action}",
    (Field("source", "Sender", "ipv4", placeholder="192.0.2.10"), _groups()),
    "Whether a receiver behind PIM (another router) may get these groups from this sender.",
)

_DEFAULTS = Scope(
    key="defaults",
    label="Host policy default",
    ident=(_vrf(), Field("role", "For", "choice", choices=("sender", "receiver", "pim"))),
    enter=(_IN_VRF, "nbm host-policy", "{role}"),
    help="What happens to hosts no entry names.",
    settings=(
        Setting(
            "default",
            "Default",
            "default {action}",
            (_action(),),
            removable=False,
            group="Default",
            help="permit by default. The switch refuses a change while entries exist: "
            "delete them first.",
        ),
    ),
)

# ---- flow definitions and external links ---------------------------------------------------

_DEFINITION = Scope(
    key="definition",
    label="Flow definition",
    ident=(
        _vrf(),
        Field("group", "Group", "maddr4", placeholder="239.1.1.5"),
        Field("source", "Sender", "ipv4", placeholder="192.0.2.10"),
    ),
    enter=(_IN_VRF, "nbm flow-definition {group} {source}"),
    create=True,
    create_label="Define a flow",
    delete=(_IN_VRF, "no nbm flow-definition {group} {source}"),
    help="A flow set up in advance, sent where it is named.",
    settings=(
        Setting(
            "stage_flow",
            "Set it up now",
            "stage-flow",
            group="Flow",
            help="Reserve the path before any receiver asks.",
        ),
        Setting(
            "egress_interface",
            "Out of this interface",
            "egress-interface {interface}",
            (Field("interface", "Interface", "ifname", placeholder="Ethernet1/5"),),
            group="Flow",
        ),
        Setting(
            "egress_host",
            "To this receiver",
            "egress-host {host}",
            (Field("host", "Receiver", "ipv4", placeholder="192.0.2.30"),),
            group="Flow",
        ),
    ),
)

_INTERFACE = Scope(
    key="interface",
    label="Interface",
    ident=(interface_field(),),
    enter=("interface {interface}",),
    help="A routed front port towards another network.",
    settings=(
        Setting(
            "external_link",
            "External link",
            "nbm external-link",
            group="NBM",
            help="Flows to and from another network cross here. Cisco: only routed front "
            "ports, not port-channels.",
            warning="The port goes down and up again.",
        ),
    ),
)

SCOPES = (_GLOBAL, _POLICY, _GROUP, _SENDER, _RECEIVER, _PIM, _DEFAULTS, _DEFINITION, _INTERFACE)

# ---- reading ---------------------------------------------------------------------------------


def _kbps(value: Any) -> str:
    """Kbps from the switch as words: 3000000 -> '3 Gbps', 1500 -> '1.5 Mbps'."""
    found = text(value).strip()
    try:
        number = float(found)
    except ValueError:
        return found or "-"
    for size, unit in ((1000000, "Gbps"), (1000, "Mbps")):
        if number >= size:
            return f"{number / size:g} {unit}"
    return f"{number:g} kbps"


@dataclass
class NbmConfig:
    """The NBM lines of one VRF (default: the top level), as read from the configuration."""

    lines: list[str]  # its own "nbm ..." lines
    policies: dict[str, list[str]]  # policy name -> its lines
    groups: dict[tuple[str, str], list[str]]  # (policy, group) -> its lines
    entries: list[tuple[str, dict[str, str]]]  # (scope, identity values)
    definitions: dict[tuple[str, str], list[str]]  # (group, source) -> its lines


_ENTRY_LINES = {
    "sender": re.compile(r"(\d+) host (\S+) group (\S+) (permit|deny)"),
    "receiver": re.compile(r"(\d+) host (\S+) source (\S+) group (\S+) (permit|deny)"),
    "pim": re.compile(r"(\d+) source (\S+) group (\S+) (permit|deny)"),
}
_ENTRY_NAMES = {
    "sender": ("seq", "host", "group", "action"),
    "receiver": ("seq", "host", "source", "group", "action"),
    "pim": ("seq", "source", "group", "action"),
}


_ROLE_WORDS = {"sender": "Sender", "receiver": "Local receiver", "pim": "PIM receiver"}


def _any(address: str) -> str:
    return "any" if address == "0.0.0.0" else address


def _read_vrf(tree: Any, path: tuple[str, ...]) -> NbmConfig:
    found = NbmConfig([], {}, {}, [], {})
    for line in tree.children(*path):
        if line.startswith("nbm flow-definition "):
            group, source = line.split()[2:4]
            found.definitions[(group, source)] = tree.children(*path, line)
        elif line == "nbm flow-policy":
            for policy in tree.children(*path, line):
                if not policy.startswith("policy "):
                    continue
                name = policy.split()[1]
                inner = tree.children(*path, line, policy)
                found.policies[name] = inner
                for entry in inner:
                    if entry.startswith("ip group ") and " to " not in entry:
                        found.groups[(name, entry.split()[2])] = tree.children(
                            *path, line, policy, entry
                        )
        elif line == "nbm host-policy":
            for role in ("sender", "receiver", "pim"):
                for entry in tree.children(*path, line, role):
                    if match := _ENTRY_LINES[role].fullmatch(entry):
                        values = dict(zip(_ENTRY_NAMES[role], match.groups(), strict=True))
                        for key in ("host", "source"):
                            if key in values and role != "pim":
                                values[key] = _any(values[key])
                        found.entries.append((role, values))
        elif line.startswith("nbm ") and not line.startswith("nbm vrf "):
            found.lines.append(line)
    return found


def parse_nbm_config(config: str) -> dict[str, NbmConfig]:
    """The NBM lines of ``show running-config``, per VRF (``default`` for the top level and
    each ``nbm vrf <name>`` block)."""
    tree = parse_vxlan_config(config)
    found = {DEFAULT_VRF: _read_vrf(tree, ())}
    for line in tree.children():
        if match := re.fullmatch(r"nbm vrf (\S+)", line):
            found[match.group(1)] = _read_vrf(tree, (line,))
    return found


def _global_values(lines: list[str], policer: bool) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {"flow_policer": {}} if policer else {}
    for line in lines:
        if match := re.fullmatch(r"nbm mode (\S+)", line):
            values["mode"] = {"mode": match.group(1)}
        elif match := re.fullmatch(r"nbm flow bandwidth (\d+) (kbps|mbps|gbps)", line):
            values["flow_bandwidth"] = {"amount": match.group(1), "unit": match.group(2)}
        elif match := re.fullmatch(r"nbm flow dscp (\d+)", line):
            values["flow_dscp"] = {"dscp": match.group(1)}
        elif line == "no nbm flow policer":
            values.pop("flow_policer", None)
        elif match := re.fullmatch(r"nbm reserve unicast fabric bandwidth (\d+)", line):
            values["reserve_unicast"] = {"percent": match.group(1)}
        elif match := re.fullmatch(r"nbm flow asm range (\S+)", line):
            values.setdefault("asm_range", {"group": match.group(1)})
        elif line == "nbm flow reserve-bandwidth receiver-only":
            values["receiver_only"] = {}
    return values


def _policy_values(lines: list[str]) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {"policer": {}}
    for line in lines:
        if match := re.fullmatch(r"bandwidth (\d+) (kbps|mbps|gbps)", line):
            values["bandwidth"] = {"amount": match.group(1), "unit": match.group(2)}
        elif match := re.fullmatch(r"dscp (\d+)", line):
            values["dscp"] = {"dscp": match.group(1)}
        elif line == "no policer":
            values.pop("policer", None)
        elif match := re.fullmatch(r"ip group-range (\S+) to (\S+)", line):
            values.setdefault("group_range", {"first": match.group(1), "last": match.group(2)})
    return values


def _defaults(body: Any) -> tuple[list[tuple[str, ...]], dict[str, bool]]:
    rows = []
    policers = {}
    for row in table_rows(body, "TABLE_vrf", "ROW_vrf"):
        vrf = text(row.get("vrfName")) or DEFAULT_VRF
        policers[vrf] = text(row.get("policer")).lower() != "disabled"
        mode = {"TOR_PIM_A": "pim-active", "TOR_PIM_P": "pim-passive"}.get(
            text(row.get("operMode")), text(row.get("operMode"))
        )
        asm = [
            f"{text(a.get('groupPrefix'))}/{text(a.get('groupMaskLen'))}"
            for a in table_rows(row, "TABLE_ASM", "ROW_ASM")
        ]
        rows.append(
            (
                vrf,
                mode,
                _kbps(row.get("bandwidthInKbps")),
                text(row.get("dscp")),
                text(row.get("policer")),
                f"{text(row.get('unicastFabricBandwidth')) or '0'}%",
                "yes" if text(row.get("ResBwRxOnly")) == "1" else "no",
                ", ".join(asm) or "-",
                " / ".join(
                    text(row.get(k))
                    for k in ("senderPolicy", "localReceiverPolicy", "externalReceiverPolicy")
                ),
            )
        )
    return rows, policers


def _flow_policies(body: Any) -> list[tuple[str, ...]]:
    rows = []
    for vrf in table_rows(body, "TABLE_vrf", "ROW_vrf"):
        name = text(vrf.get("vrfName")) or DEFAULT_VRF
        for row in table_rows(vrf, "TABLE_flow_policy", "ROW_flow_policy"):
            rows.append(
                (
                    text(row.get("policyName")),
                    name,
                    text(row.get("groupRange")).replace("-", " to "),
                    _kbps(row.get("bandwidthKbps")),
                    text(row.get("dscp")),
                    text(row.get("policer")),
                    text(row.get("priority")).lower(),
                )
            )
    return rows


def _host_policies(bodies: list[Any]) -> list[tuple[str, ...]]:
    rows = []
    for body in bodies:
        for vrf in table_rows(body, "TABLE_vrf", "ROW_vrf"):
            name = text(vrf.get("vrf-name")) or DEFAULT_VRF
            kind = text(vrf.get("policyType"))
            for row in table_rows(vrf, "TABLE_host_policies", "ROW_host_policies"):
                rows.append(
                    (
                        kind,
                        name,
                        text(row.get("seqNum")),
                        _any(text(row.get("host"))) or "-",
                        _any(text(row.get("source"))) or "-",
                        f"{text(row.get('group'))}/{text(row.get('groupMask'))}",
                        text(row.get("permission")),
                    )
                )
            rows.append((kind, name, "default", "-", "-", "-", text(vrf.get("defaultHostPolicy"))))
    return rows


def _summary(body: Any) -> list[tuple[str, ...]]:
    rows = []
    for vrf in table_rows(body, "TABLE_vrf", "ROW_vrf"):
        name = text(vrf.get("vrf-name")) or DEFAULT_VRF
        for row in table_rows(vrf, "TABLE_flows_summary", "ROW_flows_summary"):
            rows.append(
                (
                    name,
                    text(row.get("flow_type")),
                    text(row.get("starg")),
                    text(row.get("sg")),
                    text(row.get("total")),
                )
            )
    return rows


def _static_flows(body: Any) -> list[tuple[str, ...]]:
    rows = []
    for vrf in table_rows(body, "TABLE_vrf", "ROW_vrf"):
        name = text(vrf.get("vrf-name")) or DEFAULT_VRF
        for state, word in (("stitched", "set up"), ("unstitched", "not set up")):
            table, row_key = f"TABLE_{state}", f"ROW_{state}"
            for row in table_rows(vrf, table, row_key):
                out = [
                    text(e.get(f"{state}EgressIntf"))
                    for e in table_rows(row, f"TABLE_{state}Egress", f"ROW_{state}Egress")
                ]
                hosts = [
                    text(h.get(f"{state}HostIp"))
                    for h in table_rows(row, f"TABLE_{state}Host", f"ROW_{state}Host")
                ]
                rows.append(
                    (
                        name,
                        text(row.get(f"{state}Grp")),
                        text(row.get(f"{state}Src")),
                        word,
                        ", ".join(o for o in out if o) or "-",
                        ", ".join(h for h in hosts if h) or "-",
                    )
                )
    return rows


def _bandwidth(body: Any) -> list[tuple[str, ...]]:
    rows = []
    for row in table_rows(body, "TABLE_bw", "ROW_bw"):

        def both(prefix: str, row: dict[str, Any] = row) -> str:
            available = text(row.get(f"{prefix}_fl_bw_available"))
            capacity = text(row.get(f"{prefix}_fl_bw_capacity"))
            return f"{available} of {capacity}"

        rows.append(
            (
                text(row.get("ifname")),
                both("ingr"),
                both("egr"),
                text(row.get("ingr_unicast_rsvd_percent")).replace(" ", "") or "-",
                "yes" if text(row.get("external")) == "T" else "no",
            )
        )
    return rows


def _definition_values(lines: list[str]) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    for line in lines:
        if line == "stage-flow":
            values["stage_flow"] = {}
        elif match := re.fullmatch(r"egress-interface (\S+)", line):
            values["egress_interface"] = {"interface": match.group(1)}
        elif match := re.fullmatch(r"egress-host (\S+)", line):
            values["egress_host"] = {"host": match.group(1)}
    return values


def _instances(configs: dict[str, NbmConfig], policers: dict[str, bool]) -> list[Instance]:
    instances = []
    for vrf, found in configs.items():
        where = {"vrf": vrf}
        suffix = "" if vrf == DEFAULT_VRF else f" (VRF {vrf})"
        instances.append(
            Instance(
                "global",
                where,
                "Whole switch" if vrf == DEFAULT_VRF else f"NBM VRF {vrf}",
                (),
                _global_values(found.lines, policers.get(vrf, True)),
            )
        )
        for name, lines in found.policies.items():
            ranges = [line.split(" ", 2)[2] for line in lines if line.startswith("ip group-range ")]
            facts = (("Group ranges", "; ".join(ranges) or "none yet"),)
            instances.append(
                Instance(
                    "policy",
                    {**where, "name": name},
                    f"Flow policy {name}{suffix}",
                    facts,
                    _policy_values(lines),
                )
            )
        for (name, group), lines in found.groups.items():
            values = {"priority": {}} if "priority critical" in lines else {}
            instances.append(
                Instance(
                    "group",
                    {**where, "name": name, "group": group},
                    f"Flow policy {name}: group {group}{suffix}",
                    (),
                    values,
                )
            )
        for role, ident in found.entries:
            words = " ".join(f"{k} {v}" for k, v in ident.items() if k not in ("seq", "action"))
            instances.append(
                Instance(
                    role,
                    {**where, **ident},
                    f"{_ROLE_WORDS[role]} entry {ident['seq']}: {words} {ident['action']}{suffix}",
                )
            )
        for (group, source), lines in found.definitions.items():
            instances.append(
                Instance(
                    "definition",
                    {**where, "group": group, "source": source},
                    f"Flow {source} to {group}{suffix}",
                    (),
                    _definition_values(lines),
                )
            )
    return instances


def _external_links(config: str) -> list[Instance]:
    tree = parse_vxlan_config(config)
    found = []
    for line in tree.children():
        if line.startswith("interface ") and "nbm external-link" in tree.children(line):
            name = line.split(" ", 1)[1]
            found.append(
                Instance(
                    "interface",
                    {"interface": name},
                    f"{name}: external link",
                    (),
                    {"external_link": {}},
                )
            )
    return found


def parse_nbm(bodies: list[Any], config: str | None) -> ProtocolView:
    """The page from the ``COMMANDS`` bodies, in order, and the configuration text (None
    when the switch did not show it)."""

    def body(index: int) -> Any:
        return bodies[index] if index < len(bodies) else None

    default_rows, policers = _defaults(body(0))
    notes: tuple[str, ...] = ()
    if config is None:
        instances = [Instance("global", {"vrf": DEFAULT_VRF}, "Whole switch")]
        notes = (
            "The switch did not show its configuration to NXray's account: the flow "
            "policies, host policy entries and flow definitions are listed below, but their "
            "current values are not filled in.",
        )
    else:
        instances = [*_instances(parse_nbm_config(config), policers), *_external_links(config)]
    tables = (
        Table(
            "Defaults",
            (
                "VRF",
                "Mode",
                "Flow bandwidth",
                "DSCP",
                "Policer",
                "Kept for unicast",
                "Receivers only",
                "ASM ranges",
                "Senders / local / PIM receivers",
            ),
            tuple(default_rows),
            empty="The switch reported no NBM defaults.",
        ),
        Table(
            "Flow policies",
            ("Policy", "VRF", "Groups", "Bandwidth", "DSCP", "Policer", "Priority"),
            tuple(_flow_policies(body(1))),
            empty="No flow policies: every group gets the default flow settings.",
        ),
        Table(
            "Host policies",
            ("Kind", "VRF", "Entry", "Host", "Sender", "Groups", "Action"),
            tuple(_host_policies([body(2), body(3), body(4)])),
            empty="No host policies.",
        ),
        Table(
            "Flows",
            ("VRF", "Flows", "(*,G)", "(S,G)", "Total"),
            tuple(_summary(body(5))),
            empty="No flows.",
            note="Read when the page loads.",
        ),
        Table(
            "Defined flows",
            ("VRF", "Group", "Sender", "State", "Out of", "To receivers"),
            tuple(_static_flows(body(6))),
            empty="No flow definitions.",
        ),
        Table(
            "Interface bandwidth",
            (
                "Interface",
                "In: free of total",
                "Out: free of total",
                "Unicast reserved",
                "External link",
            ),
            tuple(_bandwidth(body(7))),
            empty="The switch reported no NBM interfaces.",
        ),
    )
    return ProtocolView(tuple(instances), tables, notes)


NBM = Protocol(
    key="nbm",
    name="Non-blocking multicast",
    summary="Bandwidth reserved for each multicast flow, for media streams",
    features=(FEATURE,),
    commands=COMMANDS,
    parse=lambda bodies: parse_nbm(bodies, None),
    scopes=SCOPES,
    about=(
        "Give the media groups flow policies with their bandwidth, then say which hosts may "
        "send and receive. PIM and IGMP set the flows up (PIM page, Protocols); NBM checks "
        "each one fits."
    ),
)


@dataclass(frozen=True)
class NbmPage:
    """Everything the Non-blocking multicast page shows."""

    protocol: Protocol
    view: ProtocolView
    interfaces: tuple[str, ...]  # the routed front ports (external links)
    vrfs: tuple[str, ...]  # default, management, then the others
    problem: str = ""
    missing: tuple[str, ...] = ()  # the nbm feature, when it is off


def load_nbm_page(client: NxapiClient) -> NbmPage:
    """One request for the feature, interfaces and VRFs, the TCAM regions as text; while
    nbm is on, one for its state and the configuration text."""
    feature, brief, vrf_body, vrf_members = client.show(*PAGE_COMMANDS)
    routed = tuple(
        name
        for name in layer3_interfaces(brief, parse_vrf_members(vrf_members))
        if name.startswith("Ethernet")
    )
    vrfs = vrf_choices(vrf_body)
    states = feature_states(feature)
    try:
        sizes = {
            region: size for region, _, size in parse_tcam_regions(client.show_text(TCAM_COMMAND))
        }
    except NxapiCommandError:
        sizes = {}
    problems = [VXLAN_ON] if states.get(VXLAN_FEATURE, False) else []
    if sizes.get(NBM_REGION) == "0":
        problems.append(NO_TCAM)
    if not states.get(FEATURE, False):
        return NbmPage(NBM, ProtocolView(), routed, vrfs, " ".join(problems), (FEATURE,))
    try:
        bodies = client.show(*COMMANDS)
    except NxapiCommandError as exc:
        bodies = []
        problems.append(f"The switch did not report NBM: {exc}")
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = None
    return NbmPage(NBM, parse_nbm(bodies, config), routed, vrfs, " ".join(problems))


def check_nbm_place(page: NbmPage, ident: dict[str, str]) -> None:
    """Refuse a VRF the switch does not have (``nbm vrf`` would make it) and an interface
    that is not a routed front port."""
    vrf = ident.get("vrf", "").strip()
    if vrf and vrf != DEFAULT_VRF and vrf not in page.vrfs:
        raise ValueError(f"the switch has no VRF {vrf}; make it on the Routing page first")
    interface = ident.get("interface", "").strip()
    if interface and interface not in page.interfaces:
        known = ", ".join(page.interfaces) or "none"
        raise ValueError(
            f"{interface} is not a routed front port on the switch (an external link must "
            f"be one); those are: {known}"
        )


def build_nbm_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Non-blocking multicast page; a flow policy's name may hold
    letters and digits only (the switch refuses a ``-``)."""
    name = ident.get("name", "").strip()
    if scope in ("policy", "group") and name and not _POLICY_NAME.fullmatch(name):
        raise ValueError("a flow policy's name is 1 to 63 letters and digits")
    return build_change(NBM, scope, setting, action, ident, values)
