"""QoS: class-maps and policy-maps (classification, network-qos and queuing), where they
are applied, and the queue counters.

The page is described with the same parts as the routing protocol pages
(``app/protocols.py``): scopes (a class-map, a policy-map, a class inside a policy-map,
a port, the system), each setting the one configuration line it sends with checked
values in its blanks, and ``build_change`` building the lines. ``NxapiClient.configure_qos``
sends them.

Three kinds of policy-map exist on a Nexus 9000 and the page has a part for each:

* ``type qos`` (classification): class-maps match traffic (DSCP, CoS, precedence, an ACL,
  RTP ports), the policy-map's classes set a QoS group, DSCP, CoS or precedence and may
  police; the policy is applied to a port as ``service-policy type qos input``;
* ``type network-qos``: a class per QoS group with its MTU and pause (PFC); applied to the
  whole switch under ``system qos``;
* ``type queuing``: the egress queues (bandwidth, priority, shaping, queue limit). The
  queuing classes are the switch's own (``c-out-8q-q3``), so none are made; applied
  under ``system qos``.

Read from the switch (all JSON): ``show class-map type qos``, ``show policy-map type qos``
(these two answer nothing at all while no policy was made), ``show class-map type
network-qos``, ``show policy-map type network-qos``, ``show policy-map type queuing``,
``show policy-map interface brief`` (what is applied to each port), ``show policy-map
system`` (what is applied to the system) and ``show queuing interface`` (the counters).

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-10) with throwaway classes and policies on
Ethernet1/54, all removed afterwards: every line of the classification and queuing
policies and of the port attachment, and the JSON of all the commands above. What the
switch showed and the page works around:

* ``class-map type qos`` takes ``match dscp`` (numbers; names such as af11 were refused),
  ``cos``, ``precedence``, ``access-group name`` and ``ip rtp``; ``match ip dscp``, ``match
  vlan``, ``match qos-group`` and ``match ipv6 access-group`` were refused;
* a class-map's ``description`` takes the rest of the line;
* ``set cos`` and ``police`` are removed with the whole line (``no set cos 5``,
  ``no police cir 5 mbps conform transmit violate drop``): ``no set cos`` and ``no police``
  alone were refused;
* ``set qos-group`` is 0 to 7;
* a ``type qos`` policy attaches to a port as ``input`` only ("not supported in output
  direction"); a queuing policy cannot be attached to a port, and the default policies cannot
  be added by hand;
* a queuing class takes ``bandwidth remaining percent`` or ``priority level``, not both;
  ``random-detect`` was refused; ``set cos`` in a network-qos class was refused.

Not tried, because they change the whole switch: ``system qos`` with a ``service-policy``
line, and so everything the page sends in the System part. Those lines are written from
Cisco's NX-OS 9.3 guide.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

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
    port_field,
    table_rows,
)
from app.switch import text

PAGE_COMMANDS = (
    "show interface brief",
    "show class-map type network-qos",
    "show policy-map type network-qos",
    "show policy-map type queuing",
    "show policy-map interface brief",
    "show policy-map system",
)
QOS_CLASSES_COMMAND = "show class-map type qos"
QOS_POLICIES_COMMAND = "show policy-map type qos"
COUNTERS_COMMAND = "show queuing interface"
NAME_MAX = 40
COUNTER_ROWS = 40

# The switch's own classes and policies. They are shown in the tables but not as places
# to change: the switch refuses edits to the defaults, and a name like these cannot be made.
_BUILT_IN_CLASS = re.compile(r"class-default|c-(?:out-)?(?:8q-)?(?:nq|q)(?:[0-9]|-default)")
_BUILT_IN_POLICY = re.compile(r"default-[a-z0-9-]*policy")
# The queuing classes of the default policies; a queuing policy uses these, none are made.
QUEUING_CLASSES = (
    "c-out-8q-q-default",
    *(f"c-out-8q-q{n}" for n in range(1, 8)),
    "c-out-q-default",
    *(f"c-out-q{n}" for n in range(1, 4)),
)
UNITS = ("kbps", "mbps", "gbps")


def is_built_in(name: str) -> bool:
    """True for a class-map or policy-map the switch has by itself."""
    return bool(_BUILT_IN_CLASS.fullmatch(name) or _BUILT_IN_POLICY.fullmatch(name))


def _name(key: str, label: str, hint: str = "") -> Field:
    return Field(
        key,
        label,
        "name",
        maximum=NAME_MAX,
        hint=hint or f"Up to {NAME_MAX} letters, digits, '.', '_' or '-'",
    )


def _description() -> Setting:
    return Setting(
        key="description",
        label="Description",
        line="description {text}",
        no_line="no description",
        group="Description",
        fields=(Field("text", "Description", "text", maximum=200),),
        help="A note on what it is for.",
    )


def _set(key: str, label: str, line: str, field: Field, help: str) -> Setting:
    return Setting(
        key=key, label=label, line=line, group="Mark the traffic", fields=(field,), help=help
    )


# ---- classification (type qos) ---------------------------------------------------------

_CLASS_MAP = Scope(
    key="cmap",
    label="Class-map (match traffic)",
    ident=(
        _name("cmap", "Class-map"),
        Field(
            "mode",
            "Match",
            "choice",
            choices=("match-any", "match-all"),
            hint="match-any: traffic that fits one of the lines; match-all: traffic that fits "
            "every line",
        ),
    ),
    enter=("class-map type qos {mode} {cmap}",),
    create=True,
    create_label="Make a class-map",
    delete=("no class-map type qos {cmap}",),
    delete_warning="A class-map still used by a policy-map is refused by the switch.",
    help="Picks out traffic for a policy-map's class. Add the lines it matches below; to "
    "remove a line, type the same values again.",
    settings=(
        _description(),
        Setting(
            key="match_dscp",
            label="Match DSCP",
            line="match dscp {values}",
            no_line="no match dscp {values}",
            group="Match",
            fields=(
                Field(
                    "values",
                    "DSCP values",
                    "numlist",
                    minimum=0,
                    maximum=63,
                    hint="Numbers 0 to 63, such as 46 or 8,10-12 (46 is expedited forwarding)",
                    placeholder="46",
                ),
            ),
            help="Traffic marked with these DSCP values.",
        ),
        Setting(
            key="match_cos",
            label="Match CoS",
            line="match cos {values}",
            no_line="no match cos {values}",
            group="Match",
            fields=(
                Field(
                    "values",
                    "CoS values",
                    "numlist",
                    minimum=0,
                    maximum=7,
                    hint="Numbers 0 to 7, such as 5 or 0-3",
                    placeholder="5",
                ),
            ),
            help="Traffic with these 802.1p priority values in its VLAN tag.",
        ),
        Setting(
            key="match_precedence",
            label="Match IP precedence",
            line="match precedence {values}",
            no_line="no match precedence {values}",
            group="Match",
            fields=(
                Field(
                    "values",
                    "Precedence",
                    "numlist",
                    minimum=0,
                    maximum=7,
                    hint="Numbers 0 to 7, such as 5",
                    placeholder="5",
                ),
            ),
            help="Traffic with these IP precedence values.",
        ),
        Setting(
            key="match_acl",
            label="Match an ACL",
            line="match access-group name {acl}",
            no_line="no match access-group name {acl}",
            group="Match",
            fields=(
                Field(
                    "acl",
                    "ACL",
                    "name",
                    maximum=64,
                    hint="An IPv4 or MAC ACL made on the ACLs page",
                ),
            ),
            help="Traffic the ACL permits.",
        ),
        Setting(
            key="match_rtp",
            label="Match RTP ports",
            line="match ip rtp {ports}",
            no_line="no match ip rtp {ports}",
            group="Match",
            fields=(
                Field(
                    "ports",
                    "UDP ports",
                    "numlist",
                    minimum=2000,
                    maximum=65535,
                    hint="A range of UDP ports from 2000, such as 16384-32767",
                    placeholder="16384-32767",
                ),
            ),
            help="Voice and video (RTP) traffic on these UDP ports.",
        ),
    ),
)

_POLICY = Scope(
    key="policy",
    label="Policy-map (mark and limit traffic)",
    ident=(_name("policy", "Policy-map"),),
    enter=("policy-map type qos {policy}",),
    create=True,
    create_label="Make a policy-map",
    delete=("no policy-map type qos {policy}",),
    delete_warning="Remove it from every port first: the switch refuses to delete a policy-map "
    "that is still applied.",
    help="A list of classes, each with what is done to its traffic. Make the policy-map, "
    "add its classes below, then apply it to a port.",
)

_POLICY_CLASS = Scope(
    key="pclass",
    label="Class in a policy-map",
    ident=(
        _name("policy", "Policy-map"),
        _name("class", "Class-map", "A class-map made above, or class-default for the rest"),
    ),
    enter=("policy-map type qos {policy}", "class {class}"),
    create=True,
    create_label="Add a class to a policy-map",
    delete=("policy-map type qos {policy}", "no class {class}"),
    delete_warning="The class and what it does are removed from the policy-map.",
    help="Traffic is given to the first class (top down) that matches it. A class added "
    "goes after the ones already there; class-default catches the rest.",
    settings=(
        _set(
            "set_qos_group",
            "Set QoS group",
            "set qos-group {group}",
            Field("group", "QoS group", "int", minimum=0, maximum=7, hint="0 to 7"),
            "The internal class the traffic is put in; the queuing policy and the "
            "network-qos policy work on it.",
        ),
        _set(
            "set_dscp",
            "Set DSCP",
            "set dscp {dscp}",
            Field("dscp", "DSCP", "int", minimum=0, maximum=63, hint="0 to 63"),
            "Re-mark the traffic's DSCP value.",
        ),
        _set(
            "set_cos",
            "Set CoS",
            "set cos {cos}",
            Field("cos", "CoS", "int", minimum=0, maximum=7, hint="0 to 7"),
            "Re-mark the traffic's 802.1p priority.",
        ),
        _set(
            "set_precedence",
            "Set IP precedence",
            "set precedence {precedence}",
            Field("precedence", "Precedence", "int", minimum=0, maximum=7, hint="0 to 7"),
            "Re-mark the traffic's IP precedence.",
        ),
        Setting(
            key="police",
            label="Limit the rate",
            line="police cir {rate} {unit} [bc {burst} ms] conform transmit violate drop",
            group="Limit",
            fields=(
                Field("rate", "Rate", "int", minimum=1, maximum=100000000, hint="A whole number"),
                Field("unit", "Unit", "choice", choices=UNITS),
                Field(
                    "burst",
                    "Burst (ms)",
                    "int",
                    minimum=1,
                    maximum=1000,
                    optional=True,
                    hint="Leave empty for the switch's 200",
                ),
            ),
            help="Traffic over the rate is dropped. To remove it, type the same rate and "
            "unit again.",
        ),
        Setting(
            key="police_percent",
            label="Limit the rate (percent of the port)",
            line="police cir percent {percent} conform transmit violate drop",
            group="Limit",
            fields=(Field("percent", "Percent", "int", minimum=1, maximum=100, hint="1 to 100"),),
            help="Traffic over this share of the port's speed is dropped. To remove it, type "
            "the same percent again.",
        ),
    ),
)

_PORT = Scope(
    key="qos_port",
    label="Port",
    ident=(port_field(),),
    enter=("interface {port}",),
    help="Apply a policy-map to the traffic coming in on a port. The switch takes a "
    "classification policy as input only.",
    settings=(
        Setting(
            key="service_policy",
            label="Incoming policy",
            line="service-policy type qos input {policy}",
            no_line="no service-policy type qos input {policy}",
            group="Policy",
            fields=(_name("policy", "Policy-map", "A policy-map made above"),),
            help="Marks and limits the traffic coming in on this port. To take it off, type "
            "the same policy again.",
        ),
    ),
)

# ---- network-qos -----------------------------------------------------------------------

_NQ_MAP = Scope(
    key="nqmap",
    label="Network-qos class-map",
    ident=(_name("nqmap", "Class-map"),),
    enter=("class-map type network-qos match-any {nqmap}",),
    create=True,
    create_label="Make a network-qos class-map",
    delete=("no class-map type network-qos {nqmap}",),
    delete_warning="A class-map still used by a policy-map is refused by the switch.",
    help="Picks out the QoS groups a network-qos class covers.",
    settings=(
        Setting(
            key="match_group",
            label="Match QoS groups",
            line="match qos-group {groups}",
            no_line="no match qos-group {groups}",
            group="Match",
            fields=(
                Field(
                    "groups",
                    "QoS groups",
                    "numlist",
                    minimum=0,
                    maximum=7,
                    hint="Numbers 0 to 7, such as 3",
                    placeholder="3",
                ),
            ),
            help="The QoS groups a classification policy sets.",
        ),
    ),
)

_NQ_POLICY = Scope(
    key="nqpolicy",
    label="Network-qos policy-map",
    ident=(_name("nqpolicy", "Policy-map"),),
    enter=("policy-map type network-qos {nqpolicy}",),
    create=True,
    create_label="Make a network-qos policy-map",
    delete=("no policy-map type network-qos {nqpolicy}",),
    delete_warning="The switch refuses to delete one that is applied to the system.",
    help="Sets the MTU and pause (PFC) of each QoS group. It does nothing until it is "
    "applied under System below.",
)

_NQ_CLASS = Scope(
    key="nqclass",
    label="Class in a network-qos policy-map",
    ident=(
        _name("nqpolicy", "Policy-map"),
        _name("nqclass", "Class-map", "A network-qos class-map made above"),
    ),
    enter=("policy-map type network-qos {nqpolicy}", "class type network-qos {nqclass}"),
    create=True,
    create_label="Add a class to a network-qos policy-map",
    delete=("policy-map type network-qos {nqpolicy}", "no class type network-qos {nqclass}"),
    delete_warning="The class and its settings are removed from the policy-map.",
    help="What the switch does with the traffic of one class.",
    settings=(
        Setting(
            key="mtu",
            label="MTU",
            line="mtu {mtu}",
            no_line="no mtu",
            group="Class",
            fields=(Field("mtu", "Bytes", "int", minimum=1500, maximum=9216, hint="1500 to 9216"),),
            help="The largest packet of this class.",
        ),
        Setting(
            key="pause",
            label="Pause (PFC)",
            line="pause pfc-cos {cos}",
            no_line="no pause pfc-cos {cos}",
            group="Class",
            fields=(Field("cos", "CoS", "int", minimum=0, maximum=7, hint="0 to 7"),),
            help="Priority flow control: the class stops its sender with a pause frame instead "
            "of dropping. Needs priority flow control on the ports too.",
            warning="Pause changes how the switch treats this traffic once the policy is "
            "applied to the system.",
        ),
    ),
)

# ---- queuing ---------------------------------------------------------------------------

_Q_POLICY = Scope(
    key="qpolicy",
    label="Queuing policy-map",
    ident=(_name("qpolicy", "Policy-map"),),
    enter=("policy-map type queuing {qpolicy}",),
    create=True,
    create_label="Make a queuing policy-map",
    delete=("no policy-map type queuing {qpolicy}",),
    delete_warning="The switch refuses to delete one that is applied to the system.",
    help="Sets how the output queues share a port. It does nothing until it is applied "
    "under System below.",
)

_Q_CLASS = Scope(
    key="qclass",
    label="Queue in a queuing policy-map",
    ident=(
        _name("qpolicy", "Policy-map"),
        Field(
            "qclass",
            "Queue",
            "choice",
            choices=QUEUING_CLASSES,
            hint="The switch's own queues: c-out-8q-q3 is the one for QoS group 3",
        ),
    ),
    enter=("policy-map type queuing {qpolicy}", "class type queuing {qclass}"),
    create=True,
    create_label="Add a queue to a queuing policy-map",
    delete=("policy-map type queuing {qpolicy}", "no class type queuing {qclass}"),
    delete_warning="The queue's settings are removed from the policy-map.",
    help="A queue takes either a share of the bandwidth or strict priority, not both.",
    settings=(
        Setting(
            key="bandwidth",
            label="Bandwidth share",
            line="bandwidth remaining percent {percent}",
            no_line="no bandwidth remaining percent {percent}",
            group="Queue",
            fields=(Field("percent", "Percent", "int", minimum=0, maximum=100, hint="0 to 100"),),
            help="The share of the bandwidth left after the priority queue. The shares add up "
            "to 100.",
        ),
        Setting(
            key="priority",
            label="Strict priority",
            line="priority level {level}",
            no_line="no priority level {level}",
            group="Queue",
            fields=(Field("level", "Level", "int", minimum=1, maximum=1, hint="1"),),
            help="Sent before every other queue.",
        ),
        Setting(
            key="shape",
            label="Shape the rate",
            line="shape min {minimum} {unit} max {maximum} {unit}",
            no_line="no shape min {minimum} {unit} max {maximum} {unit}",
            group="Queue",
            fields=(
                Field("minimum", "Minimum", "int", minimum=0, maximum=100000000),
                Field("maximum", "Maximum", "int", minimum=1, maximum=100000000),
                Field("unit", "Unit", "choice", choices=UNITS),
            ),
            help="The queue is held between these rates. To remove it, type the same values again.",
        ),
        Setting(
            key="queue_limit",
            label="Queue limit",
            line="queue-limit {size} bytes",
            no_line="no queue-limit {size} bytes",
            group="Queue",
            fields=(Field("size", "Bytes", "int", minimum=1, maximum=1000000000),),
            help="How much the queue holds before it drops. To remove it, type the same "
            "size again.",
        ),
    ),
)

# ---- the system ------------------------------------------------------------------------

_SYSTEM = Scope(
    key="system",
    label="System (the whole switch)",
    ident=(),
    enter=("system qos",),
    help="Network-qos and queuing policies are applied to the whole switch, not to a port.",
    settings=(
        Setting(
            key="network_qos",
            label="Network-qos policy",
            line="service-policy type network-qos {policy}",
            no_line="no service-policy type network-qos {policy}",
            group="Apply",
            fields=(_name("policy", "Policy-map", "A network-qos policy-map made above"),),
            help="Applies the network-qos policy to every port.",
            warning="This changes the whole switch, not one port. Not yet tried on a switch.",
        ),
        Setting(
            key="queuing_output",
            label="Queuing policy (output)",
            line="service-policy type queuing output {policy}",
            no_line="no service-policy type queuing output {policy}",
            group="Apply",
            fields=(_name("policy", "Policy-map", "A queuing policy-map made above"),),
            help="Applies the queuing policy to the output queues of every port.",
            warning="This changes the whole switch, not one port. Not yet tried on a switch.",
        ),
        Setting(
            key="qos_input",
            label="Classification policy (input)",
            line="service-policy type qos input {policy}",
            no_line="no service-policy type qos input {policy}",
            group="Apply",
            fields=(_name("policy", "Policy-map", "A classification policy-map made above"),),
            help="Applies the classification policy to the traffic coming in on every port.",
            warning="This changes the whole switch, not one port. Not yet tried on a switch.",
        ),
    ),
)


# ---- reading the answers ----------------------------------------------------------------


def _first(row: dict[str, Any], *keys: str) -> str:
    """The first of ``keys`` the row has, as text ('' for none)."""
    for key in keys:
        if value := text(row.get(key)):
            return value
    return ""


def _match_words(row: dict[str, Any]) -> list[str]:
    """What a class-map matches, as 'dscp 46'."""
    found = []
    for match in table_rows(row, "TABLE_match", "ROW_match"):
        for key, words in (
            ("dscp-list", "dscp"),
            ("cos-list", "cos"),
            ("precedence-list", "precedence"),
            ("match-acl-name", "access-group"),
            ("rtp-port-list", "ip rtp"),
            ("xqos-group-list", "qos-group"),
        ):
            if value := _first(match, key):
                found.append(f"{words} {value}")
        if _first(match, "prot"):
            found.append("protocol")
    return found


def _action_words(row: dict[str, Any]) -> tuple[list[str], dict[str, dict[str, str]]]:
    """What a policy-map class does, as words and as field values of the settings."""
    words: list[str] = []
    values: dict[str, dict[str, str]] = {}
    # Network-qos answers call their actions TABLE_xaction.
    for action in (
        *table_rows(row, "TABLE_action", "ROW_action"),
        *table_rows(row, "TABLE_xaction", "ROW_xaction"),
    ):
        if group := _first(action, "qos-group"):
            words.append(f"set qos-group {group}")
            values["set_qos_group"] = {"group": group}
        if dscp := _first(action, "dscp", "dscp-enum"):
            words.append(f"set dscp {dscp}")
            if dscp.isdigit():
                values["set_dscp"] = {"dscp": dscp}
        if cos := _first(action, "cos"):
            words.append(f"set cos {cos}")
            values["set_cos"] = {"cos": cos}
        if precedence := _first(action, "prec"):
            words.append(f"set precedence {precedence}")
            values["set_precedence"] = {"precedence": precedence}
        if rate := _first(action, "cir"):
            unit = _first(action, "cir-rate-units")
            burst = _first(action, "bc")
            words.append(f"police {rate} {unit}" + (f", burst {burst} ms" if burst else ""))
            if unit == "percent":
                values["police_percent"] = {"percent": rate}
            elif unit in UNITS:
                values["police"] = {"rate": rate, "unit": unit}
        if _first(action, "mtu"):
            words.append(f"mtu {_first(action, 'mtu')}")
            values["mtu"] = {"mtu": _first(action, "mtu")}
        if cos_list := _first(action, "pfc-cos-list"):
            words.append(f"pause pfc-cos {cos_list}")
            values["pause"] = {"cos": cos_list}
        if level := _first(action, "prio-level"):
            words.append(f"priority level {level}")
            values["priority"] = {"level": level}
        if share := _first(action, "rem-bw-rate"):
            words.append(f"bandwidth remaining percent {share}")
            values["bandwidth"] = {"percent": share}
        if size := _first(action, "qlim-size"):
            words.append(f"queue-limit {size} {_first(action, 'size-units') or 'bytes'}")
            values["queue_limit"] = {"size": size}
        if _first(action, "shape-max-rate"):
            low = _first(action, "shape-min-rate") or "0"
            unit = _first(action, "max-rate-units")
            high = _first(action, "shape-max-rate")
            words.append(f"shape min {low} max {high} {unit}")
            if unit in UNITS:
                values["shape"] = {"minimum": low, "maximum": high, "unit": unit}
    return words, values


def _description_value(row: dict[str, Any]) -> dict[str, dict[str, str]]:
    description = _first(row, "desc")
    return {"description": {"text": description}} if description else {}


def _qos_class_maps(body: dict[str, Any]) -> list[Instance]:
    found = []
    for row in table_rows(body, "TABLE_cmap", "ROW_cmap"):
        name = _first(row, "cmap-name-out", "cmap-name")
        if not name or is_built_in(name):
            continue
        mode = _first(row, "any_or_all") or "match-any"
        matches = _match_words(row)
        facts = [("Match", mode), ("Matches", "; ".join(matches) or "nothing yet")]
        found.append(
            Instance(
                "cmap",
                {"cmap": name, "mode": mode},
                f"Class-map {name}",
                tuple(facts),
                _description_value(row),
            )
        )
    return found


def _class_places(
    policy: str,
    entries: list[dict[str, Any]],
    class_scope: str,
    policy_key: str,
    class_key: str,
    name_key: str,
    match_key: str,
) -> tuple[list[str], list[Instance]]:
    """The classes of one policy-map as words for its card and as places of their own."""
    summary = []
    places = []
    for entry in entries:
        name = _first(entry, name_key)
        if not name:
            continue
        words, values = _action_words(entry)
        for match in table_rows(entry, "TABLE_xmatch", "ROW_xmatch"):
            if groups := _first(match, match_key):
                words.insert(0, f"match qos-group {groups}")
        done = ", ".join(words) or "nothing set"
        summary.append(f"{name}: {done}")
        places.append(
            Instance(
                class_scope,
                {policy_key: policy, class_key: name},
                f"{policy}: {name}",
                (("Does", done),),
                values,
            )
        )
    return summary, places


def _policy_places(
    body: dict[str, Any],
    *,
    network_qos: bool,
    policy_scope: str,
    class_scope: str,
    policy_key: str,
    class_key: str,
    applied: dict[str, list[str]],
) -> list[Instance]:
    """A place for each policy-map that is not the switch's own, then one for each of its
    classes. ``network_qos`` answers use other names than the qos and queuing ones."""
    found: list[Instance] = []
    if network_qos:
        table, row, names = ("TABLE_xpmap", "ROW_xpmap", ("xpmap-name",))
        class_table, class_row, class_name = ("TABLE_xcmap", "ROW_xcmap", "xcmap-name")
    else:
        table, row, names = ("TABLE_pmap", "ROW_pmap", ("pmap-name-out", "pmap-name"))
        class_table, class_row, class_name = ("TABLE_cmap", "ROW_cmap", "cmap-name")
    for policy in table_rows(body, table, row):
        name = _first(policy, *names)
        if not name or is_built_in(name):
            continue
        summary, places = _class_places(
            name,
            table_rows(policy, class_table, class_row),
            class_scope,
            policy_key,
            class_key,
            class_name,
            "xqos-group-list",
        )
        facts = [("Classes", "; ".join(summary) or "none yet")]
        if where := applied.get(name):
            facts.append(("Applied to", ", ".join(where)))
        found.append(Instance(policy_scope, {policy_key: name}, f"Policy-map {name}", tuple(facts)))
        found.extend(places)
    return found


def _nq_class_maps(body: dict[str, Any]) -> list[Instance]:
    found = []
    for row in table_rows(body, "TABLE_cmap", "ROW_cmap"):
        name = _first(row, "xcmap-name", "cmap-name")
        if not name or is_built_in(name):
            continue
        groups = [
            _first(m, "xqos-group-list") for m in table_rows(row, "TABLE_xmatch", "ROW_xmatch")
        ]
        found.append(
            Instance(
                "nqmap",
                {"nqmap": name},
                f"Class-map {name}",
                (("Matches", ", ".join(f"qos-group {g}" for g in groups if g) or "nothing yet"),),
            )
        )
    return found


def parse_applied(brief: dict[str, Any]) -> dict[str, dict[str, str]]:
    """What is applied to each port, from ``show policy-map interface brief``:
    ``{port: {"qos": name, "queuing": name}}`` for a port that has one that is not the
    switch's own."""
    found: dict[str, dict[str, str]] = {}
    for row in table_rows(brief, "TABLE_ifvlanstr", "ROW_ifvlanstr"):
        port = _first(row, "if-vlan-str")
        qos = _first(row, "in-pmap-qos")
        queuing = _first(row, "out-pmap-que")
        mine: dict[str, str] = {}
        if qos and not is_built_in(qos):
            mine["qos"] = qos
        if queuing and not is_built_in(queuing):
            mine["queuing"] = queuing
        if port and mine:
            found[port] = mine
    return found


def parse_system(system: dict[str, Any]) -> list[tuple[str, str]]:
    """The policies applied to the whole switch, from ``show policy-map system``, as
    (kind, name)."""
    found = []
    for row in table_rows(system, "TABLE_xpmap", "ROW_xpmap"):
        if name := _first(row, "xpmap-name"):
            found.append(("network-qos", name))
    for row in table_rows(system, "TABLE_pmap", "ROW_pmap"):
        name = _first(row, "pmap-name", "pmap-name-out")
        kind = _first(row, "yqos-or-q") or "qos"
        direction = _first(row, "in-or-out")
        if name:
            found.append((f"{kind} {direction}".strip(), name))
    return found


def parse_counters(body: dict[str, Any]) -> list[tuple[str, ...]]:
    """The busy output queues from ``show queuing interface``: a row for each port and
    QoS group that sent or dropped something, as (port, group, sent, dropped, queued)."""
    rows = []
    for port in table_rows(body, "TABLE_module", "ROW_module"):
        for entry in table_rows(port, "TABLE_queuing_interface", "ROW_queuing_interface"):
            if _first(entry, "dir") != "Egress":
                continue
            name = _first(entry, "if_name_str")
            for group in table_rows(entry, "TABLE_qosgrp_egress_stats", "ROW_qosgrp_egress_stats"):
                seen = {"Tx": 0, "WRED/AFD & Tail Drop": 0, "Q Depth": 0}
                for stat in table_rows(
                    group, "TABLE_qosgrp_egress_stats_entry", "ROW_qosgrp_egress_stats_entry"
                ):
                    kind = _first(stat, "eq-stat-type")
                    if kind not in seen:
                        continue
                    wanted = "Byts" if kind == "Q Depth" else "Pkts"
                    if _first(stat, "eq-stat-units") != wanted:
                        continue
                    for key in ("eq-uc-stat-value", "eq-mc-stat-value"):
                        value = _first(stat, key)
                        seen[kind] += int(value) if value.isdigit() else 0
                if any(seen.values()):
                    rows.append(
                        (
                            name,
                            _first(group, "eq-qosgrp"),
                            str(seen["Tx"]),
                            str(seen["WRED/AFD & Tail Drop"]),
                            str(seen["Q Depth"]),
                        )
                    )
    return rows


def parse_qos(bodies: list[dict[str, Any]], counters: dict[str, Any] | None = None) -> ProtocolView:
    """The page from the answers, in the order of ``QOS_ANSWERS``: the qos class-maps,
    the qos policy-maps, the network-qos class-maps and policy-maps, the queuing
    policy-maps, what is applied to each port, what is applied to the system."""
    padded = [*bodies, *({} for _ in range(QOS_ANSWERS - len(bodies)))]
    qos_maps, qos_policies, nq_maps, nq_policies, queuing, brief, system = padded[:QOS_ANSWERS]
    applied = parse_applied(brief)
    by_policy: dict[str, list[str]] = {}
    for port, mine in applied.items():
        for name in mine.values():
            by_policy.setdefault(name, []).append(port)
    instances: list[Instance] = [
        *_qos_class_maps(qos_maps),
        *_policy_places(
            qos_policies,
            network_qos=False,
            policy_scope="policy",
            class_scope="pclass",
            policy_key="policy",
            class_key="class",
            applied=by_policy,
        ),
        *(
            Instance(
                "qos_port",
                {"port": port},
                port,
                (("Incoming policy", mine.get("qos", "none")),),
                {"service_policy": {"policy": mine["qos"]}} if "qos" in mine else {},
            )
            for port, mine in applied.items()
            if "qos" in mine
        ),
        *_nq_class_maps(nq_maps),
        *_policy_places(
            nq_policies,
            network_qos=True,
            policy_scope="nqpolicy",
            class_scope="nqclass",
            policy_key="nqpolicy",
            class_key="nqclass",
            applied={},
        ),
        *_policy_places(
            queuing,
            network_qos=False,
            policy_scope="qpolicy",
            class_scope="qclass",
            policy_key="qpolicy",
            class_key="qclass",
            applied={},
        ),
    ]
    system_policies = parse_system(system)
    instances.append(
        Instance(
            "system",
            {},
            "System policies",
            tuple((kind, name) for kind, name in system_policies) or (("Policies", "none"),),
        )
    )
    built_in = sorted(
        {
            (kind, name)
            for body, kind in (
                (nq_policies, "network-qos"),
                (queuing, "queuing"),
                (qos_policies, "qos"),
            )
            for row in [
                *table_rows(body, "TABLE_xpmap", "ROW_xpmap"),
                *table_rows(body, "TABLE_pmap", "ROW_pmap"),
            ]
            if (name := _first(row, "xpmap-name", "pmap-name-out", "pmap-name"))
            and is_built_in(name)
        }
    )
    tables = [
        Table(
            "Applied to ports",
            ("Port", "Incoming policy (qos)", "Output queuing policy"),
            tuple(
                (port, mine.get("qos", "-"), mine.get("queuing", "-"))
                for port, mine in sorted(applied.items())
            ),
            empty="No port has a policy of its own. Every port uses the switch's default "
            "queuing policy.",
        ),
        Table(
            "The switch's own policies",
            ("Type", "Policy-map"),
            tuple(built_in),
            empty="None reported.",
            note="These come with the switch and cannot be changed.",
        ),
    ]
    if counters is not None:
        # The queues that dropped most come first.
        rows = sorted(parse_counters(counters), key=lambda row: -int(row[3]))
        shown = rows[:COUNTER_ROWS]
        cut = f"The first {COUNTER_ROWS} of {len(rows)} queues that sent or dropped something."
        tables.append(
            Table(
                "Output queue counters",
                ("Port", "QoS group", "Packets sent", "Packets dropped", "Bytes queued now"),
                tuple(shown),
                empty="No output queue has sent or dropped a packet.",
                note=cut if len(rows) > COUNTER_ROWS else "",
            )
        )
    return ProtocolView(tuple(instances), tuple(tables))


QOS_ANSWERS = 7

QOS = Protocol(
    key="qos",
    name="QoS",
    summary="Mark, limit and queue traffic with class-maps and policy-maps",
    features=(),
    commands=(),
    parse=parse_qos,
    scopes=(
        _CLASS_MAP,
        _POLICY,
        _POLICY_CLASS,
        _PORT,
        _NQ_MAP,
        _NQ_POLICY,
        _NQ_CLASS,
        _Q_POLICY,
        _Q_CLASS,
        _SYSTEM,
    ),
    about=(
        "To mark or limit traffic: make a class-map, make a policy-map, add the class to "
        "it and apply the policy-map to a port. Network-qos and queuing policies are "
        "applied to the whole switch under System."
    ),
)


# ---- the page -----------------------------------------------------------------------------


@dataclass(frozen=True)
class QosPage:
    """Everything the QoS page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # the front ports and port-channels
    classes: tuple[str, ...] = ()  # the qos class-maps, for the check of a policy's classes
    nq_classes: tuple[str, ...] = ()  # the network-qos class-maps
    problem: str = ""
    missing: tuple[str, ...] = ()  # QoS needs no feature; kept for the template
    vlans: tuple[str, ...] = ()  # kept for the template


def _read_or_empty(client: NxapiClient, command: str) -> tuple[dict[str, Any], str]:
    """One show command's body, and a problem to tell. While no class-map or policy-map was
    made the switch prints nothing, which NX-API cannot turn into JSON: that is no body and
    no problem (seen on cisco-25gb 2026-11-10)."""
    try:
        (body,) = client.show(command)
    except NxapiCommandError as exc:
        message = str(exc).lower()
        if "cannot be parsed" in message or not message.strip():
            return {}, ""
        return {}, f"The switch did not answer {command!r}: {exc}"
    return body, ""


def load_qos_page(client: NxapiClient) -> QosPage:
    """One request for the ports, network-qos, queuing and applied policies, then one each
    for the qos class-maps, qos policy-maps and the queue counters (any of which may be
    empty)."""
    brief, *rest = client.show(*PAGE_COMMANDS)
    nq_maps, nq_policies, queuing, applied, system = rest
    problems = []
    qos_maps, problem = _read_or_empty(client, QOS_CLASSES_COMMAND)
    problems.append(problem)
    qos_policies, problem = _read_or_empty(client, QOS_POLICIES_COMMAND)
    problems.append(problem)
    counters, problem = _read_or_empty(client, COUNTERS_COMMAND)
    problems.append(problem)
    view = parse_qos(
        [qos_maps, qos_policies, nq_maps, nq_policies, queuing, applied, system], counters
    )
    return QosPage(
        QOS,
        view,
        all_port_names(brief),
        classes=tuple(
            _first(row, "cmap-name-out", "cmap-name")
            for row in table_rows(qos_maps, "TABLE_cmap", "ROW_cmap")
        ),
        nq_classes=tuple(
            _first(row, "xcmap-name", "cmap-name")
            for row in table_rows(nq_maps, "TABLE_cmap", "ROW_cmap")
        ),
        problem=" ".join(p for p in problems if p),
    )


def build_qos_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the QoS page."""
    return build_change(QOS, scope, setting, action, ident, values)
