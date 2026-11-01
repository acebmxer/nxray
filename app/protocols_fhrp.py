"""Gateway backup: HSRP, VRRP and VRRPv3, the three ways two switches share
one gateway address.

Devices on a network send everything for elsewhere to one gateway address.
With a gateway-backup protocol, two (or more) switches agree to share that
address: one answers for it (the active switch, or "master"), the other
watches and takes it over within seconds if the first one stops. Each shared
address lives in a numbered *group* on an interface; the switch with the
higher priority answers.

Read from the switch, in one request per page:

- HSRP (Cisco's own): ``show hsrp``, every group with its state, virtual
  address, priority, timers, authentication type, name and virtual MAC
  address. For an IPv6 group the switch shows only the link-local virtual
  address it made, and writes the group's configured global address into
  the secondary-address field as a garbled IPv4 address (``184.13.1.32``
  for ``2001:db8:1::fe`` on NX-OS 9.3(16)); the parser drops it.
- VRRP (the standard, version 2, IPv4 only): ``show vrrp detail`` and
  ``show vrrp``.
- VRRPv3 (the standard, version 3, IPv4 and IPv6): ``show vrrpv3 detail``
  and ``show vrrpv3``.

What can be changed: a group made or deleted on a routed interface, and
every setting of it (virtual addresses, priority, taking over, timers,
authentication, tracking, name, MAC address, turned on or off), plus the
interface-wide HSRP settings (version, BFD, MAC refresh, burned-in MAC,
start-up delay).

Tried on cisco-25gb (NX-OS 9.3(16)) as NXray's restricted account: HSRP
``hsrp version 2``, ``hsrp 10`` with ``ip``, ``priority``, ``preempt``,
``timers 1 3``, ``authentication md5 key-chain`` and ``name``; ``hsrp 20
ipv6`` with ``ip 2001:db8:1::fe``; ``no hsrp 20 ipv6``; VRRP ``vrrp 30``
with ``address``, ``priority``, ``advertisement-interval``, ``preempt`` and
``no shutdown``; ``no vrrp 30``; VRRPv3 ``vrrpv3 40 address-family ipv4``
with ``address ... primary``, ``priority``, ``preempt``, ``timers
advertise`` and ``no shutdown``, ``vrrpv3 41 address-family ipv6`` with a
link-local primary and a global secondary; ``no vrrpv3 ... address-family
...``. The other lines follow Cisco's NX-OS 9.3 Unicast Routing guide and
command reference. Rows with a real active, standby or master router were
never seen live (nothing was plugged in); they are read by the same NX-API
field names, which Cisco documents for that output.
"""

from __future__ import annotations

import ipaddress
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
    table_rows,
    text,
)
from app.routing import long_name

# ---- shared fields -------------------------------------------------------------

_TRACK_MAX = 512  # tracked objects are numbered 1 to 512 (track ... global command)


def _int(name: str, label: str, low: int, high: int, **kw: Any) -> Field:
    return Field(name, label, "int", minimum=low, maximum=high, **kw)


def _shown(value: Any) -> str:
    """An address from the output, or "" for the switch's "nobody" values."""
    found = text(value)
    if found in ("", "0.0.0.0", "0::", "::", "Unknown", "unknown"):
        return ""
    return found


def _bodies(bodies: list[dict[str, Any]], count: int) -> list[Any]:
    found = list(bodies)[:count]
    return found + [{}] * (count - len(found))


# ---- HSRP ----------------------------------------------------------------------

_HSRP_INTERFACE = Scope(
    key="interface",
    label="HSRP on an interface",
    ident=(interface_field(),),
    enter=("interface {interface}",),
    help="Settings for every HSRP group on one interface.",
    settings=(
        Setting(
            key="version",
            label="HSRP version",
            line="hsrp version {version}",
            fields=(Field("version", "Version", "choice", choices=("1", "2")),),
            help=(
                "Version 2 allows groups 0 to 4095, MD5 keys and IPv6 groups; version 1 "
                "allows groups 0 to 255. Both switches must use the same version."
            ),
            warning=(
                "Changing the version gives every group on this interface a new MAC "
                "address, so they all start over."
            ),
        ),
        Setting(
            key="bfd",
            label="Fast failure detection (BFD)",
            line="hsrp bfd",
            help=(
                "Notice within a second that the other switch is gone, instead of waiting "
                "for the hold time. Needs the BFD feature; IPv4 groups only."
            ),
        ),
        Setting(
            key="mac_refresh",
            label="MAC refresh",
            line="hsrp mac-refresh {seconds}",
            fields=(_int("seconds", "Every (seconds)", 0, 10000),),
            help="How often the standby switch refreshes the virtual MAC address in the network.",
        ),
        Setting(
            key="use_bia",
            label="Use the port's own MAC address",
            line="hsrp use-bia[ {scope}]",
            fields=(
                Field(
                    "scope",
                    "For every group on this interface",
                    "flag",
                    choices=("scope interface",),
                ),
            ),
            help=(
                "Answer with the interface's built-in MAC address instead of a virtual one; "
                "for devices that cannot learn a shared MAC address."
            ),
        ),
        Setting(
            key="delay_minimum",
            label="Wait after the interface comes up",
            line="hsrp delay minimum {seconds}",
            fields=(_int("seconds", "Seconds", 0, 10000),),
            help="How long HSRP waits after the interface comes up before joining its groups.",
        ),
        Setting(
            key="delay_reload",
            label="Wait after the switch starts",
            line="hsrp delay reload {seconds}",
            fields=(_int("seconds", "Seconds", 0, 10000),),
            help="How long HSRP waits after the switch restarts before joining its groups.",
        ),
    ),
)

_HSRP_GROUP = Scope(
    key="group",
    label="HSRP group",
    ident=(
        interface_field(),
        _int(
            "group",
            "Group",
            0,
            4095,
            hint="0 to 255 with HSRP version 1, up to 4095 with version 2",
            placeholder="10",
        ),
        Field(
            "ipv6",
            "IPv6 group",
            "flag",
            choices=("ipv6",),
            hint="Tick for an IPv6 group (needs HSRP version 2 on the interface)",
        ),
    ),
    enter=("interface {interface}", "hsrp {group}[ {ipv6}]"),
    create=True,
    create_label="Make an HSRP group",
    delete=("interface {interface}", "no hsrp {group}[ {ipv6}]"),
    delete_warning=(
        "The switch stops sharing this gateway address; if it was the active switch, "
        "devices lose their gateway until the other switch takes over."
    ),
    help=(
        "One shared gateway address. The group starts working once it has its virtual "
        "address, so set authentication, timers and priority first."
    ),
    settings=(
        Setting(
            key="address",
            label="Virtual IPv4 address",
            line="ip {address}[ {secondary}]",
            fields=(
                Field(
                    "address",
                    "Address",
                    "ipv4",
                    hint="In the interface's own network; devices use it as their gateway",
                    placeholder="192.0.2.254",
                ),
                Field("secondary", "Extra address", "flag", choices=("secondary",)),
            ),
            group="Address",
            help="The gateway address the switches share (IPv4 groups).",
        ),
        Setting(
            key="address6",
            label="Virtual IPv6 address",
            line="ip {address6}",
            fields=(Field("address6", "Address", "ipv6", placeholder="2001:db8:1::fe"),),
            group="Address",
            help="An IPv6 gateway address the switches share (IPv6 groups).",
        ),
        Setting(
            key="autoconfig",
            label="Make the IPv6 address by itself",
            line="ip autoconfig",
            group="Address",
            help="Use a link-local virtual address worked out from the group's MAC address.",
        ),
        Setting(
            key="priority",
            label="Priority",
            line="priority {priority}[ forwarding-threshold lower {lower} upper {upper}]",
            fields=(
                _int("priority", "Priority", 0, 255, hint="Higher wins; 100 if not set"),
                _int("lower", "vPC lower threshold", 1, 255, optional=True),
                _int("upper", "vPC upper threshold", 1, 255, optional=True),
            ),
            group="Who answers",
            help=(
                "The switch with the higher priority answers for the address. The two "
                "thresholds (both or neither) only matter with vPC."
            ),
        ),
        Setting(
            key="preempt",
            label="Take over when better",
            line="preempt",
            group="Who answers",
            help=(
                "Take the address back from a switch with a lower priority (for example "
                "after this one restarts). Off unless set."
            ),
        ),
        Setting(
            key="preempt_delay",
            label="Wait before taking over",
            line="preempt delay minimum {minimum} reload {reload} sync {sync}",
            fields=(
                _int("minimum", "After coming up (seconds)", 0, 3600),
                _int("reload", "After the switch starts (seconds)", 0, 3600),
                _int("sync", "For other software to catch up (seconds)", 0, 3600),
            ),
            removable=False,
            group="Who answers",
            help=(
                "Turns on taking over, with waits; 0 means no wait. To stop taking over, "
                "remove Take over when better."
            ),
        ),
        Setting(
            key="track",
            label="Lower priority when a tracked object goes down",
            line="track {object}[ decrement {decrement}]",
            fields=(
                _int("object", "Tracked object", 1, _TRACK_MAX, hint="Made with the track command"),
                _int("decrement", "Lower by", 1, 255, optional=True, hint="10 if empty"),
            ),
            group="Who answers",
        ),
        Setting(
            key="timers",
            label="Hello and hold time (seconds)",
            line="timers {hello} {hold}",
            fields=(
                _int("hello", "Hello every (seconds)", 1, 254),
                _int("hold", "Give up after (seconds)", 3, 255),
            ),
            group="Timers",
            help="How often the switches greet each other, and how long without a greeting "
            "counts as gone. 3 and 10 if not set.",
        ),
        Setting(
            key="timers_msec",
            label="Hello and hold time (milliseconds)",
            line="timers msec {hello_ms} msec {hold_ms}",
            fields=(
                _int("hello_ms", "Hello every (ms)", 250, 999),
                _int("hold_ms", "Give up after (ms)", 750, 3000),
            ),
            group="Timers",
        ),
        Setting(
            key="auth_text",
            label="Plain-text password",
            line="authentication text {password}",
            no_line="no authentication",
            fields=(Field("password", "Password", "secret"),),
            group="Authentication",
            help="Both switches must use the same one. Sent in the clear.",
        ),
        Setting(
            key="auth_md5",
            label="MD5 key",
            line="authentication md5 key-string 0 {key}[ timeout {timeout}]",
            no_line="no authentication",
            fields=(
                Field("key", "Key", "secret"),
                _int(
                    "timeout",
                    "Accept the old key for (seconds)",
                    0,
                    32767,
                    optional=True,
                ),
            ),
            group="Authentication",
            help="HSRP version 2. Both switches must use the same key.",
        ),
        Setting(
            key="auth_keychain",
            label="MD5 key chain",
            line="authentication md5 key-chain {key_chain}",
            no_line="no authentication",
            fields=(
                Field(
                    "key_chain",
                    "Key chain",
                    "name",
                    hint="Made on the Routing policy page",
                ),
            ),
            group="Authentication",
            help="HSRP version 2. Keys that change on a schedule.",
        ),
        Setting(
            key="name",
            label="Group name",
            line="name {name}",
            fields=(Field("name", "Name", "name"),),
            group="Other",
            help="Gives the group a name other groups can follow.",
        ),
        Setting(
            key="follow",
            label="Follow another group",
            line="follow {follow}",
            fields=(Field("follow", "Group name", "name"),),
            group="Other",
            help=(
                "Copy the state of a named group instead of sending hellos of its own. "
                "Set this before the virtual address: it clears the group's other settings."
            ),
            warning="Following a group clears this group's other settings, its address too.",
        ),
        Setting(
            key="mac",
            label="Virtual MAC address",
            line="mac-address {mac}",
            fields=(Field("mac", "MAC address", "mac", placeholder="0200.0000.0001"),),
            group="Other",
            help="Written like 0200.0000.0001. Normally worked out from the group number.",
        ),
        Setting(
            key="shutdown",
            label="Turned off",
            line="shutdown",
            group="Other",
            help="Stop the group without deleting it.",
        ),
    ),
)

_HSRP_COLUMNS = (
    "Interface",
    "Group",
    "Family",
    "State",
    "Virtual address",
    "Priority",
    "Take over",
    "Active router",
    "Standby router",
    "Virtual MAC",
)


def _hsrp_auth(row: dict[str, Any]) -> str:
    kind = text(row.get("sh_authentication_type"))
    if kind == "text":
        # The switch reports text "cisco" when nobody set authentication; any
        # other text is a password, never shown back.
        if text(row.get("sh_authentication_data")) == "cisco":
            return "none set (plain text, the default)"
        return "plain-text password"
    if kind == "md5":
        return "MD5"
    return kind or "none"


def _hsrp_values(row: dict[str, Any], v6: bool) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    if not v6 and (address := _shown(row.get("sh_vip"))):
        values["address"] = {"address": address, "secondary": ""}
    if priority := text(row.get("sh_cfg_prio")):
        values["priority"] = {"priority": priority, "lower": "", "upper": ""}
    if text(row.get("sh_preempt")) == "enabled":
        values["preempt"] = {}
    hello, hold = text(row.get("sh_cfg_hello")), text(row.get("sh_cfg_hold"))
    if hello and hold:
        if text(row.get("sh_cfg_hello_attr")) == "msec":
            values["timers_msec"] = {"hello_ms": hello, "hold_ms": hold}
        else:
            values["timers"] = {"hello": hello, "hold": hold}
    if text(row.get("sh_ip_redund_name_attr")) == "Configured":
        values["name"] = {"name": text(row.get("sh_ip_redund_name"))}
    vmac_attr = text(row.get("sh_vmac_attr"))
    if vmac_attr and vmac_attr != "Default MAC" and (mac := text(row.get("sh_vmac"))):
        values["mac"] = {"mac": mac}
    return values


def parse_hsrp(bodies: list[dict[str, Any]]) -> ProtocolView:
    """HSRP groups and the interfaces they are on, from ``show hsrp``."""
    (body,) = _bodies(bodies, 1)
    instances: list[Instance] = []
    rows: list[tuple[str, ...]] = []
    interfaces: dict[str, list[str]] = {}
    versions: dict[str, str] = {}
    v6_seen = False
    for row in table_rows(body, "TABLE_grp_detail", "ROW_grp_detail"):
        interface = long_name(text(row.get("sh_if_index")))
        group = text(row.get("sh_group_num"))
        if not interface or not group:
            continue
        v6 = text(row.get("sh_group_type")).lower() == "v6"
        v6_seen = v6_seen or v6
        family = "IPv6" if v6 else "IPv4"
        if v6:
            virtual = _shown(row.get("sh_vip_v6"))
        else:
            virtual = _shown(row.get("sh_vip"))
        extra = []
        for sec in table_rows(row, "TABLE_grp_vip_sec", "ROW_grp_vip_sec"):
            address = text(sec.get("sh_vip_sec"))
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            # An IPv6 group's configured address comes out garbled as IPv4.
            if (parsed.version == 6) == v6:
                extra.append(address)
        active = _shown(row.get("sh_active_router_addr_v6" if v6 else "sh_active_router_addr"))
        standby = _shown(row.get("sh_standby_router_addr_v6" if v6 else "sh_standby_router_addr"))
        state = text(row.get("sh_group_state"))
        reason = text(row.get("sh_state_reason"))
        shown_state = f"{state} {reason}".strip()
        priority = text(row.get("sh_prio"))
        preempt = "yes" if text(row.get("sh_preempt")) == "enabled" else "no"
        vmac = text(row.get("sh_vmac"))
        hello = text(row.get("sh_cur_hello"))
        hold = text(row.get("sh_cur_hold"))
        unit = text(row.get("sh_cur_hello_attr")) or "sec"
        version = text(row.get("sh_group_version")).lstrip("v")
        if version:
            versions.setdefault(interface, version)
        interfaces.setdefault(interface, []).append(group)
        rows.append(
            (
                interface,
                group,
                family,
                shown_state,
                ", ".join([a for a in (virtual, *extra) if a]) or "-",
                priority,
                preempt,
                active or "-",
                standby or "-",
                vmac,
            )
        )
        facts = (
            ("State", shown_state),
            ("Virtual address", virtual or "-"),
            *((("Extra addresses", ", ".join(extra)),) if extra else ()),
            ("Priority now", priority),
            ("Active router", active or "none heard"),
            ("Standby router", standby or "none heard"),
            ("Hello / hold", f"{hello} / {hold} {unit}" if hello else "-"),
            ("Authentication", _hsrp_auth(row)),
            ("Name", text(row.get("sh_ip_redund_name"))),
            ("Virtual MAC", vmac),
            ("HSRP version", version),
        )
        instances.append(
            Instance(
                scope="group",
                ident={"interface": interface, "group": group, "ipv6": "ipv6" if v6 else ""},
                title=f"{interface} group {group} ({family})",
                facts=facts,
                values=_hsrp_values(row, v6),
            )
        )
    per_interface = [
        Instance(
            scope="interface",
            ident={"interface": interface},
            title=interface,
            facts=(("Groups", ", ".join(groups)),),
            values={"version": {"version": versions[interface]}} if interface in versions else {},
        )
        for interface, groups in interfaces.items()
    ]
    instances = per_interface + instances
    notes: tuple[str, ...] = ()
    if v6_seen:
        notes = (
            "For an IPv6 group the switch reports only the link-local virtual address; "
            "the global ones it was given show in the running configuration.",
        )
    return ProtocolView(
        instances=tuple(instances),
        tables=(Table("Groups", _HSRP_COLUMNS, tuple(rows), empty="No HSRP groups."),),
        notes=notes,
    )


HSRP = Protocol(
    key="hsrp",
    name="HSRP",
    summary="Cisco's gateway backup: two switches share one gateway address.",
    features=("hsrp_engine",),
    commands=("show hsrp",),
    parse=parse_hsrp,
    scopes=(_HSRP_INTERFACE, _HSRP_GROUP),
    about=(
        "HSRP lets two switches share one gateway address. Devices use that address as "
        "their gateway; one switch (the active one) answers for it and the other (the "
        "standby) takes over if the active one stops. Each shared address is a numbered "
        "group on a routed interface or VLAN interface, with the same group number and "
        "address on both switches. IPv6 groups need HSRP version 2 on the interface. "
        "The feature is called hsrp_engine on the Features page."
    ),
)

# ---- VRRP (version 2) ------------------------------------------------------------

_VRRP_GROUP = Scope(
    key="group",
    label="VRRP group",
    ident=(
        interface_field(),
        _int("group", "Group", 1, 255, placeholder="30"),
    ),
    enter=("interface {interface}", "vrrp {group}"),
    create=True,
    create_label="Make a VRRP group",
    delete=("interface {interface}", "no vrrp {group}"),
    delete_warning=(
        "The switch stops sharing this gateway address; if it was the master, devices "
        "lose their gateway until the other switch takes over."
    ),
    help=(
        "One shared IPv4 gateway address. A new group starts turned off: give it its "
        "address, then turn it on."
    ),
    settings=(
        Setting(
            key="enabled",
            label="Turned on",
            line="no shutdown",
            no_line="shutdown",
            help="A new VRRP group starts turned off. Removing this turns the group off.",
        ),
        Setting(
            key="address",
            label="Virtual address",
            line="address {address}[ {secondary}]",
            fields=(
                Field(
                    "address",
                    "Address",
                    "ipv4",
                    hint="In the interface's own network; devices use it as their gateway",
                    placeholder="192.0.2.253",
                ),
                Field("secondary", "Extra address", "flag", choices=("secondary",)),
            ),
            group="Address",
        ),
        Setting(
            key="priority",
            label="Priority",
            line="priority {priority}[ forwarding-threshold lower {lower} upper {upper}]",
            fields=(
                _int("priority", "Priority", 1, 254, hint="Higher wins; 100 if not set"),
                _int("lower", "vPC lower threshold", 1, 255, optional=True),
                _int("upper", "vPC upper threshold", 1, 255, optional=True),
            ),
            group="Who answers",
            help="The switch with the higher priority answers. The thresholds only matter "
            "with vPC (both or neither).",
        ),
        Setting(
            key="preempt",
            label="Take over when better",
            line="preempt",
            group="Who answers",
            help="Take the address back from a switch with a lower priority. On unless removed.",
        ),
        Setting(
            key="track_interface",
            label="Change priority when an interface goes down",
            line="track interface {track_interface} priority {track_priority}",
            fields=(
                Field(
                    "track_interface",
                    "Interface",
                    "interface",
                    hint="Usually the uplink",
                    placeholder="Ethernet1/49",
                ),
                _int("track_priority", "Priority while it is down", 1, 254),
            ),
            group="Who answers",
        ),
        Setting(
            key="track",
            label="Lower priority when a tracked object goes down",
            line="track {object} decrement {decrement}",
            fields=(
                _int("object", "Tracked object", 1, _TRACK_MAX, hint="Made with the track command"),
                _int("decrement", "Lower by", 1, 254),
            ),
            group="Who answers",
        ),
        Setting(
            key="advertisement",
            label="Advertisement interval",
            line="advertisement-interval {seconds}",
            fields=(_int("seconds", "Every (seconds)", 1, 255),),
            group="Timers",
            help="How often the master says it is there. 1 second if not set.",
        ),
        Setting(
            key="auth_text",
            label="Plain-text password",
            line="authentication text {password}",
            fields=(Field("password", "Password", "secret", maximum=8, hint="Up to 8 characters"),),
            group="Authentication",
            help="Both switches must use the same one. Sent in the clear.",
        ),
    ),
)

_VRRP_COLUMNS = (
    "Interface",
    "Group",
    "State",
    "Virtual address",
    "Priority",
    "Take over",
    "Advertise every",
    "Master router",
    "Virtual MAC",
)


def parse_vrrp(bodies: list[dict[str, Any]]) -> ProtocolView:
    """VRRP (version 2) groups, from ``show vrrp detail`` and ``show vrrp``."""
    detail, brief = _bodies(bodies, 2)
    found = table_rows(detail, "TABLE_vrrp_group", "ROW_vrrp_group")
    if not found:
        found = table_rows(brief, "TABLE_vrrp_group", "ROW_vrrp_group")
    instances: list[Instance] = []
    rows: list[tuple[str, ...]] = []
    for row in found:
        interface = long_name(text(row.get("sh_if_index")))
        group = text(row.get("sh_group_id"))
        if not interface or not group:
            continue
        virtual = _shown(row.get("sh_vip_addr"))
        state = text(row.get("sh_group_state"))
        priority = text(row.get("sh_priority"))
        configured = text(row.get("sh_cfg_priority")) or priority
        preempt = text(row.get("sh_group_preempt")).lower() == "enable"
        interval = text(row.get("sh_adv_interval"))
        master = _shown(row.get("sh_master_router"))
        vmac = text(row.get("sh_vmac"))
        rows.append(
            (
                interface,
                group,
                state,
                virtual or "-",
                priority,
                "yes" if preempt else "no",
                f"{interval} s" if interval else "-",
                master or "-",
                vmac or "-",
            )
        )
        values: dict[str, dict[str, str]] = {}
        if virtual:
            values["address"] = {"address": virtual, "secondary": ""}
        if configured:
            values["priority"] = {"priority": configured, "lower": "", "upper": ""}
        if preempt:
            values["preempt"] = {}
        if interval:
            values["advertisement"] = {"seconds": interval}
        instances.append(
            Instance(
                scope="group",
                ident={"interface": interface, "group": group},
                title=f"{interface} group {group}",
                facts=(
                    ("State", state),
                    ("Virtual address", virtual or "-"),
                    ("Priority now", priority),
                    ("Master router", master or "none heard"),
                    ("Virtual MAC", vmac or "-"),
                ),
                values=values,
            )
        )
    return ProtocolView(
        instances=tuple(instances),
        tables=(Table("Groups", _VRRP_COLUMNS, tuple(rows), empty="No VRRP groups."),),
    )


VRRP = Protocol(
    key="vrrp",
    name="VRRP",
    summary="The standard gateway backup (version 2, IPv4): two switches share one address.",
    features=("vrrp",),
    commands=("show vrrp detail", "show vrrp"),
    parse=parse_vrrp,
    scopes=(_VRRP_GROUP,),
    about=(
        "VRRP lets two switches (from any maker) share one IPv4 gateway address. One "
        "switch, the master, answers for it; the other takes over if the master stops. "
        "Each shared address is a numbered group on a routed interface or VLAN interface. "
        "A new group starts turned off: give it its address, then turn it on. The switch "
        "will not run VRRP and VRRPv3 at the same time: turn VRRP off on the Features "
        "page before turning VRRPv3 on."
    ),
)

# ---- VRRPv3 ----------------------------------------------------------------------

_VRRPV3_GROUP = Scope(
    key="group",
    label="VRRPv3 group",
    ident=(
        interface_field(),
        _int("group", "Group", 1, 255, placeholder="40"),
        Field("af", "Address family", "choice", choices=("ipv4", "ipv6")),
    ),
    enter=("interface {interface}", "vrrpv3 {group} address-family {af}"),
    create=True,
    create_label="Make a VRRPv3 group",
    delete=("interface {interface}", "no vrrpv3 {group} address-family {af}"),
    delete_warning=(
        "The switch stops sharing this gateway address; if it was the master, devices "
        "lose their gateway until the other switch takes over."
    ),
    help=(
        "One shared gateway address, IPv4 or IPv6. Give it a primary address first; an "
        "IPv6 group's primary is a link-local address (fe80::...)."
    ),
    settings=(
        Setting(
            key="address",
            label="Virtual IPv4 address",
            line="address {address}[ {primary}]",
            fields=(
                Field("address", "Address", "ipv4", placeholder="192.0.2.252"),
                Field("primary", "Primary address", "flag", choices=("primary",)),
            ),
            group="Address",
            help="Give the group its primary address first; others are extra addresses.",
        ),
        Setting(
            key="address6",
            label="Virtual IPv6 address",
            line="address {address6}[ {primary6}]",
            fields=(
                Field("address6", "Address", "ipv6", placeholder="fe80::40"),
                Field("primary6", "Primary address", "flag", choices=("primary",)),
            ),
            group="Address",
            help="The primary must be a link-local address (fe80::...); global addresses "
            "are added as extra ones.",
        ),
        Setting(
            key="priority",
            label="Priority",
            line="priority {priority}",
            fields=(_int("priority", "Priority", 1, 254, hint="Higher wins; 100 if not set"),),
            group="Who answers",
        ),
        Setting(
            key="preempt",
            label="Take over when better",
            line="preempt[ delay minimum {delay}]",
            fields=(
                _int(
                    "delay",
                    "Wait first (seconds)",
                    0,
                    3600,
                    optional=True,
                    hint="Empty for no wait",
                ),
            ),
            group="Who answers",
            help="Take the address back from a switch with a lower priority.",
        ),
        Setting(
            key="track",
            label="Lower priority when a tracked object goes down",
            line="object-track {object} decrement {decrement}",
            fields=(
                _int("object", "Tracked object", 1, _TRACK_MAX, hint="Made with the track command"),
                _int("decrement", "Lower by", 1, 254),
            ),
            group="Who answers",
        ),
        Setting(
            key="timers",
            label="Advertisement interval",
            line="timers advertise {msec}",
            fields=(_int("msec", "Every (milliseconds)", 100, 40950),),
            group="Timers",
            help="How often the master says it is there. 1000 ms if not set.",
        ),
        Setting(
            key="match_address",
            label="Check extra addresses",
            line="match-address",
            group="Other",
            help="Check the extra addresses in the other switch's messages match. On by default.",
        ),
        Setting(
            key="vrrp2",
            label="Also talk VRRP version 2",
            line="vrrp2",
            group="Other",
            help="Only while moving from VRRP version 2 to version 3.",
        ),
        Setting(
            key="description",
            label="Description",
            line="description {description}",
            fields=(Field("description", "Description", "text"),),
            group="Other",
        ),
        Setting(
            key="shutdown",
            label="Turned off",
            line="shutdown",
            group="Other",
            help="Stop the group without deleting it.",
        ),
    ),
)

_VRRPV3_COLUMNS = (
    "Interface",
    "Group",
    "Family",
    "State",
    "Virtual address",
    "Priority",
    "Take over",
    "Advertise every",
    "Virtual MAC",
)


def parse_vrrpv3(bodies: list[dict[str, Any]]) -> ProtocolView:
    """VRRPv3 groups, from ``show vrrpv3 detail`` and ``show vrrpv3``."""
    detail, brief = _bodies(bodies, 2)
    found = table_rows(detail, "TABLE_grp", "ROW_grp")
    if not found:
        found = table_rows(brief, "TABLE_grp", "ROW_grp")
    instances: list[Instance] = []
    rows: list[tuple[str, ...]] = []
    for row in found:
        interface = long_name(text(row.get("intf")))
        group = text(row.get("id"))
        af = text(row.get("af")).lower()
        if not interface or not group or af not in ("ipv4", "ipv6"):
            continue
        family = "IPv6" if af == "ipv6" else "IPv4"
        virtual = _shown(row.get("vip"))
        extra = [
            text(sec.get("addr"))
            for sec in table_rows(row, "TABLE_sec", "ROW_sec")
            if text(sec.get("addr"))
        ]
        state = text(row.get("state"))
        priority = text(row.get("priority"))
        configured = text(row.get("cfg_priority")) or priority
        preempt = text(row.get("preempt")) == "enabled"
        adv = text(row.get("adv"))
        vmac = text(row.get("vmac"))
        rows.append(
            (
                interface,
                group,
                family,
                state,
                ", ".join([a for a in (virtual, *extra) if a]) or "-",
                priority,
                "yes" if preempt else "no",
                f"{adv} ms" if adv else "-",
                vmac or "-",
            )
        )
        values: dict[str, dict[str, str]] = {}
        if virtual:
            if af == "ipv6":
                values["address6"] = {"address6": virtual, "primary6": "primary"}
            else:
                values["address"] = {"address": virtual, "primary": "primary"}
        if configured:
            values["priority"] = {"priority": configured}
        if preempt:
            values["preempt"] = {"delay": ""}
        if adv:
            values["timers"] = {"msec": adv}
        instances.append(
            Instance(
                scope="group",
                ident={"interface": interface, "group": group, "af": af},
                title=f"{interface} group {group} ({family})",
                facts=(
                    ("State", state),
                    ("For", text(row.get("duration"))),
                    ("Virtual address", virtual or "-"),
                    *((("Extra addresses", ", ".join(extra)),) if extra else ()),
                    ("Priority now", priority),
                    ("Virtual MAC", vmac or "-"),
                ),
                values=values,
            )
        )
    return ProtocolView(
        instances=tuple(instances),
        tables=(Table("Groups", _VRRPV3_COLUMNS, tuple(rows), empty="No VRRPv3 groups."),),
    )


VRRPV3 = Protocol(
    key="vrrpv3",
    name="VRRPv3",
    summary="The standard gateway backup, version 3: IPv4 and IPv6, faster timers.",
    features=("vrrpv3",),
    commands=("show vrrpv3 detail", "show vrrpv3"),
    parse=parse_vrrpv3,
    scopes=(_VRRPV3_GROUP,),
    about=(
        "VRRPv3 lets two switches (from any maker) share one gateway address, IPv4 or "
        "IPv6, with timers in milliseconds. One switch, the master, answers for it; the "
        "other takes over if the master stops. Each group is a number and an address "
        "family on a routed interface or VLAN interface; an IPv6 group's main address is "
        "a link-local one (fe80::...). The switch will not run VRRP and VRRPv3 at the "
        "same time: turn VRRP off on the Features page before turning VRRPv3 on."
    ),
)

PROTOCOLS: tuple[Protocol, ...] = (HSRP, VRRP, VRRPV3)
