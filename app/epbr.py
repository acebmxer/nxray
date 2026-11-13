"""Enhanced policy-based routing (ePBR): steering chosen traffic through service
appliances (firewalls, load balancers, caches) in a chain, with health probes that take an
appliance out when it stops answering and spread the traffic over several of them.

An **ePBR service** lists its **service end-points** (each appliance's address and the
interface it is reached through), optionally a **reverse** address for the traffic coming
back, and how they are probed. An **ePBR policy** takes the traffic an ACL permits (a
**match**) and sends it through one or more services in order (the **service chain**, one
numbered ``set service`` line each, with what to do when a service is down), spread over
the end-points by the source or destination address. ``epbr ip|ipv6 policy <name>
[reverse]`` on an interface applies a policy to the traffic coming in there.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (a service, an end-point, its reverse end-point, a policy, a
match, a step of the chain, an interface, a policy's counters), each setting the one
configuration line it sends with checked values in its blanks, and ``build_change``
building the lines. ``NxapiClient.configure_epbr`` sends them.

Read from the switch: ``show feature``, ``show interface brief``, ``show vrf`` and ``show
vrf interface`` in one request; while ``feature epbr`` is on, ``show epbr policy`` (each
policy's chain with every end-point's probe state), ``show running-config`` as text (the
services, policies and interfaces as set, read with the role's ``show running-config``
rule), and for each applied policy ``show epbr policy <name> reverse`` (when applied in
reverse) and ``show epbr statistics policy <name> [reverse]`` (when it counts).

Tried on cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-12) with throwaway services,
policies, ACLs and VLAN interfaces, all removed afterwards and ``feature epbr`` turned
back off. The switch takes ePBR (``feature pbr`` is not needed). What it showed and the
page follows:

* ``service-end-point ip|ipv6 <address> [interface <interface>]`` (``service-endpoint`` is
  not a command; a loopback is refused); typing an end-point again without its interface
  takes the interface off, so the page always enters it as it is; IPv4 and IPv6 end-points
  cannot share a service; inside one, ``reverse ip|ipv6 <address> interface
  <interface>``;
* a service, an end-point and a reverse end-point each take one probe: ``probe icmp``,
  ``probe tcp <port>``, ``probe udp <port> [control enable]``, ``probe http get <page>`` or
  ``probe dns host <name>``, with ``frequency`` (1 to 604800 seconds, 60 at least for
  HTTP), ``timeout``, ``retry-down-count`` and ``retry-up-count`` (1 to 5) and
  ``source-interface``; an end-point also ``probe track <object>``. A new probe replaces
  the old one; its ``no`` form names its kind (``no probe icmp``, ``no probe udp 53``);
* ``service-interface <interface>`` and ``vrf <vrf>``, whose ``no`` forms name the value;
* in a policy, ``statistics``, ``match ip|ipv6 address <acl>`` (IPv4 and IPv6 matches
  cannot share a policy, and an IPv6 match takes IPv6 services only), and inside a match
  ``<n> set service <service> [fail-action bypass|drop|forward]`` (``no <n>`` removes it)
  and ``load-balance [buckets <2-256, a power of 2>] [method src-ip|dst-ip]``, which
  replaces the one before;
* ``epbr ip|ipv6 policy <name> [reverse]`` on a VLAN interface (refused on a loopback);
  an interface takes one IPv4 and one IPv6 policy;
* a service that an applied policy uses, and an applied policy, refuse every change typed
  as usual ("Please dissociate and try again"). They are changed inside ``epbr session``,
  ended by ``commit``: end-points, reverse end-points, their probes, matches, the chain and
  load-balance; not the service's probe, service interface or VRF, nor a policy's
  ``statistics``. Objects not in use are refused there, so the page picks the way by what
  it read. A session left open by a refused line is closed with ``abort``;
* ``clear epbr statistics policy <name>`` (typed outside configuration mode) zeroes the
  counters, which a policy keeps only with ``statistics``.

ePBR makes objects of its own for its probes: IP SLA entries from 20001, tracked objects
from 1, and route-maps and ACLs whose names start with ``epbr_``; they go when the service
does.

``show epbr policy`` gives TABLE_pmap/ROW_pmap {pname, intf_name (when applied),
TABLE_pmap_match/ROW_pmap_match {match_type (1 IPv4, 2 IPv6), match_stmt,
TABLE_pmap_s_chain/ROW_pmap_s_chain {seq, sname, action (always 0, so the fail action is
read from the configuration), TABLE_pmap_s_chain_entry/ROW_pmap_s_chain_entry {ip_type,
svc_ep, track_id, probe_state}}}}; the statistics TABLE_pmap/ROW_pmap {pname, match_stmt,
bcount, TABLE_pmap_t_match/ROW_pmap_t_match {bname, TABLE_pmap_b_stats/ROW_pmap_b_stats
{sname, pval}}}.

Clearing the counters is typed outside configuration mode, which NXray's broad role allows
from version ``BROAD_EPBR_VERSION`` (rule 30); a broad role written before needs Update the
port list first.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
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
    interface_field,
    source_field,
    table_rows,
)
from app.routing import parse_vrf_members
from app.routing_protocols import layer3_interfaces
from app.switch import text
from app.switch_admin import vrf_choices
from app.track import TRACK_HINT, TRACK_MAX

FEATURE = "epbr"
PAGE_COMMANDS = ("show feature", "show interface brief", "show vrf", "show vrf interface")
COMMANDS = ("show epbr policy",)
CONFIG_COMMAND = "show running-config"
SESSION_LINE = "epbr session"
COMMIT_LINE = "commit"
ABORT_LINE = "abort"
FREQUENCY_MAX = 604800
HTTP_FREQUENCY_MIN = 60
RETRY_MAX = 5
BUCKETS = tuple(str(2**n) for n in range(1, 9))  # 2 to 256
METHODS = ("src-ip", "dst-ip")
FAIL_ACTIONS = ("bypass", "drop", "forward")
FAMILIES = ("ip", "ipv6")
# The identity keys ``check_epbr_place`` adds from what the page read: whether the service
# or policy named is in use, so its lines go through an ePBR session.
SERVICE_IN_USE = "service_in_use"
POLICY_APPLIED = "policy_applied"


def _name(name: str, label: str, placeholder: str, hint: str = "Letters, digits, - and _") -> Field:
    return Field(name, label, "name", hint=hint, placeholder=placeholder)


def _family(optional: bool = False) -> Field:
    return Field(
        "family",
        "IPv4 or IPv6",
        "choice",
        choices=FAMILIES,
        optional=optional,
        hint="Empty: taken from the address" if optional else "ip: IPv4; ipv6: IPv6",
    )


# ---- probes ------------------------------------------------------------------------------

_PROBE_OPTIONS = (
    "[ frequency {frequency}][ timeout {timeout}][ retry-down-count {down}]"
    "[ retry-up-count {up}][ source-interface {source}]"
)


def _probe_fields() -> tuple[Field, ...]:
    return (
        Field(
            "frequency", "Every (seconds)", "int", minimum=1, maximum=FREQUENCY_MAX, optional=True
        ),
        Field(
            "timeout",
            "Timeout (seconds)",
            "int",
            minimum=1,
            maximum=FREQUENCY_MAX,
            optional=True,
            hint="Shorter than how often it runs",
        ),
        Field(
            "down", "Failures before it is down", "int", minimum=1, maximum=RETRY_MAX, optional=True
        ),
        Field(
            "up",
            "Answers before it is up again",
            "int",
            minimum=1,
            maximum=RETRY_MAX,
            optional=True,
        ),
        dataclasses.replace(source_field(), optional=True, label="Send from"),
    )


def _check_http(values: dict[str, str]) -> None:
    frequency = values.get("frequency", "")
    if frequency and int(frequency) < HTTP_FREQUENCY_MIN:
        raise ValueError(f"an HTTP probe runs at most every {HTTP_FREQUENCY_MIN} seconds")


def _probes(group: str, what: str, track: bool = False) -> tuple[Setting, ...]:
    """The probe settings of a service, an end-point or a reverse end-point; the switch
    keeps one, and a new one replaces it."""
    port = Field("port", "Port", "int", minimum=1, maximum=65535, placeholder="443")
    one = " One probe at a time: setting another replaces it."
    settings = [
        Setting(
            key="probe_icmp",
            label="Probe by ping",
            line="probe icmp" + _PROBE_OPTIONS,
            no_line="no probe icmp",
            group=group,
            fields=_probe_fields(),
            help=f"Ping {what} to see that it is up." + one,
        ),
        Setting(
            key="probe_tcp",
            label="Probe a TCP port",
            line="probe tcp {port}" + _PROBE_OPTIONS,
            no_line="no probe tcp {port}",
            group=group,
            fields=(port, *_probe_fields()),
            help=f"Open a TCP connection to {what}." + one,
        ),
        Setting(
            key="probe_udp",
            label="Probe a UDP port",
            line="probe udp {port}[ {control}]" + _PROBE_OPTIONS,
            no_line="no probe udp {port}",
            group=group,
            fields=(
                port,
                Field(
                    "control",
                    "Ask it to answer first (IP SLA control)",
                    "flag",
                    choices=("control enable",),
                ),
                *_probe_fields(),
            ),
            help=f"Send to a UDP port of {what}." + one,
        ),
        Setting(
            key="probe_http",
            label="Probe a web page",
            line="probe http get {page}" + _PROBE_OPTIONS,
            no_line="no probe http get {page}",
            group=group,
            fields=(
                Field("page", "Page", "urlpath", placeholder="index.html"),
                *_probe_fields(),
            ),
            check=_check_http,
            help=f"Fetch a web page from {what}, at most every {HTTP_FREQUENCY_MIN} seconds." + one,
        ),
        Setting(
            key="probe_dns",
            label="Probe by DNS",
            line="probe dns host {host}" + _PROBE_OPTIONS,
            no_line="no probe dns host {host}",
            group=group,
            fields=(
                Field("host", "Name to look up", "host", placeholder="www.example.net"),
                *_probe_fields(),
            ),
            help=f"Ask {what}, a DNS server, for a name." + one,
        ),
    ]
    if track:
        settings.append(
            Setting(
                key="probe_track",
                label="Follow a tracked object",
                line="probe track {track}",
                no_line="no probe track {track}",
                group=group,
                fields=(
                    Field(
                        "track",
                        "Tracked object",
                        "int",
                        minimum=1,
                        maximum=TRACK_MAX,
                        hint=TRACK_HINT,
                    ),
                ),
                help=f"{what.capitalize()} is up while the object is." + one,
            )
        )
    return tuple(settings)


# ---- scopes ------------------------------------------------------------------------------

_IN_USE_NOTE = (
    " While a policy that uses it is applied to an interface, NXray sends these changes in an "
    "ePBR session and commits them, as the switch asks."
)
_APPLIED_NOTE = (
    " While the policy is applied to an interface, NXray sends these changes in an ePBR "
    "session and commits them, as the switch asks."
)


def _check_vrf(values: dict[str, str]) -> None:
    if not values.get("vrf"):
        raise ValueError("pick the VRF the end-points are in; Remove goes back to default")


_SERVICE = Scope(
    key="service",
    label="Service",
    ident=(_name("service", "Service", "firewall"),),
    enter=("epbr service {service}",),
    create=True,
    create_label="Make a service",
    delete=("no epbr service {service}",),
    delete_warning="The switch deletes a service only once no policy names it.",
    help=(
        "Appliances traffic is sent through, how they are checked, and the VRF they are in. "
        "Its probe is the one end-points use when they have none of their own."
    ),
    settings=(
        *_probes("Health probe", "each end-point"),
        Setting(
            key="service_interface",
            label="Service interface",
            line="service-interface {interface}",
            no_line="no service-interface {interface}",
            group="Service",
            fields=(Field("interface", "Interface", "interface"),),
            help="The interface the appliances sit behind.",
        ),
        Setting(
            key="vrf",
            label="VRF",
            line="vrf {vrf}",
            no_line="no vrf {vrf}",
            group="Service",
            fields=(
                Field("vrf", "VRF", "vrf", optional=True, hint="A VRF made on the Routing page"),
            ),
            check=_check_vrf,
            help="The VRF the end-points are reached in. Empty: default.",
        ),
    ),
)

_ENDPOINT_PLACE = "service-end-point {family} {address}[ interface {interface}]"

_ENDPOINT = Scope(
    key="endpoint",
    label="End-point",
    ident=(
        _name("service", "Service", "firewall"),
        _family(optional=True),
        Field(
            "address", "Address", "ip", hint="The appliance's address", placeholder="198.51.100.10"
        ),
        dataclasses.replace(
            interface_field(),
            optional=True,
            hint="The VLAN interface, routed port or port-channel it is reached through",
        ),
    ),
    enter=("epbr service {service}", _ENDPOINT_PLACE),
    create=True,
    create_label="Add an end-point",
    delete=("epbr service {service}", "no service-end-point {family} {address}"),
    delete_warning="The service's other end-points take its traffic.",
    help="One appliance of a service: IPv4 and IPv6 end-points cannot share a service."
    + _IN_USE_NOTE,
    settings=(
        Setting(
            key="reverse",
            label="Reverse end-point",
            line="reverse {family} {reverse} interface {reverse_interface}",
            no_line="no reverse {family} {reverse} interface {reverse_interface}",
            ident=("family",),
            group="Traffic coming back",
            fields=(
                Field(
                    "reverse",
                    "Address",
                    "ip",
                    hint="The appliance's address on its other side",
                    placeholder="198.51.100.20",
                ),
                Field("reverse_interface", "Interface", "interface"),
            ),
            help="Where traffic going back the other way is sent, so both ways pass the same "
            "appliance (a policy applied in reverse).",
        ),
        *_probes("Health probe", "this end-point", track=True),
    ),
)

_REVERSE = Scope(
    key="reverse",
    label="Reverse end-point",
    ident=(
        _name("service", "Service", "firewall"),
        _family(optional=True),
        Field("address", "End-point", "ip", placeholder="198.51.100.10"),
        dataclasses.replace(interface_field(), optional=True, label="End-point interface"),
        Field("reverse", "Reverse address", "ip", placeholder="198.51.100.20"),
        Field("reverse_interface", "Reverse interface", "interface"),
    ),
    enter=(
        "epbr service {service}",
        _ENDPOINT_PLACE,
        "reverse {family} {reverse} interface {reverse_interface}",
    ),
    help="How an end-point's reverse address is checked. Added and removed on the end-point."
    + _IN_USE_NOTE,
    settings=_probes("Health probe", "the reverse address", track=True),
)


def _check_buckets(values: dict[str, str]) -> None:
    if not values.get("buckets") and not values.get("method"):
        raise ValueError("pick the buckets, the method or both")


_POLICY = Scope(
    key="policy",
    label="Policy",
    ident=(_name("policy", "Policy", "web-chain"),),
    enter=("epbr policy {policy}",),
    create=True,
    create_label="Make a policy",
    delete=("no epbr policy {policy}",),
    delete_warning="The switch deletes a policy only once no interface applies it.",
    help="Which traffic goes through which services, in order.",
    settings=(
        Setting(
            key="statistics",
            label="Count the traffic",
            line="statistics",
            group="Counters",
            help="Count the packets each bucket sends to each service. The switch turns it on "
            "or off only while the policy is applied to no interface.",
        ),
    ),
)

_MATCH_PLACE = "match {family} address {acl}"

_MATCH = Scope(
    key="match",
    label="Match",
    ident=(
        _name("policy", "Policy", "web-chain"),
        _family(),
        _name("acl", "ACL", "web", hint="An ACL made on the Security page: its permit lines"),
    ),
    enter=("epbr policy {policy}", _MATCH_PLACE),
    create=True,
    create_label="Add a match",
    delete=("epbr policy {policy}", "no " + _MATCH_PLACE),
    delete_warning="The traffic this ACL permits is routed by the routing table again.",
    help=(
        "The traffic an ACL permits, and how it is spread over each service's end-points. "
        "IPv4 and IPv6 matches cannot share a policy." + _APPLIED_NOTE
    ),
    settings=(
        Setting(
            key="load_balance",
            label="Spread by",
            line="load-balance[ buckets {buckets}][ method {method}]",
            no_line="no load-balance[ buckets {buckets}][ method {method}]",
            group="Spreading",
            fields=(
                Field("buckets", "Buckets", "choice", choices=BUCKETS, optional=True),
                Field(
                    "method",
                    "Address that picks the end-point",
                    "choice",
                    choices=METHODS,
                    optional=True,
                ),
            ),
            check=_check_buckets,
            help="How many buckets the traffic is cut into, and by which address. Setting it "
            "again replaces it.",
        ),
    ),
)

_STEP_LINE = "{seq} set service {service}[ fail-action {fail}]"

_STEP = Scope(
    key="step",
    label="Step of the chain",
    ident=(
        _name("policy", "Policy", "web-chain"),
        _family(),
        _name("acl", "ACL", "web"),
        Field(
            "seq",
            "Step number",
            "int",
            minimum=1,
            maximum=65535,
            hint="Traffic goes through the steps from the lowest number",
            placeholder="10",
        ),
        _name("service", "Service", "firewall"),
        Field(
            "fail",
            "When the service is down",
            "choice",
            choices=FAIL_ACTIONS,
            optional=True,
            hint="bypass: skip it; drop: drop the traffic; forward: route it as usual. "
            "Needs a probe",
        ),
    ),
    enter=("epbr policy {policy}", _MATCH_PLACE, _STEP_LINE),
    create=True,
    create_label="Add a step",
    delete=("epbr policy {policy}", _MATCH_PLACE, "no {seq}"),
    delete_warning="The matched traffic no longer passes this service.",
    help=(
        "One service the matched traffic is sent through. Adding a step with a number "
        "already used replaces it. An IPv6 match takes IPv6 services only." + _APPLIED_NOTE
    ),
)


def _apply(key: str, label: str, family: str, reverse: bool, help_text: str) -> Setting:
    line = f"epbr {family} policy {{map}}" + (" reverse" if reverse else "")
    return Setting(
        key=key,
        label=label,
        line=line,
        no_line="no " + line,
        group="Policy",
        fields=(_name("map", "Policy", "web-chain"),),
        help=help_text,
        warning="Traffic coming in on this interface follows the policy at once.",
    )


_INTERFACE = Scope(
    key="interface",
    label="Interface",
    ident=(interface_field(),),
    enter=("interface {interface}",),
    help=(
        "Apply a policy to the traffic coming in on a VLAN interface, routed port or routed "
        "port-channel: one IPv4 and one IPv6 policy each, forward, reverse or both. Cisco's "
        "guide says an interface ITD uses cannot take one."
    ),
    settings=(
        _apply(
            "policy",
            "IPv4 policy",
            "ip",
            False,
            "IPv4 traffic coming in here goes through the policy's services.",
        ),
        _apply(
            "policy_reverse",
            "IPv4 policy, reverse",
            "ip",
            True,
            "IPv4 traffic coming back in here goes to the services' reverse end-points.",
        ),
        _apply(
            "policy6",
            "IPv6 policy",
            "ipv6",
            False,
            "IPv6 traffic coming in here goes through the policy's services.",
        ),
        _apply(
            "policy6_reverse",
            "IPv6 policy, reverse",
            "ipv6",
            True,
            "IPv6 traffic coming back in here goes to the services' reverse end-points.",
        ),
    ),
)

_COUNTERS = Scope(
    key="counters",
    label="Counters",
    ident=(_name("policy", "Policy", "web-chain"),),
    enter=(),
    help="What each bucket of a counting policy sent. Counting is turned on on the policy.",
    settings=(
        Setting(
            key="clear",
            label="Clear the counters",
            line="clear epbr statistics policy {policy}",
            ident=("policy",),
            group="Counters",
            config=False,
            removable=False,
        ),
    ),
)

SCOPES = (_SERVICE, _ENDPOINT, _REVERSE, _POLICY, _MATCH, _STEP, _INTERFACE, _COUNTERS)
_SERVICE_SIDE = ("service", "endpoint", "reverse")
_POLICY_SIDE = ("policy", "match", "step")
# What the session does not take (the switch answers "% Invalid command" there).
_NOT_IN_SESSION = ("service", "policy")


# ---- reading the configuration -----------------------------------------------------------


@dataclass
class ReverseConfig:
    family: str
    address: str
    interface: str
    probe: str = ""


@dataclass
class EndpointConfig:
    family: str
    address: str
    interface: str
    probe: str = ""
    reverse: ReverseConfig | None = None


@dataclass
class ServiceConfig:
    name: str
    lines: list[str] = field(default_factory=list)  # service-interface, vrf
    probe: str = ""
    endpoints: list[EndpointConfig] = field(default_factory=list)


@dataclass
class MatchConfig:
    family: str
    acl: str
    load_balance: str = ""
    steps: list[tuple[str, str, str]] = field(default_factory=list)  # (number, service, fail)


@dataclass
class PolicyConfig:
    name: str
    statistics: bool = False
    matches: list[MatchConfig] = field(default_factory=list)


@dataclass(frozen=True)
class Applied:
    """One ``epbr ip|ipv6 policy`` line on an interface."""

    interface: str
    family: str  # "ip" or "ipv6"
    policy: str
    reverse: bool


@dataclass
class EpbrConfig:
    services: dict[str, ServiceConfig] = field(default_factory=dict)
    policies: dict[str, PolicyConfig] = field(default_factory=dict)
    applied: list[Applied] = field(default_factory=list)

    @property
    def applied_policies(self) -> set[str]:
        return {a.policy for a in self.applied}

    @property
    def services_in_use(self) -> set[str]:
        """The services an applied policy names."""
        return {
            service
            for name in self.applied_policies
            if name in self.policies
            for match in self.policies[name].matches
            for _, service, _ in match.steps
        }


_ENDPOINT_LINE = re.compile(r"service-end-point (ip|ipv6) (\S+)(?: interface (\S+))?")
_REVERSE_LINE = re.compile(r"reverse (ip|ipv6) (\S+)(?: interface (\S+))?")
_MATCH_LINE = re.compile(r"match (ip|ipv6) address (\S+)")
_STEP_RE = re.compile(r"(\d+) set service (\S+)(?: fail-action (\S+))?")
_APPLIED_LINE = re.compile(r"epbr (ip|ipv6) policy (\S+)( reverse)?")


def parse_epbr_config(config: str) -> EpbrConfig:
    """The ``epbr service`` and ``epbr policy`` blocks of ``show running-config`` and the
    interfaces' ``epbr ... policy`` lines.

    Read by keyword, not by indentation alone: the switch indents a service's probe by 3,
    an end-point's by 5 and a reverse end-point's by 7, under lines indented 0, 2 and 4.
    """
    found = EpbrConfig()
    service: ServiceConfig | None = None
    policy: PolicyConfig | None = None
    interface = ""
    endpoint: EndpointConfig | None = None
    match: MatchConfig | None = None
    for raw in config.splitlines():
        line = raw.strip()
        if not line or line.startswith("!"):
            continue
        indent = len(raw) - len(raw.lstrip())
        if indent == 0:
            service = policy = None
            endpoint = match = None
            interface = ""
            words = line.split()
            if len(words) == 3 and words[:2] == ["epbr", "service"]:
                service = found.services.setdefault(words[2], ServiceConfig(words[2]))
            elif len(words) == 3 and words[:2] == ["epbr", "policy"]:
                policy = found.policies.setdefault(words[2], PolicyConfig(words[2]))
            elif words[0] == "interface" and len(words) == 2:
                interface = words[1]
            continue
        if interface:
            if applied := _APPLIED_LINE.fullmatch(line):
                found.applied.append(
                    Applied(interface, applied.group(1), applied.group(2), bool(applied.group(3)))
                )
            continue
        if service is not None:
            if found_endpoint := _ENDPOINT_LINE.fullmatch(line):
                family, address, port = found_endpoint.groups()
                endpoint = EndpointConfig(family, address, port or "")
                service.endpoints.append(endpoint)
            elif (found_reverse := _REVERSE_LINE.fullmatch(line)) and endpoint is not None:
                family, address, port = found_reverse.groups()
                endpoint.reverse = ReverseConfig(family, address, port or "")
            elif line.startswith("probe "):
                if indent >= 6 and endpoint is not None and endpoint.reverse is not None:
                    endpoint.reverse.probe = line
                elif indent >= 4 and endpoint is not None:
                    endpoint.probe = line
                else:
                    service.probe = line
            else:
                service.lines.append(line)
        elif policy is not None:
            if line == "statistics":
                policy.statistics = True
            elif found_match := _MATCH_LINE.fullmatch(line):
                match = MatchConfig(found_match.group(1), found_match.group(2))
                policy.matches.append(match)
            elif match is not None and line.startswith("load-balance"):
                match.load_balance = line
            elif match is not None and (step := _STEP_RE.fullmatch(line)):
                number, name, fail = step.groups()
                match.steps.append((number, name, fail or ""))
    return found


_PROBE_WORDS = {
    "frequency": "frequency",
    "timeout": "timeout",
    "retry-down-count": "down",
    "retry-up-count": "up",
    "source-interface": "source",
}


def probe_values(line: str) -> dict[str, dict[str, str]]:
    """A ``probe ...`` line as its setting's field values ({} for none)."""
    words = line.split()
    if len(words) < 2 or words[0] != "probe":
        return {}
    kind, rest = words[1], words[2:]
    found: dict[str, str] = {}
    if kind == "track" and rest:
        return {"probe_track": {"track": rest[0]}}
    if kind in ("tcp", "udp") and rest:
        found["port"], rest = rest[0], rest[1:]
        if kind == "udp" and rest[:2] == ["control", "enable"]:
            found["control"], rest = "control enable", rest[2:]
    elif kind == "http" and len(rest) >= 2 and rest[0] == "get":
        found["page"], rest = rest[1], rest[2:]
    elif kind == "dns" and len(rest) >= 2 and rest[0] == "host":
        found["host"], rest = rest[1], rest[2:]
    elif kind != "icmp":
        return {}
    for key, value in zip(rest[::2], rest[1::2], strict=False):
        if key in _PROBE_WORDS:
            found[_PROBE_WORDS[key]] = value
    return {f"probe_{kind}": found}


def _load_balance_values(line: str) -> dict[str, str]:
    match = re.fullmatch(r"load-balance(?: buckets (\d+))?(?: method (\S+))?", line)
    if not match:
        return {}
    return {"buckets": match.group(1) or "", "method": match.group(2) or ""}


# ---- reading the state -------------------------------------------------------------------


def parse_chains(body: Any, direction: str) -> list[tuple[str, ...]]:
    """``show epbr policy [<name>] [reverse]``: (policy, direction, ACL, step, service,
    end-point, tracked object, state) per end-point of each step."""
    found = []
    for row in table_rows(body or {}, "TABLE_pmap", "ROW_pmap"):
        name = text(row.get("pname"))
        for match in table_rows(row, "TABLE_pmap_match", "ROW_pmap_match"):
            acl = text(match.get("match_stmt"))
            for step in table_rows(match, "TABLE_pmap_s_chain", "ROW_pmap_s_chain"):
                entries = table_rows(step, "TABLE_pmap_s_chain_entry", "ROW_pmap_s_chain_entry")
                for entry in entries or [{}]:
                    track = text(entry.get("track_id"))
                    found.append(
                        (
                            name,
                            direction,
                            acl,
                            text(step.get("seq")),
                            text(step.get("sname")),
                            text(entry.get("svc_ep")) or "-",
                            track if track and track != "0" else "-",
                            text(entry.get("probe_state")) or "-",
                        )
                    )
    return found


def _bucket(name: str) -> str:
    """'epbr_web_1_fwd_bucket_3' -> '3'; anything else as it is."""
    match = re.search(r"_bucket_(\d+)$", name)
    return match.group(1) if match else name


def parse_counters(
    body: Any, direction: str, steps: dict[str, list[str]] | None = None
) -> list[tuple[str, ...]]:
    """``show epbr statistics policy <name> [reverse]``: (policy, direction, ACL, bucket,
    step, packets) per service of each bucket. ``steps`` gives each ACL's step numbers in
    order, so a service used twice is told apart."""
    found = []
    for row in table_rows(body or {}, "TABLE_pmap", "ROW_pmap"):
        name, acl = text(row.get("pname")), text(row.get("match_stmt"))
        numbers = (steps or {}).get(acl, [])
        for bucket in table_rows(row, "TABLE_pmap_t_match", "ROW_pmap_t_match"):
            stats = table_rows(bucket, "TABLE_pmap_b_stats", "ROW_pmap_b_stats")
            for index, stat in enumerate(stats):
                service = text(stat.get("sname"))
                if len(numbers) == len(stats):
                    service = f"{numbers[index]} {service}"
                found.append(
                    (
                        name,
                        direction,
                        acl,
                        _bucket(text(bucket.get("bname"))),
                        service,
                        text(stat.get("pval")) or "0",
                    )
                )
    return found


def _probe_fact(line: str) -> str:
    return line.removeprefix("probe ") if line else "none"


def _family_word(family: str) -> str:
    return "IPv6" if family == "ipv6" else "IPv4"


def _service_instances(parsed: EpbrConfig) -> list[Instance]:
    in_use = parsed.services_in_use
    users: dict[str, list[str]] = {}
    for policy in parsed.policies.values():
        for match in policy.matches:
            for _, service, _ in match.steps:
                users.setdefault(service, [])
                if policy.name not in users[service]:
                    users[service].append(policy.name)
    instances = []
    for name, service in parsed.services.items():
        values = probe_values(service.probe)
        facts = [
            ("End-points", ", ".join(e.address for e in service.endpoints) or "none"),
            ("Probe", _probe_fact(service.probe)),
        ]
        for line in service.lines:
            if line.startswith("service-interface "):
                values["service_interface"] = {"interface": line.split()[-1]}
                facts.append(("Service interface", line.split()[-1]))
            elif line.startswith("vrf "):
                values["vrf"] = {"vrf": line.split()[-1]}
                facts.append(("VRF", line.split()[-1]))
        facts.append(("Used by", ", ".join(users.get(name, [])) or "no policy"))
        facts.append(
            (
                "Changed in an ePBR session",
                "yes: an applied policy uses it" if name in in_use else "no",
            )
        )
        instances.append(Instance("service", {"service": name}, name, tuple(facts), values))
    return instances


def _endpoint_instances(parsed: EpbrConfig) -> list[Instance]:
    endpoints, reverses = [], []
    for name, service in parsed.services.items():
        for endpoint in service.endpoints:
            ident = {
                "service": name,
                "family": endpoint.family,
                "address": endpoint.address,
                "interface": endpoint.interface,
            }
            values = probe_values(endpoint.probe)
            facts = [
                ("Interface", endpoint.interface or "-"),
                ("Probe", _probe_fact(endpoint.probe) if endpoint.probe else "the service's"),
            ]
            reverse = endpoint.reverse
            if reverse is not None:
                values["reverse"] = {
                    "reverse": reverse.address,
                    "reverse_interface": reverse.interface,
                }
                facts.append(("Reverse", f"{reverse.address} on {reverse.interface or '-'}"))
                reverses.append(
                    Instance(
                        "reverse",
                        {
                            **ident,
                            "reverse": reverse.address,
                            "reverse_interface": reverse.interface,
                        },
                        f"{reverse.address}, reverse of {endpoint.address} in {name}",
                        (
                            (
                                "Probe",
                                _probe_fact(reverse.probe) if reverse.probe else "the service's",
                            ),
                        ),
                        probe_values(reverse.probe),
                    )
                )
            endpoints.append(
                Instance("endpoint", ident, f"{endpoint.address} in {name}", tuple(facts), values)
            )
    return [*endpoints, *reverses]


def _policy_instances(parsed: EpbrConfig) -> list[Instance]:
    where: dict[str, list[str]] = {}
    for applied in parsed.applied:
        place = applied.interface + (" (reverse)" if applied.reverse else "")
        where.setdefault(applied.policy, []).append(place)
    policies, matches, steps = [], [], []
    for name, policy in parsed.policies.items():
        policies.append(
            Instance(
                "policy",
                {"policy": name},
                name,
                (
                    ("Matches", ", ".join(m.acl for m in policy.matches) or "none"),
                    ("Applied on", ", ".join(where.get(name, [])) or "no interface"),
                    ("Counting", "yes" if policy.statistics else "no"),
                ),
                {"statistics": {"on": "yes"}} if policy.statistics else {},
            )
        )
        for match in policy.matches:
            ident = {"policy": name, "family": match.family, "acl": match.acl}
            balance = _load_balance_values(match.load_balance)
            matches.append(
                Instance(
                    "match",
                    ident,
                    f"{_family_word(match.family)} ACL {match.acl} in {name}",
                    (
                        ("Spread by", match.load_balance.removeprefix("load-balance ") or "-"),
                        (
                            "Chain",
                            ", ".join(f"{n} {s}" for n, s, _ in match.steps) or "no service yet",
                        ),
                    ),
                    {"load_balance": balance} if balance else {},
                )
            )
            for number, service, fail in match.steps:
                steps.append(
                    Instance(
                        "step",
                        {**ident, "seq": number, "service": service, "fail": fail},
                        f"{name}, ACL {match.acl}: {number} {service}",
                        (("When the service is down", fail or "the switch's default"),),
                    )
                )
    return [*policies, *matches, *steps]


def _interface_instances(parsed: EpbrConfig) -> list[Instance]:
    keys = {
        ("ip", False): ("policy", "IPv4 policy"),
        ("ip", True): ("policy_reverse", "IPv4 policy, reverse"),
        ("ipv6", False): ("policy6", "IPv6 policy"),
        ("ipv6", True): ("policy6_reverse", "IPv6 policy, reverse"),
    }
    places: dict[str, dict[str, dict[str, str]]] = {}
    facts: dict[str, list[tuple[str, str]]] = {}
    for applied in parsed.applied:
        key, label = keys[(applied.family, applied.reverse)]
        places.setdefault(applied.interface, {})[key] = {"map": applied.policy}
        facts.setdefault(applied.interface, []).append((label, applied.policy))
    return [
        Instance("interface", {"interface": name}, name, tuple(facts[name]), values)
        for name, values in places.items()
    ]


def parse_epbr(
    body: Any,
    config: str | None,
    reverse_bodies: dict[str, Any] | None = None,
    counters: dict[tuple[str, str], Any] | None = None,
) -> ProtocolView:
    """The page from ``show epbr policy``, the configuration text (None when the switch did
    not show it), ``show epbr policy <name> reverse`` per policy applied in reverse, and the
    statistics by (policy, "forward" or "reverse")."""
    parsed = parse_epbr_config(config or "")
    instances: list[Instance] = [
        *_service_instances(parsed),
        *_endpoint_instances(parsed),
        *_policy_instances(parsed),
        *_interface_instances(parsed),
    ]
    notes: tuple[str, ...] = ()
    if config is None:
        notes = (
            "The switch did not show ePBR's settings to NXray's account: only the state is shown.",
        )
        for row in table_rows(body or {}, "TABLE_pmap", "ROW_pmap"):
            name = text(row.get("pname"))
            if name:
                facts = (("Applied on", text(row.get("intf_name")) or "no interface"),)
                instances.append(Instance("policy", {"policy": name}, name, facts))
    counting = counters or {}
    for name, policy in parsed.policies.items():
        if policy.statistics:
            instances.append(Instance("counters", {"policy": name}, name))
    chains = parse_chains(body, "forward")
    for body_reverse in (reverse_bodies or {}).values():
        chains += parse_chains(body_reverse, "reverse")
    fails = {
        (name, match.acl, number): fail
        for name, policy in parsed.policies.items()
        for match in policy.matches
        for number, _, fail in match.steps
    }
    chain_rows = tuple(
        (*row[:5], fails.get((row[0], row[2], row[3]), "") or "-", *row[5:]) for row in chains
    )
    counter_rows: list[tuple[str, ...]] = []
    for (name, direction), stat in counting.items():
        policy_config = parsed.policies.get(name)
        steps = {
            m.acl: [n for n, _, _ in m.steps]
            for m in (policy_config.matches if policy_config else [])
        }
        counter_rows += parse_counters(stat, direction, steps)
    tables = (
        Table(
            "Where policies apply",
            ("Interface", "Family", "Policy", "Direction"),
            tuple(
                (
                    a.interface,
                    _family_word(a.family),
                    a.policy,
                    "reverse" if a.reverse else "forward",
                )
                for a in parsed.applied
            ),
            empty="No policy is applied to an interface yet.",
        ),
        Table(
            "Service chains",
            (
                "Policy",
                "Direction",
                "ACL",
                "Step",
                "Service",
                "When down",
                "End-point",
                "Tracked object",
                "State",
            ),
            chain_rows,
            empty="No policy sends traffic through a service yet.",
            note="The probes are run by IP SLA entries (from 20001) and tracked objects ePBR "
            "makes itself, which the IP SLA and Tracked objects pages show too; with them come "
            "route-maps and ACLs named epbr_. They go when the service does. Read when the page "
            "loads.",
        ),
        Table(
            "Counters",
            ("Policy", "Direction", "ACL", "Bucket", "Step and service", "Packets"),
            tuple(counter_rows),
            empty="No applied policy counts its traffic. Turn on Count the traffic on a policy "
            "below.",
            note="Read when the page loads.",
        ),
    )
    return ProtocolView(tuple(instances), tables, notes)


EPBR = Protocol(
    key="epbr",
    name="Enhanced policy-based routing",
    summary="Send chosen traffic through firewalls and other appliances, checked by probes",
    features=(FEATURE,),
    commands=COMMANDS,
    parse=lambda bodies: parse_epbr(bodies[0] if bodies else None, None),
    scopes=SCOPES,
    about=(
        "Make a service with its end-points (the appliances) and a probe, make an ACL for "
        "the traffic on the Security page, make a policy with a match for that ACL and a step "
        "for each service, then apply the policy to the interface the traffic comes in on."
    ),
)


@dataclass(frozen=True)
class EpbrPage:
    """Everything the Enhanced policy-based routing page shows."""

    protocol: Protocol
    view: ProtocolView
    interfaces: tuple[str, ...]  # VLAN interfaces, routed ports and port-channels
    vrfs: tuple[str, ...]  # default, management, then the others
    services_in_use: frozenset[str] = frozenset()
    applied_policies: frozenset[str] = frozenset()
    problem: str = ""
    missing: tuple[str, ...] = ()  # the epbr feature, when it is off


def load_epbr_page(client: NxapiClient) -> EpbrPage:
    """One request for the feature, interfaces and VRFs; while epbr is on, ``show epbr
    policy``, the configuration text, and for each applied policy its reverse chain and its
    counters."""
    feature, brief, vrf_body, vrf_members = client.show(*PAGE_COMMANDS)
    interfaces = layer3_interfaces(brief, parse_vrf_members(vrf_members))
    vrfs = vrf_choices(vrf_body)
    if not feature_states(feature).get(FEATURE, False):
        return EpbrPage(EPBR, ProtocolView(), interfaces, vrfs, missing=(FEATURE,))
    problem = ""
    try:
        (body,) = client.show(*COMMANDS)
    except NxapiCommandError as exc:
        body, problem = None, f"The switch did not report ePBR's state: {exc}"
    try:
        config: str | None = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = None
    parsed = parse_epbr_config(config or "")
    applied = parsed.applied
    if config is None:  # only the policies the state names as applied, forward
        applied = [
            Applied(text(r.get("intf_name")), "ip", text(r.get("pname")), False)
            for r in table_rows(body or {}, "TABLE_pmap", "ROW_pmap")
            if r.get("intf_name")
        ]
    reverse_bodies: dict[str, Any] = {}
    counters: dict[tuple[str, str], Any] = {}
    counting = {n for n, p in parsed.policies.items() if p.statistics}
    for name in dict.fromkeys(a.policy for a in applied):
        reverse = any(a.policy == name and a.reverse for a in applied)
        if reverse:
            try:
                (reverse_bodies[name],) = client.show(f"show epbr policy {name} reverse")
            except NxapiCommandError:
                pass
        if config is not None and name not in counting:
            continue
        for direction in ("forward", "reverse") if reverse else ("forward",):
            command = f"show epbr statistics policy {name}"
            command += " reverse" if direction == "reverse" else ""
            try:
                (stat,) = client.show(command)
            except NxapiCommandError:
                continue  # not counting
            if stat:
                counters[(name, direction)] = stat
    view = parse_epbr(body, config, reverse_bodies, counters)
    return EpbrPage(
        EPBR,
        view,
        interfaces,
        vrfs,
        frozenset(parsed.services_in_use),
        frozenset(parsed.applied_policies),
        problem,
    )


def check_epbr_place(page: EpbrPage, ident: dict[str, str]) -> None:
    """Refuse an interface the switch does not have, and note in ``ident`` whether the
    service or policy named is in use, which decides how its lines are sent."""
    for name in ("interface", "reverse_interface"):
        interface = ident.get(name, "").strip()
        if interface and interface not in page.interfaces:
            known = ", ".join(page.interfaces) or "none"
            raise ValueError(
                f"{interface} is not a VLAN interface (up to Vlan254), routed port or routed "
                f"port-channel on the switch; those are: {known}"
            )
    ident[SERVICE_IN_USE] = (
        "yes" if ident.get("service", "").strip() in page.services_in_use else ""
    )
    ident[POLICY_APPLIED] = (
        "yes" if ident.get("policy", "").strip() in page.applied_policies else ""
    )


def _with_family(scope: str, ident: dict[str, str]) -> dict[str, str]:
    """An end-point's family taken from its address when not picked; a picked one that
    does not fit the address is refused."""
    if scope not in ("endpoint", "reverse"):
        return ident
    address = ident.get("address", "").strip()
    if not address:
        return ident  # build_change names the field
    family = "ipv6" if ":" in address else "ip"
    picked = ident.get("family", "").strip()
    if picked and picked != family:
        raise ValueError(f"{address} is an {_family_word(family)} address: pick {family}")
    return {**ident, "family": family}


def build_epbr_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the ePBR page. A change to a service an applied policy uses, or
    to an applied policy, goes inside ``epbr session`` ... ``commit``, as the switch asks;
    what the session does not take is refused with the reason."""
    ident = _with_family(scope, ident)
    change = build_change(EPBR, scope, setting, action, ident, values)
    busy = (scope in _SERVICE_SIDE and ident.get(SERVICE_IN_USE) == "yes") or (
        scope in _POLICY_SIDE and ident.get(POLICY_APPLIED) == "yes"
    )
    if not busy or (action == "create" and scope in _NOT_IN_SESSION):
        return change  # making one that exists only enters it
    if scope == "service":
        if action == "delete":
            raise ValueError(
                "a policy applied to an interface uses this service: take that policy off its "
                "interfaces first"
            )
        raise ValueError(
            "a policy applied to an interface uses this service, and the switch changes a "
            "service's probe, service interface and VRF only while none does: take that "
            "policy off its interfaces first"
        )
    if scope == "policy":
        if action == "delete":
            raise ValueError("the policy is applied to an interface: take it off there first")
        raise ValueError(
            "the switch turns counting on or off only while the policy is applied to no "
            "interface: take it off its interfaces first"
        )
    return dataclasses.replace(
        change,
        lines=(SESSION_LINE, *change.lines, COMMIT_LINE),
        labels=(SESSION_LINE, *change.labels, COMMIT_LINE),
    )
