"""AAA on the switch: how people sign in (the switch's own accounts, or RADIUS and TACACS+
server groups), what is logged where (accounting), which commands a TACACS+ server allows,
and the RADIUS and TACACS+ servers and groups themselves.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (the sign-in and accounting methods, the RADIUS servers, a
RADIUS group, the TACACS+ servers, a TACACS+ group), each setting the one configuration
line it sends with checked values in its blanks, and ``build_change`` building the lines.
``NxapiClient.configure_aaa`` sends them.

These lines decide who may sign in to the switch, NXray's own account included, so NXray's
broad role keeps denying them (``app/port_changes.py``): changes go with the stored admin
login only, and only an NXray admin makes them. A server key is sent as ``key 0 <key>``
(typed in the clear; the switch stores it encrypted, ``key 7``) and never shown back.

Read from the switch: ``show aaa authentication``, ``show aaa authentication login
error-enable``, ``show aaa accounting``, ``show aaa authorization``, ``show aaa groups``,
``show aaa user default-role``, ``show radius-server`` and ``show vrf`` in one request;
``show radius-server groups`` on its own (network-operator, and so NXray's limited account,
is refused it: the page then says so); ``show tacacs-server`` and ``show tacacs-server
groups`` in a third (the switch refuses them while ``feature tacacs+`` is off). With the
admin login stored, the page reads with it.

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-12) with throwaway servers at documentation
addresses (192.0.2.x) and throwaway groups, all removed afterwards: ``feature tacacs+``,
``tacacs-server host <a> key 0 <k> port <p> timeout <s>`` (without a key it warns "no key
is configured for the host" and takes it), ``radius-server host <a> key 0 <k> auth-port
<p> acct-port <p> authentication accounting timeout <s> retransmit <n>``, ``aaa group
server tacacs+|radius <g>`` with ``server <a>``, ``use-vrf <v>`` and ``deadtime <m>`` and
their ``no`` forms (which name the value), ``no aaa group server ...``, ``no
tacacs-server|radius-server host <a>``, and ``tacacs-server timeout|deadtime <n>`` and
``tacacs-server key 0 <k>`` with their ``no`` forms (a bare ``no tacacs-server timeout``
is "% Incomplete command": the value is needed). Not tried, because each changes how
people sign in to a switch in production: the ``aaa authentication``, ``aaa accounting``
and ``aaa authorization`` lines, the RADIUS switch-wide lines and ``aaa user
default-role`` (from Cisco's NX-OS 9.3 Security Configuration Guide).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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
from app.switch import text
from app.switch_admin import vrf_choices

PAGE_COMMANDS = (
    "show aaa authentication",
    "show aaa authentication login error-enable",
    "show aaa accounting",
    "show aaa authorization",
    "show aaa groups",
    "show aaa user default-role",
    "show radius-server",
    "show vrf",
)
# NXray's limited account (network-operator) is refused this one (seen on cisco-25gb); the
# broad role and the admin login may read it.
RADIUS_GROUPS_COMMAND = "show radius-server groups"
TACACS_COMMANDS = ("show tacacs-server", "show tacacs-server groups")
SERVICES = ("default", "console")
AUTHORIZATIONS = ("commands", "config-commands")
# What ``show aaa authorization`` names, in words; anything else keeps its own name.
AUTHORIZATION_LABELS = {
    "pki_ssh_cert_author": "SSH certificate sign-ins checked by",
    "pki_ssh_pubkey_author": "SSH key sign-ins checked by",
}
# The RADIUS group every switch has: all its RADIUS servers. It cannot be removed.
BUILT_IN_GROUP = "radius"

LOCKOUT_WARNING = (
    "Everyone signs in this way from now on, NXray's own account and the stored admin "
    "login included. A group with no server that answers, or a server that does not know "
    "the accounts, can lock everyone out; the switch falls back to its own accounts only "
    "while every server of the groups is unreachable (and the fallback is on). Keep a "
    "session to the switch open until a new sign-in works."
)


def _groups(hint: str) -> tuple[Field, ...]:
    """Up to three server groups, tried in order."""
    return (
        Field("group1", "Server group", "name", hint=hint),
        Field("group2", "Then group", "name", optional=True),
        Field("group3", "Then group", "name", optional=True),
    )


def _in_order(values: dict[str, str]) -> None:
    """A third group needs a second."""
    if values.get("group3") and not values.get("group2"):
        raise ValueError("give the second group before the third")


def _not_default_vrf(values: dict[str, str]) -> None:
    if not values.get("vrf"):
        raise ValueError(
            "the group uses the default VRF without this line: Remove it to go back to it"
        )


_SERVICE = Field(
    "service",
    "Sign-ins",
    "choice",
    choices=SERVICES,
    hint="default: SSH, NX-API and the web; console: the serial port",
)

_METHODS = Scope(
    key="methods",
    label="Sign-in and accounting",
    ident=(),
    enter=(),
    help=(
        "How the switch checks who signs in, and where it records what they do. The "
        "switch starts with its own accounts (local) for both."
    ),
    settings=(
        Setting(
            key="login_groups",
            label="Sign in through server groups",
            line="aaa authentication login {service} group {group1}[ {group2}][ {group3}]",
            removable=False,
            group="Sign-in",
            fields=(
                _SERVICE,
                *_groups("A RADIUS or TACACS+ group, or radius for every RADIUS server"),
            ),
            check=_in_order,
            warning=LOCKOUT_WARNING,
        ),
        Setting(
            key="login_local",
            label="Sign in with the switch's own accounts only",
            line="aaa authentication login {service} local",
            removable=False,
            group="Sign-in",
            fields=(_SERVICE,),
            help="How the switch starts.",
        ),
        Setting(
            key="fallback",
            label="Fall back to the switch's own accounts",
            line="aaa authentication login {service} fallback error local",
            group="Sign-in",
            fields=(_SERVICE,),
            help=(
                "On from the start: while every server of the groups is unreachable, the "
                "switch's own accounts still sign in. Remove turns it off, which can lock "
                "everyone out when the servers are down."
            ),
        ),
        Setting(
            key="error_enable",
            label="Say why a sign-in failed",
            line="aaa authentication login error-enable",
            group="Sign-in",
            help="Off from the start: the person signing in sees the server's reason.",
        ),
        Setting(
            key="default_role",
            label="Give server accounts without a role network-operator",
            line="aaa user default-role",
            group="Sign-in",
            help=(
                "On from the start: an account the server gives no role still signs in, "
                "with the read-only role. Remove refuses such accounts."
            ),
        ),
        Setting(
            key="acct_groups",
            label="Record to server groups",
            line="aaa accounting default group {group1}[ {group2}][ {group3}]",
            removable=False,
            group="Accounting",
            fields=_groups("A RADIUS or TACACS+ group"),
            check=_in_order,
            help="Who signed in and the commands they typed go to the groups' servers.",
        ),
        Setting(
            key="acct_local",
            label="Record on the switch only",
            line="aaa accounting default local",
            removable=False,
            group="Accounting",
            help="How the switch starts: show accounting log reads it.",
        ),
        Setting(
            key="authorization",
            label="Ask TACACS+ before each command",
            line="aaa authorization {kind} default group {group1}[ {group2}][ {group3}][ {local}]",
            group="Command authorization",
            fields=(
                Field(
                    "kind",
                    "Commands",
                    "choice",
                    choices=AUTHORIZATIONS,
                    hint="commands: every command; config-commands: configuration only",
                ),
                *_groups("A TACACS+ group"),
                Field("local", "If the servers do not answer", "flag", choices=("local",)),
            ),
            check=_in_order,
            warning=(
                "Every command typed on the switch, NXray's included, is refused unless the "
                "TACACS+ server allows it for that account. A server that does not list "
                "NXray's commands stops NXray from working."
            ),
            help="Needs TACACS+ on. Remove names the same groups.",
        ),
    ),
)


def _server_fields(port_fields: tuple[Field, ...]) -> tuple[Field, ...]:
    return (
        Field("host", "Server", "host", placeholder="192.0.2.10"),
        Field(
            "key",
            "Shared key",
            "secret",
            optional=True,
            hint="Without it the switch-wide key is used. Never shown back.",
        ),
        *port_fields,
        Field("timeout", "Wait (seconds)", "int", 1, 60, optional=True, hint="Default 5"),
    )


_RADIUS = Scope(
    key="radius",
    label="RADIUS servers",
    ident=(),
    enter=(),
    help="The RADIUS servers the switch may ask, and what holds for all of them.",
    settings=(
        Setting(
            key="host",
            label="Server",
            line="radius-server host {host}[ key 0 {key}][ auth-port {auth_port}]"
            "[ acct-port {acct_port}][ {authentication}][ {accounting}][ timeout {timeout}]"
            "[ retransmit {retransmit}]",
            no_line="no radius-server host {host}",
            group="Servers",
            fields=(
                *_server_fields(
                    (
                        Field(
                            "auth_port",
                            "Sign-in port",
                            "int",
                            0,
                            65535,
                            optional=True,
                            hint="Default 1812",
                        ),
                        Field(
                            "acct_port",
                            "Accounting port",
                            "int",
                            0,
                            65535,
                            optional=True,
                            hint="Default 1813",
                        ),
                    )
                ),
                Field("retransmit", "Tries", "int", 0, 5, optional=True, hint="Default 1"),
                Field("authentication", "Use for sign-in", "flag", choices=("authentication",)),
                Field("accounting", "Use for accounting", "flag", choices=("accounting",)),
            ),
            help="Set adds a server or changes one. Remove needs only the address.",
        ),
        Setting(
            key="key",
            label="Switch-wide key",
            line="radius-server key 0 {key}",
            group="All servers",
            fields=(Field("key", "Shared key", "secret"),),
            help="For servers without a key of their own. Remove asks for the key again.",
        ),
        Setting(
            key="timeout",
            label="Wait for an answer",
            line="radius-server timeout {seconds}",
            group="All servers",
            fields=(Field("seconds", "Seconds", "int", 1, 60, hint="Default 5"),),
        ),
        Setting(
            key="retransmit",
            label="Tries",
            line="radius-server retransmit {count}",
            group="All servers",
            fields=(Field("count", "Tries", "int", 0, 5, hint="Default 1"),),
        ),
        Setting(
            key="deadtime",
            label="Skip a server that did not answer",
            line="radius-server deadtime {minutes}",
            group="All servers",
            fields=(
                Field("minutes", "Minutes", "int", 0, 1440, hint="0 (the default): never skip"),
            ),
        ),
    ),
)

_TACACS = Scope(
    key="tacacs",
    label="TACACS+ servers",
    ident=(),
    enter=(),
    help="The TACACS+ servers the switch may ask. Needs tacacs+ on (Features page).",
    settings=(
        Setting(
            key="host",
            label="Server",
            line="tacacs-server host {host}[ key 0 {key}][ port {port}][ timeout {timeout}]",
            no_line="no tacacs-server host {host}",
            group="Servers",
            fields=_server_fields(
                (Field("port", "Port", "int", 1, 65535, optional=True, hint="Default 49"),)
            ),
            help="Set adds a server or changes one. Remove needs only the address.",
        ),
        Setting(
            key="key",
            label="Switch-wide key",
            line="tacacs-server key 0 {key}",
            group="All servers",
            fields=(Field("key", "Shared key", "secret"),),
            help="For servers without a key of their own. Remove asks for the key again.",
        ),
        Setting(
            key="timeout",
            label="Wait for an answer",
            line="tacacs-server timeout {seconds}",
            group="All servers",
            fields=(Field("seconds", "Seconds", "int", 1, 60, hint="Default 5"),),
        ),
        Setting(
            key="deadtime",
            label="Skip a server that did not answer",
            line="tacacs-server deadtime {minutes}",
            group="All servers",
            fields=(
                Field("minutes", "Minutes", "int", 0, 1440, hint="0 (the default): never skip"),
            ),
        ),
    ),
)


def _group_scope(key: str, label: str, kind: str, help_text: str) -> Scope:
    return Scope(
        key=key,
        label=label,
        ident=(Field("group", "Group", "name", hint="Letters, digits, . _ -"),),
        enter=(f"aaa group server {kind} {{group}}",),
        create=True,
        create_label=f"Make a {label.lower()}",
        delete=(f"no aaa group server {kind} {{group}}",),
        delete_warning="Sign-in or accounting that names this group stops using it.",
        help=help_text,
        settings=(
            Setting(
                key="server",
                label="Server in the group",
                line="server {server}",
                group="Servers",
                fields=(Field("server", "Server", "host"),),
                help="Add the server under the servers above first.",
            ),
            Setting(
                key="vrf",
                label="Reach the servers in VRF",
                line="use-vrf {vrf}",
                group="Settings",
                fields=(Field("vrf", "VRF", "usevrf"),),
                check=_not_default_vrf,
                help="management for servers reached through mgmt0.",
            ),
            Setting(
                key="deadtime",
                label="Skip a server that did not answer",
                line="deadtime {minutes}",
                group="Settings",
                fields=(Field("minutes", "Minutes", "int", 0, 1440),),
            ),
        ),
    )


_RADIUS_GROUP = _group_scope(
    "radius_group",
    "RADIUS group",
    "radius",
    "A list of RADIUS servers that sign-in and accounting name.",
)
_TACACS_GROUP = _group_scope(
    "tacacs_group",
    "TACACS+ group",
    "tacacs+",
    "A list of TACACS+ servers that sign-in, accounting and command checks name.",
)


def _methods_text(rows: list[dict[str, Any]], key: str) -> dict[str, str]:
    return {text(r.get("service")): text(r.get(key)) for r in rows if r.get("service")}


def _servers(body: Any, tacacs: bool) -> tuple[tuple[str, ...], ...]:
    out = []
    for row in table_rows(body, "TABLE_server", "ROW_server"):
        ports = (
            text(row.get("port")) or "49"
            if tacacs
            else f"{text(row.get('auth_port')) or '1812'} / {text(row.get('acct_port')) or '1813'}"
        )
        cells = [
            text(row.get("server_ip")),
            ports,
            text(row.get("timeout")) or "switch-wide",
        ]
        if not tacacs:
            cells.append(text(row.get("retries")) or "switch-wide")
        cells.append("yes" if row.get("secretKey") else "switch-wide")
        out.append(tuple(cells))
    return tuple(out)


def _group_instances(body: Any, scope: str) -> list[Instance]:
    out = []
    for row in table_rows(body, "TABLE_group", "ROW_group"):
        name = text(row.get("group_name"))
        if not name or (scope == "radius_group" and name == BUILT_IN_GROUP):
            continue
        members = [
            text(server.get("server_ip"))
            for server in table_rows(row, "TABLE_server", "ROW_server")
            if server.get("server_ip")
        ]
        vrf = text(row.get("vrf_name"))
        deadtime = text(row.get("dead_time"))
        values: dict[str, dict[str, str]] = {}
        if vrf:
            values["vrf"] = {"vrf": vrf}
        if deadtime and deadtime != "0":
            values["deadtime"] = {"minutes": deadtime}
        out.append(
            Instance(
                scope,
                {"group": name},
                name,
                (
                    ("Servers", ", ".join(members) or "none"),
                    ("VRF", vrf or "default"),
                    ("Skip for (minutes)", deadtime or "0"),
                ),
                values,
            )
        )
    return out


def _globals(body: Any, tacacs: bool) -> tuple[tuple[str, str], ...]:
    body = body if isinstance(body, dict) else {}
    facts = [
        ("Wait (seconds)", text(body.get("global_timeout")) or "-"),
        ("Skip a silent server (minutes)", text(body.get("global_deadtime")) or "0"),
        ("Source interface", text(body.get("global_source_intf")) or "-"),
        ("Servers", text(body.get("server_count")) or "0"),
    ]
    if not tacacs:
        facts.insert(1, ("Tries", text(body.get("retransmissionCount")) or "-"))
    return tuple(facts)


def _values_of(body: Any, tacacs: bool) -> dict[str, dict[str, str]]:
    body = body if isinstance(body, dict) else {}
    values: dict[str, dict[str, str]] = {}
    if text(body.get("global_timeout")):
        values["timeout"] = {"seconds": text(body.get("global_timeout"))}
    if text(body.get("global_deadtime")):
        values["deadtime"] = {"minutes": text(body.get("global_deadtime"))}
    if not tacacs and text(body.get("retransmissionCount")):
        values["retransmit"] = {"count": text(body.get("retransmissionCount"))}
    return values


def parse_aaa(bodies: list[Any], radius_groups: Any, tacacs: list[Any] | None) -> ProtocolView:
    """The page from the first request's bodies (``PAGE_COMMANDS`` order), the RADIUS
    groups (None when the account may not read them) and the TACACS+ bodies (None while
    TACACS+ is off)."""
    authen, error_enable, accounting, authorization, groups, default_role = bodies[:6]
    radius = bodies[6]
    login = _methods_text(table_rows(authen, "TABLE_AuthenMethods", "ROW_AuthenMethods"), "method")
    acct = _methods_text(table_rows(accounting, "TABLE_acctMethods", "ROW_acctMethods"), "methods")
    role = text(((default_role or {}).get("default_role_status") or {}).get("udr_status"))
    facts = [
        ("Default sign-in", login.get("default", "-")),
        ("Console sign-in", login.get("console", "-")),
        ("Reason shown when a sign-in fails", text((error_enable or {}).get("status")) or "-"),
        ("Accounting", acct.get("default", "-")),
        ("Server accounts without a role", "network-operator" if role == "enabled" else "refused"),
    ]
    for key, value in (authorization or {}).items():
        if isinstance(value, (str, int)):
            facts.append((AUTHORIZATION_LABELS.get(key, f"Authorization ({key})"), text(value)))
    values: dict[str, dict[str, str]] = {}
    if text((error_enable or {}).get("status")) == "enabled":
        values["error_enable"] = {}
    if role == "enabled":
        values["default_role"] = {}
    instances = [Instance("methods", {}, "Sign-in and accounting", tuple(facts), values)]
    instances.append(
        Instance(
            "radius", {}, "RADIUS, all servers", _globals(radius, False), _values_of(radius, False)
        )
    )
    notes: list[str] = []
    if radius_groups is None:
        notes.append(
            "NXray's account may not read the RADIUS groups (show radius-server groups): "
            "store the switch admin login on the Switch page to see them here."
        )
    else:
        instances += _group_instances(radius_groups, "radius_group")
    tables = [
        Table(
            "RADIUS servers",
            ("Server", "Ports (sign-in / accounting)", "Wait (s)", "Tries", "Own key"),
            _servers(radius, False),
            empty="No RADIUS server is set.",
        )
    ]
    if tacacs is None:
        notes.append(
            "TACACS+ is off on the switch (feature tacacs+): an NXray admin turns it on on "
            "the Features page to set TACACS+ servers and groups."
        )
    else:
        instances.append(
            Instance(
                "tacacs",
                {},
                "TACACS+, all servers",
                _globals(tacacs[0], True),
                _values_of(tacacs[0], True),
            )
        )
        instances += _group_instances(tacacs[1], "tacacs_group")
        tables.append(
            Table(
                "TACACS+ servers",
                ("Server", "Port", "Wait (s)", "Own key"),
                _servers(tacacs[0], True),
                empty="No TACACS+ server is set.",
            )
        )
    names = [text(r.get("group")) for r in table_rows(groups, "TABLE_groups", "ROW_groups")]
    tables.append(
        Table(
            "Server groups",
            ("Group",),
            tuple((name,) for name in names if name),
            empty="No server group.",
            note=f"{BUILT_IN_GROUP} is the switch's own group of every RADIUS server.",
        )
    )
    return ProtocolView(tuple(instances), tuple(tables), tuple(notes))


AAA = Protocol(
    key="aaa",
    name="AAA",
    summary="How people sign in to the switch, what is recorded, and the RADIUS and "
    "TACACS+ servers",
    features=(),
    commands=(),
    parse=lambda bodies: ProtocolView(),
    scopes=(_METHODS, _RADIUS, _RADIUS_GROUP, _TACACS, _TACACS_GROUP),
    about=(
        "AAA (authentication, authorization and accounting) decides who may sign in, what "
        "they may type and where it is recorded. Changes need the stored admin login and an "
        "NXray admin: a wrong one can lock everyone out, NXray included."
    ),
)


@dataclass(frozen=True)
class AaaPage:
    """Everything the AAA page shows."""

    protocol: Protocol
    view: ProtocolView
    vrfs: tuple[str, ...]
    groups: tuple[str, ...]  # every server group's name
    tacacs_on: bool
    problem: str = ""
    missing: tuple[str, ...] = ()  # always empty: RADIUS needs no feature


def load_aaa_page(client: NxapiClient) -> AaaPage:
    """One request for the AAA, RADIUS and VRF reads; one for the RADIUS groups, which
    NXray's limited account is refused; one for TACACS+, which the switch refuses while it
    is off."""
    bodies = client.show(*PAGE_COMMANDS)
    try:
        (radius_groups,) = client.show(RADIUS_GROUPS_COMMAND)
    except NxapiCommandError:
        radius_groups = None
    try:
        tacacs: list[Any] | None = client.show(*TACACS_COMMANDS)
    except NxapiCommandError:
        tacacs = None
    groups = tuple(
        text(r.get("group")) for r in table_rows(bodies[4], "TABLE_groups", "ROW_groups")
    )
    return AaaPage(
        AAA,
        parse_aaa(bodies, radius_groups, tacacs),
        vrf_choices(bodies[7]),
        tuple(g for g in groups if g),
        tacacs is not None,
    )


def build_aaa_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the AAA page. The switch's own RADIUS group is not changed."""
    if scope == "radius_group" and ident.get("group", "").strip() == BUILT_IN_GROUP:
        raise ValueError(f"{BUILT_IN_GROUP} is the switch's own group of every RADIUS server")
    return build_change(AAA, scope, setting, action, ident, values)
