"""802.1X port authentication: a device must sign in before its port lets it on the
network.

The switch (the authenticator) passes what the device sends to a RADIUS server, which
says yes or no; until then the port carries nothing but the sign-in. The page is
described with the same parts as the Monitor sessions page (``app/protocols.py``):
scopes (the switch, a port), each setting the one configuration line it sends with
checked values in its blanks, and ``build_change`` building the lines.
``NxapiClient.configure_dot1x`` sends them.

Read from the switch: ``show feature`` and ``show interface brief`` in one request;
while ``feature dot1x`` is on (the commands are refused before), ``show dot1x`` and
``show dot1x all details`` as text (``NxapiClient.show_text``).

NOT tried on a switch (cisco-25gb is in production and has 802.1X off). Written from
Cisco's NX-OS 9.3 Security Configuration Guide ("Configuring 802.1X") and its ``show
dot1x all``, ``show dot1x all details`` and ``show running-config dot1x all`` samples:

* switch-wide: ``dot1x system-auth-control``, ``aaa authentication dot1x default group
  <group>``, ``aaa accounting dot1x default group <group>``, ``dot1x radius-accounting``
  and ``dot1x mac-move permit|deny``;
* per port: ``dot1x port-control auto|force-authorized|force-unauthorized``, ``dot1x
  host-mode single-host|multi-host|multi-auth``, ``dot1x pae authenticator``, ``dot1x
  re-authentication``, ``dot1x timeout <timer> <1-65535>``, ``dot1x max-req <1-10>``,
  ``dot1x max-reauth-req <1-10>`` and ``dot1x mac-auth-bypass [eap]``.

The guide writes the third port-control word as ``forced-unauthorized`` in one place and
``force-unauthorized`` in another; the second is sent. NX-OS has no guest VLAN (the
guide lists it as not supported) and no auth-fail VLAN, so the page has neither. The
RADIUS servers and server groups themselves are not made here.

The show text is read tolerantly: any ``Label = Value`` line under a port or a signed-in
device is kept, and one the switch words differently shows empty rather than breaking
the page.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

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
from app.spanning_tree import switch_port_names

PAGE_COMMANDS = ("show feature", "show interface brief")
GLOBAL_COMMAND = "show dot1x"
DETAILS_COMMAND = "show dot1x all details"
PORT_CONTROLS = ("auto", "force-authorized", "force-unauthorized")
HOST_MODES = ("single-host", "multi-host", "multi-auth")
TIMERS = (
    "re-authperiod",
    "quiet-period",
    "tx-period",
    "supp-timeout",
    "server-timeout",
    "ratelimit-period",
    "inactivity-period",
)
MAC_MOVE = ("permit", "deny")
TIMEOUT_MAX = 65535
RETRY_MAX = 10
GROUP_MAX = 127  # an AAA server group's name


def _group(label: str) -> Field:
    return Field(
        "group",
        label,
        "name",
        maximum=GROUP_MAX,
        hint="radius (every RADIUS server), or the name of a RADIUS server group",
        placeholder="radius",
    )


_SWITCH = Scope(
    key="dot1x_switch",
    label="Whole switch",
    ident=(),
    enter=(),
    help="802.1X for the switch as a whole. The RADIUS servers are set up on the switch "
    "first; NXray does not make them yet.",
    settings=(
        Setting(
            key="auth_group",
            label="RADIUS servers that check sign-ins",
            line="aaa authentication dot1x default group {group}",
            group="RADIUS",
            fields=(_group("Server group"),),
            help="Without this no device can sign in.",
        ),
        Setting(
            key="accounting_group",
            label="RADIUS servers that get accounting",
            line="aaa accounting dot1x default group {group}",
            group="RADIUS",
            fields=(_group("Server group"),),
            help="Where the switch reports each sign-in and sign-out.",
        ),
        Setting(
            key="radius_accounting",
            label="RADIUS accounting for 802.1X",
            line="dot1x radius-accounting",
            group="RADIUS",
            help="Off until set.",
        ),
        Setting(
            key="system_auth",
            label="802.1X on the switch",
            line="dot1x system-auth-control",
            group="802.1X",
            help="On as soon as the feature is on. Remove stops 802.1X everywhere but "
            "keeps every port's settings: all ports then let every device on.",
        ),
        Setting(
            key="mac_move",
            label="A signed-in device moving to another port",
            line="dot1x mac-move {policy}",
            removable=False,
            group="802.1X",
            fields=(Field("policy", "Moving", "choice", choices=MAC_MOVE),),
            help="permit: the device may sign in on the new port; deny: it is refused "
            "there while still signed in on the old one.",
        ),
    ),
)

_PORT = Scope(
    key="dot1x_port",
    label="Port",
    ident=(
        Field(
            "port",
            "Port",
            "port",
            hint="A front port carrying VLANs, such as Ethernet1/3",
            placeholder="Ethernet1/3",
        ),
    ),
    enter=("interface {port}",),
    help="802.1X on one front port. Not for port-channels, routed ports or private VLAN "
    "ports; use it on ports that go to end devices.",
    settings=(
        Setting(
            key="port_control",
            label="Port control",
            line="dot1x port-control {control}",
            no_line="no dot1x port-control",
            group="Sign-in",
            fields=(
                Field(
                    "control",
                    "Control",
                    "choice",
                    choices=PORT_CONTROLS,
                    hint="auto: devices must sign in; force-authorized: everyone is let "
                    "on (the default); force-unauthorized: nobody is",
                ),
            ),
            help="Whether devices on this port must sign in.",
            warning="With auto, devices on this port are cut off until they sign in; with "
            "force-unauthorized, for good.",
        ),
        Setting(
            key="host_mode",
            label="Host mode",
            line="dot1x host-mode {mode}",
            no_line="no dot1x host-mode",
            group="Sign-in",
            fields=(
                Field(
                    "mode",
                    "Mode",
                    "choice",
                    choices=HOST_MODES,
                    hint="single-host: one device (the default); multi-host: the first "
                    "device signs in for all; multi-auth: every device signs in",
                ),
            ),
            help="How many devices the port takes. Needs port control auto. A trunk or a "
            "port-channel member cannot be single-host.",
        ),
        Setting(
            key="mab",
            label="MAC authentication bypass",
            line="dot1x mac-auth-bypass [{eap}]",
            no_line="no dot1x mac-auth-bypass",
            group="Sign-in",
            fields=(Field("eap", "Send it as EAP", "flag", choices=("eap",)),),
            help="A device that cannot sign in (a printer, a camera) is checked by its "
            "MAC address at the RADIUS server instead.",
        ),
        Setting(
            key="pae",
            label="Authenticator role",
            line="dot1x pae authenticator",
            group="Sign-in",
            help="The switch makes this by itself when 802.1X is set on the port. Remove "
            "takes the port out of 802.1X.",
        ),
        Setting(
            key="reauth",
            label="Sign in again regularly",
            line="dot1x re-authentication",
            group="Timers",
            help="Each device signs in again every re-authperiod (3600 seconds unless set).",
        ),
        Setting(
            key="timeout",
            label="A timer",
            line="dot1x timeout {timer} {seconds}",
            no_line="no dot1x timeout {timer}",
            group="Timers",
            fields=(
                Field(
                    "timer",
                    "Timer",
                    "choice",
                    choices=TIMERS,
                    hint="re-authperiod: between sign-ins (3600); quiet-period: wait after "
                    "a failed sign-in (60); tx-period: between requests to a silent device "
                    "(30); supp-timeout: wait for the device (30); server-timeout: wait for "
                    "the RADIUS server (30); ratelimit-period: ignore repeated starts (0); "
                    "inactivity-period: sign a silent device out (0 = never)",
                ),
                Field("seconds", "Seconds", "int", minimum=1, maximum=TIMEOUT_MAX),
            ),
            help="Set one timer at a time. Remove needs only the timer's name and puts it "
            "back to the switch's own value.",
        ),
        Setting(
            key="max_req",
            label="Requests to the device before giving up",
            line="dot1x max-req {count}",
            no_line="no dot1x max-req",
            group="Timers",
            fields=(Field("count", "Times", "int", minimum=1, maximum=RETRY_MAX, placeholder="2"),),
            help="1 to 10; the switch starts with 2. Needs port control auto.",
        ),
        Setting(
            key="max_reauth_req",
            label="Sign-in restarts before the port is refused",
            line="dot1x max-reauth-req {count}",
            no_line="no dot1x max-reauth-req",
            group="Timers",
            fields=(Field("count", "Times", "int", minimum=1, maximum=RETRY_MAX, placeholder="2"),),
            help="1 to 10; the switch starts with 2.",
        ),
    ),
)


@dataclass
class Dot1xPort:
    """One port's block in ``show dot1x all details``: its ``Label = Value`` lines (labels
    in lower case) and the devices signed in on it."""

    name: str
    settings: dict[str, str] = field(default_factory=dict)
    clients: list[dict[str, str]] = field(default_factory=list)


_HEADING = re.compile(r"^\s*Dot1x Info for\s+(\S+)\s*$", re.IGNORECASE)
_CLIENT_LIST = re.compile(r"^\s*Dot1x (Authenticator|Supplicant) Client List\s*$", re.IGNORECASE)
_PAIR = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 /_-]*?)\s*=\s*(.*?)\s*$")
_GLOBAL = re.compile(r"^\s*(Sysauthcontrol|Dot1x Protocol Version|Mac-Move)\s+(\S+)", re.IGNORECASE)


def parse_dot1x_global(*texts: str) -> dict[str, str]:
    """The switch-wide lines of ``show dot1x`` (and the top of ``show dot1x all``):
    ``{"sysauthcontrol": "Enabled", "dot1x protocol version": "2", "mac-move":
    "Deny"}``, with what the switch left out left out."""
    found: dict[str, str] = {}
    for text_out in texts:
        for line in text_out.splitlines():
            if _HEADING.match(line):
                break  # the ports follow
            if match := _GLOBAL.match(line):
                found.setdefault(match.group(1).lower(), match.group(2))
    return found


def parse_dot1x_ports(text_out: str) -> list[Dot1xPort]:
    """The ports in ``show dot1x all details``, each with its settings and the devices
    in its authenticator client list. A port's second block (the switch signing in to
    another switch) and that list are left out."""
    ports: dict[str, Dot1xPort] = {}
    current: Dot1xPort | None = None
    section = "port"  # "port", "clients" (devices signed in here) or "other"
    for line in text_out.splitlines():
        if match := _HEADING.match(line):
            current = ports.setdefault(match.group(1), Dot1xPort(match.group(1)))
            section = "port"
            continue
        if current is None:
            continue
        if match := _CLIENT_LIST.match(line):
            section = "clients" if match.group(1).lower() == "authenticator" else "other"
            continue
        match = _PAIR.match(line)
        if not match:
            continue
        label, value = match.group(1).lower(), match.group(2)
        if section == "port":
            if label == "pae" and current.settings.get("pae"):
                section = "other"  # the supplicant block of the same port
                continue
            current.settings.setdefault(label, value)
        elif section == "clients":
            if label == "supplicant":
                current.clients.append({})
            if current.clients:
                current.clients[-1].setdefault(label, value)
    return list(ports.values())


def _choice(value: str, choices: tuple[str, ...]) -> str:
    """'MULTI AUTH' -> 'multi-auth', 'FORCE_AUTH' -> 'force-authorized': the choice a
    value the switch prints stands for, or "" for one that is none of them."""
    word = re.sub(r"[\s_]+", "-", value.strip().lower())
    for choice in choices:
        if word == choice:
            return choice
    for choice in choices:
        if word and choice.startswith(word.replace("forced", "force")):
            return choice
    return ""


def _on(value: str) -> bool:
    return value.strip().lower() in ("enabled", "enable", "true", "yes", "on")


def parse_dot1x(global_text: str, details_text: str) -> ProtocolView:
    """The page from ``show dot1x`` and ``show dot1x all details``: the switch-wide
    state, a place and a table row per port with 802.1X on it, and a table of the
    devices signed in."""
    switch = parse_dot1x_global(global_text, details_text)
    ports = parse_dot1x_ports(details_text)
    instances: list[Instance] = []
    if switch:
        values: dict[str, dict[str, str]] = {}
        move = switch.get("mac-move", "").lower()
        if move in MAC_MOVE:
            values["mac_move"] = {"policy": move}
        instances.append(
            Instance(
                "dot1x_switch",
                {},
                "802.1X on the switch",
                (
                    ("802.1X", switch.get("sysauthcontrol", "-")),
                    ("Protocol version", switch.get("dot1x protocol version", "-")),
                    ("Moving between ports", switch.get("mac-move", "-")),
                ),
                values,
            )
        )
    port_rows: list[tuple[str, ...]] = []
    client_rows: list[tuple[str, ...]] = []
    for port in ports:
        have = port.settings
        control = _choice(have.get("portcontrol", ""), PORT_CONTROLS)
        mode = _choice(have.get("hostmode", ""), HOST_MODES)
        port_values: dict[str, dict[str, str]] = {}
        if control:
            port_values["port_control"] = {"control": control}
        if mode:
            port_values["host_mode"] = {"mode": mode}
        for key, label in (("max_req", "maxreq"), ("max_reauth_req", "reauthmax")):
            if have.get(label, "").isdigit():
                port_values[key] = {"count": have[label]}
        facts = [
            ("Port control", have.get("portcontrol", "-")),
            ("Host mode", have.get("hostmode", "-")),
            ("Sign in again regularly", have.get("reauthentication", "-")),
            ("MAC authentication bypass", have.get("mac-auth-bypass", "-")),
        ]
        timers = [
            f"{name} {have[label]}"
            for name, label in (
                ("re-authperiod", "reauthperiod"),
                ("quiet-period", "quietperiod"),
                ("tx-period", "txperiod"),
                ("supp-timeout", "supptimeout"),
                ("server-timeout", "servertimeout"),
                ("ratelimit-period", "ratelimitperiod"),
                ("inactivity-period", "inactivityperiod"),
            )
            if have.get(label)
        ]
        if timers:
            facts.append(("Timers (seconds)", ", ".join(timers)))
        instances.append(
            Instance("dot1x_port", {"port": port.name}, port.name, tuple(facts), port_values)
        )
        port_rows.append(
            (
                port.name,
                have.get("portcontrol", "-"),
                have.get("hostmode", "-"),
                have.get("reauthentication", "-"),
                "on" if _on(have.get("mac-auth-bypass", "")) else "off",
                str(len(port.clients)),
            )
        )
        for client in port.clients:
            vlan = client.get("auth-vlan") or client.get("voice-vlan") or ""
            client_rows.append(
                (
                    port.name,
                    client.get("supplicant", "-"),
                    client.get("domain", "-"),
                    client.get("port status", "-"),
                    client.get("authentication method", "-"),
                    client.get("authenticated by", "-"),
                    vlan if vlan and vlan != "0" else "-",
                )
            )
    tables = (
        Table(
            "Signed-in devices",
            ("Port", "Device", "Domain", "Status", "Method", "Checked by", "VLAN"),
            tuple(client_rows),
            empty="No device is signed in on any port.",
            note="Method is EAP for a device that signed in itself, MAB for one checked "
            "by its MAC address. VLAN shows only when the RADIUS server gave one.",
        ),
        Table(
            "Ports with 802.1X",
            ("Port", "Port control", "Host mode", "Sign in again", "MAC bypass", "Devices"),
            tuple(port_rows),
            empty="No port is set up for 802.1X.",
        ),
    )
    return ProtocolView(tuple(instances), tables)


DOT1X = Protocol(
    key="dot1x",
    name="802.1X",
    summary="Make devices sign in before their port lets them on the network (802.1X)",
    features=("dot1x",),
    commands=(),
    parse=lambda bodies: ProtocolView(),
    scopes=(_SWITCH, _PORT),
    about=(
        "Set up in this order: the RADIUS servers on the switch, the RADIUS servers that "
        "check sign-ins here, then port control auto on each port. This kind of switch "
        "has no guest VLAN and no auth-fail VLAN: a device that fails stays off the "
        "network."
    ),
)


@dataclass(frozen=True)
class Dot1xPage:
    """Everything the 802.1X page shows."""

    protocol: Protocol
    view: ProtocolView
    ports: tuple[str, ...]  # the switched front ports
    problem: str = ""
    missing: tuple[str, ...] = ()  # the feature, when it is off


def load_dot1x_page(client: NxapiClient) -> Dot1xPage:
    """One request for the feature and the ports; while dot1x is on, one for the
    switch-wide state and one for the ports and the devices signed in."""
    feature, brief = client.show(*PAGE_COMMANDS)
    ports = tuple(p for p in switch_port_names(brief) if p.startswith("Ethernet"))
    states = feature_states(feature)
    missing = tuple(name for name in DOT1X.features if not states.get(name, False))
    if missing:
        return Dot1xPage(DOT1X, ProtocolView(), ports, missing=missing)
    problem = ""
    try:
        global_text = client.show_text(GLOBAL_COMMAND)
        details_text = client.show_text(DETAILS_COMMAND)
    except NxapiCommandError as exc:
        global_text = details_text = ""
        problem = f"The switch did not report 802.1X's state: {exc}"
    return Dot1xPage(DOT1X, parse_dot1x(global_text, details_text), ports, problem)


def build_dot1x_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the 802.1X page."""
    return build_change(DOT1X, scope, setting, action, ident, values)
