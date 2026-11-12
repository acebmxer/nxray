"""Smart Call Home: the switch's contact details, the destination profiles it sends its
messages to (email addresses or web addresses, the message format and level, the alert
groups), the mail server or web proxy it sends through, and a test message.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (the contact details and switch-wide settings, the
transport, one destination profile), each setting the one configuration line it sends
with checked values in its blanks, and ``build_change`` building the lines. Every line is
typed inside ``callhome``. ``NxapiClient.configure_callhome`` sends them.

Read from the switch, each as text: ``show callhome`` (on or off, and the contact
details), ``show callhome destination-profile`` (every profile, the three built-in ones
too), ``show callhome transport`` and ``show running-config callhome`` (what is set, for
the forms). The JSON forms of the profile and transport commands put the email and web
addresses in lists that do not line up, so the text is read instead.

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-11) with an account holding NXray's broad role,
with throwaway values, all removed afterwards: the contact lines and their bare ``no``
forms, ``destination-profile <name>`` and ``format``, ``index <n> email-addr`` and
``index <n> http`` (the switch refuses ``email-addr`` without an index), ``message-level``
and ``message-size`` (no ``no`` form: set the value), ``alert-group`` (kept in lower
case), ``transport-method`` (it adds a method: both give "email and http", and ``no
transport-method http`` takes one away), ``no destination-profile <name>``, and the
transport lines with their ``no`` forms. Not tried: ``enable`` (it starts sending), the
test message, ``switch-priority``, ``duplicate-message throttle``, ``periodic-inventory``
and ``transport http proxy enable`` (from Cisco's NX-OS 9.3 System Management
Configuration Guide).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

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
from app.switch_admin import vrf_choices

PAGE_COMMANDS = ("show vrf",)
STATUS_COMMAND = "show callhome"
PROFILES_COMMAND = "show callhome destination-profile"
TRANSPORT_COMMAND = "show callhome transport"
CONFIG_COMMAND = "show running-config callhome"
FORMATS = ("XML", "full-txt", "short-txt")
METHODS = ("email", "http")
ALERT_GROUPS = (
    "all",
    "cisco-tac",
    "configuration",
    "diagnostic",
    "eem",
    "environmental",
    "inventory",
    "license",
    "supervisor-hardware",
    "syslog-group-port",
    "system",
    "test",
)
INDEX_MAX = 50  # Cisco's guide: up to 50 addresses per profile
LEVELS = (
    "0 debugging, 1 normal, 2 notification, 3 warning, 4 minor, 5 major, 6 critical, "
    "7 fatal, 8 disaster, 9 catastrophic"
)


def _text_setting(key: str, label: str, line: str, hint: str, longest: int = 255) -> Setting:
    """A contact line with one text value, removed with its bare ``no`` form."""
    word = line.split(" ")[0]
    return Setting(
        key=key,
        label=label,
        line=line,
        no_line=f"no {word}",
        group="Contact",
        fields=(Field("value", label, "text", maximum=longest, hint=hint),),
    )


_CALLHOME = Scope(
    key="callhome",
    label="Call Home",
    ident=(),
    enter=("callhome",),
    help=(
        "Who looks after the switch, and whether Call Home runs. Cisco's guide asks for the "
        "email address, phone number and street address before it is turned on."
    ),
    settings=(
        Setting(
            key="email",
            label="Contact email",
            line="email-contact {email}",
            no_line="no email-contact",
            group="Contact",
            fields=(Field("email", "Email", "email", placeholder="noc@example.net"),),
        ),
        Setting(
            key="phone",
            label="Contact phone",
            line="phone-contact {phone}",
            no_line="no phone-contact",
            group="Contact",
            fields=(
                Field(
                    "phone",
                    "Phone",
                    "phone",
                    hint="+ and the digits, no spaces",
                    placeholder="+15550100",
                ),
            ),
        ),
        _text_setting("street", "Street address", "streetaddress {value}", "Where the switch is"),
        _text_setting("contract", "Contract ID", "contract-id {value}", "Your Cisco contract"),
        _text_setting("customer", "Customer ID", "customer-id {value}", "Your Cisco customer"),
        _text_setting("site", "Site ID", "site-id {value}", "A name for the site"),
        Setting(
            key="priority",
            label="Switch priority",
            line="switch-priority {priority}",
            removable=False,
            group="Messages",
            fields=(
                Field(
                    "priority",
                    "Priority",
                    "int",
                    0,
                    7,
                    hint="0 highest to 7 lowest; the switch starts with 7",
                ),
            ),
        ),
        Setting(
            key="throttle",
            label="Hold back repeated messages",
            line="duplicate-message throttle",
            group="Messages",
            help="On from the start: more than 30 of the same message in 2 hours are not "
            "sent. Remove sends every one.",
        ),
        Setting(
            key="inventory",
            label="Send the inventory regularly",
            line="periodic-inventory notification[ interval {days}][ timeofday {at}]",
            no_line="no periodic-inventory notification",
            group="Messages",
            fields=(
                Field("days", "Every (days)", "int", 1, 30, optional=True, hint="Default 7"),
                Field("at", "At", "hhmm", optional=True, hint="Default 08:00"),
            ),
            help="On from the start, every 7 days at 08:00.",
        ),
        Setting(
            key="enable",
            label="Call Home on",
            line="enable",
            no_line="no enable",
            group="On or off",
            warning="Call Home starts sending messages to every destination profile's "
            "addresses, the inventory every few days included.",
            help="Set turns Call Home on, Remove turns it off. Set the contact details and "
            "the transport first.",
        ),
        Setting(
            key="test",
            label="Send a test message",
            line="callhome test",
            removable=False,
            config=False,
            group="On or off",
            warning="The switch sends a test message to every destination profile's addresses now.",
            help="Needs Call Home on. Changes nothing in the configuration.",
        ),
    ),
)

_TRANSPORT = Scope(
    key="transport",
    label="How messages are sent",
    ident=(),
    enter=("callhome",),
    help=(
        "Email goes through a mail server (up to five); web messages go straight out, or "
        "through a proxy."
    ),
    settings=(
        Setting(
            key="mail_server",
            label="Mail server",
            line="transport email mail-server {server}[ port {port}][ priority {priority}]"
            "[ use-vrf {vrf}]",
            no_line="no transport email mail-server {server}",
            group="Email",
            fields=(
                Field("server", "Server address", "ip", placeholder="192.0.2.25"),
                Field("port", "Port", "int", 1, 65535, optional=True, hint="Default 25"),
                Field(
                    "priority",
                    "Priority",
                    "int",
                    1,
                    100,
                    optional=True,
                    hint="1 is tried first; default 50",
                ),
                Field("vrf", "Reached in VRF", "usevrf", optional=True),
            ),
            help="Remove needs only the address.",
        ),
        Setting(
            key="from",
            label="From address",
            line="transport email from {email}",
            group="Email",
            fields=(Field("email", "Email", "email", placeholder="switch@example.net"),),
        ),
        Setting(
            key="reply_to",
            label="Reply-to address",
            line="transport email reply-to {email}",
            group="Email",
            fields=(Field("email", "Email", "email"),),
        ),
        Setting(
            key="http_vrf",
            label="VRF for web messages",
            line="transport http use-vrf {vrf}",
            group="Web",
            fields=(Field("vrf", "VRF", "usevrf"),),
            help="Without it the default VRF is used.",
        ),
        Setting(
            key="proxy",
            label="Web proxy",
            line="transport http proxy server {server}[ port {port}]",
            group="Web",
            fields=(
                Field("server", "Proxy address", "ip"),
                Field("port", "Port", "int", 1, 65535, optional=True, hint="Default 8080"),
            ),
        ),
        Setting(
            key="proxy_on",
            label="Use the web proxy",
            line="transport http proxy enable",
            group="Web",
            help="Set the proxy's address first.",
        ),
    ),
)


def _profile_field() -> Field:
    return Field(
        "profile",
        "Profile",
        "name",
        maximum=31,
        hint="A name of your own",
        placeholder="noc",
    )


_PROFILE = Scope(
    key="profile",
    label="Destination profiles",
    ident=(_profile_field(),),
    enter=("callhome",),
    delete=("callhome", "no destination-profile {profile}"),
    delete_warning="Its addresses and alert groups go with it.",
    help=(
        "Where messages go and which ones: each profile has email or web addresses, a "
        "format, the lowest level it sends and the alert groups it takes. To make one, set "
        "Make the profile with a new name, then its settings."
    ),
    settings=(
        Setting(
            key="make",
            label="Make the profile",
            line="destination-profile {profile}",
            ident=("profile",),
            removable=False,
            group="Profile",
        ),
        Setting(
            key="format",
            label="Format",
            line="destination-profile {profile} format {format}",
            ident=("profile",),
            removable=False,
            group="Profile",
            fields=(Field("format", "Format", "choice", choices=FORMATS),),
        ),
        Setting(
            key="method",
            label="Send by",
            line="destination-profile {profile} transport-method {method}",
            ident=("profile",),
            group="Profile",
            fields=(Field("method", "Method", "choice", choices=METHODS),),
            help="Set adds a method (a profile can send both ways); Remove takes it away.",
        ),
        Setting(
            key="email",
            label="Email address",
            line="destination-profile {profile} index {index} email-addr {email}",
            ident=("profile",),
            group="Addresses",
            fields=(
                Field("index", "Number", "int", 1, INDEX_MAX, hint=f"1 to {INDEX_MAX}"),
                Field("email", "Email", "email"),
            ),
        ),
        Setting(
            key="url",
            label="Web address",
            line="destination-profile {profile} index {index} http {url}",
            ident=("profile",),
            group="Addresses",
            fields=(
                Field("index", "Number", "int", 1, INDEX_MAX, hint=f"1 to {INDEX_MAX}"),
                Field(
                    "url",
                    "Web address",
                    "weburl",
                    hint="http:// or https://; a ? cannot be sent",
                    placeholder="https://example.net/callhome",
                ),
            ),
        ),
        Setting(
            key="level",
            label="Lowest level sent",
            line="destination-profile {profile} message-level {level}",
            ident=("profile",),
            removable=False,
            group="Messages",
            fields=(Field("level", "Level", "int", 0, 9, hint=LEVELS),),
            help="0 sends everything; the switch starts with 0.",
        ),
        Setting(
            key="size",
            label="Largest message (bytes)",
            line="destination-profile {profile} message-size {size}",
            ident=("profile",),
            removable=False,
            group="Messages",
            fields=(Field("size", "Bytes", "int", 0, 5000000, hint="0 to 5000000"),),
        ),
        Setting(
            key="alert_group",
            label="Alert group",
            line="destination-profile {profile} alert-group {group}",
            ident=("profile",),
            group="Messages",
            fields=(Field("group", "Group", "choice", choices=ALERT_GROUPS),),
            help="Which kinds of message the profile gets; set one at a time.",
        ),
    ),
)


# The switch's own profiles: shown as ``full_txt`` and ``short_txt``, named
# ``full-txt-destination`` and ``short-txt-destination`` in their lines (Cisco's guide;
# CiscoTAC-1 is the same both ways). They cannot be deleted.
BUILT_IN = {
    "full_txt": "full-txt-destination",
    "short_txt": "short-txt-destination",
    "CiscoTAC-1": "CiscoTAC-1",
}

_BUILT_IN = Scope(
    key="builtin_profile",
    label="Built-in destination profiles",
    ident=(
        Field(
            "profile",
            "Profile",
            "choice",
            choices=tuple(BUILT_IN.values()),
            hint="CiscoTAC-1 sends to Cisco's support service",
        ),
    ),
    enter=("callhome",),
    help=(
        "The switch's own three profiles. Their settings change like any profile's; they "
        "cannot be deleted. Their names in the configuration lines are "
        "full-txt-destination, short-txt-destination and CiscoTAC-1. Not tried on a switch."
    ),
    settings=tuple(s for s in _PROFILE.settings if s.key != "make"),
)


# ---- reading the switch ------------------------------------------------------------------


def parse_label_lines(text_out: str) -> list[tuple[str, str]]:
    """Every ``label:value`` line of a Call Home show command, in order (the value may be
    empty); lines without a colon are left out."""
    found = []
    for line in text_out.splitlines():
        label, colon, value = line.strip().partition(":")
        if colon and label and not label.startswith("Index"):
            found.append((label.strip(), value.strip()))
    return found


@dataclass
class Profile:
    """One destination profile as ``show callhome destination-profile`` prints it."""

    name: str
    values: dict[str, str] = field(default_factory=dict)  # label -> value
    emails: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)


_PROFILE_HEAD = re.compile(r"^(\S+) destination profile information$")
_INDEXED = re.compile(r"^Index:\s*(\d+)\s+(\S+)$")


def parse_profiles(text_out: str) -> list[Profile]:
    """Every profile in ``show callhome destination-profile``: its labelled values and the
    lists under ``email addresses configured:``, ``url addresses configured:`` and ``alert
    groups configured:``."""
    profiles: list[Profile] = []
    current: Profile | None = None
    listing: list[str] | None = None
    for raw in text_out.splitlines():
        line = raw.strip()
        if head := _PROFILE_HEAD.match(line):
            current = Profile(head.group(1))
            profiles.append(current)
            listing = None
            continue
        if current is None or not line:
            continue
        lowered = line.lower()
        if lowered.startswith("email addresses configured"):
            listing = current.emails
        elif lowered.startswith("url addresses configured"):
            listing = current.urls
        elif lowered.startswith("alert groups configured"):
            listing = current.groups
        elif (indexed := _INDEXED.match(line)) and listing is not None:
            listing.append(f"{indexed.group(1)}: {indexed.group(2)}")
        elif ":" in line:
            label, _, value = line.partition(":")
            current.values[label.strip().lower()] = value.strip()
            listing = None
        elif listing is not None:
            listing.append(line)
    return profiles


def config_lines(config: str) -> list[str]:
    """The lines inside ``callhome`` in ``show running-config callhome``, stripped."""
    lines: list[str] = []
    inside = False
    for raw in config.splitlines():
        if raw.strip() == "callhome" and not raw.startswith(" "):
            inside = True
            continue
        if inside and raw.startswith(" ") and raw.strip():
            lines.append(raw.strip())
        elif inside and raw.strip() and not raw.startswith(" "):
            inside = False
    return lines


def _after(lines: list[str], word: str) -> str:
    for line in lines:
        if line.startswith(word + " "):
            return line[len(word) + 1 :]
    return ""


def _switch_values(lines: list[str]) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    for key, word, name in (
        ("email", "email-contact", "email"),
        ("phone", "phone-contact", "phone"),
        ("street", "streetaddress", "value"),
        ("contract", "contract-id", "value"),
        ("customer", "customer-id", "value"),
        ("site", "site-id", "value"),
        ("priority", "switch-priority", "priority"),
    ):
        if found := _after(lines, word):
            values[key] = {name: found}
    if "enable" in lines:
        values["enable"] = {}
    return values


def _transport_values(lines: list[str]) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    for key, word in (("from", "transport email from"), ("reply_to", "transport email reply-to")):
        if found := _after(lines, word):
            values[key] = {"email": found}
    if found := _after(lines, "transport http use-vrf"):
        values["http_vrf"] = {"vrf": found}
    if found := _after(lines, "transport http proxy server"):
        server, _, rest = found.partition(" port ")
        values["proxy"] = {"server": server.strip(), "port": rest.strip()}
    if "transport http proxy enable" in lines:
        values["proxy_on"] = {}
    return values


def _profile_values(profile: Profile) -> dict[str, dict[str, str]]:
    values: dict[str, dict[str, str]] = {}
    fmt = profile.values.get("message format", "")
    if fmt in FORMATS:
        values["format"] = {"format": fmt}
    for key, label, name in (
        ("level", "message-level", "level"),
        ("size", "maximum message size", "size"),
    ):
        if profile.values.get(label, "").isdigit():
            values[key] = {name: profile.values[label]}
    return values


def parse_callhome(
    status: str, profiles_text: str, transport: str, config: str = ""
) -> ProtocolView:
    """The page from the four Call Home texts: Call Home's state and contact details, the
    transport, and a place per destination profile."""
    pairs = parse_label_lines(status)
    first = status.strip().splitlines()[0].strip() if status.strip() else ""
    state = "on" if first.lower() == "callhome enabled" else "off" if first else "-"
    lines = config_lines(config)
    shown = tuple(
        (label, value or "-") for label, value in pairs if label != "Callhome Information"
    )
    instances: list[Instance] = [
        Instance("callhome", {}, f"Call Home is {state}", shown, _switch_values(lines)),
        Instance(
            "transport",
            {},
            "Transport",
            tuple((label, value or "-") for label, value in parse_label_lines(transport)),
            _transport_values(lines),
        ),
    ]
    for profile in parse_profiles(profiles_text):
        built_in = BUILT_IN.get(profile.name)
        facts = (
            ("Format", profile.values.get("message format", "-")),
            ("Send by", profile.values.get("transport-method", "-")),
            ("Lowest level", profile.values.get("message-level", "-")),
            ("Largest message", profile.values.get("maximum message size", "-")),
            ("Email", ", ".join(profile.emails) or "none"),
            ("Web", ", ".join(profile.urls) or "none"),
            ("Alert groups", ", ".join(profile.groups) or "none"),
        )
        instances.append(
            Instance(
                "builtin_profile" if built_in else "profile",
                {"profile": built_in or profile.name},
                profile.name,
                facts,
                _profile_values(profile),
            )
        )
    servers = tuple(
        tuple(line.split()[3:4]) + (" ".join(line.split()[4:]) or "-",)
        for line in lines
        if line.startswith("transport email mail-server ")
    )
    tables = (
        Table(
            "Mail servers",
            ("Server", "Options"),
            servers,
            empty="No mail server is set.",
            note="Email needs at least one.",
        ),
    )
    return ProtocolView(tuple(instances), tables)


CALLHOME = Protocol(
    key="callhome",
    name="Call Home",
    summary="Contact details, where the switch sends its messages, and a test message",
    features=(),
    commands=(),
    parse=lambda bodies: ProtocolView(),
    scopes=(_CALLHOME, _TRANSPORT, _PROFILE, _BUILT_IN),
    about=(
        "Smart Call Home sends the switch's own messages (hardware faults, the inventory, "
        "syslog, the configuration) to email or web addresses, such as Cisco's support "
        "service or your own team."
    ),
)


@dataclass(frozen=True)
class CallhomePage:
    """Everything the Call Home page shows."""

    protocol: Protocol
    view: ProtocolView
    vrfs: tuple[str, ...]  # default, management, then the others
    problem: str = ""
    missing: tuple[str, ...] = ()  # always empty: Call Home needs no feature


def load_callhome_page(client: NxapiClient) -> CallhomePage:
    """One request for the VRFs; then the four Call Home texts."""
    (vrf_body,) = client.show(*PAGE_COMMANDS)
    vrfs = vrf_choices(vrf_body)
    try:
        status = client.show_text(STATUS_COMMAND)
        profiles = client.show_text(PROFILES_COMMAND)
        transport = client.show_text(TRANSPORT_COMMAND)
    except NxapiCommandError as exc:
        return CallhomePage(
            CALLHOME, ProtocolView(), vrfs, f"The switch did not report Call Home: {exc}"
        )
    try:
        config = client.show_text(CONFIG_COMMAND)
    except NxapiCommandError:
        config = ""  # the forms start empty; the rest is still worth showing
    return CallhomePage(CALLHOME, parse_callhome(status, profiles, transport, config), vrfs)


def build_callhome_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the Call Home page. A profile of your own may not take a
    built-in profile's name."""
    name = ident.get("profile", "").strip()
    if scope == "profile" and (name in BUILT_IN or name in BUILT_IN.values()):
        raise ValueError(f"{name} is one of the switch's own profiles: change it under Built-in")
    return build_change(CALLHOME, scope, setting, action, ident, values)
