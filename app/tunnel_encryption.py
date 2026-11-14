"""VXLAN tunnel encryption (CloudSec): border gateways of a VXLAN EVPN multi-site fabric
encrypt the VXLAN traffic they send each other across the link between the sites.

Under ``feature tunnel-encryption``, in the order of Cisco's guide:

1. a **key chain** for it (``key chain <name> tunnel-encryption``) with keys (``key <hex
   id>``, then ``key-octet-string <hex> cryptographic-algorithm AES_128_CMAC|AES_256_CMAC``
   and ``send-lifetime``), the same on every peer;
2. the switch-wide lines: the loopback whose address is announced as the key's route
   (``tunnel-encryption source-interface loopback<n>``), dropping what is not encrypted
   (``tunnel-encryption must-secure-policy``) and the integrity check (``tunnel-encryption
   icv``);
3. a **policy** (``tunnel-encryption policy <name>``: ``cipher-suite GCM-AES-XPN-128|256``,
   ``window-size``, ``sak-rekey-time``);
4. per **peer** (another site's border gateway, by its NVE source address:
   ``tunnel-encryption peer-ip <a>``) the key chain and policy (``keychain <k> policy <p>``,
   or ``pki policy <p>`` with certificates);
5. ``tunnel-encryption`` on each link to the other sites (a routed port or port-channel).

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes, each setting the one line it sends with checked values in its
blanks, and ``build_change`` building the lines. ``NxapiClient.configure_tunnel_encryption``
sends them. A key's string is typed in hexadecimal, stored by the switch encrypted
(``key-octet-string 7 ...``) and never shown back, as the AAA page does with server keys.

Read from the switch: ``show feature``, ``show inventory``, ``show interface brief`` and ``show
vrf interface`` in one request; while the feature is on, ``show key chain``,
``show tunnel-encryption session``, ``show tunnel-encryption policy``, ``show
tunnel-encryption info global`` and ``show running-config`` as text.

Cisco's NX-OS 9.3 VXLAN guide gives tunnel encryption to the Nexus 9300-FX2 only, from
9.3(5), on border gateways of a multi-site fabric (``evpn multisite border-gateway`` with
``dci-advertise-pip``). cisco-25gb (N9K-C92160YC-X, NX-OS 9.3(16), 2026-11-13) refused
``feature tunnel-encryption`` ("ERROR: Tunnel-encryption cannot be enabled on this system"),
and without it ``show tunnel-encryption ...`` and the ``tunnel-encryption`` lines are not
commands there; the page says so on a switch other than a 9300-FX2. What was tried there,
without the feature, all removed afterwards: ``key chain <name> tunnel-encryption``, ``key
<id>`` (an even number of hexadecimal digits, up to 64), ``key-octet-string <hex>
cryptographic-algorithm AES_128_CMAC|AES_256_CMAC`` (32 hexadecimal digits for AES-128, 64
for AES-256; a key that has one refuses another until ``no key-octet-string``),
``send-lifetime [local] <time> <month> <day> <year> duration <1800-2147483646>|infinite|<end>``
and the ``no`` forms; ``show key chain`` prints such a chain as ``Key-Chain <name>
tunnel-encryption``. The policy, peer, switch-wide and interface lines and the show commands'
layouts follow the guide and were not tried on a switch.
"""

from __future__ import annotations

import re
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
    check_value,
    interface_field,
)
from app.protocols_policy import _lifetimes
from app.routing import parse_vrf_members
from app.routing_protocols import layer3_interfaces
from app.switch import chassis_model
from app.vxlan import parse_vxlan_config

FEATURE = "tun_enc_mgr"  # as show feature names it; the command is feature tunnel-encryption
PAGE_COMMANDS = ("show feature", "show inventory", "show interface brief", "show vrf interface")
KEY_CHAIN_COMMAND = "show key chain"
SESSION_COMMAND = "show tunnel-encryption session"
POLICY_COMMAND = "show tunnel-encryption policy"
INFO_COMMAND = "show tunnel-encryption info global"
CONFIG_COMMAND = "show running-config"
CIPHERS = ("GCM-AES-XPN-256", "GCM-AES-XPN-128")
ALGORITHMS = ("AES_256_CMAC", "AES_128_CMAC")
# Hexadecimal digits of a key's string for each algorithm, as cisco-25gb took them.
KEY_DIGITS = {"AES_128_CMAC": 32, "AES_256_CMAC": 64}
WINDOW_MIN = 134217728
WINDOW_MAX = 1073741823
REKEY_MIN = 1800
REKEY_MAX = 2592000
LIFETIME_MIN = 1800  # the shortest send-lifetime duration the switch takes, in seconds

NOT_THIS_MODEL = (
    "This switch does not do VXLAN tunnel encryption: it refuses feature tunnel-encryption "
    '("Tunnel-encryption cannot be enabled on this system"). Cisco\'s NX-OS 9.3 guide '
    "lists it for the Nexus 9300-FX2 only, on the border gateways of a multi-site fabric."
)


def _chain(label: str = "Key chain") -> Field:
    return Field("chain", label, "name", hint="A key chain made below", placeholder="kc1")


def _policy_name() -> Field:
    return Field("policy", "Policy", "name", hint="A policy made below", placeholder="p1")


# ---- the whole switch ------------------------------------------------------------------------


def _loopback_only(values: dict[str, str]) -> None:
    if not values["source"].startswith("loopback"):
        raise ValueError("the source interface is a loopback, such as loopback4")


_GLOBAL = Scope(
    key="global",
    label="Whole switch",
    ident=(),
    enter=(),
    help="Tunnel encryption for every peer.",
    settings=(
        Setting(
            "source_interface",
            "Source loopback",
            "tunnel-encryption source-interface {source}",
            (
                Field(
                    "source",
                    "Loopback",
                    "source",
                    hint="Its address is announced as the key's route; not the NVE "
                    "interface's source or the BGP peering loopback",
                    placeholder="loopback4",
                ),
            ),
            group="Switch",
            check=_loopback_only,
        ),
        Setting(
            "must_secure",
            "Encrypted traffic only",
            "tunnel-encryption must-secure-policy",
            group="Switch",
            help="Drop anything not encrypted, rather than send or take it in the clear.",
            warning="Peers not encrypting yet lose their traffic.",
        ),
        Setting(
            "icv",
            "Integrity check",
            "tunnel-encryption icv",
            group="Switch",
            help="Add an integrity check value to each packet. Off by default; give every "
            "peer the same.",
        ),
    ),
)

# ---- key chains and keys ---------------------------------------------------------------------

_KEY_CHAIN = Scope(
    key="key_chain",
    label="Key chain",
    ident=(_chain(),),
    enter=("key chain {chain} tunnel-encryption",),
    create=True,
    create_label="Make a key chain",
    delete=("no key chain {chain} tunnel-encryption",),
    delete_warning="Peers using this key chain stop encrypting.",
    help="Keys for tunnel encryption, the same on every peer.",
)


def _key_matches_algorithm(values: dict[str, str]) -> None:
    digits = KEY_DIGITS[values["algorithm"]]
    if not re.fullmatch(rf"[0-9a-fA-F]{{{digits}}}", values["octets"]):
        raise ValueError(f"an {values['algorithm']} key is {digits} hexadecimal digits")


_KEY = Scope(
    key="key",
    label="Key",
    ident=(
        _chain(),
        Field(
            "key",
            "Key ID",
            "hexkey",
            hint="An even number of hexadecimal digits, such as 2006",
            placeholder="2006",
        ),
    ),
    enter=("key chain {chain} tunnel-encryption", "key {key}"),
    create=True,
    create_label="Add a key",
    delete=("key chain {chain} tunnel-encryption", "no key {key}"),
    delete_warning="Peers still using this key stop encrypting.",
    help="Give each key a send lifetime, as Cisco advises; at most one key without one.",
    settings=(
        Setting(
            "octet_string",
            "Key",
            "key-octet-string {octets} cryptographic-algorithm {algorithm}",
            (
                Field(
                    "octets",
                    "Key",
                    "secret",
                    maximum=64,
                    hint="Hexadecimal: 32 digits for AES-128, 64 for AES-256; never shown back",
                ),
                Field("algorithm", "Algorithm", "choice", choices=ALGORITHMS),
            ),
            no_line="no key-octet-string",
            group="Key",
            help="The switch keeps a key once set: remove it, then set the new one.",
            check=_key_matches_algorithm,
        ),
        *_lifetimes("send", "Send", "used", duration_min=LIFETIME_MIN),
    ),
)

# ---- policies and peers ----------------------------------------------------------------------

_POLICY = Scope(
    key="policy",
    label="Policy",
    ident=(_policy_name(),),
    enter=("tunnel-encryption policy {policy}",),
    create=True,
    create_label="Make a policy",
    delete=("no tunnel-encryption policy {policy}",),
    delete_warning="Peers using this policy stop encrypting.",
    help="How the traffic is encrypted. An interface uses one policy.",
    settings=(
        Setting(
            "cipher_suite",
            "Cipher",
            "cipher-suite {cipher}",
            (Field("cipher", "Cipher", "choice", choices=CIPHERS),),
            group="Policy",
            help="GCM-AES-XPN-256 by default.",
        ),
        Setting(
            "window_size",
            "Replay window",
            "window-size {packets}",
            (
                Field(
                    "packets",
                    "Packets",
                    "int",
                    minimum=WINDOW_MIN,
                    maximum=WINDOW_MAX,
                    hint="Default 268435456",
                ),
            ),
            group="Policy",
            help="How far out of order a packet may arrive and still be taken.",
        ),
        Setting(
            "sak_rekey_time",
            "New key every",
            "sak-rekey-time {seconds}",
            (Field("seconds", "Seconds", "int", minimum=REKEY_MIN, maximum=REKEY_MAX),),
            group="Policy",
            help="Force a new session key this often; give every peer the same.",
        ),
    ),
)

_PEER = Scope(
    key="peer",
    label="Peer",
    ident=(
        Field(
            "peer",
            "Peer address",
            "ipv4",
            hint="The NVE source address of another site's border gateway",
            placeholder="192.0.2.11",
        ),
    ),
    enter=("tunnel-encryption peer-ip {peer}",),
    create=True,
    create_label="Add a peer",
    delete=("no tunnel-encryption peer-ip {peer}",),
    delete_warning="Traffic to this peer is no longer encrypted (or is dropped, with "
    "encrypted traffic only).",
    help="Another site's border gateway this switch encrypts to.",
    settings=(
        Setting(
            "keychain_policy",
            "Key chain and policy",
            "keychain {chain} policy {policy}",
            (_chain(), _policy_name()),
            group="Peer",
        ),
        Setting(
            "pki_policy",
            "Certificates and policy",
            "pki policy {policy}",
            (_policy_name(),),
            group="Peer",
            help="Instead of a key chain: the certificates of the SSH and certificates page.",
        ),
    ),
)

_INTERFACE = Scope(
    key="interface",
    label="Link to other sites",
    ident=(interface_field(),),
    enter=("interface {interface}",),
    help="Encrypt on the routed ports and port-channels toward the other sites; not on "
    "layer 2 ports.",
    settings=(
        Setting(
            "encrypt",
            "Encrypt here",
            "tunnel-encryption",
            group="Link",
            warning="Cisco: the link goes down and up again.",
        ),
    ),
)

SCOPES = (_GLOBAL, _KEY_CHAIN, _KEY, _POLICY, _PEER, _INTERFACE)


# ---- reading ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Key:
    """One key of a tunnel encryption key chain, as ``show key chain`` prints it (the key's
    string is never kept)."""

    chain: str
    key: str
    algorithm: str
    has_string: bool
    lifetime: str


def parse_key_chains(output: str | None) -> tuple[list[str], list[Key]]:
    """The tunnel encryption key chains and their keys in ``show key chain`` text; other
    key chains are the Routing policy page's."""
    chains: list[str] = []
    keys: list[Key] = []
    chain = ""
    current: dict[str, Any] | None = None

    def done() -> None:
        if current is not None:
            keys.append(Key(**current))

    for line in (output or "").splitlines():
        stripped = line.strip()
        if match := re.fullmatch(r"Key-Chain (\S+)(?: (\S+))?", stripped):
            done()
            current = None
            chain = match.group(1) if match.group(2) == "tunnel-encryption" else ""
            if chain:
                chains.append(chain)
        elif not chain:
            continue
        elif match := re.fullmatch(r"Key (\S+) -- text(?: \d+)? \"(.*)\"", stripped):
            done()
            current = {
                "chain": chain,
                "key": match.group(1).lower(),
                "algorithm": "",
                "has_string": bool(match.group(2)),
                "lifetime": "",
            }
        elif current is not None and stripped.startswith("cryptographic-algorithm "):
            current["algorithm"] = stripped.split()[-1]
        elif current is not None and stripped.startswith("send lifetime"):
            current["lifetime"] = stripped.removeprefix("send lifetime").strip()
    done()
    return chains, keys


def _rows_after_rule(output: str | None) -> list[str]:
    """The lines under the dashed rule of a table the switch prints."""
    lines = (output or "").splitlines()
    for number, line in enumerate(lines):
        if line.strip() and set(line.replace(" ", "")) == {"-"}:
            return [x for x in lines[number + 1 :] if x.strip()]
    return []


_ADDRESS = re.compile(r"\d+\.\d+\.\d+\.\d+")


def parse_sessions(output: str | None) -> list[tuple[str, ...]]:
    """``show tunnel-encryption session``: (peer, policy, key chain, receive, send). A row
    the switch wraps onto a second line (a certificate's long name) is joined first."""
    records: list[str] = []
    for line in _rows_after_rule(output):
        if _ADDRESS.match(line.strip()):
            records.append(line.strip())
        elif records:
            records[-1] += "  " + line.strip()
    rows = []
    for record in records:
        peer, _, rest = record.partition(" ")
        cells = re.split(r"\s{2,}", rest.strip())
        rows.append((peer, *(cells + [""] * 4)[:4]))
    return rows


def parse_policies(output: str | None) -> list[tuple[str, str, str, str]]:
    """``show tunnel-encryption policy``: (policy, cipher, window, rekey time)."""
    rows = []
    for line in _rows_after_rule(output):
        cells = re.split(r"\s{2,}", line.strip())
        name, cipher, window, rekey = (cells + [""] * 4)[:4]
        rows.append((name, cipher, window, rekey))
    return rows


def parse_info(output: str | None) -> dict[str, str]:
    """``show tunnel-encryption info global``: the policy mode and the active peers."""
    found = {}
    for line in (output or "").splitlines():
        name, colon, value = line.partition(":")
        if colon:
            found[" ".join(name.split())] = value.strip()
    return found


@dataclass(frozen=True)
class TunnelEncryptionConfig:
    """What ``show running-config`` says about tunnel encryption."""

    switch: dict[str, dict[str, str]]  # the switch-wide settings
    policies: dict[str, dict[str, dict[str, str]]]
    peers: dict[str, dict[str, dict[str, str]]]
    interfaces: tuple[str, ...]  # with tunnel-encryption on


def parse_tunnel_encryption_config(config: str) -> TunnelEncryptionConfig:
    """The tunnel encryption lines of ``show running-config``."""
    tree = parse_vxlan_config(config)
    switch: dict[str, dict[str, str]] = {}
    policies: dict[str, dict[str, dict[str, str]]] = {}
    peers: dict[str, dict[str, dict[str, str]]] = {}
    interfaces = []
    for line in tree.children():
        if match := re.fullmatch(r"tunnel-encryption source-interface (\S+)", line):
            switch["source_interface"] = {"source": match.group(1)}
        elif line == "tunnel-encryption must-secure-policy":
            switch["must_secure"] = {}
        elif line == "tunnel-encryption icv":
            switch["icv"] = {}
        elif match := re.fullmatch(r"tunnel-encryption policy (\S+)", line):
            values: dict[str, dict[str, str]] = {}
            for inner in tree.children(line):
                if found := re.fullmatch(r"cipher-suite (\S+)", inner):
                    values["cipher_suite"] = {"cipher": found.group(1)}
                elif found := re.fullmatch(r"window-size (\d+)", inner):
                    values["window_size"] = {"packets": found.group(1)}
                elif found := re.fullmatch(r"sak-rekey-time (\d+)", inner):
                    values["sak_rekey_time"] = {"seconds": found.group(1)}
            policies[match.group(1)] = values
        elif match := re.fullmatch(r"tunnel-encryption peer-ip (\S+)", line):
            values = {}
            for inner in tree.children(line):
                if found := re.fullmatch(r"keychain (\S+) policy (\S+)", inner):
                    values["keychain_policy"] = {"chain": found.group(1), "policy": found.group(2)}
                elif found := re.fullmatch(r"pki policy (\S+)", inner):
                    values["pki_policy"] = {"policy": found.group(1)}
            peers[match.group(1)] = values
        elif line.startswith("interface ") and "tunnel-encryption" in tree.children(line):
            interfaces.append(line.split(" ", 1)[1])
    return TunnelEncryptionConfig(switch, policies, peers, tuple(interfaces))


def parse_tunnel_encryption(
    config: str | None,
    keys_text: str | None = None,
    sessions: str | None = None,
    policies_text: str | None = None,
    info: str | None = None,
) -> ProtocolView:
    """The page from the configuration text (None: not shown) and the show commands' text
    (None: not shown)."""
    found = parse_tunnel_encryption_config(config or "")
    chains, keys = parse_key_chains(keys_text)
    facts_info = parse_info(info)
    source = found.switch.get("source_interface", {}).get("source", "not set")
    instances = [
        Instance(
            "global",
            {},
            "Whole switch",
            (
                ("Mode", facts_info.get("Global Policy Mode", "not reported")),
                ("Active peers", facts_info.get("No. of Active Peers", "not reported")),
                ("Source loopback", source),
                ("Encrypted traffic only", "yes" if "must_secure" in found.switch else "no"),
                ("Integrity check", "yes" if "icv" in found.switch else "no"),
            ),
            found.switch,
        )
    ]
    for chain in chains:
        count = sum(1 for k in keys if k.chain == chain)
        instances.append(Instance("key_chain", {"chain": chain}, chain, (("Keys", str(count)),)))
    for key in keys:
        instances.append(
            Instance(
                "key",
                {"chain": key.chain, "key": key.key},
                f"{key.chain} key {key.key}",
                (
                    ("Key", "set" if key.has_string else "not set"),
                    ("Algorithm", key.algorithm or "none"),
                    ("Send lifetime", key.lifetime or "none"),
                ),
                {"octet_string": {"algorithm": key.algorithm}} if key.has_string else {},
            )
        )
    for name, values in found.policies.items():
        facts = (
            ("Cipher", values.get("cipher_suite", {}).get("cipher", "GCM-AES-XPN-256 (default)")),
            ("Replay window", values.get("window_size", {}).get("packets", "268435456 (default)")),
            ("New key every", values.get("sak_rekey_time", {}).get("seconds", "not set")),
        )
        instances.append(Instance("policy", {"policy": name}, name, facts, values))
    for peer, values in found.peers.items():
        pair = values.get("keychain_policy")
        pki = values.get("pki_policy")
        uses = (
            f"key chain {pair['chain']}, policy {pair['policy']}"
            if pair
            else f"certificates, policy {pki['policy']}"
            if pki
            else "nothing yet"
        )
        instances.append(Instance("peer", {"peer": peer}, peer, (("Uses", uses),), values))
    for interface in found.interfaces:
        instances.append(
            Instance(
                "interface",
                {"interface": interface},
                interface,
                (("Encrypts", "yes"),),
                {"encrypt": {}},
            )
        )
    notes = []
    if config is None:
        notes.append(
            "The switch did not show its configuration to NXray's account: the switch-wide "
            "settings, policies, peers and links are not listed."
        )
    tables = (
        Table(
            "Sessions",
            ("Peer", "Policy", "Key chain", "Receiving", "Sending"),
            tuple(parse_sessions(sessions)),
            empty="No peer yet." if sessions is not None else "The switch did not report them.",
        ),
        Table(
            "Policies",
            ("Policy", "Cipher", "Replay window", "New key every"),
            tuple(parse_policies(policies_text)),
            empty="No policy." if policies_text is not None else "The switch did not report them.",
        ),
        Table(
            "Keys",
            ("Key chain", "Key", "Algorithm", "Key set", "Send lifetime"),
            tuple(
                (k.chain, k.key, k.algorithm, "yes" if k.has_string else "no", k.lifetime)
                for k in keys
            ),
            empty="No tunnel encryption key chain yet."
            if keys_text is not None
            else "The switch did not report its key chains.",
        ),
    )
    return ProtocolView(tuple(instances), tables, tuple(notes))


TUNNEL_ENCRYPTION = Protocol(
    key="tunnel-encryption",
    name="VXLAN tunnel encryption",
    summary="Encrypt the VXLAN traffic between the border gateways of a multi-site fabric",
    features=(FEATURE,),
    commands=(),
    parse=lambda bodies: parse_tunnel_encryption(None),
    scopes=SCOPES,
    about=(
        "Make a key chain with a key, a policy, then a peer per border gateway of the other "
        "sites with the key chain and policy, set the source loopback, and turn it on on the "
        "links to the other sites. Every border gateway of a site needs it, with the same keys."
    ),
)


@dataclass(frozen=True)
class TunnelEncryptionPage:
    """Everything the VXLAN tunnel encryption page shows."""

    protocol: Protocol
    view: ProtocolView
    interfaces: tuple[str, ...]  # the routed ports and port-channels
    problem: str = ""
    missing: tuple[str, ...] = ()  # the tunnel-encryption feature, when it is off


def model_note(inventory: Any) -> str:
    """The plain refusal for a switch Cisco's guide does not list (anything but a Nexus
    9300-FX2, as ``show inventory`` names it); "" for a 9300-FX2 or an unknown model."""
    chassis = chassis_model(inventory)
    if not chassis or re.search(r"\bC93\w*-FX2\b", chassis):
        return ""
    return NOT_THIS_MODEL


def _text_or_none(client: NxapiClient, command: str) -> str | None:
    try:
        return client.show_text(command)
    except NxapiCommandError:
        return None


def load_tunnel_encryption_page(client: NxapiClient) -> TunnelEncryptionPage:
    """One request for the features, model and interfaces; while the feature is on,
    the key chains, sessions, policies, global state and configuration as text."""
    feature, inventory, brief, vrf_members = client.show(*PAGE_COMMANDS)
    interfaces = tuple(
        name
        for name in layer3_interfaces(brief or {}, parse_vrf_members(vrf_members))
        if not name.startswith("Vlan")
    )
    problem = model_note(inventory)
    if not feature_states(feature).get(FEATURE, False):
        return TunnelEncryptionPage(
            TUNNEL_ENCRYPTION, ProtocolView(), interfaces, problem, (FEATURE,)
        )
    view = parse_tunnel_encryption(
        _text_or_none(client, CONFIG_COMMAND),
        _text_or_none(client, KEY_CHAIN_COMMAND),
        _text_or_none(client, SESSION_COMMAND),
        _text_or_none(client, POLICY_COMMAND),
        _text_or_none(client, INFO_COMMAND),
    )
    return TunnelEncryptionPage(TUNNEL_ENCRYPTION, view, interfaces, problem)


def check_tunnel_encryption_place(page: TunnelEncryptionPage, ident: dict[str, str]) -> None:
    """Refuse an interface the switch does not have as a routed port or port-channel
    (unless it already encrypts, so it can still be turned off), and a VLAN interface."""
    raw = ident.get("interface", "").strip()
    if not raw:
        return
    try:
        interface = check_value(interface_field(), raw)
    except ValueError:
        return  # build_change names the field
    if interface.startswith("Vlan"):
        raise ValueError("tunnel encryption goes on a routed port or port-channel, not a VLAN")
    listed = {i.ident.get("interface") for i in page.view.of("interface")}
    if interface not in page.interfaces and interface not in listed:
        raise ValueError(f"{interface} is not a routed port or port-channel on the switch")


def build_tunnel_encryption_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the VXLAN tunnel encryption page."""
    return build_change(TUNNEL_ENCRYPTION, scope, setting, action, ident, values)
