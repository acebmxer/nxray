"""SSH and certificates: the switch's SSH host key (and making a new one), the RSA key
pairs, trustpoints and certificates the switch holds, importing a certificate with its
key from a PKCS#12 file on bootflash, and giving a trustpoint its CA certificate.

The page is described with the same parts as the Monitor sessions page
(``app/protocols.py``): scopes (the SSH key, a key pair, a trustpoint), each setting the
line it sends with checked values in its blanks, and ``build_change`` building the lines;
``build_pki_change`` adds what a few changes need around their line (SSH off and on again
around a new host key, leaving the trustpoint before an import). ``NxapiClient.
configure_pki`` sends them. Pasting a CA certificate is not a configuration line NX-API
can send (the switch asks for the certificate, then whether to accept it), so it goes
over SSH (``switch_ssh.authenticate_ca``) after ``check_ca_certificates`` has read it.

Read from the switch: ``show ssh key``, ``show crypto key mypubkey rsa``, ``show crypto
ca trustpoints`` and ``show crypto ca certificates`` in one request (the last three answer
with nothing when there is none), and ``dir bootflash:`` for the files an import may name.

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-12) with a throwaway key pair, two throwaway
trustpoints and a throwaway test CA, all removed afterwards: ``crypto key generate rsa
label <l> exportable modulus 2048``; ``crypto ca trustpoint <t>`` with ``enrollment
terminal``, ``rsakeypair <l>`` and ``revocation-check none``; ``crypto ca authenticate
<t>`` over SSH (a certificate dated after the switch's clock is refused: "certificate is
not yet valid"); ``crypto ca import <t> pkcs12 bootflash:<file> <password>`` over NX-API
(it makes a key pair named after the trustpoint, and leaves its log in
bootflash:cert.err); ``delete certificate force`` and ``delete ca-certificate`` inside the
trustpoint, ``no crypto ca trustpoint <t>`` (the switch says the key pairs go too, but they
stay) and ``crypto key zeroize rsa <l>`` (not ``label <l>``). Not tried, because it
replaces the key of a switch in production: a new SSH host key (``no feature ssh``, ``ssh
key <type> <bits> force``, ``feature ssh``, from Cisco's NX-OS 9.3 Security Configuration
Guide).
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from app.nxapi import FLASH_FILE, NxapiClient, NxapiCommandError
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

PAGE_COMMANDS = (
    "show ssh key",
    "show crypto key mypubkey rsa",
    "show crypto ca trustpoints",
    "show crypto ca certificates",
)
SSH_OFF = "no feature ssh"
SSH_ON = "feature ssh"
SSH_KEYS = ("rsa 2048", "rsa 3072", "rsa 4096", "ecdsa 256", "ecdsa 384", "ecdsa 521")
MODULI = ("2048", "3072", "4096")
REVOCATION = ("crl", "none", "crl none")
# File names an import is offered: PKCS#12 files.
PKCS12_ENDINGS = (".p12", ".pfx")
# The most certificates one paste takes (a CA and its intermediates).
CHAIN_MAX = 10

NEW_KEY_WARNING = (
    "The switch turns its SSH server off, makes the new key and turns SSH on again: every "
    "SSH session to it drops, and every SSH client that knew the old key warns that the "
    "key changed until its known-hosts entry is updated. NX-API, and so NXray's pages, "
    "carry on. The old key cannot be brought back."
)

_SSH = Scope(
    key="ssh",
    label="SSH host key",
    ident=(),
    enter=(),
    help="The key the switch proves itself with to SSH clients.",
    settings=(
        Setting(
            key="newkey",
            label="Make a new SSH host key",
            line="ssh key {key} force",
            removable=False,
            group="New key",
            fields=(
                Field(
                    "key",
                    "Type and size",
                    "choice",
                    choices=SSH_KEYS,
                    hint="RSA 2048 is what the switch starts with",
                ),
            ),
            warning=NEW_KEY_WARNING,
        ),
    ),
)

_KEYPAIR = Scope(
    key="keypair",
    label="Key pair",
    ident=(Field("label", "Label", "name", maximum=64, hint="Letters, digits, . _ -"),),
    enter=(),
    delete=("crypto key zeroize rsa {label}",),
    delete_warning=(
        "A trustpoint that uses this key pair loses its key: its own certificate no longer works."
    ),
    help="RSA key pairs a trustpoint's certificate is made for.",
    settings=(
        Setting(
            key="generate",
            label="Make the key pair",
            line="crypto key generate rsa label {label}[ {exportable}] modulus {bits}",
            ident=("label",),
            removable=False,
            group="Make",
            fields=(
                Field("bits", "Size (bits)", "choice", choices=MODULI),
                Field("exportable", "Can be exported", "flag", choices=("exportable",)),
            ),
            help="The switch refuses a label it already has.",
        ),
    ),
)

_TRUSTPOINT = Scope(
    key="trustpoint",
    label="Trustpoint",
    ident=(Field("name", "Name", "name", maximum=64, hint="Letters, digits, . _ -"),),
    enter=("crypto ca trustpoint {name}",),
    create=True,
    create_label="Make a trustpoint",
    delete=("no crypto ca trustpoint {name}",),
    delete_warning="Delete its certificates first (under Certificates).",
    help=(
        "A certificate authority the switch trusts, with the key pair and certificate the "
        "switch has from it."
    ),
    settings=(
        Setting(
            key="keypair",
            label="Key pair",
            line="rsakeypair {label}",
            no_line="no rsakeypair {label}",
            group="Settings",
            fields=(Field("label", "Key pair label", "name", maximum=64),),
        ),
        Setting(
            key="enrollment",
            label="Enrol by pasting",
            line="enrollment terminal",
            group="Settings",
            help="The certificate request and the certificate are pasted, not fetched.",
        ),
        Setting(
            key="revocation",
            label="Check for revoked certificates",
            line="revocation-check {how}",
            removable=False,
            group="Settings",
            fields=(
                Field(
                    "how",
                    "How",
                    "choice",
                    choices=REVOCATION,
                    hint="crl: the authority's revocation list; crl none: the list if it "
                    "can be had",
                ),
            ),
        ),
        Setting(
            key="import",
            label="Import a PKCS#12 file",
            line="crypto ca import {name} pkcs12 bootflash:{file} {password}",
            ident=("name",),
            removable=False,
            group="Certificates",
            fields=(
                Field(
                    "file", "File on bootflash", "flashfile", hint="Copy it there on the Files page"
                ),
                Field("password", "File password", "secret"),
            ),
            help=(
                "The certificate, its key and the authority's certificate from one file; "
                "the switch makes a key pair named after the trustpoint."
            ),
        ),
        Setting(
            key="delete_cert",
            label="Delete the switch's certificate",
            line="delete certificate force",
            removable=False,
            group="Certificates",
        ),
        Setting(
            key="delete_ca",
            label="Delete the CA certificate",
            line="delete ca-certificate",
            removable=False,
            group="Certificates",
            help="Delete the switch's certificate first.",
        ),
    ),
)


@dataclass(frozen=True)
class Certificate:
    """One certificate as ``show crypto ca certificates`` prints it."""

    trustpoint: str
    role: str  # "CA" or "Switch"
    subject: str
    issuer: str
    not_after: str
    fingerprint: str


def parse_certificate(trustpoint: str, role: str, block: str) -> Certificate:
    """A certificate from its printed lines (``subject= /CN=x``, ``notAfter=...``)."""
    pairs: dict[str, str] = {}
    for line in block.splitlines():
        name, sep, value = line.partition("=")
        if sep:
            pairs[name.strip()] = value.strip()
    return Certificate(
        trustpoint,
        role,
        pairs.get("subject", "-"),
        pairs.get("issuer", "-"),
        pairs.get("notAfter", "-"),
        pairs.get("SHA1 Fingerprint", "-"),
    )


def parse_certificates(body: Any) -> list[Certificate]:
    """Every trustpoint's certificates; ``body`` is ``show crypto ca certificates`` for
    every trustpoint (TABLE_ca_certificates) or for one (Trustpoint at the top)."""
    places = table_rows(body, "TABLE_ca_certificates", "ROW_ca_certificates")
    if not places and isinstance(body, dict) and isinstance(body.get("Trustpoint"), dict):
        places = [{"trustpoint": body["Trustpoint"].get("trustpoint"), **body}]
    found: list[Certificate] = []
    for place in places:
        name = text(place.get("trustpoint"))
        own = place.get("Certificate")
        if isinstance(own, dict) and own.get("certificate"):
            found.append(parse_certificate(name, "Switch", text(own["certificate"])))
        for row in table_rows(place, "TABLE_ca_cert_chains", "ROW_ca_cert_chains"):
            if row.get("ca_certificate"):
                found.append(parse_certificate(name, "CA", text(row["ca_certificate"])))
    return found


def parse_pki(bodies: list[Any]) -> ProtocolView:
    """The page from ``PAGE_COMMANDS``' bodies."""
    ssh_body, keys_body, trust_body, cert_body = bodies[:4]
    ssh_rows = table_rows(ssh_body, "TABLE_sessions", "ROW_sessions")
    instances: list[Instance] = []
    ssh_facts: list[tuple[str, str]] = []
    for row in ssh_rows:
        ssh_facts += [
            ("Type", f"{text(row.get('key_type')).upper()} {text(row.get('key_bitcount'))} bits"),
            ("Fingerprint", text(row.get("key_fingerprint")) or "-"),
            ("Made", text(row.get("key_time")).strip() or "-"),
        ]
    instances.append(Instance("ssh", {}, "SSH host key", tuple(ssh_facts)))
    certificates = parse_certificates(cert_body)
    for row in table_rows(keys_body, "TABLE_rsa_keys", "ROW_rsa_keys"):
        label = text(row.get("key_label"))
        if label:
            instances.append(
                Instance(
                    "keypair",
                    {"label": label},
                    label,
                    (
                        ("Size", f"{text(row.get('key_size'))} bits"),
                        ("Can be exported", text(row.get("exportable")) or "-"),
                    ),
                )
            )
    for row in table_rows(trust_body, "TABLE_ca_truspoints", "ROW_ca_truspoints"):
        name = text(row.get("trustpoint"))
        if not name:
            continue
        methods = [
            text(m.get("revocation-method"))
            for m in table_rows(row, "TABLE_revocation_methods", "ROW_revocation_methods")
        ]
        keypair = text(row.get("key-pair"))
        held = [c for c in certificates if c.trustpoint == name]
        values: dict[str, dict[str, str]] = {}
        if keypair:
            values["keypair"] = {"label": keypair}
        if " ".join(methods) in REVOCATION:
            values["revocation"] = {"how": " ".join(methods)}
        instances.append(
            Instance(
                "trustpoint",
                {"name": name},
                name,
                (
                    ("Key pair", keypair or "none"),
                    ("Revocation check", " ".join(methods) or "-"),
                    ("CA certificate", "yes" if any(c.role == "CA" for c in held) else "no"),
                    (
                        "Switch's certificate",
                        "yes" if any(c.role == "Switch" for c in held) else "no",
                    ),
                ),
                values,
            )
        )
    tables = (
        Table(
            "Certificates",
            ("Trustpoint", "Whose", "Subject", "Issued by", "Valid until", "SHA1 fingerprint"),
            tuple(
                (c.trustpoint, c.role, c.subject, c.issuer, c.not_after, c.fingerprint)
                for c in certificates
            ),
            empty="The switch holds no certificates.",
            wrap_column=2,
        ),
    )
    return ProtocolView(tuple(instances), tables)


PKI = Protocol(
    key="pki",
    name="SSH and certificates",
    summary="The switch's SSH host key, its key pairs, trustpoints and certificates",
    features=(),
    commands=(),
    parse=lambda bodies: ProtocolView(),
    scopes=(_SSH, _KEYPAIR, _TRUSTPOINT),
    about=(
        "SSH clients check the switch with its host key. Trustpoints hold the certificate "
        "authorities the switch trusts and the certificates it has from them."
    ),
)


@dataclass(frozen=True)
class PkiPage:
    """Everything the SSH and certificates page shows."""

    protocol: Protocol
    view: ProtocolView
    trustpoints: tuple[str, ...]
    keypairs: tuple[str, ...]
    files: tuple[str, ...]  # PKCS#12 files on bootflash
    problem: str = ""
    missing: tuple[str, ...] = ()  # always empty: no feature to turn on


def pkcs12_files(listing: dict[str, Any]) -> tuple[str, ...]:
    """The PKCS#12 files of a ``dir bootflash:`` body, by name."""
    return tuple(
        sorted(
            name
            for row in table_rows(listing, "TABLE_dir", "ROW_dir")
            if (name := text(row.get("fname"))).lower().endswith(PKCS12_ENDINGS)
            and FLASH_FILE.fullmatch(name)
        )
    )


def load_pki_page(client: NxapiClient) -> PkiPage:
    """One request for the key, key pairs, trustpoints and certificates; the file list."""
    bodies = client.show(*PAGE_COMMANDS)
    view = parse_pki(bodies)
    problem = ""
    try:
        files = pkcs12_files(client.list_files())
    except NxapiCommandError as exc:
        files = ()
        problem = f"The switch did not list its files: {exc}"
    return PkiPage(
        PKI,
        view,
        tuple(i.ident["name"] for i in view.of("trustpoint")),
        tuple(i.ident["label"] for i in view.of("keypair")),
        files,
        problem,
    )


def build_pki_change(
    scope: str, setting: str, action: str, ident: dict[str, str], values: dict[str, str]
) -> ProtocolChange:
    """``build_change`` for the page: SSH off and on again around a new host key; an
    import typed at the top, after leaving the trustpoint."""
    change = build_change(PKI, scope, setting, action, ident, values)
    if (scope, setting, action) == ("ssh", "newkey", "set"):
        return dataclasses.replace(
            change,
            lines=(SSH_OFF, *change.lines, SSH_ON),
            labels=(SSH_OFF, *change.labels, SSH_ON),
        )
    if (scope, setting, action) == ("trustpoint", "import", "set"):
        enter, line = change.lines[:-1], change.lines[-1]
        return dataclasses.replace(
            change,
            lines=(*enter, "exit", line),
            labels=(*change.labels[:-1], "exit", change.labels[-1]),
        )
    return change


# ---- a pasted CA certificate --------------------------------------------------------------

_PEM_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")


@dataclass(frozen=True)
class PastedCa:
    """CA certificates read from what was pasted, ready to type to the switch."""

    lines: tuple[str, ...]  # the PEM lines, written again by NXray
    fingerprints: frozenset[str]  # SHA1, as the switch prints them (AA:BB:...)
    subjects: tuple[str, ...]
    not_before: tuple[str, ...]


def check_ca_certificates(pasted: str) -> PastedCa:
    """Read the pasted PEM certificates (a CA and any intermediates); ValueError when
    there is none, one does not read, or one is not a CA. The switch is given the
    certificates as NXray writes them again, never the pasted text itself."""
    blocks = _PEM_BLOCK.findall(pasted)
    rest = _PEM_BLOCK.sub("", pasted).strip()
    if not blocks:
        raise ValueError(
            "paste the CA certificate in PEM form, from -----BEGIN CERTIFICATE----- to "
            "-----END CERTIFICATE-----"
        )
    if rest:
        raise ValueError("paste only certificates: there is other text around them")
    if len(blocks) > CHAIN_MAX:
        raise ValueError(f"at most {CHAIN_MAX} certificates at a time")
    lines: list[str] = []
    prints: set[str] = set()
    subjects: list[str] = []
    starts: list[str] = []
    for block in blocks:
        try:
            cert = x509.load_pem_x509_certificate(block.encode())
        except ValueError as exc:
            raise ValueError("a pasted certificate does not read as one") from exc
        try:
            constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            constraints = None
        if constraints is None or not constraints.ca:
            raise ValueError(
                f"{cert.subject.rfc4514_string()} is not a CA certificate: give the "
                "authority's certificate, not the switch's"
            )
        lines += cert.public_bytes(serialization.Encoding.PEM).decode().strip().splitlines()
        digest = cert.fingerprint(hashes.SHA1()).hex().upper()  # noqa: S303 - as the switch shows it
        prints.add(":".join(digest[i : i + 2] for i in range(0, len(digest), 2)))
        subjects.append(cert.subject.rfc4514_string())
        starts.append(cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M UTC"))
    return PastedCa(tuple(lines), frozenset(prints), tuple(subjects), tuple(starts))
