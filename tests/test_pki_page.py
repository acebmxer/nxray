"""The SSH and certificates page (#88), end to end against the fake switch, and its lines."""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.config import Settings
from app.pki import (
    SSH_OFF,
    SSH_ON,
    build_pki_change,
    check_ca_certificates,
    parse_certificates,
    pkcs12_files,
)
from tests.conftest import load_fixture
from tests.fake_switch import FakeSwitch
from tests.stage_d_helpers import config_requests, csrf, enable, set_up, text


def _cert(ca: bool) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab-ca" if ca else "lab-id")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def test_the_lines() -> None:
    key = build_pki_change("ssh", "newkey", "set", {}, {"key": "rsa 4096"})
    assert key.lines == (SSH_OFF, "ssh key rsa 4096 force", SSH_ON) and key.warning
    with pytest.raises(ValueError):
        build_pki_change("ssh", "newkey", "set", {}, {"key": "dsa 1024"})
    pair = build_pki_change("keypair", "generate", "set", {"label": "kp"}, {"bits": "2048"})
    assert pair.lines == ("crypto key generate rsa label kp modulus 2048",)
    assert build_pki_change("keypair", "", "delete", {"label": "kp"}, {}).lines == (
        "crypto key zeroize rsa kp",
    )
    imported = build_pki_change(
        "trustpoint", "import", "set", {"name": "tp"}, {"file": "id.p12", "password": "pw1"}
    )
    assert imported.lines == (
        "crypto ca trustpoint tp",
        "exit",
        "crypto ca import tp pkcs12 bootflash:id.p12 pw1",
    )
    assert "pw1" not in " ".join(imported.labels)
    with pytest.raises(ValueError):
        build_pki_change(
            "trustpoint", "import", "set", {"name": "tp"}, {"file": "../x.p12", "password": "p"}
        )


def test_certificates_are_read() -> None:
    (own, ca) = parse_certificates(load_fixture("show_crypto_ca_certificates_one"))
    assert (own.trustpoint, own.role, own.subject) == ("lab-tp", "Switch", "/CN=lab-id")
    assert ca.role == "CA" and ca.fingerprint.startswith("C4:5F:C8")
    listing = {"TABLE_dir": {"ROW_dir": [{"fname": "a.p12"}, {"fname": "b.cfg"}, {"fname": "x/"}]}}
    assert pkcs12_files(listing) == ("a.p12",)


def test_pasted_certificates_are_checked() -> None:
    ca = check_ca_certificates("\n" + _cert(True) + "\n")
    assert ca.lines[0] == "-----BEGIN CERTIFICATE-----" and len(ca.fingerprints) == 1
    assert ca.subjects == ("CN=lab-ca",)
    with pytest.raises(ValueError, match="not a CA"):
        check_ca_certificates(_cert(False))
    with pytest.raises(ValueError, match="other text"):
        check_ca_certificates(_cert(True) + "\nconfigure terminal")
    with pytest.raises(ValueError):
        check_ca_certificates("hello")


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    return set_up(logged_in)


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/pki/change", data=data)


def test_page_reads_the_switch(logged_in: TestClient, switch: FakeSwitch) -> None:
    page = logged_in.get("/pki")
    assert page.status_code == 200, text(page.text)
    assert "RSA 2048 bits" in text(page.text) and "SHA256:fake-rsa-2048" in page.text
    assert "/pki/change" not in page.text


def test_a_new_ssh_key_turns_ssh_off_and_on(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    fields = {"scope": "ssh", "setting": "newkey", "action": "set", "v_key": "ecdsa 384"}
    asked = _change(logged_in, confirm=False, **fields)
    assert "every SSH session to it drops" in text(asked.text)
    done = _change(logged_in, **fields)
    assert done.status_code == 200, text(done.text)
    assert config_requests(switch) == [[SSH_OFF, "ssh key ecdsa 384 force", SSH_ON]]
    assert switch.ssh_key == "ecdsa 384" and switch.ssh_server_on


def test_a_refused_ssh_key_leaves_ssh_on(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "broad")
    switch.reject.add("ssh key")
    refused = _change(logged_in, scope="ssh", setting="newkey", action="set", v_key="rsa 3072")
    assert refused.status_code == 400
    assert config_requests(switch)[-1] == [SSH_ON] and switch.ssh_server_on


def test_a_trustpoint_is_made_and_given_a_pasted_ca(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "stored")
    made = _change(logged_in, scope="trustpoint", action="create", id_name="lab-tp")
    assert made.status_code == 200, text(made.text)
    pem = _cert(True)
    asked = logged_in.post(
        "/pki/authenticate", data={"csrf": csrf(logged_in), "trustpoint": "lab-tp", "pem": pem}
    )
    assert "SHA1 fingerprints" in text(asked.text) and "CN=lab-ca" in text(asked.text)
    done = logged_in.post(
        "/pki/authenticate",
        data={"csrf": csrf(logged_in), "trustpoint": "lab-tp", "pem": pem, "confirm": "yes"},
    )
    assert done.status_code == 200, text(done.text)
    assert switch.trustpoints["lab-tp"]["ca"]
    assert "crypto ca authenticate lab-tp" in switch.ssh_lines and "yes" in switch.ssh_lines


def test_a_different_fingerprint_is_answered_no(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "stored")
    _change(logged_in, scope="trustpoint", action="create", id_name="lab-tp")
    switch.ca_fingerprint = "00" * 20
    refused = logged_in.post(
        "/pki/authenticate",
        data={
            "csrf": csrf(logged_in),
            "trustpoint": "lab-tp",
            "pem": _cert(True),
            "confirm": "yes",
        },
    )
    assert refused.status_code == 400 and "answered no" in text(refused.text)
    assert not switch.trustpoints["lab-tp"]["ca"] and "no" in switch.ssh_lines


def test_a_pkcs12_file_is_imported(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    enable(logged_in, settings, switch, "stored")
    switch.flash["lab.p12"] = b"pkcs12"
    _change(logged_in, scope="trustpoint", action="create", id_name="lab-tp")
    done = _change(
        logged_in,
        scope="trustpoint",
        setting="import",
        action="set",
        id_name="lab-tp",
        v_file="lab.p12",
        v_password="pw1",
    )
    assert done.status_code == 200, text(done.text)
    shown = text(logged_in.get("/pki").text)
    assert "/CN=nexus-lab" in shown and "lab-tp" in shown
