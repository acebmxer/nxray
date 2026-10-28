"""Built-in HTTPS: the certificate, nginx's config and the Settings page."""

from __future__ import annotations

import datetime as dt
import re
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app import healthcheck, tls
from app.config import Settings
from app.db import open_db
from app.users import create_user
from tests.conftest import with_settings

REPO = Path(__file__).resolve().parent.parent
TEMPLATE = REPO / "docker" / "nginx.conf.template"
PASSWORD = "another-long-password"


def _key(kind: str = "ec") -> ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey:
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return ec.generate_private_key(ec.SECP256R1())


def _cert(
    key,
    *,
    name: str = "nxray.lab",
    issuer_key=None,
    issuer_name: str | None = None,
    days_from: int = -1,
    days_to: int = 365,
) -> x509.Certificate:
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name or name)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + dt.timedelta(days=days_from))
        .not_valid_after(now + dt.timedelta(days=days_to))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(issuer_key or key, hashes.SHA256())
    )


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key, password: bytes | None = None) -> bytes:
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )


# ---- the self-signed certificate ------------------------------------------------


def test_first_start_makes_a_self_signed_certificate(tmp_path: Path) -> None:
    assert tls.ensure_certificate(tmp_path) is True
    key_mode = stat.S_IMODE((tmp_path / "key.pem").stat().st_mode)
    assert key_mode == 0o600
    info = tls.current_certificate(tmp_path)
    assert info is not None and info.self_signed
    assert "nxray" in info.names and "localhost" in info.names
    assert info.not_after >= f"{dt.date.today().year + 9}"
    # The pair is one the upload check would accept too.
    tls.validate_certificate_pair(
        (tmp_path / "cert.pem").read_bytes(), (tmp_path / "key.pem").read_bytes()
    )


def test_an_existing_certificate_is_kept(tmp_path: Path) -> None:
    tls.ensure_certificate(tmp_path)
    before = (tmp_path / "cert.pem").read_bytes()
    assert tls.ensure_certificate(tmp_path) is False
    assert (tmp_path / "cert.pem").read_bytes() == before


# ---- checking an upload ------------------------------------------------------------


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_a_matching_pair_is_accepted(kind: str) -> None:
    key = _key(kind)
    info = tls.validate_certificate_pair(_pem(_cert(key)), _key_pem(key))
    assert info.subject == "CN=nxray.lab" and info.self_signed
    assert info.names == ("nxray.lab",)


def test_a_chain_is_accepted_with_the_server_certificate_first() -> None:
    ca_key, key = _key(), _key()
    ca = _cert(ca_key, name="Lab CA")
    server = _cert(key, issuer_key=ca_key, issuer_name="Lab CA")
    info = tls.validate_certificate_pair(_pem(server) + _pem(ca), _key_pem(key))
    assert not info.self_signed
    with pytest.raises(tls.CertificateError, match="server's own certificate must come first"):
        tls.validate_certificate_pair(_pem(ca) + _pem(server), _key_pem(key))


@pytest.mark.parametrize(
    ("make", "message"),
    [
        (lambda k: (_pem(_cert(_key())), _key_pem(k)), "don't belong together"),
        (lambda k: (_pem(_cert(k, days_from=-30, days_to=-1)), _key_pem(k)), "expired on"),
        (lambda k: (_pem(_cert(k, days_from=5)), _key_pem(k)), "not valid until"),
        (lambda k: (b"hello", _key_pem(k)), "not a PEM certificate"),
        (lambda k: (_pem(_cert(k)), b"hello"), "not a PEM private key"),
        (lambda k: (_pem(_cert(k)), _key_pem(k, b"secret")), "passphrase"),
        (lambda k: (b"", _key_pem(k)), "Choose both"),
        (lambda k: (_pem(_cert(k)) + b"x" * tls.MAX_PEM_BYTES, _key_pem(k)), "too large"),
    ],
)
def test_unusable_uploads_are_refused(make: Callable, message: str) -> None:
    key = _key()
    cert_pem, key_pem = make(key)
    with pytest.raises(tls.CertificateError, match=message):
        tls.validate_certificate_pair(cert_pem, key_pem)


def test_installing_replaces_both_files_and_tells_nginx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tls.ensure_certificate(tmp_path)
    told: list[bool] = []
    monkeypatch.setattr(tls, "reload_nginx", lambda: told.append(True) or True)
    key = _key()
    cert_pem, key_pem = _pem(_cert(key)), _key_pem(key)
    tls.install_certificate(tmp_path, cert_pem, key_pem)
    assert (tmp_path / "cert.pem").read_bytes() == cert_pem
    assert (tmp_path / "key.pem").read_bytes() == key_pem
    assert stat.S_IMODE((tmp_path / "key.pem").stat().st_mode) == 0o600
    assert told == [True]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["cert.pem", "key.pem"]


def test_a_refused_upload_leaves_the_old_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tls.ensure_certificate(tmp_path)
    before = (tmp_path / "cert.pem").read_bytes()
    monkeypatch.setattr(tls, "reload_nginx", lambda: pytest.fail("nginx told"))
    with pytest.raises(tls.CertificateError):
        tls.install_certificate(tmp_path, _pem(_cert(_key())), _key_pem(_key()))
    assert (tmp_path / "cert.pem").read_bytes() == before


def test_reload_sends_sighup_to_the_pid_in_the_file(tmp_path: Path) -> None:
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        pid_file = tmp_path / "nginx.pid"
        pid_file.write_text(f"{child.pid}\n")
        assert tls.reload_nginx(pid_file) is True
        assert child.wait(timeout=10) == -1  # SIGHUP's default action ends it
    finally:
        child.kill()
    assert tls.reload_nginx(tmp_path / "missing.pid") is False


# ---- nginx's config and the entrypoint helper -----------------------------------------


def test_the_nginx_config_gets_the_port_and_the_tls_folder(tmp_path: Path) -> None:
    target = tmp_path / "nginx.conf"
    tls.write_nginx_config(9443, Path("/data/tls"), TEMPLATE, target)
    text = target.read_text()
    assert "@" not in re.sub(r"#.*", "", text), "a placeholder was left in"
    assert "return 301 https://$host:9443$request_uri;" in text
    assert "ssl_certificate /data/tls/cert.pem;" in text
    assert "ssl_certificate_key /data/tls/key.pem;" in text
    # The visitor's address replaces whatever a browser sent; it is never appended.
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in text
    assert "proxy_add_x_forwarded_for" not in text


def _run_main(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], settings: Settings
) -> str:
    monkeypatch.setattr("app.config.load_settings", lambda: settings)
    monkeypatch.setattr(tls, "NGINX_DIR", settings.data_dir / "nginx")
    monkeypatch.setattr(tls, "NGINX_CONFIG", settings.data_dir / "nginx" / "nginx.conf")
    monkeypatch.setattr(tls, "NGINX_TEMPLATE", TEMPLATE)
    assert tls.main() == 0
    return capsys.readouterr().out.strip()


def test_the_entrypoint_helper_says_http_when_off(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], settings: Settings
) -> None:
    assert _run_main(monkeypatch, capsys, settings) == "http"
    assert not settings.tls_dir.exists(), "nothing is made while HTTPS is off"


def test_the_entrypoint_helper_prepares_https(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], settings: Settings
) -> None:
    on = with_settings(settings, enable_https=True, https_port=8453)
    assert _run_main(monkeypatch, capsys, on) == "https"
    assert (on.tls_dir / "cert.pem").is_file() and (on.tls_dir / "key.pem").is_file()
    config = (on.data_dir / "nginx" / "nginx.conf").read_text()
    assert "https://$host:8453" in config and f"{on.tls_dir}/cert.pem" in config


@pytest.mark.parametrize(("value", "on"), [("true", True), ("ON", True), ("", False), ("0", False)])
def test_the_health_check_follows_the_https_setting(
    monkeypatch: pytest.MonkeyPatch, value: str, on: bool
) -> None:
    monkeypatch.setenv("NXRAY_ENABLE_HTTPS", value)
    assert healthcheck.https_enabled() is on


# ---- the Settings page ------------------------------------------------------------------


def _csrf(client: TestClient) -> str:
    # From the Account page: the Settings page has no form while HTTPS is off.
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get("/account").text)
    assert match
    return match.group(1)


@pytest.fixture
def https_admin(
    settings: Settings,
    make_client: Callable[[Settings], TestClient],
    monkeypatch: pytest.MonkeyPatch,
) -> TestClient:
    on = with_settings(settings, enable_https=True)
    tls.ensure_certificate(on.tls_dir)
    monkeypatch.setattr(tls, "reload_nginx", lambda: True)
    client = make_client(on)
    client.post("/login", data={"username": "admin", "password": "correct-horse-battery"})
    return client


def _upload(client: TestClient, cert_pem: bytes, key_pem: bytes, csrf: str | None = None):
    return client.post(
        "/settings/certificate",
        data={"csrf": csrf if csrf is not None else _csrf(client)},
        files={
            "cert_file": ("cert.pem", cert_pem, "application/x-pem-file"),
            "key_file": ("key.pem", key_pem, "application/x-pem-file"),
        },
    )


def test_settings_says_how_to_turn_https_on_when_off(logged_in: TestClient) -> None:
    text = logged_in.get("/settings").text
    assert "NXRAY_ENABLE_HTTPS=true" in text and 'action="/settings/certificate"' not in text
    assert 'href="/settings"' in text, "admins have Settings in the menu"


def test_settings_shows_the_self_signed_certificate(https_admin: TestClient) -> None:
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", https_admin.get("/settings").text))
    assert "Certificate CN=nxray" in text and "Self-signed" in text
    assert "Upload certificate" in text


def test_uploading_a_certificate_puts_it_in_use(
    https_admin: TestClient, settings: Settings
) -> None:
    ca_key, key = _key(), _key("rsa")
    ca = _cert(ca_key, name="Lab CA")
    cert_pem = _pem(_cert(key, issuer_key=ca_key, issuer_name="Lab CA")) + _pem(ca)
    key_pem = _key_pem(key)
    response = _upload(https_admin, cert_pem, key_pem)
    assert response.status_code == 200 and "Certificate saved and in use" in response.text
    assert (settings.data_dir / "tls" / "cert.pem").read_bytes() == cert_pem
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", https_admin.get("/settings").text))
    assert "Certificate CN=nxray.lab" in text and "Kind Uploaded" in text
    assert "Self-signed" not in text


def test_a_mismatched_upload_is_refused_and_changes_nothing(
    https_admin: TestClient, settings: Settings
) -> None:
    before = (settings.data_dir / "tls" / "cert.pem").read_bytes()
    response = _upload(https_admin, _pem(_cert(_key())), _key_pem(_key()))
    assert response.status_code == 400 and "don&#39;t belong together" in response.text
    assert (settings.data_dir / "tls" / "cert.pem").read_bytes() == before


def test_uploading_needs_the_csrf_token(https_admin: TestClient) -> None:
    key = _key()
    assert _upload(https_admin, _pem(_cert(key)), _key_pem(key), csrf="nope").status_code == 403


def test_uploading_is_refused_while_https_is_off(logged_in: TestClient) -> None:
    key = _key()
    response = _upload(logged_in, _pem(_cert(key)), _key_pem(key))
    assert response.status_code == 400 and "Built-in HTTPS is off" in response.text


@pytest.mark.parametrize("role", ["viewer", "operator"])
def test_settings_is_for_admins_only(logged_in: TestClient, settings: Settings, role: str) -> None:
    with open_db(settings.db_path) as conn:
        create_user(conn, "someone", PASSWORD, PASSWORD, role)
    other = TestClient(logged_in.app, follow_redirects=False)
    other.post("/login", data={"username": "someone", "password": PASSWORD})
    assert other.get("/settings").status_code == 403
    assert 'href="/settings"' not in other.get("/").text
    token = re.search(r'name="csrf" value="([0-9a-f]+)"', other.get("/account").text)
    assert token
    assert other.post("/settings/certificate", data={"csrf": token.group(1)}).status_code == 403


def test_a_half_pair_is_made_again_whole(tmp_path: Path) -> None:
    # A key file left without its certificate (a crash between the two
    # renames) gets a fresh pair, not a half one.
    tls.ensure_certificate(tmp_path)
    (tmp_path / "cert.pem").unlink()
    assert tls.ensure_certificate(tmp_path) is True
    tls.validate_certificate_pair(
        (tmp_path / "cert.pem").read_bytes(), (tmp_path / "key.pem").read_bytes()
    )
