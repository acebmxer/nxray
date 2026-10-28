"""Built-in HTTPS: the certificate nginx serves, and nginx's settings.

Off unless ``NXRAY_ENABLE_HTTPS=true``. Then the container's entrypoint
(docker/entrypoint.sh) runs ``python -m app.tls`` before anything else, which

- makes a self-signed certificate in ``<data>/tls/`` on the first start, so
  HTTPS works at once (browsers warn about it until a real one is uploaded),
- writes nginx's config with the port plain-HTTP visits are redirected to,
- prints ``https`` or ``http`` so the entrypoint knows what to start.

An admin can replace the certificate on the Settings page
(app/routes/settings_page.py); ``install_certificate`` checks it, writes it,
and tells nginx to load it, with no restart.

The certificate is made here with ``cryptography`` (already a dependency)
rather than the openssl command, so the image needs no extra package for it.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import os
import signal
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

log = logging.getLogger("nxray.tls")

CERT_NAME = "cert.pem"
KEY_NAME = "key.pem"

# nginx's own files live under /tmp/nginx (the container user can't write the
# Debian defaults under /var). The pid file is how a new certificate is
# announced to it.
NGINX_DIR = Path("/tmp/nginx")
NGINX_PID_FILE = NGINX_DIR / "run" / "nginx.pid"
NGINX_TEMPLATE = Path("/etc/nxray/nginx.conf.template")
NGINX_CONFIG = NGINX_DIR / "nginx.conf"

# Ten years: a self-signed certificate on a management network is not trusted
# because of its dates, and one that runs out would only teach people to
# click through the browser warning again.
SELF_SIGNED_DAYS = 3650
SELF_SIGNED_NAME = "nxray"

# A certificate with its chain and a key are a few KB.
MAX_PEM_BYTES = 256 * 1024


class CertificateError(ValueError):
    """An uploaded certificate or key can't be used. The message is shown on the page."""


@dataclass(frozen=True)
class CertificateInfo:
    subject: str
    names: tuple[str, ...]
    not_after: str
    self_signed: bool


def _info(cert: x509.Certificate) -> CertificateInfo:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = tuple(str(n.value) for n in san)
    except x509.ExtensionNotFound:
        names = ()
    return CertificateInfo(
        subject=cert.subject.rfc4514_string(),
        names=names,
        not_after=cert.not_valid_after_utc.strftime("%Y-%m-%d"),
        self_signed=cert.issuer == cert.subject,
    )


def ensure_certificate(tls_dir: Path) -> bool:
    """Make a self-signed certificate and key unless both exist. True if it made them.

    EC P-256 key, names ``nxray`` and ``localhost``, valid for ten years. The
    key file is created readable by the container user only.
    """
    cert_path, key_path = tls_dir / CERT_NAME, tls_dir / KEY_NAME
    if cert_path.is_file() and key_path.is_file():
        return False
    tls_dir.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SELF_SIGNED_NAME)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=SELF_SIGNED_DAYS))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(SELF_SIGNED_NAME),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    _write_pair(tls_dir, cert.public_bytes(serialization.Encoding.PEM), key_pem)
    return True


def validate_certificate_pair(cert_pem: bytes, key_pem: bytes) -> CertificateInfo:
    """Check an uploaded certificate and key; raise CertificateError with the first problem.

    The certificate file may also hold the chain (intermediate certificates
    after the server's own); nginx sends the whole file. The key must not be
    protected by a passphrase: nginx could not ask for it at every start.
    """
    if not cert_pem.strip() or not key_pem.strip():
        raise CertificateError("Choose both a certificate file and a private key file.")
    if len(cert_pem) > MAX_PEM_BYTES or len(key_pem) > MAX_PEM_BYTES:
        raise CertificateError("That file is too large to be a certificate or a private key.")
    try:
        certs = x509.load_pem_x509_certificates(cert_pem)
    except ValueError as exc:
        raise CertificateError(
            "The certificate file is not a PEM certificate (it should start with "
            "-----BEGIN CERTIFICATE-----)."
        ) from exc
    cert = certs[0]
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except TypeError as exc:
        raise CertificateError(
            "The private key is protected by a passphrase. Upload it without one "
            "(openssl pkey -in key.pem -out key-plain.pem)."
        ) from exc
    except ValueError as exc:
        raise CertificateError(
            "The key file is not a PEM private key (it should start with "
            "-----BEGIN PRIVATE KEY----- or -----BEGIN RSA/EC PRIVATE KEY-----)."
        ) from exc
    if not isinstance(key, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
        raise CertificateError("Only RSA and EC private keys are supported.")
    if key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) != cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ):
        raise CertificateError(
            "The certificate and the private key don't belong together. If the "
            "certificate file holds a chain, the server's own certificate must come first."
        )
    now = dt.datetime.now(dt.UTC)
    if cert.not_valid_after_utc < now:
        raise CertificateError(f"That certificate expired on {cert.not_valid_after_utc:%Y-%m-%d}.")
    if cert.not_valid_before_utc > now:
        raise CertificateError(
            f"That certificate is not valid until {cert.not_valid_before_utc:%Y-%m-%d}."
        )
    return _info(cert)


def current_certificate(tls_dir: Path) -> CertificateInfo | None:
    """The certificate nginx serves, read from disk; None if there is none (yet)."""
    try:
        return _info(x509.load_pem_x509_certificates((tls_dir / CERT_NAME).read_bytes())[0])
    except (OSError, ValueError):
        return None


def _write_pair(tls_dir: Path, cert_pem: bytes, key_pem: bytes) -> None:
    """Write both files beside the old ones, then rename them into place.

    nginx never sees half a file, and the key is created mode 600 rather
    than written first and restricted after.
    """
    tls_dir.mkdir(parents=True, exist_ok=True)
    key_tmp, cert_tmp = tls_dir / f"{KEY_NAME}.new", tls_dir / f"{CERT_NAME}.new"
    for path in (key_tmp, cert_tmp):
        path.unlink(missing_ok=True)
    fd = os.open(key_tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key_pem)
    cert_tmp.write_bytes(cert_pem)
    os.replace(key_tmp, tls_dir / KEY_NAME)
    os.replace(cert_tmp, tls_dir / CERT_NAME)


def install_certificate(tls_dir: Path, cert_pem: bytes, key_pem: bytes) -> CertificateInfo:
    """Check an uploaded pair, store it, and have nginx load it. Raises CertificateError."""
    info = validate_certificate_pair(cert_pem, key_pem)
    _write_pair(tls_dir, cert_pem, key_pem)
    reload_nginx()
    return info


def reload_nginx(pid_file: Path = NGINX_PID_FILE) -> bool:
    """Tell nginx to reload (SIGHUP), which re-reads the certificate. True if signalled.

    nginx opens the new files before it lets go of the old ones, so pages in
    flight are not cut off.
    """
    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
        os.kill(pid, signal.SIGHUP)
    except (OSError, ValueError) as exc:
        log.warning("could not tell nginx to load the new certificate: %s", exc)
        return False
    log.info("nginx told to load the new certificate")
    return True


def write_nginx_config(https_port: int, tls_dir: Path, template: Path, target: Path) -> None:
    """nginx's config from the image's template, with the redirect port and TLS paths."""
    text = template.read_text(encoding="utf-8")
    text = text.replace("@HTTPS_PORT@", str(https_port)).replace("@TLS_DIR@", str(tls_dir))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def main() -> int:
    """Entrypoint helper: print ``https`` (after preparing nginx) or ``http``."""
    from app.config import ConfigError, load_settings

    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"NXray's settings are not usable: {exc}", file=sys.stderr)
        return 1
    if not settings.enable_https:
        print("http")
        return 0
    if ensure_certificate(settings.tls_dir):
        print(
            f"nxray: made a self-signed certificate in {settings.tls_dir}; "
            "upload your own on the Settings page",
            file=sys.stderr,
        )
    for sub in ("run", "logs", "client_temp", "proxy_temp"):
        (NGINX_DIR / sub).mkdir(parents=True, exist_ok=True)
    write_nginx_config(settings.https_port, settings.tls_dir, NGINX_TEMPLATE, NGINX_CONFIG)
    print("https")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
