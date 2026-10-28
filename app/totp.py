"""Two-factor sign-in codes (TOTP, RFC 6238), backup codes and the setup QR code.

The codes are the ones every authenticator app makes (Google Authenticator,
Microsoft Authenticator, Authy, 1Password, ...): HMAC-SHA1 over a 30-second
counter, six digits. That is a few lines on top of the standard library, so
there is no dependency for it.

The QR code is drawn with ``segno`` (pure Python, no dependencies of its own)
as inline SVG on the setup page. The ``otpauth://`` text in it carries the
secret, so it is never sent to an outside image service and never written to
disk.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import secrets
import time
from urllib.parse import quote

import segno

ISSUER = "NXray"
DIGITS = 6
PERIOD = 30
_SECRET_BYTES = 20  # 160 bits, the length RFC 4226 recommends.

# Codes one 30-second step either side of now are still accepted: a phone
# clock a little off, or a code typed just as it changed.
_DRIFT_STEPS = 1

BACKUP_CODE_COUNT = 10
# No 0/O or 1/I, so a code read off paper is not mistyped.
_BACKUP_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
_BACKUP_HALF = 5  # shown as XXXXX-XXXXX


def generate_secret() -> str:
    """A new random TOTP secret, base32 as authenticator apps expect it."""
    return base64.b32encode(secrets.token_bytes(_SECRET_BYTES)).decode("ascii")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32.upper())
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def time_step(at: float | None = None) -> int:
    """The 30-second step a moment falls in (now when ``at`` is None)."""
    return int((time.time() if at is None else at) // PERIOD)


def code_at(secret_b32: str, step: int) -> str:
    """The six-digit code for one step. Tests use it; sign-in only checks codes."""
    return _hotp(secret_b32, step)


def matching_step(secret_b32: str, code: str, *, at: float | None = None) -> int | None:
    """The step a typed code belongs to, or None when it matches none near now.

    The caller stores the step and refuses any code from that step or an
    earlier one afterwards, so a code that was seen (over a shoulder, in a
    proxy log) can't be used a second time. Each candidate is compared with
    ``hmac.compare_digest`` so timing gives nothing away.
    """
    code = code.strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    now = time_step(at)
    found = None
    for step in range(now - _DRIFT_STEPS, now + _DRIFT_STEPS + 1):
        if hmac.compare_digest(_hotp(secret_b32, step), code):
            found = step
    return found


def provisioning_uri(secret_b32: str, username: str) -> str:
    """The ``otpauth://`` text the QR code holds: the app shows "NXray (username)"."""
    label = quote(f"{ISSUER}:{username}")
    return (
        f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(ISSUER)}"
        f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}"
    )


def qr_svg(text: str) -> str:
    """``text`` as a QR code, as ``<svg>`` markup for the page."""
    qr = segno.make(text, error="m")
    buffer = io.BytesIO()
    qr.save(buffer, kind="svg", scale=5, border=3, xmldecl=False, svgns=True)
    return buffer.getvalue().decode("utf-8")


def spaced_secret(secret_b32: str) -> str:
    """The secret in groups of four, easier to type into an app by hand."""
    return " ".join(secret_b32[i : i + 4] for i in range(0, len(secret_b32), 4))


def generate_backup_codes() -> list[str]:
    """Ten one-time codes for when the phone is lost, as XXXXX-XXXXX.

    Shown once; only their hashes are stored (``hash_backup_code``).
    """
    codes = []
    for _ in range(BACKUP_CODE_COUNT):
        raw = "".join(secrets.choice(_BACKUP_ALPHABET) for _ in range(2 * _BACKUP_HALF))
        codes.append(f"{raw[:_BACKUP_HALF]}-{raw[_BACKUP_HALF:]}")
    return codes


def hash_backup_code(code: str) -> str:
    """The stored form of a backup code; case, spaces and the dash are ignored.

    SHA-256 rather than Argon2: the code is random (50 bits), not a
    human-chosen password, and sign-in attempts are throttled anyway.
    """
    normalised = code.strip().upper().replace("-", "").replace(" ", "")
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()
