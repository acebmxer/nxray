"""Encryption of the stored switch password."""

from __future__ import annotations

import base64

import pytest

from app.crypto import DecryptionError, decrypt, encrypt


def test_round_trip() -> None:
    assert decrypt(encrypt("Secret1Password", "key-a"), "key-a") == "Secret1Password"


def test_same_value_encrypts_differently_each_time() -> None:
    assert encrypt("same", "key-a") != encrypt("same", "key-a")


def test_wrong_key_is_refused() -> None:
    with pytest.raises(DecryptionError):
        decrypt(encrypt("Secret1Password", "key-a"), "key-b")


def test_tampering_is_detected() -> None:
    raw = bytearray(base64.b64decode(encrypt("Secret1Password", "key-a")))
    raw[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt(base64.b64encode(bytes(raw)).decode(), "key-a")


@pytest.mark.parametrize("stored", ["not base64!", "", base64.b64encode(b"short").decode()])
def test_garbage_is_refused(stored: str) -> None:
    with pytest.raises(DecryptionError):
        decrypt(stored, "key-a")
