"""MAC addresses: their written forms, and the maker each one belongs to.

The maker comes from the IEEE's public list of address blocks (MA-L, MA-M
and MA-S), kept in ``app/oui.tsv.gz`` and refreshed by
``scripts/update_oui.py`` each time the image is built. The longest block
that matches wins, so a company holding a small MA-S block inside a split
MA-L block is named rather than the IEEE itself.

An address whose second-lowest bit of the first byte is set is "locally
administered": it was made up by the device or its software (virtual
machines, containers, phones hiding their real address) and has no maker.
"""

from __future__ import annotations

import gzip
from functools import lru_cache
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parent / "oui.tsv.gz"

_HEX = frozenset("0123456789abcdef")


def normalize_mac(text: str) -> str | None:
    """The 12 hex digits of a MAC address in any common form, lower case; None if it is not one.

    Accepts the switch's ``0cea.1439.bb3a``, ``0c:ea:14:39:bb:3a``,
    ``0C-EA-14-39-BB-3A`` and plain ``0cea1439bb3a``.
    """
    digits = "".join(ch for ch in text.strip().lower() if ch not in ".:-")
    if len(digits) != 12 or not set(digits) <= _HEX:
        return None
    return digits


def format_mac(text: str) -> str:
    """``0cea.1439.bb3a`` -> ``0c:ea:14:39:bb:3a``; other text comes back as is."""
    digits = normalize_mac(text)
    if digits is None:
        return text.strip()
    return ":".join(digits[index : index + 2] for index in range(0, 12, 2))


def is_local_mac(text: str) -> bool:
    """True for a locally administered address (made up by the device, not assigned to a maker)."""
    digits = normalize_mac(text)
    return digits is not None and bool(int(digits[:2], 16) & 0x02)


@lru_cache(maxsize=1)
def _makers() -> dict[str, str]:
    """Hex prefix (upper case, 6, 7 or 9 digits) -> organisation. Read once, on first use."""
    table: dict[str, str] = {}
    try:
        with gzip.open(DATA_FILE, "rt", encoding="utf-8") as lines:
            for line in lines:
                prefix, _, name = line.rstrip("\n").partition("\t")
                if prefix and name:
                    table[prefix] = name
    except (OSError, EOFError):
        # A missing or damaged list means no maker names, never a broken page.
        return {}
    return table


def mac_maker(text: str) -> str:
    """The organisation a MAC address was assigned to.

    "" when the address is unknown or locally administered.
    """
    digits = normalize_mac(text)
    if digits is None or is_local_mac(digits):
        return ""
    makers = _makers()
    upper = digits.upper()
    for length in (9, 7, 6):
        name = makers.get(upper[:length])
        if name:
            return name
    return ""
