"""Download the IEEE list of MAC address makers into app/oui.tsv.gz.

NXray shows the maker of each device the switch has learned (app/oui.py).
The maker is read from the first part of the MAC address, which the IEEE
assigns to companies in three block sizes: MA-L (the first 24 bits), MA-M
(28 bits) and MA-S (36 bits). This script fetches all three public lists and
writes one line per block, ``<hex prefix>\\t<organisation>``, gzip-compressed.

The image build runs it (see the Dockerfile), so each published image carries
the list as it was that day. The copy committed in the repository is the
fallback for a build that cannot reach the IEEE, and what the tests read.
Run it by hand to refresh that copy:

    python scripts/update_oui.py

Standard library only: it runs in the image's build stage before anything
is installed. The output is written to a temporary file first and moved into
place only when every list was read, so a failed download keeps the old file.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import os
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

SOURCES = (
    "https://standards-oui.ieee.org/oui/oui.csv",
    "https://standards-oui.ieee.org/oui28/mam.csv",
    "https://standards-oui.ieee.org/oui36/oui36.csv",
)

DEFAULT_OUT = Path(__file__).resolve().parent.parent / "app" / "oui.tsv.gz"

# MA-L blocks the IEEE split into MA-M and MA-S blocks carry this name; the
# smaller blocks name the real maker, so the placeholder is left out.
_PLACEHOLDER = "IEEE Registration Authority"

_HEX = frozenset("0123456789ABCDEF")


def fetch(url: str, attempts: int = 4) -> str:
    """The text at ``url``, trying a few times before giving up."""
    request = urllib.request.Request(url, headers={"User-Agent": "nxray-oui-update"})
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - fixed https URLs
                return response.read().decode("utf-8")
        except OSError as exc:
            if attempt == attempts:
                raise
            print(f"{url}: {exc}; trying again", file=sys.stderr)
            time.sleep(2 * attempt)
    raise AssertionError("unreachable")


def parse(text: str) -> dict[str, str]:
    """Prefix -> organisation from one IEEE CSV (Registry, Assignment, Organization Name, ...)."""
    found: dict[str, str] = {}
    for row in csv.DictReader(io.StringIO(text)):
        prefix = (row.get("Assignment") or "").strip().upper()
        name = " ".join((row.get("Organization Name") or "").split())
        if not prefix or not set(prefix) <= _HEX or len(prefix) not in (6, 7, 9):
            continue
        if not name or name == _PLACEHOLDER:
            continue
        found[prefix] = name
    return found


def build(texts: list[str]) -> bytes:
    """The gzip file's bytes: sorted lines, no timestamp, so the same lists give the same file."""
    table: dict[str, str] = {}
    for text in texts:
        table.update(parse(text))
    if len(table) < 10_000:
        raise ValueError(f"only {len(table)} makers read; the IEEE lists look wrong")
    lines = "".join(f"{prefix}\t{table[prefix]}\n" for prefix in sorted(table))
    return gzip.compress(lines.encode("utf-8"), mtime=0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Download the IEEE list of MAC address makers.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="where to write the list")
    args = parser.parse_args(argv)
    try:
        data = build([fetch(url) for url in SOURCES])
    except (OSError, ValueError) as exc:
        print(f"MAC maker list not updated: {exc}", file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=args.out.parent, prefix=".oui-")
    with os.fdopen(handle, "wb") as out:
        out.write(data)
    os.chmod(temporary, 0o644)
    os.replace(temporary, args.out)
    print(f"MAC maker list written to {args.out} ({len(data):,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
