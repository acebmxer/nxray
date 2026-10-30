"""MAC addresses and their makers (app/oui.py), and the list's download script."""

from __future__ import annotations

import gzip
import importlib.util
from pathlib import Path

import pytest

from app import oui
from app.oui import format_mac, is_local_mac, mac_maker, normalize_mac

REPO_ROOT = Path(__file__).resolve().parent.parent


def _script():
    """scripts/update_oui.py as a module (scripts/ is not a package)."""
    path = REPO_ROOT / "scripts" / "update_oui.py"
    spec = importlib.util.spec_from_file_location("update_oui", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def small_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A three-line maker list in place of the real one."""
    path = tmp_path / "oui.tsv.gz"
    path.write_bytes(
        gzip.compress(
            b"0CEA14\tUbiquiti Inc\n70B3D5\tBig Block Ltd\n70B3D5123\tSmall Block GmbH\n",
            mtime=0,
        )
    )
    monkeypatch.setattr(oui, "DATA_FILE", path)
    oui._makers.cache_clear()
    yield path
    oui._makers.cache_clear()


def test_every_written_form_of_a_mac_address_is_read() -> None:
    for text in ("0cea.1439.bb3a", "0c:ea:14:39:bb:3a", "0C-EA-14-39-BB-3A", "0cea1439bb3a"):
        assert normalize_mac(text) == "0cea1439bb3a"
        assert format_mac(text) == "0c:ea:14:39:bb:3a"


def test_text_that_is_not_a_mac_address_is_left_alone() -> None:
    for text in ("", "0cea.1439", "zzzz.zzzz.zzzz", "0cea.1439.bb3a.ff"):
        assert normalize_mac(text) is None
    assert format_mac(" sup-eth1(R) ") == "sup-eth1(R)"
    assert mac_maker("not a mac") == ""


def test_locally_administered_addresses_have_no_maker() -> None:
    assert is_local_mac("0a00.0000.000a")
    assert is_local_mac("32:fe:ba:11:d7:08")
    assert not is_local_mac("0cea.1439.bb3a")
    # Even when a block in the list starts with the same digits.
    assert mac_maker("0200.0000.bbde") == ""


def test_the_shipped_list_names_real_makers() -> None:
    oui._makers.cache_clear()
    assert "Cisco" in mac_maker("00:00:0c:12:34:56")
    assert "Ubiquiti" in mac_maker("0cea.1439.bb3a")
    assert len(oui._makers()) > 30_000


def test_the_smallest_matching_block_wins(small_list: Path) -> None:
    assert mac_maker("70b3.d512.3456") == "Small Block GmbH"
    assert mac_maker("70b3.d5ff.0001") == "Big Block Ltd"
    assert mac_maker("0cea.1400.0001") == "Ubiquiti Inc"
    assert mac_maker("1c6a.1b00.0003") == ""


def test_a_missing_list_means_no_makers_not_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(oui, "DATA_FILE", tmp_path / "gone.tsv.gz")
    oui._makers.cache_clear()
    try:
        assert mac_maker("0cea.1439.bb3a") == ""
    finally:
        oui._makers.cache_clear()


def test_a_damaged_list_means_no_makers_not_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broken = tmp_path / "broken.tsv.gz"
    broken.write_bytes(b"this is not gzip")
    monkeypatch.setattr(oui, "DATA_FILE", broken)
    oui._makers.cache_clear()
    try:
        assert mac_maker("0cea.1439.bb3a") == ""
    finally:
        oui._makers.cache_clear()


_CSV_HEAD = "Registry,Assignment,Organization Name,Organization Address\r\n"


def test_the_script_keeps_real_blocks_and_drops_the_ieee_placeholder() -> None:
    script = _script()
    found = script.parse(
        _CSV_HEAD
        + 'MA-L,0CEA14,Ubiquiti Inc,"685 Third Avenue New York NY US 10017 "\r\n'
        + "MA-L,70B3D5,IEEE Registration Authority,445 Hoes Lane Piscataway NJ US 08554\r\n"
        + 'MA-S,70B3D5123,"Small   Block, GmbH",Somewhere DE\r\n'
        + "MA-L,XYZ123,Not Hex,Nowhere\r\n"
    )
    assert found == {"0CEA14": "Ubiquiti Inc", "70B3D5123": "Small Block, GmbH"}


def test_the_script_writes_the_same_file_for_the_same_lists() -> None:
    script = _script()
    rows = "".join(f"MA-L,{n:06X},Maker {n},Address\r\n" for n in range(12_000))
    first = script.build([_CSV_HEAD + rows])
    assert first == script.build([_CSV_HEAD + rows])
    lines = gzip.decompress(first).decode().splitlines()
    assert lines[0] == "000000\tMaker 0" and len(lines) == 12_000
    assert lines == sorted(lines)


def test_the_script_refuses_a_list_that_looks_wrong(tmp_path: Path) -> None:
    script = _script()
    with pytest.raises(ValueError, match="look wrong"):
        script.build([_CSV_HEAD + "MA-L,0CEA14,Ubiquiti Inc,Address\r\n"])


def test_a_failed_download_keeps_the_old_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = _script()
    out = tmp_path / "oui.tsv.gz"
    out.write_bytes(b"old")

    def refuse(url: str, attempts: int = 4) -> str:
        raise OSError("no route to host")

    monkeypatch.setattr(script, "fetch", refuse)
    assert script.main(["--out", str(out)]) == 1
    assert out.read_bytes() == b"old"
    assert [path.name for path in tmp_path.iterdir()] == ["oui.tsv.gz"]
