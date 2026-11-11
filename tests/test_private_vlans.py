"""Private VLANs (app/private_vlans.py): reading the private VLANs, ports and VLAN
interface mappings, the lines every setting sends, and the values NXray refuses.

The show output and the lines were recorded on cisco-25gb (NX-OS 9.3(16)); the port rows
were recorded on one spare port in each mode and are shown here on four ports."""

from __future__ import annotations

import pytest

from app.private_vlans import (
    PRIVATE_VLANS,
    build_private_vlan_change,
    parse_private_vlans,
    parse_pvlan_ports,
)
from tests.conftest import load_fixture

TYPES = load_fixture("show_vlan_private-vlan_type")
PAIRS = load_fixture("show_vlan_private-vlan")
PORTS = load_fixture("show_interface_switchport_private-vlan")
MAPPING = load_fixture("show_interface_private-vlan_mapping")


def _view():
    return parse_private_vlans([TYPES, PAIRS, PORTS], MAPPING)


def _lines(scope: str, setting: str, action: str, ident: dict, values: dict) -> tuple[str, ...]:
    return build_private_vlan_change(scope, setting, action, ident, values).lines


def test_the_pairs_table_has_each_secondary_with_its_ports() -> None:
    rows = _view().tables[0].rows
    assert (
        "250",
        "251",
        "isolated",
        "Ethernet1/51, Ethernet1/53",
        "Ethernet1/52, Ethernet1/54",
    ) in rows
    assert ("250", "252", "community", "-", "Ethernet1/52, Ethernet1/54") in rows
    # A primary VLAN with no secondary yet still shows.
    assert ("260", "-", "primary", "-", "-") in rows


def test_every_private_vlan_is_a_place_with_its_type() -> None:
    places = {i.ident["vlan"]: i for i in _view().of("vlan")}
    assert sorted(places) == ["250", "251", "252", "260"]
    assert places["250"].values == {
        "type": {"type": "primary"},
        "association": {"secondary": "251-252"},
    }
    facts = dict(places["250"].facts)
    assert facts["Secondary VLANs"] == "251-252"
    assert facts["Routed by"] == "Vlan250"
    assert dict(places["251"].facts)["Primary VLAN"] == "250"
    assert dict(places["260"].facts)["Secondary VLANs"] == "none yet"


def test_only_ports_with_private_vlan_settings_are_listed() -> None:
    ports = {p.name: p for p in parse_pvlan_ports(PORTS)}
    assert sorted(ports) == ["Ethernet1/51", "Ethernet1/52", "Ethernet1/53", "Ethernet1/54"]
    assert ports["Ethernet1/51"].mode == "host"
    assert ports["Ethernet1/51"].host == ("250", "251")
    assert ports["Ethernet1/52"].mapping == ("250", "251-252")
    assert ports["Ethernet1/53"].trunk_pairs == (("250", "251"),)
    assert ports["Ethernet1/54"].mode == "trunk promiscuous"
    # The native VLAN the switch reports for a port that is not a trunk is not shown.
    assert ports["Ethernet1/51"].trunk_native == ""


def test_the_ports_shown_have_their_current_values() -> None:
    places = {i.ident["port"]: i for i in _view().of("port")}
    assert places["Ethernet1/51"].values == {
        "mode": {"mode": "host"},
        "host": {"primary": "250", "secondary": "251"},
    }
    assert places["Ethernet1/52"].values["mapping"] == {"primary": "250", "secondary": "251-252"}


def test_a_vlan_interface_mapping_is_a_place() -> None:
    (svi,) = _view().of("svi")
    assert svi.ident == {"interface": "Vlan250"}
    assert svi.values == {"mapping": {"secondary": "251-252"}}


def test_nothing_made_gives_empty_tables() -> None:
    view = parse_private_vlans([{}, {}, {}], {})
    assert view.instances == ()
    assert all(t.rows == () for t in view.tables)


@pytest.mark.parametrize(
    ("scope", "setting", "action", "ident", "values", "lines"),
    [
        ("vlan", "type", "set", {"vlan": "250"}, {"type": "primary"},
         ("vlan 250", "private-vlan primary")),
        ("vlan", "type", "remove", {"vlan": "251"}, {"type": "isolated"},
         ("vlan 251", "no private-vlan isolated")),
        ("vlan", "association", "set", {"vlan": "250"}, {"secondary": "251, 252-254"},
         ("vlan 250", "private-vlan association 251,252-254")),
        ("vlan", "association", "remove", {"vlan": "250"}, {"secondary": "252"},
         ("vlan 250", "private-vlan association remove 252")),
        ("vlan", "association_all", "remove", {"vlan": "250"}, {},
         ("vlan 250", "no private-vlan association")),
        ("port", "mode", "set", {"port": "Ethernet1/5"}, {"mode": "trunk secondary"},
         ("interface Ethernet1/5", "switchport mode private-vlan trunk secondary")),
        ("port", "mode", "remove", {"port": "po20"}, {"mode": "host"},
         ("interface port-channel20", "no switchport mode private-vlan host")),
        ("port", "host", "set", {"port": "Ethernet1/5"}, {"primary": "250", "secondary": "251"},
         ("interface Ethernet1/5", "switchport private-vlan host-association 250 251")),
        ("port", "host", "remove", {"port": "Ethernet1/5"}, {},
         ("interface Ethernet1/5", "no switchport private-vlan host-association")),
        ("port", "mapping", "set", {"port": "Ethernet1/5"},
         {"primary": "250", "secondary": "251-252"},
         ("interface Ethernet1/5", "switchport private-vlan mapping 250 251-252")),
        ("port", "mapping", "remove", {"port": "Ethernet1/5"},
         {"primary": "250", "secondary": "252"},
         ("interface Ethernet1/5", "switchport private-vlan mapping 250 remove 252")),
        ("port", "mapping_all", "remove", {"port": "Ethernet1/5"}, {},
         ("interface Ethernet1/5", "no switchport private-vlan mapping")),
        ("port", "trunk_mapping", "set", {"port": "Ethernet1/5"},
         {"primary": "250", "secondary": "251-252"},
         ("interface Ethernet1/5", "switchport private-vlan mapping trunk 250 251-252")),
        ("port", "trunk_mapping", "remove", {"port": "Ethernet1/5"}, {},
         ("interface Ethernet1/5", "no switchport private-vlan mapping trunk")),
        ("port", "trunk_association", "set", {"port": "Ethernet1/5"},
         {"primary": "250", "secondary": "251"},
         ("interface Ethernet1/5", "switchport private-vlan association trunk 250 251")),
        ("port", "trunk_association", "remove", {"port": "Ethernet1/5"}, {"primary": "250"},
         ("interface Ethernet1/5", "no switchport private-vlan association trunk 250")),
        ("port", "trunk_allowed", "set", {"port": "Ethernet1/5"}, {"vlans": "10,20"},
         ("interface Ethernet1/5", "switchport private-vlan trunk allowed vlan 10,20")),
        ("port", "trunk_allowed", "remove", {"port": "Ethernet1/5"}, {"vlans": "20"},
         ("interface Ethernet1/5", "no switchport private-vlan trunk allowed vlan 20")),
        ("port", "trunk_native", "set", {"port": "Ethernet1/5"}, {"vlan": "10"},
         ("interface Ethernet1/5", "switchport private-vlan trunk native vlan 10")),
        ("port", "trunk_native", "remove", {"port": "Ethernet1/5"}, {},
         ("interface Ethernet1/5", "no switchport private-vlan trunk native vlan")),
        ("svi", "mapping", "set", {"interface": "Vlan250"}, {"secondary": "251-252"},
         ("interface Vlan250", "private-vlan mapping 251-252")),
        ("svi", "mapping", "remove", {"interface": "Vlan250"}, {"secondary": "252"},
         ("interface Vlan250", "private-vlan mapping remove 252")),
        ("svi", "mapping_all", "remove", {"interface": "Vlan250"}, {},
         ("interface Vlan250", "no private-vlan mapping")),
    ],
)  # fmt: skip
def test_each_setting_sends_its_line(scope, setting, action, ident, values, lines) -> None:
    assert _lines(scope, setting, action, ident, values) == lines


@pytest.mark.parametrize(
    ("scope", "setting", "action", "ident", "values"),
    [
        ("vlan", "type", "set", {"vlan": "250"}, {"type": "twin"}),
        ("vlan", "type", "set", {"vlan": "4000"}, {"type": "primary"}),
        ("vlan", "association", "set", {"vlan": "250"}, {"secondary": "251 ; reload"}),
        ("vlan", "association_all", "set", {"vlan": "250"}, {}),
        ("port", "mode", "set", {"port": "Ethernet1/5"}, {"mode": "trunk"}),
        ("port", "host", "set", {"port": "Ethernet1/5"}, {"primary": "250", "secondary": "1-5"}),
        ("port", "host", "set", {"port": "mgmt0"}, {"primary": "250", "secondary": "251"}),
        ("svi", "mapping", "set", {"interface": "Ethernet1/5 ; x"}, {"secondary": "251"}),
    ],
)
def test_wrong_values_are_refused(scope, setting, action, ident, values) -> None:
    with pytest.raises(ValueError):
        build_private_vlan_change(scope, setting, action, ident, values)


def test_the_page_needs_the_feature() -> None:
    assert PRIVATE_VLANS.features == ("private-vlan",)
