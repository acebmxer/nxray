"""The front-panel picture: layout, colours and tooltips (app/face.py)."""

from __future__ import annotations

import copy
import re
from dataclasses import replace

from app.face import (
    color_mode,
    draw_face,
    panel_layout,
    port_colour,
    tooltip,
    vlan_colours,
)
from app.ports import Port, Transceiver, parse_ports
from tests.conftest import load_fixture


def _ports(interface_body: dict | None = None) -> list[Port]:
    return parse_ports(
        interface_body or load_fixture("show_interface"),
        load_fixture("show_interface_status"),
        load_fixture("show_interface_transceiver"),
    )


def _port(ports: list[Port], name: str) -> Port:
    return next(port for port in ports if port.name == name)


def test_the_recorded_switch_has_48_small_and_6_wide_cages() -> None:
    cages, width, height = panel_layout(_ports())
    assert len(cages) == 54
    assert [cage.number for cage in cages if cage.wide] == [49, 50, 51, 52, 53, 54]
    assert all(not cage.wide for cage in cages if cage.number <= 48)
    assert width > height > 0


def test_odd_ports_sit_on_top_of_the_even_ones() -> None:
    cages = {cage.number: cage for cage in panel_layout(_ports())[0]}
    for odd in (1, 3, 47, 49, 53):
        top, bottom = cages[odd], cages[odd + 1]
        assert top.top and not bottom.top
        assert top.x == bottom.x
        assert top.y + top.height < bottom.y
    # Pairs run left to right, and the wide cages come after the small ones.
    assert cages[1].x < cages[3].x < cages[47].x < cages[49].x < cages[51].x < cages[53].x
    # Both kinds of cage use the same rows, so the picture lines up.
    assert cages[1].y == cages[49].y
    assert cages[2].y + cages[2].height == cages[50].y + cages[50].height


def test_small_cages_come_in_blocks_of_six_pairs() -> None:
    cages = {cage.number: cage for cage in panel_layout(_ports())[0]}
    inside = cages[3].x - cages[1].x
    assert cages[11].x - cages[9].x == inside
    assert cages[13].x - cages[11].x > inside


def test_a_broken_out_port_is_one_cage_cut_in_four() -> None:
    body = load_fixture("show_interface")
    rows = body["TABLE_interface"]["ROW_interface"]
    parent = next(row for row in rows if row["interface"] == "Ethernet1/50")
    rows.remove(parent)
    for lane in (1, 2, 3, 4):
        row = copy.deepcopy(parent)
        row.update({"interface": f"Ethernet1/50/{lane}", "eth_hw_desc": "10000/25000 Ethernet"})
        rows.append(row)
    cages = {cage.number: cage for cage in panel_layout(_ports(body))[0]}
    assert cages[50].wide
    assert [port.name for port in cages[50].ports] == [f"Ethernet1/50/{n}" for n in (1, 2, 3, 4)]
    svg = str(draw_face(_ports(body), "state").svg)
    for lane in (1, 2, 3, 4):
        assert f'href="/ports/detail?name=Ethernet1/50/{lane}"' in svg


def test_state_colours() -> None:
    port = _port(_ports(), "Ethernet1/1")
    assert port_colour(port, "state", {})[0] == "f-empty"
    assert port_colour(replace(port, up=True), "state", {})[0] == "f-up"
    assert port_colour(replace(port, admin_up=False), "state", {})[0] == "f-off"
    plugged = replace(port, transceiver=Transceiver(present=True, type="SFP-H10GB-CU3M"))
    assert port_colour(plugged, "state", {}) == (
        "f-down",
        "Down: something is plugged in, no link",
    )


def test_traffic_colours_are_a_share_of_the_link() -> None:
    port = replace(_port(_ports(), "Ethernet1/1"), up=True, bandwidth_bits=10_000_000_000)
    assert port_colour(replace(port, up=False), "traffic", {})[0] == "f-none"
    assert port_colour(port, "traffic", {})[0] == "f-t0"
    assert port_colour(replace(port, in_bits_per_second=200_000_000), "traffic", {})[0] == "f-t1"
    assert port_colour(replace(port, out_bits_per_second=2_000_000_000), "traffic", {})[0] == "f-t2"
    assert port_colour(replace(port, in_bits_per_second=6_000_000_000), "traffic", {})[0] == "f-t3"
    # No bandwidth reported: counted as idle rather than dividing by zero.
    assert (
        port_colour(replace(port, bandwidth_bits=0, in_bits_per_second=5), "traffic", {})[0]
        == "f-t0"
    )


def test_error_colours() -> None:
    port = _port(_ports(), "Ethernet1/1")
    assert port_colour(port, "errors", {})[0] == "f-none"
    assert port_colour(replace(port, up=True), "errors", {})[0] == "f-clean"
    counted = replace(port, counters={"eth_indiscard": 3})
    assert port_colour(counted, "errors", {})[0] == "f-err"


def test_vlan_colours() -> None:
    vlans = ["1", "79", "10", "trunk", "routed", "79"]
    ports = [replace(port, vlan=vlan) for port, vlan in zip(_ports()[:6], vlans, strict=True)]
    colours = vlan_colours(ports)
    assert colours == {"1": 0, "10": 1, "79": 2}
    up = [replace(port, up=True) for port in ports]
    assert port_colour(up[1], "vlan", colours, {79: "Work"}) == ("f-vlan s2", "VLAN 79 Work")
    assert port_colour(up[3], "vlan", colours)[0] == "f-trunk"
    assert port_colour(up[4], "vlan", colours)[0] == "f-routed"
    # A port without a link keeps its VLAN colour, faded.
    assert port_colour(ports[1], "vlan", colours)[0] == "f-vlan s2 f-faded"


def test_unknown_mode_is_state() -> None:
    assert color_mode("nonsense") == "state"
    assert color_mode(None) == "state"
    assert color_mode("vlan") == "vlan"


def test_tooltip_lists_the_port_facts() -> None:
    port = replace(
        _port(_ports(), "Ethernet1/3"),
        up=True,
        speed="25 Gb/s",
        vlan="79",
        description="xcp-host-1",
        in_bits_per_second=12_500_000,
        counters={"eth_inerr": 4},
        transceiver=Transceiver(present=True, type="SFP-25G-SR-S"),
    )
    assert tooltip(port, "Proxmox node 2", {79: "Work"}).splitlines() == [
        "Ethernet1/3 — Proxmox node 2",
        "Up, 25 Gb/s",
        "VLAN 79 (Work)",
        "Description: xcp-host-1",
        "Transceiver: SFP-25G-SR-S",
        "In 12.5 Mb/s, out 0 b/s",
        "Errors and discards: 4",
    ]
    down = _port(_ports(), "Ethernet1/1")
    assert tooltip(down).splitlines()[1:] == [
        "Down: XCVR not inserted",
        "VLAN 1",
        "Nothing plugged in",
    ]


def test_every_port_is_a_link_with_a_tooltip_and_text_is_escaped() -> None:
    ports = _ports()
    ports[2] = replace(ports[2], description='<script>alert("x")</script>')
    face = draw_face(ports, "state", {"Ethernet1/3": "rack <A> & B"})
    svg = str(face.svg)
    assert svg.count('<a class="face-port"') == 54
    assert svg.count("<title>") == 54
    assert "<script>" not in svg and "&lt;script&gt;" in svg
    assert "rack &lt;A&gt; &amp; B" in svg
    # A labelled port gets a mark; the others don't.
    assert svg.count('class="face-mark"') == 1


def test_the_legend_counts_ports_per_colour() -> None:
    ports = _ports()
    ports[0] = replace(ports[0], up=True)
    legend = {entry.css: entry.count for entry in draw_face(ports, "state").legend}
    assert legend == {"f-up": 1, "f-empty": 53}
    labels = [entry.label for entry in draw_face(ports, "state").legend]
    assert labels[0] == "Up"


def test_no_inline_style_or_script_reaches_the_svg() -> None:
    """The page's Content-Security-Policy refuses both, so colours must be classes."""
    svg = str(draw_face(_ports(), "vlan").svg)
    assert "style=" not in svg and "<script" not in svg
    assert not re.search(r"\bon[a-z]+=", svg)
