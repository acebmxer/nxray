"""The front-panel picture: layout, colours and tooltips (app/face.py)."""

from __future__ import annotations

import copy
import re
from dataclasses import replace

from app.face import (
    channel_colours,
    color_mode,
    draw_face,
    panel_layout,
    port_colour,
    short_device_name,
    speed_class,
    tooltip,
    vlan_colours,
)
from app.neighbors import Neighbor, NeighborView, PortChannel
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


def test_small_cages_come_in_blocks_of_eight_pairs() -> None:
    """As on the Nexus 92160YC-X: ports 1-16, 17-32 and 33-48."""
    cages = {cage.number: cage for cage in panel_layout(_ports())[0]}
    inside = cages[3].x - cages[1].x
    assert cages[15].x - cages[13].x == inside
    assert cages[17].x - cages[15].x > inside
    assert cages[31].x - cages[29].x == inside
    assert cages[33].x - cages[31].x > inside


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
    up = replace(port, up=True, bandwidth_bits=25_000_000_000)
    assert port_colour(up, "state", {}) == ("f-25g", "Up, 25G")
    assert port_colour(replace(up, bandwidth_bits=10_000_000_000), "state", {})[0] == "f-10g"
    assert port_colour(replace(up, bandwidth_bits=7_000_000_000), "state", {})[0] == "f-other"
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
    ports[0] = replace(ports[0], up=True, bandwidth_bits=25_000_000_000)
    legend = {entry.css: entry.count for entry in draw_face(ports, "state").legend}
    # Every colour of the State view is listed, with 0 when no port has it.
    assert legend == {
        "f-1g": 0,
        "f-10g": 0,
        "f-25g": 1,
        "f-40g": 0,
        "f-100g": 0,
        "f-down": 0,
        "f-empty": 53,
        "f-off": 0,
    }
    labels = [entry.label for entry in draw_face(ports, "state").legend]
    assert labels[:5] == ["Up, 1G", "Up, 10G", "Up, 25G", "Up, 40G", "Up, 100G"]


def test_fixed_colour_views_list_every_colour() -> None:
    """Speed, Traffic and Errors show all their colours, with 0 for the unused."""
    ports = _ports()
    expected = {
        "speed": ["f-1g", "f-10g", "f-25g", "f-40g", "f-100g", "f-none"],
        "traffic": ["f-t0", "f-t1", "f-t2", "f-t3", "f-none"],
        "errors": ["f-err", "f-clean", "f-none"],
    }
    for mode, classes in expected.items():
        legend = draw_face(ports, mode).legend
        assert sorted(entry.css for entry in legend) == sorted(classes)
        assert all(entry.count == 0 for entry in legend if entry.css != "f-none")


def test_no_inline_style_or_script_reaches_the_svg() -> None:
    """The page's Content-Security-Policy refuses both, so colours must be classes."""
    svg = str(draw_face(_ports(), "vlan").svg)
    assert "style=" not in svg and "<script" not in svg
    assert not re.search(r"\bon[a-z]+=", svg)


def _view() -> NeighborView:
    return NeighborView(
        neighbors=[
            Neighbor("LLDP", "Ethernet1/3", "esx-01.lab.example", "vmnic2", "", "", "", ""),
            Neighbor("CDP", "Ethernet1/4", "core-switch-north(FOX123)", "Te1/0/1", "", "", "", ""),
        ],
        port_channels=[
            PortChannel("port-channel43", ("Ethernet1/43", "Ethernet1/44"), "LACP", True),
            PortChannel("port-channel5", ("Ethernet1/5",), "LACP", True),
        ],
    )


def test_speed_colours_follow_the_running_speed() -> None:
    port = _port(_ports(), "Ethernet1/1")
    assert speed_class(port) == ("f-none", "No link")
    for bits, css in (
        (10**9, "f-1g"),
        (10**10, "f-10g"),
        (25 * 10**9, "f-25g"),
        (10**11, "f-100g"),
    ):
        assert speed_class(replace(port, up=True, bandwidth_bits=bits))[0] == css
    odd = replace(port, up=True, bandwidth_bits=5 * 10**9, speed="5 Gb/s")
    assert speed_class(odd) == ("f-other", "5 Gb/s")
    assert port_colour(odd, "speed", {}) == ("f-other", "5 Gb/s")


def test_port_channel_colours() -> None:
    colours = channel_colours(_view())
    # port-channel5 before port-channel43: by number, not as text.
    assert colours == {"port-channel5": 0, "port-channel43": 1}
    port = replace(_port(_ports(), "Ethernet1/43"), up=True)
    assert port_colour(port, "channel", colours, channel="port-channel43") == (
        "f-channel s1",
        "port-channel43",
    )
    assert port_colour(replace(port, up=False), "channel", colours, channel="port-channel43")[
        0
    ] == ("f-channel s1 f-faded")
    assert port_colour(port, "channel", colours)[0] == "f-none"
    assert channel_colours(None) == {}


def test_device_names_are_written_next_to_their_ports() -> None:
    assert short_device_name("esx-01.lab.example") == "esx-01"
    assert short_device_name("core-switch-north(FOX123)") == "core-switch-north"
    svg = str(draw_face(_ports(), "state", neighbors=_view()).svg)
    assert '<text class="face-device face-device-on"' in svg
    assert ">esx-01</text>" in svg
    # Too long for one cage: cut, with an ellipsis.
    assert ">core-…</text>" in svg


def test_the_model_link_and_selected_port() -> None:
    face = draw_face(
        _ports(),
        "channel",
        neighbors=_view(),
        model="Nexus9000 C92160YC-X chassis",
        link=lambda name: f"/ports?port={name}",
        selected="Ethernet1/7",
    )
    svg = str(face.svg)
    assert ">Nexus9000</text>" in svg and ">C92160YC-X</text>" in svg
    assert ">48 × SFP</text>" in svg and ">6 × QSFP</text>" in svg
    assert '<a class="face-port face-sel" href="/ports?port=Ethernet1/7">' in svg
    assert svg.count("face-sel") == 1
    assert {entry.label for entry in face.legend} >= {"port-channel43", "Not in a port-channel"}


def test_a_light_is_lit_on_ports_with_a_link() -> None:
    ports = _ports()
    ports[0] = replace(ports[0], up=True)
    svg = str(draw_face(ports, "state").svg)
    assert svg.count('class="face-light face-light-on"') == 1
