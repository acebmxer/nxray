"""The switch face: a picture of the front panel, every port coloured.

Drawn on the server as inline SVG, like the History charts (app/charts.py):
no script, every colour from a CSS class in static/style.css, so the page's
Content-Security-Policy stays strict. Each port is a link (by default to its
own page; the Ports page passes one that opens its side panel) and carries an
SVG <title>, which browsers show as a tooltip on hover. Above each top-row
port and below each bottom-row port is the name of the device plugged into it,
when the switch heard one over CDP or LLDP.

The layout follows Cisco's front-panel numbering: ports in pairs, the odd
number on top and the even one below it, the small SFP cages first (in blocks
of eight pairs, as on the Nexus 92160YC-X: 1-16, 17-32, 33-48) and the wide
QSFP cages after them. Which cages are wide is read from the port's hardware
line (a port that can run at 40 Gb/s or more is a QSFP), so the drawing comes
from what the switch reports, not a table of models. A QSFP port split into
four (breakout, Ethernet1/50/1-4) is drawn as one cage cut into four.

Pure functions over app/ports.Port, so they are tested without a switch.
Every text that reaches the markup goes through ``html.escape``.
"""

from __future__ import annotations

import html
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import quote

from markupsafe import Markup

from app.neighbors import NeighborView, PortDevices
from app.ports import Port, human_rate

# How the ports can be coloured, and the words on the buttons for each.
MODES = {
    "state": "State",
    "speed": "Speed",
    "vlan": "VLAN",
    "channel": "Port-channel",
    "traffic": "Traffic",
    "errors": "Errors",
}

# How many VLAN colours style.css defines (.s0 to .s7, shared with the charts).
VLAN_COLOURS = 8

_PORT_NAME = re.compile(r"^Ethernet(\d+)/(\d+)(?:/(\d+))?$")
_SPEEDS = re.compile(r"\d+")
# A port that can run this fast (Mb/s) is a wide QSFP cage.
_QSFP_SPEED = 40_000

_PAD = 12
_LABELS = 13  # the band above and below the cages for device names
_BADGE = 100  # the model name at the left, when known
_SFP = (30, 22, 34)  # cage width, height, distance from one pair to the next
_QSFP = (44, 23, 50)
_ROW_GAP = {"sfp": 5, "qsfp": 3}  # between the top and bottom cage of a pair
_BLOCK_PAIRS = 8  # SFP pairs per block
_BLOCK_GAP = 18
_SECTION_GAP = 26  # between the SFP cages and the QSFP cages
# A pair of cages is as tall for SFP (2 x 22 + 5) as for QSFP (2 x 23 + 3),
# so the top and bottom rows line up across the panel.
_PAIR_HEIGHT = 2 * _SFP[1] + _ROW_GAP["sfp"]
# Roughly how wide one character of the device names is, in picture units.
_CHAR = 4.6

# Running speed (bits per second) -> (CSS class, legend words), for the Speed view.
_SPEED_CLASSES = {
    1_000_000_000: ("f-1g", "1G"),
    10_000_000_000: ("f-10g", "10G"),
    25_000_000_000: ("f-25g", "25G"),
    40_000_000_000: ("f-40g", "40G"),
    100_000_000_000: ("f-100g", "100G"),
}


@dataclass(frozen=True)
class LegendEntry:
    css: str
    label: str
    count: int


@dataclass(frozen=True)
class Face:
    svg: Markup
    legend: list[LegendEntry]


@dataclass(frozen=True)
class Cage:
    """One opening in the front panel and the port (or four breakout ports) in it."""

    number: int
    wide: bool
    ports: tuple[Port, ...]
    x: float
    y: float
    width: float
    height: float
    top: bool


def color_mode(value: str | None) -> str:
    """The colour mode asked for, or "state" for anything unknown."""
    return value if value in MODES else "state"


def _max_speed(port: Port) -> int:
    """The fastest speed in the port's hardware line ("1000/10000/25000 Ethernet")."""
    return max((int(speed) for speed in _SPEEDS.findall(port.hardware)), default=0)


def panel_layout(ports: Sequence[Port], left: float = _PAD) -> tuple[list[Cage], float, float]:
    """Where each port sits on the panel, plus the picture's width and height.

    ``left`` is where the first cage starts (room for the model name before it).
    """
    groups: dict[tuple[int, int], list[Port]] = {}
    for port in ports:
        match = _PORT_NAME.match(port.name)
        if match:
            groups.setdefault((int(match[1]), int(match[2])), []).append(port)
    narrow: list[tuple[int, int]] = []
    wide: list[tuple[int, int]] = []
    for key, members in groups.items():
        split = len(members) > 1 or "/" in members[0].name.split("/", 1)[1]
        is_wide = split or any(_max_speed(port) >= _QSFP_SPEED for port in members)
        (wide if is_wide else narrow).append(key)

    cages: list[Cage] = []
    top_y = _PAD + _LABELS
    x = float(left)
    for keys, kind in ((sorted(narrow), "sfp"), (sorted(wide), "qsfp")):
        if not keys:
            continue
        width, height, pitch = _SFP if kind == "sfp" else _QSFP
        pairs = sorted({(module, (number + 1) // 2) for module, number in keys})
        column = {pair: index for index, pair in enumerate(pairs)}
        for module, number in keys:
            index = column[(module, (number + 1) // 2)]
            gaps = index // _BLOCK_PAIRS if kind == "sfp" else 0
            top = number % 2 == 1
            members = sorted(groups[(module, number)], key=lambda port: port.name)
            cages.append(
                Cage(
                    number=number,
                    wide=kind == "qsfp",
                    ports=tuple(sorted(members, key=_sub_number)),
                    x=x + index * pitch + gaps * _BLOCK_GAP,
                    y=top_y if top else top_y + height + _ROW_GAP[kind],
                    width=width,
                    height=height,
                    top=top,
                )
            )
        blocks = (len(pairs) - 1) // _BLOCK_PAIRS if kind == "sfp" else 0
        x += (len(pairs) - 1) * pitch + width + blocks * _BLOCK_GAP + _SECTION_GAP
    panel_width = (x - _SECTION_GAP + _PAD) if cages else left + _PAD
    return cages, panel_width, top_y + _PAIR_HEIGHT + _LABELS + _PAD


def _sub_number(port: Port) -> int:
    match = _PORT_NAME.match(port.name)
    return int(match[3]) if match and match[3] else 0


def vlan_colours(ports: Sequence[Port]) -> dict[str, int]:
    """A colour number for each access VLAN in use, lowest VLAN first."""
    used = sorted({port.vlan for port in ports if port.vlan.isdigit()}, key=int)
    return {vlan: index % VLAN_COLOURS for index, vlan in enumerate(used)}


def channel_colours(neighbors: NeighborView | None) -> dict[str, int]:
    """A colour number for each port-channel, in name order."""
    names = sorted(
        (pc.name for pc in neighbors.port_channels) if neighbors else (),
        key=lambda name: (len(name), name),
    )
    return {name: index % VLAN_COLOURS for index, name in enumerate(names)}


def speed_class(port: Port) -> tuple[str, str]:
    """(CSS class, words) for the speed a port runs at; f-none when it has no link."""
    if not port.up:
        return "f-none", "No link"
    known = _SPEED_CLASSES.get(port.bandwidth_bits)
    if known:
        return known
    return "f-other", port.speed or "Other speed"


def port_colour(
    port: Port,
    mode: str,
    colours: Mapping[str, int],
    vlan_names: Mapping[int, str] | None = None,
    channel: str = "",
) -> tuple[str, str]:
    """(CSS classes, legend words) for one port in a colour mode.

    ``colours`` maps VLANs (vlan mode) or port-channel names (channel mode) to
    a colour number; ``channel`` is the port-channel the port is in.
    """
    if mode == "speed":
        return speed_class(port)
    if mode == "channel":
        faded = "" if port.up else " f-faded"
        if channel and channel in colours:
            return f"f-channel s{colours[channel]}{faded}", channel
        return "f-none", "Not in a port-channel"
    if mode == "traffic":
        if not port.up:
            return "f-none", "No link"
        busiest = max(port.in_bits_per_second, port.out_bits_per_second)
        share = busiest / port.bandwidth_bits if port.bandwidth_bits else 0.0
        if share >= 0.5:
            return "f-t3", "50 % of the link or more"
        if share >= 0.1:
            return "f-t2", "10 to 50 %"
        if share >= 0.01:
            return "f-t1", "1 to 10 %"
        return "f-t0", "Up, under 1 % of the link"
    if mode == "errors":
        if port.errors:
            return "f-err", "Errors or discards counted"
        if port.up:
            return "f-clean", "Up, no errors"
        return "f-none", "No link, no errors"
    if mode == "vlan":
        faded = "" if port.up else " f-faded"
        if port.vlan == "trunk":
            return "f-trunk" + faded, "Trunk (several VLANs)"
        if port.vlan == "routed":
            return "f-routed" + faded, "Routed port (no VLAN)"
        if port.vlan in colours:
            name = (vlan_names or {}).get(int(port.vlan), "")
            words = f"VLAN {port.vlan}" + (f" {name}" if name else "")
            return f"f-vlan s{colours[port.vlan]}{faded}", words
        return "f-none" + faded, "No VLAN"
    if port.up:
        return "f-up", "Up"
    if not port.admin_up:
        return "f-off", "Turned off"
    if port.transceiver.present:
        return "f-down", "Down: something is plugged in, no link"
    return "f-empty", "Empty: nothing plugged in"


def tooltip(
    port: Port,
    label: str = "",
    vlan_names: Mapping[int, str] | None = None,
    devices: PortDevices | None = None,
) -> str:
    """What hovering over a port shows, one fact per line."""
    lines = [f"{port.name} — {label}" if label else port.name]
    if port.up:
        lines.append(f"Up, {port.speed}")
    elif not port.admin_up:
        lines.append("Turned off")
    else:
        lines.append(f"Down: {port.reason}" if port.reason else "Down")
    if port.vlan == "trunk":
        lines.append("Trunk (several VLANs)")
    elif port.vlan == "routed":
        lines.append("Routed port")
    elif port.vlan.isdigit():
        name = (vlan_names or {}).get(int(port.vlan), "")
        lines.append(f"VLAN {port.vlan}" + (f" ({name})" if name else ""))
    if port.description:
        lines.append(f"Description: {port.description}")
    if port.transceiver.present:
        lines.append(f"Transceiver: {port.transceiver.type or 'present'}")
    else:
        lines.append("Nothing plugged in")
    if port.up:
        lines.append(
            f"In {human_rate(port.in_bits_per_second)}, out {human_rate(port.out_bits_per_second)}"
        )
    if port.errors:
        lines.append(f"Errors and discards: {port.errors:,}")
    if devices is not None:
        lines.extend(device_lines(devices))
    return "\n".join(lines)


# How many learned addresses a tooltip names before it only counts the rest.
_TOOLTIP_DEVICES = 3


def device_lines(devices: PortDevices) -> list[str]:
    """The tooltip lines for what is plugged into a port: neighbors, then learned addresses."""
    lines = []
    for neighbor in devices.neighbors:
        line = f"{neighbor.protocol} neighbor: {neighbor.name}"
        if neighbor.remote_port:
            line += f", its port {neighbor.remote_port}"
        lines.append(line)
    if devices.channel:
        lines.append(f"Part of {devices.channel.name}")
    seen: dict[str, str] = {}
    for entry in devices.macs:
        if not entry.switch_own and entry.mac not in seen:
            seen[entry.mac] = entry.maker or ("locally administered" if entry.local else "")
    if seen:
        where = f" on {devices.channel.name}" if devices.channel else ""
        lines.append(f"Devices learned{where}: {len(seen)}")
        for mac, maker in list(seen.items())[:_TOOLTIP_DEVICES]:
            lines.append(f"  {mac} ({maker})" if maker else f"  {mac}")
        if len(seen) > _TOOLTIP_DEVICES:
            lines.append(f"  and {len(seen) - _TOOLTIP_DEVICES} more")
    return lines


def short_device_name(name: str) -> str:
    """A neighbor's name without its domain or CDP serial.

    "esx-01.lab.example(FOX1)" -> "esx-01".
    """
    return name.split("(", 1)[0].split(".", 1)[0].strip()


def _fit(text: str, room: float) -> str:
    """``text`` cut to fit ``room`` picture units, with an ellipsis when cut."""
    most = max(1, int(room // _CHAR))
    return text if len(text) <= most else text[: most - 1] + "…"


def detail_link(name: str) -> str:
    """A port's own page."""
    return "/ports/detail?name=" + quote(name, safe="/")


def draw_face(
    ports: Sequence[Port],
    mode: str,
    labels: Mapping[str, str] | None = None,
    vlan_names: Mapping[int, str] | None = None,
    neighbors: NeighborView | None = None,
    *,
    model: str = "",
    link: Callable[[str], str] = detail_link,
    selected: str = "",
) -> Face:
    """The front panel as SVG, plus a legend of the colours it uses with their counts.

    With ``neighbors``, each port's tooltip also says what is plugged into it
    and the device's name is written next to the port. ``model`` is written at
    the left; ``link`` gives each port's address; the ``selected`` port is
    outlined.
    """
    labels = labels or {}
    mode = color_mode(mode)
    colours = channel_colours(neighbors) if mode == "channel" else vlan_colours(ports)
    left = _PAD + (_BADGE if model else 0)
    cages, width, height = panel_layout(ports, left)
    counts: dict[tuple[str, str], int] = {}
    parts = [
        f'<svg class="face" viewBox="0 0 {width:.0f} {height:.0f}" role="group" '
        f'aria-label="Front panel" xmlns="http://www.w3.org/2000/svg">',
        '<defs><pattern id="face-hatch" width="5" height="5" patternUnits="userSpaceOnUse" '
        'patternTransform="rotate(45)"><rect class="face-hatch-bg" width="5" height="5"/>'
        '<line class="face-hatch-line" x1="0" y1="0" x2="0" y2="5"/></pattern></defs>',
        f'<rect class="face-body" x="0.5" y="0.5" width="{width - 1:.0f}" '
        f'height="{height - 1:.0f}" rx="4"/>',
        f'<rect class="face-ear" x="3" y="{height / 2 - 14:.1f}" width="4" height="28" rx="1"/>',
        f'<rect class="face-ear" x="{width - 7:.0f}" y="{height / 2 - 14:.1f}" width="4" '
        f'height="28" rx="1"/>',
    ]
    if model:
        # "Nexus9000 C92160YC-X chassis" is written as "Nexus9000" over "C92160YC-X".
        lines = [
            (_fit(word, _BADGE - 12), "face-model")
            for word in model.removesuffix(" chassis").split(" ", 1)
        ]
        narrow = sum(1 for cage in cages if not cage.wide)
        wide = sum(1 for cage in cages if cage.wide)
        if narrow:
            lines.append((f"{narrow} × SFP", "face-sub"))
        if wide:
            lines.append((f"{wide} × QSFP", "face-sub"))
        y = height / 2 - (len(lines) - 1) * 6.5 + 3
        for words, css in lines:
            parts.append(
                f'<text class="{css}" x="{_PAD + 4}" y="{y:.1f}">{html.escape(words)}</text>'
            )
            y += 13
    pitch = {False: _SFP[2], True: _QSFP[2]}
    for cage in cages:
        first = cage.ports[0]
        devices = neighbors.for_port(first.name) if neighbors else None
        if devices and devices.neighbors:
            device = _fit(short_device_name(devices.neighbors[0].name), pitch[cage.wide] - 3)
            device_y = cage.y - 4 if cage.top else cage.y + cage.height + 10
            parts.append(
                f'<text class="face-device face-device-on" x="{cage.x + cage.width / 2:.1f}" '
                f'y="{device_y:.1f}" text-anchor="middle">{html.escape(device)}</text>'
            )
        slice_width = (cage.width - (len(cage.ports) - 1)) / len(cage.ports)
        for index, port in enumerate(cage.ports):
            channel_pc = neighbors.channel_of(port.name) if neighbors else None
            css, words = port_colour(
                port, mode, colours, vlan_names, channel_pc.name if channel_pc else ""
            )
            key = (css.replace(" f-faded", ""), words)
            counts[key] = counts.get(key, 0) + 1
            label = labels.get(port.name, "")
            port_devices = (
                devices if index == 0 else (neighbors.for_port(port.name) if neighbors else None)
            )
            x = cage.x + index * (slice_width + 1)
            classes = "face-port face-sel" if port.name == selected else "face-port"
            dim = css.startswith(("f-none", "f-empty", "f-off"))
            parts.append(
                f'<a class="{classes}" href="{html.escape(link(port.name))}">'
                f"<title>{html.escape(tooltip(port, label, vlan_names, port_devices))}</title>"
                f'<rect class="face-cell {css}" x="{x:.1f}" y="{cage.y:.1f}" '
                f'width="{slice_width:.1f}" height="{cage.height:.1f}" rx="2"/>'
            )
            light = "face-light face-light-on" if port.up else "face-light"
            if port.reason and "disabled" in port.reason.lower() and port.admin_up:
                light = "face-light face-light-err"
            parts.append(
                f'<rect class="{light}" x="{x + slice_width - 7:.1f}" y="{cage.y + 3:.1f}" '
                f'width="4.5" height="2.5" rx="0.6"/>'
            )
            if index == 0:
                number_class = "face-number face-number-dim" if dim else "face-number"
                parts.append(
                    f'<text class="{number_class}" x="{x + 3:.1f}" '
                    f'y="{cage.y + cage.height - 4:.1f}">{cage.number}</text>'
                )
            if label:
                parts.append(
                    f'<circle class="face-mark" cx="{x + 4:.1f}" cy="{cage.y + 4:.1f}" r="2"/>'
                )
            parts.append("</a>")
    parts.append("</svg>")
    legend = [LegendEntry(css, words, count) for (css, words), count in counts.items()]
    legend.sort(key=_legend_order)
    svg = Markup("".join(parts))  # noqa: S704 - every text above went through html.escape
    return Face(svg=svg, legend=legend)


_ORDER = (
    "f-up",
    "f-down",
    "f-empty",
    "f-off",
    "f-1g",
    "f-10g",
    "f-25g",
    "f-40g",
    "f-100g",
    "f-other",
    "f-t0",
    "f-t1",
    "f-t2",
    "f-t3",
    "f-clean",
    "f-err",
    "f-trunk",
    "f-routed",
    "f-none",
)


def _legend_order(entry: LegendEntry) -> tuple[int, int]:
    """Legend entries in a fixed order; VLANs and port-channels by number."""
    first = entry.css.split()[0]
    if first in ("f-vlan", "f-channel"):
        number = re.search(r"\d+", entry.label)
        return (len(_ORDER), int(number[0]) if number else 0)
    return (_ORDER.index(first) if first in _ORDER else len(_ORDER) + 1, 0)
