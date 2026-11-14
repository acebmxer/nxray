"""The commands a scheduler job or an EEM applet may run, as a fixed menu.

Both run switch commands later, on their own, so NXray never takes a typed command for
them (AGENTS.md: no way to send free text). Each menu entry is built from checked
values: a port from the switch's own list, a bootflash file name of plain characters,
a show command from ``SHOW_COMMANDS``. ``menu_lines`` turns one entry into the command
lines it stands for, in order; a scheduler job takes them as its lines, an EEM applet as
one ``action ... cli`` line each.

Tried on cisco-25gb (NX-OS 9.3(16), 2026-11-11): a job with ``configure terminal``,
``interface Ethernet1/54`` and ``shutdown`` keeps the three lines (they run only when
the job does), and a job with ``copy running-config bootflash:<file>`` made with the
admin login wrote the file when it ran. An account with NXray's broad role is refused
the copy to bootflash (its role permits only ``copy running-config startup-config``),
and ``clear counters`` the same way, so those two need the stored admin login.
"""

from __future__ import annotations

from typing import Any

from app.nxapi import validate_port_name
from app.protocols import table_rows
from app.switch import text

SAVE = "save the configuration"
BACKUP = "copy the configuration to a bootflash file"
PORT_OFF = "turn a port off"
PORT_ON = "turn a port on"
CLEAR = "clear a port's counters"
SHOW = "run a show command"
MENU = (SAVE, BACKUP, PORT_OFF, PORT_ON, CLEAR, SHOW)
# What the show entry may run: read-only, and short enough for a log.
SHOW_COMMANDS = (
    "show clock",
    "show version",
    "show environment",
    "show interface brief",
    "show interface counters errors",
    "show interface status err-disabled",
    "show logging last 100",
    "show mac address-table",
    "show ip route vrf all",
    "show running-config",
)


def menu_lines(entry: str, port: str = "", file: str = "", show: str = "") -> list[str]:
    """The command lines of one menu entry, from values already checked (the port's name,
    a bootflash file name, a show command of ``SHOW_COMMANDS``). ValueError names a value
    the entry needs and lacks."""
    if entry == SAVE:
        return ["copy running-config startup-config"]
    if entry == BACKUP:
        if not file:
            raise ValueError(f'"{entry}" needs the file name')
        return [f"copy running-config bootflash:{file}"]
    if entry in (PORT_OFF, PORT_ON, CLEAR):
        if not port:
            raise ValueError(f'"{entry}" needs the port')
        if entry == CLEAR:
            return [f"clear counters interface {port}"]
        return [
            "configure terminal",
            f"interface {port}",
            "shutdown" if entry == PORT_OFF else "no shutdown",
        ]
    if entry == SHOW:
        if show not in SHOW_COMMANDS:
            raise ValueError(f'"{entry}" needs the show command')
        return [show]
    raise ValueError(f"{entry!r} is not one of the commands offered")


def port_and_channel_names(brief: dict[str, Any]) -> list[str]:
    """Every front port and port-channel in ``show interface brief``, switched or routed."""
    names = []
    for row in table_rows(brief, "TABLE_interface", "ROW_interface"):
        name = text(row.get("interface"))
        if name.startswith("port-channel"):
            names.append(name)
            continue
        try:
            names.append(validate_port_name(name))
        except ValueError:
            continue
    return names
