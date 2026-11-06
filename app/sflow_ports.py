"""Which VLAN a frame without a tag belongs to, for the sFlow collector.

A frame that comes in untagged (on an access port, or on a trunk's native VLAN)
has no VLAN in the sample the switch sends, only the SNMP ifIndex of the port it
came in on. So NXray reads each port's access or native VLAN, and the ifIndex
of each port, from the switch, and the collector counts those frames there.
"""

from __future__ import annotations

from typing import Any

from app.nxapi import NxapiClient
from app.switch import rows

PORT_VLAN_COMMANDS = ("show interface switchport", "show interface snmp-ifindex")


def parse_port_vlans(switchport: dict[str, Any], ifindex: dict[str, Any]) -> dict[int, int]:
    """SNMP ifIndex -> the VLAN a frame without a tag belongs to, for every
    switched port and port-channel: an access port's VLAN, a trunk's native VLAN.

    Routed ports and anything else have no entry. ``switchport`` and ``ifindex``
    are the bodies of ``show interface switchport`` and ``show interface
    snmp-ifindex``.
    """
    index_of: dict[str, int] = {}
    for row in rows(ifindex, "TABLE_interface", "ROW_interface"):
        try:
            index_of[str(row["interface"]).strip()] = int(str(row["snmp-ifindex"]).strip())
        except (KeyError, ValueError):
            continue
    found: dict[int, int] = {}
    for row in rows(switchport, "TABLE_interface", "ROW_interface"):
        name = str(row.get("interface", "")).strip()
        if name not in index_of or str(row.get("switchport", "")).strip().lower() != "enabled":
            continue
        mode = str(row.get("oper_mode", "")).strip().lower()
        key = {"access": "access_vlan", "trunk": "native_vlan"}.get(mode)
        try:
            vlan = int(str(row.get(key, "")).strip()) if key else 0
        except ValueError:
            continue
        if 0 < vlan <= 4094:
            found[index_of[name]] = vlan
    return found


def load_port_vlans(client: NxapiClient) -> dict[int, int]:
    """``parse_port_vlans`` over what the switch says now, in one request."""
    switchport, ifindex = client.show(*PORT_VLAN_COMMANDS)
    return parse_port_vlans(switchport, ifindex)
