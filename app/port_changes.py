"""Turning on port changes: give NXray's switch account a role that allows them.

The role allows exactly these: on the front-panel Ethernet ports only,
turning a port on or off, setting or removing its description, setting its
mode (access or trunk) and VLANs, and its settings (speed, MTU, FEC, flow
control, storm control, switched or routed with an IPv4 address),
turning CDP and LLDP on or off on them, and putting them into port-channels
and taking them out again, with their LACP rate and priority, and their IPv4
and IPv6 addresses when routed; on the port-channels, the same settings plus
their description and LACP minimum links, and deleting them; on the VLAN
interfaces, making and deleting them, their addresses, description, MTU and
on/off; the VRFs, making and deleting them and moving VLAN interfaces and
routed ports between them, and their static routes; the routing protocols
(OSPF, OSPFv3, BGP, EIGRP, RIP, IS-IS, HSRP, VRRP, VRRPv3, PIM, PIM6, IGMP,
MSDP, BFD), their settings on those interfaces, and the route-maps,
prefix-lists and key chains they use; switch-wide, creating,
naming and deleting VLANs, splitting a 100G port into four and joining it
again, turning switch features on and off, setting how long learned MAC addresses are kept,
adding and removing static MAC addresses, clearing learned ones, and the
switch's LACP priority; spanning tree; the switch admin settings (hostname,
banner, clock and NTP, DNS, logging, SNMP contact, location, read-only
communities and trap receivers) and reading the running configuration; IPv4
and IPv6 ACLs and where they apply, port security on the ports, reading the
saved configuration and making and deleting checkpoints; DHCP snooping, the
DHCP relay, ARP inspection, IP Source Guard, MAC ACLs, object groups, VLAN
access maps and the TCAM regions' sizes; how long the front ports average
their traffic rates over, and sFlow (where the samples go, how often, and from
which ports); resetting a port or a port-channel to its defaults
(``default interface``); and saving the configuration.
Everything else (mgmt0, a VLAN's own on/off state, accounts, SNMP users and
read-write communities, rolling the switch back, reloading it, other
switch-wide settings) stays refused by the switch itself, not just by NXray.

NX-API refuses the ";" these rules need, so the role is typed over SSH with
the admin login entered on the Switch page (``app/switch_ssh.py``). Checks
and saving go through NX-API. The admin login is used only inside
``enable_port_changes`` and never stored.

The role is named ``nxray-ports`` and is the same for every NXray install on
a switch, so a second install turning port changes on rewrites it with the
same rules.

NX-OS caches an account's roles in its NX-API session, which ends after
NX-API's idle timeout (``show nxapi``, 10 minutes by default). Until then the
account keeps its old permissions, so NXray stops calling the switch for that
long plus a minute. New rules in a role the account already has apply at
once, so an account that already had the role (port changes turned on
before VLAN changes existed) needs no wait. Both were measured on an
N9K-C92160YC-X with NX-OS 9.3(16).

When the role gains the port-channels (``CHANNEL_PERMIT``) or the VLAN
interfaces (``VLAN_INTERFACE_PERMIT``), NXray checks the role and saves the
configuration over SSH instead of over NX-API: on that switch NX-API stopped
answering every account for 10 to 15 minutes right after such a line was
typed (once for the port-channels, once for the VLAN interfaces), while SSH
kept working. The cause was not confirmed (a later port-channel change went
through with NX-API answering at once), so NXray adds no wait for it.

``ROLE_VERSION`` counts the rule sets: 1 had the port rules only, 2 added
the VLAN rules, 3 the port settings rules, 4 the feature rules, 5 the
neighbor rules (CDP, LLDP and the MAC address table), 6 the port-channel
rules and the port-channels in the role's port list, 7 the VLAN interface
rules and the VLAN interfaces in the port list, 8 the VRF rules, 9 the static route rules,
10 the routing protocol rules, 11 the spanning tree rules, 12 the switch
admin rules, 13 the security and config rules, 14 the layer 2 security rules,
15 the traffic measuring rules, 16 the reset rule, 17 the sFlow status rule, 18 the restart
rules, 19 the vPC rules, 20 the VXLAN rules and the NVE interface in the port list.

The switch knows the ``Vlan`` interface type only while the interface-vlan
feature is on: with it off, ``VLAN_INTERFACE_PERMIT`` is refused
("Invalid interface format"). So the port list names the VLAN interfaces only
when the feature is on; once an admin turns it on, Update the port list adds
them. NXray
stores the version it gave its account, so the
Switch page can offer the update when the code knows newer rules.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import httpx

from app.features import feature_states
from app.nxapi import (
    PORT_CHANGES_ROLE,
    VLAN_INTERFACE_MAX,
    NxapiClient,
    NxapiError,
    SwitchTarget,
    validate_account_name,
    validate_port_name,
)
from app.switch import rows, to_int
from app.switch_connection import ROLE_BROAD, ROLE_LIMITED, ROLE_MODES, ROLE_STORED, SWITCH_TIMEOUT
from app.switch_setup import SetupError, account_names, describe_error, scrub_secrets
from app.switch_ssh import (
    ShellOpener,
    SshAuthError,
    SshCommandError,
    SshError,
    run_commands,
    run_config,
)

log = logging.getLogger("nxray.port_changes")

ROLE_NAME = PORT_CHANGES_ROLE

# How long one SSH step may stay silent before it counts as stuck.
SSH_TIMEOUT = 30.0

# Added to NX-API's idle timeout before NXray calls the switch again.
PAUSE_MARGIN_SECONDS = 60
DEFAULT_NXAPI_TIMEOUT_MINUTES = 10


# The role's command rules. "conf t ; interface * ; <cmd>" is how NX-OS
# names a command typed inside an interface's configuration; a rule without
# the "conf t ; interface *" part never matches there (checked on the switch).
ROLE_RULES = (
    "rule 1 permit command conf t ; interface * ; shutdown",
    "rule 2 permit command conf t ; interface * ; no shutdown",
    "rule 3 permit command conf t ; interface * ; description *",
    "rule 4 permit command conf t ; interface * ; no description",
    "rule 5 permit command copy running-config startup-config",
)

# VLAN rules, added in ROLE_VERSION 2. "conf t ; vlan * ; name *" also lets
# the account create a VLAN (entering a VLAN is allowed when a rule names a
# command inside it) but not shut one down or suspend it; a bare
# "conf t ; vlan *" would allow every VLAN setting. The "no switchport ..."
# forms are not needed: setting the default values back leaves a port's
# configuration as bare as removing them does (checked on the switch).
VLAN_RULES = (
    "rule 6 permit command conf t ; vlan * ; name *",
    "rule 7 permit command conf t ; no vlan *",
    "rule 8 permit command conf t ; interface * ; switchport mode *",
    "rule 9 permit command conf t ; interface * ; switchport access vlan *",
    "rule 10 permit command conf t ; interface * ; switchport trunk allowed vlan *",
    "rule 11 permit command conf t ; interface * ; switchport trunk native vlan *",
)

# Port settings rules, added in ROLE_VERSION 3. Each names one command
# with its value as "*", so the account can set these and nothing else
# inside a port. A storm-control level goes back to "no limit" by setting
# 100.00 (the switch's default), so only the action needs a "no" form. The
# breakout lines are typed outside any port: the role's port list does not
# cover them, so they are named on their own. The ports a split makes are not
# in the role's port list until it is updated (Switch page).
SETTINGS_RULES = (
    "rule 12 permit command conf t ; interface * ; speed *",
    "rule 13 permit command conf t ; interface * ; mtu *",
    "rule 14 permit command conf t ; interface * ; fec *",
    "rule 15 permit command conf t ; interface * ; flowcontrol receive *",
    "rule 16 permit command conf t ; interface * ; flowcontrol send *",
    "rule 17 permit command conf t ; interface * ; storm-control broadcast level *",
    "rule 18 permit command conf t ; interface * ; storm-control multicast level *",
    "rule 19 permit command conf t ; interface * ; storm-control unicast level *",
    "rule 20 permit command conf t ; interface * ; storm-control action *",
    "rule 21 permit command conf t ; interface * ; no storm-control action *",
    "rule 22 permit command conf t ; interface * ; switchport",
    "rule 23 permit command conf t ; interface * ; no switchport",
    "rule 24 permit command conf t ; interface * ; ip address *",
    "rule 25 permit command conf t ; interface * ; no ip address *",
    "rule 26 permit command conf t ; interface breakout module * port * map *",
    "rule 27 permit command conf t ; no interface breakout module * port * map *",
)

# Feature rules, added in ROLE_VERSION 4: "feature <name>" and "no feature
# <name>", typed in configuration mode. Proven on cisco-25gb (2026-10-30)
# with a throwaway account holding only these two rules: it turned the
# scheduler feature on and off over NX-API and was refused everything else.
# NXray itself never turns off NX-API or SSH (NxapiClient.set_feature).
FEATURE_RULES = (
    "rule 28 permit command conf t ; feature *",
    "rule 29 permit command conf t ; no feature *",
)

# Neighbor rules, added in ROLE_VERSION 5: CDP and LLDP per port, the MAC
# address aging time, static MAC addresses and clearing learned ones. Proven on
# cisco-25gb (2026-10-30) with a throwaway account holding the CDP, MAC table
# and clearing rules: each worked over NX-API on the one port its role named.
# The static entry's port is checked by NXray (NxapiClient.add_static_mac takes
# front ports only). The LLDP lines need the lldp feature on and were not
# tried on the switch. Clearing is not a configuration command, so its rule has
# no "conf t"; the bare form clears every learned address.
NEIGHBOR_RULES = (
    "rule 30 permit command conf t ; interface * ; cdp enable",
    "rule 31 permit command conf t ; interface * ; no cdp enable",
    "rule 32 permit command conf t ; interface * ; lldp transmit",
    "rule 33 permit command conf t ; interface * ; no lldp transmit",
    "rule 34 permit command conf t ; interface * ; lldp receive",
    "rule 35 permit command conf t ; interface * ; no lldp receive",
    "rule 36 permit command conf t ; mac address-table aging-time *",
    "rule 37 permit command conf t ; mac address-table static *",
    "rule 38 permit command conf t ; no mac address-table static *",
    "rule 39 permit command clear mac address-table dynamic",
    "rule 40 permit command clear mac address-table dynamic *",
)

# Port-channel rules, added in ROLE_VERSION 6, with every port-channel added
# to the role's port list (CHANNEL_PERMIT). Proven on cisco-25gb (2026-10-30)
# with a throwaway account on two unused ports: "channel-group" on a port
# creates the port-channel even without CHANNEL_PERMIT, but its description,
# minimum links and "no interface port-channel" are "Interface permission
# denied" until the role names port-channels, and that line is taken only
# inside "interface policy deny" (stored as one line). Naming port-channels
# also lets rules 1-27 act on them, as on the front ports. The switch-wide
# "lacp system-priority" line was not tried on the switch: it makes every
# LACP port-channel negotiate again.
CHANNEL_RULES = (
    "rule 41 permit command conf t ; interface * ; channel-group *",
    "rule 42 permit command conf t ; interface * ; no channel-group",
    "rule 43 permit command conf t ; interface * ; lacp rate *",
    "rule 44 permit command conf t ; interface * ; lacp port-priority *",
    "rule 45 permit command conf t ; interface * ; lacp min-links *",
    "rule 46 permit command conf t ; no interface port-channel *",
    "rule 47 permit command conf t ; lacp system-priority *",
)
CHANNEL_PERMIT = "permit interface port-channel1-4096"

# VLAN interface rules, added in ROLE_VERSION 7, with every VLAN interface added
# to the role's port list (VLAN_INTERFACE_PERMIT). Proven on cisco-25gb
# (2026-10-30) with a throwaway account: without the permit the switch refuses
# "interface vlan<n>"; with it, rules 1-4, 13, 24 and 25 act on VLAN interfaces
# (on/off, description, MTU, IPv4 addresses, secondary ones too), and the two
# IPv6 rules below put IPv6 addresses on them and on routed ports. Deleting one
# needs the rule written exactly as below: "no interface vlan *" and
# "no interface vlan*" never matched "no interface vlan3900", "no interface
# Vlan *" matched every way of typing it.
LAYER3_RULES = (
    "rule 48 permit command conf t ; interface * ; ipv6 address *",
    "rule 49 permit command conf t ; interface * ; no ipv6 address *",
    "rule 50 permit command conf t ; no interface Vlan *",
)
# One range, which the switch stores as one line per VLAN interface, so it stays
# small (see VLAN_INTERFACE_MAX).
VLAN_INTERFACE_PERMIT = f"permit interface Vlan1-{VLAN_INTERFACE_MAX}"

# VRF rules, added in ROLE_VERSION 8. Proven on cisco-25gb (2026-10-30) with a
# throwaway account: "vrf context <name>" made a VRF and "no vrf context"
# deleted it, and on a permitted port "vrf member" and "no vrf member" moved
# it into the VRF and out again. Entering a VRF's configuration (which makes
# it) is allowed when a rule names a command inside it, as with VLANs: rule 51
# is there for that. NXray sends no VRF description, since no show command
# its account may run lists one. The port list stays as it was, so this needs
# no SSH save and no wait.
VRF_RULES = (
    "rule 51 permit command conf t ; vrf context * ; description *",
    "rule 52 permit command conf t ; no vrf context *",
    "rule 53 permit command conf t ; interface * ; vrf member *",
    "rule 54 permit command conf t ; interface * ; no vrf member *",
)

# Static route rules, added in ROLE_VERSION 9: "ip route" and "ipv6 route" and
# their "no" forms, in the default VRF (typed in configuration mode) and in
# any other (typed inside "vrf context"). Proven on cisco-25gb (2026-10-30)
# with a throwaway account, all eight forms. The switch would also take them
# inside the management VRF; NXray itself never sends that
# (nxapi.validate_vrf_name refuses it).
ROUTE_RULES = (
    "rule 55 permit command conf t ; ip route *",
    "rule 56 permit command conf t ; no ip route *",
    "rule 57 permit command conf t ; ipv6 route *",
    "rule 58 permit command conf t ; no ipv6 route *",
    "rule 59 permit command conf t ; vrf context * ; ip route *",
    "rule 60 permit command conf t ; vrf context * ; no ip route *",
    "rule 61 permit command conf t ; vrf context * ; ipv6 route *",
    "rule 62 permit command conf t ; vrf context * ; no ipv6 route *",
)

# Routing protocol rules, added in ROLE_VERSION 10. Proven on cisco-25gb
# (2026-10-31) with a throwaway account on one unused port: a rule naming a
# configuration mode ("conf t ; router ospf *") covers every line inside it,
# however deep (a VRF, an address family, a neighbor and its address family,
# a route-map's match and set lines, a key chain's keys); the interface rules
# name the start of each protocol's lines, with "*" also in the middle
# ("ip * eigrp *" matched "ip passive-interface eigrp <tag>"). PIM and MSDP
# lines inside a VRF (rules 105-108) and the IPv6 EIGRP rules (99-100) were
# not tried on their own: they are the same shapes as the ones that were.
# The port list stays as it was, so this needs no SSH save and no wait.
PROTOCOL_RULES = (
    "rule 63 permit command conf t ; router ospf *",
    "rule 64 permit command conf t ; no router ospf *",
    "rule 65 permit command conf t ; router ospfv3 *",
    "rule 66 permit command conf t ; no router ospfv3 *",
    "rule 67 permit command conf t ; router bgp *",
    "rule 68 permit command conf t ; no router bgp *",
    "rule 69 permit command conf t ; router eigrp *",
    "rule 70 permit command conf t ; no router eigrp *",
    "rule 71 permit command conf t ; router rip *",
    "rule 72 permit command conf t ; no router rip *",
    "rule 73 permit command conf t ; router isis *",
    "rule 74 permit command conf t ; no router isis *",
    "rule 75 permit command conf t ; route-map *",
    "rule 76 permit command conf t ; no route-map *",
    "rule 77 permit command conf t ; ip prefix-list *",
    "rule 78 permit command conf t ; no ip prefix-list *",
    "rule 79 permit command conf t ; ipv6 prefix-list *",
    "rule 80 permit command conf t ; no ipv6 prefix-list *",
    "rule 81 permit command conf t ; key chain *",
    "rule 82 permit command conf t ; no key chain *",
    "rule 83 permit command conf t ; ip pim *",
    "rule 84 permit command conf t ; no ip pim *",
    "rule 85 permit command conf t ; ipv6 pim *",
    "rule 86 permit command conf t ; no ipv6 pim *",
    "rule 87 permit command conf t ; ip msdp *",
    "rule 88 permit command conf t ; no ip msdp *",
    "rule 89 permit command conf t ; bfd *",
    "rule 90 permit command conf t ; no bfd *",
    "rule 91 permit command conf t ; interface * ; ip router *",
    "rule 92 permit command conf t ; interface * ; no ip router *",
    "rule 93 permit command conf t ; interface * ; ipv6 router *",
    "rule 94 permit command conf t ; interface * ; no ipv6 router *",
    "rule 95 permit command conf t ; interface * ; ip ospf *",
    "rule 96 permit command conf t ; interface * ; no ip ospf *",
    "rule 97 permit command conf t ; interface * ; ospfv3 *",
    "rule 98 permit command conf t ; interface * ; no ospfv3 *",
    "rule 99 permit command conf t ; interface * ; ipv6 * eigrp *",
    "rule 100 permit command conf t ; interface * ; no ipv6 * eigrp *",
    "rule 101 permit command conf t ; interface * ; ip * eigrp *",
    "rule 102 permit command conf t ; interface * ; no ip * eigrp *",
    "rule 103 permit command conf t ; interface * ; ip rip *",
    "rule 104 permit command conf t ; interface * ; no ip rip *",
    "rule 105 permit command conf t ; vrf context * ; ip pim *",
    "rule 106 permit command conf t ; vrf context * ; no ip pim *",
    "rule 107 permit command conf t ; vrf context * ; ipv6 pim *",
    "rule 108 permit command conf t ; vrf context * ; no ipv6 pim *",
    "rule 109 permit command conf t ; vrf context * ; ip msdp *",
    "rule 110 permit command conf t ; vrf context * ; no ip msdp *",
    "rule 111 permit command conf t ; interface * ; ipv6 rip *",
    "rule 112 permit command conf t ; interface * ; no ipv6 rip *",
    "rule 113 permit command conf t ; interface * ; isis *",
    "rule 114 permit command conf t ; interface * ; no isis *",
    "rule 115 permit command conf t ; interface * ; hsrp *",
    "rule 116 permit command conf t ; interface * ; no hsrp *",
    "rule 117 permit command conf t ; interface * ; vrrp *",
    "rule 118 permit command conf t ; interface * ; no vrrp *",
    "rule 119 permit command conf t ; interface * ; vrrpv3 *",
    "rule 120 permit command conf t ; interface * ; no vrrpv3 *",
    "rule 121 permit command conf t ; interface * ; ip pim *",
    "rule 122 permit command conf t ; interface * ; no ip pim *",
    "rule 123 permit command conf t ; interface * ; ipv6 pim *",
    "rule 124 permit command conf t ; interface * ; no ipv6 pim *",
    "rule 125 permit command conf t ; interface * ; ip igmp *",
    "rule 126 permit command conf t ; interface * ; no ip igmp *",
    "rule 127 permit command conf t ; interface * ; bfd *",
    "rule 128 permit command conf t ; interface * ; no bfd *",
)

# Spanning tree rules, added in ROLE_VERSION 11. Proven on cisco-25gb
# (2026-10-31) with a throwaway account on one unused port and a throwaway
# VLAN: "conf t ; spanning-tree *" covers the per-VLAN lines and the MST
# region's submode lines (name, revision, instance), the interface rules every
# port line (port type, BPDU guard and filter, guard, cost, port priority,
# per-VLAN cost and priority, link type), each with its "no" form. The
# switch-wide lines (mode, path cost method, defaults, Bridge Assurance) are
# the same rule; they were not typed, since each changes every VLAN or port.
# Rules 133-134 let NXray read the spanning tree lines of the running
# configuration, which NX-API gives only as text (``NxapiClient.show_text``):
# the only place a down port's settings show. The port list stays as it was,
# so this needs no SSH save and no wait.
STP_RULES = (
    "rule 129 permit command conf t ; spanning-tree *",
    "rule 130 permit command conf t ; no spanning-tree *",
    "rule 131 permit command conf t ; interface * ; spanning-tree *",
    "rule 132 permit command conf t ; interface * ; no spanning-tree *",
    "rule 133 permit command show running-config spanning-tree",
    "rule 134 permit command show running-config spanning-tree *",
)

# Switch admin rules, added in ROLE_VERSION 12: the hostname, banner, clock,
# DNS, NTP, logging and SNMP lines of the Switch admin page, each with its
# "no" form, and reading the running configuration (as text, through
# ``NxapiClient.show_text``), the only place most of these settings show.
# SNMP is narrow on purpose: only read-only communities ("group
# network-operator") and trap receivers, never SNMP users or read-write
# communities, which would each be a way in to the whole switch. "clock set"
# changes no configuration, so its rule has no "conf t". Written after
# Cisco's NX-OS 9.3 guides and the shapes of the rules proven before (a "*" in
# the middle matches, as in rule 101); not yet tried on a switch. The port
# list stays as it was, so this needs no SSH save and no wait.
ADMIN_RULES = (
    "rule 135 permit command conf t ; hostname *",
    "rule 136 permit command conf t ; banner motd *",
    "rule 137 permit command conf t ; no banner motd",
    "rule 138 permit command conf t ; clock timezone *",
    "rule 139 permit command conf t ; no clock timezone",
    "rule 140 permit command conf t ; clock summer-time *",
    "rule 141 permit command conf t ; no clock summer-time",
    "rule 142 permit command clock set *",
    "rule 143 permit command conf t ; ntp server *",
    "rule 144 permit command conf t ; no ntp server *",
    "rule 145 permit command conf t ; ip domain-name *",
    "rule 146 permit command conf t ; no ip domain-name *",
    "rule 147 permit command conf t ; ip domain-lookup",
    "rule 148 permit command conf t ; no ip domain-lookup",
    "rule 149 permit command conf t ; ip name-server *",
    "rule 150 permit command conf t ; no ip name-server *",
    "rule 151 permit command conf t ; vrf context * ; no ip name-server *",
    "rule 152 permit command conf t ; logging server *",
    "rule 153 permit command conf t ; no logging server *",
    "rule 154 permit command conf t ; logging logfile messages *",
    "rule 155 permit command conf t ; logging console *",
    "rule 156 permit command conf t ; no logging console",
    "rule 157 permit command conf t ; logging monitor *",
    "rule 158 permit command conf t ; no logging monitor",
    "rule 159 permit command conf t ; logging timestamp *",
    "rule 160 permit command conf t ; snmp-server contact *",
    "rule 161 permit command conf t ; no snmp-server contact",
    "rule 162 permit command conf t ; snmp-server location *",
    "rule 163 permit command conf t ; no snmp-server location",
    "rule 164 permit command conf t ; snmp-server community * group network-operator",
    "rule 165 permit command conf t ; no snmp-server community *",
    "rule 166 permit command conf t ; snmp-server host * traps version 2c *",
    "rule 167 permit command conf t ; no snmp-server host * traps version 2c *",
    "rule 168 permit command conf t ; snmp-server host * use-vrf *",
    "rule 169 permit command conf t ; no snmp-server host * use-vrf *",
    "rule 170 permit command show running-config",
)

# Security and config rules, added in ROLE_VERSION 13: IPv4 and IPv6 ACLs (a
# rule naming the ACL's mode covers its entries, as rule 63 does a router's
# lines), applying them to interfaces (routed and VLAN interfaces with
# "ip access-group" and "ipv6 traffic-filter", switched ports with their "port"
# forms), port security on the ports, reading the saved configuration for the
# Config page's comparison, and making, listing and deleting checkpoints. NXray
# names its checkpoints nxray-<n> (nxapi.validate_checkpoint_name). Rolling back
# is left out on purpose: NXray rolls back with the switch admin login typed on
# the Config page, never with its own account. Written after Cisco's NX-OS 9.3
# Security and System Management Configuration Guides and the shapes of the
# rules proven before; not yet tried on a switch. The port list stays as it
# was, so this needs no SSH save and no wait.
SECURITY_RULES = (
    "rule 171 permit command conf t ; ip access-list *",
    "rule 172 permit command conf t ; no ip access-list *",
    "rule 173 permit command conf t ; ipv6 access-list *",
    "rule 174 permit command conf t ; no ipv6 access-list *",
    "rule 175 permit command conf t ; interface * ; ip access-group *",
    "rule 176 permit command conf t ; interface * ; no ip access-group *",
    "rule 177 permit command conf t ; interface * ; ip port access-group *",
    "rule 178 permit command conf t ; interface * ; no ip port access-group *",
    "rule 179 permit command conf t ; interface * ; ipv6 traffic-filter *",
    "rule 180 permit command conf t ; interface * ; no ipv6 traffic-filter *",
    "rule 181 permit command conf t ; interface * ; ipv6 port traffic-filter *",
    "rule 182 permit command conf t ; interface * ; no ipv6 port traffic-filter *",
    "rule 183 permit command conf t ; interface * ; switchport port-security",
    "rule 184 permit command conf t ; interface * ; switchport port-security *",
    "rule 185 permit command conf t ; interface * ; no switchport port-security",
    "rule 186 permit command conf t ; interface * ; no switchport port-security *",
    "rule 187 permit command show startup-config",
    "rule 188 permit command checkpoint *",
    "rule 189 permit command no checkpoint *",
    "rule 190 permit command show checkpoint *",
)

# Layer 2 security rules, added in ROLE_VERSION 14: DHCP snooping, the DHCP and
# DHCPv6 relay, dynamic ARP inspection and its ARP ACLs, IP Source Guard and its
# fixed bindings, switch-wide and on the ports and interfaces; MAC ACLs and MAC
# port ACLs; object groups; VLAN access maps and the VLAN filters that apply
# them; and the TCAM regions' sizes. A bare line ("ip dhcp snooping") gets its
# own rule next to the "*" one, as rules 183 and 184 do. Written after Cisco's
# NX-OS 9.3 Security Configuration Guide and the shapes of the rules proven
# before; not yet tried on a switch. The port list stays as it was, so this
# needs no SSH save and no wait.
LAYER2_RULES = (
    "rule 191 permit command conf t ; ip dhcp snooping",
    "rule 192 permit command conf t ; ip dhcp snooping *",
    "rule 193 permit command conf t ; no ip dhcp snooping",
    "rule 194 permit command conf t ; no ip dhcp snooping *",
    "rule 195 permit command conf t ; ip dhcp relay",
    "rule 196 permit command conf t ; ip dhcp relay *",
    "rule 197 permit command conf t ; no ip dhcp relay",
    "rule 198 permit command conf t ; no ip dhcp relay *",
    "rule 199 permit command conf t ; ipv6 dhcp relay",
    "rule 200 permit command conf t ; no ipv6 dhcp relay",
    "rule 201 permit command conf t ; interface * ; ip dhcp snooping *",
    "rule 202 permit command conf t ; interface * ; no ip dhcp snooping *",
    "rule 203 permit command conf t ; interface * ; ip dhcp relay address *",
    "rule 204 permit command conf t ; interface * ; no ip dhcp relay address *",
    "rule 205 permit command conf t ; interface * ; ipv6 dhcp relay address *",
    "rule 206 permit command conf t ; interface * ; no ipv6 dhcp relay address *",
    "rule 207 permit command conf t ; ip arp inspection *",
    "rule 208 permit command conf t ; no ip arp inspection *",
    "rule 209 permit command conf t ; interface * ; ip arp inspection trust",
    "rule 210 permit command conf t ; interface * ; no ip arp inspection trust",
    "rule 211 permit command conf t ; arp access-list *",
    "rule 212 permit command conf t ; no arp access-list *",
    "rule 213 permit command conf t ; ip source binding *",
    "rule 214 permit command conf t ; no ip source binding *",
    "rule 215 permit command conf t ; interface * ; ip verify source *",
    "rule 216 permit command conf t ; interface * ; no ip verify source *",
    "rule 217 permit command conf t ; mac access-list *",
    "rule 218 permit command conf t ; no mac access-list *",
    "rule 219 permit command conf t ; interface * ; mac port access-group *",
    "rule 220 permit command conf t ; interface * ; no mac port access-group *",
    "rule 221 permit command conf t ; object-group *",
    "rule 222 permit command conf t ; no object-group *",
    "rule 223 permit command conf t ; vlan access-map *",
    "rule 224 permit command conf t ; no vlan access-map *",
    "rule 225 permit command conf t ; vlan filter *",
    "rule 226 permit command conf t ; no vlan filter *",
    "rule 227 permit command conf t ; hardware access-list tcam region *",
)

# Traffic measuring rules, added in ROLE_VERSION 15: how long a port's In and
# Out rates are averaged over (``load-interval counter 1 <seconds>``, and its
# ``no`` form to go back to the default), and sFlow: where the switch sends its
# samples, how often it samples and which ports (``sflow ...`` and ``no sflow
# ...``, typed in configuration mode; the sflow feature itself is turned on with
# the feature rules). Written after Cisco's NX-OS 9.3 Interfaces and System
# Management Configuration Guides and the shapes of the rules proven before; not
# yet tried on a switch. The port list stays as it was, so this needs no SSH
# save and no wait.
TRAFFIC_RULES = (
    "rule 228 permit command conf t ; interface * ; load-interval *",
    "rule 229 permit command conf t ; interface * ; no load-interval *",
    "rule 230 permit command conf t ; sflow *",
    "rule 231 permit command conf t ; no sflow *",
)

# Reset rule, added in ROLE_VERSION 16: ``default interface <name>``, typed in
# configuration mode, outside any port's own lines (as the breakout lines in
# SETTINGS_RULES are). It covers a front-panel port or a port-channel, since
# both are named after "default interface" and the role already names every
# one of each in its port list. Written after Cisco's NX-OS 9.3 Interfaces
# Configuration Guide; not yet tried on a switch. The port list stays as it
# was, so this needs no SSH save and no wait.
RESET_RULES = ("rule 232 permit command conf t ; default interface *",)

# sFlow status rule, added in ROLE_VERSION 17: ``show sflow``, the only way to
# read the collector, sampling rate and sources (it has no structured form on
# NX-OS 9.3, so NXray reads its text). The ``sflow`` lines in TRAFFIC_RULES
# only configure; a role refuses every show command no rule names, so the
# Traffic page's sFlow card got "Permission denied for the role" without this.
# Proven on cisco-25gb (2026-11-02): with the rule, the Traffic page reads it.
# The port list stays as it was, so this needs no SSH save and no wait.
SFLOW_STATUS_RULES = ("rule 233 permit command show sflow",)

# Restart rules, added in ROLE_VERSION 18: ``terminal dont-ask`` (so ``reload``
# asks nothing) and ``reload``, sent by NXray over NX-API as two commands of
# one request. Before this, restarting needed the switch admin login typed
# each time. Written from the NX-OS command reference; not yet tried on a
# switch. The port list stays as it was, so this needs no SSH save and no wait.
RELOAD_RULES = (
    "rule 234 permit command terminal dont-ask",
    "rule 235 permit command reload",
)

# The broad role (issue #40): any configuration command, except what could hand
# NXray's account more access or take the switch away, and any show command, plus
# the few commands NXray types outside configuration mode. A rule with a higher
# number wins over a lower one that also matches (checked on the switch: with the
# permit as rule 1 and "rule 2 deny command conf t ; username *", "username ..."
# was refused; with the numbers the other way round it was not), so the denies
# sit right after rule 1 and every other permit after them. Numbers stay below
# 256, the most a role takes. Only the "username" deny has been tried on a
# switch; the others, and the "no" forms of all of them, follow it.
#
# EEM applets are denied too (rules 23 and 24, added later, so numbered after
# the rest). An applet's "action cli" lines run as the switch's admin, not as the
# account that made the applet: checked on a switch (NX-OS 9.3(16)), an applet
# made by an account with this role ran "username ..." and made an account. Both
# denies, and that "event manager environment" is refused with them, were checked
# there too. Scheduler jobs need no deny: a job runs as the account that made it,
# so the denies above still hold inside it (checked the same way).
_DENIED_CONFIG = ("username", "role", "aaa", "tacacs-server", "radius-server", "boot")
EEM_DENY_RULES = (
    "rule 23 deny command conf t ; event manager *",
    "rule 24 deny command conf t ; no event manager *",
)
# ITD's counters are turned on, off and cleared outside configuration mode, so "conf t
# ; *" does not cover them (rules 25 to 27, added in BROAD_ITD_VERSION). The lines were
# tried on cisco-25gb as admin; the rules were not (the fake switch stands in).
ITD_STATISTICS_RULES = (
    "rule 25 permit command itd statistics *",
    "rule 26 permit command no itd statistics *",
    "rule 27 permit command clear itd statistics *",
)
# NAT's translations and counters are cleared outside configuration mode too (rules 28 and
# 29, added in BROAD_NAT_VERSION). The lines were tried on cisco-25gb as admin; the rules
# were not (the fake switch stands in).
NAT_CLEAR_RULES = (
    "rule 28 permit command clear ip nat translation *",
    "rule 29 permit command clear ip nat statistics",
)
# ePBR's counters are cleared outside configuration mode as well (rule 30, added in
# BROAD_EPBR_VERSION); its ``epbr session`` is a configuration command, which "conf t ; *"
# covers. The line was tried on cisco-25gb as admin; the rule was not (the fake switch
# stands in).
EPBR_CLEAR_RULES = ("rule 30 permit command clear epbr statistics *",)
# IGMP snooping's learned groups, counters and tracked IGMPv3 hosts are cleared outside
# configuration mode, one VLAN at a time (rules 31 to 33, added in
# BROAD_SNOOPING_CLEAR_VERSION). The lines were tried on cisco-25gb as admin; the rules were
# not (the fake switch stands in).
SNOOPING_CLEAR_RULES = (
    "rule 31 permit command clear ip igmp snooping groups *",
    "rule 32 permit command clear ip igmp snooping statistics *",
    "rule 33 permit command clear ip igmp snooping explicit-tracking *",
)
# A VM Tracker connection is synced now with ``vmtracker connection <name> refresh``, typed
# outside configuration mode (rule 34, added in BROAD_VMTRACKER_VERSION; outside
# configuration mode that is the command's only form). The line was typed on cisco-25gb as
# admin, with no vCenter to sync from ("ERROR: failure"); the rule was not tried (the fake
# switch stands in).
VMTRACKER_REFRESH_RULES = ("rule 34 permit command vmtracker connection *",)
BROAD_RULES = (
    "rule 1 permit command conf t ; *",
    *(
        f"rule {number} deny command conf t ; {form}{word} *"
        for number, (form, word) in enumerate(
            ((form, word) for word in _DENIED_CONFIG for form in ("", "no ")), start=2
        )
    ),
    "rule 14 permit command show *",
    "rule 15 permit command copy running-config startup-config",
    "rule 16 permit command clear mac address-table dynamic",
    "rule 17 permit command clear mac address-table dynamic *",
    "rule 18 permit command clock set *",
    "rule 19 permit command checkpoint *",
    "rule 20 permit command no checkpoint *",
    "rule 21 permit command terminal dont-ask",
    "rule 22 permit command reload",
    *EEM_DENY_RULES,
    *ITD_STATISTICS_RULES,
    *NAT_CLEAR_RULES,
    *EPBR_CLEAR_RULES,
    *SNOOPING_CLEAR_RULES,
    *VMTRACKER_REFRESH_RULES,
)

# vPC rules, added in ROLE_VERSION 19: the vPC domain and every line inside it
# ("conf t ; vpc domain *" covers the submode, as the routing protocol rules do),
# ``vpc peer-link`` and ``vpc <number>`` on a port-channel, their "no" forms, and
# reading the vPC lines of the running configuration as text. Written after
# Cisco's NX-OS 9.3 Interfaces Configuration Guide; not yet tried on a switch (vPC
# is off on the switch in production). The port list stays as it was, so this needs
# no SSH save and no wait.
VPC_RULES = (
    "rule 236 permit command conf t ; vpc domain *",
    "rule 237 permit command conf t ; no vpc domain *",
    "rule 238 permit command conf t ; interface * ; vpc *",
    "rule 239 permit command conf t ; interface * ; no vpc *",
    "rule 240 permit command show running-config vpc",
    "rule 241 permit command show running-config vpc *",
)

# VXLAN and EVPN rules, added in ROLE_VERSION 20: the NVE interface and every line
# inside it (member VNIs too), the ``evpn`` block, a VLAN's ``vn-segment``, a VRF's
# ``vni`` and route-targets, the switch-wide ``nv overlay evpn`` and ``fabric
# forwarding`` lines and their "no" forms. Reading the lines needs no rule of its own: it is
# ``show running-config`` (rule 170). The lines themselves were tried on cisco-25gb
# (2026-11-10) as admin; the rules were not (the fake switch stands in).
# Entering ``interface nve1`` also needs NVE_PERMIT in the port list, which the
# switch is expected to take only while the nve feature is on, as with the VLAN
# interfaces.
VXLAN_RULES = (
    "rule 242 permit command conf t ; nv overlay evpn",
    "rule 243 permit command conf t ; no nv overlay evpn",
    "rule 244 permit command conf t ; fabric forwarding *",
    "rule 245 permit command conf t ; no fabric forwarding *",
    "rule 246 permit command conf t ; vlan * ; vn-segment *",
    "rule 247 permit command conf t ; vlan * ; no vn-segment *",
    "rule 248 permit command conf t ; interface nve*",
    "rule 249 permit command conf t ; no interface nve*",
    "rule 250 permit command conf t ; evpn*",
    "rule 251 permit command conf t ; vrf context * ; vni *",
    "rule 252 permit command conf t ; vrf context * ; no vni *",
    "rule 253 permit command conf t ; vrf context * ; address-family * ; route-target *",
    "rule 254 permit command conf t ; vrf context * ; address-family * ; no route-target *",
)
# The NVE interface (NX-OS 9.3 has one, nve1), in the port list like the VLAN interfaces.
NVE_PERMIT = "permit interface nve1"
# Every loopback, in the broad role's port list only (BROAD_LOOPBACK_VERSION). Checked on
# cisco-25gb (NX-OS 9.3(16)) with a throwaway role and account: the switch stores this
# range as one line (unlike the VLAN interfaces, which it writes one per line), takes it
# with no feature on, and with it lets the account make, change and delete the loopbacks
# it covers, refusing others ("% Interface permission denied"). The limited role has no
# rules for loopbacks, so its port list does not name them.
LOOPBACK_PERMIT = "permit interface loopback0-1023"

# Role versions whose port list gained a line, and so are checked and saved
# over SSH (see the module notes): accounts below this one get one.
LAST_PERMIT_VERSION = 7

ROLE_VERSION = 20

LIMITED_RULES = (
    *ROLE_RULES,
    *VLAN_RULES,
    *SETTINGS_RULES,
    *FEATURE_RULES,
    *NEIGHBOR_RULES,
    *CHANNEL_RULES,
    *LAYER3_RULES,
    *VRF_RULES,
    *ROUTE_RULES,
    *PROTOCOL_RULES,
    *STP_RULES,
    *ADMIN_RULES,
    *SECURITY_RULES,
    *LAYER2_RULES,
    *TRAFFIC_RULES,
    *RESET_RULES,
    *SFLOW_STATUS_RULES,
    *RELOAD_RULES,
    *VPC_RULES,
    *VXLAN_RULES,
)

# What each role mode says in the page's words.
ROLE_MODE_WORDS = {
    ROLE_LIMITED: "Limited role",
    ROLE_BROAD: "Broad role with a deny list",
    ROLE_STORED: "Limited role with the admin login stored",
}


def check_role_mode(mode: str) -> str:
    """``mode`` when it is one of the role modes; ValueError otherwise."""
    if mode not in ROLE_MODES:
        raise ValueError(f"unknown role mode {mode!r}")
    return mode


def rules_for_mode(mode: str) -> tuple[str, ...]:
    """The role's command rules in ``mode``: the broad set, or the listed rules
    (which the limited role and the stored-login role share)."""
    return BROAD_RULES if check_role_mode(mode) == ROLE_BROAD else LIMITED_RULES


def _rule_numbers(rules: tuple[str, ...]) -> list[int]:
    return [int(rule.split()[1]) for rule in rules]


# What each role version added, for the Switch page's button names.
_ADDED_BY_VERSION = {
    2: "VLAN",
    3: "port settings",
    4: "feature",
    5: "neighbor",
    6: "port-channel",
    7: "VLAN interface",
    8: "VRF",
    9: "static route",
    10: "routing protocol",
    11: "spanning tree",
    12: "switch admin",
    13: "security and config",
    14: "layer 2 security",
    15: "traffic measuring",
    16: "reset to defaults",
    17: "sFlow status",
    18: "switch restart",
    19: "vPC",
    20: "VXLAN",
}


def missing_changes(role_version: int) -> str:
    """The kinds of change a role of ``role_version`` lacks, in words.

    ``missing_changes(4)`` is "neighbor and port-channel changes"; "" when
    nothing is missing.
    """
    names = [name for version, name in _ADDED_BY_VERSION.items() if version > role_version]
    if not names:
        return ""
    if len(names) == 1:
        return f"{names[0]} changes"
    return f"{', '.join(names[:-1])} and {names[-1]} changes"


@dataclass(frozen=True)
class EnableResult:
    pause_seconds: int
    port_count: int
    config_saved: bool
    save_error: str | None
    # True when the account already had the role, so only its rules changed.
    had_role: bool = False
    # True when the role's port list names the VLAN interfaces (interface-vlan on).
    vlan_interfaces: bool = False
    # True when the role's port list names the NVE interface (the nve feature on).
    nve: bool = False


def front_ports(interface_brief_body: dict) -> list[str]:
    """Every front-panel Ethernet port name in ``show interface brief``."""
    names = []
    for row in rows(interface_brief_body, "TABLE_interface", "ROW_interface"):
        name = str(row.get("interface", ""))
        try:
            names.append(validate_port_name(name))
        except ValueError:
            continue
    return names


def role_lines(
    ports: list[str],
    account_name: str,
    vlan_interfaces: bool = True,
    mode: str = ROLE_LIMITED,
    previous_mode: str | None = None,
    nve: bool = False,
) -> list[str]:
    """The configuration lines that create the role and give it to the account.

    Typed after ``configure terminal``. Every value is checked first, so the
    lines can only ever be these. ``vlan_interfaces`` adds the VLAN interfaces
    to the port list; the switch refuses that line while interface-vlan is off.
    ``nve`` adds the NVE interface the same way, for the nve feature. The broad role's
    port list also names every loopback (``LOOPBACK_PERMIT``); a role leaving the broad
    mode has that line taken out again (checked on a switch: ``no permit interface
    loopback0-1023`` is taken).
    ``previous_mode`` is the mode the role was in (None for a new role): when its
    rules differ from ``mode``'s, they are all removed first, so the role keeps
    none the new mode lacks (a ``no rule`` for a rule that is not there is
    accepted by the switch).
    """
    validate_account_name(account_name)
    if not ports:
        raise ValueError("the switch reported no front-panel ports")
    rules = rules_for_mode(mode)
    if previous_mode is not None and rules_for_mode(previous_mode) != rules:
        cleared = [f"no rule {n}" for n in _rule_numbers(rules_for_mode(previous_mode))]
    else:
        cleared = []
    permits = [f"permit interface {validate_port_name(port)}" for port in ports]
    description = (
        "NXray: any configuration except accounts, roles, AAA, boot and EEM, on the listed ports"
        if mode == ROLE_BROAD
        # Kept short: NX-OS takes up to 128 characters here.
        else "NXray: ports, port-channels, VLANs, layer 3, STP, features, MAC, "
        "admin, ACLs, port security, DHCP, ARP, checkpoints, reset"
    )
    return [
        f"role name {ROLE_NAME}",
        f"description {description}",
        *cleared,
        *rules,
        "interface policy deny",
        *permits,
        CHANNEL_PERMIT,
        *([VLAN_INTERFACE_PERMIT] if vlan_interfaces else []),
        *([NVE_PERMIT] if nve else []),
        *([LOOPBACK_PERMIT] if mode == ROLE_BROAD else []),
        # Leaving the broad role: the limited rules would act on the loopbacks too.
        *(["no " + LOOPBACK_PERMIT] if previous_mode == ROLE_BROAD and mode != ROLE_BROAD else []),
        "exit",
        "exit",
        f"username {account_name} role {ROLE_NAME}",
    ]


def account_roles(user_account_body: dict, account_name: str) -> set[str]:
    """The roles ``show user-account`` lists for one account."""
    for row in rows(user_account_body, "TABLE_template", "ROW_template"):
        if str(row.get("usr_name", "")).lower() == account_name.lower():
            return {
                str(role.get("role", ""))
                for role in rows(row, "TABLE_role", "ROW_role")
                if role.get("role")
            }
    return set()


def pause_seconds(nxapi_body: dict) -> int:
    """NX-API's idle timeout from ``show nxapi``, in seconds, plus the margin."""
    minutes = to_int(nxapi_body.get("timeout")) or DEFAULT_NXAPI_TIMEOUT_MINUTES
    return max(minutes, 1) * 60 + PAUSE_MARGIN_SECONDS


SAVE_COMMAND = "copy running-config startup-config"


def _check_role_output(roles_output: str, account_name: str) -> None:
    """Stop unless ``show user-account <name>`` (typed over SSH) lists the role."""
    if not re.search(rf"(?<![\w-]){re.escape(ROLE_NAME)}(?![\w-])", roles_output):
        raise SetupError(
            f"The switch accepted the commands, but {account_name} does not have the "
            f"{ROLE_NAME} role. Nothing was saved."
        )


def _saved_over_ssh(
    ssh: dict,
    admin_password: str,
    port_count: int,
    had_role: bool,
    wait: int,
    vlans: bool,
    nve: bool = False,
) -> EnableResult:
    """Save the configuration over SSH, and the result."""
    try:
        (output,) = run_commands(lines=(SAVE_COMMAND,), **ssh)
    except SshError as exc:
        output = scrub_secrets(str(exc), admin_password)
    if "Copy complete" not in output:
        log.warning("switch config not saved after adding %s: %s", ROLE_NAME, output)
        return EnableResult(wait, port_count, False, output or "no answer", had_role, vlans, nve)
    log.info("saved the switch configuration over SSH")
    return EnableResult(wait, port_count, True, None, had_role, vlans, nve)


def enable_port_changes(
    *,
    host: str,
    nxapi_port: int,
    ssh_port: int,
    admin_user: str,
    admin_password: str,
    account_name: str,
    role_version: int = 0,
    vlan_interfaces_listed: bool = False,
    nve_listed: bool = False,
    mode: str = ROLE_LIMITED,
    previous_mode: str | None = None,
    transport: httpx.BaseTransport | None = None,
    ssh_opener: ShellOpener | None = None,
) -> EnableResult:
    """Create the role over SSH, give it to NXray's account, check it, save the config.

    ``role_version`` is the version NXray gave its account before (0 for
    none). Below ``LAST_PERMIT_VERSION`` the role's port list gains a line,
    and so does it when interface-vlan is on and ``vlan_interfaces_listed``
    (the port list names the VLAN interfaces already) is false, or the nve feature is
    on and ``nve_listed`` (the port list names the NVE interface already) is false; then the
    check and the save go over SSH, which does not depend on NX-API answering.
    ``mode`` is the role mode to write and ``previous_mode`` the one the role
    has now (None for no role yet); see ``role_lines``.
    Raises SetupError with a message for the page when it stops.
    """
    admin = SwitchTarget(
        host=host,
        port=nxapi_port,
        username=admin_user,
        password=admin_password,
        timeout=SWITCH_TIMEOUT,
    )
    with NxapiClient(admin, transport=transport) as client:
        try:
            brief, users, nxapi, features = client.show(
                "show interface brief", "show user-account", "show nxapi", "show feature"
            )
        except NxapiError as exc:
            raise SetupError(
                scrub_secrets(describe_error(exc, host, nxapi_port, "admin"), admin_password)
            ) from exc
        if account_name.lower() not in account_names(users):
            raise SetupError(
                f"NXray's account {account_name} is no longer on the switch. Press Run "
                "setup again on the Switch page: it makes the account again."
            )
        had_role = ROLE_NAME in account_roles(users, account_name)
        ports = front_ports(brief)
        vlans = feature_states(features).get("interface-vlan", False)
        nve = feature_states(features).get("nve", False)
        lines = role_lines(
            ports,
            account_name,
            vlan_interfaces=vlans,
            mode=mode,
            previous_mode=previous_mode,
            nve=nve,
        )
        over_ssh = (
            role_version < LAST_PERMIT_VERSION
            or (vlans and not vlan_interfaces_listed)
            or (nve and not nve_listed)
        )
        then = (f"show user-account {account_name}",) if over_ssh else ()

        try:
            outputs = run_config(
                host=host,
                port=ssh_port,
                username=admin_user,
                password=admin_password,
                lines=lines,
                timeout=SSH_TIMEOUT,
                opener=ssh_opener,
                then=then,
            )
        except SshAuthError as exc:
            raise SetupError("The switch refused the admin username or password over SSH.") from exc
        except SshCommandError as exc:
            raise SetupError(
                scrub_secrets(
                    f"The switch refused a line while creating the role: {exc}", admin_password
                )
            ) from exc
        except SshError as exc:
            raise SetupError(
                scrub_secrets(
                    f"NXray could not reach the switch over SSH at {host}, port {ssh_port}. "
                    "Check that SSH is on and that this machine can reach it. "
                    f"Details: {exc}",
                    admin_password,
                )
            ) from exc
        log.info(
            "%s switch account %s the %s role (version %d) on %s",
            "updated" if had_role else "gave",
            account_name,
            ROLE_NAME,
            ROLE_VERSION,
            host,
        )
        # Rules added to a role the account already has apply at once.
        wait = 0 if had_role else pause_seconds(nxapi)
        if over_ssh:
            _check_role_output(outputs[0], account_name)
            ssh = {
                "host": host,
                "port": ssh_port,
                "username": admin_user,
                "password": admin_password,
                "timeout": SSH_TIMEOUT,
                "opener": ssh_opener,
            }
            return _saved_over_ssh(ssh, admin_password, len(ports), had_role, wait, vlans, nve)

        try:
            (users,) = client.show("show user-account")
        except NxapiError as exc:
            raise SetupError(
                scrub_secrets(describe_error(exc, host, nxapi_port, "admin"), admin_password)
            ) from exc
        if ROLE_NAME not in account_roles(users, account_name):
            raise SetupError(
                f"The switch accepted the commands, but {account_name} does not have the "
                f"{ROLE_NAME} role. Nothing was saved."
            )

        try:
            client.save_config()
        except NxapiError as exc:
            log.warning("switch config not saved after adding %s: %s", ROLE_NAME, exc)
            return EnableResult(
                wait,
                len(ports),
                False,
                scrub_secrets(str(exc), admin_password),
                had_role,
                vlans,
                nve,
            )

    log.info("saved the switch configuration on %s", host)
    return EnableResult(wait, len(ports), True, None, had_role, vlans, nve)
