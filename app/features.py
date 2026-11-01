"""The switch's features: which are on, what each does, and whether one may be turned off.

``show feature`` lists every feature NX-OS knows on this switch, some of them
once per routing-protocol instance (16 rows for ospf), with its name as the
switch keeps it internally (``sshServer``, ``hsrp_engine``). The command that
turns a feature on is not always that name (``feature ssh``, ``feature
hsrp``), so ``CATALOG`` maps each name to its command, a group for the page and
a plain description. The commands are the ones ``feature ?`` lists on an
N9K-C92160YC-X with NX-OS 9.3(16). A feature with no command there (a
switch-internal service, or one this model does not offer) is shown, but
NXray does not change it.

Turning a feature off removes every setting that belongs to it. NXray
refuses that while it can see something that uses the feature (an LACP
port-channel, a VLAN interface), and it never turns off what NXray itself
needs (NX-API, SSH).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.nxapi import FEATURE_COMMANDS, NxapiClient
from app.switch import rows

# The page's groups, in the order they are shown.
GROUPS = (
    "Routing and layer 3",
    "Gateway redundancy",
    "Multicast",
    "Layer 2",
    "VXLAN, MPLS and overlays",
    "Management and access",
    "Security",
    "Monitoring",
    "Programmability",
    "Other",
)


@dataclass(frozen=True)
class FeatureInfo:
    command: str | None  # what follows "feature"; None: NXray does not change it
    group: str
    description: str


def _info(command: str | None, group: str, description: str) -> FeatureInfo:
    return FeatureInfo(command, group, description)


R, G, M, L2, OV, A, S, MON, P, X = GROUPS

CATALOG: dict[str, FeatureInfo] = {
    # Routing and layer 3
    "bgp": _info(
        "bgp",
        R,
        "BGP: exchanges routes with other routers, usually between networks or with an "
        "internet provider.",
    ),
    "ospf": _info("ospf", R, "OSPF: shares IPv4 routes with the other routers in your network."),
    "ospfv3": _info(
        "ospfv3",
        R,
        "OSPFv3: shares IPv6 routes with the other routers in your network.",
    ),
    "eigrp": _info(
        "eigrp",
        R,
        "EIGRP: Cisco's routing protocol for sharing routes with other Cisco routers.",
    ),
    "isis": _info("isis", R, "IS-IS: a routing protocol used mostly in large provider networks."),
    "rip": _info("rip", R, "RIP: an old, simple routing protocol for small networks."),
    "bfd": _info(
        "bfd",
        R,
        "BFD: notices within milliseconds that a link to a neighbouring router died, so "
        "routing reacts fast.",
    ),
    "interface-vlan": _info(
        "interface-vlan",
        R,
        "VLAN interfaces: gives the switch an IP address in a VLAN, to route between VLANs or"
        " to manage the switch over the front ports.",
    ),
    "pbr": _info(
        "pbr",
        R,
        "Policy-based routing: sends chosen traffic along a path set by rules instead of the "
        "routing table.",
    ),
    "epbr": _info(
        "epbr",
        R,
        "Enhanced policy-based routing: steers traffic through service devices such as firewalls.",
    ),
    "itd": _info(
        "itd",
        R,
        "Intelligent Traffic Director: spreads traffic over a group of servers or appliances.",
    ),
    "nat": _info("nat", R, "NAT: rewrites the IP addresses of traffic passing through the switch."),
    "tunnel": _info("tunnel", R, "Tunnel interfaces: GRE and IP-in-IP tunnels to other routers."),
    "dhcp": _info(
        "dhcp",
        R,
        "DHCP relay and DHCP snooping: forwards address requests to a DHCP server in another "
        "network, and checks DHCP answers.",
    ),
    # Gateway redundancy
    "hsrp_engine": _info(
        "hsrp",
        G,
        "HSRP: two switches share one gateway address, so devices keep their gateway when one"
        " switch fails (Cisco).",
    ),
    "vrrp": _info(
        "vrrp",
        G,
        "VRRP: the standard way for two switches to share one gateway address (version 2, IPv4).",
    ),
    "vrrpv3": _info("vrrpv3", G, "VRRP version 3: a shared gateway address for IPv4 and IPv6."),
    # Multicast
    "pim": _info("pim", M, "PIM: routes IPv4 multicast traffic between networks."),
    "pim6": _info("pim6", M, "PIM for IPv6: routes IPv6 multicast traffic between networks."),
    "msdp": _info(
        "msdp",
        M,
        "MSDP: tells other multicast domains which multicast sources are active.",
    ),
    "nbm": _info(
        "nbm",
        M,
        "Non-blocking multicast: reserves bandwidth for media multicast streams.",
    ),
    "ngmvpn": _info("ngmvpn", M, "Multicast over VXLAN EVPN fabrics."),
    # Layer 2
    "lacp": _info(
        "lacp",
        L2,
        "LACP: bundles several ports into one port-channel that both ends agree on.",
    ),
    "lldp": _info(
        "lldp",
        L2,
        "LLDP: announces the switch to the device on each port and learns about it (the open "
        "standard beside Cisco's CDP).",
    ),
    "udld": _info(
        "udld",
        L2,
        "UDLD: finds a cable that carries traffic in one direction only and turns the port off.",
    ),
    "vpc": _info(
        "vpc",
        L2,
        "vPC: lets two switches act as one, so a server can have a port-channel to both.",
    ),
    "private-vlan": _info(
        "private-vlan",
        L2,
        "Private VLANs: keeps ports in the same VLAN from reaching each other.",
    ),
    "vtp": _info("vtp", L2, "VTP: shares the VLAN list between Cisco switches."),
    "Flexlink": _info(
        "flexlink",
        L2,
        "Flex Links: a backup port takes over when its main port fails, without spanning tree.",
    ),
    "evb": _info(
        "evb",
        L2,
        "Edge Virtual Bridging: lets a server's virtual switch hand its VMs' traffic to the "
        "switch.",
    ),
    "vmtracker": _info(
        "vmtracker",
        L2,
        "VM Tracker: learns from VMware vCenter which virtual machines sit behind which port.",
    ),
    "mvrp": _info(None, L2, "MVRP: shares VLANs between switches with a standard protocol."),
    # VXLAN, MPLS and overlays
    "nve": _info("nv overlay", OV, "VXLAN: carries VLANs across a routed network."),
    "vnseg_vlan": _info("vn-segment-vlan-based", OV, "Ties VLANs to VXLAN segments (VNIs)."),
    "hmm": _info(
        "fabric forwarding",
        OV,
        "Host mobility for VXLAN EVPN fabrics (the same gateway address on every switch).",
    ),
    "segment-routing": _info("mpls segment-routing", OV, "Segment routing over MPLS."),
    "tun_enc_mgr": _info("tunnel-encryption", OV, "Encrypts VXLAN tunnels between sites."),
    "ngoam": _info("ngoam", OV, "Ping and traceroute tools for VXLAN fabrics."),
    "l2vpn": _info(None, OV, "Layer 2 VPNs over MPLS."),
    "l3vpn": _info(None, OV, "Layer 3 VPNs over MPLS."),
    "ldp": _info(None, OV, "LDP: hands out MPLS labels between routers."),
    "mpls-evpn": _info(None, OV, "EVPN over MPLS."),
    "mpls_oam": _info(None, OV, "Ping and traceroute for MPLS."),
    "mpls_static": _info(None, OV, "Static MPLS labels."),
    "mvpn": _info(None, OV, "Multicast VPNs."),
    "srte": _info(None, OV, "Segment routing traffic engineering."),
    "srv6": _info(None, OV, "Segment routing over IPv6."),
    "vni": _info(None, OV, "VXLAN network identifiers (used by the VXLAN feature)."),
    "evc": _info(None, OV, "Ethernet virtual circuits."),
    # Management and access
    "nxapi": _info("nxapi", A, "NX-API: the web API NXray talks to the switch through."),
    "sshServer": _info("ssh", A, "SSH server: signing in to the switch's command line over SSH."),
    "telnetServer": _info(
        "telnet",
        A,
        "Telnet server: signing in to the command line without encryption.",
    ),
    "scpServer": _info(
        "scp-server",
        A,
        "SCP server: copying files to and from the switch over SSH.",
    ),
    "sftpServer": _info(
        "sftp-server",
        A,
        "SFTP server: copying files to and from the switch over SSH with SFTP.",
    ),
    "netconf": _info(
        "netconf",
        A,
        "NETCONF: reading and changing the configuration through a standard XML API.",
    ),
    "restconf": _info(
        "restconf",
        A,
        "RESTCONF: reading and changing the configuration through a standard REST API.",
    ),
    "grpc": _info("grpc", A, "gRPC: a model-based API and streaming telemetry over gRPC."),
    "bash-shell": _info(
        "bash-shell",
        A,
        "Bash shell: a Linux shell on the switch for network-admin accounts.",
    ),
    "scheduler": _info(
        "scheduler",
        A,
        "Scheduler: runs commands at set times, such as a nightly configuration backup.",
    ),
    "ptp": _info("ptp", A, "PTP: very precise time from a grandmaster clock over the network."),
    "license-smart": _info("license smart", A, "Smart Licensing: reports licence use to Cisco."),
    # Security
    "tacacs": _info("tacacs+", S, "TACACS+: sign-ins checked by a TACACS+ server."),
    "ldap": _info("ldap", S, "LDAP: sign-ins checked against an LDAP directory."),
    "dot1x": _info(
        "dot1x",
        S,
        "802.1X: a device must sign in before its port lets it on the network.",
    ),
    "eth-port-sec": _info(
        "port-security",
        S,
        "Port security: limits which device addresses a port accepts.",
    ),
    "macsec": _info(None, S, "MACsec: encrypts the traffic on a link."),
    "privilege": _info(None, S, "Privilege levels for switch accounts."),
    # Monitoring
    "sflow": _info(
        "sflow",
        MON,
        "sFlow: sends samples of the traffic to a collector, for traffic graphs.",
    ),
    "telemetry": _info("telemetry", MON, "Streaming telemetry: pushes switch data to a collector."),
    "analytics": _info("analytics", MON, "Flow analytics in the switch's hardware."),
    "sla_responder": _info(
        "sla responder",
        MON,
        "IP SLA responder: answers network-quality tests that another device sends.",
    ),
    "sla_sender": _info(
        "sla sender",
        MON,
        "IP SLA sender: measures delay and loss to other devices.",
    ),
    "sla_twamp": _info(
        "sla twamp-server",
        MON,
        "TWAMP server: answers standard two-way delay tests.",
    ),
    "evmed": _info(
        "evmed",
        MON,
        "Event detectors that let the Embedded Event Manager act when something happens.",
    ),
    "container-tracker": _info(
        "container-tracker",
        MON,
        "Container Tracker: learns about Kubernetes containers on connected servers.",
    ),
    "imp": _info("imp", MON, "IMP (the switch's own help gives no more than the name)."),
    "hardware-telemetry": _info(None, MON, "Telemetry from the switch's hardware."),
    "bulkstat": _info(None, MON, "Bulk statistics collection."),
    "icam": _info(
        None,
        MON,
        "iCAM: the switch's own monitor of its resources and traffic, kept on by NX-OS.",
    ),
    "bluez": _info(None, X, "Bluetooth support, for a Bluetooth console on some Nexus models."),
    "cable-management": _info(None, X, "Checks the cabling against a cable plan."),
    "catena": _info(None, X, "Catena: chains traffic through a series of service devices."),
    "enm": _info(None, X, "A switch-internal service; the switch gives no description."),
    "fabric-access": _info(None, X, "A switch-internal service; the switch gives no description."),
    "fport-channel-trunk": _info(None, X, "Fibre Channel port-channel trunking."),
    "fsync_mgr": _info(None, X, "Frequency synchronisation (SyncE)."),
    "intersight": _info(None, X, "The connector for Cisco Intersight cloud management."),
    "license-smart-res": _info(
        None, X, "Smart Licensing reservation: licences without a link to Cisco."
    ),
    "npiv": _info(None, X, "NPIV: several Fibre Channel logins over one port."),
    "ofm": _info(None, X, "Overlay forwarding manager, used by VXLAN."),
    "plb": _info(None, X, "Pervasive load balancing across a fabric."),
    "poe": _info(None, X, "Power over Ethernet; this model has none."),
    "rise": _info(None, X, "RISE: ties load balancers to the switch as service modules."),
    "smart-channel": _info(
        None, X, "Smart Channel: spreads traffic over service appliances in hardware."
    ),
    "vmfex": _info(None, X, "VM-FEX: extends the switch to virtual machines' network cards."),
    # Programmability
    "nxsdk_mgr": _info("nxsdk", P, "NX-SDK: runs your own apps on the switch."),
    "openflow": _info("openflow", P, "OpenFlow agent: lets an SDN controller program the switch."),
    "onep": _info(None, P, "onePK, Cisco's older programming kit."),
}

# NX-SDK app slots: shown as one line, not 32.
NXSDK_APP = re.compile(r"^nxsdk_app\d+$")
NXSDK_APPS_NAME = "nxsdk_app1-32"

# Features NXray never turns off, and why.
KEEP_ON = {
    "nxapi": "NXray talks to the switch through NX-API; turning it off cuts NXray off.",
    "sshServer": (
        "NXray signs in over SSH to update its role, and SSH is how an admin signs in "
        "to the switch; turn it off on the switch itself if you mean to."
    ),
}

# Extra words on the confirm page for turning these on.
ON_WARNINGS = {
    "telnetServer": "Telnet sends passwords unencrypted. SSH does the same job safely.",
    "bash-shell": "Every network-admin account gets a full Linux shell on the switch.",
    "lldp": (
        "The switch starts announcing itself on every port and learning about the devices there."
    ),
    "udld": "A port where UDLD finds a one-way cable is turned off.",
    "dot1x": "Nothing changes until ports are set up for 802.1X, but then devices must sign in.",
}

OFF_WARNING = (
    "Turning a feature off deletes all of its settings from the switch's running "
    "configuration. NXray cannot read the running configuration with its account, so "
    "it cannot list everything that goes."
)


@dataclass(frozen=True)
class Feature:
    name: str  # as show feature names it
    command: str | None
    group: str
    description: str
    enabled: bool
    # Things on the switch that use it (refuses turning it off).
    used_by: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        """What a person types: ``feature <label>``; the switch's name when there is none."""
        return self.command or self.name

    def refusal(self, turn_on: bool) -> str | None:
        """Why this feature may not be turned on (or off) from NXray; None if it may."""
        if self.command is None:
            return (
                f"{self.name} has no feature command on this switch: NX-OS manages it "
                "itself, or this model does not offer it."
            )
        if turn_on:
            return None
        if self.name in KEEP_ON:
            return KEEP_ON[self.name]
        if self.used_by:
            items = ", ".join(self.used_by)
            return (
                f"Not turned off: {items} still use{'s' if len(self.used_by) == 1 else ''} "
                f"{self.label}. Turning it off would delete "
                f"{'it' if len(self.used_by) == 1 else 'them'}; remove "
                f"{'it' if len(self.used_by) == 1 else 'them'} first."
            )
        return None


@dataclass(frozen=True)
class FeatureView:
    features: list[Feature] = field(default_factory=list)

    def get(self, name: str) -> Feature | None:
        return next((f for f in self.features if f.name == name), None)

    def grouped(self) -> list[tuple[str, list[Feature]]]:
        """(group, its features by name) for every group that has any, in GROUPS order."""
        found = []
        for group in GROUPS:
            members = sorted(
                (f for f in self.features if f.group == group), key=lambda f: f.label.lower()
            )
            if members:
                found.append((group, members))
        return found

    @property
    def enabled(self) -> list[Feature]:
        return sorted((f for f in self.features if f.enabled), key=lambda f: f.label.lower())


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def feature_states(body: dict[str, Any]) -> dict[str, bool]:
    """Every feature name in ``show feature`` and whether any instance of it is on."""
    states: dict[str, bool] = {}
    for row in rows(body, "TABLE_cfcFeatureCtrlTable", "ROW_cfcFeatureCtrlTable"):
        name = _text(row.get("cfcFeatureCtrlName2"))
        if not name:
            continue
        on = _text(row.get("cfcFeatureCtrlOpStatus2")).lower() == "enabled"
        states[name] = states.get(name, False) or on
    return states


def lacp_channels(channel_body: dict[str, Any]) -> list[str]:
    """Port-channels the switch runs with LACP, from ``show port-channel summary``."""
    found = []
    for row in rows(channel_body, "TABLE_channel", "ROW_channel"):
        if _text(row.get("prtcl")).upper() == "LACP":
            name = _text(row.get("port-channel")) or f"port-channel{_text(row.get('group'))}"
            members = [
                _text(member.get("port"))
                for member in rows(row, "TABLE_member", "ROW_member")
                if _text(member.get("port"))
            ]
            found.append(f"{name} ({', '.join(members)})" if members else name)
    return found


def vlan_interfaces(brief_body: dict[str, Any]) -> list[str]:
    """VLAN interfaces (``Vlan10``) in ``show interface brief``."""
    return [
        _text(row.get("interface"))
        for row in rows(brief_body, "TABLE_interface", "ROW_interface")
        if re.fullmatch(r"Vlan\d+", _text(row.get("interface")))
    ]


def parse_features(
    feature_body: dict[str, Any],
    channel_body: dict[str, Any],
    brief_body: dict[str, Any],
) -> FeatureView:
    """The Features page, from ``show feature``, ``show port-channel summary`` and
    ``show interface brief``."""
    states = feature_states(feature_body)
    used = {
        "lacp": tuple(lacp_channels(channel_body)),
        "interface-vlan": tuple(vlan_interfaces(brief_body)),
    }
    features: list[Feature] = []
    apps = [on for name, on in states.items() if NXSDK_APP.match(name)]
    for name, enabled in states.items():
        if NXSDK_APP.match(name):
            continue
        info = CATALOG.get(name) or FeatureInfo(None, X, "")
        command = info.command if info.command in FEATURE_COMMANDS else None
        feature = Feature(
            name=name,
            command=command,
            group=info.group,
            description=info.description,
            enabled=enabled,
            used_by=used.get(name, ()) if enabled else (),
        )
        features.append(feature)
    if apps:
        features.append(
            Feature(
                name=NXSDK_APPS_NAME,
                command=None,
                group=X,
                description=f"Slots for {len(apps)} NX-SDK apps; NX-SDK starts them itself.",
                enabled=any(apps),
            )
        )
    return FeatureView(features)


# One request: the feature list plus what NXray can see using a feature.
FEATURE_COMMANDS_TO_READ = ("show feature", "show port-channel summary", "show interface brief")


def load_features(client: NxapiClient) -> FeatureView:
    feature, channels, brief = client.show(*FEATURE_COMMANDS_TO_READ)
    return parse_features(feature, channels, brief)
