"""Changing several ports at once: one shared configuration for every ticked port.

The Ports page's "Change several ports" card is one form. Every setting in it
starts at "leave as it is" (an empty field); only the settings filled in are
checked and sent. Each ticked port is planned on its own, with the same
checks as its own page: ``plan_port_settings`` (app/port_settings.py),
``plan_port_vlans`` (app/vlans.py, with the trunk-must-carry-its-native-VLAN
rule), ``plan_port_discovery`` and ``plan_clear`` (app/neighbor_changes.py).
The commands are then built by the same ``NxapiClient`` methods, one port at
a time, so the role NXray's account is given already allows every one.

Not offered here, because each port needs its own: an IPv4 address on a
routed port (two ports cannot share one), the label, and splitting a 100G
port (the switch splits only some ports, and each split replaces the port).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from app.neighbor_changes import (
    ClearRequest,
    DiscoveryChange,
    PortDiscovery,
    describe_port_discovery,
    plan_clear,
    plan_port_discovery,
)
from app.neighbors import NeighborView
from app.nxapi import (
    FEC_MODES,
    ON_OFF,
    PORT_MODES,
    STORM_ACTIONS,
    STORM_TYPES,
    NxapiClient,
    parse_vlan_list,
    validate_description,
    validate_storm_level,
    validate_vlan_id,
)
from app.port_settings import (
    LAYERS,
    PortSettings,
    SettingsChange,
    describe_port_settings,
    plan_port_settings,
    settings_form,
)
from app.ports import Port
from app.vlans import PortVlanChange, PortVlans, VlanView, describe_port_vlans, plan_port_vlans

# The shared form's fields, by the kind of change they make. An empty value
# means "leave as it is".
POWER_FIELDS = ("power", "set_description", "description")
VLAN_FIELDS = ("mode", "access_vlan", "native_vlan", "allowed")
SETTINGS_FIELDS = (
    "layer",
    "speed",
    "mtu",
    "fec",
    "flow_receive",
    "flow_send",
    "storm_broadcast",
    "storm_multicast",
    "storm_unicast",
    "storm_action",
)
DISCOVERY_FIELDS = ("cdp", "lldp_transmit", "lldp_receive")
MAC_FIELDS = ("clear_macs",)
BULK_FIELDS = (*POWER_FIELDS, *VLAN_FIELDS, *SETTINGS_FIELDS, *DISCOVERY_FIELDS, *MAC_FIELDS)

# The speeds the shared form offers, in Mb/s. Each ticked port is checked
# against the speeds it can run at, as on its own page.
SPEED_CHOICES = ("auto", "100", "1000", "10000", "25000", "40000", "50000", "100000")

# What a storm-control box takes for "no limit"; an empty box leaves it alone.
NO_LIMIT_WORDS = ("none", "100", "100.0", "100.00")

# The VLAN settings a port gets from the switch when it goes back to switched
# (``switchport``): access mode in VLAN 1, a trunk carrying every VLAN.
DEFAULT_ACCESS_VLAN = 1


def empty_bulk_form() -> dict[str, str]:
    """The shared form with every setting at "leave as it is"."""
    return dict.fromkeys(BULK_FIELDS, "")


def bulk_kinds(form: dict[str, str]) -> set[str]:
    """Which kinds of change the form asks for: "port" (on/off, description),
    "vlans", "settings", "discovery" and "macs". Each needs its own switch
    on the Switch page."""
    kinds: set[str] = set()
    if form.get("power") or form.get("set_description"):
        kinds.add("port")
    if any(form.get(key) for key in VLAN_FIELDS):
        kinds.add("vlans")
    if any(form.get(key) for key in SETTINGS_FIELDS):
        kinds.add("settings")
    if any(form.get(key) for key in DISCOVERY_FIELDS):
        kinds.add("discovery")
    if form.get("clear_macs"):
        kinds.add("macs")
    return kinds


def check_bulk_form(form: dict[str, str]) -> dict[str, str]:
    """Check what does not depend on the port: the choices are ones the form
    offers, the description and numbers are valid, and the settings fit
    together. Returns the form cleaned up (spaces trimmed, the description
    as the switch keeps it). Raises ValueError with the reason.
    """
    clean = {key: str(form.get(key, "")).strip() for key in BULK_FIELDS}
    clean["description"] = str(form.get("description", ""))
    if not bulk_kinds(clean):
        raise ValueError("fill in at least one setting to change")
    if clean["power"] not in ("", *ON_OFF):
        raise ValueError("turn the ports on or off, or leave them as they are")
    if clean["set_description"] not in ("", "yes"):
        raise ValueError("tick the description box to change the description")
    if clean["set_description"]:
        clean["description"] = validate_description(clean["description"])
    else:
        clean["description"] = ""
    if clean["mode"] not in ("", *PORT_MODES):
        raise ValueError("pick access or trunk")
    for key, what in (("access_vlan", "access VLAN"), ("native_vlan", "native VLAN")):
        if clean[key]:
            try:
                clean[key] = str(validate_vlan_id(clean[key]))
            except ValueError as exc:
                raise ValueError(f"{exc} ({what})") from None
    if clean["allowed"]:
        parse_vlan_list(clean["allowed"])
    if clean["layer"] not in ("", *LAYERS):
        raise ValueError("pick switched (layer 2) or routed (layer 3)")
    if clean["layer"] == "routed" and any(clean[key] for key in VLAN_FIELDS):
        raise ValueError(
            "a routed port carries no VLANs; leave the VLAN settings as they are, "
            "or make the ports switched"
        )
    if clean["speed"] not in ("", *SPEED_CHOICES):
        raise ValueError("pick a speed from the list")
    if clean["fec"] not in ("", *FEC_MODES):
        raise ValueError("pick a FEC mode from the list")
    for key in ("flow_receive", "flow_send"):
        if clean[key] not in ("", *ON_OFF):
            raise ValueError("flow control is on or off")
    for kind in STORM_TYPES:
        key = f"storm_{kind}"
        typed = clean[key].rstrip("%").strip()
        if typed.lower() in NO_LIMIT_WORDS:
            clean[key] = "none"
        elif typed:
            clean[key] = validate_storm_level(typed)
    if clean["storm_action"] not in ("", "none", *STORM_ACTIONS):
        raise ValueError("storm-control action is none, shutdown or trap")
    for key in DISCOVERY_FIELDS:
        if clean[key] not in ("", *ON_OFF):
            raise ValueError("CDP and LLDP are on or off")
    if clean["clear_macs"] not in ("", "yes"):
        raise ValueError("tick the box to clear the learned addresses")
    return clean


def change_summary(port: Port, action: str, description: str) -> tuple[str, str | None]:
    """(what a change of one port's on/off or description does, in words; a
    warning for the confirm page or None). ``action`` is off, on or description."""
    if action == "off":
        warning = (
            "This port is up now: whatever is plugged into it loses its connection at once."
            if port.up
            else None
        )
        return f"Turn off {port.name}.", warning
    if action == "on":
        return f"Turn on {port.name}.", None
    before = port.description or "none"
    after = description or "none"
    return f'Change the description of {port.name} from "{before}" to "{after}".', None


@dataclass(frozen=True)
class BulkStep:
    """One request for one port: what it does, in words, and how it is sent."""

    what: str  # "port settings", "VLANs", ...
    lines: list[str]
    run: Callable[[NxapiClient], None]
    config: bool = True  # False for clearing learned addresses: nothing to save


@dataclass
class PortPlan:
    """What the shared form does to one ticked port."""

    port: Port
    settings_change: SettingsChange | None = None
    vlan_change: PortVlanChange | None = None
    discovery_change: DiscoveryChange | None = None
    description: str | None = None
    enabled: bool | None = None
    clear: ClearRequest | None = None
    steps: list[BulkStep] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.steps

    @property
    def lines(self) -> list[str]:
        return [line for step in self.steps for line in step.lines]

    @property
    def summary(self) -> str:
        """The port and everything that happens to it, on one line."""
        return f"{self.port.name}: " + " ".join(self.lines + self.notes)


def _settings_for_port(current: PortSettings, form: dict[str, str]) -> dict[str, str]:
    """The port's settings form with the shared form's filled-in values on top."""
    wanted = settings_form(current)
    for key in SETTINGS_FIELDS:
        value = form.get(key, "")
        if not value:
            continue
        wanted[key] = "" if value == "none" else value
    return wanted


def plan_port(
    port: Port,
    form: dict[str, str],
    *,
    view: VlanView | None,
    settings: PortSettings | None,
    discovery: PortDiscovery | None,
    neighbors: NeighborView | None,
    port_names: list[str],
) -> PortPlan:
    """Plan the checked shared form (see check_bulk_form) for one port.

    ``settings`` and ``discovery`` need only be read when the form changes
    them. Raises ValueError with the reason the port cannot be changed.
    """
    name = port.name
    kinds = bulk_kinds(form)
    plan = PortPlan(port)
    warnings: list[str] = []

    # Port settings first: a change of layer decides what the VLANs start from.
    vlans = view.ports.get(name) if view else None
    if "settings" in kinds:
        if settings is None:
            raise ValueError(f"the switch did not report the settings of {name}")
        change = plan_port_settings(settings, _settings_for_port(settings, form))
        layer = change.layer or settings.layer
        storm_asked = any(form.get(f"storm_{k}") for k in STORM_TYPES) or form.get("storm_action")
        if layer == "routed" and storm_asked:
            plan.notes.append(f"Storm control was left alone: {name} is routed.")
        if not change.empty:
            lines, found = describe_port_settings(settings, change, up=port.up)
            warnings += found
            plan.settings_change = change
            plan.steps.append(
                BulkStep(
                    "port settings",
                    lines,
                    lambda client, c=change, old=settings.storm_action: (
                        client.configure_port_settings(
                            name,
                            layer=c.layer,
                            remove_extra=c.remove_extra,
                            remove_ip=c.remove_ip,
                            ip_address=c.ip_address,
                            speed=c.speed,
                            mtu=c.mtu,
                            fec=c.fec,
                            flow_receive=c.flow_receive,
                            flow_send=c.flow_send,
                            storm_levels=c.storm_levels,
                            storm_action=c.storm_action,
                            old_storm_action=old,
                        )
                    ),
                )
            )
        if change.layer == "switched":
            # The port comes back with the switch's defaults.
            vlans = PortVlans(name, True, "access", DEFAULT_ACCESS_VLAN, DEFAULT_ACCESS_VLAN)

    if "vlans" in kinds:
        if view is None or vlans is None:
            raise ValueError(f"the switch reported no VLAN settings for {name}")
        mode = form.get("mode") or vlans.mode
        trunk_asked = form.get("native_vlan") or form.get("allowed")
        if mode == "access" and trunk_asked and not form.get("mode"):
            plan.notes.append(
                f"{name} is an access port, so the native VLAN and VLANs carried were left alone."
            )
        if mode == "trunk" and form.get("access_vlan") and not form.get("mode"):
            plan.notes.append(f"{name} is a trunk, so the access VLAN was left alone.")
        vlan_change = plan_port_vlans(
            vlans,
            view,
            mode=mode,
            access_vlan=form.get("access_vlan") or str(vlans.access_vlan),
            native_vlan=form.get("native_vlan") or str(vlans.native_vlan),
            allowed=form.get("allowed") or vlans.allowed_text,
        )
        if not vlan_change.empty:
            lines, found = describe_port_vlans(vlans, vlan_change)
            warnings += found
            plan.vlan_change = vlan_change
            plan.steps.append(
                BulkStep(
                    "VLANs",
                    lines,
                    lambda client, c=vlan_change: client.configure_port_vlans(
                        name,
                        mode=c.mode,
                        access_vlan=c.access_vlan,
                        native_vlan=c.native_vlan,
                        allowed_vlans=c.allowed_vlans,
                    ),
                )
            )

    if "discovery" in kinds:
        if discovery is None:
            raise ValueError(f"the switch did not report CDP on {name}")
        lldp_asked = bool(form.get("lldp_transmit") or form.get("lldp_receive"))
        if lldp_asked and not discovery.lldp_known:
            raise ValueError(f"the switch did not say what {name} does with LLDP")

        def wanted(key: str, now: bool | None) -> bool:
            value = form.get(key, "")
            return value == "on" if value else bool(now)

        discovery_change = plan_port_discovery(
            discovery,
            cdp=wanted("cdp", discovery.cdp),
            lldp_transmit=wanted("lldp_transmit", discovery.lldp_transmit),
            lldp_receive=wanted("lldp_receive", discovery.lldp_receive),
            lldp_shown=lldp_asked,
        )
        if not discovery_change.empty:
            lines, found = describe_port_discovery(name, discovery_change)
            warnings += found
            plan.discovery_change = discovery_change
            plan.steps.append(
                BulkStep(
                    "CDP and LLDP",
                    lines,
                    lambda client, c=discovery_change: client.set_port_discovery(
                        name, cdp=c.cdp, lldp_transmit=c.lldp_transmit, lldp_receive=c.lldp_receive
                    ),
                )
            )

    if "port" in kinds:
        lines = []
        if form.get("set_description") and form.get("description", "") != port.description:
            plan.description = form.get("description", "")
            lines.append(change_summary(port, "description", plan.description)[0])
        power = form.get("power", "")
        if power and (power == "on") != port.admin_up:
            plan.enabled = power == "on"
            line, warning = change_summary(port, power, "")
            lines.append(line)
            if warning:
                warnings.append(warning)
        if lines:
            plan.steps.append(
                BulkStep(
                    "description and on/off",
                    lines,
                    lambda client, d=plan.description, e=plan.enabled: client.configure_port(
                        name, description=d, enabled=e
                    ),
                )
            )

    if "macs" in kinds:
        if neighbors is None:
            raise ValueError("the switch did not give its MAC address table")
        clear, lines, found = plan_clear(neighbors, scope="port", ports=port_names, port=name)
        warnings += found
        plan.clear = clear
        plan.steps.append(
            BulkStep(
                "learned addresses",
                lines,
                lambda client, c=clear: client.clear_learned_macs(port=c.port),
                config=False,
            )
        )

    plan.warnings = warnings
    return plan


def plan_bulk(
    ports: list[Port],
    names: list[str],
    form: dict[str, str],
    *,
    view: VlanView | None,
    settings: dict[str, PortSettings | None],
    discovery: dict[str, PortDiscovery | None],
    neighbors: NeighborView | None,
) -> tuple[list[PortPlan], list[str]]:
    """Plan the checked shared form for every ticked port.

    Returns (the plans of the ports that change, in front-panel order; one
    line per ticked port already as asked). Raises ValueError naming every
    port that cannot be changed and why, so nothing is sent until each
    ticked port can take the whole form.
    """
    if not names:
        raise ValueError("tick at least one port")
    lldp_asked = form.get("lldp_transmit") or form.get("lldp_receive")
    if lldp_asked and neighbors is not None and not neighbors.lldp_enabled:
        raise ValueError(
            "LLDP is off for the whole switch; an NXray admin turns it on on the Features "
            "page first"
        )
    known = {port.name for port in ports}
    unknown = sorted(set(names) - known)
    if unknown:
        raise ValueError(f"the switch has no port called {', '.join(unknown)}")
    wanted = set(names)
    port_names = [port.name for port in ports]
    changing: list[PortPlan] = []
    already: list[str] = []
    refused: list[str] = []
    for port in ports:  # already in front-panel order
        if port.name not in wanted:
            continue
        try:
            plan = plan_port(
                port,
                form,
                view=view,
                settings=settings.get(port.name),
                discovery=discovery.get(port.name),
                neighbors=neighbors,
                port_names=port_names,
            )
        except ValueError as exc:
            refused.append(f"{port.name}: {exc}")
            continue
        if plan.empty:
            already.append(" ".join([f"{port.name} is already set as asked.", *plan.notes]))
        else:
            changing.append(plan)
    if refused:
        raise ValueError(
            "these ports cannot take this configuration (untick them or change the form): "
            + "; ".join(refused)
        )
    return changing, already


def group_warnings(plans: list[PortPlan]) -> list[str]:
    """Each warning once, naming the ports it is about, in the order first met."""
    ports_by_warning: dict[str, list[str]] = {}
    for plan in plans:
        for warning in plan.warnings:
            names = ports_by_warning.setdefault(warning, [])
            if plan.port.name not in names:
                names.append(plan.port.name)
    return [f"{', '.join(names)}: {warning}" for warning, names in ports_by_warning.items()]


def form_from_port(
    port: Port,
    settings: PortSettings | None,
    vlans: PortVlans | None,
    discovery: PortDiscovery | None,
) -> dict[str, str]:
    """The shared form filled with one port's VLANs, settings and CDP/LLDP, to
    copy a known-good port onto others ("Start from port").

    On/off, the description and clearing addresses stay at "leave as it is",
    and so does the speed of a port that is up: the switch then reports the
    speed it runs at, which may come from auto. A routed port's IPv4 address
    is never copied.
    """
    form = empty_bulk_form()
    if vlans is not None and vlans.switchport and vlans.mode in PORT_MODES:
        form["mode"] = vlans.mode
        if vlans.mode == "access":
            form["access_vlan"] = str(vlans.access_vlan)
        else:
            form["native_vlan"] = str(vlans.native_vlan)
            form["allowed"] = vlans.allowed_text
    if settings is not None:
        form["layer"] = settings.layer
        if not port.up and settings.speed in SPEED_CHOICES:
            form["speed"] = settings.speed
        form["mtu"] = str(settings.mtu)
        if settings.fec in FEC_MODES:
            form["fec"] = settings.fec
        form["flow_receive"] = settings.flow_receive if settings.flow_receive in ON_OFF else ""
        form["flow_send"] = settings.flow_send if settings.flow_send in ON_OFF else ""
        if not settings.routed:
            for kind in STORM_TYPES:
                form[f"storm_{kind}"] = settings.storm_field(kind) or "none"
            form["storm_action"] = settings.storm_action
    if discovery is not None:
        form["cdp"] = "on" if discovery.cdp else "off"
        if discovery.lldp_known:
            form["lldp_transmit"] = "on" if discovery.lldp_transmit else "off"
            form["lldp_receive"] = "on" if discovery.lldp_receive else "off"
    return form
