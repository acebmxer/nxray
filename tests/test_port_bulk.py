"""The shared configuration for several ports (app/port_bulk.py), without a switch."""

from __future__ import annotations

from dataclasses import replace

import pytest

from app.neighbor_changes import PortDiscovery
from app.port_bulk import (
    BULK_FIELDS,
    bulk_kinds,
    check_bulk_form,
    empty_bulk_form,
    form_from_port,
    group_warnings,
    plan_port,
)
from app.port_settings import PortSettings, settings_form
from app.ports import Port, Transceiver
from app.vlans import PortVlans, Vlan, VlanView

PORT = Port(
    name="Ethernet1/3",
    description="",
    up=False,
    admin_up=True,
    reason="",
    speed="auto",
    vlan="1",
    mode="access",
    mtu="1500",
    hardware="",
    mac="",
    last_flap="",
    transceiver=Transceiver(present=False),
    in_bits_per_second=0,
    out_bits_per_second=0,
    in_bytes=0,
    out_bytes=0,
    in_packets=0,
    out_packets=0,
)
SETTINGS = PortSettings(
    name="Ethernet1/3",
    speeds=("1000", "10000", "25000"),
    speed="auto",
    duplex="full",
    mtu=1500,
    fec="auto",
    fec_oper="",
    flow_receive="off",
    flow_send="off",
    storm={"broadcast": "100.00", "multicast": "10.00", "unicast": "100.00"},
)
VLANS = PortVlans("Ethernet1/3", True, "access", 1, 1)
VIEW = VlanView([Vlan(1, "default", "active"), Vlan(10, "users", "active")], {"Ethernet1/3": VLANS})


def _form(**values: str) -> dict[str, str]:
    return check_bulk_form({**empty_bulk_form(), **values})


def test_empty_form_is_all_leave_as_it_is() -> None:
    form = empty_bulk_form()
    assert set(form) == set(BULK_FIELDS) and not any(form.values())
    assert bulk_kinds(form) == set()
    with pytest.raises(ValueError, match="fill in at least one setting"):
        check_bulk_form(form)


def test_kinds_follow_the_filled_in_fields() -> None:
    assert bulk_kinds(_form(power="off", mtu="9216", cdp="on")) == {"port", "settings", "discovery"}
    assert bulk_kinds(_form(allowed="10", clear_macs="yes")) == {"vlans", "macs"}


def test_check_cleans_up_what_was_typed() -> None:
    form = _form(access_vlan=" 010 ", storm_broadcast="5%", storm_unicast="None", mtu=" 9216 ")
    assert form["access_vlan"] == "10"
    assert form["storm_broadcast"] == "5.00" and form["storm_unicast"] == "none"
    assert form["mtu"] == "9216"
    # A description is kept only when its box is ticked.
    assert _form(power="on", description="x")["description"] == ""
    assert _form(set_description="yes", description="rack 4")["description"] == "rack 4"


def test_storm_none_removes_the_limit() -> None:
    plan = plan_port(
        PORT,
        _form(storm_multicast="none"),
        view=VIEW,
        settings=SETTINGS,
        discovery=None,
        neighbors=None,
        port_names=[PORT.name],
    )
    assert plan.settings_change is not None
    assert plan.settings_change.storm_levels == {"multicast": "100.00"}


def test_a_switched_port_gets_the_defaults_before_its_vlans() -> None:
    routed = replace(SETTINGS, routed=True, ip_address="192.0.2.1/24")
    view = VlanView(VIEW.vlans, {"Ethernet1/3": PortVlans("Ethernet1/3", False, "routed", 0, 0)})
    plan = plan_port(
        PORT,
        _form(layer="switched", access_vlan="10"),
        view=view,
        settings=routed,
        discovery=None,
        neighbors=None,
        port_names=[PORT.name],
    )
    assert [step.what for step in plan.steps] == ["port settings", "VLANs"]
    assert plan.settings_change is not None and plan.settings_change.remove_ip == "192.0.2.1/24"
    assert plan.vlan_change is not None and plan.vlan_change.access_vlan == 10


def test_settings_form_matches_what_the_switch_reports() -> None:
    form = settings_form(SETTINGS)
    assert form["mtu"] == "1500" and form["storm_multicast"] == "10.00"
    assert form["storm_broadcast"] == ""


def test_form_from_a_port_copies_settings_but_not_power_or_description() -> None:
    trunk = PortVlans("Ethernet1/9", True, "trunk", 1, 10, frozenset({10, 20}))
    form = form_from_port(
        replace(PORT, up=False, description="desk"),
        replace(SETTINGS, speed="10000", mtu=9216),
        trunk,
        PortDiscovery(cdp=False, lldp_transmit=True, lldp_receive=False),
    )
    assert form["mode"] == "trunk" and form["native_vlan"] == "10" and form["allowed"] == "10,20"
    assert form["access_vlan"] == ""
    assert form["speed"] == "10000" and form["mtu"] == "9216" and form["fec"] == "auto"
    assert form["storm_broadcast"] == "none" and form["storm_multicast"] == "10.00"
    assert form["cdp"] == "off" and form["lldp_transmit"] == "on" and form["lldp_receive"] == "off"
    assert form["power"] == "" and form["set_description"] == "" and form["description"] == ""
    # The form it gives passes the same checks.
    check_bulk_form(form)


def test_form_from_an_up_port_leaves_the_speed_alone() -> None:
    form = form_from_port(replace(PORT, up=True), replace(SETTINGS, speed="10000"), VLANS, None)
    assert form["speed"] == ""
    assert form["cdp"] == ""


def test_warnings_are_grouped_by_port() -> None:
    plans = [
        plan_port(
            replace(PORT, name=name, up=True),
            _form(power="off"),
            view=VIEW,
            settings=None,
            discovery=None,
            neighbors=None,
            port_names=[],
        )
        for name in ("Ethernet1/3", "Ethernet1/7")
    ]
    assert group_warnings(plans) == [
        "Ethernet1/3, Ethernet1/7: This port is up now: whatever is plugged into it loses its "
        "connection at once."
    ]
