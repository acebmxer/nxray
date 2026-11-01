"""Turning on port changes, and the guarded port-change command, against a fake switch."""

from __future__ import annotations

import pytest

from app.nxapi import (
    DESCRIPTION_MAX,
    NxapiClient,
    NxapiCommandError,
    SwitchTarget,
    validate_description,
    validate_port_name,
)
from app.port_changes import (
    ROLE_NAME,
    ROLE_RULES,
    account_roles,
    enable_port_changes,
    front_ports,
    pause_seconds,
    role_lines,
)
from app.switch_setup import SetupError
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

NXRAY_PASSWORD = "Nxray4Test9Pw"


@pytest.fixture
def switch() -> FakeSwitch:
    fake = FakeSwitch()
    fake.users["nxray"] = (NXRAY_PASSWORD, "network-operator")
    return fake


def _enable(switch: FakeSwitch, **overrides):
    args = {
        "host": "192.0.2.10",
        "nxapi_port": 443,
        "ssh_port": 22,
        "admin_user": "admin",
        "admin_password": ADMIN_PASSWORD,
        "account_name": "nxray",
        "transport": switch.transport(),
        "ssh_opener": switch.ssh_opener(),
    }
    args.update(overrides)
    return enable_port_changes(**args)


def _nxray(switch: FakeSwitch) -> NxapiClient:
    target = SwitchTarget("192.0.2.10", 443, "nxray", NXRAY_PASSWORD, 10)
    return NxapiClient(target, transport=switch.transport())


# ---- pure pieces ----------------------------------------------------------


def test_front_ports_are_the_ethernet_ports_only() -> None:
    ports = front_ports(load_fixture("show_interface_brief"))
    assert len(ports) == 54
    assert ports[0] == "Ethernet1/1" and ports[-1] == "Ethernet1/54"
    assert "mgmt0" not in ports


def test_role_lines() -> None:
    lines = role_lines(["Ethernet1/1", "Ethernet1/49/2"], "nxray-dev")
    assert lines[0] == f"role name {ROLE_NAME}"
    assert all(rule in lines for rule in ROLE_RULES)
    assert lines.index("interface policy deny") < lines.index("permit interface Ethernet1/1")
    assert "permit interface Ethernet1/49/2" in lines
    assert lines[-3:] == ["exit", "exit", f"username nxray-dev role {ROLE_NAME}"]
    # Only interface-level on/off and description, plus saving; nothing broader.
    for rule in ROLE_RULES:
        assert rule.endswith(
            ("; shutdown", "; no shutdown", "; description *", "; no description")
        ) or rule.endswith("copy running-config startup-config")


@pytest.mark.parametrize(
    ("ports", "account"),
    [
        ([], "nxray"),
        (["mgmt0"], "nxray"),
        (["Ethernet1/1 ; reload"], "nxray"),
        (["Ethernet1/1"], "admin"),
        (["Ethernet1/1"], "bad name"),
    ],
)
def test_role_lines_refuse_unchecked_values(ports: list[str], account: str) -> None:
    with pytest.raises(ValueError):
        role_lines(ports, account)


def test_account_roles_one_or_several() -> None:
    body = {
        "TABLE_template": {
            "ROW_template": [
                {"usr_name": "admin", "TABLE_role": {"ROW_role": {"role": "network-admin"}}},
                {
                    "usr_name": "nxray",
                    "TABLE_role": {"ROW_role": [{"role": "network-operator"}, {"role": ROLE_NAME}]},
                },
            ]
        }
    }
    assert account_roles(body, "nxray") == {"network-operator", ROLE_NAME}
    assert account_roles(body, "ADMIN") == {"network-admin"}
    assert account_roles(body, "nobody") == set()


@pytest.mark.parametrize(
    ("body", "seconds"),
    [({"timeout": "10"}, 660), ({"timeout": "5"}, 360), ({}, 660), ({"timeout": "x"}, 660)],
)
def test_pause_is_the_nxapi_idle_timeout_plus_a_minute(body: dict, seconds: int) -> None:
    assert pause_seconds(body) == seconds


@pytest.mark.parametrize("name", ["Ethernet1/1", "Ethernet1/54", "Ethernet1/49/4"])
def test_port_names_accepted(name: str) -> None:
    assert validate_port_name(name) == name


@pytest.mark.parametrize(
    "name",
    ["mgmt0", "Eth1/1", "Ethernet1/1 ", "Ethernet1/1\nshutdown", "Ethernet1/1-2", "vlan1", ""],
)
def test_port_names_refused(name: str) -> None:
    with pytest.raises(ValueError):
        validate_port_name(name)


@pytest.mark.parametrize(
    ("typed", "stored"),
    [
        ("xcp-host-1 <storage>", "xcp-host-1 <storage>"),
        ('quote "a" | b & c % $d `e` \\f', 'quote "a" | b & c % $d `e` \\f'),
        ("   leading spaces go", "leading spaces go"),
        ("", ""),
        ("x" * DESCRIPTION_MAX, "x" * DESCRIPTION_MAX),
    ],
)
def test_descriptions_accepted(typed: str, stored: str) -> None:
    assert validate_description(typed) == stored


@pytest.mark.parametrize(
    "typed",
    ["what?", "a;b", "café", "tab\there", "two\nlines", "x" * (DESCRIPTION_MAX + 1)],
)
def test_descriptions_refused(typed: str) -> None:
    with pytest.raises(ValueError):
        validate_description(typed)


# ---- configure_port -------------------------------------------------------


def test_configure_port_sends_one_request(switch: FakeSwitch) -> None:
    _enable(switch)
    with _nxray(switch) as client:
        client.configure_port("Ethernet1/3", description="uplink", enabled=False)
        client.configure_port("Ethernet1/3", description="")
    assert switch.requests[-2] == ["interface Ethernet1/3", "description uplink", "shutdown"]
    assert switch.requests[-1] == ["interface Ethernet1/3", "no description"]
    assert switch.port_state["Ethernet1/3"] == {"desc": "", "admin_up": False}


def test_configure_port_checks_before_sending(switch: FakeSwitch) -> None:
    with _nxray(switch) as client:
        for kwargs in (
            {"name": "mgmt0", "enabled": False},
            {"name": "Ethernet1/3", "description": "a?b"},
            {"name": "Ethernet1/3"},
        ):
            with pytest.raises(ValueError):
                client.configure_port(**kwargs)
    assert switch.requests == []


def test_without_the_role_the_switch_refuses_port_changes(switch: FakeSwitch) -> None:
    with _nxray(switch) as client, pytest.raises(NxapiCommandError, match="Permission denied"):
        client.configure_port("Ethernet1/3", enabled=False)
    assert switch.port_state == {}


# ---- enable_port_changes --------------------------------------------------


def test_enable_names_the_vlan_interfaces_only_while_interface_vlan_is_on(
    switch: FakeSwitch,
) -> None:
    switch.feature_state["interface-vlan"] = True
    result = _enable(switch, role_version=7)
    assert result.vlan_interfaces
    assert "vlan1-254" in switch.roles[ROLE_NAME].interfaces
    # The port list gained a line, so the check and save went over SSH.
    assert switch.ssh_lines[-1] == "copy running-config startup-config"


def test_enable_creates_the_role_gives_it_and_saves(switch: FakeSwitch) -> None:
    result = _enable(switch)
    assert (result.pause_seconds, result.port_count, result.config_saved) == (660, 54, True)
    assert switch.saved
    assert ROLE_NAME in switch.roles_of("nxray")
    role = switch.roles[ROLE_NAME]
    # The 54 front ports one by one and every port-channel in one line; never mgmt0.
    # interface-vlan is off, so the switch would refuse the VLAN interfaces' line.
    assert role.interface_policy_deny and len(role.interfaces) == 55
    assert "port-channel1-4096" in role.interfaces and "mgmt0" not in role.interfaces
    assert "vlan1-254" not in role.interfaces and not result.vlan_interfaces
    assert switch.ssh_lines[0] == "configure terminal"
    # The role gains the port-channels, so the check and the save go over SSH.
    assert switch.ssh_lines[-3:] == [
        "end",
        "show user-account nxray",
        "copy running-config startup-config",
    ]
    # NXray's own account is never used for this; only the admin login is.
    assert all(";" not in cmd for request in switch.requests for cmd in request)


def test_enable_works_while_nxapi_is_frozen(switch: FakeSwitch) -> None:
    """As on cisco-25gb: once the role names port-channels, NX-API stops answering
    every account for a while. NXray must not need it after typing the role."""
    switch.freeze_on_channel_permit = True
    result = _enable(switch)
    assert switch.nxapi_frozen
    assert result.config_saved and switch.saved
    assert result.pause_seconds == 660
    assert ROLE_NAME in switch.roles_of("nxray")


def test_enable_over_ssh_reports_a_failed_save(switch: FakeSwitch) -> None:
    switch.freeze_on_channel_permit = True
    switch.save_text = "Copy failed\n"
    result = _enable(switch)
    assert not result.config_saved and result.save_error == "Copy failed"


def test_enable_over_ssh_checks_the_role_took(switch: FakeSwitch) -> None:
    opener = switch.ssh_opener()

    def without_the_role(host, port, username, password, timeout):  # noqa: ANN001
        shell = opener(host, port, username, password, timeout)
        real = shell.run

        def run(line: str) -> str:
            return "" if line.startswith("username ") else real(line)

        shell.run = run
        return shell

    with pytest.raises(SetupError, match="does not have the nxray-ports role. Nothing was saved"):
        _enable(switch, ssh_opener=without_the_role)
    assert not switch.saved


def test_a_current_role_is_checked_and_saved_over_nxapi(switch: FakeSwitch) -> None:
    _enable(switch)
    switch.ssh_lines.clear()
    switch.saved = False
    result = _enable(switch, role_version=7)
    assert result.pause_seconds == 0 and result.config_saved and switch.saved
    assert switch.ssh_lines[-1] == "end"


def test_enable_twice_gives_the_same_role(switch: FakeSwitch) -> None:
    _enable(switch)
    first = switch.roles[ROLE_NAME]
    _enable(switch)
    assert switch.roles[ROLE_NAME] == first


def test_after_enabling_only_front_port_changes_are_allowed(switch: FakeSwitch) -> None:
    switch.bodies["show interface brief"] = {
        "TABLE_interface": {"ROW_interface": [{"interface": "Ethernet1/1"}]}
    }
    _enable(switch)
    with _nxray(switch) as client:
        client.configure_port("Ethernet1/1", description="ok", enabled=True)
        with pytest.raises(NxapiCommandError):
            client.configure_port("Ethernet1/2", enabled=False)  # outside the policy


def test_wrong_admin_password(switch: FakeSwitch) -> None:
    with pytest.raises(SetupError, match="refused the admin username or password"):
        _enable(switch, admin_password="Wrong-pw-1")
    assert switch.ssh_lines == [] and switch.roles == {}


def test_ssh_unreachable_is_explained(switch: FakeSwitch) -> None:
    switch.ssh_reachable = False
    with pytest.raises(
        SetupError, match="could not reach the switch over SSH at 192.0.2.10, port 22"
    ):
        _enable(switch)
    assert not switch.saved


def test_ssh_wrong_password_is_explained(switch: FakeSwitch) -> None:
    # NX-API and SSH may use different logins on some switches.
    opener = switch.ssh_opener()

    def ssh_with_other_password(host, port, username, password, timeout):  # noqa: ANN001
        return opener(host, port, username, "not-the-password", timeout)

    with pytest.raises(SetupError, match="refused the admin username or password over SSH"):
        _enable(switch, ssh_opener=ssh_with_other_password)


def test_a_refused_role_line_stops_before_saving(switch: FakeSwitch) -> None:
    switch.ssh_reject.add("interface policy deny")
    with pytest.raises(SetupError, match="refused a line while creating the role"):
        _enable(switch)
    assert not switch.saved
    assert ROLE_NAME not in switch.roles_of("nxray")
    assert switch.ssh_lines[-1] == "end"


def test_missing_account_is_explained(switch: FakeSwitch) -> None:
    del switch.users["nxray"]
    with pytest.raises(SetupError, match="no longer on the switch"):
        _enable(switch)
    assert switch.ssh_lines == []


def test_a_failed_save_is_reported_not_raised(switch: FakeSwitch) -> None:
    switch.save_text = "Copy failed\n"
    result = _enable(switch, role_version=6)
    assert not result.config_saved and "Copy failed" in (result.save_error or "")
    assert ROLE_NAME in switch.roles_of("nxray")
