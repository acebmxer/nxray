"""vPC (app/vpc.py): reading ``show vpc`` and the configuration text, the lines every
setting sends, and the values NXray refuses."""

from __future__ import annotations

import pytest

from app.port_changes import LIMITED_RULES, ROLE_VERSION, VPC_RULES, role_lines
from app.protocols import Field, check_value
from app.vpc import (
    VPC,
    build_vpc_change,
    channel_name,
    domain_values,
    parse_vpc,
    parse_vpc_config,
)
from tests.conftest import load_fixture

CONFIG = """\
feature vpc

vpc domain 10
  peer-switch
  role priority 100
  system-priority 4000
  peer-keepalive destination 192.0.2.2 source 192.0.2.1 vrf management
  delay restore 150
  peer-gateway
  auto-recovery reload-delay 300
  ip arp synchronize

interface port-channel1
  vpc peer-link

interface port-channel43
  vpc 43
"""


def _lines(scope: str, setting: str, action: str, ident: dict, values: dict) -> tuple[str, ...]:
    return build_vpc_change(scope, setting, action, ident, values).lines


# ---- reading ---------------------------------------------------------------------


def test_channel_name_long_form() -> None:
    assert channel_name("Po43") == "port-channel43"
    assert channel_name("port-channel1") == "port-channel1"
    assert channel_name("Ethernet1/1") == "Ethernet1/1"


def test_parse_vpc_config() -> None:
    config = parse_vpc_config(CONFIG)
    assert config.domain == "10"
    assert "peer-switch" in config.lines
    assert config.channels == {
        "port-channel1": ("vpc peer-link",),
        "port-channel43": ("vpc 43",),
    }


def test_parse_vpc_config_without_a_domain() -> None:
    config = parse_vpc_config("feature vpc\n")
    assert config.domain == "" and config.lines == () and config.channels == {}


def test_domain_values_from_the_lines() -> None:
    values = parse_vpc_config(CONFIG).values()
    assert values["keepalive"] == {
        "destination": "192.0.2.2",
        "source": "192.0.2.1",
        "vrf": "management",
    }
    assert values["role_priority"] == {"priority": "100"}
    assert values["system_priority"] == {"priority": "4000"}
    assert values["delay_restore"] == {"seconds": "150"}
    assert values["auto_recovery"] == {"delay": "300"}
    assert domain_values(["auto-recovery"])["auto_recovery"] == {"delay": ""}
    assert domain_values(["peer-keepalive destination 192.0.2.2"])["keepalive"]["vrf"] == "default"


def test_parse_vpc_reads_the_domain_and_the_pair() -> None:
    view = parse_vpc([load_fixture("show_vpc_doc")], parse_vpc_config(CONFIG))
    (domain,) = view.of("domain")
    assert domain.ident == {"domain": "10"}
    facts = dict(domain.facts)
    assert facts["Peer status"] == "peer-ok (peer adjacency formed ok)"
    assert facts["This switch is"] == "primary"
    assert facts["Peer keepalive"] == "peer-alive"
    assert "Peer switch" in facts["Turned on"] and "Peer gateway" in facts["Turned on"]
    assert "VLANs shut down on a split" not in facts  # "-" means none
    by_name = {i.ident["channel"]: i for i in view.of("channel")}
    assert set(by_name) == {"port-channel1", "port-channel43", "port-channel44"}
    assert dict(by_name["port-channel1"].facts)["Role"] == "vPC peer-link"
    assert by_name["port-channel43"].values["number"] == {"number": "43"}
    link, vpcs = view.tables
    assert link.rows == (("port-channel1", "up", "1,10,20"),)
    assert vpcs.rows[0] == ("43", "port-channel43", "up", "consistent SUCCESS", "10")
    assert vpcs.rows[1] == ("44", "port-channel44", "down", "inconsistent failed", "-")
    assert view.notes == ()


def test_parse_vpc_without_config_says_so() -> None:
    view = parse_vpc([load_fixture("show_vpc_doc")], None)
    assert view.notes and "does not let it read the vPC settings" in view.notes[0]
    assert [i.ident["domain"] for i in view.of("domain")] == ["10"]


def test_parse_vpc_tolerates_an_empty_answer() -> None:
    view = parse_vpc([{}], parse_vpc_config(""))
    assert view.instances == ()
    assert [len(t.rows) for t in view.tables] == [0, 0]
    assert parse_vpc([], None).instances == ()


def test_a_vpc_only_in_the_configuration_is_still_listed() -> None:
    view = parse_vpc([{}], parse_vpc_config(CONFIG))
    by_name = {i.ident["channel"]: i for i in view.of("channel")}
    assert by_name["port-channel43"].values["number"] == {"number": "43"}


# ---- the lines -----------------------------------------------------------------------


def test_make_and_delete_the_domain() -> None:
    assert _lines("domain", "", "create", {"domain": "10"}, {}) == ("vpc domain 10",)
    deleted = build_vpc_change("domain", "", "delete", {"domain": "10"}, {})
    assert deleted.lines == ("no vpc domain 10",)
    assert "takes down the peer-link" in deleted.warning


@pytest.mark.parametrize(
    ("setting", "values", "line"),
    [
        (
            "keepalive",
            {"destination": "192.0.2.2", "source": "192.0.2.1", "vrf": "management"},
            "peer-keepalive destination 192.0.2.2 source 192.0.2.1 vrf management",
        ),
        ("keepalive", {"destination": "192.0.2.2", "source": "", "vrf": "default"},
         "peer-keepalive destination 192.0.2.2"),
        ("role_priority", {"priority": "100"}, "role priority 100"),
        ("system_priority", {"priority": "4000"}, "system-priority 4000"),
        ("peer_switch", {}, "peer-switch"),
        ("peer_gateway", {}, "peer-gateway"),
        ("layer3_peer_router", {}, "layer3 peer-router"),
        ("arp_sync", {}, "ip arp synchronize"),
        ("nd_sync", {}, "ipv6 nd synchronize"),
        ("auto_recovery", {"delay": ""}, "auto-recovery"),
        ("auto_recovery", {"delay": "300"}, "auto-recovery reload-delay 300"),
        ("delay_restore", {"seconds": "150"}, "delay restore 150"),
        ("delay_restore_svi", {"seconds": "20"}, "delay restore interface-vlan 20"),
    ],
)  # fmt: skip
def test_domain_settings_send_one_line(setting: str, values: dict, line: str) -> None:
    assert _lines("domain", setting, "set", {"domain": "10"}, values) == ("vpc domain 10", line)


def test_removing_a_setting_sends_its_no_form() -> None:
    assert _lines("domain", "peer_switch", "remove", {"domain": "10"}, {}) == (
        "vpc domain 10",
        "no peer-switch",
    )
    assert _lines(
        "domain", "keepalive", "remove", {"domain": "10"}, {"destination": "192.0.2.2"}
    ) == ("vpc domain 10", "no peer-keepalive destination 192.0.2.2")


def test_port_channel_lines() -> None:
    assert _lines("channel", "peer_link", "set", {"channel": "Po1"}, {}) == (
        "interface port-channel1",
        "vpc peer-link",
    )
    assert _lines("channel", "peer_link", "remove", {"channel": "port-channel1"}, {}) == (
        "interface port-channel1",
        "no vpc peer-link",
    )
    assert _lines("channel", "number", "set", {"channel": "po43"}, {"number": "43"}) == (
        "interface port-channel43",
        "vpc 43",
    )
    assert _lines("channel", "number", "remove", {"channel": "po43"}, {"number": "43"}) == (
        "interface port-channel43",
        "no vpc 43",
    )


# ---- what is refused ---------------------------------------------------------------------


@pytest.mark.parametrize("domain", ["0", "1001", "ten", "", "10; reload", "-1"])
def test_bad_domain_numbers_are_refused(domain: str) -> None:
    with pytest.raises(ValueError):
        _lines("domain", "", "create", {"domain": domain}, {})


@pytest.mark.parametrize(
    "values",
    [
        {"destination": "", "source": "", "vrf": "default"},
        {"destination": "not-an-address", "source": "", "vrf": "default"},
        {"destination": "224.0.0.1", "source": "", "vrf": "default"},
        {"destination": "192.0.2.2; reload", "source": "", "vrf": "default"},
        {"destination": "192.0.2.2", "source": "2001:db8::1", "vrf": "default"},
        {"destination": "192.0.2.2", "source": "", "vrf": "bad vrf"},
    ],
)
def test_bad_keepalive_values_are_refused(values: dict) -> None:
    with pytest.raises(ValueError):
        _lines("domain", "keepalive", "set", {"domain": "10"}, values)


@pytest.mark.parametrize(
    ("setting", "values"),
    [
        ("role_priority", {"priority": "0"}),
        ("role_priority", {"priority": "65536"}),
        ("delay_restore", {"seconds": "3601"}),
        ("auto_recovery", {"delay": "239"}),
        ("auto_recovery", {"delay": "3601"}),
    ],
)
def test_out_of_range_numbers_are_refused(setting: str, values: dict) -> None:
    with pytest.raises(ValueError):
        _lines("domain", setting, "set", {"domain": "10"}, values)


@pytest.mark.parametrize("number", ["0", "4097", "x", ""])
def test_bad_vpc_numbers_are_refused(number: str) -> None:
    with pytest.raises(ValueError):
        _lines("channel", "number", "set", {"channel": "po43"}, {"number": number})


@pytest.mark.parametrize(
    "channel", ["Ethernet1/1", "port-channel0", "port-channel4097", "Vlan10", ""]
)
def test_only_port_channels_take_vpc_lines(channel: str) -> None:
    with pytest.raises(ValueError):
        _lines("channel", "peer_link", "set", {"channel": channel}, {})


def test_channel_field_kind() -> None:
    spec = Field("channel", "Port-channel", "channel")
    assert check_value(spec, "Po7") == "port-channel7"
    assert check_value(spec, "port-channel 7") == "port-channel7"
    with pytest.raises(ValueError, match="port-channel"):
        check_value(spec, "Ethernet1/1")


def test_unknown_scope_setting_or_action_is_refused() -> None:
    with pytest.raises(ValueError):
        _lines("vlan", "x", "set", {}, {})
    with pytest.raises(ValueError):
        _lines("domain", "nothing", "set", {"domain": "10"}, {})
    with pytest.raises(ValueError):
        _lines("channel", "peer_link", "create", {"channel": "po1"}, {})


# ---- the role ---------------------------------------------------------------------------


def test_every_setting_has_a_role_rule() -> None:
    assert ROLE_VERSION >= 19
    assert all(rule in LIMITED_RULES for rule in VPC_RULES)
    assert all(rule in role_lines(["Ethernet1/1"], "nxray") for rule in VPC_RULES)
    assert "conf t ; vpc domain *" in " ".join(VPC_RULES)
    assert "conf t ; interface * ; vpc *" in " ".join(VPC_RULES)
    assert "show running-config vpc" in " ".join(VPC_RULES)


def test_the_page_needs_both_features() -> None:
    assert VPC.features == ("vpc", "lacp")
