"""The Non-blocking multicast page (#95), end to end against the fake switch, and its
parsers."""

from __future__ import annotations

import html
import json
import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.nbm import (
    COMMANDS,
    NO_TCAM,
    PAGE_COMMANDS,
    VXLAN_ON,
    build_nbm_change,
    parse_nbm,
    parse_nbm_config,
)
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"

# Recorded on cisco-25gb (NX-OS 9.3(16)) during the probe, with throwaway policies.
NAMES = (
    "show_nbm_defaults",
    "show_nbm_flow_policy",
    "show_nbm_host_policy_all_sender",
    "show_nbm_host_policy_all_receiver_local",
    "show_nbm_host_policy_all_receiver_external",
    "show_nbm_flows_summary",
    "show_nbm_flows_static",
    "show_nbm_interface_bandwidth",
)
BODIES = [json.loads((FIXTURES / f"{name}.json").read_text()) for name in NAMES]
CONFIG = (FIXTURES / "show_running_config_nbm.txt").read_text()


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(page: str) -> str:
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def _db(settings: Settings, sql: str) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute(sql)
    conn.commit()
    conn.close()


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


def _lines(scope, setting, action, ident, values=None):
    return list(build_nbm_change(scope, setting, action, ident, values or {}).lines)


def _table(view, title):
    return next(t for t in view.tables if t.title == title)


# ---- parsing and lines ----------------------------------------------------------------------


def test_the_configuration_is_read():
    found = parse_nbm_config(CONFIG)["default"]
    assert "nbm mode pim-active" in found.lines and "nbm flow dscp 46" in found.lines
    assert found.policies["nxprobefp"][:3] == ["bandwidth 3000000 kbps", "dscp 34", "no policer"]
    assert found.groups[("nxprobefp", "239.250.2.1")] == ["priority critical"]
    sender = {"seq": "10", "host": "192.0.2.10", "group": "239.250.1.0/24", "action": "deny"}
    assert ("sender", sender) in found.entries
    assert (
        "receiver",
        {
            "seq": "30",
            "host": "any",
            "source": "any",
            "group": "239.250.2.0/24",
            "action": "permit",
        },
    ) in found.entries
    assert found.definitions[("239.250.1.5", "192.0.2.10")] == [
        "egress-interface eth1/54",
        "stage-flow",
        "egress-host 192.0.2.30",
    ]


def test_an_nbm_vrf_is_read_on_its_own():
    config = "nbm vrf red\n  nbm mode pim-active\n  nbm flow dscp 10\n"
    found = parse_nbm_config(config)
    assert found["red"].lines == ["nbm mode pim-active", "nbm flow dscp 10"]
    assert found["default"].lines == []


def test_the_page_view():
    view = parse_nbm(BODIES, CONFIG)
    whole = next(i for i in view.of("global") if i.ident == {"vrf": "default"})
    assert whole.values["flow_bandwidth"] == {"amount": "100", "unit": "kbps"}
    assert whole.values["reserve_unicast"] == {"percent": "10"}
    assert "flow_policer" not in whole.values  # Disabled in show nbm defaults
    (policy,) = [i for i in view.of("policy") if i.ident["name"] == "nxprobefp"]
    assert policy.values["bandwidth"] == {"amount": "3000000", "unit": "kbps"}
    assert "policer" not in policy.values
    (group,) = view.of("group")
    assert group.values == {"priority": {}}
    (link,) = view.of("interface")
    assert link.ident == {"interface": "Ethernet1/53"}
    defaults = _table(view, "Defaults")
    assert defaults.rows[0][:5] == ("default", "pim-active", "100 kbps", "46", "Disabled")
    policies = _table(view, "Flow policies")
    critical = ("nxprobefp", "default", "239.250.2.1 to 239.250.2.1", "3 Gbps", "34")
    assert (*critical, "Disabled", "critical") in policies.rows
    hosts = _table(view, "Host policies")
    assert (
        "Local Receiver",
        "default",
        "30",
        "any",
        "any",
        "239.250.2.0/24",
        "Allow",
    ) in hosts.rows
    flows = _table(view, "Defined flows")
    assert flows.rows[1] == (
        "default",
        "239.250.1.5",
        "192.0.2.10",
        "not set up",
        "eth1/54",
        "192.0.2.30",
    )
    bandwidth = _table(view, "Interface bandwidth")
    assert bandwidth.rows[0][0] == "Vlan253" and bandwidth.rows[0][4] == "no"


def test_the_lines():
    assert _lines("global", "mode", "set", {"vrf": "default"}, {"mode": "pim-active"}) == [
        "nbm mode pim-active"
    ]
    assert _lines("global", "flow_dscp", "set", {"vrf": "red"}, {"dscp": "46"}) == [
        "nbm vrf red",
        "nbm flow dscp 46",
    ]
    assert _lines("policy", "", "create", {"vrf": "", "name": "video"}) == [
        "nbm flow-policy",
        "policy video",
    ]
    assert (
        _lines(
            "policy",
            "group_range",
            "set",
            {"name": "video"},
            {"first": "239.1.1.1", "last": "239.1.1.9"},
        )[-1]
        == "ip group-range 239.1.1.1 to 239.1.1.9"
    )
    assert _lines("policy", "policer", "remove", {"name": "video"})[-1] == "no policer"
    assert _lines("group", "priority", "set", {"name": "video", "group": "239.1.2.1"}) == [
        "nbm flow-policy",
        "policy video",
        "ip group 239.1.2.1",
        "priority critical",
    ]
    sender = {"seq": "10", "host": "any", "group": "239.1.1.0/24", "action": "deny"}
    assert _lines("sender", "", "create", sender) == [
        "nbm host-policy",
        "sender",
        "10 host 0.0.0.0 group 239.1.1.0/24 deny",
    ]
    assert _lines("sender", "", "delete", sender)[-1] == "no 10"
    assert _lines("defaults", "default", "set", {"role": "pim"}, {"action": "deny"}) == [
        "nbm host-policy",
        "pim",
        "default deny",
    ]
    assert _lines("interface", "external_link", "set", {"interface": "Ethernet1/53"}) == [
        "interface Ethernet1/53",
        "nbm external-link",
    ]


@pytest.mark.parametrize(
    ("scope", "setting", "ident", "values", "message"),
    [
        ("policy", "", {"name": "nx-video"}, {}, "letters and digits"),
        ("global", "flow_bandwidth", {}, {"amount": "26", "unit": "gbps"}, "at most 25 gbps"),
        (
            "policy",
            "group_range",
            {"name": "v"},
            {"first": "239.1.1.9", "last": "239.1.1.1"},
            "before",
        ),
        ("global", "flow_dscp", {}, {"dscp": "64"}, "0 to 63"),
    ],
)
def test_wrong_values_are_refused(scope, setting, ident, values, message):
    with pytest.raises(ValueError, match=message):
        build_nbm_change(scope, setting, "create" if not setting else "set", ident, values)


# ---- the page ---------------------------------------------------------------------------------


@pytest.fixture
def switch(logged_in: TestClient) -> FakeSwitch:
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "host": "192.0.2.10",
            "port": "443",
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "account_name": "nxray",
            "confirm_save": "yes",
        },
    )
    fake.feature_state["nbm"] = True
    fake.bodies.update(dict(zip(COMMANDS, BODIES, strict=True)))
    fake.mcast_lines += ["nbm mode pim-active", "nbm flow-policy", "nbm flow-policy ; policy video"]
    fake.requests.clear()
    return fake


def _enable(client: TestClient, settings: Settings, fake: FakeSwitch, mode: str) -> FakeSwitch:
    response = client.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(client, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "role_mode": mode,
            "confirm_save": "yes",
        },
    )
    assert response.status_code == 200
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    fake.requests.clear()
    fake.signed_in.clear()
    return fake


@pytest.fixture
def enabled(logged_in: TestClient, switch: FakeSwitch, settings: Settings) -> FakeSwitch:
    return _enable(logged_in, settings, switch, "broad")


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/nbm/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/nbm", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/nbm"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/nbm")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "Flow policy video" in text and "nxprobefp" in text and "TOR" not in text
    assert enabled.requests == [
        list(PAGE_COMMANDS),
        ["show hardware access-list tcam region"],
        list(COMMANDS),
        ["show running-config"],
    ]


def test_with_nbm_off_the_page_says_so_and_why_it_may_not_suit(
    logged_in: TestClient, switch: FakeSwitch
) -> None:
    switch.feature_state["nbm"] = False
    switch.feature_state["nve"] = True
    text = _text(logged_in.get("/nbm").text)
    assert "nbm is off on the switch" in text
    assert VXLAN_ON in text and NO_TCAM in text


def test_policies_host_policies_and_flows(logged_in: TestClient, enabled: FakeSwitch) -> None:
    bandwidth = _change(
        logged_in, scope="policy", setting="bandwidth", action="set", id_vrf="", id_name="video",
        v_amount="3", v_unit="gbps",
    )  # fmt: skip
    assert bandwidth.status_code == 200, _text(bandwidth.text)
    again = _change(
        logged_in, scope="policy", setting="bandwidth", action="set", id_vrf="", id_name="video",
        v_amount="2", v_unit="gbps",
    )  # fmt: skip
    assert again.status_code == 200, _text(again.text)
    assert [p for p in enabled.mcast_lines if "bandwidth" in p] == [
        "nbm flow-policy ; policy video ; bandwidth 2 gbps"
    ]
    refused = _change(logged_in, scope="policy", action="create", id_vrf="", id_name="nx-two")
    assert refused.status_code == 400 and "letters and digits" in _text(refused.text)
    entry = _change(
        logged_in, scope="sender", action="create", id_vrf="", id_seq="10", id_host="192.0.2.10",
        id_group="239.1.1.0/24", id_action="deny",
    )  # fmt: skip
    assert entry.status_code == 200, _text(entry.text)
    default = _change(
        logged_in, scope="defaults", setting="default", action="set", id_vrf="",
        id_role="sender", v_action="deny",
    )  # fmt: skip
    assert default.status_code == 400 and "cannot be modified" in _text(default.text)
    gone = _change(
        logged_in, scope="sender", action="delete", id_vrf="", id_seq="10", id_host="192.0.2.10",
        id_group="239.1.1.0/24", id_action="deny",
    )  # fmt: skip
    assert gone.status_code == 200, _text(gone.text)
    assert not any(" ; 10 " in p for p in enabled.mcast_lines)


def test_an_unknown_vrf_or_a_switched_port_is_refused(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    vrf = _change(
        logged_in, scope="global", setting="flow_dscp", action="set", id_vrf="nosuch", v_dscp="1"
    )
    assert vrf.status_code == 400 and "no VRF nosuch" in _text(vrf.text)
    port = _change(
        logged_in, scope="interface", setting="external_link", action="set",
        id_interface="Vlan10",
    )  # fmt: skip
    assert port.status_code == 400 and "not a routed front port" in _text(port.text)
    assert _config_requests(enabled) == []


def test_with_the_admin_login_stored_the_change_is_sent_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "stored")
    done = _change(
        logged_in, scope="global", setting="flow_dscp", action="set", id_vrf="", v_dscp="46"
    )
    assert done.status_code == 200, _text(done.text)
    assert "admin" in switch.signed_in and "nbm flow dscp 46" in switch.mcast_lines


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    refused = _change(
        logged_in, scope="global", setting="flow_dscp", action="set", id_vrf="", v_dscp="46"
    )
    assert refused.status_code == 400
    assert "Non-blocking multicast changes are off" in _text(refused.text)
    assert _config_requests(switch) == []


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "nbm"})
    assert saved.status_code == 200
    assert "Make a flow policy" in _text(saved.text) and enabled.saved
