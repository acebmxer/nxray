"""The ITD page (#80), end to end against the fake switch, and its parser."""

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
from app.itd import COMMANDS, PAGE_COMMANDS, build_itd_change, parse_itd, parse_itd_config
from app.port_changes import ITD_STATISTICS_RULES, ROLE_NAME
from app.switch_connection import BROAD_ITD_VERSION
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"


def _body(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


# Shaped with the keys show itd and show itd <service> statistics had on cisco-25gb
# (NX-OS 9.3(16)) during the probe; names and addresses are made up.
SUMMARY = _body("show_itd")
STATISTICS = _body("show_itd_statistics")
CONFIG = """
version 9.3(16)
feature pbr
feature itd
itd device-group servers
  probe icmp frequency 10 retry-down-count 3
  node ip 198.51.100.10
    weight 2
  node ip 198.51.100.11
    mode hot-standby
itd web
  device-group servers
  ingress interface Vlan250
  virtual ip 198.51.100.100 255.255.255.255 tcp 443 advertise enable
  load-balance method src ip buckets 4
  failaction node reassign
  no shutdown
"""


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


# ---- parsing and lines --------------------------------------------------------------------


def test_the_configuration_gives_the_groups_nodes_and_services() -> None:
    parsed = parse_itd_config(CONFIG)
    assert parsed.groups == {"servers": ["probe icmp frequency 10 retry-down-count 3"]}
    assert parsed.nodes["servers"] == {
        "198.51.100.10": ["weight 2"],
        "198.51.100.11": ["mode hot-standby"],
    }
    assert parsed.services["web"][0] == "device-group servers"


def test_the_page_view() -> None:
    view = parse_itd(SUMMARY, CONFIG, {"web": STATISTICS})
    (group,) = view.of("group")
    assert group.values == {"probe_icmp": {"frequency": "10", "down": "3"}}
    assert dict(group.facts)["Nodes"] == "198.51.100.10, 198.51.100.11"
    first, second = view.of("node")
    assert first.ident == {"group": "servers", "address": "198.51.100.10"}
    assert first.values == {"weight": {"weight": "2"}}
    assert second.values == {"hot_standby": {"on": "yes"}}
    (service,) = view.of("service")
    facts = dict(service.facts)
    assert facts["State"] == "ACTIVE (None)" and facts["Ingress"] == "Vlan250"
    assert service.values["vip"] == {
        "address": "198.51.100.100",
        "mask": "255.255.255.255",
        "protocol": "tcp",
        "port": "443",
        "advertise": "advertise enable",
    }
    assert service.values["load_balance"] == {"method": "src ip"}
    assert service.values["failaction"] == {"mode": "node reassign"}
    (counters,) = view.of("counters")
    assert counters.values == {"statistics": {"on": "yes"}}
    nodes, buckets = view.tables
    assert nodes.rows[0] == ("web", "198.51.100.10", "Active", "2", "OK", "PROBE_SUCCESS")
    assert buckets.rows[1] == ("web", "198.51.100.11", "web_itd_vip_1_bucket_2", "130", "24.53")


def test_without_the_configuration_the_state_still_shows() -> None:
    view = parse_itd(SUMMARY, None)
    (service,) = view.of("service")
    assert dict(service.facts)["Spread by"] == "src-ip"
    assert view.notes and "did not show ITD's settings" in view.notes[0]


def test_the_lines() -> None:
    def lines(scope: str, setting: str, action: str, ident: dict[str, str], **values: str):
        return build_itd_change(scope, setting, action, ident, values).lines

    group = {"name": "servers"}
    assert lines("group", "", "create", group) == ("itd device-group servers",)
    assert lines("group", "", "delete", group) == ("no itd device-group servers",)
    assert lines("group", "probe_icmp", "set", group, frequency="10", down="3")[-1] == (
        "probe icmp frequency 10 retry-down-count 3"
    )
    assert lines("group", "probe_icmp", "remove", group)[-1] == "no probe icmp"
    assert lines("group", "probe_tcp", "set", group, port="443")[-1] == "probe tcp port 443"
    assert (
        lines("group", "probe_dns", "set", group, host="www.example.net", timeout="5")[-1]
        == "probe dns host www.example.net timeout 5"
    )
    node = {"group": "servers", "address": "198.51.100.10"}
    assert lines("node", "", "create", node) == (
        "itd device-group servers",
        "node ip 198.51.100.10",
    )
    assert lines("node", "", "delete", node) == (
        "itd device-group servers",
        "no node ip 198.51.100.10",
    )
    assert lines("node", "weight", "set", node, weight="2")[-1] == "weight 2"
    assert lines("node", "hot_standby", "set", node)[-1] == "mode hot-standby"
    web = {"name": "web"}
    assert lines("service", "", "create", web) == ("itd web",)
    assert lines("service", "ingress", "set", web, interface="Vlan250")[-1] == (
        "ingress interface Vlan250"
    )
    assert lines(
        "service", "vip", "set", web, address="198.51.100.100", mask="255.255.255.255",
        protocol="tcp", port="443", advertise="yes",
    )[-1] == "virtual ip 198.51.100.100 255.255.255.255 tcp 443 advertise enable"  # fmt: skip
    assert lines(
        "service", "load_balance", "set", web, method="dst ip-l4port", range_protocol="tcp",
        low="80", high="443", buckets="8",
    )[-1] == "load-balance method dst ip-l4port tcp range 80 443 buckets 8"  # fmt: skip
    assert lines("service", "failaction", "set", web, mode="bucket distribute")[-1] == (
        "failaction bucket distribute"
    )
    assert lines("service", "admin_up", "set", web)[-1] == "no shutdown"
    counting = build_itd_change("counters", "statistics", "set", web, {})
    assert counting.lines == ("itd statistics web",) and not counting.config
    assert lines("counters", "statistics", "remove", web) == ("no itd statistics web",)
    assert lines("counters", "clear", "set", web) == ("clear itd statistics web",)


@pytest.mark.parametrize(
    ("scope", "setting", "ident", "values"),
    [
        ("service", "load_balance", {"name": "web"}, {"method": "round-robin"}),
        ("service", "vip", {"name": "web"}, {"address": "198.51.100.100", "mask": ""}),
        ("group", "probe_tcp", {"name": "g"}, {"port": "70000"}),
        ("group", "probe_icmp", {"name": "g"}, {"frequency": "0"}),
        ("node", "weight", {"group": "g", "address": "not an address"}, {"weight": "2"}),
        ("service", "ingress", {"name": "web"}, {"interface": "loopback0"}),
    ],
)
def test_wrong_values_are_refused(
    scope: str, setting: str, ident: dict[str, str], values: dict[str, str]
) -> None:
    with pytest.raises(ValueError):
        build_itd_change(scope, setting, "set", ident, values)


def test_the_broad_role_allows_the_counters() -> None:
    from app.port_changes import BROAD_RULES

    assert set(ITD_STATISTICS_RULES) <= set(BROAD_RULES)


# ---- the page -----------------------------------------------------------------------------


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
    fake.feature_state.update({"pbr": True, "itd": True, "interface-vlan": True})
    fake.svis = {250}
    fake.port_state["Vlan250"] = {"routed": True, "admin_up": True}
    fake.protocol_lines += [
        "itd device-group servers",
        "itd device-group servers ; probe icmp",
        "itd device-group servers ; node ip 198.51.100.10",
        "itd web",
        "itd web ; device-group servers",
    ]
    fake.bodies.update({"show itd": SUMMARY, "show itd web statistics": STATISTICS})
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
    return client.post("/itd/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/itd", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/itd"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/itd")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "198.51.100.10 in servers" in text and "probe icmp" in text
    assert "web_itd_vip_1_bucket_1" in text
    assert enabled.requests == [
        list(PAGE_COMMANDS),
        list(COMMANDS),
        ["show running-config"],
        ["show itd web statistics"],
    ]
    assert "/itd/change" in page.text


def test_with_itd_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["itd"] = False
    text = _text(logged_in.get("/itd").text)
    assert "itd is off on the switch" in text
    assert switch.requests == [list(PAGE_COMMANDS)]


def test_making_a_service_and_its_lines(logged_in: TestClient, enabled: FakeSwitch) -> None:
    fields = {"scope": "service", "setting": "ingress", "action": "set", "id_name": "app"}
    asked = _change(logged_in, confirm=False, v_interface="Vlan250", **fields)
    assert "ingress interface Vlan250" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, v_interface="Vlan250", **fields)
    assert done.status_code == 200, _text(done.text)
    node = _change(
        logged_in,
        scope="node",
        setting="weight",
        action="set",
        id_group="servers",
        id_address="198.51.100.10",
        v_weight="3",
    )
    assert node.status_code == 200, _text(node.text)
    assert _config_requests(enabled) == [
        ["itd app", "ingress interface Vlan250"],
        ["itd device-group servers", "node ip 198.51.100.10", "weight 3"],
    ]
    assert "itd device-group servers ; node ip 198.51.100.10 ; weight 3" in (enabled.protocol_lines)
    # The page shows what was set, from the running configuration.
    assert "Line weight 3" in _text(node.text)


def test_counting_is_typed_outside_configuration_mode(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    done = _change(logged_in, scope="counters", setting="statistics", action="set", id_name="web")
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [["itd statistics web"]]
    assert enabled.itd_counting == {"web"}
    # Nothing to save: counting is not configuration.
    assert "not saved" not in _text(done.text).lower().split("done:")[-1][:200]


def test_a_broad_role_written_before_the_counters_is_refused_until_updated(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    for rule in ITD_STATISTICS_RULES:
        enabled.roles[ROLE_NAME].entities.discard(rule.split(" command ", 1)[1])
    _db(settings, f"UPDATE switch_connection SET role_version = {BROAD_ITD_VERSION - 1}")
    refused = _change(
        logged_in, scope="counters", setting="statistics", action="set", id_name="web"
    )
    assert refused.status_code == 400 and "Update the port list" in _text(refused.text)
    assert _config_requests(enabled) == []
    assert "allowed ITD's counters" in _text(logged_in.get("/switch").text)
    # The rest of the page still changes.
    done = _change(logged_in, scope="service", action="create", id_name="app")
    assert done.status_code == 200, _text(done.text)
    updated = logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "role_mode": "broad",
            "confirm_save": "yes",
        },
    )
    assert "The role now also allows ITD's counters" in _text(updated.text)
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    done = _change(logged_in, scope="counters", setting="statistics", action="set", id_name="web")
    assert done.status_code == 200, _text(done.text)


def test_with_the_admin_login_stored_the_change_is_sent_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "stored")
    done = _change(logged_in, scope="counters", setting="clear", action="set", id_name="web")
    assert done.status_code == 200, _text(done.text)
    assert "admin" in switch.signed_in


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    refused = _change(logged_in, scope="service", action="create", id_name="app")
    assert refused.status_code == 400 and "ITD changes are off" in _text(refused.text)
    assert _config_requests(switch) == []


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "itd"})
    assert saved.status_code == 200
    assert "Make a service" in _text(saved.text) and enabled.saved
