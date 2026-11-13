"""The Enhanced policy-based routing page (#95), end to end against the fake switch, and
its parsers."""

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
from app.epbr import (
    COMMANDS,
    PAGE_COMMANDS,
    POLICY_APPLIED,
    SERVICE_IN_USE,
    build_epbr_change,
    parse_epbr,
    parse_epbr_config,
    probe_values,
)
from app.port_changes import BROAD_RULES, EPBR_CLEAR_RULES, ROLE_NAME
from app.switch_connection import BROAD_EPBR_VERSION
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"


def _body(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


# Recorded on cisco-25gb (NX-OS 9.3(16)) during the probe; the names are changed.
POLICY = _body("show_epbr_policy")
POLICY_REVERSE = _body("show_epbr_policy_reverse")
STATISTICS = _body("show_epbr_statistics_policy")
STATISTICS_REVERSE = _body("show_epbr_statistics_policy_reverse")
CONFIG = (FIXTURES / "show_running_config_epbr.txt").read_text()


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


# ---- parsing ------------------------------------------------------------------------------


def test_the_configuration_is_read_by_keyword_not_by_indentation() -> None:
    parsed = parse_epbr_config(CONFIG)
    firewall = parsed.services["firewall"]
    assert firewall.lines == ["service-interface Vlan250"]
    assert firewall.probe == "probe icmp retry-down-count 5"
    first, second = firewall.endpoints
    assert (first.family, first.address, first.interface) == ("ip", "198.51.100.10", "Vlan250")
    assert first.probe == "probe track 250"
    assert first.reverse is not None and first.reverse.address == "198.51.100.20"
    assert first.reverse.probe == "probe track 250"
    assert second.probe == "probe icmp" and second.reverse and not second.reverse.probe
    assert parsed.services["cache"].endpoints[0].interface == ""
    web = parsed.policies["web-chain"]
    assert web.statistics
    (match,) = web.matches
    assert (match.family, match.acl, match.load_balance) == (
        "ip",
        "web",
        "load-balance method dst-ip",
    )
    assert match.steps == [("10", "firewall", "drop"), ("30", "firewall", "forward")]
    assert [(a.interface, a.family, a.policy, a.reverse) for a in parsed.applied] == [
        ("Vlan251", "ip", "web-chain", False),
        ("Vlan251", "ip", "web-chain", True),
        ("Vlan251", "ipv6", "web6-chain", False),
    ]
    # mail-chain is not applied: the cache service it names is not in use.
    assert parsed.services_in_use == {"firewall", "firewall6"}
    assert parsed.applied_policies == {"web-chain", "web6-chain"}


@pytest.mark.parametrize(
    ("line", "values"),
    [
        ("probe icmp retry-down-count 5", {"probe_icmp": {"down": "5"}}),
        (
            "probe tcp 80 frequency 10 timeout 3 source-interface loopback0",
            {"probe_tcp": {"port": "80", "frequency": "10", "timeout": "3", "source": "loopback0"}},
        ),
        ("probe udp 53 control enable", {"probe_udp": {"port": "53", "control": "control enable"}}),
        (
            "probe http get index.html frequency 60",
            {"probe_http": {"page": "index.html", "frequency": "60"}},
        ),
        ("probe dns host www.example.net", {"probe_dns": {"host": "www.example.net"}}),
        ("probe track 250", {"probe_track": {"track": "250"}}),
        ("probe ctp", {}),
        ("", {}),
    ],
)
def test_a_probe_line_gives_its_values(line: str, values: dict) -> None:
    assert probe_values(line) == values


def test_the_page_view() -> None:
    view = parse_epbr(
        POLICY,
        CONFIG,
        {"web-chain": POLICY_REVERSE},
        {("web-chain", "forward"): STATISTICS, ("web-chain", "reverse"): STATISTICS_REVERSE},
    )
    firewall = next(i for i in view.of("service") if i.ident == {"service": "firewall"})
    facts = dict(firewall.facts)
    assert facts["Used by"] == "web-chain" and facts["Changed in an ePBR session"].startswith("yes")
    assert firewall.values["service_interface"] == {"interface": "Vlan250"}
    cache = next(i for i in view.of("service") if i.ident == {"service": "cache"})
    assert dict(cache.facts)["Changed in an ePBR session"] == "no"
    endpoint = view.of("endpoint")[0]
    assert endpoint.ident == {
        "service": "firewall",
        "family": "ip",
        "address": "198.51.100.10",
        "interface": "Vlan250",
    }
    assert endpoint.values["reverse"] == {
        "reverse": "198.51.100.20",
        "reverse_interface": "Vlan250",
    }
    assert endpoint.values["probe_track"] == {"track": "250"}
    reverse = view.of("reverse")[0]
    assert reverse.ident["reverse"] == "198.51.100.20" and reverse.values == {
        "probe_track": {"track": "250"}
    }
    match = next(i for i in view.of("match") if i.ident["policy"] == "web-chain")
    assert match.values == {"load_balance": {"buckets": "", "method": "dst-ip"}}
    steps = [i.ident for i in view.of("step") if i.ident["policy"] == "web-chain"]
    assert steps[1] == {
        "policy": "web-chain",
        "family": "ip",
        "acl": "web",
        "seq": "30",
        "service": "firewall",
        "fail": "forward",
    }
    (interface,) = view.of("interface")
    assert interface.values == {
        "policy": {"map": "web-chain"},
        "policy_reverse": {"map": "web-chain"},
        "policy6": {"map": "web6-chain"},
    }
    assert [i.ident for i in view.of("counters")] == [{"policy": "web-chain"}]
    where, chains, counters = view.tables
    assert where.rows[1] == ("Vlan251", "IPv4", "web-chain", "reverse")
    assert chains.rows[0] == (
        "web-chain", "forward", "web", "10", "firewall", "drop", "198.51.100.10", "250", "DOWN",
    )  # fmt: skip
    assert ("web-chain", "reverse", "web", "30", "firewall", "forward", "198.51.100.23", "2",
            "DOWN") in chains.rows  # fmt: skip
    # The unapplied policy's end-point has no probe yet: no tracked object.
    assert ("mail-chain", "forward", "mail", "10", "cache", "-", "198.51.100.30", "-",
            "INACTIVE") in chains.rows  # fmt: skip
    assert counters.rows[0] == ("web-chain", "forward", "web", "1", "10 firewall", "0")
    assert counters.rows[1][4] == "30 firewall"
    assert ("web-chain", "reverse", "web", "2", "30 firewall", "0") in counters.rows


def test_without_the_configuration_the_state_still_shows() -> None:
    view = parse_epbr(POLICY, None)
    assert view.notes and "did not show ePBR's settings" in view.notes[0]
    names = {i.ident["policy"]: dict(i.facts)["Applied on"] for i in view.of("policy")}
    assert names == {"web-chain": "Vlan251", "mail-chain": "no interface", "web6-chain": "Vlan251"}


# ---- lines --------------------------------------------------------------------------------


def _lines(scope: str, setting: str, action: str, ident: dict[str, str], **values: str):
    return build_epbr_change(scope, setting, action, ident, values).lines


def test_the_lines_of_objects_not_in_use() -> None:
    service = {"service": "firewall"}
    assert _lines("service", "", "create", service) == ("epbr service firewall",)
    assert _lines("service", "", "delete", service) == ("no epbr service firewall",)
    assert _lines(
        "service", "probe_tcp", "set", service, port="80", frequency="10", down="2",
        source="loopback0",
    )[-1] == "probe tcp 80 frequency 10 retry-down-count 2 source-interface loopback0"  # fmt: skip
    assert _lines("service", "probe_tcp", "remove", service, port="80")[-1] == "no probe tcp 80"
    assert _lines("service", "probe_udp", "set", service, port="53", control="yes")[-1] == (
        "probe udp 53 control enable"
    )
    assert (
        _lines("service", "probe_http", "set", service, page="index.html", frequency="60")[-1]
        == "probe http get index.html frequency 60"
    )
    assert _lines("service", "service_interface", "remove", service, interface="Vlan250")[-1] == (
        "no service-interface Vlan250"
    )
    assert _lines("service", "vrf", "set", service, vrf="tenant")[-1] == "vrf tenant"
    endpoint = {"service": "firewall", "address": "198.51.100.10", "interface": "Vlan250"}
    assert _lines("endpoint", "", "create", endpoint) == (
        "epbr service firewall",
        "service-end-point ip 198.51.100.10 interface Vlan250",
    )
    assert _lines("endpoint", "", "delete", endpoint) == (
        "epbr service firewall",
        "no service-end-point ip 198.51.100.10",
    )
    assert _lines(
        "endpoint", "reverse", "set", endpoint, reverse="198.51.100.20",
        reverse_interface="Vlan250",
    )[-1] == "reverse ip 198.51.100.20 interface Vlan250"  # fmt: skip
    assert _lines("endpoint", "probe_track", "set", endpoint, track="250")[-1] == "probe track 250"
    six = {"service": "firewall6", "address": "2001:db8::10"}
    assert _lines("endpoint", "", "create", six)[-1] == "service-end-point ipv6 2001:db8::10"
    reverse = {**endpoint, "reverse": "198.51.100.20", "reverse_interface": "Vlan250"}
    assert _lines("reverse", "probe_icmp", "set", reverse) == (
        "epbr service firewall",
        "service-end-point ip 198.51.100.10 interface Vlan250",
        "reverse ip 198.51.100.20 interface Vlan250",
        "probe icmp",
    )
    policy = {"policy": "web-chain"}
    assert _lines("policy", "statistics", "set", policy)[-1] == "statistics"
    assert _lines("policy", "statistics", "remove", policy)[-1] == "no statistics"
    match = {"policy": "web-chain", "family": "ip", "acl": "web"}
    assert _lines("match", "", "create", match) == ("epbr policy web-chain", "match ip address web")
    assert _lines("match", "load_balance", "set", match, buckets="8", method="src-ip")[-1] == (
        "load-balance buckets 8 method src-ip"
    )
    assert _lines("match", "load_balance", "remove", match, method="dst-ip")[-1] == (
        "no load-balance method dst-ip"
    )
    step = {**match, "seq": "10", "service": "firewall", "fail": "drop"}
    assert _lines("step", "", "create", step)[-1] == "10 set service firewall fail-action drop"
    assert _lines("step", "", "delete", step)[-1] == "no 10"
    interface = {"interface": "Vlan251"}
    assert _lines("interface", "policy_reverse", "set", interface, map="web-chain") == (
        "interface Vlan251",
        "epbr ip policy web-chain reverse",
    )
    assert _lines("interface", "policy6", "remove", interface, map="web6-chain")[-1] == (
        "no epbr ipv6 policy web6-chain"
    )
    cleared = build_epbr_change("counters", "clear", "set", policy, {})
    assert cleared.lines == ("clear epbr statistics policy web-chain",) and not cleared.config


def test_objects_in_use_are_changed_in_an_epbr_session() -> None:
    endpoint = {
        "service": "firewall",
        "address": "198.51.100.13",
        "interface": "Vlan250",
        SERVICE_IN_USE: "yes",
    }
    assert _lines("endpoint", "", "create", endpoint) == (
        "epbr session",
        "epbr service firewall",
        "service-end-point ip 198.51.100.13 interface Vlan250",
        "commit",
    )
    step = {
        "policy": "web-chain",
        "family": "ip",
        "acl": "web",
        "seq": "20",
        "service": "firewall",
        POLICY_APPLIED: "yes",
    }
    assert _lines("step", "", "delete", step) == (
        "epbr session",
        "epbr policy web-chain",
        "match ip address web",
        "no 20",
        "commit",
    )
    # A service in use that only an unapplied policy's step names: the policy decides.
    assert _lines("step", "", "create", {**step, POLICY_APPLIED: "", SERVICE_IN_USE: "yes"})[0] == (
        "epbr policy web-chain"
    )
    # Making a service that exists only enters it.
    assert _lines("service", "", "create", {"service": "firewall", SERVICE_IN_USE: "yes"}) == (
        "epbr service firewall",
    )


@pytest.mark.parametrize(
    ("scope", "setting", "action", "ident", "values", "message"),
    [
        ("service", "probe_icmp", "set", {"service": "f", SERVICE_IN_USE: "yes"}, {}, "probe"),
        ("service", "", "delete", {"service": "f", SERVICE_IN_USE: "yes"}, {}, "uses this service"),
        ("policy", "statistics", "set", {"policy": "p", POLICY_APPLIED: "yes"}, {}, "counting"),
        ("policy", "", "delete", {"policy": "p", POLICY_APPLIED: "yes"}, {}, "applied"),
        ("service", "probe_http", "set", {"service": "f"}, {"page": "x", "frequency": "30"}, "60"),
        ("service", "probe_http", "set", {"service": "f"}, {"page": "a b"}, "Page"),
        ("service", "probe_icmp", "set", {"service": "f"}, {"down": "6"}, "Failures"),
        ("service", "vrf", "set", {"service": "f"}, {"vrf": "default"}, "Remove goes back"),
        (
            "match",
            "load_balance",
            "set",
            {"policy": "p", "family": "ip", "acl": "a"},
            {"buckets": "7"},
            "Buckets",
        ),  # fmt: skip
        (
            "match",
            "load_balance",
            "set",
            {"policy": "p", "family": "ip", "acl": "a"},
            {},
            "buckets, the method",
        ),  # fmt: skip
        (
            "endpoint",
            "",
            "create",
            {"service": "f", "family": "ip", "address": "2001:db8::1"},
            {},
            "pick ipv6",
        ),  # fmt: skip
        (
            "endpoint",
            "",
            "create",
            {"service": "f", "address": "1.1.1.1", "interface": "loopback0"},
            {},
            "Interface",
        ),  # fmt: skip
    ],
)
def test_wrong_changes_are_refused(
    scope: str, setting: str, action: str, ident: dict, values: dict, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        build_epbr_change(scope, setting, action, ident, values)


def test_the_broad_role_allows_clearing() -> None:
    assert set(EPBR_CLEAR_RULES) <= set(BROAD_RULES)


# ---- the page -----------------------------------------------------------------------------


def _seed(fake: FakeSwitch) -> None:
    """The fake's ePBR state, as in the recorded configuration."""
    fake.tracks[250] = ["interface Ethernet1/53 line-protocol"]
    fake.epbr_services = {
        "firewall": {
            "lines": ["service-interface Vlan250"],
            "probe": "probe icmp retry-down-count 5",
            "endpoints": {
                ("ip", "198.51.100.10"): {
                    "interface": "Vlan250",
                    "probe": "probe track 250",
                    "reverse": {
                        "family": "ip",
                        "address": "198.51.100.20",
                        "interface": "Vlan250",
                        "probe": "probe track 250",
                    },
                },
            },
        },
        "cache": {"lines": [], "probe": "", "endpoints": {}},
    }
    fake.epbr_policies = {
        "web-chain": {
            "statistics": True,
            "matches": {
                ("ip", "web"): {
                    "load_balance": "load-balance method dst-ip",
                    "steps": {10: ("firewall", "drop")},
                }
            },
        },
    }
    fake.epbr_applied = {
        "Vlan251": ["epbr ip policy web-chain", "epbr ip policy web-chain reverse"]
    }


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
    fake.feature_state.update({"epbr": True, "interface-vlan": True})
    fake.svis = {250, 251}
    fake.port_state["Vlan250"] = {"routed": True, "admin_up": True}
    fake.port_state["Vlan251"] = {"routed": True, "admin_up": True}
    _seed(fake)
    fake.bodies.update(
        {
            "show epbr policy": POLICY,
            "show epbr policy web-chain reverse": POLICY_REVERSE,
            "show epbr statistics policy web-chain": STATISTICS,
            "show epbr statistics policy web-chain reverse": STATISTICS_REVERSE,
        }
    )
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
    return client.post("/epbr/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/epbr", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/epbr"' in logged_in.get("/").text


def test_page_reads_the_switch(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/epbr")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "198.51.100.10 in firewall" in text and "Vlan251" in text
    assert "10 firewall" in text and "IP SLA entries (from 20001)" in text
    assert enabled.requests == [
        list(PAGE_COMMANDS),
        list(COMMANDS),
        ["show running-config"],
        ["show epbr policy web-chain reverse"],
        ["show epbr statistics policy web-chain"],
        ["show epbr statistics policy web-chain reverse"],
    ]
    assert "/epbr/change" in page.text


def test_with_epbr_off_the_page_says_so(logged_in: TestClient, switch: FakeSwitch) -> None:
    switch.feature_state["epbr"] = False
    text = _text(logged_in.get("/epbr").text)
    assert "epbr is off on the switch" in text
    assert switch.requests == [list(PAGE_COMMANDS)]


def test_a_service_not_in_use_is_changed_as_usual(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    fields = {"scope": "endpoint", "action": "create", "id_service": "cache"}
    asked = _change(logged_in, confirm=False, id_address="198.51.100.30", **fields)
    assert "service-end-point ip 198.51.100.30" in _text(asked.text)
    assert _config_requests(enabled) == []
    done = _change(logged_in, id_address="198.51.100.30", id_interface="Vlan250", **fields)
    assert done.status_code == 200, _text(done.text)
    probe = _change(
        logged_in,
        scope="service",
        setting="probe_tcp",
        action="set",
        id_service="cache",
        v_port="80",
        v_frequency="10",
    )
    assert probe.status_code == 200, _text(probe.text)
    assert _config_requests(enabled) == [
        ["epbr service cache", "service-end-point ip 198.51.100.30 interface Vlan250"],
        ["epbr service cache", "probe tcp 80 frequency 10"],
    ]
    cache = enabled.epbr_services["cache"]
    assert cache["probe"] == "probe tcp 80 frequency 10"
    assert cache["endpoints"][("ip", "198.51.100.30")]["interface"] == "Vlan250"
    assert "198.51.100.30 in cache" in _text(probe.text)


def test_a_service_in_use_is_changed_in_a_session(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    done = _change(
        logged_in,
        scope="endpoint",
        action="create",
        id_service="firewall",
        id_address="198.51.100.13",
        id_interface="Vlan250",
    )
    assert done.status_code == 200, _text(done.text)
    assert _config_requests(enabled) == [
        [
            "epbr session",
            "epbr service firewall",
            "service-end-point ip 198.51.100.13 interface Vlan250",
            "commit",
        ]
    ]
    assert ("ip", "198.51.100.13") in enabled.epbr_services["firewall"]["endpoints"]
    assert not enabled.epbr_session_open
    step = _change(
        logged_in,
        scope="step",
        action="create",
        id_policy="web-chain",
        id_family="ip",
        id_acl="web",
        id_seq="20",
        id_service="firewall",
        id_fail="bypass",
    )
    assert step.status_code == 200, _text(step.text)
    assert _config_requests(enabled)[-1][-2:] == [
        "20 set service firewall fail-action bypass",
        "commit",
    ]


def test_what_a_session_does_not_take_is_refused_before_sending(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    refused = _change(
        logged_in, scope="service", setting="probe_icmp", action="set", id_service="firewall"
    )
    assert refused.status_code == 400
    assert "take that policy off its interfaces first" in _text(refused.text)
    assert _config_requests(enabled) == []


def test_a_refused_session_line_is_aborted(logged_in: TestClient, enabled: FakeSwitch) -> None:
    refused = _change(
        logged_in,
        scope="endpoint",
        setting="probe_track",
        action="set",
        id_service="firewall",
        id_address="198.51.100.10",
        id_interface="Vlan250",
        v_track="99",
    )
    assert refused.status_code == 400 and "Track object does not exist" in _text(refused.text)
    assert _config_requests(enabled)[-1] == ["epbr session", "abort"]
    assert not enabled.epbr_session_open
    assert enabled.epbr_services["firewall"]["endpoints"][("ip", "198.51.100.10")]["probe"] == (
        "probe track 250"
    )


def test_applying_a_policy(logged_in: TestClient, enabled: FakeSwitch) -> None:
    done = _change(
        logged_in,
        scope="interface",
        setting="policy",
        action="remove",
        id_interface="Vlan251",
        v_map="web-chain",
    )
    assert done.status_code == 200, _text(done.text)
    assert enabled.epbr_applied["Vlan251"] == ["epbr ip policy web-chain reverse"]
    refused = _change(
        logged_in,
        scope="interface",
        setting="policy",
        action="set",
        id_interface="loopback0",
        v_map="web-chain",
    )
    assert refused.status_code == 400 and "is not a VLAN interface" in _text(refused.text)


def test_clearing_is_typed_outside_configuration_mode(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    done = _change(
        logged_in, scope="counters", setting="clear", action="set", id_policy="web-chain"
    )
    assert done.status_code == 200, _text(done.text)
    assert enabled.epbr_cleared == ["clear epbr statistics policy web-chain"]


def test_a_broad_role_written_before_clearing_is_refused_until_updated(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    for rule in EPBR_CLEAR_RULES:
        enabled.roles[ROLE_NAME].entities.discard(rule.split(" command ", 1)[1])
    _db(settings, f"UPDATE switch_connection SET role_version = {BROAD_EPBR_VERSION - 1}")
    refused = _change(
        logged_in, scope="counters", setting="clear", action="set", id_policy="web-chain"
    )
    assert refused.status_code == 400 and "Update the port list" in _text(refused.text)
    assert _config_requests(enabled) == []
    assert "allowed clearing ePBR's counters" in _text(logged_in.get("/switch").text)
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
    assert "The role now also allows clearing ePBR's counters" in _text(updated.text)
    _db(settings, f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    done = _change(
        logged_in, scope="counters", setting="clear", action="set", id_policy="web-chain"
    )
    assert done.status_code == 200, _text(done.text)


def test_with_the_admin_login_stored_the_change_is_sent_with_it(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "stored")
    done = _change(logged_in, scope="service", action="create", id_service="ips")
    assert done.status_code == 200, _text(done.text)
    assert "admin" in switch.signed_in and "ips" in switch.epbr_services


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    refused = _change(logged_in, scope="service", action="create", id_service="ips")
    assert refused.status_code == 400
    assert "Enhanced policy-based routing changes are off" in _text(refused.text)
    assert _config_requests(switch) == []


def test_a_viewer_looks_only(logged_in: TestClient, enabled: FakeSwitch) -> None:
    password = "another-long-password"
    logged_in.post(
        "/users/create",
        data={
            "csrf": _csrf(logged_in, "/users"),
            "new_username": "vera",
            "password": password,
            "confirm_password": password,
            "role": "viewer",
        },
    )
    vera = TestClient(logged_in.app, follow_redirects=False)
    vera.post("/login", data={"username": "vera", "password": password, "next": "/"})
    page = vera.get("/epbr")
    assert page.status_code == 200 and "198.51.100.10 in firewall" in _text(page.text)
    assert "/epbr/change" not in page.text
    refused = vera.post("/epbr/change", data={"csrf": _csrf(vera), "scope": "service"})
    assert refused.status_code in (303, 403)
    assert _config_requests(enabled) == []


def test_save_config_comes_back_here(logged_in: TestClient, enabled: FakeSwitch) -> None:
    saved = logged_in.post("/switch/save", data={"csrf": _csrf(logged_in), "back": "epbr"})
    assert saved.status_code == 200
    assert "Make a service" in _text(saved.text) and enabled.saved
