"""The VXLAN tunnel encryption page (#95), end to end against the fake switch, and its
parsers."""

from __future__ import annotations

import html
import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.tunnel_encryption import (
    NOT_THIS_MODEL,
    PAGE_COMMANDS,
    build_tunnel_encryption_change,
    model_note,
    parse_info,
    parse_key_chains,
    parse_policies,
    parse_sessions,
    parse_tunnel_encryption,
    parse_tunnel_encryption_config,
)
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch

FIXTURES = Path(__file__).parent / "fixtures"

# Laid out as cisco-25gb printed a tunnel encryption key chain (2026-11-13; the encrypted
# strings made up), after a plain key chain to be skipped.
KEYS = (FIXTURES / "show_key_chain_tunnel_encryption.txt").read_text()
# Laid out as in Cisco's NX-OS 9.3 VXLAN guide: cisco-25gb refuses the feature.
SESSIONS = (FIXTURES / "show_tunnel_encryption_session_doc.txt").read_text()
SESSIONS_PKI = (FIXTURES / "show_tunnel_encryption_session_pki_doc.txt").read_text()
POLICIES = (FIXTURES / "show_tunnel_encryption_policy_doc.txt").read_text()
INFO = (FIXTURES / "show_tunnel_encryption_info_global_doc.txt").read_text()
CONFIG = (FIXTURES / "show_running_config_tunnel_encryption_doc.txt").read_text()
KEY_256 = "ab" * 32
KEY_128 = "cd" * 16


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


def _lines(scope, setting, action, ident=None, values=None):
    return list(
        build_tunnel_encryption_change(scope, setting, action, ident or {}, values or {}).lines
    )


# ---- parsing and lines ----------------------------------------------------------------------


def test_the_key_chains_are_read_without_their_strings():
    chains, keys = parse_key_chains(KEYS)
    assert chains == ["nxprobe-te"]
    assert [(k.key, k.algorithm, k.has_string) for k in keys] == [
        ("2006", "AES_256_CMAC", True),
        ("abcd12", "AES_128_CMAC", True),
        ("1111", "", False),
    ]
    assert keys[0].lifetime == "local (00:00:00 May 06 2026)-(always valid) [active]"
    assert "075f79696a58" not in repr(keys)
    assert parse_key_chains(None) == ([], [])


def test_the_show_commands_are_read():
    assert parse_sessions(SESSIONS) == [
        ("33.1.33.33", "p1", "kc1", "Secure (AN: 0)", "Secure (AN: 2)"),
        ("44.1.44.44", "p1", "kc1", "Secure (AN: 0)", "Secure (AN: 0)"),
    ]
    assert parse_sessions(SESSIONS_PKI) == [
        ("20.20.20.2", "p1", "PKI: myCA (RSA)", "Secure (AN: 0)", "Secure (AN: 0)")
    ]
    assert parse_policies(POLICIES)[1] == ("p1", "GCM-AES-XPN-256", "1073741823", "")
    info = parse_info(INFO)
    assert info["Global Policy Mode"] == "Must-Secure" and info["No. of Active Peers"] == "1"


def test_the_configuration_is_read():
    found = parse_tunnel_encryption_config(CONFIG)
    assert found.switch == {"source_interface": {"source": "loopback4"}, "must_secure": {}}
    assert found.policies == {
        "p1": {"window_size": {"packets": "1073741823"}, "sak_rekey_time": {"seconds": "1800"}}
    }
    assert found.peers["192.0.2.11"] == {"keychain_policy": {"chain": "kc1", "policy": "p1"}}
    assert found.peers["192.0.2.12"] == {"pki_policy": {"policy": "p1"}}
    assert found.interfaces == ("Ethernet1/49",)


def test_the_page_view():
    view = parse_tunnel_encryption(CONFIG, KEYS, SESSIONS, POLICIES, INFO)
    facts = dict(view.of("global")[0].facts)
    assert facts["Mode"] == "Must-Secure" and facts["Source loopback"] == "loopback4"
    assert facts["Encrypted traffic only"] == "yes" and facts["Integrity check"] == "no"
    assert [i.title for i in view.of("peer")] == ["192.0.2.11", "192.0.2.12"]
    assert dict(view.of("peer")[1].facts)["Uses"] == "certificates, policy p1"
    assert [i.title for i in view.of("key")][0] == "nxprobe-te key 2006"
    assert "did not show its configuration" in parse_tunnel_encryption(None).notes[0]


def test_the_model_note():
    assert model_note({"chassis_id": "Nexus9000 C92160YC-X chassis"}) == NOT_THIS_MODEL
    assert model_note({"chassis_id": "Nexus9000 C93240YC-FX2 Chassis"}) == ""
    assert model_note({}) == ""


def test_the_lines():
    chain = {"chain": "kc1"}
    assert _lines("key_chain", "", "create", chain) == ["key chain kc1 tunnel-encryption"]
    assert _lines("key_chain", "", "delete", chain) == ["no key chain kc1 tunnel-encryption"]
    key = {"chain": "kc1", "key": "20AB"}
    assert _lines("key", "", "create", key) == ["key chain kc1 tunnel-encryption", "key 20ab"]
    made = build_tunnel_encryption_change(
        "key", "octet_string", "set", key, {"octets": KEY_256, "algorithm": "AES_256_CMAC"}
    )
    assert made.lines[-1] == f"key-octet-string {KEY_256} cryptographic-algorithm AES_256_CMAC"
    assert KEY_256 not in " ".join(made.labels) and KEY_256 not in made.describe
    assert _lines("key", "octet_string", "remove", key)[-1] == "no key-octet-string"
    lifetime = _lines(
        "key",
        "send_lifetime_duration",
        "set",
        key,
        {
            "start_hour": "00",
            "start_minute": "00",
            "start_second": "00",
            "start_month": "May",
            "start_day": "6",
            "start_year": "2026",
            "duration": "1800",
        },
    )
    assert lifetime[-1] == "send-lifetime 00:00:00 May 6 2026 duration 1800"
    assert _lines("global", "source_interface", "set", values={"source": "lo4"}) == [
        "tunnel-encryption source-interface loopback4"
    ]
    assert _lines("policy", "window_size", "set", {"policy": "p1"}, {"packets": "134217728"}) == [
        "tunnel-encryption policy p1",
        "window-size 134217728",
    ]
    assert _lines(
        "peer", "keychain_policy", "set", {"peer": "192.0.2.11"}, {"chain": "kc1", "policy": "p1"}
    ) == ["tunnel-encryption peer-ip 192.0.2.11", "keychain kc1 policy p1"]
    assert _lines("interface", "encrypt", "set", {"interface": "Ethernet1/49"}) == [
        "interface Ethernet1/49",
        "tunnel-encryption",
    ]


def test_values_are_refused_before_anything_is_sent():
    key = {"chain": "kc1", "key": "2006"}
    with pytest.raises(ValueError, match="64 hexadecimal digits"):
        build_tunnel_encryption_change(
            "key", "octet_string", "set", key, {"octets": KEY_128, "algorithm": "AES_256_CMAC"}
        )
    with pytest.raises(ValueError, match="even number of hexadecimal digits"):
        build_tunnel_encryption_change("key", "", "create", {"chain": "kc1", "key": "123"}, {})
    with pytest.raises(ValueError, match="1800 to"):
        build_tunnel_encryption_change(
            "key",
            "send_lifetime_duration",
            "set",
            key,
            {
                "start_hour": "00",
                "start_minute": "00",
                "start_second": "00",
                "start_month": "May",
                "start_day": "6",
                "start_year": "2026",
                "duration": "100",
            },
        )
    with pytest.raises(ValueError, match="loopback"):
        build_tunnel_encryption_change(
            "global", "source_interface", "set", {}, {"source": "Vlan10"}
        )
    with pytest.raises(ValueError, match="134217728 to"):
        build_tunnel_encryption_change(
            "policy", "window_size", "set", {"policy": "p1"}, {"packets": "5"}
        )


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


@pytest.fixture
def supported(enabled: FakeSwitch) -> FakeSwitch:
    """A switch that does tunnel encryption (a Nexus 9300-FX2), with it on."""
    enabled.tunnel_encryption_supported = True
    enabled.feature_state["tun_enc_mgr"] = True
    enabled.texts["show tunnel-encryption session"] = SESSIONS
    enabled.texts["show tunnel-encryption policy"] = POLICIES
    enabled.texts["show tunnel-encryption info global"] = INFO
    enabled.requests.clear()
    return enabled


def _change(client: TestClient, confirm: bool = True, **fields):
    data = {"csrf": _csrf(client), **fields}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/tunnel-encryption/change", data=data)


def test_page_needs_login(client: TestClient) -> None:
    assert client.get("/tunnel-encryption", follow_redirects=False).status_code == 303


def test_menu_links_to_the_page(logged_in: TestClient) -> None:
    assert 'href="/tunnel-encryption"' in logged_in.get("/").text


def test_on_this_model_the_page_says_it_cannot(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    # The limited role has the Features page's rules.
    _enable(logged_in, settings, switch, "limited")
    text = _text(logged_in.get("/tunnel-encryption").text)
    assert "does not do VXLAN tunnel encryption" in text
    assert "tunnel-encryption is off on the switch" in text
    refused = logged_in.post(
        "/features/set",
        data={"csrf": _csrf(logged_in), "name": "tun_enc_mgr", "state": "on", "confirm": "yes"},
    )
    assert "cannot be enabled on this system" in _text(refused.text)
    assert not switch.feature_state.get("tun_enc_mgr")


def test_page_reads_the_switch(logged_in: TestClient, supported: FakeSwitch) -> None:
    page = logged_in.get("/tunnel-encryption")
    assert page.status_code == 200, _text(page.text)
    text = _text(page.text)
    assert "Must-Secure" in text and "33.1.33.33" in text and "system-default-tunenc-policy" in text
    assert supported.requests == [
        list(PAGE_COMMANDS),
        ["show running-config"],
        ["show key chain"],
        ["show tunnel-encryption session"],
        ["show tunnel-encryption policy"],
        ["show tunnel-encryption info global"],
    ]


def test_a_key_is_set_without_showing_it(logged_in: TestClient, supported: FakeSwitch) -> None:
    made = _change(logged_in, scope="key_chain", action="create", id_chain="kc1")
    assert made.status_code == 200, _text(made.text)
    key = _change(logged_in, scope="key", action="create", id_chain="kc1", id_key="2006")
    assert key.status_code == 200, _text(key.text)
    fields = dict(
        scope="key",
        setting="octet_string",
        action="set",
        id_chain="kc1",
        id_key="2006",
        v_octets=KEY_256,
        v_algorithm="AES_256_CMAC",
    )
    asked = _change(logged_in, confirm=False, **fields)
    assert KEY_256 not in _text(asked.text) and "key-octet-string ***" in _text(asked.text)
    done = _change(logged_in, **fields)
    assert done.status_code == 200, _text(done.text)
    assert KEY_256 not in done.text and "kc1 key 2006" in _text(done.text)
    assert supported.te_key_strings[("kc1", "2006")] == KEY_256
    again = _change(logged_in, **fields)
    assert again.status_code == 400 and "Overwriting" in _text(again.text)
    assert KEY_256 not in again.text
    wrong = _change(logged_in, **{**fields, "v_octets": KEY_128})
    assert wrong.status_code == 400 and "64 hexadecimal digits" in _text(wrong.text)
    assert KEY_128 not in wrong.text
    long = _change(logged_in, **{**fields, "v_octets": KEY_256 + "ab"})
    assert long.status_code == 400 and KEY_256 not in long.text


def test_policy_peer_and_link(logged_in: TestClient, supported: FakeSwitch) -> None:
    supported.port_state["Ethernet1/49"] = {"routed": True}
    for fields in (
        dict(scope="policy", action="create", id_policy="p1"),
        dict(
            scope="policy",
            setting="cipher_suite",
            action="set",
            id_policy="p1",
            v_cipher="GCM-AES-XPN-128",
        ),
        dict(scope="peer", action="create", id_peer="192.0.2.11"),
        dict(
            scope="peer",
            setting="keychain_policy",
            action="set",
            id_peer="192.0.2.11",
            v_chain="kc1",
            v_policy="p1",
        ),
        dict(scope="global", setting="must_secure", action="set"),
    ):
        done = _change(logged_in, **fields)
        assert done.status_code == 200, _text(done.text)
    assert "tunnel-encryption policy p1 ; cipher-suite GCM-AES-XPN-128" in supported.te_lines
    assert "tunnel-encryption peer-ip 192.0.2.11 ; keychain kc1 policy p1" in supported.te_lines
    assert "tunnel-encryption must-secure-policy" in supported.te_lines
    vlan = _change(
        logged_in, scope="interface", setting="encrypt", action="set", id_interface="Vlan10"
    )
    assert vlan.status_code == 400 and "not a VLAN" in _text(vlan.text)


def test_changes_are_off_in_the_limited_role(
    logged_in: TestClient, switch: FakeSwitch, settings: Settings
) -> None:
    _enable(logged_in, settings, switch, "limited")
    switch.tunnel_encryption_supported = True
    switch.feature_state["tun_enc_mgr"] = True
    refused = _change(logged_in, scope="policy", action="create", id_policy="p1")
    assert refused.status_code == 400
    assert "VXLAN tunnel encryption changes are off" in _text(refused.text)
    assert _config_requests(switch) == []


def test_save_config_comes_back_here(logged_in: TestClient, supported: FakeSwitch) -> None:
    saved = logged_in.post(
        "/switch/save", data={"csrf": _csrf(logged_in), "back": "tunnel-encryption"}
    )
    assert saved.status_code == 200
    assert "Make a key chain" in _text(saved.text) and supported.saved
