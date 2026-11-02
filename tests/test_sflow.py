"""The sFlow collector: decoding datagrams, adding samples up, storing and
reading them back, the listener, the switch side and the Traffic page.

Datagrams are built here by ``_datagram``, after sflow.org's sFlow version 5
specification; no switch output is recorded."""

from __future__ import annotations

import ipaddress
import re
import socket
import sqlite3
import struct
import threading
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import ConfigError, Settings, load_settings
from app.db import init_db, open_db
from app.neighbors import PortChannel
from app.nxapi import (
    NxapiClient,
    SwitchTarget,
    sflow_data_source,
    validate_sflow_address,
    validate_sflow_vrf,
)
from app.port_changes import TRAFFIC_RULES, role_lines
from app.ports import parse_ports
from app.sflow import (
    MAC_RECEIVES,
    MAC_SENDS,
    MAX_DEVICES_PER_MINUTE,
    OTHER,
    UNKNOWN_VLAN,
    VLAN,
    SflowCollector,
    SflowError,
    SflowRow,
    agent_addresses,
    decode_datagram,
    item_series,
    latest_minute,
    minute_rows,
    parse_frame_header,
    purge_sflow,
    run_collector,
    sflow_charts,
    start_collector,
    store_rows,
    top_items,
)
from app.sflow_switch import SflowConfig, parse_sflow_text, plan_sflow, sflow_form
from app.switch_connection import delete_connection
from tests.conftest import load_fixture
from tests.fake_switch import ADMIN_PASSWORD, FakeSwitch
from tests.fake_switch import _error as fake_error

AGENT = "192.0.2.10"
SERVER = "02:00:00:00:00:01"
CLIENT = "02:00:00:00:00:02"
BROADCAST = "ff:ff:ff:ff:ff:ff"


# ---- building datagrams -------------------------------------------------------


def _u32(*values: int) -> bytes:
    return struct.pack(f">{len(values)}I", *values)


def _opaque(data: bytes) -> bytes:
    return data + b"\0" * ((4 - len(data) % 4) % 4)


def _mac(text: str) -> bytes:
    return bytes(int(part, 16) for part in text.split(":"))


def _frame(
    src: str = SERVER,
    dst: str = CLIENT,
    vlan: int | None = None,
    src_ip: str = "198.51.100.1",
    dst_ip: str = "198.51.100.2",
) -> bytes:
    head = _mac(dst) + _mac(src)
    if vlan is not None:
        head += struct.pack(">HH", 0x8100, vlan)
    if ":" in src_ip:
        ip = b"\x60" + b"\0" * 7 + ipaddress.IPv6Address(src_ip).packed
        ip += ipaddress.IPv6Address(dst_ip).packed
        return head + struct.pack(">H", 0x86DD) + ip
    ip = b"\x45" + b"\0" * 11 + ipaddress.IPv4Address(src_ip).packed
    ip += ipaddress.IPv4Address(dst_ip).packed
    return head + struct.pack(">H", 0x0800) + ip


def _record(record_format: int, body: bytes) -> bytes:
    return _u32(record_format, len(body)) + body


def _raw_header(frame: bytes, length: int = 1500) -> bytes:
    return _record(1, _u32(1, length, 4, len(frame)) + _opaque(frame))


def _switch_record(vlan: int) -> bytes:
    return _record(1001, _u32(vlan, 0, vlan, 0))


def _flow_sample(records: list[bytes], rate: int = 4096, expanded: bool = False) -> bytes:
    if expanded:
        head = _u32(7, 0, 5, rate, 1000, 0, 0, 5, 0, 6)
    else:
        head = _u32(7, 5, rate, 1000, 0, 5, 6)
    body = head + _u32(len(records)) + b"".join(records)
    return _u32(3 if expanded else 1, len(body)) + body


def _counter_sample() -> bytes:
    body = _u32(1, 5, 0)
    return _u32(2, len(body)) + body


def _datagram(samples: list[bytes], agent: str = AGENT, version: int = 5) -> bytes:
    address = ipaddress.ip_address(agent)
    kind = 1 if address.version == 4 else 2
    return (
        _u32(version, kind) + address.packed + _u32(0, 42, 123456, len(samples)) + b"".join(samples)
    )


def _one(vlan: int = 10, size: int = 1500, src: str = SERVER, dst: str = CLIENT) -> bytes:
    return _datagram([_flow_sample([_raw_header(_frame(src, dst), size), _switch_record(vlan)])])


# ---- decoding -----------------------------------------------------------------


def test_a_flow_sample_with_its_header_and_vlan() -> None:
    datagram = decode_datagram(
        _datagram(
            [
                _flow_sample([_raw_header(_frame(vlan=30), 1000), _switch_record(10)]),
                _counter_sample(),
            ]
        )
    )
    assert datagram.agent == AGENT and datagram.sequence == 42
    assert datagram.counter_samples == 1
    (sample,) = datagram.samples
    # The switch's own record wins over the tag in the header.
    assert sample.vlan == 10
    assert (sample.src_mac, sample.dst_mac) == (SERVER, CLIENT)
    assert (sample.src_ip, sample.dst_ip) == ("198.51.100.1", "198.51.100.2")
    assert sample.sampling_rate == 4096 and sample.input_index == 5
    assert sample.estimated_bytes == 1000 * 4096


def test_an_expanded_sample_with_a_tagged_header_only() -> None:
    sample = decode_datagram(
        _datagram([_flow_sample([_raw_header(_frame(vlan=20))], rate=8192, expanded=True)])
    ).samples[0]
    assert sample.vlan == 20 and sample.sampling_rate == 8192 and sample.input_index == 5


def test_an_untagged_sample_without_the_switch_record_has_no_vlan() -> None:
    sample = decode_datagram(_datagram([_flow_sample([_raw_header(_frame())])])).samples[0]
    assert sample.vlan == 0


def test_an_ethernet_frame_record() -> None:
    record = _record(2, _u32(800) + _opaque(_mac(SERVER)) + _opaque(_mac(CLIENT)) + _u32(0x800))
    sample = decode_datagram(_datagram([_flow_sample([record])])).samples[0]
    assert (sample.frame_length, sample.src_mac, sample.dst_mac) == (800, SERVER, CLIENT)


def test_ipv6_frames_and_an_ipv6_agent() -> None:
    frame = _frame(src_ip="2001:db8::1", dst_ip="2001:db8::2")
    datagram = decode_datagram(
        _datagram([_flow_sample([_raw_header(frame)])], agent="2001:db8::10")
    )
    assert datagram.agent == "2001:db8::10"
    assert datagram.samples[0].src_ip == "2001:db8::1"


def test_a_short_header_gives_what_it_has() -> None:
    assert parse_frame_header(b"\x01\x02") == {}
    found = parse_frame_header(_frame()[:14])
    assert found == {"dst_mac": CLIENT, "src_mac": SERVER}


@pytest.mark.parametrize(
    "data",
    [
        b"",
        _datagram([], version=4),
        _one()[:-3],
        _u32(5, 9) + b"\0" * 20,
        _datagram([_u32(1, 10_000)]),
    ],
)
def test_damaged_datagrams_are_refused(data: bytes) -> None:
    with pytest.raises(SflowError):
        decode_datagram(data)


def test_a_sample_with_too_many_records_is_refused() -> None:
    body = _u32(7, 5, 4096, 1000, 0, 5, 6, 10_000)
    with pytest.raises(SflowError):
        decode_datagram(_datagram([_u32(1, len(body)) + body]))


def test_another_makers_samples_are_skipped() -> None:
    body = _u32(1, 2, 3)
    other = _u32((9 << 12) | 1, len(body)) + body
    assert decode_datagram(_datagram([other])).samples == ()


# ---- adding up ----------------------------------------------------------------


def test_only_known_switches_are_counted() -> None:
    collector = SflowCollector()
    assert collector.receive(_one(), now=60.0) == 0
    assert collector.unknown_agents() == [(AGENT, 60.0)]
    collector.set_agents({AGENT: 1})
    assert collector.receive(_one(), now=61.0) == 1
    status = collector.status(1)
    assert status and status.samples == 1 and status.sampling_rate == 4096
    assert collector.status(2) is None


def test_a_damaged_datagram_is_counted_as_such() -> None:
    collector = SflowCollector()
    collector.set_agents({AGENT: 1})
    assert collector.receive(b"\0\0\0\5garbage", now=60.0) == 0
    assert collector.malformed == 1


def test_minutes_are_handed_out_once_they_are_over() -> None:
    collector = SflowCollector()
    collector.set_agents({AGENT: 1})
    collector.receive(_one(vlan=10, size=1000), now=60.0)
    collector.receive(_one(vlan=10, size=500), now=70.0)
    collector.receive(_one(vlan=20, dst=BROADCAST), now=119.0)
    assert collector.drain(now=119.5) == []
    rows = {(r.kind, r.item): r for r in collector.drain(now=120.0)}
    assert rows[(VLAN, "10")].bytes == 1500 * 4096 and rows[(VLAN, "10")].samples == 2
    assert rows[(MAC_SENDS, SERVER)].samples == 3
    # Broadcast is no one device's.
    assert rows[(MAC_RECEIVES, CLIENT)].samples == 2
    assert (MAC_RECEIVES, BROADCAST) not in rows
    assert all(r.minute == 60 for r in rows.values())
    assert collector.drain(now=500.0) == []


def test_everything_is_handed_out_at_shutdown() -> None:
    collector = SflowCollector()
    collector.set_agents({AGENT: 1})
    collector.receive(_one(vlan=0), now=60.0)
    rows = collector.drain(now=61.0, everything=True)
    assert (VLAN, UNKNOWN_VLAN) in {(r.kind, r.item) for r in rows}


def test_a_minute_keeps_every_vlan_and_the_busiest_devices() -> None:
    totals = {(MAC_SENDS, f"02:00:00:00:{n // 256:02x}:{n % 256:02x}"): [n, 1] for n in range(150)}
    totals[(VLAN, "10")] = [5, 1]
    rows = minute_rows(1, 60, totals)
    sends = [r for r in rows if r.kind == MAC_SENDS]
    assert len(sends) == MAX_DEVICES_PER_MINUTE + 1
    other = next(r for r in sends if r.item == OTHER)
    assert other.bytes == sum(range(50)) and other.samples == 50
    assert [r.item for r in rows if r.kind == VLAN] == ["10"]


def test_which_address_is_which_switch() -> None:
    found = agent_addresses(
        [(1, "192.0.2.10", ""), (2, "switch.example", "198.51.100.20"), (3, "nexus.lan", "")]
    )
    assert found == {"192.0.2.10": 1, "198.51.100.20": 2}


# ---- the table ----------------------------------------------------------------


@pytest.fixture
def db(tmp_path) -> sqlite3.Connection:
    path = tmp_path / "nxray.db"
    init_db(path)
    with open_db(path) as conn:
        yield conn


def _rows(minute: int, vlan_bytes: dict[str, int]) -> list[SflowRow]:
    return [SflowRow(1, minute, VLAN, item, size, 1) for item, size in vlan_bytes.items()]


def test_rows_add_up_and_read_back(db: sqlite3.Connection) -> None:
    store_rows(db, _rows(60, {"10": 600, "20": 60}))
    store_rows(db, _rows(60, {"10": 600}))
    store_rows(db, _rows(120, {"10": 1200}))
    top = top_items(db, 1, VLAN, start=60, end=180)
    assert [(t.item, t.bytes, t.samples) for t in top] == [("10", 2400, 3), ("20", 60, 1)]
    assert top[0].bits_per_second == 2400 * 8 // 120
    assert top_items(db, 2, VLAN, start=60, end=180) == []
    assert latest_minute(db, 1) == 120 and latest_minute(db, 2) is None


def test_series_are_bits_per_second_with_quiet_minutes_as_zero(db: sqlite3.Connection) -> None:
    store_rows(db, _rows(60, {"10": 600}) + _rows(180, {"10": 1200}))
    series = item_series(db, 1, VLAN, ["10", "30"], start=0, end=300, bucket=60)
    assert series["10"] == [(90.0, 80.0), (150.0, 0.0), (210.0, 160.0)]
    assert series["30"] == []


def test_old_rows_are_purged(db: sqlite3.Connection) -> None:
    store_rows(db, _rows(60, {"10": 1}) + _rows(10 * 86400, {"10": 1}))
    assert purge_sflow(db, 10 * 86400 + 100, keep_days=7) == 1
    assert latest_minute(db, 1) == 10 * 86400


def test_the_charts(db: sqlite3.Connection) -> None:
    now = time.time()
    minute = int(now // 60) * 60 - 120
    store_rows(db, _rows(minute, {"10": 6000}))
    store_rows(db, [SflowRow(1, minute, MAC_SENDS, SERVER, 3000, 1)])
    vlans, device = sflow_charts(db, 1, "1h", now, mac=SERVER)
    assert vlans.svg is not None and vlans.legend[0].label == "VLAN 10"
    assert device.svg is not None and device.title.startswith(SERVER)
    (only_vlans,) = sflow_charts(db, 1, "1h", now)
    assert only_vlans.anchor == "vlans"


def test_forgetting_a_switch_forgets_its_traffic(db: sqlite3.Connection) -> None:
    store_rows(db, _rows(60, {"10": 1}))
    delete_connection(db, 1)
    assert latest_minute(db, 1) is None


# ---- the listener -------------------------------------------------------------


def test_the_listener_counts_stores_and_stops(tmp_path) -> None:
    path = tmp_path / "nxray.db"
    init_db(path)
    with open_db(path) as conn:
        conn.execute(
            "INSERT INTO switch_connection (host, port, username, password_encrypted, "
            "switch_hostname, created_at, config_saved) VALUES (?, 443, 'nxray', '', '', 0, 1)",
            (AGENT,),
        )
        conn.commit()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.1)
    address = sock.getsockname()
    collector = SflowCollector()
    stop = threading.Event()
    thread = threading.Thread(target=run_collector, args=(sock, collector, path, 7, stop))
    thread.start()
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    deadline = time.time() + 5
    while (collector.status(1) is None) and time.time() < deadline:
        sender.sendto(_one(vlan=10), address)
        time.sleep(0.05)
    sender.close()
    stop.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    with open_db(path) as conn:
        assert top_items(conn, 1, VLAN, start=0, end=time.time() + 60)[0].item == "10"


def test_the_listener_is_off_without_a_port(tmp_path) -> None:
    assert start_collector(0, SflowCollector(), tmp_path / "x.db", 7) is None


def test_a_port_in_use_turns_the_listener_off(tmp_path) -> None:
    taken = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    taken.bind(("0.0.0.0", 0))
    try:
        port = taken.getsockname()[1]
        assert start_collector(port, SflowCollector(), tmp_path / "x.db", 7) is None
    finally:
        taken.close()


def test_the_settings(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("NXRAY_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NXRAY_ADMIN_PASSWORD_HASH", "$argon2id$v=19$m=65536,t=3,p=4$x$y")
    monkeypatch.delenv("NXRAY_SFLOW_PORT", raising=False)
    assert load_settings().sflow_port == 0 and load_settings().sflow_keep_days == 7
    monkeypatch.setenv("NXRAY_SFLOW_PORT", "6343")
    monkeypatch.setenv("NXRAY_SFLOW_KEEP_DAYS", "30")
    assert (load_settings().sflow_port, load_settings().sflow_keep_days) == (6343, 30)
    monkeypatch.setenv("NXRAY_SFLOW_KEEP_DAYS", "365")
    with pytest.raises(ConfigError):
        load_settings()


# ---- the switch side ----------------------------------------------------------


def _recording() -> tuple[list[list[str]], NxapiClient]:
    sent: list[list[str]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        import json

        entries = json.loads(request.content)
        sent.append([entry["params"]["cmd"] for entry in entries])
        replies = [{"jsonrpc": "2.0", "result": None, "id": entry["id"]} for entry in entries]
        return httpx.Response(200, json=replies[0] if len(replies) == 1 else replies)

    target = SwitchTarget("192.0.2.10", 443, "nxray", "pw", 5.0)
    return sent, NxapiClient(target, transport=httpx.MockTransport(handle))


def test_the_client_builds_each_line_from_checked_values() -> None:
    sent, client = _recording()
    client.configure_sflow(
        sampling_rate=4096,
        collector="192.0.2.5",
        vrf="management",
        collector_port=6343,
        agent="192.0.2.10",
        add_ports=["Ethernet1/1", "Ethernet1/50/2"],
        remove_ports=["Ethernet1/3"],
    )
    assert sent == [
        [
            "sflow sampling-rate 4096",
            "sflow collector-ip 192.0.2.5 vrf management",
            "sflow collector-port 6343",
            "sflow agent-ip 192.0.2.10",
            "sflow data-source interface ethernet 1/1",
            "sflow data-source interface ethernet 1/50/2",
            "no sflow data-source interface ethernet 1/3",
        ]
    ]


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"sampling_rate": 1000},
        {"collector": "192.0.2.5"},
        {"collector": "192.0.2.5 vrf x ; shutdown", "vrf": "default"},
        {"collector": "192.0.2.5", "vrf": "all"},
        {"collector_port": 0},
        {"collector_port": 70000},
        {"agent": "switch.example"},
        {"add_ports": ["mgmt0"]},
    ],
)
def test_the_client_refuses_anything_else(kwargs: dict) -> None:
    sent, client = _recording()
    with pytest.raises(ValueError):
        client.configure_sflow(**kwargs)
    assert sent == []


def test_checked_values() -> None:
    assert validate_sflow_address(" 192.0.2.5 ") == "192.0.2.5"
    for bad in ("0.0.0.0", "255.255.255.255", "224.0.0.1", "127.0.0.1", "2001:db8::1", ""):
        with pytest.raises(ValueError):
            validate_sflow_address(bad)
    assert validate_sflow_vrf("Management") == "management"
    assert validate_sflow_vrf("lab") == "lab"
    assert sflow_data_source("Ethernet1/5") == "ethernet 1/5"
    assert sflow_data_source("port-channel41") == "port-channel 41"
    for bad in ("port-channel0", "port-channel41 ; shutdown", "port-channel", "Vlan10"):
        with pytest.raises(ValueError):
            sflow_data_source(bad)


def test_the_client_samples_a_port_channel() -> None:
    sent, client = _recording()
    client.configure_sflow(add_ports=["port-channel41"], remove_ports=["port-channel43"])
    assert sent == [
        [
            "sflow data-source interface port-channel 41",
            "no sflow data-source interface port-channel 43",
        ]
    ]


def test_the_role_has_the_sflow_rules() -> None:
    lines = role_lines(["Ethernet1/1"], "nxray")
    assert "rule 230 permit command conf t ; sflow *" in lines
    assert "rule 231 permit command conf t ; no sflow *" in lines
    assert set(TRAFFIC_RULES) <= set(lines)


SHOW_SFLOW = """sflow sampling-rate : 8192
sflow max-sampled-size : 128
sflow counter-poll-interval : 20
sflow max-datagram-size : 1400
sflow collector-ip : 192.0.2.5 , vrf : management
sflow collector-port : 6343
sflow agent-ip : 192.0.2.10
sflow data-source interface Ethernet1/2
sflow data-source interface Ethernet1/1
sflow data-source interface Ethernet1/10-12
"""


def test_reading_show_sflow() -> None:
    config = parse_sflow_text(SHOW_SFLOW)
    assert config == SflowConfig(
        feature_on=True,
        sampling_rate=8192,
        collector="192.0.2.5",
        collector_vrf="management",
        collector_port=6343,
        agent="192.0.2.10",
        data_sources=(
            "Ethernet1/1",
            "Ethernet1/2",
            "Ethernet1/10",
            "Ethernet1/11",
            "Ethernet1/12",
        ),
    )
    assert config.sending
    bare = parse_sflow_text(
        "sflow collector-ip : 0.0.0.0 , vrf : default\nsflow agent-ip : 0.0.0.0"
    )
    assert bare.collector == "" and bare.agent == "" and not bare.sending


def test_reading_port_channel_sources() -> None:
    config = parse_sflow_text(
        SHOW_SFLOW
        + "sflow data-source interface port-channel43\n"
        + "sflow data-source interface Po41\n"
        + "sflow data-source interface port-channel 0\n"
    )
    assert config.data_sources[-2:] == ("port-channel41", "port-channel43")
    assert config.data_sources[0] == "Ethernet1/1"


CHANNEL = PortChannel("port-channel43", ("Ethernet1/43", "Ethernet1/44"), "LACP", True)


def _front():
    ports = parse_ports(
        load_fixture("show_interface"),
        load_fixture("show_interface_status"),
        load_fixture("show_interface_transceiver"),
    )
    return ports


FORM = {
    "collector": "192.0.2.5",
    "vrf": "management",
    "collector_port": "6343",
    "agent": "192.0.2.10",
    "sampling_rate": "8192",
    "scope": "list",
    "ports": "Ethernet1/1, eth1/2, 1/10-12",
}


def test_planning_from_the_feature_off() -> None:
    plan = plan_sflow(SflowConfig(feature_on=False), _front(), FORM)
    assert plan.turn_on_feature and plan.configures
    assert plan.lines[0] == "Turn on the sflow feature on the switch."
    assert plan.add_ports == (
        "Ethernet1/1",
        "Ethernet1/2",
        "Ethernet1/10",
        "Ethernet1/11",
        "Ethernet1/12",
    )
    assert "Sample 5 ports" in " ".join(plan.lines)


def test_planning_keeps_only_what_changes() -> None:
    current = parse_sflow_text(SHOW_SFLOW)
    assert plan_sflow(current, _front(), FORM).empty
    fewer = plan_sflow(current, _front(), {**FORM, "ports": "Ethernet1/1"})
    assert fewer.add_ports == () and fewer.sampling_rate is None
    assert fewer.remove_ports == ("Ethernet1/2", "Ethernet1/10", "Ethernet1/11", "Ethernet1/12")
    moved = plan_sflow(current, _front(), {**FORM, "agent": "192.0.2.11"})
    assert moved.agent == "192.0.2.11" and any("agent address" in w for w in moved.warnings)
    every = plan_sflow(current, _front(), {**FORM, "scope": "all"})
    assert len(every.add_ports) == len(_front()) - 5


def test_a_port_in_a_port_channel_is_sampled_through_it() -> None:
    off = SflowConfig(feature_on=False, port_channels=(CHANNEL,))
    every = plan_sflow(off, _front(), {**FORM, "scope": "all"})
    assert "port-channel43" in every.add_ports
    assert "Ethernet1/43" not in every.add_ports and "Ethernet1/44" not in every.add_ports
    assert len(every.add_ports) == len(_front()) - 1
    assert any(
        "port-channel43 for Ethernet1/43, Ethernet1/44" in warning for warning in every.warnings
    )
    one = plan_sflow(off, _front(), {**FORM, "ports": "Ethernet1/1, 1/43-44"})
    assert one.add_ports == ("Ethernet1/1", "port-channel43")
    named = plan_sflow(off, _front(), {**FORM, "ports": "po43, 1/1"})
    assert named.add_ports == ("port-channel43", "Ethernet1/1")
    with pytest.raises(ValueError, match="no port-channel41"):
        plan_sflow(off, _front(), {**FORM, "ports": "Po41"})
    current = parse_sflow_text(
        SHOW_SFLOW + "sflow data-source interface port-channel43\n", (CHANNEL,)
    )
    assert plan_sflow(current, _front(), {**FORM, "ports": "1/1-2, 1/10-12, 1/44"}).empty
    dropped = plan_sflow(current, _front(), FORM)
    assert dropped.remove_ports == ("port-channel43",) and dropped.add_ports == ()
    names = [port.name for port in _front()]
    whole = parse_sflow_text(
        "".join(f"sflow data-source interface {n}\n" for n in names if n not in CHANNEL.members)
        + "sflow data-source interface port-channel43\n",
        (CHANNEL,),
    )
    assert plan_sflow(whole, _front(), {**FORM, "scope": "all"}).add_ports == ()
    form = sflow_form(whole, collector="", agent="", port=0, front=names)
    assert form["scope"] == "all" and form["ports"] == ""


@pytest.mark.parametrize(
    ("change", "words"),
    [
        ({"collector": "nxray.example"}, "not an IPv4 address"),
        ({"collector_port": "x"}, "UDP port"),
        ({"sampling_rate": "100"}, "sampling rate"),
        ({"ports": "Ethernet9/99"}, "no front port"),
        ({"ports": "mgmt0"}, "not a front port"),
        ({"ports": ""}, "at least one port"),
        ({"scope": "up"}, "No front port is up"),
        ({"scope": "some"}, "Pick which ports"),
        ({"vrf": "all"}, "keeps the VRF name"),
    ],
)
def test_planning_refuses_a_bad_form(change: dict, words: str) -> None:
    with pytest.raises(ValueError, match=words):
        plan_sflow(SflowConfig(feature_on=False), _front(), {**FORM, **change})


def test_the_form_starts_from_the_switch_or_from_guesses() -> None:
    guessed = sflow_form(
        SflowConfig(feature_on=False), collector="192.0.2.5", agent="192.0.2.10", port=6343
    )
    assert guessed["collector"] == "192.0.2.5" and guessed["scope"] == "all"
    assert guessed["sampling_rate"] == "4096" and guessed["vrf"] == "management"
    current = sflow_form(parse_sflow_text(SHOW_SFLOW), collector="", agent="", port=0)
    assert current["sampling_rate"] == "8192" and current["scope"] == "list"
    assert current["ports"].startswith("Ethernet1/1, Ethernet1/2")
    names = [port.name for port in _front()]
    every = parse_sflow_text("".join(f"sflow data-source interface {n}\n" for n in names))
    whole = sflow_form(every, collector="", agent="", port=0, front=names)
    assert whole["scope"] == "all" and whole["ports"] == ""


# ---- the Traffic page ---------------------------------------------------------


def _csrf(client: TestClient, path: str = "/account") -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', client.get(path).text)
    assert match, f"no csrf field on {path}"
    return match.group(1)


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).replace("&#39;", "'")


def _config_requests(switch: FakeSwitch) -> list[list[str]]:
    return [r for r in switch.requests if not all(cmd.startswith("show ") for cmd in r)]


@pytest.fixture
def enabled(logged_in: TestClient, settings: Settings) -> FakeSwitch:
    fake = FakeSwitch()
    logged_in.app.state.nxapi_transport = fake.transport()  # type: ignore[attr-defined]
    logged_in.app.state.ssh_opener = fake.ssh_opener()  # type: ignore[attr-defined]
    logged_in.post(
        "/switch/setup",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "host": AGENT,
            "port": "443",
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "account_name": "nxray",
            "confirm_save": "yes",
        },
    )
    logged_in.post(
        "/switch/enable-changes",
        data={
            "csrf": _csrf(logged_in, "/switch"),
            "admin_user": "admin",
            "admin_password": ADMIN_PASSWORD,
            "ssh_port": "22",
            "confirm_save": "yes",
        },
    )
    conn = sqlite3.connect(settings.db_path)
    conn.execute(f"UPDATE switch_connection SET paused_until = {time.time() - 1}")
    conn.commit()
    conn.close()
    fake.requests.clear()
    return fake


def _setup(client: TestClient, confirm: bool = False, **change: str):
    data = {"csrf": _csrf(client), **FORM, **change}
    if confirm:
        data["confirm"] = "yes"
    return client.post("/traffic/sflow", data=data)


def test_the_page_says_the_collector_is_off(logged_in: TestClient, enabled: FakeSwitch) -> None:
    page = logged_in.get("/traffic")
    assert page.status_code == 200
    text = _text(page.text)
    assert "NXRAY_SFLOW_PORT is not set" in text
    assert "The sflow feature is off on the switch" in text
    assert "No sFlow samples from this switch in this range." in text
    assert 'action="/traffic/sflow"' in page.text
    assert 'href="/traffic"' in page.text


def test_setting_sflow_up_asks_first_then_sends_it(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    asked = _setup(logged_in)
    assert asked.status_code == 200
    assert "Turn on the sflow feature on the switch." in _text(asked.text)
    assert _config_requests(enabled) == []

    done = _setup(logged_in, confirm=True)
    assert done.status_code == 200, _text(done.text)
    assert "Done: Turn on the sflow feature" in _text(done.text)
    assert enabled.feature_state["sflow"] is True
    assert enabled.sflow["collector"] == "192.0.2.5" and enabled.sflow["vrf"] == "management"
    assert enabled.sflow["rate"] == 8192 and enabled.sflow["agent"] == "192.0.2.10"
    assert len(enabled.sflow["sources"]) == 5
    page = _text(logged_in.get("/traffic").text)
    assert "Sending" in page and "one frame in 8192" in page
    with open_db(settings.db_path) as conn:
        row = conn.execute("SELECT sflow_agent, unsaved_changes FROM switch_connection").fetchone()
    assert row["sflow_agent"] == "192.0.2.10" and row["unsaved_changes"] == 1

    enabled.requests.clear()
    again = _setup(logged_in, confirm=True)
    assert "Nothing to change" in _text(again.text)
    assert _config_requests(enabled) == []


def test_every_front_port_samples_a_port_channel_through_it(
    logged_in: TestClient, enabled: FakeSwitch
) -> None:
    assert enabled.channels[43]  # Ethernet1/43-44, as recorded
    asked = _text(_setup(logged_in, scope="all").text)
    assert "port-channel43 for Ethernet1/43, Ethernet1/44" in asked
    done = _setup(logged_in, confirm=True, scope="all")
    assert done.status_code == 200, _text(done.text)
    sources = enabled.sflow["sources"]
    assert "port-channel43" in sources
    assert "Ethernet1/43" not in sources and "Ethernet1/44" not in sources
    assert "Ethernet1/1" in sources
    enabled.requests.clear()
    again = _setup(logged_in, confirm=True, scope="all")
    assert "Nothing to change" in _text(again.text)
    assert _config_requests(enabled) == []


def test_a_refusal_part_way_marks_the_switch_unsaved(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings, monkeypatch
) -> None:
    sflow = enabled._sflow

    def refuse_one_port(ident: int, undo: bool, rest: str):
        if rest == "data-source interface ethernet 1/2":
            return fake_error(ident, "ERR sflow data source refused\n")
        return sflow(ident, undo, rest)

    monkeypatch.setattr(enabled, "_sflow", refuse_one_port)
    with open_db(settings.db_path) as conn:
        row = conn.execute("SELECT unsaved_changes FROM switch_connection").fetchone()
    assert row["unsaved_changes"] == 0
    response = _setup(logged_in, confirm=True)
    assert response.status_code == 400
    text = _text(response.text)
    assert "Lines before the refused one have taken effect" in text
    assert enabled.sflow["sources"] == {"Ethernet1/1"}
    with open_db(settings.db_path) as conn:
        row = conn.execute("SELECT unsaved_changes FROM switch_connection").fetchone()
    assert row["unsaved_changes"] == 1


def test_a_bad_form_is_refused(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = _setup(logged_in, confirm=True, collector="nxray.example")
    assert response.status_code == 400
    assert "not an IPv4 address" in _text(response.text)
    assert 'value="nxray.example"' in response.text
    assert _config_requests(enabled) == []


def test_turning_sflow_off(logged_in: TestClient, enabled: FakeSwitch) -> None:
    _setup(logged_in, confirm=True)
    asked = logged_in.post("/traffic/sflow-off", data={"csrf": _csrf(logged_in)})
    assert "forgets every sFlow line" in _text(asked.text)
    done = logged_in.post("/traffic/sflow-off", data={"csrf": _csrf(logged_in), "confirm": "yes"})
    assert "sFlow is off on the switch" in _text(done.text)
    assert enabled.feature_state["sflow"] is False and enabled.sflow == {}


def test_off_before_role_version_15(
    logged_in: TestClient, enabled: FakeSwitch, settings: Settings
) -> None:
    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE switch_connection SET role_version = 14")
    conn.commit()
    conn.close()
    assert "Traffic measuring changes are off" in _text(logged_in.get("/traffic").text)
    response = _setup(logged_in, confirm=True)
    assert response.status_code == 400
    assert _config_requests(enabled) == []


def test_needs_a_csrf_token(logged_in: TestClient, enabled: FakeSwitch) -> None:
    response = logged_in.post("/traffic/sflow", data={**FORM, "csrf": "nope", "confirm": "yes"})
    assert response.status_code in (400, 403)
    assert _config_requests(enabled) == []


def test_the_page_shows_what_was_measured(logged_in: TestClient, enabled: FakeSwitch) -> None:
    collector: SflowCollector = logged_in.app.state.sflow_collector  # type: ignore[attr-defined]
    collector.set_agents({AGENT: 1})
    earlier = time.time() - 180
    collector.receive(_one(vlan=10, size=1000), now=earlier)
    collector.receive(_one(vlan=20, size=100, src=CLIENT, dst=SERVER), now=earlier)
    settings = logged_in.app.state.settings  # type: ignore[attr-defined]
    with open_db(settings.db_path) as conn:
        store_rows(conn, collector.drain())
    page = logged_in.get("/traffic?range=1h")
    text = _text(page.text)
    assert "VLAN 10" in text and "VLAN 20" in text
    assert SERVER in text and CLIENT in text
    assert "2 samples in 2 datagrams" in text
    assert "Traffic per VLAN, measured" in text
    device = _text(logged_in.get(f"/traffic?range=1h&mac={SERVER}").text)
    assert f"{SERVER}: traffic over time" in device


def test_samples_from_another_address_are_named(logged_in: TestClient, enabled: FakeSwitch) -> None:
    collector: SflowCollector = logged_in.app.state.sflow_collector  # type: ignore[attr-defined]
    collector.receive(_one(), now=time.time())
    assert "sFlow also came from 192.0.2.10" in _text(logged_in.get("/traffic").text)


def test_a_viewer_sees_the_page_but_no_form(logged_in: TestClient, enabled: FakeSwitch) -> None:
    password = "another-long-password"
    logged_in.post(
        "/users/create",
        data={
            "csrf": _csrf(logged_in, "/users"),
            "new_username": "viewer1",
            "password": password,
            "confirm_password": password,
            "role": "viewer",
        },
    )
    viewer = TestClient(logged_in.app, follow_redirects=False)
    viewer.post("/login", data={"username": "viewer1", "password": password, "next": "/"})
    page = viewer.get("/traffic")
    assert page.status_code == 200 and 'action="/traffic/sflow"' not in page.text
    refused = viewer.post("/traffic/sflow", data={**FORM, "csrf": _csrf(viewer), "confirm": "yes"})
    assert refused.status_code == 403
    assert _config_requests(enabled) == []
