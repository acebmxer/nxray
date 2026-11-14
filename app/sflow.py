"""NXray as an sFlow collector: measured traffic per VLAN and per device.

With ``feature sflow`` on, the switch sends samples of the frames it forwards
to a collector over UDP (port 6343 by convention): one frame in every N (the
sampling rate), each with the first bytes of the frame, its length and, when
the switch adds it, the VLAN it belongs to. Multiplying each sampled frame's
length by N estimates the traffic it stands for. Unlike the switch's port
counters this splits a trunk's traffic by VLAN, and names the devices
behind it by MAC address.

This module has three parts:

- ``decode_datagram``: sFlow version 5 (sflow.org's specification), pure and
  bounds-checked, so a damaged or hostile datagram is refused, never trusted.
  Only flow samples (formats 1 and 3) are used; counter samples are counted
  and skipped, as NXray reads the counters over NX-API already.
- ``SflowCollector``: adds each sample up per switch, minute, VLAN and device
  (the MAC address that sent it, and the one it went to), in memory. Only
  datagrams count whose agent address is one of NXray's switches and that
  were sent from an address of that same switch: sFlow has no authentication,
  so anything else is only noted.
- Storage and reading: completed minutes go into the ``sflow_traffic`` table,
  kept ``NXRAY_SFLOW_KEEP_DAYS`` days, and the Traffic page reads them back as
  top lists and charts.

The listener (``start_collector``) runs only when ``NXRAY_SFLOW_PORT`` is set.
NXray never changes the switch from here: the switch side is set up from the
Traffic page through ``NxapiClient.configure_sflow``.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import sqlite3
import struct
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from app.charts import SERIES_COLOURS, Line, area_chart
from app.db import open_db
from app.history import RANGES, ChartView, bucket_seconds, chart_view, rate_text
from app.oui import is_group_mac

log = logging.getLogger("nxray.sflow")

SFLOW_VERSION = 5
# What the table keeps: a VLAN's traffic, and a device's, by the MAC address
# that sent it (sends) and the one it went to (receives).
VLAN = "vlan"
MAC_SENDS = "mac_out"
MAC_RECEIVES = "mac_in"
KINDS = (VLAN, MAC_SENDS, MAC_RECEIVES)
# The item for a sample whose VLAN the switch did not say, and for the devices
# left over once a minute's busiest are kept.
UNKNOWN_VLAN = "unknown"
OTHER = "other"
# Of each minute, this many devices per direction are kept by name; the rest
# are added up as OTHER, so a flood of made-up addresses cannot fill the disk.
MAX_DEVICES_PER_MINUTE = 100
# And at most this many different items per switch and minute in memory.
MAX_ITEMS_IN_MEMORY = 5000
# A datagram is at most one UDP packet; a sample with more records than this
# is refused as damaged.
MAX_DATAGRAM = 65535
MAX_RECORDS = 64
# How often the listener writes the minutes that are over, and looks up
# NXray's switches again.
FLUSH_SECONDS = 10
AGENTS_SECONDS = 30
PURGE_SECONDS = 3600

_FLOW_SAMPLE = 1
_COUNTER_SAMPLE = 2
_EXPANDED_FLOW_SAMPLE = 3
_EXPANDED_COUNTER_SAMPLE = 4
_RAW_HEADER = 1
_ETHERNET_FRAME = 2
_EXTENDED_SWITCH = 1001
_HEADER_ETHERNET = 1


class SflowError(ValueError):
    """A datagram that is not sFlow version 5, or is cut short or damaged."""


@dataclass(frozen=True)
class FlowSample:
    """One sampled frame, as much as NXray uses of it."""

    sampling_rate: int
    frame_length: int
    vlan: int = 0  # 0 when the switch did not say
    src_mac: str = ""  # aa:bb:cc:dd:ee:ff, "" when not in the sample
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    input_index: int = 0  # the SNMP ifIndex it came in on, 0 when not given

    @property
    def estimated_bytes(self) -> int:
        """The traffic this one sample stands for: its length times the rate."""
        return self.frame_length * max(self.sampling_rate, 1)


@dataclass(frozen=True)
class Datagram:
    agent: str
    sequence: int
    samples: tuple[FlowSample, ...]
    counter_samples: int = 0


class _Reader:
    """Big-endian XDR fields from a bytes object, refusing to read past its end."""

    def __init__(self, data: bytes, start: int = 0, end: int | None = None) -> None:
        self.data = data
        self.at = start
        self.end = len(data) if end is None else end

    def take(self, count: int) -> bytes:
        if count < 0 or self.at + count > self.end:
            raise SflowError("the datagram is cut short")
        chunk = self.data[self.at : self.at + count]
        self.at += count
        return chunk

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def opaque(self, count: int) -> bytes:
        """``count`` bytes padded to a multiple of four, as XDR writes them."""
        chunk = self.take(count)
        self.take((4 - count % 4) % 4)
        return chunk

    def sub(self, length: int) -> _Reader:
        """A reader over the next ``length`` bytes, which this one then skips."""
        if length < 0 or self.at + length > self.end:
            raise SflowError("a sample is longer than the datagram")
        inner = _Reader(self.data, self.at, self.at + length)
        self.at += length
        return inner


def _mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def _address(reader: _Reader) -> str:
    kind = reader.u32()
    if kind == 1:
        return str(ipaddress.IPv4Address(reader.take(4)))
    if kind == 2:
        return str(ipaddress.IPv6Address(reader.take(16)))
    raise SflowError(f"unknown agent address type {kind}")


def parse_frame_header(header: bytes) -> dict[str, object]:
    """What NXray reads from the first bytes of an Ethernet frame: its MAC
    addresses, the 802.1Q VLAN tag (0 for none) and the IPv4 or IPv6 addresses.
    A header cut short gives what it has."""
    found: dict[str, object] = {}
    if len(header) < 14:
        return found
    found["dst_mac"] = _mac(header[0:6])
    found["src_mac"] = _mac(header[6:12])
    kind = struct.unpack(">H", header[12:14])[0]
    at = 14
    if kind in (0x8100, 0x88A8) and len(header) >= 18:
        found["vlan"] = struct.unpack(">H", header[14:16])[0] & 0x0FFF
        kind = struct.unpack(">H", header[16:18])[0]
        at = 18
    if kind == 0x0800 and len(header) >= at + 20:
        found["src_ip"] = str(ipaddress.IPv4Address(header[at + 12 : at + 16]))
        found["dst_ip"] = str(ipaddress.IPv4Address(header[at + 16 : at + 20]))
    elif kind == 0x86DD and len(header) >= at + 40:
        found["src_ip"] = str(ipaddress.IPv6Address(header[at + 8 : at + 24]))
        found["dst_ip"] = str(ipaddress.IPv6Address(header[at + 24 : at + 40]))
    return found


def _flow_sample(reader: _Reader, expanded: bool) -> FlowSample:
    reader.u32()  # sequence number
    if expanded:
        reader.u32()  # source id type
        reader.u32()  # source id index
    else:
        reader.u32()  # source id
    rate = reader.u32()
    reader.u32()  # sample pool
    reader.u32()  # drops
    if expanded:
        reader.u32()  # input format
        input_index = reader.u32()
        reader.u32()  # output format
        reader.u32()  # output value
    else:
        input_index = reader.u32() & 0x3FFFFFFF
        reader.u32()  # output
    records = reader.u32()
    if records > MAX_RECORDS:
        raise SflowError(f"a flow sample says it has {records} records")
    values: dict[str, object] = {"input_index": input_index}
    frame_length = 0
    switch_vlan = 0
    for _ in range(records):
        record_format = reader.u32()
        record = reader.sub(reader.u32())
        if record_format == _RAW_HEADER:
            protocol = record.u32()
            frame_length = record.u32()
            record.u32()  # stripped
            header = record.opaque(record.u32())
            if protocol == _HEADER_ETHERNET:
                values.update(parse_frame_header(header))
        elif record_format == _ETHERNET_FRAME:
            length = record.u32()
            frame_length = frame_length or length
            values.setdefault("src_mac", _mac(record.opaque(6)))
            values.setdefault("dst_mac", _mac(record.opaque(6)))
        elif record_format == _EXTENDED_SWITCH:
            switch_vlan = record.u32()
    header_vlan = int(values.pop("vlan", 0) or 0)  # type: ignore[call-overload]
    vlan = switch_vlan or header_vlan
    return FlowSample(
        sampling_rate=rate,
        frame_length=frame_length,
        vlan=vlan if 0 < vlan <= 4094 else 0,
        **values,  # type: ignore[arg-type]
    )


def decode_datagram(data: bytes) -> Datagram:
    """One sFlow version 5 datagram, or raise SflowError."""
    if len(data) > MAX_DATAGRAM:
        raise SflowError("the datagram is longer than a UDP packet")
    reader = _Reader(data)
    version = reader.u32()
    if version != SFLOW_VERSION:
        raise SflowError(f"sFlow version {version}, not 5")
    agent = _address(reader)
    reader.u32()  # sub-agent id
    sequence = reader.u32()
    reader.u32()  # uptime
    count = reader.u32()
    samples: list[FlowSample] = []
    counters = 0
    for _ in range(count):
        data_format = reader.u32()
        sample = reader.sub(reader.u32())
        enterprise, number = data_format >> 12, data_format & 0xFFF
        if enterprise != 0:
            continue
        if number in (_FLOW_SAMPLE, _EXPANDED_FLOW_SAMPLE):
            samples.append(_flow_sample(sample, number == _EXPANDED_FLOW_SAMPLE))
        elif number in (_COUNTER_SAMPLE, _EXPANDED_COUNTER_SAMPLE):
            counters += 1
    return Datagram(agent, sequence, tuple(samples), counters)


# ---- adding up -------------------------------------------------------------------


@dataclass
class AgentStatus:
    """What NXray heard from one switch since it started."""

    datagrams: int = 0
    samples: int = 0
    last_at: float = 0.0
    sampling_rate: int = 0
    agent: str = ""


@dataclass
class _Minute:
    totals: dict[tuple[str, str], list[int]] = field(default_factory=dict)


def _switch_addresses(
    connections: Iterable[tuple[int, str, str]], *, every: bool
) -> dict[str, int]:
    """The IP addresses in (switch id, NX-API host, stored agent) rows: the
    first one of each row, or all of them when ``every``. A name is not looked up."""
    found: dict[str, int] = {}
    for switch_id, host, agent in connections:
        for text in (agent, host):
            try:
                found.setdefault(str(ipaddress.ip_address(text.strip())), switch_id)
            except ValueError:
                continue
            if not every:
                break
    return found


def agent_addresses(connections: Iterable[tuple[int, str, str]]) -> dict[str, int]:
    """Which agent address belongs to which of NXray's switches.

    ``connections`` are (switch id, NX-API host, the agent address NXray set
    on the switch, "" when none): the stored agent address counts, else the
    host when it is an IP address. A name is not looked up.
    """
    return _switch_addresses(connections, every=False)


def sender_addresses(connections: Iterable[tuple[int, str, str]]) -> dict[str, int]:
    """Every IP address a datagram of one of NXray's switches may be sent from.

    Same ``connections`` as ``agent_addresses``, but both the agent address and
    the NX-API host count (a switch can send from another interface than the
    one it names as its agent).
    """
    return _switch_addresses(connections, every=True)


def _sender_text(sender: str) -> str:
    """The sender's address in the same form as ``agent_addresses`` keys: an
    IPv4 address a dual-stack socket reports as ``::ffff:a.b.c.d`` is plain."""
    try:
        address = ipaddress.ip_address(sender.strip())
    except ValueError:
        return sender
    mapped = getattr(address, "ipv4_mapped", None)
    return str(mapped or address)


class SflowCollector:
    """sFlow samples added up in memory per switch, minute, VLAN and device,
    until ``drain`` hands the minutes that are over to the database."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._agents: dict[str, int] = {}
        self._senders: dict[str, int] = {}
        # Per switch: SNMP ifIndex -> the VLAN a frame without a tag belongs to.
        self._port_vlans: dict[int, dict[int, int]] = {}
        self._minutes: dict[tuple[int, int], _Minute] = {}
        self._status: dict[int, AgentStatus] = {}
        self._unknown: dict[str, float] = {}
        self.malformed = 0
        self.listening_port = 0

    def set_agents(self, agents: dict[str, int], senders: dict[str, int] | None = None) -> None:
        """``agents``: agent address -> switch; ``senders``: the addresses a
        switch's datagrams may come from (the agent addresses when not given)."""
        with self._lock:
            self._agents = dict(agents)
            self._senders = dict(agents if senders is None else senders)

    def set_port_vlans(self, switch_id: int, port_vlans: dict[int, int]) -> None:
        """Which VLAN an untagged frame belongs to, by the ifIndex of the port it
        came in on, for one switch (``load_port_vlans``)."""
        with self._lock:
            self._port_vlans[switch_id] = dict(port_vlans)

    def receive(self, data: bytes, now: float | None = None, *, sender: str) -> int:
        """Add one datagram up; how many of its samples counted (0 for one
        that is damaged, or whose agent address or sender (the address the
        UDP packet really came from) is not one of the same NXray switch)."""
        moment = self._clock() if now is None else now
        try:
            datagram = decode_datagram(data)
        except (SflowError, ValueError, struct.error):
            with self._lock:
                self.malformed += 1
            return 0
        with self._lock:
            sender = _sender_text(sender)
            switch_id = self._agents.get(datagram.agent)
            if switch_id is None or self._senders.get(sender) != switch_id:
                # The agent field is written by whoever sends the packet, so
                # the address it really came from is the one to report.
                shown = datagram.agent if switch_id is None else sender
                if len(self._unknown) < 100 or shown in self._unknown:
                    self._unknown[shown] = moment
                return 0
            status = self._status.setdefault(switch_id, AgentStatus())
            status.datagrams += 1
            status.last_at = moment
            status.agent = datagram.agent
            minute = int(moment // 60) * 60
            bucket = self._minutes.setdefault((switch_id, minute), _Minute())
            port_vlans = self._port_vlans.get(switch_id, {})
            for sample in datagram.samples:
                status.samples += 1
                status.sampling_rate = sample.sampling_rate
                size = sample.estimated_bytes
                # A frame without a tag belongs to the VLAN of the port it came in on.
                vlan = sample.vlan or port_vlans.get(sample.input_index, 0)
                self._add(bucket, VLAN, str(vlan) if vlan else UNKNOWN_VLAN, size)
                if sample.src_mac and not is_group_mac(sample.src_mac):
                    self._add(bucket, MAC_SENDS, sample.src_mac, size)
                if sample.dst_mac and not is_group_mac(sample.dst_mac):
                    self._add(bucket, MAC_RECEIVES, sample.dst_mac, size)
            return len(datagram.samples)

    @staticmethod
    def _add(bucket: _Minute, kind: str, item: str, size: int) -> None:
        key = (kind, item)
        if key not in bucket.totals and len(bucket.totals) >= MAX_ITEMS_IN_MEMORY:
            key = (kind, OTHER)
        totals = bucket.totals.setdefault(key, [0, 0])
        totals[0] += size
        totals[1] += 1

    def drain(self, now: float | None = None, everything: bool = False) -> list[SflowRow]:
        """The rows of every minute that is over (all of them with
        ``everything``, at shutdown), forgotten here once handed out."""
        moment = self._clock() if now is None else now
        current = int(moment // 60) * 60
        with self._lock:
            done = [key for key in self._minutes if everything or key[1] < current]
            taken = {key: self._minutes.pop(key) for key in done}
        rows: list[SflowRow] = []
        for (switch_id, minute), bucket in sorted(taken.items()):
            rows.extend(minute_rows(switch_id, minute, bucket.totals))
        return rows

    def status(self, switch_id: int) -> AgentStatus | None:
        with self._lock:
            found = self._status.get(switch_id)
            return AgentStatus(**vars(found)) if found else None

    def unknown_agents(self) -> list[tuple[str, float]]:
        """Addresses that sent sFlow but are not one of NXray's switches, newest first."""
        with self._lock:
            return sorted(self._unknown.items(), key=lambda item: -item[1])


@dataclass(frozen=True)
class SflowRow:
    switch_id: int
    minute: int
    kind: str
    item: str
    bytes: int
    samples: int


def minute_rows(
    switch_id: int, minute: int, totals: dict[tuple[str, str], list[int]]
) -> list[SflowRow]:
    """One minute's rows: every VLAN, and the busiest MAX_DEVICES_PER_MINUTE
    devices each way with the rest added up as OTHER."""
    rows = []
    for kind in KINDS:
        items = sorted(
            ((item, value) for (k, item), value in totals.items() if k == kind),
            key=lambda pair: -pair[1][0],
        )
        keep = items if kind == VLAN else items[:MAX_DEVICES_PER_MINUTE]
        rest = [] if kind == VLAN else items[MAX_DEVICES_PER_MINUTE:]
        for item, (size, count) in keep:
            rows.append(SflowRow(switch_id, minute, kind, item, size, count))
        if rest:
            other = next((r for r in rows if r.kind == kind and r.item == OTHER), None)
            size = sum(value[0] for _, value in rest) + (other.bytes if other else 0)
            count = sum(value[1] for _, value in rest) + (other.samples if other else 0)
            rows = [r for r in rows if r is not other]
            rows.append(SflowRow(switch_id, minute, kind, OTHER, size, count))
    return rows


# ---- the table -------------------------------------------------------------------


def store_rows(conn: sqlite3.Connection, rows: Sequence[SflowRow]) -> None:
    """Add rows to the table; a minute written twice adds up."""
    conn.executemany(
        """
        INSERT INTO sflow_traffic (switch_id, minute, kind, item, bytes, samples)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (switch_id, minute, kind, item)
        DO UPDATE SET bytes = bytes + excluded.bytes, samples = samples + excluded.samples
        """,
        [(r.switch_id, r.minute, r.kind, r.item, r.bytes, r.samples) for r in rows],
    )
    conn.commit()


def purge_sflow(conn: sqlite3.Connection, now: float, keep_days: int) -> int:
    """Delete every switch's rows older than ``keep_days``; how many went."""
    cursor = conn.execute("DELETE FROM sflow_traffic WHERE minute < ?", (now - keep_days * 86400,))
    conn.commit()
    return cursor.rowcount


@dataclass(frozen=True)
class TopItem:
    item: str
    bytes: int
    samples: int
    # The average over the range asked for, in bits per second.
    bits_per_second: int


def top_items(
    conn: sqlite3.Connection,
    switch_id: int,
    kind: str,
    *,
    start: float,
    end: float,
    limit: int = 20,
) -> list[TopItem]:
    """The busiest VLANs or devices of a switch over start..end, busiest first."""
    span = max(end - start, 60.0)
    found = conn.execute(
        """
        SELECT item, SUM(bytes) AS b, SUM(samples) AS s FROM sflow_traffic
         WHERE switch_id = ? AND kind = ? AND minute >= ? AND minute < ?
         GROUP BY item ORDER BY b DESC LIMIT ?
        """,
        (switch_id, kind, int(start // 60) * 60, end, limit),
    ).fetchall()
    return [TopItem(row["item"], row["b"], row["s"], round(row["b"] * 8 / span)) for row in found]


def item_series(
    conn: sqlite3.Connection,
    switch_id: int,
    kind: str,
    items: Sequence[str],
    *,
    start: float,
    end: float,
    bucket: int,
) -> dict[str, list[tuple[float, float]]]:
    """Each item's traffic in bits per second per bucket over start..end; a
    bucket with no sample is 0 once the item has been seen, so a quiet minute
    reads as quiet rather than as a gap."""
    if not items:
        return {}
    marks = ",".join("?" for _ in items)
    found = conn.execute(
        f"""
        SELECT item, CAST(minute / ? AS INTEGER) * ? AS b, SUM(bytes) AS total
          FROM sflow_traffic
         WHERE switch_id = ? AND kind = ? AND minute >= ? AND minute < ? AND item IN ({marks})
         GROUP BY item, b
        """,  # noqa: S608 - only "?" marks are put in
        (bucket, bucket, switch_id, kind, start, end, *items),
    ).fetchall()
    by_item: dict[str, dict[float, float]] = {item: {} for item in items}
    for row in found:
        by_item[row["item"]][float(row["b"])] = row["total"] * 8 / bucket
    series: dict[str, list[tuple[float, float]]] = {}
    first_bucket = int(start // bucket) * bucket
    last_bucket = int((end - 1) // bucket) * bucket
    for item, values in by_item.items():
        if not values:
            series[item] = []
            continue
        # From the first bucket with traffic to the last: quiet buckets between
        # them are 0, and the line stops where the samples stop.
        series[item] = [
            (moment + bucket / 2, values.get(float(moment), 0.0))
            for moment in range(
                max(first_bucket, int(min(values))), min(last_bucket, int(max(values))) + 1, bucket
            )
        ]
    return series


def latest_minute(conn: sqlite3.Connection, switch_id: int) -> float | None:
    """When the newest stored minute of a switch began."""
    row = conn.execute(
        "SELECT MAX(minute) AS m FROM sflow_traffic WHERE switch_id = ?", (switch_id,)
    ).fetchone()
    return row["m"] if row and row["m"] is not None else None


def vlan_label(item: str) -> str:
    return "VLAN not given" if item == UNKNOWN_VLAN else f"VLAN {item}"


def device_label(item: str) -> str:
    return "Other devices" if item == OTHER else item


@dataclass(frozen=True)
class VlanCard:
    """One VLAN's card on the Traffic page: its name, the figures, a filled chart."""

    label: str
    now: str
    highest: str
    average: str
    svg: object


def vlan_cards(conn: sqlite3.Connection, switch_id: int, key: str, now: float) -> list[VlanCard]:
    """A card for each of the busiest VLANs over the range named ``key``, busiest
    first: the latest figure large, the highest and the average beside it, and
    the traffic drawn as a filled area. sFlow counts each frame once, on the
    port it came in on, so there is one figure per VLAN, not an in and an out."""
    span = RANGES[key]
    start, end, bucket = now - span, now, bucket_seconds(span)
    tops = top_items(conn, switch_id, VLAN, start=start, end=end, limit=SERIES_COLOURS)
    found = item_series(
        conn, switch_id, VLAN, [top.item for top in tops], start=start, end=end, bucket=bucket
    )
    cards = []
    for number, top in enumerate(tops):
        points = found[top.item]
        if not points:
            continue
        label = vlan_label(top.item)
        cards.append(
            VlanCard(
                label=label,
                now=rate_text(points[-1][1]),
                highest=rate_text(max(value for _, value in points)),
                average=rate_text(top.bits_per_second),
                svg=area_chart(
                    points,
                    start=start,
                    end=end,
                    bucket=bucket,
                    fmt=rate_text,
                    colour=number,
                    label=f"{label}: traffic over time",
                ),
            )
        )
    return cards


def sflow_charts(
    conn: sqlite3.Connection, switch_id: int, key: str, now: float, mac: str = ""
) -> list[ChartView]:
    """The Traffic page's chart of one device's sends and receives when ``mac``
    names one; none otherwise (the VLANs are cards, see ``vlan_cards``)."""
    span = RANGES[key]
    start, end, bucket = now - span, now, bucket_seconds(span)
    common = {"start": start, "end": end, "bucket": bucket, "fmt": rate_text}
    charts: list[ChartView] = []
    if mac:
        sends = item_series(conn, switch_id, MAC_SENDS, [mac], start=start, end=end, bucket=bucket)
        receives = item_series(
            conn, switch_id, MAC_RECEIVES, [mac], start=start, end=end, bucket=bucket
        )
        charts.append(
            chart_view(
                f"{mac}: traffic over time",
                [Line("Sends", sends.get(mac, [])), Line("Receives", receives.get(mac, []))],
                note=(
                    "Sends: frames this device sent into the switch. Receives: frames sent "
                    "to it. Measured from sFlow samples, so a quiet device may show none."
                ),
                empty="No sFlow sample from or to this device in this range.",
                anchor="device",
                **common,
            )
        )
    return charts


# ---- the listener ----------------------------------------------------------------


def load_agents(db_path: Path) -> tuple[dict[str, int], dict[str, int]]:
    """The agent address of each of NXray's switches, and every address a
    datagram of theirs may be sent from, from the database."""
    with open_db(db_path) as conn:
        found = conn.execute("SELECT id, host, sflow_agent FROM switch_connection").fetchall()
    connections = [(row["id"], row["host"], row["sflow_agent"]) for row in found]
    return agent_addresses(connections), sender_addresses(connections)


def run_collector(
    sock: socket.socket,
    collector: SflowCollector,
    db_path: Path,
    keep_days: int,
    stop: threading.Event,
    clock: Callable[[], float] = time.time,
) -> None:
    """Receive datagrams on ``sock`` until ``stop`` is set, writing the minutes
    that are over to the database every few seconds and purging old ones."""
    next_flush = next_agents = next_purge = 0.0
    try:
        while not stop.is_set():
            now = clock()
            if now >= next_agents:
                try:
                    collector.set_agents(*load_agents(db_path))
                except sqlite3.Error as exc:
                    log.warning("sFlow: could not read NXray's switches: %s", exc)
                next_agents = now + AGENTS_SECONDS
            try:
                data, (sender, *_rest) = sock.recvfrom(MAX_DATAGRAM)
            except TimeoutError:
                data, sender = b"", ""
            except OSError as exc:
                if stop.is_set():
                    break
                log.warning("sFlow: receiving failed: %s", exc)
                data, sender = b"", ""
            if data:
                collector.receive(data, sender=sender)
            now = clock()
            if now >= next_flush:
                _flush(collector, db_path, now, keep_days, purge=now >= next_purge)
                if now >= next_purge:
                    next_purge = now + PURGE_SECONDS
                next_flush = now + FLUSH_SECONDS
    finally:
        _flush(collector, db_path, clock(), keep_days, purge=False, everything=True)
        sock.close()


def _flush(
    collector: SflowCollector,
    db_path: Path,
    now: float,
    keep_days: int,
    *,
    purge: bool,
    everything: bool = False,
) -> None:
    rows = collector.drain(now, everything=everything)
    if not rows and not purge:
        return
    try:
        with open_db(db_path) as conn:
            if rows:
                store_rows(conn, rows)
            if purge:
                purge_sflow(conn, now, keep_days)
    except sqlite3.Error as exc:
        log.warning("sFlow: could not store %d rows: %s", len(rows), exc)


def start_collector(
    port: int, collector: SflowCollector, db_path: Path, keep_days: int
) -> threading.Event | None:
    """Listen for sFlow on UDP ``port`` on a thread; None when ``port`` is 0
    (off) or cannot be opened (logged, and NXray runs on without it)."""
    if not port:
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", port))  # noqa: S104 - the switch sends from its own address
    except OSError as exc:
        sock.close()
        log.error("sFlow: cannot listen on UDP port %d: %s; the collector is off", port, exc)
        return None
    sock.settimeout(1.0)
    collector.listening_port = port
    stop = threading.Event()
    thread = threading.Thread(
        target=run_collector,
        args=(sock, collector, db_path, keep_days, stop),
        name="nxray-sflow",
        daemon=True,
    )
    thread.start()
    log.info("sFlow collector listening on UDP port %d", port)
    return stop
