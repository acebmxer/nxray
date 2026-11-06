"""sFlow on the switch: what it is set to, and planning a change to it.

Pure functions over the switch's output, like app/port_settings.py. The sflow
feature's state comes from ``show feature``; while it is on, the settings come
from ``show sflow``, which has no structured form on NX-OS 9.3 and is read as
text. Its layout here follows Cisco's NX-OS 9.3 System Management
Configuration Guide (``sflow collector-ip : 192.0.2.5 , vrf : management``),
which matches what cisco-25gb prints for front ports; a port-channel data
source has not been recorded yet, so both ``port-channel41`` and ``Po41`` are
read. Every line is read on its own and a line NXray does not know is left
alone.

The commands are built by ``NxapiClient.configure_sflow`` (and
``set_feature("sflow", ...)``) from checked values.

The switch refuses a port that is in a port-channel as a data source ("is
already member of a portchannel"); the port-channel is the data source and
samples all its ports. So the port-channels are read with the settings, and a
port picked for sampling is sent as its port-channel.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.features import feature_states
from app.neighbors import PortChannel, parse_port_channels
from app.nxapi import (
    SFLOW_DEFAULT_PORT,
    SFLOW_DEFAULT_RATE,
    SFLOW_SAMPLING_RATES,
    NxapiClient,
    validate_channel_number,
    validate_port_name,
    validate_sflow_address,
    validate_sflow_vrf,
)
from app.ports import Port, port_sort_key

_RATE = re.compile(r"sampling-rate\s*:\s*(\d+)", re.IGNORECASE)
_COLLECTOR = re.compile(
    r"collector-ip\s*:\s*([0-9.]+)(?:\s*,\s*vrf\s*:\s*([A-Za-z0-9_-]+))?", re.IGNORECASE
)
_COLLECTOR_PORT = re.compile(r"collector-port\s*:\s*(\d+)", re.IGNORECASE)
_AGENT = re.compile(r"agent-ip\s*:\s*([0-9.]+)", re.IGNORECASE)
_SOURCE = re.compile(
    r"data-source\s+interface\s*:?\s*(?:ethernet|Eth)\s*([0-9]+(?:/[0-9]+){1,2})(?:-([0-9]+))?",
    re.IGNORECASE,
)
_CHANNEL_SOURCE = re.compile(
    r"data-source\s+interface\s*:?\s*(?:port-channel|Po)\s*([0-9]+)(?:-([0-9]+))?",
    re.IGNORECASE,
)

SCOPES = {
    "all": "Every front port",
    "up": "The front ports that are up now",
    "list": "These ports",
}


@dataclass(frozen=True)
class SflowConfig:
    """sFlow as the switch has it. With the feature off, only ``feature_on``
    and ``port_channels``."""

    feature_on: bool
    sampling_rate: int = 0
    collector: str = ""
    collector_vrf: str = ""
    collector_port: int = 0
    agent: str = ""
    data_sources: tuple[str, ...] = ()  # Ethernet1/5 and port-channel41
    # The switch's port-channels: a port in one is sampled through it.
    port_channels: tuple[PortChannel, ...] = ()

    @property
    def sending(self) -> bool:
        """True when the switch has somewhere to send samples and ports to take them from."""
        return self.feature_on and bool(self.collector) and bool(self.data_sources)

    def channel_of(self, port: str) -> PortChannel | None:
        """The port-channel a front port is in, if any."""
        return next((pc for pc in self.port_channels if port in pc.members), None)

    def sources_for(self, ports: list[str] | tuple[str, ...]) -> list[str]:
        """The data sources that sample these front ports (or port-channels):
        each port in a port-channel becomes that port-channel, once."""
        found: list[str] = []
        for name in ports:
            channel = self.channel_of(name)
            source = channel.name if channel else name
            if source not in found:
                found.append(source)
        return found


def _source_key(name: str) -> tuple[int, ...]:
    """Front ports in their order, then port-channels by number."""
    if name.startswith("port-channel"):
        return (1, int(name.removeprefix("port-channel") or 0))
    return (0, *port_sort_key(name))


def _expand(base: str, last: str | None) -> list[str]:
    """``1/5`` and ``8`` -> Ethernet1/5 to Ethernet1/8."""
    if last is None:
        return [f"Ethernet{base}"]
    head, _, first = base.rpartition("/")
    start, end = int(first), int(last)
    if end < start or end - start > 128:
        return [f"Ethernet{base}"]
    return [f"Ethernet{head}/{number}" for number in range(start, end + 1)]


def _channel_names(first: str, last: str | None) -> list[str]:
    """``41`` (and ``44``) -> port-channel41 (to port-channel44); out of range -> []."""
    start = int(first)
    end = int(last) if last is not None else start
    if end < start or end - start > 128:
        end = start
    names = []
    for number in range(start, end + 1):
        try:
            names.append(f"port-channel{validate_channel_number(number)}")
        except ValueError:
            continue
    return names


def parse_sflow_text(text: str, port_channels: tuple[PortChannel, ...] = ()) -> SflowConfig:
    """``show sflow``, printed while the feature is on."""
    rate = _RATE.search(text)
    collector = _COLLECTOR.search(text)
    port = _COLLECTOR_PORT.search(text)
    agent = _AGENT.search(text)
    sources: set[str] = set()
    for match in _SOURCE.finditer(text):
        for name in _expand(match.group(1), match.group(2)):
            try:
                sources.add(validate_port_name(name))
            except ValueError:
                continue
    for match in _CHANNEL_SOURCE.finditer(text):
        sources.update(_channel_names(match.group(1), match.group(2)))
    return SflowConfig(
        feature_on=True,
        sampling_rate=int(rate.group(1)) if rate else 0,
        collector="" if not collector or collector.group(1) == "0.0.0.0" else collector.group(1),
        collector_vrf=(collector.group(2) or "").lower() if collector else "",
        collector_port=int(port.group(1)) if port else 0,
        agent="" if not agent or agent.group(1) == "0.0.0.0" else agent.group(1),
        data_sources=tuple(sorted(sources, key=_source_key)),
        port_channels=port_channels,
    )


def load_sflow_config(client: NxapiClient) -> SflowConfig:
    """sFlow on the switch: ``show feature`` and ``show port-channel summary``,
    then ``show sflow`` while the feature is on."""
    features, channels_body = client.show("show feature", "show port-channel summary")
    channels = tuple(parse_port_channels(channels_body))
    if not feature_states(features).get("sflow", False):
        return SflowConfig(feature_on=False, port_channels=channels)
    return parse_sflow_text(client.show_text("show sflow"), channels)


def sflow_form(
    current: SflowConfig | None,
    *,
    collector: str,
    agent: str,
    port: int,
    front: list[str] | tuple[str, ...] = (),
) -> dict:
    """The setup form filled with what the switch has, else with NXray's guesses:
    ``collector`` the address the switch may reach NXray at, ``agent`` the
    switch's own (its NX-API address), ``port`` the one NXray listens on.
    ``front`` are the switch's front ports: sampling all of them reads as
    "every front port" rather than as a list."""
    has = current is not None and current.feature_on
    every = (
        current is not None
        and has
        and bool(front)
        and set(current.data_sources) == set(current.sources_for(tuple(front)))
    )
    return {
        "collector": (current.collector if has and current.collector else collector),
        "vrf": (current.collector_vrf if has and current.collector_vrf else "management"),
        "collector_port": str(
            current.collector_port if has and current.collector_port else port or SFLOW_DEFAULT_PORT
        ),
        "agent": (current.agent if has and current.agent else agent),
        "sampling_rate": str(
            current.sampling_rate
            if has and current.sampling_rate in SFLOW_SAMPLING_RATES
            else SFLOW_DEFAULT_RATE
        ),
        "scope": "list" if has and current.data_sources and not every else "all",
        "ports": ", ".join(current.data_sources) if has and not every else "",
    }


@dataclass(frozen=True)
class SflowPlan:
    """What a setup form asks of the switch, with the confirm page's words."""

    turn_on_feature: bool = False
    sampling_rate: int | None = None
    collector: str | None = None
    vrf: str | None = None
    collector_port: int | None = None
    agent: str | None = None
    add_ports: tuple[str, ...] = ()
    remove_ports: tuple[str, ...] = ()
    lines: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.lines

    @property
    def configures(self) -> bool:
        """True when there is more to send than turning the feature on."""
        return any(
            value is not None
            for value in (self.sampling_rate, self.collector, self.collector_port, self.agent)
        ) or bool(self.add_ports or self.remove_ports)


def _port_list(text: str, front: list[str], channels: tuple[PortChannel, ...] = ()) -> list[str]:
    """``Ethernet1/1, eth1/3-4, 1/7, po41`` -> those front ports and port-channels,
    or raise ValueError."""
    known = {name.lower(): name for name in front}
    known.update({pc.name.lower(): pc.name for pc in channels})
    wanted: list[str] = []
    for part in re.split(r"[,\s]+", text.strip()):
        if not part:
            continue
        channel = re.fullmatch(r"(?:port-channel|po)([0-9]+)", part, re.IGNORECASE)
        if channel:
            name = f"port-channel{int(channel.group(1))}"
            if name not in known:
                raise ValueError(f"the switch has no {name}")
            if name not in wanted:
                wanted.append(name)
            continue
        match = re.fullmatch(
            r"(?:ethernet|eth|e)?\s*([0-9]+(?:/[0-9]+){1,2})(?:-([0-9]+))?", part, re.IGNORECASE
        )
        if not match:
            raise ValueError(f"{part!r} is not a front port such as Ethernet1/5")
        for name in _expand(match.group(1), match.group(2)):
            found = known.get(name.lower())
            if found is None:
                raise ValueError(f"the switch has no front port {name}")
            if found not in wanted:
                wanted.append(found)
    if not wanted:
        raise ValueError("Name at least one port to sample, or pick every front port.")
    return wanted


def _short_list(names: list[str] | tuple[str, ...], most: int = 8) -> str:
    shown = ", ".join(names[:most])
    return shown + (f" and {len(names) - most} more" if len(names) > most else "")


def plan_sflow(current: SflowConfig, ports: list[Port], form: dict[str, str]) -> SflowPlan:
    """Check the setup form against the switch, or raise ValueError; keep only
    what changes. ``ports`` are the switch's front ports, for the port choice."""
    collector = validate_sflow_address(form.get("collector", ""))
    vrf = validate_sflow_vrf(form.get("vrf", "") or "management")
    port_text = form.get("collector_port", "").strip()
    if not (port_text.isascii() and port_text.isdigit() and 1 <= int(port_text) <= 65535):
        raise ValueError("The collector's UDP port is a number from 1 to 65535.")
    collector_port = int(port_text)
    agent = validate_sflow_address(form.get("agent", ""))
    rate_text = form.get("sampling_rate", "").strip()
    if not (rate_text.isdigit() and int(rate_text) in SFLOW_SAMPLING_RATES):
        raise ValueError(
            "Pick a sampling rate: one frame in "
            + ", ".join(str(n) for n in SFLOW_SAMPLING_RATES)
            + "."
        )
    rate = int(rate_text)
    front = [port.name for port in ports]
    scope = form.get("scope", "all")
    if scope == "all":
        wanted = front
    elif scope == "up":
        wanted = [port.name for port in ports if port.up]
        if not wanted:
            raise ValueError("No front port is up now, so there is nothing to sample.")
    elif scope == "list":
        wanted = _port_list(form.get("ports", ""), front, current.port_channels)
    else:
        raise ValueError("Pick which ports to sample.")
    wanted = current.sources_for(wanted)

    has = current.feature_on
    lines: list[str] = []
    warnings: list[str] = []
    if not has:
        lines.append("Turn on the sflow feature on the switch.")
    new_rate = rate if not has or current.sampling_rate != rate else None
    if new_rate is not None:
        lines.append(f"Sample one frame in {rate}.")
    new_collector = (
        collector
        if not has or (current.collector, current.collector_vrf) != (collector, vrf)
        else None
    )
    if new_collector is not None:
        lines.append(f"Send the samples to {collector} (reached in VRF {vrf}).")
    new_port = collector_port if not has or current.collector_port != collector_port else None
    if new_port is not None:
        lines.append(f"Send them to UDP port {collector_port}.")
    new_agent = agent if not has or current.agent != agent else None
    if new_agent is not None:
        lines.append(f"Mark them as coming from {agent}, the switch's agent address.")
    before = set(current.data_sources) if has else set()
    add = tuple(name for name in wanted if name not in before)
    remove = tuple(sorted(before - set(wanted), key=_source_key))
    if add:
        lines.append(f"Sample {len(add)} port{'s' if len(add) != 1 else ''}: {_short_list(add)}.")
    if remove:
        lines.append(
            f"Stop sampling {len(remove)} port{'s' if len(remove) != 1 else ''}: "
            f"{_short_list(remove)}."
        )
    if lines:
        warnings.append(
            "Sampling costs the switch a little CPU for every sampled frame; one in "
            f"{rate} is light. The traffic itself is not changed."
        )
    through = [
        f"{pc.name} for {', '.join(pc.members) or 'its ports'}"
        for pc in current.port_channels
        if pc.name in add
    ]
    if through:
        warnings.append(
            "The switch samples a port in a port-channel only through its port-channel, "
            "which covers all its ports: " + "; ".join(through) + "."
        )
    if new_agent is not None and has and current.agent:
        warnings.append(
            "NXray tells datagrams apart by the agent address: until it has the new one, "
            "samples from the old address are not counted."
        )
    return SflowPlan(
        turn_on_feature=not has,
        sampling_rate=new_rate,
        collector=new_collector,
        vrf=vrf if new_collector is not None else None,
        collector_port=new_port,
        agent=new_agent,
        add_ports=add,
        remove_ports=remove,
        lines=lines,
        warnings=warnings,
    )
