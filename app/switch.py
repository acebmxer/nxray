"""Turns NX-API show output into what the pages display.

Pure functions over the parsed JSON bodies from app/nxapi.py, so every one of
them is tested against output recorded from a real switch
(tests/fixtures/), with no network involved.

NX-OS JSON has one quirk worth knowing: a table with a single row holds that
row as an object, and only a table with several rows holds a list. ``rows``
hides that so no parser has to remember it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.nxapi import NxapiClient

# The commands one dashboard load runs, in one NX-API request.
DASHBOARD_COMMANDS = (
    "show version",
    "show environment",
    "show system resources",
    "show interface brief",
)


def rows(body: dict[str, Any], table: str, row: str) -> list[dict[str, Any]]:
    """The rows of an NX-OS table as a list, whether it held one row or many."""
    container = body.get(table)
    if not isinstance(container, dict):
        return []
    value = container.get(row)
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def section(body: dict[str, Any], key: str) -> dict[str, Any]:
    """A nested object of an NX-OS body, or an empty one if it is missing."""
    value = body.get(key)
    return value if isinstance(value, dict) else {}


def to_int(value: Any) -> int | None:
    """A number from NX-OS text such as "27" or "650 W"; None if there is none."""
    if value is None:
        return None
    text = str(value).strip().split(" ")[0]
    try:
        return int(float(text))
    except ValueError:
        return None


@dataclass(frozen=True)
class SystemInfo:
    hostname: str
    model: str
    nxos_version: str
    uptime: str
    last_reset_reason: str


@dataclass(frozen=True)
class TempSensor:
    module: str
    name: str
    current_c: int | None
    minor_c: int | None
    major_c: int | None
    status: str

    @property
    def level(self) -> str:
        """ok / warn / crit, from the switch's own alarm and thresholds."""
        if self.status.lower() not in ("ok", ""):
            return "crit" if "major" in self.status.lower() else "warn"
        if self.current_c is None:
            return "unknown"
        if self.major_c is not None and self.current_c >= self.major_c:
            return "crit"
        if self.minor_c is not None and self.current_c >= self.minor_c:
            return "warn"
        return "ok"


@dataclass(frozen=True)
class Fan:
    name: str
    model: str
    direction: str
    status: str

    @property
    def ok(self) -> bool:
        return self.status.lower() == "ok"


@dataclass(frozen=True)
class PowerSupply:
    number: str
    model: str
    output_w: int | None
    input_w: int | None
    capacity_w: int | None
    status: str

    @property
    def ok(self) -> bool:
        return self.status.lower() == "ok"


@dataclass(frozen=True)
class Environment:
    temperatures: list[TempSensor]
    fans: list[Fan]
    fan_speed_percent: int | None
    power_supplies: list[PowerSupply]
    redundancy_mode: str
    total_draw_w: int | None


@dataclass(frozen=True)
class Resources:
    cpu_used_percent: float | None
    memory_used_percent: float | None
    load_1min: str


@dataclass(frozen=True)
class PortSummary:
    total: int
    up: int
    down: int
    no_transceiver: int


@dataclass(frozen=True)
class Dashboard:
    system: SystemInfo
    environment: Environment
    resources: Resources
    ports: PortSummary


def parse_version(body: dict[str, Any]) -> SystemInfo:
    """Identity and uptime from ``show version``."""
    days = to_int(body.get("kern_uptm_days")) or 0
    hours = to_int(body.get("kern_uptm_hrs")) or 0
    minutes = to_int(body.get("kern_uptm_mins")) or 0
    parts = []
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours or days:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")

    return SystemInfo(
        hostname=str(body.get("host_name") or "unknown"),
        model=str(body.get("chassis_id") or "unknown"),
        nxos_version=str(body.get("nxos_ver_str") or "unknown"),
        uptime=", ".join(parts),
        last_reset_reason=str(body.get("rr_reason") or ""),
    )


def fan_speed_percent(zone_speed: Any) -> int | None:
    """The fan zone speed (hex out of 0xFF, e.g. "0x80") as a percentage."""
    if not isinstance(zone_speed, str):
        return None
    try:
        raw = int(zone_speed, 16)
    except ValueError:
        return None
    return round(raw * 100 / 255)


def parse_environment(body: dict[str, Any]) -> Environment:
    """Temperatures, fans and power supplies from ``show environment``."""
    temperatures = [
        TempSensor(
            module=str(row.get("tempmod", "")),
            name=str(row.get("sensor", "")),
            current_c=to_int(row.get("curtemp")),
            minor_c=to_int(row.get("minthres")),
            major_c=to_int(row.get("majthres")),
            status=str(row.get("alarmstatus", "")),
        )
        for row in rows(body, "TABLE_tempinfo", "ROW_tempinfo")
    ]

    fan_body = section(body, "fandetails")
    fans = [
        Fan(
            name=str(row.get("fanname", "")),
            model=str(row.get("fanmodel", "")),
            direction=str(row.get("fandir", "")),
            status=str(row.get("fanstatus", "")),
        )
        for row in rows(fan_body, "TABLE_faninfo", "ROW_faninfo")
    ]
    zones = rows(fan_body, "TABLE_fan_zone_speed", "ROW_fan_zone_speed")
    speed = fan_speed_percent(zones[0].get("zonespeed")) if zones else None

    power_body = section(body, "powersup")
    supplies = [
        PowerSupply(
            number=str(row.get("psnum", "")),
            model=str(row.get("psmodel", "")),
            output_w=to_int(row.get("actual_out")),
            input_w=to_int(row.get("actual_input")),
            capacity_w=to_int(row.get("tot_capa")),
            status=str(row.get("ps_status", "")),
        )
        for row in rows(power_body, "TABLE_psinfo", "ROW_psinfo")
    ]
    summary = section(power_body, "power_summary")

    return Environment(
        temperatures=temperatures,
        fans=fans,
        fan_speed_percent=speed,
        power_supplies=supplies,
        redundancy_mode=str(summary.get("ps_oper_mode", "")),
        total_draw_w=to_int(summary.get("tot_pow_input_actual_draw")),
    )


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_resources(body: dict[str, Any]) -> Resources:
    """CPU and memory use from ``show system resources``."""
    idle = _float(body.get("cpu_state_idle"))
    total = _float(body.get("memory_usage_total"))
    used = _float(body.get("memory_usage_used"))
    return Resources(
        cpu_used_percent=round(100 - idle, 1) if idle is not None else None,
        memory_used_percent=round(used * 100 / total, 1) if total and used is not None else None,
        load_1min=str(body.get("load_avg_1min", "")),
    )


def parse_port_summary(body: dict[str, Any]) -> PortSummary:
    """Front-panel port counts from ``show interface brief`` (mgmt0 excluded)."""
    ports = [
        row
        for row in rows(body, "TABLE_interface", "ROW_interface")
        if str(row.get("interface", "")).lower().startswith("ethernet")
    ]
    up = sum(1 for row in ports if str(row.get("state", "")).lower() == "up")
    no_xcvr = sum(
        1 for row in ports if "xcvr not inserted" in str(row.get("state_rsn_desc", "")).lower()
    )
    return PortSummary(total=len(ports), up=up, down=len(ports) - up, no_transceiver=no_xcvr)


def load_dashboard(client: NxapiClient) -> Dashboard:
    """Everything the dashboard shows, from one NX-API request."""
    version, environment, resources, interfaces = client.show(*DASHBOARD_COMMANDS)
    return Dashboard(
        system=parse_version(version),
        environment=parse_environment(environment),
        resources=parse_resources(resources),
        ports=parse_port_summary(interfaces),
    )
