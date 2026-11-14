"""Turns NX-API show output into what the pages display.

Pure functions over the parsed JSON bodies from app/nxapi.py, so every one of
them is tested against output recorded from a real switch
(tests/fixtures/), with no network involved.

NX-OS JSON has one quirk worth knowing: a table with a single row holds that
row as an object, and only a table with several rows holds a list. ``rows``
hides that so no parser has to remember it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.nxapi import NxapiClient

# The commands one dashboard load runs, in one NX-API request. The first five give
# the identity block: ``show version`` would give it in one command, but the switch
# needs about 1.5 seconds for it and under 120 ms for these five together (#97).
DASHBOARD_COMMANDS = (
    "show hostname",
    "show inventory",
    "show module",
    "show system uptime",
    "show system reset-reason",
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


def text(value: Any) -> str:
    """A value from NX-OS JSON as stripped text; "" for missing or null."""
    return "" if value is None else str(value).strip()


def int_or(value: Any, default: int = 0) -> int:
    """A whole number from text such as "10" or " 10 "; ``default`` if it is not one.

    ``routing`` needs the stricter ``digits_int``, which refuses signs and returns None.
    """
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def digits_int(value: Any) -> int | None:
    """A whole number from text made only of digits; None for anything else, a sign included."""
    found = text(value)
    return int(found) if found.isdigit() else None


def is_true(value: Any) -> bool:
    """True only for the word "true", in any case. ``is_enabled`` also takes "yes" and "enabled"."""
    return text(value).lower() == "true"


def is_enabled(value: Any) -> bool:
    """True for "true", "yes" or "enabled", in any case (BGP writes its flags all three ways)."""
    return text(value).lower() in ("true", "yes", "enabled")


def row_vrf(row: dict[str, Any], *keys: str) -> str:
    """The VRF a row names, read from the first of ``keys`` that holds text; "default" if none."""
    for key in keys:
        if found := text(row.get(key)):
            return found
    return "default"


# An ISO 8601 duration as the switch writes it: P7DT11H59M45S, PT5S, P0DT0H0M5.5S.
ISO_DURATION = re.compile(
    r"^P(?:(?P<d>\d+)D)?(?:T(?:(?P<h>\d+)H)?(?:(?P<m>\d+)M)?(?:(?P<s>\d+(?:\.\d+)?)S)?)?$"
)


def duration_text(value: Any) -> str:
    """ "P7DT11H59M45S" -> "7d 11h 59m 45s"; zero parts left out, "0s" if all are zero.

    Seconds may be fractional ("PT5.5S" -> "5.5s"); anything that is not a duration comes
    back unchanged. ``protocols.route_age`` and ``neighbors.readable_duration`` are
    different on purpose: they round to the largest parts, for ages in a table.
    """
    raw = text(value)
    match = ISO_DURATION.match(raw)
    if not match or not any(match.groupdict().values()):
        return raw
    shown = [f"{v}{k}" for k, v in match.groupdict().items() if v and float(v)]
    return " ".join(shown) or "0s"


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


def uptime_words(days: Any, hours: Any, minutes: Any) -> str:
    """Words such as "3 days, 2 hours, 5 minutes" from the numbers an uptime is given
    as; the larger units are left out while they are zero."""
    day, hour, minute = to_int(days) or 0, to_int(hours) or 0, to_int(minutes) or 0
    parts = []
    if day:
        parts.append(f"{day} day{'s' if day != 1 else ''}")
    if hour or day:
        parts.append(f"{hour} hour{'s' if hour != 1 else ''}")
    parts.append(f"{minute} minute{'s' if minute != 1 else ''}")
    return ", ".join(parts)


def parse_version(body: dict[str, Any]) -> SystemInfo:
    """Identity and uptime from ``show version``."""
    return SystemInfo(
        hostname=str(body.get("host_name") or "unknown"),
        model=str(body.get("chassis_id") or "unknown"),
        nxos_version=str(body.get("nxos_ver_str") or "unknown"),
        uptime=uptime_words(
            body.get("kern_uptm_days"), body.get("kern_uptm_hrs"), body.get("kern_uptm_mins")
        ),
        last_reset_reason=str(body.get("rr_reason") or ""),
    )


def chassis_row(inventory: Any) -> dict[str, Any]:
    """The chassis row of ``show inventory``: the one named "Chassis", else the first."""
    found = rows(inventory, "TABLE_inv", "ROW_inv") if isinstance(inventory, dict) else []
    named = [row for row in found if text(row.get("name")).strip('"').lower() == "chassis"]
    return (named or found or [{}])[0]


def chassis_description(inventory: Any) -> str:
    """The chassis as the inventory words it ("Nexus9000 C92160YC-X chassis"); "" when
    the inventory names none."""
    return text(chassis_row(inventory).get("desc")).strip('"').strip()


def chassis_model(inventory: Any) -> str:
    """The chassis description and product id together ("Nexus9000 C92160YC-X chassis
    N9K-C92160YC-X"), what the pages that depend on the model look for a model name
    in; "" when the inventory names none."""
    row = chassis_row(inventory)
    return " ".join(
        part for part in (chassis_description(inventory), text(row.get("productid"))) if part
    )


def module_version(module: Any) -> str:
    """The NX-OS version the active module runs, from ``show module``; "" when it
    names none."""
    if not isinstance(module, dict):
        return ""
    found = rows(module, "TABLE_modinfo", "ROW_modinfo")
    active = [row for row in found if text(row.get("status")).lower().startswith("active")]
    chosen = (active or found or [{}])[0]
    versions = rows(module, "TABLE_modwwninfo", "ROW_modwwninfo")
    mine = [row for row in versions if text(row.get("modwwn")) == text(chosen.get("modinf"))]
    return text(((mine or versions or [{}])[0]).get("sw"))


def last_reset_reason(reset: Any) -> str:
    """The newest restart reason, from ``show system reset-reason`` (it lists them
    newest first); "" when the switch lists none."""
    if not isinstance(reset, dict):
        return ""
    for slot in rows(reset, "TABLE_reason", "ROW_reason"):
        for entry in rows(slot, "TABLE_rr", "ROW_rr"):
            return text(entry.get("reason"))
    return ""


def parse_identity(
    hostname: Any, inventory: Any, module: Any, uptime: Any, reset: Any
) -> SystemInfo:
    """The same identity and uptime ``parse_version`` reads from ``show version``, from
    the bodies of ``show hostname``, ``show inventory``, ``show module``, ``show system
    uptime`` and ``show system reset-reason``."""
    hostname = hostname if isinstance(hostname, dict) else {}
    uptime = uptime if isinstance(uptime, dict) else {}
    return SystemInfo(
        hostname=text(hostname.get("hostname")) or "unknown",
        model=chassis_description(inventory) or "unknown",
        nxos_version=module_version(module) or "unknown",
        uptime=uptime_words(
            uptime.get("kn_up_days"), uptime.get("kn_up_hrs"), uptime.get("kn_up_mins")
        ),
        last_reset_reason=last_reset_reason(reset),
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
    hostname, inventory, module, uptime, reset, environment, resources, interfaces = client.show(
        *DASHBOARD_COMMANDS
    )
    return Dashboard(
        system=parse_identity(hostname, inventory, module, uptime, reset),
        environment=parse_environment(environment),
        resources=parse_resources(resources),
        ports=parse_port_summary(interfaces),
    )


def health_problems(dashboard: Dashboard) -> list[str]:
    """What needs attention, in plain words; empty when everything is fine.

    Based only on the switch's own judgement: a sensor's alarm status and
    thresholds, and the status the switch reports for each fan and power
    supply.
    """
    problems: list[str] = []
    for sensor in dashboard.environment.temperatures:
        if sensor.level == "crit":
            problems.append(
                f"Temperature {sensor.name} is {sensor.current_c}°C, at or above its "
                f"major limit of {sensor.major_c}°C."
            )
        elif sensor.level == "warn":
            problems.append(
                f"Temperature {sensor.name} is {sensor.current_c}°C, at or above its "
                f"minor limit of {sensor.minor_c}°C."
            )
    for fan in dashboard.environment.fans:
        if not fan.ok:
            problems.append(f"Fan {fan.name} reports {fan.status or 'no status'}.")
    for supply in dashboard.environment.power_supplies:
        if not supply.ok:
            problems.append(f"Power supply {supply.number} reports {supply.status or 'no status'}.")
    return problems
