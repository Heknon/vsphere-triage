"""Host hardware health from ESXi's own sensors.

A failing power supply, an overheating CPU, a bad DIMM — the host's own hardware
going sick stalls every VM on it, and none of it shows in CPU or storage
counters. ESXi exposes it through `numericSensorInfo` (PSU, fan, temperature,
voltage) and the memory/CPU/storage status groups, each carrying a health state
(green / yellow / red / unknown). This reduces them to a verdict: any red is
critical, any yellow is a warning, and no sensor data at all (a host that does
not report, or a simulator) is said rather than taken for healthy.

`read_sensors` reads them for many hosts in one property read, for a scan and
for `get_host_health`; the classification is pure and tested.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pyVmomi import vim

if TYPE_CHECKING:
    from collections.abc import Sequence

    from vsphere_triage.vcenter import VCenterSession

SENSOR_PATHS = (
    "runtime.healthSystemRuntime.systemHealthInfo.numericSensorInfo",
    "runtime.healthSystemRuntime.hardwareStatusInfo",
)


def _reading(sensor: Any) -> float | None:
    """A numeric sensor's reading in its base units, applying its unitModifier."""
    raw = getattr(sensor, "currentReading", None)
    if not isinstance(raw, (int, float)) or isinstance(raw, bool):
        return None
    modifier = getattr(sensor, "unitModifier", 0) or 0
    return round(raw * (10**modifier), 3) if isinstance(modifier, int) else float(raw)


def flatten(row: dict[str, Any]) -> list[dict[str, Any]]:
    """One host row's sensors and hardware status groups as {name, type, health, reading, unit}."""
    sensors: list[dict[str, Any]] = [
        {
            "name": getattr(sensor, "name", None),
            "type": getattr(sensor, "sensorType", None),
            "health": getattr(getattr(sensor, "healthState", None), "key", None),
            # currentReading is scaled by 10^unitModifier: 4500 with modifier -2 is 45.0.
            "reading": _reading(sensor),
            "unit": getattr(sensor, "baseUnits", None) or None,
        }
        for sensor in row.get(SENSOR_PATHS[0]) or []
    ]
    hardware_status = row.get(SENSOR_PATHS[1])
    for group in ("memoryStatusInfo", "cpuStatusInfo", "storageStatusInfo"):
        sensors.extend(
            {
                "name": getattr(item, "name", None),
                "type": group.removesuffix("StatusInfo"),
                "health": getattr(getattr(item, "status", None), "key", None),
                "reading": None,
            }
            for item in getattr(hardware_status, group, None) or []
        )
    return sensors


def read_sensors(session: VCenterSession, host_morefs: Sequence[str]) -> dict[str, list[dict[str, Any]]]:
    """The hardware sensors of each host, by moref, in one property read. Read-only."""
    if not host_morefs:
        return {}
    rows = session.retrieve(
        vim.HostSystem,
        SENSOR_PATHS,
        objects=[session.reference("HostSystem", moref) for moref in host_morefs],
    )
    return {row["moref"]: flatten(row) for row in rows}


# unknown is not a failure signal — many sensors report it when idle — so only
# red and yellow count against health.
_RED = "red"
_YELLOW = "yellow"


def classify_sensors(sensors: list[dict[str, Any]]) -> dict[str, Any]:
    """Partition hardware sensors into red/yellow and give a verdict. Pure.

    `sensors`: {name, type, health, reading?}. `health` is ESXi's state key.
    """
    red = [sensor for sensor in sensors if str(sensor.get("health", "")).lower() == _RED]
    yellow = [sensor for sensor in sensors if str(sensor.get("health", "")).lower() == _YELLOW]
    findings = []
    if red:
        names = ", ".join(sorted({str(sensor.get("name")) for sensor in red})[:10])
        findings.append(
            f"{len(red)} hardware sensor(s) CRITICAL (red): {names} — a failing host stalls its VMs"
        )
    if yellow:
        names = ", ".join(sorted({str(sensor.get("name")) for sensor in yellow})[:10])
        findings.append(f"{len(yellow)} hardware sensor(s) warning (yellow): {names}")
    green = [sensor for sensor in sensors if str(sensor.get("health", "")).lower() == "green"]
    if sensors and not green and not red and not yellow:
        findings.append(
            f"none of the host's {len(sensors)} hardware sensor(s) reports a state (all unknown): its CIM "
            "provider is likely off or broken — the hardware is not judged, not evidence it is fine"
        )
    if not sensors:
        findings.append(
            "no hardware sensor data from this host (it reports none, or the host is a simulator)"
        )
    return {
        # No sensors is no evidence: unknown, not healthy.
        # Only green proves health: no sensors, or only unknown ones (a CIM provider
        # that is off or broken on the host), is unknown, not healthy.
        "healthy": False if (red or yellow) else (True if green else None),
        "green_total": len(green),
        "sensors_total": len(sensors),
        "red": red[:20],
        "yellow": yellow[:20],
        "findings": findings
        or [
            f"{len(green)} of {len(sensors)} hardware sensor(s) green, none red or yellow"
            + (" (the rest report no state)" if len(green) < len(sensors) else "")
        ],
    }
