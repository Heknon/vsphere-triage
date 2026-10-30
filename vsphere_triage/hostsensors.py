"""Host hardware health from ESXi's own sensors.

A failing power supply, an overheating CPU, a bad DIMM — the host's own hardware
going sick stalls every VM on it, and none of it shows in CPU or storage
counters. ESXi exposes it through `numericSensorInfo` (PSU, fan, temperature,
voltage) and the memory/CPU/storage status groups, each carrying a health state
(green / yellow / red / unknown). This reduces them to a verdict: any red is
critical, any yellow is a warning, and no sensor data at all (a host that does
not report, or a simulator) is said rather than taken for healthy.

Pure and tested; the read is in `get_host_health`.
"""

from __future__ import annotations

from typing import Any

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
    if not sensors:
        findings.append(
            "no hardware sensor data from this host (it reports none, or the host is a simulator)"
        )
    return {
        # No sensors is no evidence: unknown, not healthy.
        "healthy": False if (red or yellow) else (None if not sensors else True),
        "sensors_total": len(sensors),
        "red": red[:20],
        "yellow": yellow[:20],
        "findings": findings or ["all hardware sensors green"],
    }
