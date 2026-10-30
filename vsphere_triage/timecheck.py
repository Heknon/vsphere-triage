"""Host time health: NTP configuration and clock skew against vCenter.

A host whose clock drifts breaks TLS handshakes and Kerberos/AD token auth —
one of the roots of the SSL/handshake errors seen fleet-wide, separate from
session exhaustion. The signals are read-only: the NTP servers configured, the
time service's state, and the host's own clock (one `QueryDateTime` per host)
compared with vCenter's.

The classification is pure (`classify_host_time`); the fleet orchestration reads
each vCenter's hosts and measures skew where the host answers.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from vsphere_triage.inventory import read_host_time

if TYPE_CHECKING:
    from collections.abc import Sequence

    from vsphere_triage.config import Settings, Thresholds
    from vsphere_triage.vcenter import VCenterPool, VCenterSession

# Auth (Kerberos / Active Directory) rejects a ticket past roughly this much skew.
AUTH_BREAKS_SECONDS = 300.0


def classify_host_time(row: dict[str, Any], thresholds: Thresholds) -> dict[str, Any]:
    """Judge one host's time config and skew. Pure: the raw row in, a verdict out."""
    name = row["name"]
    connection_state = row.get("connection_state")
    ntp_servers = row.get("ntp_servers") or []
    running = row.get("service_running")
    policy = row.get("service_policy")
    skew = row.get("skew_seconds")
    result: dict[str, Any] = {
        "vcenter": row["vcenter"],
        "moref": row["moref"],
        "name": name,
        "connection_state": connection_state,
        "ntp_servers": ntp_servers,
        "time_service": row.get("service_key"),
        "time_service_running": running,
        "time_service_policy": policy,
        "skew_seconds": None if skew is None else round(skew, 1),
        "skew_error": row.get("skew_error"),
    }
    findings: list[str] = []
    if connection_state not in (None, "connected"):
        result["checked"] = False
        result["findings"] = [f"host is {connection_state}; its time configuration cannot be judged"]
        result["healthy"] = None
        return result
    result["checked"] = True
    if not ntp_servers:
        findings.append("no NTP servers configured: the clock is free-running and will drift")
    if running is False:
        findings.append("the time service is not running: the clock is not being disciplined")
    if policy == "off":
        findings.append("the time service start policy is 'off': it will not come up on the next boot")
    if skew is not None and abs(skew) >= thresholds.clock_skew_seconds:
        past_auth = (
            " — past the ~300 s where Kerberos/AD auth fails outright"
            if abs(skew) >= AUTH_BREAKS_SECONDS
            else ""
        )
        findings.append(
            f"clock is {skew:+.0f} s from vCenter, over the {thresholds.clock_skew_seconds:g} s "
            f"threshold{past_auth}"
        )
    result["findings"] = findings
    result["healthy"] = not findings
    return result


def _scan_host_time(session: VCenterSession, *, measure_skew: bool) -> list[dict[str, Any]]:
    """Read every host's time config, and its clock skew where it answers. Blocking."""
    rows = read_host_time(session)
    if measure_skew:
        vcenter_now = session.now()
        for row in rows:
            if row.get("connection_state") not in (None, "connected"):
                continue
            system = row.get("datetime_system_moref")
            if not system:
                row["skew_error"] = "the host does not expose a dateTimeSystem"
                continue
            try:
                host_now = session.host_datetime(system)
                row["skew_seconds"] = (host_now - vcenter_now).total_seconds()
            except Exception as error:  # noqa: BLE001 - a host that will not answer is not a healthy one
                row["skew_error"] = f"clock not read ({type(error).__name__})"
    return rows


async def check_host_time(
    pool: VCenterPool,
    settings: Settings,
    names: Sequence[str],
    *,
    measure_skew: bool,
) -> dict[str, Any]:
    """Each host's NTP configuration and clock skew across the vCenters, worst first."""
    results = await asyncio.gather(
        *(
            pool.run(name, lambda session: _scan_host_time(session, measure_skew=measure_skew))
            for name in names
        ),
        return_exceptions=True,
    )
    verdicts: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    read: dict[str, int] = {}
    for name, result in zip(names, results, strict=True):
        if isinstance(result, BaseException):
            errors[name] = str(result)
            continue
        read[name] = len(result)
        verdicts.extend(classify_host_time(row, settings.thresholds) for row in result)

    unhealthy = [verdict for verdict in verdicts if verdict["healthy"] is False]
    unhealthy.sort(key=lambda verdict: abs(verdict["skew_seconds"] or 0), reverse=True)
    skewed = [
        verdict
        for verdict in unhealthy
        if verdict["skew_seconds"] is not None
        and abs(verdict["skew_seconds"]) >= settings.thresholds.clock_skew_seconds
    ]
    could_not_measure = [verdict for verdict in verdicts if verdict.get("skew_error")]
    findings = [
        f"{len(unhealthy)} of {len(verdicts)} hosts have a time problem across {len(read)} vCenter(s)",
        *(
            f"{verdict['vcenter']}:{verdict['name']} — {'; '.join(verdict['findings'])}"
            for verdict in unhealthy[:15]
        ),
    ]
    if skewed:
        findings.append(
            f"{len(skewed)} host(s) are skewed from vCenter — skew breaks TLS and Kerberos/AD auth, "
            "a common root of the SSL/handshake errors clients hit"
        )
    if measure_skew and could_not_measure:
        findings.append(
            f"{len(could_not_measure)} host(s): clock not measured (simulator, permission, or no "
            "dateTimeSystem) — their NTP configuration was still read"
        )
    for name, error in errors.items():
        findings.append(f"vCenter {name} not read: {error}")
    return {
        "findings": findings,
        "hosts_total": len(verdicts),
        "unhealthy_total": len(unhealthy),
        "hosts": unhealthy[:50] if unhealthy else verdicts[:50],
        "all_healthy": bool(verdicts) and not unhealthy,
        "vcenters_read": read,
        "errors": errors,
        "note": (
            "skew is the host's QueryDateTime clock minus vCenter's, at read time; NTP config and the "
            "time service state are read even where the clock itself cannot be measured"
        ),
    }
