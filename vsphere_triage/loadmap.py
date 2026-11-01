"""Tools errors, mass creation, host CPU and guest-transfer failures, lined up per host over one window.

Many VMware Tools errors at once, with SSL errors on guest file transfers at the
same time, can have one cause or several. A creation burst (clones, then
power-ons) loads the hosts and vCenter together; an overcommitted host starves
its guests, so Tools comes up late or its heartbeat drops; the same host's hostd
answers guest operations slowly, and its transfers are dropped. Or the Tools
errors sit on the busy hosts while the transfer failures spread over every
host, which points at the network or the client instead.

This reads, per host: the VMs in Tools trouble now, how many VMs were created
and powered on in the window, the host's CPU demand over it, and (optionally)
how many guest-transfer/TLS lines its hostd log holds. Then it says whether the
Tools trouble follows host load, follows the creation burst, and lands on the
same hosts as the transfer failures. The vCenter-wide clone and power-on waves
come from the task stream.

Reads only: the inventory, the performance counters, the task history and the
host logs, all on the read-only list.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from pyVmomi import vim

from vsphere_triage import hostlogs, taskhistory
from vsphere_triage.checks import (
    BOOTED_NOT_UP,
    BUSY_NOT_UP,
    GUEST_OPS_NOT_READY,
    HEARTBEAT_INTERMITTENT,
    HUNG,
    LOST_HEARTBEAT,
    NO_BOOT_TIME,
    TOOLS_FLAPPING,
    classify,
)
from vsphere_triage.contention import hosts_cpu
from vsphere_triage.inventory import read_inventory

if TYPE_CHECKING:
    from collections.abc import Sequence

    from vsphere_triage.config import Settings
    from vsphere_triage.vcenter import VCenterPool, VCenterSession

# The states and flags a monitoring "Tools error" comes from: Tools not up when it
# should be, or up with a heartbeat that drops.
TOOLS_TROUBLE_STATES = (HUNG, BUSY_NOT_UP, BOOTED_NOT_UP, LOST_HEARTBEAT, NO_BOOT_TIME)
TOOLS_TROUBLE_FLAGS = (HEARTBEAT_INTERMITTENT, TOOLS_FLAPPING)
# A host that took this many power-ons in the window took part in the burst.
BURST_POWER_ONS = 3
# The share of the Tools trouble that must sit on one kind of host to call it the pattern.
FOLLOWS_SHARE = 0.6
SHOWN = 8


def tools_trouble(state: str, flags: Sequence[str]) -> bool:
    """Whether a verdict is the kind a monitoring Tools error reports. Pure."""
    return state in TOOLS_TROUBLE_STATES or any(flag in TOOLS_TROUBLE_FLAGS for flag in flags)


def _share(part: int, whole: int) -> float:
    return part / whole if whole else 0.0


def correlate(rows: list[dict[str, Any]], *, logs_read: bool) -> list[str]:
    """What the per-host rows say: does Tools trouble follow load, the burst, the transfer failures. Pure.

    Each row: {vcenter, host, tools_trouble, overcommitted, powered_on_in_window,
    log_hits (None when not read)}.
    """
    troubled = sum(row["tools_trouble"] for row in rows)
    findings: list[str] = []
    if not troubled:
        findings.append("no VM is in Tools trouble now (hung, not up after boot, or a heartbeat that drops)")
    else:
        hot = [row for row in rows if row.get("overcommitted")]
        on_hot = sum(row["tools_trouble"] for row in hot)
        burst = [row for row in rows if row.get("powered_on_in_window", 0) >= BURST_POWER_ONS]
        on_burst = sum(row["tools_trouble"] for row in burst)
        hosts_with = [row for row in rows if row["tools_trouble"]]
        findings.append(
            f"{troubled} VM(s) in Tools trouble on {len(hosts_with)} of {len(rows)} hosts; most on "
            + ", ".join(f"{row['host']} ({row['tools_trouble']})" for row in hosts_with[:3])
        )
        if hot and _share(on_hot, troubled) >= FOLLOWS_SHARE:
            findings.append(
                f"Tools trouble follows host load: {on_hot} of {troubled} on overcommitted host(s) "
                f"({', '.join(row['host'] for row in hot[:SHOWN])}) — starved guests bring Tools up late "
                "and drop its heartbeat"
            )
        elif hot:
            findings.append(
                f"only {on_hot} of {troubled} Tools-trouble VMs are on overcommitted hosts: host CPU is not "
                "the common factor"
            )
        if burst and _share(on_burst, troubled) >= FOLLOWS_SHARE:
            findings.append(
                f"Tools trouble follows the creation burst: {on_burst} of {troubled} on hosts that took "
                f"{BURST_POWER_ONS} or more power-ons in the window"
            )
        if not any(row.get("overcommitted") is not None for row in rows):
            findings.append("host CPU demand could not be read for the window, so load could not be judged")
    if logs_read:
        hit = [row for row in rows if row.get("log_hits")]
        if not hit:
            findings.append("no guest-transfer/TLS lines in the hostd logs read")
        else:
            hits = sum(row["log_hits"] for row in hit)
            on_troubled = sum(
                row["log_hits"] for row in hit if row["tools_trouble"] or row.get("overcommitted")
            )
            if _share(on_troubled, hits) >= FOLLOWS_SHARE:
                findings.append(
                    f"guest-transfer failures land on the same hosts: {on_troubled} of {hits} hostd lines on "
                    "hosts with Tools trouble or overcommit — one load explains both"
                )
            else:
                findings.append(
                    f"guest-transfer failures are not where the Tools trouble is: {hits - on_troubled} of "
                    f"{hits} hostd lines on otherwise quiet hosts — look at the network or the client "
                    "for those"
                )
    return findings


def _empty_row(session: VCenterSession, moref: str, host: Any) -> dict[str, Any]:
    return {
        "vcenter": session.vcenter.name,
        "host": host.name,
        "moref": moref,
        "cluster": host.cluster,
        "vms": 0,
        "tools_trouble": 0,
        "tools_trouble_vms": [],
        "guest_ops_not_ready": 0,
        "created_in_window": 0,
        "powered_on_in_window": 0,
        "overcommitted": None,
        "cpu_peak_percent": None,
        "log_hits": None,
    }


def _count_vms(rows: dict[str, dict[str, Any]], inventory: Any, settings: Settings, begin: Any) -> None:
    """Add each VM to its host's row: Tools trouble, guest-ops readiness, created and powered on."""
    for vm in inventory.vms:
        row = rows.get(vm.host_moref or "")
        if row is None or vm.template:
            continue
        verdict = classify(vm, settings.thresholds)
        row["vms"] += 1
        if tools_trouble(verdict.state, verdict.flags):
            row["tools_trouble"] += 1
            if len(row["tools_trouble_vms"]) < SHOWN:
                row["tools_trouble_vms"].append({"name": vm.name, "moref": vm.moref, "state": verdict.state})
        if GUEST_OPS_NOT_READY in verdict.flags:
            row["guest_ops_not_ready"] += 1
        if vm.created and vm.created >= begin:
            row["created_in_window"] += 1
        if vm.power_on_time and vm.power_on_time >= begin:
            row["powered_on_in_window"] += 1


def _add_cpu(
    session: VCenterSession,
    rows: dict[str, dict[str, Any]],
    inventory: Any,
    settings: Settings,
    begin: Any,
    end: Any,
) -> list[str]:
    live = [host for host in inventory.hosts.values() if host.connection_state in (None, "connected")]
    try:
        cpu, unknown = hosts_cpu(session, live, begin=begin, end=end, thresholds=settings.thresholds)
    except vim.fault.NotAuthenticated:
        raise
    except Exception as error:  # noqa: BLE001 - without counters the rest still stands, said so
        return [f"host CPU not read ({type(error).__name__})"]
    for moref, verdict in cpu.items():
        rows[moref]["overcommitted"] = verdict.get("overcommitted")
        rows[moref]["cpu_peak_percent"] = verdict.get("peak_percent_of_capacity")
    return ["host CPU counters unavailable: " + ", ".join(unknown)] if unknown else []


def _waves(session: VCenterSession, begin: Any, end: Any) -> tuple[dict[str, Any], list[str]]:
    try:
        tasks, _ = session.tasks(begin=begin, end=end)
    except vim.fault.NotAuthenticated:
        raise
    except Exception as error:  # noqa: BLE001
        return {}, [f"tasks not read ({type(error).__name__}); clone and power-on waves unknown"]
    task_rows = [
        {
            "operation": getattr(info, "descriptionId", None) or getattr(info, "name", "") or "",
            "time": getattr(info, "queueTime", None),
        }
        for info in tasks
    ]
    peaks, findings = taskhistory.creation_waves(task_rows)
    return {"busiest": {family: peak for family, peak in peaks.items() if peak}, "findings": findings}, []


def _add_log_hits(session: VCenterSession, rows: dict[str, dict[str, Any]]) -> tuple[bool, list[str]]:
    swept = hostlogs.sweep_vcenter(
        session, log="hostd", pattern=hostlogs.GUEST_TRANSFER_PATTERN, lines=3000, keep=1
    )
    read = False
    for line in swept["rows"]:
        if line.get("read"):
            rows[line["moref"]]["log_hits"] = line.get("matched", 0)
            read = True
    if read:
        return True, []
    first = next((line.get("reason") for line in swept["rows"] if not line.get("read")), None)
    return False, [f"no hostd log could be read ({first}); guest-transfer failures per host unknown"]


def _read_vcenter(
    session: VCenterSession, settings: Settings, *, minutes: int, read_logs: bool
) -> dict[str, Any]:
    """Every host's Tools trouble, creation, CPU and log hits on one vCenter. Blocking."""
    now = session.now()
    begin = now - timedelta(minutes=minutes)
    inventory = read_inventory(session, with_devices=False)
    rows = {moref: _empty_row(session, moref, host) for moref, host in inventory.hosts.items()}
    _count_vms(rows, inventory, settings, begin)
    notes = _add_cpu(session, rows, inventory, settings, begin, now)
    waves, wave_notes = _waves(session, begin, now)
    notes += wave_notes
    logs_read = False
    if read_logs:
        logs_read, log_notes = _add_log_hits(session, rows)
        notes += log_notes
    return {"rows": list(rows.values()), "waves": waves, "notes": notes, "logs_read": logs_read}


async def correlate_hosts(
    pool: VCenterPool, settings: Settings, names: Sequence[str], *, minutes: int, read_logs: bool
) -> dict[str, Any]:
    """Line up Tools trouble, creation, CPU and transfer failures per host across the vCenters."""

    def work(session: VCenterSession) -> dict[str, Any]:
        return _read_vcenter(session, settings, minutes=minutes, read_logs=read_logs)

    results = await asyncio.gather(*(pool.sweep(name, work) for name in names), return_exceptions=True)
    rows: list[dict[str, Any]] = []
    waves: dict[str, Any] = {}
    notes: list[str] = []
    logs_read = False
    errors: dict[str, str] = {}
    for name, result in zip(names, results, strict=True):
        if isinstance(result, BaseException):
            errors[name] = str(result)
            continue
        rows.extend(result["rows"])
        if result["waves"]:
            waves[name] = result["waves"]
        notes.extend(f"{name}: {note}" for note in result["notes"])
        logs_read = logs_read or result["logs_read"]
    rows.sort(
        key=lambda row: (row["tools_trouble"], row["log_hits"] or 0, row["cpu_peak_percent"] or 0),
        reverse=True,
    )
    findings = correlate(rows, logs_read=logs_read)
    for name, wave in waves.items():
        findings.extend(f"{name}: {finding}" for finding in wave["findings"])
    findings.extend(f"vCenter {name} not read: {error}" for name, error in errors.items())
    not_ready = sum(row["guest_ops_not_ready"] for row in rows)
    if not_ready:
        findings.append(
            f"{not_ready} VM(s) run Tools but are not ready for guest operations: transfers started on them "
            "now fail; the automation should wait for guestOperationsReady"
        )
    return {
        "findings": findings,
        "window_minutes": minutes,
        "hosts": rows[:40],
        "hosts_total": len(rows),
        "task_waves": waves,
        "notes": notes,
        "errors": errors,
        "note": (
            "Tools trouble is the VMs' state now; creation and power-ons are VMs whose create date or "
            "power-on falls in the window; CPU is the host's demand peak over it; log hits are hostd lines "
            "matching guest transfers, TLS and dropped connections in the last 3000 lines"
        ),
    }
