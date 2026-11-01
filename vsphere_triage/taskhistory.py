"""Reading vCenter tasks over a window — what was *done* around the incident.

Events say what happened; tasks say what someone (or an automation) *did*. A
storage-vMotion sweep onto one datastore, a mass reconfigure, a snapshot
consolidation across a cluster — these routinely slow or stall the VMs caught in
them, and none of it shows in a single VM's counters. This reads the task stream
over a window and groups it, so "a cause someone introduced" becomes visible.

Tasks are read through a task history collector (`VCenterSession.tasks`), which
holds each task's final state: the TaskEvents in the event stream carry a task
as it was queued, so they never say it failed. Pure and tested here.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

# Operation-key substrings grouped into what they do, lowercased. The first
# matching category wins.
CATEGORIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    # Power first: DRS's 'Drm.ExecuteVmPowerOnLRO' (initial placement of a power-on)
    # is a power-on, not a migration, and a routine burst of them is no vMotion wave.
    ("power", ("poweroff", "poweron", "resetvm", "suspend", "reboot", "shutdown", "standbyguest")),
    ("migration", ("relocate", "migrate", "vmotion", "drm.executevmotion")),
    ("reconfigure", ("reconfig",)),
    ("snapshot", ("snapshot", "consolidate")),
    ("clone", ("clone", "createvm", "deploy")),
    ("destroy", ("destroy", "delete", "unregister")),
)


def categorize(operation: str) -> str:
    """Which family a task operation belongs to: migration, reconfigure, …, or other."""
    lowered = operation.lower()
    if lowered.endswith(".reset"):  # VirtualMachine.reset, but not resetGuestInformation
        return "power"
    for name, needles in CATEGORIES:
        if any(needle in lowered for needle in needles):
            return name
    return "other"


# A burst worth naming: this many tasks of one family inside one bucket.
BUCKET_MINUTES = 10
CLONE_WAVE = 10
POWER_ON_WAVE = 20


def is_power_on(operation: str) -> bool:
    """Whether a task operation powers a VM on (including DRS's initial placement of one)."""
    lowered = operation.lower()
    return "poweron" in lowered


def busiest_bucket(times: list[datetime], *, minutes: int = BUCKET_MINUTES) -> dict[str, Any] | None:
    """The `minutes`-long bucket holding the most of `times`: its start and count. Pure."""
    if not times:
        return None
    width = timedelta(minutes=minutes)
    first = min(times)
    counts: dict[int, int] = {}
    for moment in times:
        index = int((moment - first) / width)
        counts[index] = counts.get(index, 0) + 1
    index, count = max(counts.items(), key=lambda item: (item[1], -item[0]))
    return {"start": first + index * width, "minutes": minutes, "count": count}


def creation_waves(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    """Clone and power-on bursts: the busiest bucket of each, and a finding for a wave. Pure.

    Mass VM creation is clones (or deploys) followed by power-ons; at once, they
    load the hosts and vCenter together, which is when Tools comes up late and
    guest operations fail.
    """
    clone_times = [
        row["time"]
        for row in rows
        if categorize(str(row.get("operation", ""))) == "clone" and row.get("time")
    ]
    power_times = [
        row["time"] for row in rows if is_power_on(str(row.get("operation", ""))) and row.get("time")
    ]
    peaks = {"clone": busiest_bucket(clone_times), "power_on": busiest_bucket(power_times)}
    findings = []
    for family, threshold, words in (
        ("clone", CLONE_WAVE, "clone/deploy"),
        ("power_on", POWER_ON_WAVE, "power-on"),
    ):
        peak = peaks[family]
        if peak and peak["count"] >= threshold:
            findings.append(
                f"{words} wave: {peak['count']} {words} tasks in the {BUCKET_MINUTES} minutes from "
                f"{peak['start']:%H:%M}Z — mass creation loads the hosts and vCenter at once, which is when "
                "Tools comes up late and guest operations fail"
            )
    return peaks, findings


def summarize_tasks(rows: list[dict[str, Any]], *, now: datetime, window_minutes: float) -> dict[str, Any]:
    """Group tasks by family over the window, flag waves and failures.

    `rows`: {operation, target, state, time, user}. `state` is the task state
    ('success'/'error'/…); a burst of migrations or reconfigures, or a cluster of
    failures, is called out as a possible cause introduced during the window.
    """
    begin = now - timedelta(minutes=window_minutes)
    families: dict[str, int] = {}
    failures: list[dict[str, Any]] = []
    by_user: dict[str, int] = {}
    for row in rows:
        family = categorize(str(row.get("operation", "")))
        families[family] = families.get(family, 0) + 1
        user = row.get("user") or "unknown"
        by_user[user] = by_user.get(user, 0) + 1
        if str(row.get("state", "")).lower() == "error":
            failures.append(
                {
                    "operation": row.get("operation"),
                    "target": row.get("target"),
                    "time": row.get("time"),
                    "user": row.get("user"),
                    "error": row.get("error"),
                }
            )
    findings = []
    if families.get("migration", 0) >= 10:  # noqa: PLR2004 - a wave, not one move
        findings.append(
            f"{families['migration']} migration tasks in the window — a storage- or host-vMotion wave, "
            "which can saturate the destination datastore or host while it runs"
        )
    if families.get("reconfigure", 0) >= 10:  # noqa: PLR2004 - a sweep, not one edit
        findings.append(f"{families['reconfigure']} reconfigure tasks — a mass change swept the fleet")
    if families.get("snapshot", 0) >= 10:  # noqa: PLR2004 - a sweep
        findings.append(
            f"{families['snapshot']} snapshot tasks — a snapshot or consolidation sweep, which hits "
            "datastore I/O hard"
        )
    peaks, wave_findings = creation_waves(rows)
    findings.extend(wave_findings)
    if failures:
        findings.append(f"{len(failures)} task(s) failed in the window — see failures")
    return {
        "window_minutes": window_minutes,
        "since": begin,
        "total_tasks": len(rows),
        "by_family": dict(sorted(families.items(), key=lambda item: -item[1])),
        "by_user": dict(sorted(by_user.items(), key=lambda item: -item[1])[:5]),
        "busiest": {family: peak for family, peak in peaks.items() if peak},
        "failures": failures[:20],
        "findings": findings or ["no notable tasks in the window"],
    }
