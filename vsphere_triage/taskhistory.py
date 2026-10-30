"""Reading vCenter tasks over a window — what was *done* around the incident.

Events say what happened; tasks say what someone (or an automation) *did*. A
storage-vMotion sweep onto one datastore, a mass reconfigure, a snapshot
consolidation across a cluster — these routinely slow or stall the VMs caught in
them, and none of it shows in a single VM's counters. This reads the task stream
over a window and groups it, so "a cause someone introduced" becomes visible.

Tasks are read from the event stream (each task raises a TaskEvent carrying its
operation, target, state and who asked), so this needs no method beyond the
QueryEvents the rest of the server already uses. Pure and tested here.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

# Operation-key substrings grouped into what they do, lowercased. The first
# matching category wins.
CATEGORIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("migration", ("relocate", "migrate", "vmotion", "drm.execute")),
    ("reconfigure", ("reconfig",)),
    ("snapshot", ("snapshot",)),
    ("clone", ("clone", "createvm", "deploy")),
    ("power", ("poweroff", "poweron", "reset", "suspend", "reboot", "shutdown")),
    ("destroy", ("destroy", "delete", "unregister")),
)


def categorize(operation: str) -> str:
    """Which family a task operation belongs to: migration, reconfigure, …, or other."""
    lowered = operation.lower()
    for name, needles in CATEGORIES:
        if any(needle in lowered for needle in needles):
            return name
    return "other"


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
    if failures:
        findings.append(f"{len(failures)} task(s) failed in the window — see failures")
    return {
        "window_minutes": window_minutes,
        "since": begin,
        "total_tasks": len(rows),
        "by_family": dict(sorted(families.items(), key=lambda item: -item[1])),
        "by_user": dict(sorted(by_user.items(), key=lambda item: -item[1])[:5]),
        "failures": failures[:20],
        "findings": findings
        or [
            (
                "no notable tasks in the window (each task's state is as recorded when it was created, "
                "so a task that failed later may not show as failed here; check the VM's or host's events)"
            )
        ],
        "note": "task states come from TaskEvents, a snapshot taken when each task was created",
    }
