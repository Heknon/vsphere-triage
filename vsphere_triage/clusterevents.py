"""Reading cluster-level events — why a whole cluster moved at once.

A per-VM diagnosis explains one machine. When many machines reboot or go
unreachable together, the cause is usually above them: a vSphere HA restart
after a host failed or was isolated, a DRS migration wave, or a host dropping
out of vCenter. Those are events on the cluster and its hosts, not on any VM, so
this reads them over a window and names the shape — "N VMs restarted by HA
after host X failed at 02:11" — instead of leaving it to be inferred from VMs
that merely correlate.

The event-id spelling drifts across vCenter versions, so classification is by
pattern over each event's type name and message (heuristic, like the boot-log
reader), and every match carries its event so a reader judges the line. Pure and
tested here; the read is in the tool.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

# Each bucket: a name, what it means, and a pattern matched against the event's
# class name and formatted message (case-insensitive). Order matters — the first
# match wins, most specific first.
BUCKETS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "ha_vm_restart",
        "vSphere HA restarted a VM after its host failed — a host problem, not a per-VM one",
        # vCenter 6.x-8 logs this as an EventEx, com.vmware.vc.ha.VmRestartedByHAEvent,
        # whose message reads "vSphere HA restarted virtual machine ...".
        re.compile(r"(?i)(restarted by (vsphere )?ha|VmRestartedByHaEvent|ha restarted|das.*restart)"),
    ),
    (
        "host_isolation",
        "a host was isolated from the management network (HA may have acted)",
        re.compile(r"(?i)(isolat|HostIsolated|no.*management network|HostNoRedundantManagement)"),
    ),
    (
        # Before host_failure: HostConnectionLostEvent's own message reads "Host X is
        # not responding", which is vCenter losing the host, not the host failing.
        "host_connection_lost",
        "a host lost its connection to vCenter",
        re.compile(r"(?i)(connection.*lost|HostConnectionLost|host .*disconnected|not responding)"),
    ),
    (
        "host_failure",
        "a host failed (vSphere HA declared it failed)",
        re.compile(r"(?i)(HostFailed|DasHostFailed|ha.*host.*fail)"),
    ),
    (
        "vm_failover_failed",
        "a VM could not be restarted or powered on (HA failover may have failed)",
        re.compile(
            r"(?i)(FailedToPowerOn|failover.*fail|insufficient.*failover|not.*enough.*resources|"
            r"ha\.FailedRestartAfterIsolation|vmrestartedbyha.*fail)"
        ),
    ),
    (
        "host_maintenance",
        "a host entered maintenance mode (its VMs were migrated or powered off)",
        re.compile(r"(?i)(entered maintenance|EnteredMaintenanceMode|EnteringMaintenance)"),
    ),
    (
        "drs_migration",
        "a VM was migrated between hosts (DRS load balancing, an evacuation, or by hand)",
        # The completed migration only: one vMotion also logs a 'being migrated'
        # event and a task, which would count each move two or three times.
        re.compile(r"(?i)\b(DrsVmMigratedEvent|VmMigratedEvent)\b"),
    ),
)


def classify_event(type_name: str, message: str) -> tuple[str, str] | None:
    """The (bucket, meaning) a cluster event falls in, or None if it is not one we track."""
    text = f"{type_name} {message}"
    for name, meaning, pattern in BUCKETS:
        if pattern.search(text):
            return name, meaning
    return None


def summarize_cluster_events(
    rows: list[dict[str, Any]], *, now: datetime, window_minutes: float
) -> dict[str, Any]:
    """Group cluster events by kind over the window, with the hosts and VMs each touched.

    `rows` are plain dicts: {type, time, message, host, vm}. The findings call
    out the shapes that explain a mass incident — an HA restart wave, a host
    failure, a migration surge — with the count and the span.
    """
    begin = now - timedelta(minutes=window_minutes)
    buckets: dict[str, dict[str, Any]] = {}
    for row in rows:
        hit = classify_event(str(row.get("type", "")), str(row.get("message", "")))
        if hit is None:
            continue
        name, meaning = hit
        entry = buckets.setdefault(
            name, {"meaning": meaning, "count": 0, "first": None, "last": None, "hosts": set(), "vms": set()}
        )
        entry["count"] += 1
        moment = row.get("time")
        if isinstance(moment, datetime):
            entry["first"] = moment if entry["first"] is None else min(entry["first"], moment)
            entry["last"] = moment if entry["last"] is None else max(entry["last"], moment)
        if row.get("host"):
            entry["hosts"].add(row["host"])
        if row.get("vm"):
            entry["vms"].add(row["vm"])
    findings = []
    restart = buckets.get("ha_vm_restart")
    if restart and restart["count"]:
        hosts = ", ".join(sorted(restart["hosts"])[:5]) or "unknown host(s)"
        findings.append(
            f"vSphere HA restarted {restart['count']} VM(s) between {_iso(restart['first'])} and "
            f"{_iso(restart['last'])} — a host failure on {hosts}, not a per-VM problem; the restarted "
            "VMs rebooting is expected, so judge them from that restart, not as independent hangs"
        )
    for name in ("host_failure", "host_isolation", "host_connection_lost", "vm_failover_failed"):
        entry = buckets.get(name)
        if entry and entry["count"]:
            hosts = ", ".join(sorted(entry["hosts"])[:5]) or "—"
            findings.append(f"{entry['count']}x {name} ({entry['meaning']}); hosts: {hosts}")
    migration = buckets.get("drs_migration")
    if migration and migration["count"] >= 10:  # noqa: PLR2004 - a wave, not a stray balance move
        findings.append(
            f"{migration['count']} VM migrations in the window — a migration wave (an evacuation or "
            "heavy rebalancing) can slow the VMs involved while it runs"
        )
    return {
        "window_minutes": window_minutes,
        "since": begin,
        "buckets": {
            name: {
                "meaning": entry["meaning"],
                "count": entry["count"],
                "first": entry["first"],
                "last": entry["last"],
                "hosts": sorted(entry["hosts"]),
                "vms": sorted(entry["vms"])[:20],
            }
            for name, entry in buckets.items()
        },
        "findings": findings or ["no HA, host-failure or DRS events in the window"],
    }


def _iso(moment: datetime | None) -> str:
    """A timestamp for a finding, or a dash when it is unknown."""
    return moment.isoformat() if isinstance(moment, datetime) else "—"
