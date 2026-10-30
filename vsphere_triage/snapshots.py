"""Fleet snapshot query: the VMs whose snapshots are big, old, or deeply chained.

Snapshots are a top production cause here — a forgotten one grows unbounded,
fills the datastore, and slows every read through its redo chain (the 50 GB
snapshot). This finds them across the vCenters, biggest first, with the space
each is using and how old it is, so you can see what to consolidate.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from vsphere_triage.ages import under_any
from vsphere_triage.inventory import read_folders, read_vm_snapshots

if TYPE_CHECKING:
    from collections.abc import Sequence

    from vsphere_triage.config import Settings
    from vsphere_triage.vcenter import VCenterPool, VCenterSession

GIGABYTE = 1024**3


def _by_template(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Roll the matched VMs up by their base disk (template), biggest first.

    This is what names a template-wide problem when the clones are all renamed:
    the base-disk file is identical across every clone of one template.
    """
    templates: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = row.get("base_disk")
        if not key:
            continue
        entry = templates.setdefault(
            key,
            {"base_disk": key, "clones": 0, "total_bytes": 0, "oldest_age_hours": None, "names": []},
        )
        entry["clones"] += 1
        entry["total_bytes"] += row["total_bytes"]
        entry["names"].append(row["name"])
        age = row.get("oldest_age_hours")
        if age is not None and (entry["oldest_age_hours"] is None or age > entry["oldest_age_hours"]):
            entry["oldest_age_hours"] = age
    ranked = sorted(templates.values(), key=lambda entry: entry["total_bytes"], reverse=True)
    for entry in ranked:
        entry["total_gb"] = round(entry.pop("total_bytes") / GIGABYTE, 2)
        entry["names"] = sorted(entry["names"])[:20]
    return ranked


def _scan_snapshots(session: VCenterSession, under: Sequence[str]) -> list[dict[str, Any]]:
    folders = read_folders(session)
    rows = read_vm_snapshots(session, folders)
    if under:
        rows = [row for row in rows if under_any(row["folder"], under)]
    return rows


def _flags(row: dict[str, Any], settings: Settings) -> list[str]:
    """Why this VM's snapshots are a problem."""
    thresholds = settings.thresholds
    reasons = []
    gb = row["total_bytes"] / GIGABYTE
    if gb >= thresholds.snapshot_warn_gb:
        reasons.append(f"{gb:.1f} GB of snapshot data")
    if row["oldest_age_hours"] is not None and row["oldest_age_hours"] >= thresholds.snapshot_old_hours:
        reasons.append(f"oldest snapshot is {row['oldest_age_hours'] / 24:.1f} days old")
    if row["max_chain_depth"] >= thresholds.snapshot_deep_chain:
        reasons.append(f"redo chain {row['max_chain_depth']} deep")
    if row["consolidation_needed"]:
        reasons.append("consolidation needed — a delete left delta disks behind that keep growing")
    return reasons


async def find_vms_by_snapshot(  # noqa: PLR0913 - one filtered fleet query
    pool: VCenterPool,
    settings: Settings,
    names: Sequence[str],
    *,
    min_total_gb: float,
    older_than_hours: float | None,
    min_count: int,
    only_problems: bool,
    under: Sequence[str],
    limit: int,
) -> dict[str, Any]:
    """VMs with snapshots across the vCenters, biggest first, filtered and flagged."""
    results = await asyncio.gather(
        *(pool.run(name, lambda session: _scan_snapshots(session, under)) for name in names),
        return_exceptions=True,
    )
    rows: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    read: dict[str, int] = {}
    for name, result in zip(names, results, strict=True):
        if isinstance(result, BaseException):
            errors[name] = str(result)
            continue
        read[name] = len(result)
        rows.extend(result)

    matched = [
        row
        for row in rows
        if row["total_bytes"] >= min_total_gb * GIGABYTE
        and row["count"] >= min_count
        and (older_than_hours is None or (row["oldest_age_hours"] or 0) >= older_than_hours)
    ]
    flagged = {id(row): _flags(row, settings) for row in matched}
    if only_problems:
        matched = [row for row in matched if flagged[id(row)]]
    matched.sort(key=lambda row: row["total_bytes"], reverse=True)

    total_gb = sum(row["total_bytes"] for row in rows) / GIGABYTE
    findings = [
        (
            f"{len(matched)} VMs with snapshots matched across {len(read)} vCenter(s); "
            f"{total_gb:.0f} GB of snapshot data on {len(rows)} VMs in all"
        )
    ]
    if matched:
        biggest = matched[0]
        findings.append(
            f"biggest: {biggest['name']} on {biggest['vcenter']} — "
            f"{biggest['total_bytes'] / GIGABYTE:.1f} GB across {biggest['count']} snapshot(s)"
        )
    stuck = [row for row in matched if row["consolidation_needed"]]
    if stuck:
        findings.append(
            f"{len(stuck)} of them need consolidation — a snapshot delete left delta disks behind "
            "that are still growing (the worst kind, invisible in the snapshot manager)"
        )
    by_template = _by_template(matched)
    if by_template and by_template[0]["clones"] > 1:
        worst = by_template[0]
        findings.append(
            f"template-wide: {worst['clones']} clones of {worst['base_disk']} carry "
            f"{worst['total_gb']} GB of snapshots between them — the template is the common factor, "
            "whatever the clones are named"
        )
    for name, error in errors.items():
        findings.append(f"vCenter {name} not read: {error}")
    return {
        "findings": findings,
        "matched_total": len(matched),
        "by_template": by_template,
        "vms": [
            {
                "vcenter": row["vcenter"],
                "moref": row["moref"],
                "name": row["name"],
                "folder": row["folder"],
                "base_disk": row["base_disk"],
                "snapshots": row["count"],
                "total_gb": round(row["total_bytes"] / GIGABYTE, 2),
                "delta_gb": round(row["delta_bytes"] / GIGABYTE, 2),
                "memory_state_gb": round(row["state_bytes"] / GIGABYTE, 2),
                "oldest_age_hours": row["oldest_age_hours"],
                "max_chain_depth": row["max_chain_depth"],
                "consolidation_needed": row["consolidation_needed"],
                "problems": flagged[id(row)],
            }
            for row in matched[:limit]
        ],
        "vcenters_read": read,
        "errors": errors,
        "note": (
            "snapshot size is the delta (redo-log) files plus the .vmsn memory/state files, from "
            "layoutEx; where vCenter does not report sizes they read as 0 and count/age/chain still apply"
        ),
    }
