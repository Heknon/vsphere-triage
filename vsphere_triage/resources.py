"""Fleet resource-policy query: VMs throttled or constrained by configured limits and reservations.

A CPU limit caps a VM below its full speed and looks exactly like host CPU
starvation without being it — the same symptom, a different fix. A memory limit
set below the VM's configured RAM forces the host to balloon or swap it. A large
reservation locks capacity the cluster can no longer admit other VMs into, which
can block power-ons. All three live in config, so a template carries them to
every linked clone made from it: a limit on a template is the root of the same
limit on each clone.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from typing import TYPE_CHECKING, Any

from vsphere_triage.ages import under_any
from vsphere_triage.inventory import read_folders, read_vm_resource_policy

if TYPE_CHECKING:
    from collections.abc import Sequence

    from vsphere_triage.config import Settings
    from vsphere_triage.vcenter import VCenterPool, VCenterSession


def _scan_resource_policy(session: VCenterSession, under: Sequence[str]) -> list[dict[str, Any]]:
    folders = read_folders(session)
    rows = read_vm_resource_policy(session, folders)
    if under:
        rows = [row for row in rows if under_any(row["folder"], under)]
    return rows


def _memory_capped(row: dict[str, Any]) -> bool:
    """A memory limit that caps something: below the VM's RAM (or RAM unknown)."""
    return row["memory_limit_mb"] is not None and (
        row["memory_mb"] is None or row["memory_limit_mb"] < row["memory_mb"]
    )


def _findings_for(row: dict[str, Any]) -> list[str]:
    """Why this VM's resource policy is worth seeing."""
    reasons = []
    limit = row["cpu_limit_mhz"]
    if limit is not None:
        reasons.append(f"CPU limit {limit} MHz set — caps the VM below full speed (mimics starvation)")
    if _memory_capped(row):
        below = f"below its {row['memory_mb']} MB RAM" if row["memory_mb"] is not None else "(RAM not read)"
        reasons.append(f"memory limit {row['memory_limit_mb']} MB set {below} — forces balloon/swap")
    if row["cpu_reservation_mhz"] is not None:
        reasons.append(f"CPU reservation {row['cpu_reservation_mhz']} MHz locked")
    if row["memory_reservation_mb"] is not None:
        reasons.append(f"memory reservation {row['memory_reservation_mb']} MB locked")
    return reasons


def _by_template(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Roll the constrained VMs up by base disk (template), so a template-wide policy stands out."""
    templates: dict[str, dict[str, Any]] = {}
    for row in rows:
        base = row.get("base_disk")
        if not base:
            continue
        # The same path on two vCenters is two templates.
        entry = templates.setdefault(
            f"{row['vcenter']}:{base}",
            {
                "vcenter": row["vcenter"],
                "base_disk": base,
                "clones": 0,
                "cpu_limited": 0,
                "memory_limited": 0,
                "names": [],
            },
        )
        entry["clones"] += 1
        entry["cpu_limited"] += row["cpu_limit_mhz"] is not None
        entry["memory_limited"] += _memory_capped(row)
        entry["names"].append(row["name"])
    ranked = sorted(templates.values(), key=lambda entry: entry["clones"], reverse=True)
    for entry in ranked:
        entry["names"] = sorted(entry["names"])[:20]
    return ranked


def _matches(row: dict[str, Any], kind: str) -> bool:
    # A memory limit at or above the VM's RAM caps nothing, so it is not a limit here.
    has_limit = row["cpu_limit_mhz"] is not None or _memory_capped(row)
    has_reservation = row["cpu_reservation_mhz"] is not None or row["memory_reservation_mb"] is not None
    if kind == "limits":
        return has_limit
    if kind == "reservations":
        return has_reservation
    return has_limit or has_reservation


async def find_resource_limits(
    pool: VCenterPool,
    settings: Settings,  # noqa: ARG001 - kept for symmetry with the other fleet calls
    names: Sequence[str],
    *,
    kind: str,
    include_templates: bool,
    under: Sequence[str],
    limit: int,
) -> dict[str, Any]:
    """VMs with a CPU/memory limit or reservation set across the vCenters, templates marked."""
    results = await asyncio.gather(
        *(pool.sweep(name, lambda session: _scan_resource_policy(session, under)) for name in names),
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

    considered = [row for row in rows if include_templates or not row["template"]]
    matched = [row for row in considered if _matches(row, kind)]
    reasons = {id(row): _findings_for(row) for row in matched}
    # CPU-limited first, the tightest (smallest) limit leading as the strongest
    # throttle; then memory limits below RAM, tightest first; then reservations.
    matched.sort(
        key=lambda row: (
            row["cpu_limit_mhz"] is None,
            row["cpu_limit_mhz"] or 0,
            not _memory_capped(row),
            row["memory_limit_mb"] or 0,
            -(row["cpu_reservation_mhz"] or 0),
            -(row["memory_reservation_mb"] or 0),
        )
    )

    by_vcenter = Counter(row["vcenter"] for row in matched)
    findings = [
        f"{len(matched)} of {len(considered)} VMs have a {kind} policy set across {len(read)} vCenter(s)"
    ]
    findings.extend(f"{vcenter}: {count}" for vcenter, count in by_vcenter.most_common())
    templates = [row for row in matched if row["template"]]
    if templates and include_templates:
        findings.append(
            f"{len(templates)} of these are templates — every linked clone made from one inherits its "
            "limit/reservation, so fixing the template fixes the clones"
        )
    by_template = _by_template(matched)
    if by_template and by_template[0]["clones"] > 1:
        worst = by_template[0]
        findings.append(
            f"template-wide: {worst['clones']} clones of {worst['vcenter']}:{worst['base_disk']} carry "
            "the same policy — "
            "the template is the common factor, whatever the clones are named"
        )
    for name, error in errors.items():
        findings.append(f"vCenter {name} not read: {error}")
    return {
        "kind": kind,
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
                "template": row["template"],
                "num_cpu": row["num_cpu"],
                "memory_mb": row["memory_mb"],
                "cpu_limit_mhz": row["cpu_limit_mhz"],
                "cpu_reservation_mhz": row["cpu_reservation_mhz"],
                "memory_limit_mb": row["memory_limit_mb"],
                "memory_reservation_mb": row["memory_reservation_mb"],
                "problems": reasons[id(row)],
            }
            for row in matched[:limit]
        ],
        "vcenters_read": read,
        "errors": errors,
        "note": (
            "a CPU limit (MHz) throttles the VM and mimics host starvation; a memory limit forces "
            "balloon/swap; reservations lock capacity. -1/0 (unlimited/none) are omitted"
        ),
    }
