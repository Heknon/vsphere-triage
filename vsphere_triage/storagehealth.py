"""Datastore health across the fleet: fill, thin over-provisioning, and APD/PDL.

When a datastore fills or a host loses its paths to it, every VM on it wedges at
once — the layer above PowerFlex latency. This reads each datastore's capacity,
free space and uncommitted (thin, not-yet-allocated) bytes, and each host's
mount state, so three failures stand out:

- *full*: free space under the threshold — a thin disk on it then stalls on write;
- *over-provisioned*: committed plus uncommitted exceeds capacity, so thin disks
  could grow past the datastore and fill it;
- *APD/PDL*: a host has the datastore mounted but cannot reach it
  (all-paths-down or permanent-device-loss), which stalls that host's VMs on it.

Linked clones share one base disk on the template's datastore, so a datastore
that holds a template and fills or goes APD takes every clone of it down; such
datastores are marked.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from pyVmomi import vim

from vsphere_triage.inventory import read_datastore_mounts

if TYPE_CHECKING:
    from collections.abc import Sequence

    from vsphere_triage.config import Settings, Thresholds
    from vsphere_triage.vcenter import VCenterPool, VCenterSession

GIGABYTE = 1024**3
# inaccessibleReason values vCenter sets on a host mount; any of these is APD/PDL.
APD_PDL_REASONS = ("AllPathsDown_Start", "AllPathsDown_Timeout", "PermanentDeviceLoss")


def classify_datastore(row: dict[str, Any], thresholds: Thresholds) -> dict[str, Any]:
    """Judge one datastore's fill, over-provisioning and per-host reachability. Pure."""
    capacity = row.get("capacity_bytes")
    free = row.get("free_bytes")
    uncommitted = row.get("uncommitted_bytes") or 0
    committed = (capacity - free) if (capacity is not None and free is not None) else None
    provisioned = (committed + uncommitted) if committed is not None else None
    free_percent = round(free / capacity * 100, 1) if (capacity and free is not None) else None
    ratio = round(provisioned / capacity, 2) if (capacity and provisioned is not None) else None
    apd = [
        {"host_moref": mount["host_moref"], "reason": mount["inaccessible_reason"]}
        for mount in row.get("mounts") or []
        if mount.get("mounted") and mount.get("accessible") is False
    ]
    findings: list[str] = []
    name = row.get("name")
    if row.get("accessible") is False:
        findings.append(f"datastore {name} is not accessible from vCenter")
    if free_percent is not None and free_percent <= thresholds.datastore_full_percent:
        findings.append(f"nearly full: {free_percent}% free — a thin disk on it stalls on write")
    if ratio is not None and ratio >= thresholds.datastore_overprovision_ratio:
        findings.append(
            f"over-provisioned {ratio}x: committed plus thin-but-unallocated is {ratio:.0%} of capacity, "
            "so thin disks could grow past it"
        )
    for mount in apd:
        reason = mount["reason"] or "inaccessible"
        apd_pdl = " (all-paths-down / permanent-device-loss)" if reason in APD_PDL_REASONS else ""
        findings.append(f"mounted but unreachable on a host: {reason}{apd_pdl} — its VMs there stall")
    return {
        "vcenter": row["vcenter"],
        "moref": row["moref"],
        "name": name,
        "type": row.get("type"),
        "accessible": row.get("accessible"),
        "capacity_gb": round(capacity / GIGABYTE, 1) if capacity else None,
        "free_gb": round(free / GIGABYTE, 1) if free is not None else None,
        "free_percent": free_percent,
        "provisioned_gb": round(provisioned / GIGABYTE, 1) if provisioned is not None else None,
        "overprovision_ratio": ratio,
        "hosts_mounting": len(row.get("mounts") or []),
        "hosts_unreachable": apd,
        "holds_template": row.get("holds_template", False),
        "findings": findings,
        "healthy": not findings,
    }


def _scan_datastores(session: VCenterSession) -> list[dict[str, Any]]:
    """Datastores with mount state, each marked whether it holds a template's base disk. Blocking."""
    rows = read_datastore_mounts(session)
    # Which datastores hold a template: a linked clone's base disk lives here, so
    # this datastore filling or going APD takes every clone of that template down.
    template_stores: set[str] = set()
    for vm in session.retrieve(vim.VirtualMachine, ("config.template", "datastore")):
        if vm.get("config.template"):
            for store in vm.get("datastore") or []:
                template_stores.add(store._moId)  # noqa: SLF001
    for row in rows:
        row["holds_template"] = row["moref"] in template_stores
    return rows


async def check_datastores(
    pool: VCenterPool,
    settings: Settings,
    names: Sequence[str],
    *,
    only_problems: bool,
    limit: int,
) -> dict[str, Any]:
    """Every datastore's fill, over-provisioning and reachability across the vCenters, worst first."""
    results = await asyncio.gather(
        *(pool.sweep(name, _scan_datastores) for name in names),
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
        verdicts.extend(classify_datastore(row, settings.thresholds) for row in result)

    unhealthy = [verdict for verdict in verdicts if not verdict["healthy"]]
    unhealthy.sort(key=lambda verdict: (verdict["free_percent"] is None, verdict["free_percent"] or 0))
    shown = unhealthy if only_problems else [*unhealthy, *(v for v in verdicts if v["healthy"])]

    apd = [verdict for verdict in unhealthy if verdict["hosts_unreachable"]]
    full = [
        verdict
        for verdict in unhealthy
        if verdict["free_percent"] is not None
        and verdict["free_percent"] <= settings.thresholds.datastore_full_percent
    ]
    over = [
        verdict
        for verdict in unhealthy
        if verdict["overprovision_ratio"] is not None
        and verdict["overprovision_ratio"] >= settings.thresholds.datastore_overprovision_ratio
    ]
    findings = [
        f"{len(unhealthy)} of {len(verdicts)} datastores have a problem across {len(read)} vCenter(s)"
    ]
    if apd:
        findings.append(
            f"{len(apd)} datastore(s) mounted but unreachable on a host (APD/PDL) — every VM on them "
            "there is stalled: " + ", ".join(f"{v['vcenter']}:{v['name']}" for v in apd[:10])
        )
    if full:
        findings.append(
            f"{len(full)} datastore(s) nearly full: "
            + ", ".join(f"{v['vcenter']}:{v['name']} {v['free_percent']}% free" for v in full[:10])
        )
    if over:
        findings.append(
            f"{len(over)} datastore(s) over-provisioned: "
            + ", ".join(f"{v['vcenter']}:{v['name']} {v['overprovision_ratio']}x" for v in over[:10])
        )
    at_risk = [verdict for verdict in unhealthy if verdict["holds_template"]]
    if at_risk:
        findings.append(
            f"{len(at_risk)} of the troubled datastores hold a template's base disk — a linked clone "
            "reads its base from here, so this takes every clone of that template down"
        )
    for name, error in errors.items():
        findings.append(f"vCenter {name} not read: {error}")
    return {
        "findings": findings,
        "datastores_total": len(verdicts),
        "unhealthy_total": len(unhealthy),
        "datastores": shown[:limit],
        "all_healthy": bool(verdicts) and not unhealthy,
        "vcenters_read": read,
        "errors": errors,
        "note": (
            "over-provisioning uses summary.uncommitted (thin space not yet allocated); APD/PDL is a host "
            "mount that is mounted but inaccessible; confirm the exact inaccessibleReason on a real vCenter"
        ),
    }
