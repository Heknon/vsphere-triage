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

from vsphere_triage import powerflex
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
    exact_free = free / capacity * 100 if (capacity and free is not None) else None
    free_percent = round(exact_free, 1) if exact_free is not None else None
    ratio = round(provisioned / capacity, 2) if (capacity and provisioned is not None) else None
    # A host that is not connected (or is powered off, in standby) reports every
    # mount inaccessible: that is the host, not the datastore, and is not counted.
    unreachable = [
        mount
        for mount in row.get("mounts") or []
        if mount.get("mounted") and mount.get("accessible") is False
    ]
    apd = [
        {"host_moref": mount["host_moref"], "reason": mount["inaccessible_reason"]}
        for mount in unreachable
        if mount.get("host_up") is not False
    ]
    hosts_down = sum(1 for mount in unreachable if mount.get("host_up") is False)
    findings: list[str] = []
    name = row.get("name")
    unread = [
        label
        for label, value in (
            ("capacity", capacity),
            ("free space", free),
            ("accessibility", row.get("accessible")),
            ("host mounts", row.get("mounts")),
        )
        if value is None
    ]
    if row.get("accessible") is False:
        findings.append(f"datastore {name} is not accessible from vCenter")
    if exact_free is not None and exact_free <= thresholds.datastore_full_percent:
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
    host_note = (
        f"{hosts_down} host(s) mounting it are not connected or not powered on, so their mounts read "
        "inaccessible; that is the host, not the datastore"
        if hosts_down
        else None
    )
    naas = row.get("backing_naas") or []
    return {
        "vcenter": row["vcenter"],
        "moref": row["moref"],
        "name": name,
        "type": row.get("type"),
        "accessible": row.get("accessible"),
        "backing_naas": naas,
        # Decoded candidate PowerFlex volume id(s) — the handle that maps this
        # datastore to its backend volume (confirm against powerflex_find_volume).
        "powerflex_volume_ids": [
            volume_id for naa in naas if (volume_id := powerflex.volume_id_from_naa(naa))
        ],
        "capacity_gb": round(capacity / GIGABYTE, 1) if capacity else None,
        "free_gb": round(free / GIGABYTE, 1) if free is not None else None,
        "free_percent": free_percent,
        "provisioned_gb": round(provisioned / GIGABYTE, 1) if provisioned is not None else None,
        "overprovision_ratio": ratio,
        "hosts_mounting": len(row.get("mounts") or []),
        "hosts_unreachable": apd,
        "hosts_down_mounting": hosts_down,
        "host_note": host_note,
        "holds_template": row.get("holds_template", False),
        "findings": findings,
        # Healthy only when it could be judged: a datastore whose capacity, free
        # space, accessibility or mounts were not read is unknown, not healthy.
        "healthy": False if findings else (None if unread else True),
        "not_read": unread,
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
    # Whether each mounting host is up: a disconnected or powered-off host reads
    # its mounts as inaccessible, which is no APD.
    host_up = {
        host["moref"]: host.get("runtime.connectionState") == "connected"
        and host.get("runtime.powerState") in (None, "poweredOn")
        for host in session.retrieve(vim.HostSystem, ("runtime.connectionState", "runtime.powerState"))
    }
    for row in rows:
        row["holds_template"] = row["moref"] in template_stores
        for mount in row.get("mounts") or []:
            mount["host_up"] = host_up.get(mount["host_moref"])
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

    unhealthy = [verdict for verdict in verdicts if verdict["healthy"] is False]
    unjudged = [verdict for verdict in verdicts if verdict["healthy"] is None]
    unhealthy.sort(key=lambda verdict: (verdict["free_percent"] is None, verdict["free_percent"] or 0))
    shown = (
        [*unhealthy, *unjudged]
        if only_problems
        else [*unhealthy, *unjudged, *(v for v in verdicts if v["healthy"] is True)]
    )

    apd = [verdict for verdict in unhealthy if verdict["hosts_unreachable"]]
    # The same judgement classify_datastore made (on the unrounded figure).
    full = [verdict for verdict in unhealthy if any(f.startswith("nearly full") for f in verdict["findings"])]
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
    if unjudged:
        findings.append(
            f"{len(unjudged)} datastore(s) could not be judged (capacity, free space, accessibility or "
            "mounts not read, usually permission): not evidence they are healthy"
        )
    for name, error in errors.items():
        findings.append(f"vCenter {name} not read: {error}")
    return {
        "findings": findings,
        "datastores_total": len(verdicts),
        "unhealthy_total": len(unhealthy),
        "datastores": shown[:limit],
        # Not when a vCenter went unread, or a datastore could not be judged.
        "all_healthy": bool(verdicts)
        and not unhealthy
        and not errors
        and all(verdict["healthy"] is True for verdict in verdicts),
        "unjudged_total": len(unjudged),
        "vcenters_read": read,
        "errors": errors,
        "note": (
            "over-provisioning uses summary.uncommitted (thin space not yet allocated); APD/PDL is a host "
            "mount that is mounted but inaccessible; confirm the exact inaccessibleReason on a real vCenter"
        ),
    }
