"""Fleet hardware queries: which VMs have, or lack, a given virtual device.

For a production issue traced to a device — a missing sound card a product
expects, a NIC type that misbehaves, a leftover USB controller — this answers
"which VMs across these vCenters have it, and which do not", by reading each
VM's device list (the one heavy property) and matching a category or a kind.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from typing import TYPE_CHECKING, Any

from vsphere_triage.ages import under_any
from vsphere_triage.inventory import read_folders, read_vm_devices

if TYPE_CHECKING:
    from collections.abc import Sequence

    from vsphere_triage.config import Settings
    from vsphere_triage.vcenter import VCenterPool, VCenterSession

CATEGORIES = ("ethernet", "disk", "cdrom", "serial", "sound", "usb", "controller", "video", "input")


def _has_device(row: dict[str, Any], device: str) -> bool:
    """Whether a VM row has the device, matched as a category or a kind substring."""
    wanted = device.strip().lower()
    if wanted in row["categories"]:
        return True
    return any(wanted in kind.lower() for kind in row["kinds"])


def _scan_devices(session: VCenterSession, under: Sequence[str]) -> list[dict[str, Any]]:
    folders = read_folders(session)
    rows = read_vm_devices(session, folders)
    if under:
        rows = [row for row in rows if under_any(row["folder"], under)]
    return rows


async def find_vms_by_device(
    pool: VCenterPool,
    settings: Settings,  # noqa: ARG001 - kept for symmetry with the other fleet calls
    names: Sequence[str],
    *,
    device: str,
    present: bool,
    include_templates: bool,
    under: Sequence[str],
    limit: int,
) -> dict[str, Any]:
    """VMs across the named vCenters that have (present) or lack (not present) a device."""
    results = await asyncio.gather(
        *(pool.run(name, lambda session: _scan_devices(session, under)) for name in names),
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
    matched = [row for row in considered if _has_device(row, device) == present]
    verb = "with" if present else "without"
    by_vcenter = Counter(row["vcenter"] for row in matched)
    findings = [
        f"{len(matched)} of {len(considered)} VMs are {verb} a {device} device across {len(read)} vCenter(s)"
    ]
    findings.extend(f"{vcenter}: {count}" for vcenter, count in by_vcenter.most_common())
    # When looking for VMs lacking a device, the template lacking it is the usual root.
    if not present and include_templates:
        bare_templates = [row for row in matched if row["template"]]
        if bare_templates:
            findings.append(
                f"{len(bare_templates)} of these are templates — a clone lacks the device "
                "because its base does"
            )
    for name, error in errors.items():
        findings.append(f"vCenter {name} not read: {error}")
    return {
        "device": device,
        "present": present,
        "findings": findings,
        "matched_total": len(matched),
        "matched": [
            {
                "vcenter": row["vcenter"],
                "moref": row["moref"],
                "name": row["name"],
                "folder": row["folder"],
                "template": row["template"],
                "kinds": row["kinds"],
            }
            for row in matched[:limit]
        ],
        "vcenters_read": read,
        "errors": errors,
        "note": (
            "matched by device category (sound, ethernet, cdrom, usb, ...) or a kind substring "
            "(e.g. Vmxnet3, HdAudioCard); this is the virtual hardware, read without Tools"
        ),
    }


def _signature(row: dict[str, Any]) -> tuple[str, ...]:
    """A VM's hardware signature: the multiset of device kinds, as a sorted tuple."""
    kinds: list[str] = []
    for members in row["by_category"].values():
        kinds.extend(members)
    return tuple(sorted(kinds))


def _profile_scope(
    session: VCenterSession, under: Sequence[str], *, include_templates: bool
) -> list[dict[str, Any]]:
    rows = _scan_devices(session, under)
    return [row for row in rows if include_templates or not row["template"]]


async def hardware_profile(  # noqa: C901 - one fleet walk, kept together
    pool: VCenterPool,
    settings: Settings,  # noqa: ARG001 - symmetry with the other fleet calls
    names: Sequence[str],
    *,
    under: Sequence[str],
    include_templates: bool,
    limit: int,
) -> dict[str, Any]:
    """The whole fleet's virtual hardware: what every VM has, and the odd ones out.

    Counts how many VMs carry each device category and each kind (so you see the
    NIC types, controllers, and anything unusual across everything), and, within
    each environment, the common hardware signature and the VMs that deviate from
    it — the one VM on a different NIC, with an extra adapter, or missing a
    device its siblings have.
    """
    results = await asyncio.gather(
        *(
            pool.run(name, lambda s: _profile_scope(s, under, include_templates=include_templates))
            for name in names
        ),
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

    total = len(rows)
    category_counts = Counter(category for row in rows for category in row["categories"])
    kind_counts = Counter(kind for row in rows for kind in row["kinds"])
    # Adapters get their own breakdown, since that is the common question.
    nic_kinds = Counter(kind for row in rows for kind in row["by_category"].get("ethernet", []))
    nic_count = Counter(len(row["by_category"].get("ethernet", [])) for row in rows)

    # Outliers: within each environment, the majority hardware signature and the
    # VMs that differ from it.
    by_env: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        # By the folder itself: two environments of the same name elsewhere are not one.
        where = row.get("folder_moref") or row["folder"] or row["environment"]
        by_env.setdefault(f"{row['vcenter']}:{where}", []).append(row)
    outliers: list[dict[str, Any]] = []
    for members in by_env.values():
        if len(members) < 2:  # noqa: PLR2004 - need a majority to deviate from
            continue
        signatures = Counter(_signature(row) for row in members)
        majority, majority_n = signatures.most_common(1)[0]
        if majority_n == len(members):
            continue  # the whole environment matches
        # Counted, not as sets: two NICs where the norm is one is a difference.
        common = Counter(majority)
        for row in members:
            mine = Counter(_signature(row))
            if mine == common:
                continue
            outliers.append(
                {
                    "vcenter": row["vcenter"],
                    "moref": row["moref"],
                    "name": row["name"],
                    "environment": row["environment"],
                    "extra": sorted((mine - common).elements()),
                    "missing": sorted((common - mine).elements()),
                }
            )
    findings = [
        f"{total} VMs across {len(read)} vCenter(s); {len(outliers)} differ from their environment's norm"
    ]
    rare = [kind for kind, count in kind_counts.items() if count <= max(3, total // 100)]
    if rare:
        findings.append("device kinds on only a few VMs: " + ", ".join(sorted(rare)))
    if len(nic_kinds) > 1:
        findings.append(
            "more than one NIC type in use: " + ", ".join(f"{k} ({n})" for k, n in nic_kinds.most_common())
        )
    for name, error in errors.items():
        findings.append(f"vCenter {name} not read: {error}")
    return {
        "findings": findings,
        "vms": total,
        "category_counts": dict(category_counts.most_common()),
        "kind_counts": dict(kind_counts.most_common()),
        "adapter_kinds": dict(nic_kinds.most_common()),
        "adapter_count_distribution": {str(k): v for k, v in sorted(nic_count.items())},
        "environment_outliers_total": len(outliers),
        "environment_outliers": outliers[:limit],
        "vcenters_read": read,
        "errors": errors,
    }
