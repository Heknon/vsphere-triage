"""Environments and VMs that have existed longer than they should.

An environment is the folder its VMs sit in, wherever that folder is: under
`projects/`, `environments/`, a team folder below one of those, or anywhere
else. Its age is the age of its oldest VM, by `config.createDate` (vCenter 6.7
and later), because a folder has no creation time of its own and an
environment exists from the moment its first VM does.

Nothing about the layout is assumed. `under` narrows the search to folders
whose path contains a segment (`projects`) or a run of segments
(`projects/team-a`); without it every folder holding VMs is considered, the
datacenter's own root VM folder included, and marked as such.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from typing import TYPE_CHECKING, Any

from vsphere_triage.checks import classify
from vsphere_triage.inventory import Inventory, VmFacts, read_inventory

if TYPE_CHECKING:
    from collections.abc import Sequence

    from vsphere_triage.config import Settings
    from vsphere_triage.vcenter import VCenterPool, VCenterSession

VMS_LISTED = 20


def _segments(path: str) -> list[str]:
    return [part.lower() for part in path.strip("/").split("/") if part]


def under_any(path: str | None, terms: Sequence[str]) -> bool:
    """Whether a folder path lies under any of the terms: a segment or a run of segments."""
    if not terms:
        return True
    if not path:
        return False
    parts = _segments(path)
    for term in terms:
        wanted = _segments(term)
        if not wanted:
            continue
        width = len(wanted)
        if any(parts[index : index + width] == wanted for index in range(len(parts) - width + 1)):
            return True
    return False


# The group for VMs with no parent folder (inside a vApp).
OUTSIDE_FOLDERS = "(no folder: in a vApp)"


def environments(
    inventory: Inventory,
    settings: Settings,
    *,
    older_than_hours: float,
    under: Sequence[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Environment folders older than the threshold, oldest first, and those of unknown age."""
    by_folder: dict[str, list[VmFacts]] = {}
    for vm in inventory.vms:
        if under_any(vm.folder_path, under):
            # A VM in a vApp has no parent folder: grouped by its own vApp, not dropped,
            # and never merged with the VMs of other vApps.
            key = vm.folder_moref or (
                f"{OUTSIDE_FOLDERS} {vm.vapp_moref}" if vm.vapp_moref else OUTSIDE_FOLDERS
            )
            by_folder.setdefault(key, []).append(vm)
    old, unknown = [], []
    for moref, vms in by_folder.items():
        folder = inventory.folders.get(moref)
        ages = [vm.age_hours for vm in vms if vm.age_hours is not None]
        verdicts = {vm.moref: classify(vm, settings.thresholds) for vm in vms}
        states = Counter(verdict.state for verdict in verdicts.values())
        entry: dict[str, Any] = {
            "vcenter": inventory.vcenter,
            "environment": folder.name if folder else (moref if moref.startswith(OUTSIDE_FOLDERS) else None),
            "folder": folder.path if folder else None,
            "parent": folder.parent_name if folder else None,
            # The datacenter's own VM folder holds VMs outside any environment.
            "root_vm_folder": bool(folder and folder.parent_moref and folder.parent_name is None),
            "vms": len(vms),
            "powered_on": sum(1 for vm in vms if vm.powered_on),
            # As everywhere else: an abnormal state or a trouble flag, not a context flag.
            "abnormal": sum(1 for verdict in verdicts.values() if verdict.abnormal),
            "states": dict(states),
            "age_unknown_vms": len(vms) - len(ages),
        }
        if not ages:
            unknown.append(entry)
            continue
        oldest = max(vms, key=lambda vm: vm.age_hours if vm.age_hours is not None else -1.0)
        newest = min(vms, key=lambda vm: vm.age_hours if vm.age_hours is not None else float("inf"))
        entry |= {
            "age_hours": round(max(ages), 2),
            "oldest_created": oldest.created,
            "newest_created": newest.created,
            "newest_age_hours": round(min(ages), 2),
            "vm_list": [
                {
                    "name": vm.name,
                    "moref": vm.moref,
                    "created": vm.created,
                    "age_hours": None if vm.age_hours is None else round(vm.age_hours, 2),
                    "state": verdicts[vm.moref].state,
                    "power_state": vm.power_state,
                }
                for vm in sorted(vms, key=lambda vm: -(vm.age_hours or 0))[:VMS_LISTED]
            ],
        }
        if max(ages) >= older_than_hours:
            old.append(entry)
    old.sort(key=lambda entry: entry["age_hours"], reverse=True)
    return old, unknown


def _scan_ages(
    session: VCenterSession, settings: Settings, older_than_hours: float, under: Sequence[str]
) -> dict[str, Any]:
    inventory = read_inventory(session, with_devices=False)
    old, unknown = environments(inventory, settings, older_than_hours=older_than_hours, under=under)
    return {"read_at": inventory.read_at, "old": old, "unknown": unknown, "vms": len(inventory.vms)}


async def find_old_environments(
    pool: VCenterPool,
    settings: Settings,
    names: Sequence[str],
    *,
    older_than_hours: float,
    under: Sequence[str],
    limit: int,
) -> dict[str, Any]:
    """Environments older than `older_than_hours` across vCenters, oldest first."""
    results = await asyncio.gather(
        *(
            pool.sweep(name, lambda session: _scan_ages(session, settings, older_than_hours, under))
            for name in names
        ),
        return_exceptions=True,
    )
    old: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    read: dict[str, Any] = {}
    for name, result in zip(names, results, strict=True):
        if isinstance(result, BaseException):
            errors[name] = str(result)
            continue
        old.extend(result["old"])
        unknown.extend(result["unknown"])
        read[name] = {"read_at": result["read_at"], "vms": result["vms"]}
    old.sort(key=lambda entry: entry["age_hours"], reverse=True)
    where = f" under {', '.join(under)}" if under else ""
    findings = [
        (
            f"{len(old)} environment folder(s){where} older than {older_than_hours:g} h "
            f"across {len(read)} vCenter(s)"
        )
    ]
    if old:
        top = old[0]
        findings.append(
            f"oldest: {top['folder']} on {top['vcenter']}, {top['age_hours']:.1f} h, "
            f"{top['vms']} VM(s), {top['powered_on']} powered on"
        )
        still_on = sum(1 for entry in old if entry["powered_on"])
        findings.append(f"{still_on} of them still have powered-on VMs")
    if unknown:
        findings.append(
            f"{len(unknown)} folder(s) have VMs without a creation date (vCenter older than 6.7?); "
            "their age is unknown, not young"
        )
    findings.extend(f"vCenter {name} not read: {error}" for name, error in errors.items())
    return {
        "findings": findings,
        "older_than_hours": older_than_hours,
        "under": list(under),
        "environments": old[:limit],
        "environments_total": len(old),
        "age_unknown": unknown[:limit],
        "vcenters": read,
        "errors": errors,
        "how_age_is_measured": (
            "the age of the folder's oldest VM, from config.createDate, by vCenter's clock"
        ),
    }
