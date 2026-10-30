"""Reboot a VM — the other capabilities that are NOT read-only.

Everything this server does reads from vSphere, with the deliberate exceptions
the operator has allowed: `run_in_guest` and the two power operations here. They
exist for one reason — a VM that is hung or wedged often has to be rebooted
before it will produce a fresh boot log, serial console and (on Windows) the
bugcheck record its next boot writes to the event log. So rebooting *is* the
diagnostic step.

There are two, and the order matters:

1. `reboot_guest` asks the guest OS to reboot cleanly through VMware Tools. No
   data loss, but it needs Tools running and a guest responsive enough to obey.
2. `hard_reset` is the virtual reset button. It needs no Tools, so it is the
   only thing that reboots a fully hung VM — but the guest is never asked, so
   in-flight writes can be lost and in-guest evidence (an unwritten crash dump,
   "Working on updates" progress) can be destroyed along with the hang.

Prefer `reboot_guest` first; reach for `hard_reset` only when Tools is down or a
graceful reboot was issued and the VM never came back. Both go through the
session's raw (unguarded) stub, like `run_in_guest`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from vsphere_triage.diagnose import locate

if TYPE_CHECKING:
    from vsphere_triage.config import Settings
    from vsphere_triage.vcenter import VCenterPool, VCenterSession


async def reboot_guest(
    pool: VCenterPool,
    settings: Settings,
    name: str,
    *,
    moref: str | None,
    env_id: str | None,
    vm_name: str | None,
) -> dict[str, Any]:
    """Ask the guest OS to reboot gracefully through VMware Tools."""

    def work(session: VCenterSession) -> dict[str, Any]:
        located = locate(session, settings, env_id=env_id, vm_name=vm_name, moref=moref)
        if not located["found"]:
            return {"found": False, "reason": located["reason"]}
        vm = located["vm"]
        if not vm.powered_on:
            return {"found": True, "rebooted": False, "reason": "the VM is not powered on"}
        if not vm.tools_up:
            return {
                "found": True,
                "rebooted": False,
                "reason": (
                    "VMware Tools is not running in this guest, so a graceful reboot is impossible; "
                    f"Tools status is {vm.tools_running!r}. Use hard_reset to power-cycle a hung VM"
                ),
            }
        result = session.reboot_guest(vm.moref)
        return {"found": True, "rebooted": True, "vm": vm.identity(), **result}

    return await pool.run(name, work)


async def hard_reset(
    pool: VCenterPool,
    settings: Settings,
    name: str,
    *,
    moref: str | None,
    env_id: str | None,
    vm_name: str | None,
) -> dict[str, Any]:
    """Power-cycle the VM immediately, without asking the guest. Destructive."""

    def work(session: VCenterSession) -> dict[str, Any]:
        located = locate(session, settings, env_id=env_id, vm_name=vm_name, moref=moref)
        if not located["found"]:
            return {"found": False, "reason": located["reason"]}
        vm = located["vm"]
        if not vm.powered_on:
            return {
                "found": True,
                "reset": False,
                "reason": "the VM is not powered on; there is nothing to reset (power it on instead)",
            }
        result = session.hard_reset(vm.moref)
        return {"found": True, "reset": True, "vm": vm.identity(), **result}

    return await pool.run(name, work)
