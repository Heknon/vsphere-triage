"""Naming the evidence we lack, and how to get it.

A diagnosis is only as good as what it can read. When a stronger source exists
but is unavailable — vROps is not configured, the guest has no serial console so
its own boot words are unreadable, no guest credentials so nothing inside can be
asked — the honest thing is to say so, everywhere, the same way: name the
missing capability, say what it would have added (why it matters), and say how
to turn it on.

A gap is never fatal: the read-only signals still stand, and the server still
answers. But an unnamed gap lets a reader mistake "we could not see it" for "it
did not happen", and quietly accept a weaker answer when a better one was one
setting away. So every tool that a source like this would strengthen returns its
gaps, and the model is told to pass them on: *there is something better I cannot
use, because it has not been given to me.*

These are pure functions over settings and a VM's facts. Keep them pure and
tested; the live, guest-side capability checks (does the guest actually have EMS
enabled in its BCD?) live with the tool that reads the guest.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vsphere_triage.config import Settings
    from vsphere_triage.inventory import VmFacts

# The capability names, stable so a reader (or the model) can match on them.
VROPS = "vrops_history"
SERIAL_CONSOLE = "serial_console"
GUEST_ACCESS = "guest_access"


def _gap(capability: str, *, impact: str, how_to_enable: str) -> dict[str, Any]:
    """One missing capability: what it is, why its absence hurts, how to turn it on."""
    return {
        "capability": capability,
        "available": False,
        "impact": impact,
        "how_to_enable": how_to_enable,
    }


def vrops_gap(settings: Settings) -> dict[str, Any] | None:
    """The history gap when vROps is not configured — None when it is."""
    if settings.vrops_url:
        return None
    return _gap(
        VROPS,
        impact=(
            "no history: a problem that has already cleared cannot be seen. A vCenter SSL EOF or "
            "session spike from hours ago, a past CPU-ready or datastore-latency spike, the "
            "session-count curve over the incident — none of these is visible from the live state "
            "alone, so an intermittent or past failure can only be guessed at"
        ),
        how_to_enable=(
            "configure VSPHERE_VROPS_URL, VSPHERE_VROPS_USERNAME and VSPHERE_VROPS_PASSWORD "
            "(Aria / VCF Operations); the 5 vrops_* history tools then appear"
        ),
    )


def guest_gap(settings: Settings, vm: VmFacts) -> dict[str, Any] | None:
    """The in-guest-evidence gap — None when the guest can actually be asked.

    Reading the guest's own words (the Windows event log and BCD/EMS state, a
    Linux dmesg/journal) needs both VMware Tools running and guest credentials.
    Name whichever is missing, since they are fixed in different ways.
    """
    if not vm.powered_on:
        return None  # a powered-off VM is a different problem; reboot it first
    have_credentials = bool(settings.guest_username and settings.guest_password)
    if vm.tools_up and have_credentials:
        return None
    if not vm.tools_up:
        return _gap(
            GUEST_ACCESS,
            impact=(
                "cannot look inside the guest: with VMware Tools down there is no guest-ops channel, "
                "so the Windows event log, the BCD/EMS state and the guest's own boot logs are all "
                "out of reach, and the console and serial console are the only view of the guest"
            ),
            how_to_enable=(
                f"get VMware Tools running in the guest (Tools status is {vm.tools_running!r}); a "
                "reboot_guest or hard_reset may bring it back if the guest is wedged"
            ),
        )
    return _gap(
        GUEST_ACCESS,
        impact=(
            "cannot look inside the guest: without guest credentials run_in_guest and the guest-log "
            "reads (Windows event log, BCD/EMS, dmesg/journal) are unavailable, so a cause that only "
            "the guest records cannot be confirmed"
        ),
        how_to_enable=(
            "pass username and password to the guest tools, or configure VSPHERE_GUEST_USERNAME and "
            "VSPHERE_GUEST_PASSWORD as defaults"
        ),
    )


def serial_console_gap(vm: VmFacts) -> dict[str, Any] | None:
    """The guest's-own-boot-words gap when the VM has no file-backed serial port.

    None when a serial port writes to a file (then the guest's console output is
    readable even with no Tools). The wording is tuned by guest OS: on Windows
    the serial console is EMS; on Linux it is a kernel console.
    """
    if vm.serial_files:
        return None
    if vm.os_family == "windows":
        detail = (
            "Windows Emergency Management Services (EMS) output — the SAC banner and the bugcheck a "
            "crash prints — has nowhere to land"
        )
        how = (
            "add a virtual serial port backed by a datastore file, then enable EMS in the guest "
            "(`bcdedit /ems on` and `bcdedit /emssettings EMSPORT:...`)"
        )
    elif vm.os_family == "linux":
        detail = "a Linux kernel console (panics, soft-lockups, device timeouts) has nowhere to land"
        how = (
            "add a virtual serial port backed by a datastore file, then send the kernel console to "
            "it (a `console=ttyS0,115200` kernel argument)"
        )
    else:
        detail = "the guest's own console output has nowhere the hypervisor can read it"
        how = "add a virtual serial port backed by a datastore file and send the guest console to it"
    return _gap(
        SERIAL_CONSOLE,
        impact=(
            f"the guest's own boot words are unreadable while it is hung: {detail}. Without it, a hang "
            "that never reaches VMware Tools can only be seen from the outside (the vmware.log boot "
            "stages and a console screenshot), never named from the guest's own error"
        ),
        how_to_enable=how,
    )


def evidence_gaps(settings: Settings, vm: VmFacts) -> list[dict[str, Any]]:
    """Every stronger source this VM's diagnosis lacks, in the order to mention them."""
    gaps = [vrops_gap(settings), serial_console_gap(vm), guest_gap(settings, vm)]
    return [gap for gap in gaps if gap is not None]
