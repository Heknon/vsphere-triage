"""What a VM's state says, judged against the thresholds. Pure: facts in, verdicts out.

A check never hides the number it judged: every verdict carries the values it
was decided on, so a reader can disagree with a threshold without re-reading
vCenter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from vsphere_triage.inventory import STARTING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from vsphere_triage.config import Thresholds
    from vsphere_triage.inventory import VmFacts

# The states a VM can be in, worst first. A VM has exactly one.
INACCESSIBLE = "inaccessible"
BLOCKED_ON_QUESTION = "blocked_on_question"
PAUSED = "paused"
HUNG = "hung"
BUSY_NOT_UP = "busy_not_up"
BOOTED_NOT_UP = "booted_not_up"
LOST_HEARTBEAT = "lost_heartbeat"
NO_BOOT_TIME = "no_boot_time"
NO_TOOLS = "no_tools"
BOOTING = "booting"
HEALTHY = "healthy"
SUSPENDED = "suspended"
OFF = "off"

ABNORMAL = (
    INACCESSIBLE,
    BLOCKED_ON_QUESTION,
    PAUSED,
    HUNG,
    BUSY_NOT_UP,
    BOOTED_NOT_UP,
    LOST_HEARTBEAT,
    NO_BOOT_TIME,
)
STATES = (*ABNORMAL, NO_TOOLS, BOOTING, HEALTHY, SUSPENDED, OFF)

MEANING = {
    INACCESSIBLE: "vCenter cannot reach or account for the VM",
    BLOCKED_ON_QUESTION: "the VM waits on a pending question and does nothing until it is answered",
    PAUSED: "powered on but paused: the hypervisor is not running it",
    HUNG: ("booted long ago, Tools never came up, and the VM uses almost no CPU: it is waiting on something"),
    BUSY_NOT_UP: (
        "booted long ago, Tools never came up, and the VM is burning CPU: starved, spinning or still working"
    ),
    BOOTED_NOT_UP: "booted long ago and Tools never came up",
    LOST_HEARTBEAT: "Tools runs, but its heartbeat to vCenter has stopped",
    NO_BOOT_TIME: "powered on, but vCenter reports no boot time to judge it by",
    NO_TOOLS: (
        "VMware Tools is not installed, so whether the guest came up cannot be judged from Tools; "
        "its CPU, console and boot log still can"
    ),
    BOOTING: "powered on recently; Tools not up yet, which is normal this early",
    HEALTHY: "powered on with Tools running",
    SUSPENDED: "suspended",
    OFF: "powered off",
}

# Flags ride alongside the state; a VM may carry several.
BOOT_LOOP = "boot_loop"
CONSOLIDATION_NEEDED = "consolidation_needed"
TOOLS_FLAPPING = "tools_flapping"
HEARTBEAT_INTERMITTENT = "heartbeat_intermittent"
MEMORY_RECLAIMED = "memory_reclaimed"
HOST_MEMORY_PRESSURE = "host_memory_pressure"
VCENTER_ALARM = "vcenter_alarm"
HOST_NOT_CONNECTED = "host_not_connected"
HOST_IN_MAINTENANCE = "host_in_maintenance"
LONG_RUNNING = "long_running"
TOOLS_OUTDATED = "tools_outdated"
CPU_LIMITED = "cpu_limited"
MEMORY_LIMITED = "memory_limited"

# Flags worth a look on their own. The rest only add detail to a verdict.
ATTENTION_FLAGS = (
    BOOT_LOOP,
    TOOLS_FLAPPING,
    HEARTBEAT_INTERMITTENT,
    MEMORY_RECLAIMED,
    HOST_MEMORY_PRESSURE,
    VCENTER_ALARM,
    HOST_NOT_CONNECTED,
    LONG_RUNNING,
    CONSOLIDATION_NEEDED,
)
DETAIL_FLAGS = (HOST_IN_MAINTENANCE, TOOLS_OUTDATED, CPU_LIMITED, MEMORY_LIMITED)
FLAGS = (*ATTENTION_FLAGS, *DETAIL_FLAGS)
FLAG_MEANING = {
    BOOT_LOOP: "reset or rebooted several times in a short window",
    TOOLS_FLAPPING: "Tools started and stopped repeatedly (from vmware.log)",
    HEARTBEAT_INTERMITTENT: "Tools runs but its heartbeat is intermittent (yellow): Tools may be crashing",
    MEMORY_RECLAIMED: "the host is reclaiming this VM's memory (ballooned, swapped or compressed)",
    HOST_MEMORY_PRESSURE: "the VM's host is near its memory capacity",
    VCENTER_ALARM: "vCenter has a red alarm triggered on this VM",
    HOST_NOT_CONNECTED: "the VM's host is not connected to vCenter",
    LONG_RUNNING: "older than the longest an environment should live",
    CONSOLIDATION_NEEDED: "its disks need consolidation",
    HOST_IN_MAINTENANCE: "its host is in maintenance mode",
    TOOLS_OUTDATED: "its Tools version is too old, too new or blocklisted for this host",
    CPU_LIMITED: "a CPU limit caps it below full speed: apparent starvation that is configured, not the host",
    MEMORY_LIMITED: "a memory limit is set below its configured RAM, forcing the host to balloon or swap it",
}
OUTDATED_TOOLS = ("guestToolsTooOld", "guestToolsBlacklisted", "guestToolsTooNew")

RESET_EVENTS = (
    "VmResettingEvent",
    "VmGuestRebootEvent",
    "VmDasBeingResetEvent",
    "VmDasBeingResetWithScreenshotEvent",
)


@dataclass
class Verdict:
    """One VM's state, why, and on which values."""

    state: str
    reasons: list[str]
    values: dict[str, Any]
    flags: list[str] = field(default_factory=list)

    @property
    def abnormal(self) -> bool:
        """Whether the state, or a flag that matters on its own, is worth a look."""
        return self.state in ABNORMAL or any(flag in ATTENTION_FLAGS for flag in self.flags)

    def as_dict(self) -> dict[str, Any]:
        """The verdict as a tool result shows it."""
        return {
            "state": self.state,
            "meaning": MEANING[self.state],
            "reasons": self.reasons,
            "flags": self.flags,
            "flags_meaning": {flag: FLAG_MEANING[flag] for flag in self.flags},
            "values": self.values,
        }


def classify(  # noqa: C901, PLR0911, PLR0912 - one decision list, kept in one place
    vm: VmFacts,
    thresholds: Thresholds,
    *,
    resets_in_window: int = 0,
) -> Verdict:
    """Judge one VM. The order is the order of precedence; the first match wins."""
    fraction = vm.cpu_fraction
    values: dict[str, Any] = {
        "power_state": vm.power_state,
        "paused": vm.paused,
        "connection_state": vm.connection_state,
        "uptime_minutes": _round(vm.uptime_minutes),
        "uptime_measured_from": vm.boot_source,
        "age_hours": _round(vm.age_hours, 2),
        "tools_status": vm.tools_status,
        "tools_running": vm.tools_running,
        "tools_version_status": vm.tools_version_status,
        "heartbeat": vm.heartbeat,
        "guest_state": vm.guest_state,
        "cpu_mhz": vm.cpu_mhz,
        "cpu_share_of_vcpus": _round(fraction, 3),
        "cpu_limit_mhz": vm.cpu_limit_mhz,
        "cpu_reservation_mhz": vm.cpu_reservation_mhz,
        "memory_limit_mb": vm.memory_limit_mb,
        "memory_reservation_mb": vm.memory_reservation_mb,
        "memory_mb": vm.memory_mb,
        "ballooned_mb": vm.ballooned_mb,
        "swapped_mb": vm.swapped_mb,
        "compressed_kb": vm.compressed_kb,
        "host_memory_percent": _round(vm.host_memory_percent),
        "overall_status": vm.overall_status,
        "alarms": vm.alarms,
        "resets_in_window": resets_in_window,
    }
    flags = _flags(vm, thresholds, resets_in_window)
    reasons_for_flags = []
    if BOOT_LOOP in flags:
        reasons_for_flags.append(
            f"{resets_in_window} resets or guest reboots in the last "
            f"{thresholds.boot_loop_window_minutes:g} min"
        )
    if MEMORY_RECLAIMED in flags:
        reasons_for_flags.append(
            f"memory reclaimed by the host: {vm.ballooned_mb or 0} MB ballooned, "
            f"{vm.swapped_mb or 0} MB swapped, {vm.compressed_kb or 0} KB compressed"
        )
    if LONG_RUNNING in flags and vm.age_hours is not None:
        reasons_for_flags.append(
            f"created {vm.age_hours:.1f} h ago, over {thresholds.long_running_hours:g} h"
        )

    def verdict(state: str, *reasons: str) -> Verdict:
        return Verdict(state, [*reasons, *reasons_for_flags], values, flags)

    if vm.connection_state and vm.connection_state != "connected":
        return verdict(INACCESSIBLE, f"connection state is {vm.connection_state}")
    if vm.question is not None:
        values["question"] = vm.question.text
        values["choices"] = vm.question.choices
        return verdict(BLOCKED_ON_QUESTION, f"pending question: {vm.question.text}")
    if vm.power_state == "suspended":
        return verdict(SUSPENDED, "power state is suspended")
    if not vm.powered_on:
        return verdict(OFF, f"power state is {vm.power_state or 'unknown'}")
    if vm.paused:
        return verdict(PAUSED, "powered on, but vCenter reports the VM paused")
    if vm.tools_up:
        if vm.heartbeat == "red":
            return verdict(LOST_HEARTBEAT, "Tools running but heartbeat is red")
        if vm.heartbeat == "gray":
            # Gray beside a running Tools is the first seconds after it starts.
            return verdict(HEALTHY, "Tools running; heartbeat not reported yet (gray)")
        return verdict(HEALTHY, "Tools running")
    if vm.tools_installed is False:
        busy = f"; CPU at {fraction:.0%} of its vCPUs" if fraction is not None else ""
        return verdict(NO_TOOLS, f"guest.toolsStatus is {vm.tools_status}{busy}")
    if vm.uptime_minutes is None:
        return verdict(NO_BOOT_TIME, "powered on, Tools not running, and no boot time reported")
    if vm.uptime_minutes < thresholds.booted_not_up_minutes:
        return verdict(
            BOOTING,
            f"booted {vm.uptime_minutes:.1f} min ago, under the "
            f"{thresholds.booted_not_up_minutes:g} min allowed before Tools is expected",
        )
    if vm.tools_running == STARTING:
        up = (
            f"booted {vm.uptime_minutes:.0f} min ago and Tools has been starting since "
            "(executing its startup scripts) without finishing"
        )
    else:
        up = f"booted {vm.uptime_minutes:.0f} min ago and Tools is {vm.tools_running or 'unreported'}"
    if vm.cpu_mhz is not None and vm.cpu_mhz <= thresholds.hung_cpu_mhz:
        return verdict(HUNG, up, f"CPU {vm.cpu_mhz:.0f} MHz, at or under {thresholds.hung_cpu_mhz:g} MHz")
    if fraction is not None and fraction >= thresholds.busy_cpu_fraction:
        return verdict(
            BUSY_NOT_UP,
            up,
            f"CPU at {fraction:.0%} of its {vm.num_cpu} vCPU(s), at or over "
            f"{thresholds.busy_cpu_fraction:.0%}",
        )
    return verdict(BOOTED_NOT_UP, up)


def _flags(vm: VmFacts, thresholds: Thresholds, resets_in_window: int) -> list[str]:  # noqa: C901 - one test per flag
    """The flags a VM carries beside its state."""
    flags = []
    if resets_in_window >= thresholds.boot_loop_resets:
        flags.append(BOOT_LOOP)
    if vm.powered_on and vm.tools_up and vm.heartbeat == "yellow":
        flags.append(HEARTBEAT_INTERMITTENT)
    if vm.powered_on and any((vm.ballooned_mb or 0, vm.swapped_mb or 0, vm.compressed_kb or 0)):
        flags.append(MEMORY_RECLAIMED)
    if vm.powered_on and (vm.host_memory_percent or 0) >= thresholds.host_memory_percent:
        flags.append(HOST_MEMORY_PRESSURE)
    if any(alarm.get("status") == "red" for alarm in vm.alarms):
        flags.append(VCENTER_ALARM)
    if vm.host_connection_state and vm.host_connection_state != "connected":
        flags.append(HOST_NOT_CONNECTED)
    if vm.age_hours is not None and vm.age_hours >= thresholds.long_running_hours:
        flags.append(LONG_RUNNING)
    if vm.consolidation_needed:
        flags.append(CONSOLIDATION_NEEDED)
    if vm.host_maintenance:
        flags.append(HOST_IN_MAINTENANCE)
    if vm.tools_version_status in OUTDATED_TOOLS:
        flags.append(TOOLS_OUTDATED)
    if vm.cpu_limit_mhz is not None:
        flags.append(CPU_LIMITED)
    if vm.memory_limit_mb is not None and (vm.memory_mb is None or vm.memory_limit_mb < vm.memory_mb):
        flags.append(MEMORY_LIMITED)
    return flags


def ready_percent(ready_ms: float, interval_seconds: int, vcpus: int) -> float:
    """CPU ready as a percent of the sample, per vCPU.

    `cpu.ready.summation` is milliseconds spent ready but not running, summed
    over the interval and over the VM's vCPUs; raw, it misleads.
    """
    return ready_ms / (interval_seconds * 1000 * max(vcpus, 1)) * 100


def latest_reboot_by_vm(events: list[Any]) -> dict[str, Any]:
    """The most recent reset or guest-reboot event time per VM moref.

    A warm reboot does not move runtime.bootTime, but it does log one of these
    events, so this is how uptime is measured from the reboot rather than the
    original power-on.
    """
    latest: dict[str, Any] = {}
    for event in events:
        if type(event).__name__.rsplit(".", 1)[-1] not in RESET_EVENTS:
            continue
        vm = getattr(getattr(event, "vm", None), "vm", None)
        when = getattr(event, "createdTime", None)
        if vm is None or when is None:
            continue
        moref = vm._moId  # noqa: SLF001
        if moref not in latest or when > latest[moref]:
            latest[moref] = when
    return latest


def resets_by_vm(events: list[Any], window_minutes: float, now: Any) -> dict[str, int]:
    """How many reset-like events each VM had inside the window, by moref."""
    counts: dict[str, int] = {}
    for event in events:
        if type(event).__name__.rsplit(".", 1)[-1] not in RESET_EVENTS:
            continue
        if (now - event.createdTime).total_seconds() > window_minutes * 60:
            continue
        vm = getattr(getattr(event, "vm", None), "vm", None)
        if vm is not None:
            moref = vm._moId  # noqa: SLF001
            counts[moref] = counts.get(moref, 0) + 1
    return counts


def count_states(verdicts: Mapping[str, Verdict]) -> dict[str, int]:
    """How many VMs are in each state, in the order of `STATES`, zeros left out."""
    counts = dict.fromkeys(STATES, 0)
    for verdict in verdicts.values():
        counts[verdict.state] += 1
    return {state: count for state, count in counts.items() if count}


def _round(value: float | None, digits: int = 1) -> float | None:
    return None if value is None else round(value, digits)
