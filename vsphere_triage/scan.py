"""Scanning vCenters for abnormal VMs, and finding what the abnormal ones share.

A scan reads every VM on the vCenters asked for (one property-collector pass
each), judges each one, and groups the abnormal ones by everything they could
share: vCenter, cluster, host, datastore, environment folder, the folder that
holds the environments, linked-clone base disk and OS. Each group is measured
against its population, because "29 stuck VMs on ds-17" means little until it
is "29 of the 210 VMs on ds-17, against 2% across the fleet".
"""

from __future__ import annotations

import asyncio
import itertools
import time
import uuid
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from pyVmomi import vim

from vsphere_triage.checks import (
    ABNORMAL,
    ATTENTION_FLAGS,
    BOOTED_NOT_UP,
    BUSY_NOT_UP,
    CONTEXT_FLAGS,
    FLAG_MEANING,
    FLAGS,
    HUNG,
    MEANING,
    OFF,
    RESET_EVENTS,
    STATES,
    Verdict,
    classify,
    count_states,
    latest_reboot_by_vm,
    resets_by_vm,
)
from vsphere_triage.config import NotFoundError
from vsphere_triage.contention import hosts_cpu, storage
from vsphere_triage.diagnose import boot_from_vmware_log
from vsphere_triage.hostsensors import classify_sensors, read_sensors
from vsphere_triage.inventory import (
    HostFacts,
    Inventory,
    VmFacts,
    read_datastores,
    read_hosts,
    read_inventory,
    set_effective_boot,
)
from vsphere_triage.vcenter import QUERY_EVENTS_CAP, VSphereError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from vsphere_triage.config import Settings
    from vsphere_triage.vcenter import VCenterPool, VCenterSession


def _on(vm: VmFacts, value: str | None) -> list[str]:
    """A value qualified by its vCenter: two vCenters' `DC0_H0` are different hosts."""
    return [f"{vm.vcenter}:{value}"] if value else []


DIMENSIONS: dict[str, Callable[[VmFacts], list[str]]] = {
    "vcenter": lambda vm: [vm.vcenter],
    "cluster": lambda vm: _on(vm, vm.cluster),
    "host": lambda vm: _on(vm, vm.host),
    "datastore": lambda vm: [
        item
        for name in vm.datastores
        for item in _on(vm, f"{vm.datacenter}/{name}" if vm.datacenter else name)
    ],
    "environment_folder": lambda vm: _on(vm, vm.folder_path),
    "base_disk": lambda vm: _on(vm, vm.base_disk),
    # These two are concepts, not objects: the same across vCenters on purpose.
    "folder_parent": lambda vm: [vm.folder_parent] if vm.folder_parent else [],
    "os_family": lambda vm: [vm.os_family],
}
HOSTS_LISTED = 8
INFRASTRUCTURE_WINDOW = timedelta(minutes=15)
MIN_GROUP = 2
GROUPS_PER_DIMENSION = 5
REPRESENTATIVES = 3
# What a scan reports by default: every abnormal state, and the flags.
FLAGGED = (*ABNORMAL, *ATTENTION_FLAGS)
# What counts as abnormal in rates and groups: the states, and the flags that
# mean a VM in trouble. Context flags (long_running, memory_reclaimed, ...) are
# listed but would otherwise make a fleet of old VMs read as all abnormal.
STUCK = tuple(item for item in FLAGGED if item not in CONTEXT_FLAGS)
# Anything a caller may ask a scan for: every state, every flag.
SELECTABLE = (*STATES, *FLAGS)


@dataclass
class VCenterScan:
    """What one vCenter looked like at one moment."""

    inventory: Inventory
    verdicts: dict[str, Verdict]
    hosts: dict[str, dict[str, Any]]
    storage: dict[str, Any] | None
    notes: list[str] = field(default_factory=list)
    # Hardware sensor verdicts of the hosts read, by host moref.
    hardware: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass
class Scan:
    """A scan across vCenters, kept for `explain_group` to drill into."""

    id: str
    started: datetime
    vcenters: dict[str, VCenterScan]
    errors: dict[str, str]
    host_memory_percent: float = 95.0
    # What the scan was asked for, so explain_group drills into the groups it showed.
    states: tuple[str, ...] = FLAGGED

    def all_vms(self) -> list[tuple[VmFacts, Verdict]]:
        """Every VM read, with its verdict."""
        return [(vm, scan.verdicts[vm.moref]) for scan in self.vcenters.values() for vm in scan.inventory.vms]


class ScanStore:
    """The last few scans, by id, oldest dropped first."""

    def __init__(self, keep: int) -> None:
        """Keep at most `keep` scans."""
        self.keep = keep
        self._scans: OrderedDict[str, Scan] = OrderedDict()

    def put(self, scan: Scan) -> None:
        """Remember a scan."""
        self._scans[scan.id] = scan
        while len(self._scans) > self.keep:
            self._scans.popitem(last=False)

    def get(self, scan_id: str) -> Scan:
        """A remembered scan, or an error naming the ones kept."""
        try:
            return self._scans[scan_id]
        except KeyError:
            kept = ", ".join(self._scans) or "none"
            msg = f"No scan {scan_id!r} is kept (kept: {kept}); run scan again"
            raise NotFoundError(msg) from None


def scan_vcenter(session: VCenterSession, settings: Settings) -> VCenterScan:  # noqa: C901 - one read per source, each optional
    """Read and judge one vCenter. Blocking: runs in a worker thread."""
    thresholds = settings.thresholds
    notes = []
    now = session.now()
    # Events first: the latest reboot per VM measures uptime from the reboot, not
    # from power-on (which a warm reboot leaves untouched). The window covers the
    # recently rebooted VMs that would otherwise look long-stuck; a VM rebooted
    # longer ago than this with Tools still down is correctly abnormal anyway.
    reboot_window = max(thresholds.boot_loop_window_minutes, thresholds.booted_not_up_minutes * 3)
    try:
        events = session.events(begin=now - timedelta(minutes=reboot_window), end=now, types=RESET_EVENTS)
        resets = resets_by_vm(events, thresholds.boot_loop_window_minutes, now)
        reboots = latest_reboot_by_vm(events)
        if len(events) >= QUERY_EVENTS_CAP:
            notes.append(
                f"{len(events)} reset events in the window: vCenter returns at most "
                f"{QUERY_EVENTS_CAP}, so boot-loop counts are low and some reboots may be missed"
            )
    except vim.fault.NotAuthenticated:
        raise  # the session expired: let the pool re-login and run the scan again
    except Exception as error:  # noqa: BLE001 - a scan without events is still a scan
        resets, reboots = {}, {}
        notes.append(
            f"reset events not read ({type(error).__name__}); boot loops not detected and uptime "
            "is from power-on, which overstates it for warm-rebooted VMs"
        )
    inventory = read_inventory(session, with_devices=settings.scan_base_disks, reboots=reboots)
    verdicts = {
        vm.moref: classify(vm, thresholds, resets_in_window=resets.get(vm.moref, 0)) for vm in inventory.vms
    }
    notes.extend(_recheck_in_guest_reboots(session, inventory, verdicts, reboots, resets, settings))
    live_hosts = [host for host in inventory.hosts.values() if host.connection_state in (None, "connected")]
    try:
        hosts, unknown = hosts_cpu(
            session, live_hosts, begin=now - INFRASTRUCTURE_WINDOW, end=now, thresholds=thresholds
        )
        if unknown:
            notes.append("host CPU counters unavailable: " + ", ".join(unknown))
    except vim.fault.NotAuthenticated:
        raise  # the session expired: let the pool re-login and run the scan again
    except Exception as error:  # noqa: BLE001
        hosts = {}
        notes.append(f"host CPU not read ({type(error).__name__})")
    hardware: dict[str, dict[str, Any]] = {}
    try:
        sensors = read_sensors(session, [host.moref for host in live_hosts])
        hardware = {moref: classify_sensors(found) for moref, found in sensors.items()}
    except vim.fault.NotAuthenticated:
        raise  # the session expired: let the pool re-login and run the scan again
    except Exception as error:  # noqa: BLE001
        notes.append(f"host hardware sensors not read ({type(error).__name__})")
    store_report = None
    try:
        store_report = storage(
            session,
            {host.moref: host.name for host in live_hosts},
            list(inventory.datastores.values()),
            begin=now - INFRASTRUCTURE_WINDOW,
            end=now,
            thresholds=thresholds,
            with_devices=False,  # datastore-level only across the fleet; devices in explain_group
        )
    except vim.fault.NotAuthenticated:
        raise  # the session expired: let the pool re-login and run the scan again
    except Exception as error:  # noqa: BLE001
        notes.append(f"storage counters not read ({type(error).__name__})")
    return VCenterScan(inventory, verdicts, hosts, store_report, notes, hardware)


# States that rest on uptime: a VM rebooted inside the guest looks long-stuck in
# them, because vCenter logs no event for that reboot.
UPTIME_STATES = (HUNG, BUSY_NOT_UP, BOOTED_NOT_UP)
# How many such VMs a scan re-checks against their vmware.log, per vCenter, in
# how long, reading how much of each log, waiting how long for each read.
LOG_RECHECKS = 40
LOG_RECHECK_SECONDS = 30.0
LOG_RECHECK_BYTES = 256 * 1024
LOG_RECHECK_TIMEOUT = 10.0


def _recheck_in_guest_reboots(  # noqa: C901 - one bounded pass, each way a read can fail beside it
    session: VCenterSession,
    inventory: Inventory,
    verdicts: dict[str, Verdict],
    reboots: dict[str, datetime],
    resets: dict[str, int],
    settings: Settings,
) -> list[str]:
    """Re-judge VMs stuck by uptime from power-on against the last boot in their vmware.log.

    The same check diagnose_vm makes, made here for the suspects only: a mass
    in-guest reboot otherwise reads as a fleet of hung VMs. Returns notes.
    """
    suspects = [
        vm
        for vm in inventory.vms
        if verdicts[vm.moref].state in UPTIME_STATES and vm.boot_source in ("power_on", "quickstats")
    ]
    if not suspects:
        return []
    checked = suspects[:LOG_RECHECKS]
    try:
        rows = {
            row["moref"]: row
            for row in session.retrieve(
                vim.VirtualMachine,
                ("config.files.vmPathName", "config.files.logDirectory"),
                objects=[session.reference("VirtualMachine", vm.moref) for vm in checked],
            )
        }
    except vim.fault.NotAuthenticated:
        raise
    except Exception as error:  # noqa: BLE001 - the scan stands without the re-check
        return [f"in-guest reboots not re-checked in vmware.log ({type(error).__name__})"]
    rebooted = 0
    read = 0
    # Suspects often sit on a slow or unreachable datastore: the re-check gets its
    # own time budget and reads little per VM, so it cannot sink the whole scan.
    deadline = time.monotonic() + LOG_RECHECK_SECONDS
    for vm in checked:
        if time.monotonic() >= deadline:
            break
        read += 1
        try:
            log_boot = boot_from_vmware_log(
                session, vm, rows.get(vm.moref, {}), LOG_RECHECK_BYTES, timeout_seconds=LOG_RECHECK_TIMEOUT
            )
        except vim.fault.NotAuthenticated:
            raise
        except Exception:  # noqa: BLE001, S112 - one unreadable log leaves that VM as judged
            continue
        if log_boot is None:
            continue
        set_effective_boot(vm, inventory.read_at, reboots=reboots, log_boot=log_boot)
        if vm.boot_source == "vmware_log":
            rebooted += 1
            verdicts[vm.moref] = classify(vm, settings.thresholds, resets_in_window=resets.get(vm.moref, 0))
    notes = [
        (
            f"{read} VM(s) stuck by uptime from power-on re-checked against vmware.log for an "
            f"in-guest reboot: {rebooted} had rebooted since and were re-judged from that reboot"
        )
    ]
    if len(suspects) > read:
        notes.append(
            f"{len(suspects) - read} more were not re-checked (at most {LOG_RECHECKS} VMs or "
            f"{LOG_RECHECK_SECONDS:g} s); diagnose_vm re-checks any one of them"
        )
    return notes


async def run_scan(pool: VCenterPool, settings: Settings, names: Sequence[str]) -> Scan:
    """Scan the named vCenters concurrently; one failing does not fail the rest."""
    started = datetime.now().astimezone()
    results = await asyncio.gather(
        *(pool.sweep(name, lambda session: scan_vcenter(session, settings)) for name in names),
        return_exceptions=True,
    )
    scans: dict[str, VCenterScan] = {}
    errors: dict[str, str] = {}
    for name, result in zip(names, results, strict=True):
        if isinstance(result, BaseException):
            errors[name] = (
                str(result) if isinstance(result, VSphereError) else f"{type(result).__name__}: {result}"
            )
        else:
            scans[name] = result
    return Scan(
        id=uuid.uuid4().hex[:8],
        started=started,
        vcenters=scans,
        errors=errors,
        host_memory_percent=settings.thresholds.host_memory_percent,
    )


def grouping_states(states: Sequence[str]) -> tuple[str, ...]:
    """What makes a VM abnormal for rates and groups: `states` less the context flags.

    A caller who asked for context flags alone (scan for long_running) gets them.
    """
    stuck = tuple(item for item in states if item not in CONTEXT_FLAGS)
    return stuck or tuple(states)


def groups(scan: Scan, *, states: Sequence[str] = FLAGGED) -> dict[str, list[dict[str, Any]]]:
    """The groups abnormal VMs fall into, per dimension, strongest first."""
    states = grouping_states(states)
    considered = [(vm, verdict) for vm, verdict in scan.all_vms() if verdict.state != OFF]
    flagged = [(vm, verdict) for vm, verdict in considered if _counts(verdict, states)]
    if not considered or not flagged:
        return {}
    fleet_rate = len(flagged) / len(considered)
    result: dict[str, list[dict[str, Any]]] = {}
    for dimension, values_of in DIMENSIONS.items():
        population = Counter(itertools.chain.from_iterable(values_of(vm) for vm, _ in considered))
        hits: dict[str, list[tuple[VmFacts, Verdict]]] = {}
        for vm, verdict in flagged:
            for value in values_of(vm):
                hits.setdefault(value, []).append((vm, verdict))
        rows = []
        for value, members in hits.items():
            if len(members) < MIN_GROUP:
                continue
            total = population[value]
            rate = len(members) / total
            rows.append(
                {
                    "dimension": dimension,
                    "value": value,
                    "abnormal": len(members),
                    "population": total,
                    "rate": round(rate, 3),
                    "times_fleet_rate": round(rate / fleet_rate, 2),
                    # How far above the fleet, weighted by how many: 3 of 3 on one base
                    # disk outranks 9 of 13 on a whole vCenter when the fleet rate is 50%.
                    "strength": round((rate - fleet_rate) * len(members) ** 0.5, 3),
                    "states": dict(Counter(verdict.state for _, verdict in members)),
                    "representatives": [
                        vm.key | {"name": vm.name} for vm in representatives([vm for vm, _ in members])
                    ],
                }
            )
        # A value every VM shares (the only vCenter scanned) says nothing.
        rows = [row for row in rows if row["population"] < len(considered)]  # ty: ignore[unsupported-operator] - dict-of-Any value
        rows.sort(key=lambda row: (row["strength"], row["abnormal"]), reverse=True)
        if rows:
            result[dimension] = rows[:GROUPS_PER_DIMENSION]
    return result


def representatives(members: list[VmFacts]) -> list[VmFacts]:
    """Up to three VMs worth diagnosing for a group: earliest, middle and latest boot."""
    ordered = sorted(
        members,
        key=lambda vm: (vm.boot_time is None, vm.boot_time.timestamp() if vm.boot_time else 0.0),
    )
    if len(ordered) <= REPRESENTATIVES:
        return ordered
    return [ordered[0], ordered[len(ordered) // 2], ordered[-1]]


def _counts(verdict: Verdict, states: Sequence[str]) -> bool:
    return verdict.state in states or bool(set(verdict.flags) & set(states))


def summary(scan: Scan, *, states: Sequence[str] = FLAGGED, limit: int) -> dict[str, Any]:
    """A scan as a tool result: findings, counts, groups, infrastructure, then VMs."""
    everything = scan.all_vms()
    flagged = [(vm, verdict) for vm, verdict in everything if _counts(verdict, states)]
    stuck = grouping_states(states)
    abnormal = [(vm, verdict) for vm, verdict in flagged if _counts(verdict, stuck)]
    by_state = count_states({f"{vm.vcenter}/{vm.moref}": verdict for vm, verdict in everything})
    grouped = groups(scan, states=states)
    strongest = sorted(
        (row for rows in grouped.values() for row in rows if row["strength"] > 0),
        key=lambda row: row["strength"],
        reverse=True,
    )[:6]
    overcommitted = [
        host | {"vcenter": name}
        for name, vscan in scan.vcenters.items()
        for host in vscan.hosts.values()
        if host.get("overcommitted") or host.get("near_capacity")
    ]
    memory_pressed = sorted(  # ty: ignore[no-matching-overload] - dict-of-Any value sorted by a numeric field
        (
            {
                "vcenter": name,
                "name": host.name,
                "memory_percent": round(host.memory_percent, 1),
                "cluster": host.cluster,
            }
            for name, vscan in scan.vcenters.items()
            for host in vscan.inventory.hosts.values()
            if host.memory_percent is not None and host.memory_percent >= scan.host_memory_percent
        ),
        key=lambda host: host["memory_percent"],
        reverse=True,
    )
    not_connected = [
        {"vcenter": name, "name": host.name, "connection_state": host.connection_state}
        for name, vscan in scan.vcenters.items()
        for host in vscan.inventory.hosts.values()
        if host.connection_state not in (None, "connected")
    ]
    vms_on_host = Counter(
        (name, vm.host_moref)
        for name, vscan in scan.vcenters.items()
        for vm in vscan.inventory.vms
        if vm.powered_on
    )
    failing_hardware: list[dict[str, Any]] = [
        {
            "vcenter": name,
            "name": vscan.inventory.hosts[moref].name if moref in vscan.inventory.hosts else moref,
            "moref": moref,
            "red": [sensor.get("name") for sensor in verdict["red"]][:10],
            "yellow": [sensor.get("name") for sensor in verdict["yellow"]][:10],
            "powered_on_vms": vms_on_host.get((name, moref), 0),
        }
        for name, vscan in scan.vcenters.items()
        for moref, verdict in vscan.hardware.items()
        if verdict["healthy"] is False
    ]
    # Red before yellow, then the hosts carrying the most VMs.
    failing_hardware.sort(key=lambda host: (not host["red"], -int(host["powered_on_vms"])))
    hardware_unjudged = sum(
        1
        for vscan in scan.vcenters.values()
        for verdict in vscan.hardware.values()
        if verdict["healthy"] is None
    )
    flag_counts: Counter[str] = Counter(flag for _, verdict in everything for flag in verdict.flags)
    slow_storage = [
        finding
        for vscan in scan.vcenters.values()
        if vscan.storage
        for finding in vscan.storage.get("findings", [])
    ]
    findings = []
    considered = sum(1 for _, verdict in everything if verdict.state != OFF)
    # A powered-off leftover can carry an attention flag (long_running), so it is
    # flagged but not among the powered-on: count the two separately rather than
    # reporting "N abnormal of M powered-on" with N larger than M.
    abnormal_on = sum(1 for _, verdict in abnormal if verdict.state != OFF)
    context_only = len(flagged) - len(abnormal)
    flagged_off = sum(1 for _, verdict in abnormal if verdict.state == OFF)
    # Asked for other states (healthy, no_tools), the groups hold those VMs: say so,
    # or "3 of 3 on a base disk are abnormal" would send a reader after healthy VMs.
    word = "abnormal" if tuple(states) == FLAGGED else " or ".join(stuck)
    findings.append(
        f"{abnormal_on} {word} of {considered} powered-on VMs across {len(scan.vcenters)} vCenter(s)"
        + (f"; {flagged_off} powered-off VM(s) also flagged" if flagged_off else "")
        + (
            f"; {context_only} more carry only context flags (long_running, memory_reclaimed, ...), "
            "listed but not counted as abnormal"
            if context_only
            else ""
        )
    )
    findings.extend(
        f"{row['abnormal']} of {row['population']} VMs on {row['dimension']} {row['value']!r} are {word} "
        f"({row['times_fleet_rate']:g}x the fleet rate)"
        for row in strongest
    )
    overcommitted.sort(key=lambda host: host.get("peak_percent_of_capacity") or 0, reverse=True)
    if overcommitted:
        listed = ", ".join(
            f"{host['vcenter']}:{host['name']} {host['peak_percent_of_capacity']}%"
            for host in overcommitted[:HOSTS_LISTED]
        )
        more = len(overcommitted) - HOSTS_LISTED
        findings.append(
            f"{len(overcommitted)} host(s) at or over the CPU threshold in the last "
            f"{int(INFRASTRUCTURE_WINDOW.total_seconds() // 60)} min: {listed}"
            + (f", and {more} more" if more > 0 else "")
        )
    if memory_pressed:
        listed = ", ".join(
            f"{host['vcenter']}:{host['name']} {host['memory_percent']}%"
            for host in memory_pressed[:HOSTS_LISTED]
        )
        findings.append(f"{len(memory_pressed)} host(s) near memory capacity: {listed}")
    if not_connected:
        findings.append(
            f"{len(not_connected)} host(s) not connected to vCenter: "
            + ", ".join(
                f"{host['vcenter']}:{host['name']} ({host['connection_state']})"
                for host in not_connected[:HOSTS_LISTED]
            )
        )
    if failing_hardware:
        listed = "; ".join(
            f"{host['vcenter']}:{host['name']} ("
            + (
                f"red: {', '.join(map(str, host['red']))}"
                if host["red"]
                else f"yellow: {', '.join(map(str, host['yellow']))}"
            )
            + f"; {host['powered_on_vms']} VMs)"
            for host in failing_hardware[:HOSTS_LISTED]
        )
        findings.append(f"{len(failing_hardware)} host(s) report hardware sensors red or yellow: {listed}")
    if hardware_unjudged:
        findings.append(
            f"{hardware_unjudged} host(s) report no usable hardware sensor data (no CIM provider, or all "
            "unknown): their hardware is not judged"
        )
    findings.extend(
        f"{count} VM(s) flagged {flag}: {FLAG_MEANING[flag]}"
        for flag, count in flag_counts.most_common()
        if flag in ATTENTION_FLAGS
    )
    findings.extend(slow_storage[:10])
    for name, error in scan.errors.items():
        findings.append(f"vCenter {name} not scanned: {error}")
    rows = sorted(
        flagged,
        key=lambda pair: (
            not _counts(pair[1], stuck),
            ABNORMAL.index(pair[1].state) if pair[1].state in ABNORMAL else len(ABNORMAL),
            -(pair[0].uptime_minutes or 0),
        ),
    )
    return {
        "scan_id": scan.id,
        "findings": findings,
        "counts_by_state": by_state,
        "states_meaning": {state: MEANING[state] for state in by_state},
        "counts_by_flag": dict(flag_counts.most_common()),
        "flags_meaning": {flag: FLAG_MEANING[flag] for flag in flag_counts},
        "strongest_groups": strongest,
        "groups": grouped,
        "hosts_over_cpu_threshold": overcommitted,
        "hosts_near_memory_capacity": memory_pressed,
        "hosts_not_connected": not_connected,
        "hosts_with_hardware_problems": failing_hardware[:50],
        "hosts_with_hardware_problems_total": len(failing_hardware),
        "storage_findings": slow_storage,
        "vcenters": {
            name: {
                "read_at": vscan.inventory.read_at,
                "vms": len(vscan.inventory.vms),
                "hosts": len(vscan.inventory.hosts),
                "base_disks_read": vscan.inventory.base_disks_read,
                "notes": vscan.notes,
            }
            for name, vscan in scan.vcenters.items()
        },
        "errors": scan.errors,
        "abnormal_vms_total": len(abnormal),
        "context_flagged_vms_total": context_only,
        "abnormal_vms": [
            vm.identity() | {"verdict": _row_verdict(verdict), "notes": vm.notes}
            for vm, verdict in rows[:limit]
        ],
        "abnormal_vms_truncated": max(0, len(rows) - limit),
        "next": (
            "explain_group(scan_id, dimension, value) on the strongest group; "
            "diagnose_vm on its representatives"
        ),
    }


def _row_verdict(verdict: Verdict) -> dict[str, Any]:
    """A verdict as a scan row shows it: the legend once, above the rows; unset values left out."""
    shown = verdict.as_dict()
    del shown["meaning"], shown["flags_meaning"]
    shown["values"] = {key: value for key, value in verdict.values.items() if value not in (None, [], {})}
    return shown


def _sensor_names(host: dict[str, Any]) -> str:
    """The failing sensors of a host, red ones when it has any."""
    red: list[Any] = host["red"]
    yellow: list[Any] = host["yellow"]
    return f"red: {', '.join(map(str, red))}" if red else f"yellow: {', '.join(map(str, yellow))}"


def _window_since(boots: list[datetime], now: datetime) -> tuple[datetime, datetime]:
    earliest = min(boots) if boots else None
    if earliest is None or now - earliest > timedelta(minutes=58):
        return now - timedelta(minutes=58), now
    return earliest - timedelta(minutes=2), now


def explain_on_vcenter(
    session: VCenterSession,
    settings: Settings,
    vscan: VCenterScan,
    members: list[VmFacts],
    healthy: list[VmFacts],
) -> dict[str, Any]:
    """CPU and storage over the members' boot window, on one vCenter. Blocking."""
    thresholds = settings.thresholds
    now = session.now()
    begin, end = _window_since([vm.boot_time for vm in members if vm.boot_time], now)
    host_ids = {vm.host_moref for vm in [*members, *healthy] if vm.host_moref}
    hosts = [vscan.inventory.hosts[moref] for moref in host_ids if moref in vscan.inventory.hosts]
    cpu, unknown = hosts_cpu(session, hosts, begin=begin, end=end, thresholds=thresholds)
    member_hosts = {vm.host_moref for vm in members}
    # By moref: a datastore name can repeat across datacenters of one vCenter.
    morefs = {moref for vm in members for moref in vm.datastore_morefs}
    stores = [store for moref, store in vscan.inventory.datastores.items() if moref in morefs]
    disk = storage(
        session,
        {host.moref: host.name for host in hosts if host.moref in member_hosts},
        stores,
        begin=begin,
        end=end,
        thresholds=thresholds,
    )
    return {
        "window": {"from": begin, "to": end},
        "hosts_cpu": [cpu[moref] | {"has_abnormal_members": moref in member_hosts} for moref in cpu],
        "cpu_counters_unavailable": unknown,
        "storage": disk,
    }


async def explain_group(  # noqa: C901 - one comparison, then one check per vCenter
    pool: VCenterPool, settings: Settings, scan: Scan, dimension: str, value: str
) -> dict[str, Any]:
    """What a group's abnormal VMs share that the healthy VMs beside them do not, and why."""
    if dimension not in DIMENSIONS:
        msg = f"dimension must be one of {', '.join(DIMENSIONS)}"
        raise ValueError(msg)
    values_of = DIMENSIONS[dimension]
    inside = [
        (vm, verdict) for vm, verdict in scan.all_vms() if value in values_of(vm) and verdict.state != OFF
    ]
    # As the scan's groups counted them, from the states the scan was asked for.
    counted = grouping_states(scan.states)
    members = [vm for vm, verdict in inside if _counts(verdict, counted)]
    healthy = [vm for vm, verdict in inside if not _counts(verdict, counted)]
    if not members:
        return {"found": False, "reason": f"no abnormal VMs on {dimension} {value!r} in scan {scan.id}"}
    comparison = {}
    findings = [f"{len(members)} abnormal and {len(healthy)} healthy powered-on VMs on {dimension} {value!r}"]
    for other, other_values in DIMENSIONS.items():
        if other == dimension:
            continue
        bad = Counter(itertools.chain.from_iterable(other_values(vm) for vm in members))
        good = Counter(itertools.chain.from_iterable(other_values(vm) for vm in healthy))
        comparison[other] = {"abnormal": dict(bad.most_common(8)), "healthy": dict(good.most_common(8))}
        concentrated = [
            name
            for name, count in bad.items()
            if count >= max(MIN_GROUP, len(members) // 2) and good.get(name, 0) == 0 and good
        ]
        if concentrated:
            findings.append(
                f"the abnormal ones concentrate on {other} {', '.join(sorted(concentrated))}, "
                "where none of the healthy ones are"
            )
    per_vcenter: dict[str, Any] = {}
    for name in sorted({vm.vcenter for vm in members}):
        vscan = scan.vcenters[name]
        own = [vm for vm in members if vm.vcenter == name]
        own_healthy = [vm for vm in healthy if vm.vcenter == name]
        try:
            per_vcenter[name] = await pool.sweep(
                name,
                lambda session, vs=vscan, m=own, h=own_healthy: explain_on_vcenter(
                    session, settings, vs, m, h
                ),
            )
        except Exception as error:  # noqa: BLE001 - one vCenter failing leaves the rest
            per_vcenter[name] = {"available": False, "reason": f"{type(error).__name__}: {error}"}
            continue
        for host in per_vcenter[name]["hosts_cpu"]:
            if host.get("overcommitted"):
                side = "with abnormal VMs" if host["has_abnormal_members"] else "with only healthy VMs"
                findings.append(
                    f"host {host['name']} ({side}) CPU demand peaked at {host['peak_percent_of_capacity']}% "
                    "of capacity in the window"
                )
        findings.extend(per_vcenter[name]["storage"].get("findings", [])[:8])
    if len(findings) == 1:
        findings.append("no host or storage pressure found in the window; look at the guests (diagnose_vm)")
    member_ids = {id(vm) for vm in members}
    states = Counter(verdict.state for vm, verdict in inside if id(vm) in member_ids)
    return {
        "found": True,
        "scan_id": scan.id,
        "group": {"dimension": dimension, "value": value},
        "findings": findings,
        "states": dict(states),
        "comparison": comparison,
        "infrastructure": per_vcenter,
        "representatives": [vm.identity() for vm in representatives(members)],
        "next": "diagnose_vm on the representatives",
    }


WINDOW_EVENTS = (
    *RESET_EVENTS,
    "VmFailedToPowerOnEvent",
    "VmPoweredOffEvent",
    "VmMessageErrorEvent",
    "VmMessageWarningEvent",
    "VmRestartedOnAlternateHostEvent",
    "VmDasResetFailedEvent",
)


def window_on_vcenter(
    session: VCenterSession, settings: Settings, begin: datetime, end: datetime
) -> dict[str, Any]:
    """Resets, failures and pressure on one vCenter over a past window. Blocking."""
    thresholds = settings.thresholds
    # Read in pieces when the window holds more than one QueryEvents answer.
    events, events_cut = session.events_covering(begin=begin, end=end, types=WINDOW_EVENTS)
    by_host: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    by_folder_vm: Counter[str] = Counter()
    vm_names: dict[str, str] = {}
    for event in events:
        kind = type(event).__name__.rsplit(".", 1)[-1]
        by_type[kind] += 1
        host = getattr(getattr(event, "host", None), "name", None)
        if host:
            by_host[host] += 1
        vm_arg = getattr(event, "vm", None)
        vm_ref = getattr(vm_arg, "vm", None)
        if vm_ref is not None:
            # By moref, not name: names are reused across short-lived environments.
            moref = vm_ref._moId  # noqa: SLF001
            by_folder_vm[moref] += 1
            vm_names[moref] = getattr(vm_arg, "name", None) or moref
    hosts = [host for host in _hosts(session) if host.connection_state in (None, "connected")]
    cpu, unknown = hosts_cpu(session, hosts, begin=begin, end=end, thresholds=thresholds)
    disk = storage(
        session,
        {host.moref: host.name for host in hosts},
        list(read_datastores(session).values()),
        begin=begin,
        end=end,
        thresholds=thresholds,
        with_devices=False,
    )
    # Did the window actually have perf data? Below statistics level 3, or for a
    # window older than vCenter keeps fine data, the series come back empty — and
    # empty must not read as "no pressure".
    cpu_window_read = any(host.get("window_series") for host in cpu.values())
    storage_matched = any(entry.get("matched_instance") for entry in disk.get("datastores", []))
    return {
        "events_read": len(events),
        "events_capped": events_cut,
        "events_by_type": dict(by_type),
        "events_by_host": dict(by_host.most_common(15)),
        "vms_with_most_events": {
            f"{vm_names.get(moref, moref)} ({moref})": count for moref, count in by_folder_vm.most_common(15)
        },
        "hosts_over_cpu_threshold": [
            host for host in cpu.values() if host.get("overcommitted") or host.get("near_capacity")
        ],
        "cpu_counters_unavailable": unknown,
        "cpu_window_read": cpu_window_read,
        "storage_window_read": storage_matched,
        "storage": disk,
    }


def _hosts(session: VCenterSession) -> list[HostFacts]:
    return list(read_hosts(session).values())


async def diagnose_window(
    pool: VCenterPool, settings: Settings, names: Sequence[str], begin: datetime, end: datetime
) -> dict[str, Any]:
    """The fleet over a past window, when the VMs themselves may already be gone."""
    results = await asyncio.gather(
        *(
            pool.sweep(name, lambda session: window_on_vcenter(session, settings, begin, end))
            for name in names
        ),
        return_exceptions=True,
    )
    per_vcenter: dict[str, Any] = {}
    findings = []
    for name, result in zip(names, results, strict=True):
        if isinstance(result, BaseException):
            per_vcenter[name] = {"available": False, "reason": str(result)}
            findings.append(f"vCenter {name} not read: {result}")
            continue
        per_vcenter[name] = result
        if result["events_capped"]:
            findings.append(
                f"{name}: some part of the window still held over {QUERY_EVENTS_CAP} events after "
                "splitting it; counts are incomplete, narrow the window"
            )
        resets = sum(result["events_by_type"].get(kind, 0) for kind in RESET_EVENTS)
        failures = result["events_by_type"].get("VmFailedToPowerOnEvent", 0)
        if resets or failures:
            top = ", ".join(f"{host} ({count})" for host, count in list(result["events_by_host"].items())[:3])
            findings.append(
                f"{name}: {resets} resets and {failures} failed power-ons; most on {top or 'unknown hosts'}"
            )
        findings.extend(
            f"{name}: host {host['name']} CPU {host['basis']} peaked at "
            f"{host['peak_percent_of_capacity']}% of capacity"
            for host in result["hosts_over_cpu_threshold"]
        )
        findings.extend(f"{name}: {finding}" for finding in result["storage"].get("findings", [])[:8])
        # Say when CPU or storage could not be read, so an empty series is not
        # mistaken for a healthy one.
        if not result.get("cpu_window_read"):
            findings.append(
                f"{name}: host CPU for this window could not be read (counters not kept this far back "
                "or below statistics level 3); not evidence of no CPU pressure"
            )
        if not result.get("storage_window_read"):
            findings.append(
                f"{name}: datastore latency for this window could not be read; "
                "not evidence of healthy storage"
            )
    # Anything that went wrong in the window counts, resets and failed power-ons
    # as much as pressure: the "nothing found" line must never sit above them.
    trouble = (*RESET_EVENTS, "VmFailedToPowerOnEvent")
    pressure = any(
        result.get("hosts_over_cpu_threshold")
        or result.get("storage", {}).get("findings")
        or any(result.get("events_by_type", {}).get(kind) for kind in trouble)
        for result in per_vcenter.values()
        if result.get("available", True)
    )
    if not pressure and all(
        r.get("cpu_window_read") and r.get("storage_window_read")
        for r in per_vcenter.values()
        if isinstance(r, dict)
    ):
        findings.insert(0, "no resets, failures, CPU or storage pressure found in the window (all data read)")
    elif not findings:
        findings.append("nothing found, but some CPU or storage data for the window could not be read")
    return {
        "window": {"from": begin, "to": end},
        "findings": findings,
        "vcenters": per_vcenter,
        "note": (
            "windows older than about an hour use vCenter's historical rollup, which keeps fewer "
            "counters; vROps keeps longer and finer history for hosts and datastores"
        ),
    }
