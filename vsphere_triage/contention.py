"""CPU and storage contention: the two causes seen behind VMs that do not come back.

Read from vCenter's performance counters (20-second samples for about the last
hour, coarser after). Every result carries the numbers it judged and the
counters that were not available, because a missing counter is not a healthy
one: it usually means the statistics level does not keep it.
"""

from __future__ import annotations

import re
from statistics import fmean
from typing import TYPE_CHECKING, Any

from vsphere_triage.checks import ready_percent

if TYPE_CHECKING:
    from datetime import datetime

    from vsphere_triage.config import Thresholds
    from vsphere_triage.inventory import HostFacts, VmFacts
    from vsphere_triage.vcenter import PerfSeries, VCenterSession

VM_CPU = ("cpu.ready.summation", "cpu.costop.summation", "cpu.usagemhz.average")
HOST_CPU = ("cpu.demand.average", "cpu.usagemhz.average")
HOST_DATASTORE = (
    "datastore.totalReadLatency.average",
    "datastore.totalWriteLatency.average",
    "datastore.numberReadAveraged.average",
    "datastore.numberWriteAveraged.average",
)
HOST_DISK = (
    "disk.deviceLatency.average",
    "disk.kernelLatency.average",
    "disk.queueLatency.average",
    "disk.commandsAborted.summation",
    "disk.busResets.summation",
)
VM_DISK = (
    "virtualDisk.totalReadLatency.average",
    "virtualDisk.totalWriteLatency.average",
    "virtualDisk.numberReadAveraged.average",
    "virtualDisk.numberWriteAveraged.average",
)
VOLUME_UUID = re.compile(r"/volumes/([^/]+)/?")
# Usage at or above this share of capacity is a weak "near capacity" hint; only
# demand can prove overcommit, since usage caps at capacity.
USAGE_NEAR_CAPACITY_PERCENT = 90.0


def summarize(samples: list[tuple[datetime, float]]) -> dict[str, Any] | None:
    """Max, mean and last of a series, and when it peaked."""
    if not samples:
        return None
    values = [value for _, value in samples]
    peak_at, peak = max(samples, key=lambda sample: sample[1])
    return {
        "max": round(peak, 2),
        "mean": round(fmean(values), 2),
        "last": round(values[-1], 2),
        "peak_at": peak_at,
        "samples": len(values),
        "from": samples[0][0],
        "to": samples[-1][0],
    }


def _aggregate(series: PerfSeries | None) -> list[tuple[datetime, float]]:
    """The whole-entity samples of a series: instance "" where present, else summed."""
    if series is None or not series.samples:
        return []
    if "" in series.samples:
        return series.samples[""]
    if len(series.samples) == 1:
        return next(iter(series.samples.values()))
    totals: dict[datetime, float] = {}
    for samples in series.samples.values():
        for stamp, value in samples:
            totals[stamp] = totals.get(stamp, 0.0) + value
    return sorted(totals.items())


def vm_cpu(
    session: VCenterSession,
    vm: VmFacts,
    host: HostFacts | None,
    *,
    begin: datetime,
    end: datetime,
    thresholds: Thresholds,
) -> dict[str, Any]:
    """Whether this VM was starved of CPU, and its host overcommitted, in the window."""
    entities = [session.reference("VirtualMachine", vm.moref)]
    if host is not None:
        entities.append(session.reference("HostSystem", host.moref))
    series, unknown = session.perf(entities, (*VM_CPU, *HOST_CPU), begin=begin, end=end, instance="")
    own = series.get(vm.moref, {})
    result: dict[str, Any] = {"window": {"from": begin, "to": end}, "counters_unavailable": unknown}
    ready = own.get("cpu.ready.summation")
    vcpus = vm.num_cpu or 1
    if ready is not None:
        percents = [
            (stamp, ready_percent(value, ready.interval_seconds, vcpus)) for stamp, value in _aggregate(ready)
        ]
        result["vm_ready_percent_per_vcpu"] = summarize(percents)
    costop = own.get("cpu.costop.summation")
    if costop is not None:
        percents = [
            (stamp, ready_percent(value, costop.interval_seconds, vcpus))
            for stamp, value in _aggregate(costop)
        ]
        result["vm_costop_percent_per_vcpu"] = summarize(percents)
    result["vm_cpu_mhz"] = summarize(_aggregate(own.get("cpu.usagemhz.average")))
    # Whether the window had any samples at all: an old window can come back
    # empty once vCenter has rolled it up, and empty must not read as healthy.
    result["window_read"] = any(_aggregate(item) for per in series.values() for item in per.values())
    if host is not None:
        result["host"] = host_cpu_from_series(host, series.get(host.moref, {}), thresholds)
    findings = []
    ready_summary = result.get("vm_ready_percent_per_vcpu")
    if ready_summary and ready_summary["max"] >= thresholds.vm_ready_percent:
        findings.append(
            f"the VM waited for CPU: ready time peaked at {ready_summary['max']:.1f}% per vCPU "
            f"(mean {ready_summary['mean']:.1f}%), over the {thresholds.vm_ready_percent:g}% threshold"
        )
    costop_summary = result.get("vm_costop_percent_per_vcpu")
    if costop_summary and costop_summary["max"] >= thresholds.vm_costop_percent:
        findings.append(
            f"co-stop peaked at {costop_summary['max']:.1f}% per vCPU: its vCPUs could not run together"
        )
    host_result = result.get("host") or {}
    if host_result.get("overcommitted"):
        findings.append(
            f"host {host_result['name']} was overcommitted: CPU demand peaked at "
            f"{host_result['peak_percent_of_capacity']:.0f}% of capacity"
        )
    result["starved"] = bool(findings)
    result["findings"] = findings
    return result


def host_cpu_from_series(
    host: HostFacts, series: dict[str, PerfSeries], thresholds: Thresholds
) -> dict[str, Any]:
    """A host's CPU demand over the window, against its capacity.

    Demand is authoritative: over 100% means overcommit. Usage alone cannot show
    overcommit (it caps at capacity), so a usage-only window is reported with
    overcommit unknown, never as evidence either way. With no window series at
    all, only the current quickStats value is reported, clearly labelled as
    current rather than the window's peak.
    """
    demand = summarize(_aggregate(series.get("cpu.demand.average")))
    usage = summarize(_aggregate(series.get("cpu.usagemhz.average")))
    capacity = host.capacity_mhz
    base = {
        "name": host.name,
        "moref": host.moref,
        "cluster": host.cluster,
        "capacity_mhz": capacity,
        "threshold_percent": thresholds.host_cpu_demand_percent,
        "overcommitted": None,
        "near_capacity": None,
        "window_series": demand is not None or usage is not None,
    }
    if demand is not None:
        over = capacity and demand["max"] >= capacity * thresholds.host_cpu_demand_percent / 100
        return base | {
            "basis": "demand",
            "peak_percent_of_capacity": _percent(demand["max"], capacity),
            "mean_percent_of_capacity": _percent(demand["mean"], capacity),
            "peak_at": demand["peak_at"],
            # Without a capacity the peak cannot be judged: unknown, never "not over".
            "overcommitted": None if not capacity else bool(over),
        }
    if usage is not None:
        peak_pct = _percent(usage["max"], capacity)
        return base | {
            "basis": "usage",
            "peak_percent_of_capacity": peak_pct,
            "mean_percent_of_capacity": _percent(usage["mean"], capacity),
            "peak_at": usage["peak_at"],
            # Usage cannot exceed capacity, so it cannot prove overcommit; a high
            # value is a weak hint, and demand would be needed to be sure.
            "near_capacity": bool(peak_pct is not None and peak_pct >= USAGE_NEAR_CAPACITY_PERCENT),
            "note": "only CPU usage was available for the window, not demand, so overcommit cannot be judged",
        }
    return base | {
        "basis": "current",
        "peak_percent_of_capacity": None,
        "current_percent_of_capacity": _percent(host.cpu_usage_mhz, capacity),
        "peak_at": None,
        "note": "no CPU series for the window; only the host's current usage is known, not the window's peak",
    }


def _percent(value: float | None, capacity: float | None) -> float | None:
    if value is None or not capacity:
        return None
    return round(value / capacity * 100, 1)


def hosts_cpu(
    session: VCenterSession,
    hosts: list[HostFacts],
    *,
    begin: datetime,
    end: datetime,
    thresholds: Thresholds,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """CPU demand of many hosts in one query, by moref."""
    if not hosts:
        return {}, []
    series, unknown = session.perf(
        [session.reference("HostSystem", host.moref) for host in hosts],
        HOST_CPU,
        begin=begin,
        end=end,
        instance="",
    )
    return (
        {host.moref: host_cpu_from_series(host, series.get(host.moref, {}), thresholds) for host in hosts},
        unknown,
    )


def datastore_uuid(url: str | None) -> str | None:
    """The volume id in a datastore URL, which is how host counters name it."""
    if not url:
        return None
    match = VOLUME_UUID.search(url)
    return match.group(1) if match else None


def datastore_instances(store: dict[str, Any]) -> list[str]:
    """The names a host's `datastore.*` counters might use for this datastore, likeliest first.

    vCenter names the instance by the volume id in the datastore's URL. When the
    URL carries none (some NFS mounts, a simulator), the name and the last part
    of the URL are tried, and the result says which one matched.
    """
    candidates = [datastore_uuid(store.get("url")), store.get("name")]
    url = (store.get("url") or "").rstrip("/")
    if url:
        candidates.append(url.rsplit("/", 1)[-1])
    seen: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in seen:
            seen.append(candidate)
    return seen


def storage(  # noqa: C901, PLR0912, PLR0915 - one report over many counters
    session: VCenterSession,
    hosts: dict[str, str],
    datastores: list[dict[str, Any]],
    *,
    begin: datetime,
    end: datetime,
    thresholds: Thresholds,
    vm_moref: str | None = None,
    with_devices: bool = True,
) -> dict[str, Any]:
    """Whether the datastores were slow in the window, and if so the device's side or the host's queue.

    `hosts` maps the morefs of the hosts to read to their names. `with_devices`
    reads the per-device (per-LUN) counters that split the array's side from the
    host's queue; a fleet scan turns it off, because reading every device
    instance on every host across the whole fleet is a vast query, and leaves it
    to diagnose_vm / explain_group to read devices for the one host in question.
    """
    host_morefs = list(hosts)
    entities = [session.reference("HostSystem", moref) for moref in host_morefs]
    if vm_moref is not None:
        entities.append(session.reference("VirtualMachine", vm_moref))
    counters = (*HOST_DATASTORE, *(HOST_DISK if with_devices else ()), *(VM_DISK if vm_moref else ()))
    series, unknown = session.perf(entities, counters, begin=begin, end=end, instance="*")
    result: dict[str, Any] = {
        "window": {"from": begin, "to": end},
        "counters_unavailable": unknown,
        "datastores": [],
        "host_devices": [],
    }
    findings: list[str] = []
    capacity_findings: list[str] = []
    for store in datastores:
        instances = datastore_instances(store)
        entry: dict[str, Any] = {
            "name": store.get("name"),
            "volume": datastore_uuid(store.get("url")),
            "matched_instance": None,
        }
        worst_read: list[tuple[datetime, float]] = []
        worst_write: list[tuple[datetime, float]] = []
        iops: list[tuple[datetime, float]] = []
        for moref in host_morefs:
            per_host = series.get(moref, {})
            for name, sink in (
                ("datastore.totalReadLatency.average", worst_read),
                ("datastore.totalWriteLatency.average", worst_write),
                ("datastore.numberReadAveraged.average", iops),
                ("datastore.numberWriteAveraged.average", iops),
            ):
                found = per_host.get(name)
                instance = next((item for item in instances if found and item in found.samples), None)
                if found is not None and instance is not None:
                    entry["matched_instance"] = instance
                    sink.extend(found.samples[instance])
        # Worst across the hosts mounting it: each host sees its own latency to it.
        entry["read_latency_ms"] = summarize(sorted(worst_read))
        entry["write_latency_ms"] = summarize(sorted(worst_write))
        entry["iops"] = summarize(_sum_by_time(iops))
        free, capacity = store.get("free_bytes"), store.get("capacity_bytes")
        if free is not None and capacity:
            free_percent = free / capacity * 100
            entry["free_percent"] = round(free_percent, 1)
            if free_percent <= thresholds.datastore_full_percent:
                capacity_findings.append(
                    f"datastore {store.get('name')} is nearly full ({entry['free_percent']}% free)"
                )
        if store.get("accessible") is False:
            capacity_findings.append(f"datastore {store.get('name')} is not accessible")
        if not entry["matched_instance"]:
            entry["note"] = (
                "no datastore counter on these hosts matched this datastore "
                f"(tried {', '.join(instances) or 'nothing: no URL or name'})"
            )
        for label in ("read_latency_ms", "write_latency_ms"):
            summary = entry[label]
            if summary and summary["max"] >= thresholds.datastore_latency_ms:
                findings.append(
                    f"datastore {store.get('name')} {label.split('_')[0]} latency peaked at "
                    f"{summary['max']:.0f} ms at {summary['peak_at']:%H:%M:%S}Z "
                    f"(threshold {thresholds.datastore_latency_ms:g} ms)"
                )
        result["datastores"].append(entry)

    device_slow = queue_slow = False
    for moref in host_morefs if with_devices else []:
        per_host = series.get(moref, {})
        devices: dict[str, dict[str, Any]] = {}
        for name in HOST_DISK:
            found = per_host.get(name)
            if not found:
                continue
            for instance, samples in found.samples.items():
                if not instance or instance == "*":
                    continue
                devices.setdefault(instance, {"device": instance})[name.split(".")[1]] = summarize(samples)
        ranked = sorted(
            devices.values(),
            key=lambda device: (device.get("deviceLatency") or {}).get("max", 0),
            reverse=True,
        )[:5]
        for device in ranked:
            device["host"] = hosts.get(moref, moref)
            latency = (device.get("deviceLatency") or {}).get("max", 0)
            queue = (device.get("queueLatency") or {}).get("max", 0)
            if latency >= thresholds.device_latency_ms:
                device_slow = True
                findings.append(
                    f"device {device['device']} on host {device['host']}: device latency peaked "
                    f"at {latency:.0f} ms (the storage array's side)"
                )
            if queue >= thresholds.queue_latency_ms:
                queue_slow = True
                findings.append(
                    f"device {device['device']} on host {device['host']}: queue latency peaked "
                    f"at {queue:.0f} ms (the host's own queue was full)"
                )
            aborted = (device.get("commandsAborted") or {}).get("max", 0)
            resets = (device.get("busResets") or {}).get("max", 0)
            if aborted or resets:
                findings.append(
                    f"device {device['device']} on host {device['host']}: {aborted:.0f} aborted commands, "
                    f"{resets:.0f} bus resets in a sample"
                )
        result["host_devices"].extend(ranked)
    if vm_moref is not None:
        own = series.get(vm_moref, {})
        disks = {}
        for name in VM_DISK:
            found = own.get(name)
            if not found:
                continue
            for instance, samples in found.samples.items():
                disks.setdefault(instance or "all", {"disk": instance or "all"})[name.split(".")[1]] = (
                    summarize(samples)
                )
        result["vm_disks"] = list(disks.values())
        for disk in disks.values():
            for label in ("totalReadLatency", "totalWriteLatency"):
                peak = (disk.get(label) or {}).get("max", 0)
                if peak >= thresholds.datastore_latency_ms:
                    findings.append(
                        f"the VM's disk {disk['disk']} saw {label.removeprefix('total').lower()} "
                        f"latency up to {peak:.0f} ms"
                    )
    if device_slow and not queue_slow:
        result["where"] = "array: device latency high, host queue normal"
    elif queue_slow and not device_slow:
        result["where"] = "host: queue latency high, device latency normal"
    elif queue_slow and device_slow:
        result["where"] = "both device and queue latency high"
    # "Slow" is latency only. A full or unreachable datastore is a different
    # cause, kept apart so it is not weighed as latency the counters never showed.
    result["slow"] = bool(findings)
    result["window_read"] = any(entry.get("matched_instance") for entry in result["datastores"])
    result["capacity_findings"] = capacity_findings
    result["findings"] = findings + capacity_findings
    return result


def _sum_by_time(samples: list[tuple[datetime, float]]) -> list[tuple[datetime, float]]:
    totals: dict[datetime, float] = {}
    for stamp, value in samples:
        totals[stamp] = totals.get(stamp, 0.0) + value
    return sorted(totals.items())
